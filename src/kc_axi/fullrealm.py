"""Full export and import of one realm in one file (spec section 5.12).

`export_full` is the export half. A full file is a backup and restore format, not a desired-state file.
It holds password hashes and realm signing keys, so it is written owner-only and never inside a git work tree.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import runtime
from .audit import AuditTrail, require_audit_path
from .config import Settings
from .credentials import check_owner_only
from .errors import KcAxiError
from .keycloak import KeycloakClient, require_local_for_write
from .lock import RunLock
from .paths import check_outside_git


def runtime_settings(settings: Settings, password: str) -> runtime.RuntimeSettings:
    """The runtime view of the tool configuration. The password is kept only for redaction of runtime messages."""
    return runtime.RuntimeSettings(
        base_url=settings.base_url,
        port=settings.port,
        image=settings.image,
        container_name=settings.container_name,
        runtime=settings.runtime,
        hostname=settings.hostname,
        volume=settings.volume,
        volume_options=settings.volume_options,
        java_opts=settings.java_opts,
        admin_user=settings.admin_user,
        admin_password=password,
        audit_path=str(settings.audit_path or ""),
        ready_timeout_seconds=settings.ready_timeout_seconds,
        request_timeout_seconds=settings.request_timeout_seconds,
        runtime_timeout_seconds=settings.runtime_timeout_seconds,
        pull_timeout_seconds=settings.pull_timeout_seconds,
    )


def _file_failed(path: Path, exc: OSError) -> KcAxiError:
    return KcAxiError(
        "file_failed", f"cannot write {path}",
        help=("Check the path and its permissions.",), path=str(path), reason=exc.strerror or type(exc).__name__,
    )


def read_realm_file(path: Path, realm: str) -> tuple[dict[str, Any], str]:
    """Spec 5.12 export step 6: the exported text must be JSON of the realm `realm`. Returns (document, text)."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise KcAxiError("runtime_failed", f"the export wrote no readable realm file: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise KcAxiError("runtime_failed", "the export file is not JSON") from exc
    if not isinstance(document, dict) or document.get("realm") != realm:
        raise KcAxiError("runtime_failed", f"the export file is not the realm {realm}")
    return document, text


def write_private(path: Path, text: str) -> None:
    """Write `text` to `path` owner-only (0600), by a temporary file in the same directory and a rename.

    No half-written file is ever visible at `path`, and the content is never readable by another user.
    """
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=directory)  # mkstemp creates the file 0600
    except OSError as exc:
        raise _file_failed(path, exc) from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except OSError as exc:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise _file_failed(path, exc) from exc


def export_full(settings: Settings, realm: str, out: Path, password: str, *, yes: bool = False) -> dict[str, Any]:
    """`export-realm --scope full` (spec 5.12, export steps 1 to 7). Returns the result body."""
    if realm == settings.admin_realm:
        raise KcAxiError("admin_realm_refused", f"{realm} is the admin realm and is never exported", help=("use another --realm",))
    check_outside_git(out, "export output")
    audit_path = require_audit_path(settings.audit_path)
    if out.exists() and not yes:
        raise KcAxiError(
            "confirm_required", f"{out} exists. Nothing changed",
            help=("run again with --yes to replace the file",), path=str(out),
        )
    rt = runtime_settings(settings, password)
    runtime.check_image(rt.image)
    secrets_dir = Path(settings.secrets_dir)
    check_outside_git(secrets_dir, "secrets_dir")  # before any write; the lock creates the directory

    with AuditTrail.open(audit_path) as audit, RunLock.acquire(secrets_dir):
        workdir = Path(tempfile.mkdtemp(prefix="export-", dir=secrets_dir))  # mkdtemp makes it 0700
        record: dict[str, str] = {}

        def intent() -> None:
            record["id"] = audit.intent(command="export-realm", action="export", kind="realm", name=realm,
                                        base_url=settings.base_url, realm=realm)

        try:
            exported = runtime.export_realm_offline(rt, realm, workdir, before_stop=intent)
            document, text = read_realm_file(exported, realm)
            if password and password in text:
                raise KcAxiError("secret_in_export", "the admin password appears in the export. Nothing was written to --out")
            write_private(out, text)
            if "id" in record:
                audit.result(record["id"])
        except KcAxiError as err:
            if "id" in record:
                audit.record_error(record["id"], err.code)
            raise
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    users, clients = document.get("users", []), document.get("clients", [])
    return {
        "status": "written", "path": str(out), "kind": "full", "realm": realm,
        "users": len(users) if isinstance(users, list) else 0,
        "clients": len(clients) if isinstance(clients, list) else 0,
    }


# ---------------------------------------------------------------- import (spec 5.12, import steps 1 to 8)


def _count(document: dict[str, Any], key: str) -> int:
    value = document.get(key)
    return len(value) if isinstance(value, list) else 0


def read_import_file(path: Path, realm: str) -> dict[str, Any]:
    """Step 1. Every check runs before any request. Exit 2 for a file that cannot be used."""
    check_owner_only(path, "import file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise KcAxiError("import_invalid", f"{path} cannot be read as UTF-8 text: {exc.__class__.__name__}") from None
    try:
        document = json.loads(text)
    except ValueError:
        raise KcAxiError("import_invalid", f"{path} is not JSON", help=("use a file written by export-realm --scope full",)) from None
    if not isinstance(document, dict):
        raise KcAxiError("import_invalid", f"{path} is not a realm object")
    if document.get("realm") != realm:
        raise KcAxiError(
            "realm_mismatch", f"the file holds realm {document.get('realm')!r}, and --realm is {realm!r}",
            help=("use the --realm that the file names",), file_realm=str(document.get("realm")),
        )
    for key in ("users", "clients"):
        if not isinstance(document.get(key), list):
            raise KcAxiError("import_invalid", f"{path}: {key} must be a list. A full file from export-realm has both")
    return document


def preflight_import(settings: Settings, realm: str, file: Path, *, allow_remote: bool) -> dict[str, Any]:
    """Import step 1: every check that needs no server. Returns the parsed file. Nothing has changed when it raises."""
    if realm == settings.admin_realm:
        raise KcAxiError("admin_realm_refused", f"{realm} is the admin realm and is never replaced", help=("use another --realm",))
    document = read_import_file(file, realm)
    require_audit_path(settings.audit_path)
    require_local_for_write(settings.base_url, allow_remote)
    check_outside_git(Path(settings.secrets_dir), "secrets_dir")
    return document


def live_counts(client: KeycloakClient, realm: str) -> tuple[int, int] | None:
    """(users, clients) of the live realm, or None when the realm does not exist."""
    try:
        client.get(KeycloakClient.admin_path(realm))
    except KcAxiError as err:
        if err.code == "not_found":
            return None
        raise
    users = client.get(KeycloakClient.admin_path(realm, "users", "count")).body
    clients = client.get(KeycloakClient.admin_path(realm, "clients")).body
    return (users if isinstance(users, int) else 0, len(clients) if isinstance(clients, list) else 0)


def _backup_path(secrets_dir: Path, realm: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = secrets_dir / f"{realm}-backup-{stamp}.json"
    n = 1
    while path.exists():
        path = secrets_dir / f"{realm}-backup-{stamp}-{n}.json"
        n += 1
    return path


def _take_backup(rt: runtime.RuntimeSettings, realm: str, secrets_dir: Path, password: str, before_stop: Any) -> Path:
    """Steps 5 and 4 to 6 of the export: the file goes to `secrets_dir`, owner-only, and the work directory is removed."""
    try:
        workdir = Path(tempfile.mkdtemp(prefix="backup-", dir=secrets_dir))
    except OSError as exc:
        raise _file_failed(secrets_dir, exc) from exc  # before the stop and before the delete
    try:
        exported = runtime.export_realm_offline(rt, realm, workdir, before_stop=before_stop)
        _, text = read_realm_file(exported, realm)
        if password and password in text:
            raise KcAxiError("secret_in_export", "the admin password appears in the backup. Nothing was changed")
        target = _backup_path(secrets_dir, realm)
        write_private(target, text)
        return target
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def import_full(
    settings: Settings,
    client: KeycloakClient,
    realm: str,
    file: Path,
    password: str,
    *,
    yes: bool = False,
    allow_remote: bool = False,
) -> dict[str, Any]:
    """`import-realm` (spec 5.12, import steps 1 to 8). Replaces the realm with the contents of `file`."""
    document = preflight_import(settings, realm, file, allow_remote=allow_remote)
    secrets_dir = Path(settings.secrets_dir)
    file_users, file_clients = _count(document, "users"), _count(document, "clients")

    live = live_counts(client, realm)
    if not yes:
        raise KcAxiError(
            "confirm_required",
            f"import-realm replaces realm {realm}: file has {file_users} users and {file_clients} clients, "
            + (f"live realm has {live[0]} users and {live[1]} clients" if live else "the live realm does not exist")
            + ". Nothing changed",
            help=("run again with --yes to replace the realm",),
            file_users=file_users, file_clients=file_clients,
            live_users=live[0] if live else None, live_clients=live[1] if live else None,
        )
    rt = runtime_settings(settings, password)

    with AuditTrail.open(settings.audit_path) as audit, RunLock.acquire(secrets_dir):
        record: dict[str, str] = {}

        def intent() -> None:
            record["id"] = audit.intent(command="import-realm", action="import", kind="realm", name=realm,
                                        base_url=settings.base_url, realm=realm)

        backup: Path | None = None
        try:
            live = live_counts(client, realm)  # again, now that the lock is held
            if live is not None:
                runtime.check_image(rt.image)
                backup = _take_backup(rt, realm, secrets_dir, password, intent)  # writes the intent before the stop
                client.delete(KeycloakClient.admin_path(realm))
            else:
                intent()
            try:
                client.post("/admin/realms", json_body=document)
            except KcAxiError as post_error:
                if backup is None:
                    raise
                raise _restore(client, backup, post_error) from post_error
            audit.result(record["id"])
        except KcAxiError as err:
            if "id" in record:
                audit.record_error(record["id"], err.code)
            raise
    return {
        "status": "replaced", "realm": realm, "users": file_users, "clients": file_clients,
        "backup": str(backup) if backup else "none",
    }


def _restore(client: KeycloakClient, backup: Path, cause: KcAxiError) -> KcAxiError:
    """Step 7. The realm was deleted and the file did not load: send the backup through the same call."""
    try:
        client.post("/admin/realms", json_body=json.loads(backup.read_text(encoding="utf-8")))
        restored = True
    except (KcAxiError, OSError, ValueError):
        restored = False
    note = (
        "The old realm is back." if restored
        else "The old realm is NOT back. The backup file is the only copy: import it with import-realm."
    )
    return KcAxiError(
        "import_partial",
        f"the realm was deleted, and the new file did not load ({cause.code}). {note}",
        help=(f"kc-axi import-realm --realm <R> --file {backup} --yes",),
        backup=str(backup), cause=cause.code, restored=restored,
    )
