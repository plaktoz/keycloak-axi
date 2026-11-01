"""Full export and import of one realm in one file (spec section 5.12).

`export_full` is the export half. A full file is a backup and restore format, not a desired-state file.
It holds password hashes and realm signing keys, so it is written owner-only and never inside a git work tree.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import runtime
from .audit import AuditTrail, require_audit_path
from .config import Settings
from .errors import KcAxiError
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
