"""Secrets file, reader and file-level secrets commands (spec sections 3.5, 4.2, 4.3 and 5.8).

The file format is the interface. Any consumer that follows section 5.8 can read it. This module holds:

- the file format and its checks (owner-only mode, server identity, schema);
- `read_secret`, the reference reader;
- the file-level writes: a `pending` generation, the finish step (`mark_active`), `restore_pending`,
  `prune_generations` and `list_generations`.

It holds no Keycloak call. The commands that read or write the server (`capture`, and `rotate` and `restore`
against the server) need I3 and I7. Callers pass the directory, realm, normalised `base_url` and client names in
as arguments. Nothing here prints a value.

Locking: the caller holds `kc-axi.lock` (spec 5.6 step 4, `lock.RunLock`). `apply` does so in I7. The `secrets`
commands take it in I8. The write functions below do not take it themselves. The directory check against git
work trees (spec 3.5) runs in `_write_document`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .errors import KcAxiError
from .paths import check_outside_git

SCHEMA_VERSION = 1
STATES = ("pending", "active", "retired")

_REALM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


# --- names, fingerprints and values -------------------------------------------------------------------------

def normalise_base_url(base_url: str) -> str:
    """Lower the case of the scheme and the host, and remove one trailing slash (spec 3.5)."""
    parts = urlsplit(base_url)
    path = parts.path[:-1] if parts.path.endswith("/") else parts.path
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, parts.fragment))


def fingerprint(value: str) -> str:
    """The first 8 hex digits of the SHA-256 of the value. A label, not a check (spec 3.5)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def generate_value() -> str:
    """32 random bytes from `secrets.token_bytes`, as base64url without padding (spec 3.5)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def secrets_path(secrets_dir: str | os.PathLike[str], realm: str) -> Path:
    """The file of one realm inside `secrets_dir`. The realm name must be safe as a file name."""
    if not isinstance(realm, str) or not _REALM_NAME.fullmatch(realm):
        raise KcAxiError("config_invalid", "the realm name cannot be used as a file name")
    return Path(secrets_dir) / f"{realm}.secrets.json"


# --- reading ------------------------------------------------------------------------------------------------

def _file_failed(path: Path, exc: OSError) -> KcAxiError:
    return KcAxiError("file_failed", f"cannot write {path}: {exc.strerror or type(exc).__name__}")


def _check_owner_only(path: Path, mode: int) -> None:
    """Refuse a file that another user can read or write (spec 5.4).

    Windows: the check is skipped (spec 5.4). Verified by reading only.
    """
    if sys.platform.startswith("win"):
        return
    if stat.S_IMODE(mode) & 0o077:
        raise KcAxiError(
            "unsafe_file_mode",
            f"secrets file {path} can be read or written by other users",
            help=(f"chmod 600 {path}",),
        )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate(document: Any, realm: str, base_url: str, path: Path) -> None:
    """Check the document against section 3.5. Raises the typed code of section 5.8, steps 2 and 3."""

    def unreadable(reason: str) -> KcAxiError:
        return KcAxiError("secrets_unreadable", f"secrets file {path} is not readable: {reason}")

    if not isinstance(document, dict):
        raise unreadable("the top level is not an object")
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        if _is_int(version):
            raise KcAxiError("schema_unsupported", f"secrets file {path} has schema_version {version}")
        raise unreadable("no schema_version")
    if document.get("realm") != realm:
        # Spec 4.4 defines realm_mismatch for flags and config files only. A file that names another realm
        # is a damaged or misplaced file, so it is unreadable (exit 1).
        raise unreadable("it names another realm")
    server = document.get("server")
    if not isinstance(server, str):
        raise unreadable("no server")
    expected = normalise_base_url(base_url)
    if server != expected:
        raise KcAxiError(
            "secrets_server_mismatch",
            f"secrets file {path} is for server {server}, not {expected}",
        )

    generations = document.get("generations")
    active = document.get("active")
    if not isinstance(generations, list) or not _is_int(active):
        raise unreadable("generations or active is malformed")
    numbers: set[int] = set()
    pending_count = 0
    active_count = 0
    for gen in generations:
        if not isinstance(gen, dict) or not _is_int(gen.get("generation")):
            raise unreadable("a generation is malformed")
        if gen["generation"] in numbers or gen.get("state") not in STATES:
            raise unreadable("a generation number or state is malformed")
        if not isinstance(gen.get("created_at"), str) or not isinstance(gen.get("clients"), dict):
            raise unreadable("a generation is malformed")
        numbers.add(gen["generation"])
        for entry in gen["clients"].values():
            if not (isinstance(entry, dict) and isinstance(entry.get("value"), str)
                    and isinstance(entry.get("fingerprint"), str)):
                raise unreadable("a client entry is malformed")
        pending_count += gen["state"] == "pending"
        active_count += gen["state"] == "active"
    if pending_count > 1 or active_count > 1:
        raise unreadable("more than one pending or active generation")
    pointer = _by_number(document, active)
    if pointer is None or pointer["state"] not in ("pending", "active"):
        raise unreadable("the active number does not name a current generation")
    if pending_count and pointer["state"] != "pending":
        raise unreadable("a pending generation exists but the active number does not name it")


def _load(secrets_dir: str | os.PathLike[str], realm: str, base_url: str) -> dict[str, Any] | None:
    """Read and check the file. Returns None when the file does not exist.

    Order: owner-only mode, then parse, then the server and realm identity (spec 5.8, steps 1 to 3).
    """
    path = secrets_path(secrets_dir, realm)
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KcAxiError("secrets_unreadable", f"cannot read {path}: {exc.strerror or type(exc).__name__}")
    _check_owner_only(path, file_stat.st_mode)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise KcAxiError("secrets_unreadable", f"secrets file {path} cannot be parsed")
    _validate(document, realm, base_url, path)
    return document


def _by_number(document: Mapping[str, Any], number: Any) -> dict[str, Any] | None:
    for gen in document["generations"]:
        if gen["generation"] == number:
            return gen
    return None


def _first(document: Mapping[str, Any], state: str) -> dict[str, Any] | None:
    for gen in document["generations"]:
        if gen["state"] == state:
            return gen
    return None


def _values_of(gen: Mapping[str, Any]) -> dict[str, str]:
    return {name: entry["value"] for name, entry in gen["clients"].items()}


def read_secret(secrets_dir: str | os.PathLike[str], realm: str, base_url: str, client: str) -> str:
    """Return the active value of one client (spec 5.8). Prints nothing.

    Raises KcAxiError with one of: secrets_unreadable, unsafe_file_mode, secrets_server_mismatch,
    secrets_missing, generation_pending. The message never contains a value.
    """
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        raise KcAxiError("secrets_unreadable", f"secrets file is missing: {path}")
    generation = _by_number(document, document["active"])
    if generation["state"] == "pending":
        raise KcAxiError("generation_pending", "a pending generation exists; the value is not confirmed yet")
    entry = generation["clients"].get(client)
    if entry is None:
        raise KcAxiError("secrets_missing", f"client {client} has no value in the secrets file")
    return entry["value"]


# --- writing ------------------------------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_document(realm: str, base_url: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "realm": realm,
        "server": normalise_base_url(base_url),
        "active": 0,
        "generations": [],
    }


def _generation(number: int, state: str, values: Mapping[str, str]) -> dict[str, Any]:
    return {
        "generation": number,
        "created_at": _utc_now(),
        "state": state,
        "clients": {
            name: {"value": value, "fingerprint": fingerprint(value)} for name, value in sorted(values.items())
        },
    }


def _next_number(document: Mapping[str, Any]) -> int:
    return max((gen["generation"] for gen in document["generations"]), default=0) + 1


def _payload(status: str, number: int | None, pruned: int = 0) -> dict[str, Any]:
    # `applied` is 0 at file level. The step that talks to Keycloak sets the real count.
    return {"status": status, "generation": number, "applied": 0, "pruned": pruned}


def _write_document(directory: Path, path: Path, document: Mapping[str, Any]) -> None:
    """Write the whole file with fsync, then rename (spec 5.8, create path, step 2).

    The temporary file is made in the same directory, so the rename stays on one file system.
    """
    check_outside_git(directory, "secrets_dir")  # spec 3.5: never inside a git work tree
    try:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as exc:
        raise _file_failed(path, exc)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise _file_failed(path, exc)
    _fsync_directory(directory)


def _fsync_directory(directory: Path) -> None:
    """Make the rename durable on POSIX. Windows has no directory fsync, so it is skipped there."""
    if sys.platform.startswith("win"):
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _add_pending(
    document: dict[str, Any],
    client_names: Iterable[str],
    new_values: Mapping[str, str],
    check_declared: bool = True,
) -> None:
    """Append a pending generation to `document`, in memory.

    Every entry of the active generation is carried forward, including clients that are no longer declared
    (spec 5.8, "Client removed"). `new_values` override them. Each name in `client_names` must have a value.
    With `check_declared`, every name in `new_values` must be declared (rotate). Restore sets it to False,
    because generation N may hold a client that is no longer declared.
    """
    if _first(document, "pending") is not None:
        raise KcAxiError(
            "generation_pending",
            "a pending generation exists; finish it with kc-axi apply before writing another",
        )
    names = set(client_names)
    undeclared = sorted(set(new_values) - names)
    if check_declared and undeclared:
        raise KcAxiError("not_found", f"client {undeclared[0]} is not declared in the file")
    current = _first(document, "active")
    values = _values_of(current) if current is not None else {}
    values.update(new_values)
    missing = sorted(names - set(values))
    if missing:
        raise KcAxiError("secrets_missing", f"client {missing[0]} has no value in the secrets file")
    number = _next_number(document)
    document["generations"].append(_generation(number, "pending", values))
    document["active"] = number


def write_pending(
    secrets_dir: str | os.PathLike[str],
    realm: str,
    base_url: str,
    client_names: Iterable[str],
    new_values: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Write a new `pending` generation (spec 5.8).

    `new_values` maps a client name to its new value. Other clients keep their active value. The caller
    generates the values with `generate_value()`. The file is created on the first write, with owner-only
    permissions on Linux and macOS. Refused with generation_pending while a pending generation exists.
    """
    # The caller holds kc-axi.lock (spec 5.6 step 4).
    directory = Path(secrets_dir)
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        document = _new_document(realm, base_url)
    _add_pending(document, client_names, new_values or {})
    _write_document(directory, path, document)
    return _payload("done", document["active"])


def mark_active(secrets_dir: str | os.PathLike[str], realm: str, base_url: str) -> dict[str, Any]:
    """Finish the pending generation: it becomes `active`, and the old active one becomes `retired`.

    Called after Keycloak holds the pending values (spec 5.8, create path step 4). With no pending generation,
    the status is `already`.
    """
    # The caller holds kc-axi.lock (spec 5.6 step 4). The secrets commands take it in I8.
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        raise KcAxiError("secrets_unreadable", f"secrets file is missing: {path}")
    pending = _first(document, "pending")
    if pending is None:
        return _payload("already", document["active"])
    for gen in document["generations"]:
        if gen["state"] == "active":
            gen["state"] = "retired"
    pending["state"] = "active"
    document["active"] = pending["generation"]
    _write_document(Path(secrets_dir), path, document)
    return _payload("done", document["active"])


def restore_pending(
    secrets_dir: str | os.PathLike[str],
    realm: str,
    base_url: str,
    client_names: Iterable[str],
    generation: int,
) -> dict[str, Any]:
    """Copy the values of generation N as a new `pending` generation (spec 4.2, 5.8).

    A client absent from N keeps its active value. History is never edited. N never written gives
    generation_unknown. N deleted by prune gives generation_pruned. Finish the copy with `mark_active`
    after Keycloak holds the values.
    """
    # The caller holds kc-axi.lock (spec 5.6 step 4). The secrets commands take it in I8.
    directory = Path(secrets_dir)
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        raise KcAxiError("secrets_unreadable", f"secrets file is missing: {path}")
    if _first(document, "pending") is not None:
        raise KcAxiError("generation_pending", "a pending generation exists; finish it with kc-axi apply first")
    target = _by_number(document, generation)
    if target is None:
        newest = _next_number(document) - 1
        if 1 <= generation < newest:
            raise KcAxiError("generation_pruned", f"generation {generation} was deleted by prune")
        raise KcAxiError("generation_unknown", f"generation {generation} does not exist")
    _add_pending(document, client_names, _values_of(target), check_declared=False)
    _write_document(directory, path, document)
    return _payload("done", document["active"])


def prune_generations(
    secrets_dir: str | os.PathLike[str], realm: str, base_url: str, keep: int
) -> dict[str, Any]:
    """Delete the oldest `retired` generations, and keep the newest `keep` of them (spec 5.8).

    `active` and `pending` generations are never deleted. The command is refused while a pending generation
    exists, because every `secrets` write is (spec 5.8).
    """
    if not _is_int(keep) or keep < 0:
        raise KcAxiError("usage", "--keep takes a whole number of 0 or more")
    # The caller holds kc-axi.lock (spec 5.6 step 4). The secrets commands take it in I8.
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        return _payload("already", None)
    if _first(document, "pending") is not None:
        raise KcAxiError("generation_pending", "a pending generation exists; finish it with kc-axi apply first")
    retired = sorted(gen["generation"] for gen in document["generations"] if gen["state"] == "retired")
    doomed = set(retired[: max(0, len(retired) - keep)])
    if not doomed:
        return _payload("already", document["active"])
    document["generations"] = [gen for gen in document["generations"] if gen["generation"] not in doomed]
    _write_document(Path(secrets_dir), path, document)
    return _payload("done", document["active"], pruned=len(doomed))


def list_generations(secrets_dir: str | os.PathLike[str], realm: str, base_url: str) -> dict[str, Any]:
    """The payload of `secrets list` (spec 4.3). Fingerprints only, never a value.

    A missing file gives `status: empty`, as section 4.5 rule 4 asks for a list. The reader is different: it
    raises secrets_unreadable.
    """
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        return {"status": "empty", "realm": realm, "active": None, "generations": []}
    generations = [
        {
            "generation": gen["generation"],
            "state": gen["state"],
            "created_at": gen["created_at"],
            "clients": {name: entry["fingerprint"] for name, entry in gen["clients"].items()},
        }
        for gen in document["generations"]
    ]
    return {"status": "active", "realm": realm, "active": document["active"], "generations": generations}


def compare_live(
    secrets_dir: str | os.PathLike[str],
    realm: str,
    base_url: str,
    live: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Compare the live secrets with the file, for `plan` (spec 5.6 step 3). Prints nothing, and holds no lock.

    `live` maps a client name to its live secret. Each answer is `{"state", "file", "live", "pending"}`:
    `state` is `match`, `missing` (no value in the file), `mismatch` (neither the active nor the pending value),
    or `finish_pending` (a pending generation exists, and the live value equals its value or the active one).
    `file` and `live` are fingerprints, never values. `pending` is the pending generation number or None.
    A missing file gives `missing` for every client.
    """
    document = _load(secrets_dir, realm, base_url)
    active = _first(document, "active") if document is not None else None
    pending = _first(document, "pending") if document is not None else None
    stored = _values_of(active) if active is not None else {}
    waiting = _values_of(pending) if pending is not None else {}
    answers: dict[str, dict[str, Any]] = {}
    for name, value in live.items():
        file_value = stored.get(name)
        pending_value = waiting.get(name)
        if pending_value is not None:
            state = "finish_pending" if value in (pending_value, file_value) else "mismatch"
        elif file_value is None:
            state = "missing"
        else:
            state = "match" if value == file_value else "mismatch"
        answers[name] = {
            "state": state,
            "file": fingerprint(file_value) if file_value is not None else None,
            "live": fingerprint(value),
            "pending": pending["generation"] if pending is not None and pending_value is not None else None,
        }
    return answers


# --- reads and writes for `apply` (spec 5.6 and 5.8) ----------------------------------------------------------

def check_file(secrets_dir: str | os.PathLike[str], realm: str, base_url: str) -> dict[str, Any] | None:
    """Check the file without changing it. None when the file does not exist (spec 3.5, section 5.6 step 2)."""
    return _load(secrets_dir, realm, base_url)


def has_pending(secrets_dir: str | os.PathLike[str], realm: str, base_url: str) -> bool:
    """True when the file holds a `pending` generation. A missing file has none."""
    document = _load(secrets_dir, realm, base_url)
    return document is not None and _first(document, "pending") is not None


def generation_value(
    secrets_dir: str | os.PathLike[str], realm: str, base_url: str, state: str, client: str
) -> str | None:
    """The value of one client in the first generation with `state`, or None. Prints nothing."""
    document = _load(secrets_dir, realm, base_url)
    gen = _first(document, state) if document is not None else None
    if gen is None or client not in gen["clients"]:
        return None
    return gen["clients"][client]["value"]


def stage_values(
    secrets_dir: str | os.PathLike[str], realm: str, base_url: str, new_values: Mapping[str, str]
) -> None:
    """Add values to the pending generation, or start one (spec 5.8, create path, step 2).

    Unlike `write_pending`, an existing pending generation is extended, so one `apply` can stage the values of
    several clients. A value already in the pending generation is never replaced. The generation stays pending
    until `mark_active` runs after the last action that uses it.
    """
    path = secrets_path(secrets_dir, realm)
    document = _load(secrets_dir, realm, base_url)
    if document is None:
        document = _new_document(realm, base_url)
    pending = _first(document, "pending")
    if pending is None:
        _add_pending(document, new_values.keys(), new_values)
    else:
        for name, value in new_values.items():
            if name in pending["clients"]:
                raise KcAxiError("generation_pending", f"the pending generation already holds a value for {name}")
            pending["clients"][name] = {"value": value, "fingerprint": fingerprint(value)}
    _write_document(Path(secrets_dir), path, document)
