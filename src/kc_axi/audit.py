"""Audit trail for write commands (spec sections 3.3 and 5.9, criteria 12, 49 and 56).

The audit file is JSON lines. Each write runs in this order:

1. Preflight: `AuditTrail.open` opens the file for append. A missing `audit_path` is `audit_required` (exit 2).
   A file that cannot be opened is `audit_failed` (exit 1). Both happen before any change.
2. `intent()` appends an `intent` record and makes it durable (fsync) before the change.
3. The caller makes the change.
4. `result()` appends a `result` record. If that write fails, the error is `audit_incomplete` (exit 1).

Records hold names and codes only. Field names are listed, never their values. A secret never enters a record,
because the API takes no value argument. The `base_url` has any `user:password@` part removed before it is written.
"""

from __future__ import annotations

import getpass
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Iterable
from urllib.parse import urlsplit

from .errors import KcAxiError

SCHEMA_VERSION = 1

# The action names of spec section 3.3.
ACTIONS = frozenset({
    "create", "change", "adopt", "remove", "disable", "enable", "secret", "capture", "rotate", "restore",
    "prune", "password", "up", "down", "export",
})


def require_audit_path(audit_path: str | os.PathLike[str] | None) -> Path:
    """Return the audit path, or exit 2 with `audit_required` when it is empty.

    Call it before the lock is taken (criterion 76). It does not touch the file system.
    """
    if audit_path is None or str(audit_path) == "":
        raise KcAxiError(
            "audit_required",
            "this command writes, and no audit_path is set",
            help=("Set audit_path in the tool configuration, or KC_AXI_AUDIT_PATH.",),
        )
    return Path(audit_path)


def _utc_now() -> str:
    """RFC 3339 time in UTC, for example 2026-10-27T09:14:02Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _operator() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return "unknown"


def _safe_base_url(url: str | None) -> str | None:
    """Drop any `user:password@` part, so a credential in a URL never reaches the file."""
    if not url:
        return None
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return parts._replace(netloc=parts.netloc.rpartition("@")[2]).geturl()


class AuditTrail:
    """An open audit file. Build one with `AuditTrail.open` in preflight, and close it at the end of the command."""

    def __init__(self, handle: IO[bytes], path: Path, actor: str):
        self._handle = handle
        self.path = path
        self.actor = actor

    @classmethod
    def open(cls, audit_path: str | os.PathLike[str] | None, *, actor: str | None = None) -> AuditTrail:
        """Preflight. Exit 2 `audit_required` for an empty path, and exit 1 `audit_failed` when the file cannot be opened."""
        path = require_audit_path(audit_path)
        try:
            # A new file is owner-only on Linux and macOS. An existing file keeps its mode. Windows ignores the mode.
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            handle = os.fdopen(fd, "ab")
        except OSError as exc:
            raise KcAxiError(
                "audit_failed",
                f"the audit file cannot be opened for append: {path}",
                help=("Nothing changed. Fix the path or its permissions, then run the command again.",),
                path=str(path), reason=exc.strerror or type(exc).__name__,
            ) from exc
        return cls(handle, path, actor if actor is not None else _operator())

    def __enter__(self) -> AuditTrail:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()

    def _append(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=True, separators=(", ", ": ")) + "\n"
        self._handle.write(line.encode("utf-8"))
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def intent(
        self,
        *,
        command: str,
        action: str,
        kind: str | None = None,
        name: str | None = None,
        base_url: str | None = None,
        realm: str | None = None,
        fields: Iterable[str] = (),
    ) -> str:
        """Append an `intent` record before the change. Return the record `id` for `result()`.

        A failed write here means nothing has changed yet, so it is `audit_failed` (exit 1).
        """
        if action not in ACTIONS:
            raise ValueError(f"unknown audit action: {action}")
        field_names = list(fields)
        if not all(isinstance(f, str) for f in field_names):
            raise TypeError("audit fields must be field names (str), never values")
        record_id = uuid.uuid4().hex
        record = {
            "schema_version": SCHEMA_VERSION, "ts": _utc_now(), "phase": "intent", "id": record_id,
            "actor": self.actor, "base_url": _safe_base_url(base_url), "realm": realm,
            "command": command, "kind": kind, "name": name, "action": action, "fields": field_names,
        }
        try:
            self._append(record)
        except OSError as exc:
            raise KcAxiError(
                "audit_failed",
                f"the intent record cannot be written to the audit file: {self.path}",
                help=("Nothing changed. Fix the audit file, then run the command again.",),
                path=str(self.path), reason=exc.strerror or type(exc).__name__,
            ) from exc
        return record_id

    def result(self, record_id: str, *, ok: bool = True, code: str | None = None) -> None:
        """Append the `result` record after the change. A failed write here is `audit_incomplete` (exit 1).

        The change has already happened. The `intent` record stays in the file as evidence.
        """
        if ok and code is not None:
            raise ValueError("a successful result has no error code")
        record = {
            "schema_version": SCHEMA_VERSION, "ts": _utc_now(), "phase": "result", "id": record_id,
            "outcome": "ok" if ok else "error",
        }
        if not ok:
            record["code"] = code or "unknown"
        try:
            self._append(record)
        except OSError as exc:
            raise KcAxiError(
                "audit_incomplete",
                f"the change was made, but its result record cannot be written: {self.path}",
                help=("The intent record of this change stays in the audit file as evidence.",),
                path=str(self.path), audit_id=record_id, reason=exc.strerror or type(exc).__name__,
            ) from exc

    def record_error(self, record_id: str, code: str) -> None:
        """Best-effort `result` with outcome `error`, for a failed change.

        A write error is ignored here, so the original typed error still reaches the caller.
        """
        try:
            self.result(record_id, ok=False, code=code)
        except KcAxiError:
            pass


def toggle_states(audit_path: str | os.PathLike[str] | None) -> dict[tuple[str, str], str]:
    """The last `disable` or `enable` action of each object, from the intent records (spec section 5.9).

    The key is `(kind, name)`. A missing file gives an empty map. A file that cannot be read is `audit_failed`
    (exit 1). A line that is not JSON is skipped.
    """
    if audit_path is None or str(audit_path) == "":
        return {}
    try:
        text = Path(audit_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise KcAxiError(
            "audit_failed",
            f"the audit file cannot be read: {audit_path}",
            help=("Nothing changed. Fix the audit file, then run the command again.",),
            path=str(audit_path), reason=getattr(exc, "strerror", None) or type(exc).__name__,
        ) from exc
    states: dict[tuple[str, str], str] = {}
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("phase") == "intent" and record.get("action") in ("disable", "enable"):
            states[(str(record.get("kind")), str(record.get("name")))] = record["action"]
    return states
