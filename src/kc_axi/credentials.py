"""The admin password (spec section 5.4, "Credentials never on the command line").

Sources, in order: the environment variable `KC_ADMIN_PASSWORD`, then the file named by `admin_password_file`.
One trailing newline (LF or CRLF) is removed from the file. The file must be owner-only on Linux and macOS.
This module reads the password. It never prints or logs it.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from .errors import KcAxiError

PASSWORD_VARIABLE = "KC_ADMIN_PASSWORD"


def check_owner_only(path: Path, label: str) -> None:
    """Exit 2, `unsafe_file_mode`, when another user can read or write `path`. Windows: skipped, verified by reading only."""
    if sys.platform.startswith("win"):
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return  # the caller reports an unreadable file
    if mode & 0o077:
        raise KcAxiError(
            "unsafe_file_mode",
            f"{label} {path} can be read or written by other users",
            help=(f"chmod 600 {path}",),
        )


def _strip_one_newline(text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def admin_password(password_file: Path | None, env: Mapping[str, str] | None = None) -> str | None:
    """The admin password, or None when no source supplies one. The caller decides whether that is an error.

    A variable that is set and empty counts as not set. A password file that is named but unreadable is an error,
    because the operator asked for it.
    """
    env = os.environ if env is None else env
    value = env.get(PASSWORD_VARIABLE, "")
    if value:
        return value
    if password_file is None:
        return None
    check_owner_only(password_file, "admin_password_file")
    try:
        text = password_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise KcAxiError(
            "credential_missing",
            f"admin_password_file {password_file} cannot be read as UTF-8 text",
            help=("check that the file exists and is readable",),
        ) from None
    text = _strip_one_newline(text)
    return text or None


def require_admin_password(password_file: Path | None, env: Mapping[str, str] | None = None) -> str:
    """The admin password. Exit 2, `credential_missing`, before any request, when there is no source."""
    value = admin_password(password_file, env)
    if value is None:
        raise KcAxiError(
            "credential_missing",
            "no admin password: neither KC_ADMIN_PASSWORD nor admin_password_file supplies one",
            help=(f"set {PASSWORD_VARIABLE}, or set admin_password_file in the configuration file",),
        )
    return value
