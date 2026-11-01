"""The run lock (spec sections 3.5, 5.6 step 2 and 5.8, criterion 67).

The lock file is `kc-axi.lock` in `secrets_dir`. It is an OS advisory lock on an open file. The operating system
drops the lock when the process ends, even after a crash, so no stale lock remains. The lock file itself stays
on disk and is reused.

`secrets_dir` is created on first need, with owner-only mode on Linux and macOS (section 11, item 36).
The `unsafe_path` check runs first, so no directory is created inside a git work tree.

Platforms. POSIX uses `fcntl.flock`. Windows uses `msvcrt.locking` on one byte. The Windows branch is
verified by reading only. The mode bits are ignored on Windows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .errors import KcAxiError
from .paths import check_outside_git

LOCK_NAME = "kc-axi.lock"

if sys.platform == "win32":  # pragma: no cover - verified by reading only
    import msvcrt

    def _try_lock(fd: int) -> bool:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:  # BlockingIOError (EWOULDBLOCK), or EACCES on some systems
            return False
        return True

    def _unlock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


def ensure_secrets_dir(secrets_dir: str | os.PathLike[str]) -> Path:
    """Create `secrets_dir` on first need and return it. Exit 2 `unsafe_path` inside a git work tree.

    Missing parents get the default mode. The directory itself gets 0700 on Linux and macOS, when this call creates it.
    A write failure is exit 1, `file_failed`, with the path in the message.
    """
    path = Path(secrets_dir)
    check_outside_git(path, "secrets_dir")
    if path.is_dir():
        return path
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if sys.platform != "win32":
            os.chmod(path, 0o700)  # the umask can only remove bits, so this never loosens the mode
    except OSError as exc:
        raise KcAxiError(
            "file_failed", f"secrets_dir cannot be created: {path}",
            help=("Check the path and its permissions.",), path=str(path), reason=exc.strerror or type(exc).__name__,
        ) from exc
    return path


class RunLock:
    """Holds the advisory lock until `release()`, the end of the `with` block, or the end of the process."""

    def __init__(self, fd: int, path: Path):
        self._fd: int | None = fd
        self.path = path

    @classmethod
    def acquire(cls, secrets_dir: str | os.PathLike[str]) -> RunLock:
        """Take the lock without waiting. Exit 1 `locked` when another run holds it."""
        directory = ensure_secrets_dir(secrets_dir)
        path = directory / LOCK_NAME
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise KcAxiError(
                "file_failed", f"the lock file cannot be opened: {path}",
                help=("Check the path and its permissions.",), path=str(path), reason=exc.strerror or type(exc).__name__,
            ) from exc
        if not _try_lock(fd):
            os.close(fd)
            raise KcAxiError(
                "locked", f"another kc-axi run holds the lock: {path}",
                help=("Nothing changed. Wait for the other run to end, then run the command again.",), path=str(path),
            )
        return cls(fd, path)

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        _unlock(fd)
        os.close(fd)

    def __enter__(self) -> RunLock:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()
