"""Safe-path checks (spec sections 3.5, 5.4, 5.7 and criterion 69).

A path inside a git work tree is refused, so that secrets, users files and exports never reach a repository.
Detection walks up from the path and looks for a `.git` entry. A directory or a file both count, because a
linked worktree and a submodule use a `.git` file. The `git` program is not used. The path need not exist.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import KcAxiError


def git_work_tree_of(path: str | os.PathLike[str]) -> Path | None:
    """Return the git work tree that holds `path`, or None when there is none.

    The path is made absolute and symlinks are followed, so a link into a repository is detected too.
    """
    start = Path(os.path.abspath(os.fspath(path))).resolve()
    for candidate in (start, *start.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    return None


def check_outside_git(path: str | os.PathLike[str], label: str) -> None:
    """Exit 2, `unsafe_path`, when `path` lies inside a git work tree. Call it before any write.

    `label` names the value in the message, for example `secrets_dir` or `export output`.
    """
    root = git_work_tree_of(path)
    if root is None:
        return
    raise KcAxiError(
        "unsafe_path",
        f"{label} lies inside a git work tree: {root}",
        help=(f"Move the {label} outside any git work tree.",),
        path=str(path),
    )
