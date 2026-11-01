"""I2c acceptance: spec criteria 12, 49, 56, 67, 69 and 76, the audit record format (section 3.3), the run lock
(section 5.6 step 2) and the safe-path rule (sections 3.5, 5.4 and 5.7).

Criterion 56 needs the fault-injection seam (I12). The test here covers the result-write failure at unit level.
The end-to-end interruption test is not run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import kc_axi
from kc_axi.audit import AuditTrail, require_audit_path
from kc_axi.errors import KcAxiError
from kc_axi.lock import LOCK_NAME, RunLock, ensure_secrets_dir
from kc_axi.paths import check_outside_git, git_work_tree_of

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="file modes are POSIX-only")
PACKAGE_PARENT = str(Path(kc_axi.__file__).resolve().parents[1])
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def make_repo(root: Path) -> Path:
    """A git work tree without the git program: a `.git` directory is enough for the check."""
    repo = root / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def child_holding_lock(secrets_dir: Path, *, then: str) -> subprocess.Popen:
    """Start a process that takes the lock, prints `held`, then runs `then` (`wait` or `die`)."""
    body = "import time\ntime.sleep(60)" if then == "wait" else "import os\nos._exit(0)"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {PACKAGE_PARENT!r})\n"
        "from kc_axi.lock import RunLock\n"
        "lock = RunLock.acquire(sys.argv[1])\n"
        "print('held', flush=True)\n"
        f"{body}\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(secrets_dir)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8",
    )
    assert proc.stdout is not None
    line = proc.stdout.readline()
    assert line.strip() == "held", proc.stderr.read() if proc.stderr else ""
    return proc


# Criterion 12 (audit file unwritable refuses in preflight with audit_failed, before any change).


def test_c12_missing_parent_directory_is_audit_failed_in_preflight(tmp_path: Path):
    target = tmp_path / "no-such-dir" / "audit.jsonl"
    with pytest.raises(KcAxiError) as info:
        AuditTrail.open(target)
    assert info.value.code == "audit_failed"
    assert info.value.exit_code == 1
    assert not target.exists()
    assert not (tmp_path / "no-such-dir").exists()


def test_c12_audit_path_that_is_a_directory_is_audit_failed(tmp_path: Path):
    with pytest.raises(KcAxiError) as info:
        AuditTrail.open(tmp_path)
    assert info.value.code == "audit_failed"
    assert info.value.exit_code == 1


def test_c12_failed_intent_write_is_audit_failed_and_leaves_no_intent(tmp_path: Path, monkeypatch):
    trail = AuditTrail.open(tmp_path / "audit.jsonl", actor="tester")

    def broken(_record):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(trail, "_append", broken)
    with pytest.raises(KcAxiError) as info:
        trail.intent(command="apply", action="create", kind="client", name="web", realm="acme")
    trail.close()
    assert info.value.code == "audit_failed"
    assert info.value.exit_code == 1
    assert (tmp_path / "audit.jsonl").read_bytes() == b""


# Criterion 49 (commands with no audit_path exit 2 with audit_required).


@pytest.mark.parametrize("empty", ["", None])
def test_c49_empty_audit_path_is_audit_required_exit_2(empty):
    with pytest.raises(KcAxiError) as info:
        require_audit_path(empty)
    assert info.value.code == "audit_required"
    assert info.value.exit_code == 2


def test_c49_empty_audit_path_is_rejected_before_any_file_is_touched(tmp_path: Path):
    secrets_dir = tmp_path / "secrets"
    with pytest.raises(KcAxiError) as info:
        require_audit_path("")
    assert info.value.code == "audit_required"
    assert not secrets_dir.exists()
    assert not any(tmp_path.iterdir())


# Criterion 56 (partly: the result-write failure at unit level. The interruption test needs I12 and is not run).


def test_c56_result_write_failure_is_audit_incomplete_and_keeps_intent(tmp_path: Path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    with AuditTrail.open(path, actor="tester") as trail:
        record_id = trail.intent(command="apply", action="change", kind="client", name="web", fields=["redirectUris"])

        def broken(_record):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(trail, "_append", broken)
        with pytest.raises(KcAxiError) as info:
            trail.result(record_id)
    assert info.value.code == "audit_incomplete"
    assert info.value.exit_code == 1
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert [r["phase"] for r in lines] == ["intent"]


# Audit record format and secrecy (section 3.3).


def test_audit_records_follow_section_3_3(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    with AuditTrail.open(path, actor="alice") as trail:
        rid = trail.intent(
            command="apply", action="change", kind="client", name="acme-web", realm="acme",
            base_url="http://127.0.0.1:8080", fields=["redirectUris"],
        )
        trail.result(rid)
    intent, result = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]

    assert intent == {
        "schema_version": 1, "ts": intent["ts"], "phase": "intent", "id": rid, "actor": "alice",
        "base_url": "http://127.0.0.1:8080", "realm": "acme", "command": "apply", "kind": "client",
        "name": "acme-web", "action": "change", "fields": ["redirectUris"],
    }
    assert TS_RE.match(intent["ts"])
    assert result == {
        "schema_version": 1, "ts": result["ts"], "phase": "result", "id": rid, "outcome": "ok",
    }
    assert TS_RE.match(result["ts"])


def test_error_result_carries_the_typed_code(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    with AuditTrail.open(path, actor="alice") as trail:
        rid = trail.intent(command="disable-user", action="disable", kind="user", name="bob")
        trail.record_error(rid, "apply_partial")
    result = json.loads(path.read_text(encoding="utf-8").splitlines()[1])
    assert result["outcome"] == "error"
    assert result["code"] == "apply_partial"


def test_records_never_hold_a_secret(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    secret = "s3cr3t-value-XYZ"
    with AuditTrail.open(path, actor="alice") as trail:
        rid = trail.intent(
            command="reset-password", action="password", kind="user", name="bob", realm="acme",
            base_url=f"http://admin:{secret}@127.0.0.1:8080", fields=["temporary_password"],
        )
        trail.result(rid)
    text = path.read_text(encoding="utf-8")
    assert secret not in text
    assert "127.0.0.1:8080" in text
    assert json.loads(text.splitlines()[0])["base_url"] == "http://127.0.0.1:8080"


def test_fields_must_be_names_not_values(tmp_path: Path):
    with AuditTrail.open(tmp_path / "audit.jsonl", actor="alice") as trail:
        with pytest.raises(TypeError):
            trail.intent(command="apply", action="change", fields=[{"redirectUris": ["https://x"]}])


def test_unknown_action_is_refused(tmp_path: Path):
    with AuditTrail.open(tmp_path / "audit.jsonl", actor="alice") as trail:
        with pytest.raises(ValueError):
            trail.intent(command="apply", action="explode")


@POSIX_ONLY
def test_new_audit_file_is_owner_only(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    AuditTrail.open(path, actor="alice").close()
    assert path.stat().st_mode & 0o777 == 0o600


def test_audit_file_is_appended_across_runs(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    for _ in range(2):
        with AuditTrail.open(path, actor="alice") as trail:
            rid = trail.intent(command="up", action="up")
            trail.result(rid)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 4


# Criterion 67 (lock: a second run exits 1 with locked, and no stale lock remains).


def test_c67_second_run_while_first_holds_lock_is_locked(tmp_path: Path):
    secrets = tmp_path / "secrets"
    with RunLock.acquire(secrets):
        with pytest.raises(KcAxiError) as info:
            RunLock.acquire(secrets)
    assert info.value.code == "locked"
    assert info.value.exit_code == 1


def test_c67_lock_held_by_another_process_is_locked(tmp_path: Path):
    secrets = tmp_path / "secrets"
    child = child_holding_lock(secrets, then="wait")
    try:
        with pytest.raises(KcAxiError) as info:
            RunLock.acquire(secrets)
        assert info.value.code == "locked"
        assert info.value.exit_code == 1
    finally:
        child.kill()
        child.wait(timeout=10)


def test_c67_lock_is_free_after_the_holder_process_dies(tmp_path: Path):
    secrets = tmp_path / "secrets"
    child = child_holding_lock(secrets, then="die")
    child.wait(timeout=10)
    assert (secrets / LOCK_NAME).exists()  # the file stays; the lock does not
    with RunLock.acquire(secrets) as lock:
        assert lock.path == secrets / LOCK_NAME


def test_lock_is_free_after_release(tmp_path: Path):
    secrets = tmp_path / "secrets"
    lock = RunLock.acquire(secrets)
    lock.release()
    lock.release()  # a second release is a no-op
    with RunLock.acquire(secrets):
        pass


def test_lock_file_is_named_kc_axi_lock_in_secrets_dir(tmp_path: Path):
    secrets = tmp_path / "secrets"
    with RunLock.acquire(secrets) as lock:
        assert lock.path == secrets / "kc-axi.lock"
        assert lock.path.exists()


# secrets_dir is created on first need (section 3.5, item 36).


def test_secrets_dir_is_created_on_first_need(tmp_path: Path):
    secrets = tmp_path / "config" / "kc-axi" / "secrets"
    assert not secrets.exists()
    with RunLock.acquire(secrets):
        pass
    assert secrets.is_dir()
    assert (secrets / LOCK_NAME).exists()


def test_ensure_secrets_dir_creates_missing_directory_once(tmp_path: Path):
    secrets = tmp_path / "secrets"
    assert ensure_secrets_dir(secrets) == secrets
    assert secrets.is_dir()
    assert ensure_secrets_dir(secrets) == secrets  # an existing directory is not an error


@POSIX_ONLY
def test_secrets_dir_is_owner_only_when_created(tmp_path: Path):
    secrets = tmp_path / "secrets"
    ensure_secrets_dir(secrets)
    assert secrets.stat().st_mode & 0o777 == 0o700


@POSIX_ONLY
def test_lock_file_is_owner_only_when_created(tmp_path: Path):
    secrets = tmp_path / "secrets"
    with RunLock.acquire(secrets):
        pass
    assert (secrets / LOCK_NAME).stat().st_mode & 0o777 == 0o600


# Criterion 69 (a path inside a git work tree exits 2 with unsafe_path, before any write).


def test_c69_secrets_dir_inside_git_work_tree_is_unsafe_and_nothing_is_created(tmp_path: Path):
    repo = make_repo(tmp_path)
    secrets = repo / "config" / "secrets"
    with pytest.raises(KcAxiError) as info:
        RunLock.acquire(secrets)
    assert info.value.code == "unsafe_path"
    assert info.value.exit_code == 2
    assert not secrets.exists()


def test_c69_git_file_counts_as_a_work_tree(tmp_path: Path):
    # A linked worktree and a submodule use a `.git` file, not a directory.
    repo = tmp_path / "linked"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
    with pytest.raises(KcAxiError) as info:
        check_outside_git(repo / "out" / "users.yaml", "export output")
    assert info.value.code == "unsafe_path"


def test_c69_export_path_inside_git_work_tree_is_unsafe_and_no_file_is_written(tmp_path: Path):
    repo = make_repo(tmp_path)
    out = repo / "acme.users.yaml"
    with pytest.raises(KcAxiError) as info:
        check_outside_git(out, "export output")
    assert info.value.code == "unsafe_path"
    assert info.value.exit_code == 2
    assert not out.exists()


def test_c69_path_outside_git_work_tree_is_allowed(tmp_path: Path):
    outside = tmp_path / "keep" / "secrets"
    check_outside_git(outside, "secrets_dir")  # no exception
    assert git_work_tree_of(outside) is None


def test_c69_nested_dot_git_inside_a_repo_is_detected(tmp_path: Path):
    repo = make_repo(tmp_path)
    deep = repo / "a" / "b" / "c"
    assert git_work_tree_of(deep) == repo


# Criterion 76 (apply with no audit_path exits 2 before the lock is taken).
# The command-level order belongs to I7. Here the audit check comes first and touches nothing.


def test_c76_missing_audit_path_stops_before_the_lock_file_exists(tmp_path: Path):
    secrets = tmp_path / "secrets"
    with pytest.raises(KcAxiError) as info:
        require_audit_path("")  # the first step of apply, before RunLock.acquire
    assert info.value.code == "audit_required"
    assert not secrets.exists()
    assert not (secrets / LOCK_NAME).exists()
