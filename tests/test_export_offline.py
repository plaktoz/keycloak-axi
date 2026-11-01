"""I19 acceptance: spec 5.12 export steps 2 to 5 and criterion 86 (restart after a failed export).

Runs against the stub runtimes of tests/test_runtime.py. No container is started. The stub `ls` answers by call
index: one read in `_resolve`, one in `_wait_ready`. A test that restarts the container therefore lists both
reads as running. The stub `cp` writes nothing, so the copy is faked by wrapping `runtime._run` for `cp` only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from kc_axi import runtime
from kc_axi.errors import KcAxiError
from kc_axi.runtime import export_realm_offline

from test_runtime import IMAGE, NAME, PASSWORD, closed_port, inspect_json, keycloak, make_settings, stubs  # noqa: F401 - fixtures

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stub runtimes are POSIX scripts (verified by reading on Windows)")

REALM = "human-cheat-code"
RUNNING_TWICE = ["running", "running"]  # _resolve, then _wait_ready after the restart


def _workdir(tmp_path: Path) -> Path:
    workdir = tmp_path / "export"
    workdir.mkdir(mode=0o700)
    return workdir


def _fake_cp(workdir: Path, monkeypatch) -> None:
    """Make `podman cp` leave the realm file in workdir, as the real copy would."""
    original = runtime._run

    def run(argv, **kw):
        if argv[1:2] == ["cp"]:
            (workdir / f"{REALM}-realm.json").write_text("{}", encoding="utf-8")
        return original(argv, **kw)

    monkeypatch.setattr(runtime, "_run", run)


def test_c86_failed_export_restarts_the_container_and_exits_1(stubs, keycloak, tmp_path):
    # Criterion 86: the export fails, the container starts again and is ready, and the command exits 1 runtime_failed.
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"), run_rc=1, run_stderr="export failed")
    keycloak.ready_after = 0
    with pytest.raises(KcAxiError) as caught:
        export_realm_offline(make_settings(keycloak.port), REALM, _workdir(tmp_path), sleep=lambda s: None)
    assert caught.value.code == "runtime_failed"
    assert caught.value.exit_code == 1
    assert "restart_code" not in caught.value.fields
    calls = stubs.argv("podman")
    stop, start = calls.index(["stop", "-t", "10", NAME]), calls.index(["start", NAME])
    assert stop < start, "the container must start again after the failed export"


def test_export_run_is_offline_on_the_data_volume(stubs, keycloak, tmp_path, monkeypatch):
    # Step 4: a one-off run on the data volume, with the export command, and no secret in its arguments.
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    keycloak.ready_after = 0
    workdir = _workdir(tmp_path)
    _fake_cp(workdir, monkeypatch)
    export_realm_offline(make_settings(keycloak.port, volume="kc-test-data"), REALM, workdir, sleep=lambda s: None)
    run = next(call for call in stubs.argv("podman") if call[0] == "run")
    assert run == [
        "run", "--name", f"{NAME}-export", "-v", "kc-test-data:/opt/keycloak/data", IMAGE,
        "export", "--realm", REALM, "--users", "realm_file", "--dir", "/tmp/kc-axi-export",
    ]
    assert not any(PASSWORD in arg for arg in run)


def test_export_copies_one_owner_only_file_and_removes_the_one_off_container(stubs, keycloak, tmp_path, monkeypatch):
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    keycloak.ready_after = 0
    workdir = _workdir(tmp_path)
    _fake_cp(workdir, monkeypatch)
    exported = export_realm_offline(make_settings(keycloak.port), REALM, workdir, sleep=lambda s: None)
    assert exported == workdir / f"{REALM}-realm.json"
    assert oct(exported.stat().st_mode & 0o777) == "0o600"
    calls = stubs.argv("podman")
    assert ["cp", f"{NAME}-export:/tmp/kc-axi-export/{REALM}-realm.json", str(exported)] in calls
    assert ["rm", "-f", f"{NAME}-export"] in calls


@pytest.mark.parametrize("realm", ["-oops", "a/b", "a b", "", "a:b", "../x"])
def test_bad_realm_name_is_refused_before_any_runtime_call(stubs, keycloak, tmp_path, realm):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        export_realm_offline(make_settings(keycloak.port), realm, _workdir(tmp_path), sleep=lambda s: None)
    assert caught.value.code == "config_invalid"
    assert stubs.argv("podman") == [], "no runtime call may happen for a bad realm name"


def test_missing_container_is_not_found_and_nothing_is_stopped(stubs, keycloak, tmp_path):
    stubs.install("podman")
    stubs.set("podman", ls_states=["", ""])
    with pytest.raises(KcAxiError) as caught:
        export_realm_offline(make_settings(keycloak.port), REALM, _workdir(tmp_path), sleep=lambda s: None)
    assert caught.value.code == "not_found"
    assert not any(call[0] in ("stop", "run", "start") for call in stubs.argv("podman"))


def test_restart_failure_is_reported_when_the_export_succeeded(stubs, tmp_path, monkeypatch):
    # The export succeeds, the container does not come back: container_exited (exit 1). The copied file is still there
    # until the caller removes the directory, so the caller can decide.
    stubs.install("podman")
    stubs.set("podman", ls_states=["running", "exited"], container_inspect_stdout=inspect_json("exited"))
    workdir = _workdir(tmp_path)
    _fake_cp(workdir, monkeypatch)
    with pytest.raises(KcAxiError) as caught:
        export_realm_offline(make_settings(closed_port(), ready_timeout_seconds=5), REALM, workdir, sleep=lambda s: None)
    assert caught.value.code == "container_exited"
    assert caught.value.exit_code == 1
