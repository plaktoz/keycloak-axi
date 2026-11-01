"""I20 acceptance: spec 5.12 export and criteria 84, 85, 86, and the export half of 69.

The CLI runs end to end against stub runtimes (tests/test_runtime.py). Nothing starts a container. A fake `cp`
writes the realm file, because a stub does not copy files. Each test that calls the runtime writes its own
config under tmp_path.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from kc_axi import runtime
from kc_axi.cli import main

from test_runtime import IMAGE, NAME, PASSWORD, inspect_json, keycloak, stubs  # noqa: F401 - fixtures

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stub runtimes are POSIX scripts (verified by reading on Windows)")

REALM = "human-cheat-code"
RUNNING_TWICE = ["running", "running"]


def _config(tmp_path: Path, port: int, *, base: str | None = None) -> Path:
    config = tmp_path / "tool.yaml"
    config.write_text(
        f"schema_version: 1\nbase_url: http://127.0.0.1:{port}\nport: {port}\n"
        f"secrets_dir: {tmp_path / 'secrets'}\naudit_path: {tmp_path / 'audit.jsonl'}\n"
        f"image: {IMAGE}\ncontainer_name: {NAME}\nvolume: kc-test-data\n"
        "runtime: podman\nready_timeout_seconds: 5\nrequest_timeout_seconds: 2\nruntime_timeout_seconds: 5\n"
        "pull_timeout_seconds: 5\n" + (f"default_realm: {REALM}\n" if base is None else ""),
        encoding="utf-8",
    )
    return config


@pytest.fixture
def env(monkeypatch, keycloak, tmp_path, stubs):  # noqa: F811
    config = _config(tmp_path, keycloak.port)
    monkeypatch.setenv("KC_AXI_CONFIG", str(config))
    monkeypatch.setenv("KC_ADMIN_PASSWORD", PASSWORD)
    for name in ("KC_AXI_REALM", "KC_AXI_SECRETS_DIR", "KC_AXI_AUDIT_PATH"):
        monkeypatch.delenv(name, raising=False)
    keycloak.ready_after = 0
    return tmp_path


def run(*argv: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue()


def run_json(*argv: str) -> tuple[int, dict]:
    code, text = run(*argv, "--json")
    return code, json.loads(text)


def _fake_cp(monkeypatch, realm_text: str, *, tree: Path | None = None) -> None:
    """`podman cp` writes the realm file that the export left. The stub cannot copy files, so this is faked."""
    original = runtime._run

    def run_fake(argv, **kw):
        if argv[1:2] == ["cp"]:
            Path(argv[3]).write_text(realm_text, encoding="utf-8")
            os.chmod(argv[3], 0o644)  # the container writes it readable, as a real copy can
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return original(argv, **kw)

    monkeypatch.setattr(runtime, "_run", run_fake)


def _realm_doc(users: int = 2, clients: int = 1) -> str:
    return json.dumps({
        "realm": REALM,
        "users": [{"username": f"u{i}", "credentials": [{"type": "password", "secretData": "{}"}]} for i in range(users)],
        "clients": [{"clientId": f"c{i}"} for i in range(clients)],
        "components": {},
    }, indent=2)


def test_c84_full_export_writes_one_owner_only_file_with_the_realm(env, stubs, monkeypatch):  # noqa: F811
    # Criterion 84: one JSON file, realm equals R, the users and clients are counted, the admin password is absent.
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _fake_cp(monkeypatch, _realm_doc())
    out = env / "exports" / f"{REALM}-realm.json"
    code, body = run_json("export-realm", "--scope", "full", "--out", str(out), "--yes", "--realm", REALM)
    assert code == 0, body
    assert body["status"] == "written"
    assert body["kind"] == "full"
    assert body["users"] == 2 and body["clients"] == 1
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["realm"] == REALM
    assert PASSWORD not in out.read_text(encoding="utf-8")
    if sys.platform != "win32":
        assert oct(out.stat().st_mode & 0o777) == "0o600", "the file holds hashes and keys: owner-only"
    # The export left no directory behind, and the container runs again.
    assert not any(p.name.startswith("export-") for p in (env / "secrets").iterdir())
    calls = stubs.argv("podman")
    assert ["start", NAME] in calls


def test_c84_full_export_is_refused_for_the_admin_realm(env, stubs, monkeypatch):  # noqa: F811
    stubs.install("podman")
    code, body = run_json("export-realm", "--scope", "full", "--out", str(env / "x.json"), "--yes", "--realm", "master")
    assert code == 2
    assert body["error"]["code"] == "admin_realm_refused"
    assert stubs.argv("podman") == []


def test_c85_out_inside_a_git_work_tree_is_unsafe_before_the_container_stops(env, stubs, monkeypatch):  # noqa: F811
    # Criterion 85: the path is refused before any runtime call.
    repo = env / "repo"
    (repo / ".git").mkdir(parents=True)
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    code, body = run_json("export-realm", "--scope", "full", "--out", str(repo / "realm.json"), "--yes", "--realm", REALM)
    assert code == 2
    assert body["error"]["code"] == "unsafe_path"
    assert stubs.argv("podman") == [], "no runtime call may happen before the path check"
    assert not (repo / "realm.json").exists()


def test_c86_failed_export_leaves_no_file_and_starts_the_container_again(env, stubs, monkeypatch):  # noqa: F811
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"), run_rc=1, run_stderr="boom")
    out = env / "realm.json"
    code, body = run_json("export-realm", "--scope", "full", "--out", str(out), "--yes", "--realm", REALM)
    assert code == 1
    assert body["error"]["code"] == "runtime_failed"
    assert not out.exists(), "a failed export writes nothing to --out"
    calls = stubs.argv("podman")
    assert ["start", NAME] in calls


def test_export_refuses_when_the_file_exists_without_yes(env, stubs, monkeypatch):  # noqa: F811
    out = env / "realm.json"
    out.write_text("{}", encoding="utf-8")
    code, body = run_json("export-realm", "--scope", "full", "--out", str(out), "--realm", REALM)
    assert code == 1
    assert body["error"]["code"] == "confirm_required"
    assert out.read_text(encoding="utf-8") == "{}"
    assert stubs.argv("podman") == []


def test_export_with_the_admin_password_in_the_file_is_secret_in_export(env, stubs, monkeypatch):  # noqa: F811
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _fake_cp(monkeypatch, _realm_doc().replace('"u0"', f'"{PASSWORD}"'))
    out = env / "realm.json"
    code, body = run_json("export-realm", "--scope", "full", "--out", str(out), "--yes", "--realm", REALM)
    assert code == 1
    assert body["error"]["code"] == "secret_in_export"
    assert not out.exists()
    assert PASSWORD not in json.dumps(body)


def test_export_audit_has_an_intent_and_a_result_record(env, stubs, monkeypatch):  # noqa: F811
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _fake_cp(monkeypatch, _realm_doc())
    code, _ = run_json("export-realm", "--scope", "full", "--out", str(env / "r.json"), "--yes", "--realm", REALM)
    assert code == 0
    lines = [json.loads(line) for line in (env / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["phase"] for r in lines] == ["intent", "result"]
    assert lines[0]["action"] == "export" and lines[0]["realm"] == REALM
    assert lines[1]["outcome"] == "ok"
    assert PASSWORD not in (env / "audit.jsonl").read_text(encoding="utf-8")


def test_export_failure_is_recorded_as_an_error_result(env, stubs, monkeypatch):  # noqa: F811
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"), run_rc=1, run_stderr="boom")
    code, _ = run_json("export-realm", "--scope", "full", "--out", str(env / "r.json"), "--yes", "--realm", REALM)
    assert code == 1
    lines = [json.loads(line) for line in (env / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines[-1]["phase"] == "result" and lines[-1]["outcome"] == "error"
    assert lines[-1]["code"] == "runtime_failed"
