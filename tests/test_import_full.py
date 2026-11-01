"""I21 acceptance: spec 5.12 import and criteria 87, 88, 89, 90 and 91 (the replace, the realm mismatch, the
backup before the delete, the partial-failure restore and the signing key).

The Keycloak here is a small stateful fake, built for these tests. It models the two calls that the spec relies on:
`DELETE /admin/realms/{R}` removes the realm, and `POST /admin/realms` creates a realm from the body. Stub runtimes
(tests/test_runtime.py) stand in for the container. The fake `cp` writes the export of the live realm.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from kc_axi import runtime
from kc_axi.cli import main

from test_runtime import IMAGE, NAME, PASSWORD, inspect_json, stubs  # noqa: F401 - fixtures

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stub runtimes are POSIX scripts (verified by reading on Windows)")

REALM = "human-cheat-code"
RUNNING_TWICE = ["running", "running"]


class FakeRealms:
    """Realms as Keycloak keeps them, behind the admin API paths that `import-realm` uses."""

    def __init__(self):
        self.realms: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_post_once = False  # the first POST of the file after a DELETE fails; the backup POST then loads
        self.fail_post_always = False  # every POST of a realm fails: the backup cannot load either
        self.deleted_realms: list[str] = []

        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, status, body=None):
                raw = b"" if body is None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                url = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                parts = [urllib.parse.unquote(p) for p in url.path.split("/") if p]
                if method == "POST" and url.path.endswith("/protocol/openid-connect/token"):
                    form = urllib.parse.parse_qs(raw.decode("utf-8"))
                    if form.get("password") == [PASSWORD]:
                        return self._send(200, {"access_token": "tok", "expires_in": 600})
                    return self._send(400, {"error": "invalid_grant"})
                if method == "GET" and parts == ["realms", "master"]:  # the readiness probe after a restart
                    return self._send(200, {"realm": "master"})
                fake.calls.append((method, url.path))
                if parts == ["admin", "serverinfo"]:
                    return self._send(200, {"systemInfo": {"version": "26.6.4"}})
                if method == "POST" and parts == ["admin", "realms"]:
                    body = json.loads(raw)
                    if fake.fail_post_always or fake.fail_next_post_for_file(body):
                        return self._send(400, {"errorMessage": "Invalid realm file", "field": "realm"})
                    fake.realms[body["realm"]] = body
                    return self._send(201, None)
                if len(parts) >= 3 and parts[:2] == ["admin", "realms"]:
                    name = parts[2]
                    realm = fake.realms.get(name)
                    if method == "DELETE" and len(parts) == 3:
                        if realm is None:
                            return self._send(404, {"error": "Realm not found."})
                        del fake.realms[name]
                        fake.deleted_realms.append(name)
                        return self._send(204, None)
                    if realm is None:
                        return self._send(404, {"error": "Realm not found."})
                    if len(parts) == 3:
                        return self._send(200, {"realm": name})
                    if parts[3:] == ["users", "count"]:
                        return self._send(200, len(realm.get("users", [])))
                    if parts[3:] == ["clients"]:
                        return self._send(200, realm.get("clients", []))
                return self._send(404, {"error": "unknown"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_DELETE(self):
                self._handle("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def fail_next_post_for_file(self, body: dict) -> bool:
        """True once for the first POST of the realm file after a DELETE of that realm, when fail_post_once is set."""
        if self.fail_post_once and body.get("realm") == REALM and REALM in self.deleted_realms:
            self.fail_post_once = False
            return True
        return False

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def kc():
    fake = FakeRealms()
    yield fake
    fake.close()


@pytest.fixture
def env(kc, monkeypatch, tmp_path, stubs):  # noqa: F811
    secrets, audit = tmp_path / "secrets", tmp_path / "audit.jsonl"
    config = tmp_path / "tool.yaml"
    config.write_text(
        f"schema_version: 1\nbase_url: http://127.0.0.1:{kc.port}\nport: {kc.port}\n"
        f"secrets_dir: {secrets}\naudit_path: {audit}\nimage: {IMAGE}\ncontainer_name: {NAME}\n"
        "volume: kc-test-data\nruntime: podman\nready_timeout_seconds: 5\nrequest_timeout_seconds: 2\n"
        "runtime_timeout_seconds: 5\npull_timeout_seconds: 5\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KC_AXI_CONFIG", str(config))
    monkeypatch.setenv("KC_ADMIN_PASSWORD", PASSWORD)
    for name in ("KC_AXI_REALM", "KC_AXI_SECRETS_DIR", "KC_AXI_AUDIT_PATH"):
        monkeypatch.delenv(name, raising=False)
    return type("Env", (), {"tmp": tmp_path, "secrets": secrets, "audit": audit, "config": config})()


def run_json(*argv: str) -> tuple[int, dict]:
    out, err = io.StringIO(), io.StringIO()
    code = main([*argv, "--json"], out=out, err=err)
    return code, json.loads(out.getvalue())


def _doc(users: list[str], signing_key: str = "KEY-A") -> dict:
    return {
        "realm": REALM,
        "users": [{"username": u, "credentials": [{"type": "password", "secretData": "{}"}]} for u in users],
        "clients": [{"clientId": "app", "secret": "CLIENT-SECRET-7"}],
        "components": {"org.keycloak.keys.KeyProvider": [{"name": "rsa", "config": {"privateKey": [signing_key]}}]},
    }


def _write_file(path: Path, doc: dict, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _export_fake(monkeypatch, doc: dict) -> None:
    """Make `podman cp` leave the live realm, as the offline export would."""
    original = runtime._run

    def run(argv, **kw):
        if argv[1:2] == ["cp"]:
            Path(argv[3]).write_text(json.dumps(doc), encoding="utf-8")
            os.chmod(argv[3], 0o644)
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return original(argv, **kw)

    monkeypatch.setattr(runtime, "_run", run)


def test_c87_import_replaces_the_realm_and_drops_users_absent_from_the_file(env, kc, stubs, monkeypatch):  # noqa: F811
    # Criterion 87: the realm is replaced. The users of the file exist. A user absent from the file is gone.
    kc.realms[REALM] = _doc(["old-user", "alice"])
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _export_fake(monkeypatch, kc.realms[REALM])
    new = _write_file(env.tmp / "new.json", _doc(["alice", "john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 0, body
    assert body["status"] == "replaced"
    names = [u["username"] for u in kc.realms[REALM]["users"]]
    assert names == ["alice", "john"]
    assert body["backup"] != "none"


def test_c88_realm_mismatch_exits_2_and_changes_nothing(env, kc, stubs):  # noqa: F811
    kc.realms[REALM] = _doc(["alice"])
    stubs.install("podman")
    other = _write_file(env.tmp / "other.json", {**_doc(["x"]), "realm": "other-realm"})
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(other), "--yes")
    assert code == 2
    assert body["error"]["code"] == "realm_mismatch"
    assert [u["username"] for u in kc.realms[REALM]["users"]] == ["alice"]
    assert ("DELETE", f"/admin/realms/{REALM}") not in kc.calls, "a mismatch must not reach the delete"
    assert stubs.argv("podman") == []


def test_c89_backup_is_written_before_the_delete(env, kc, stubs, monkeypatch):  # noqa: F811
    # Criterion 89: the backup exists before the DELETE is sent. A failed backup leaves the realm unchanged.
    kc.realms[REALM] = _doc(["alice"])
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"), run_rc=1, run_stderr="boom")
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 1
    assert body["error"]["code"] == "runtime_failed"
    assert kc.deleted_realms == [], "no delete may happen when the backup failed"
    assert [u["username"] for u in kc.realms[REALM]["users"]] == ["alice"]


def test_c89_backup_file_is_owner_only_and_kept_in_secrets_dir(env, kc, stubs, monkeypatch):  # noqa: F811
    kc.realms[REALM] = _doc(["alice"])
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _export_fake(monkeypatch, kc.realms[REALM])
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 0, body
    backup = Path(body["backup"])
    assert backup.parent == env.secrets
    assert oct(backup.stat().st_mode & 0o777) == "0o600"
    assert json.loads(backup.read_text(encoding="utf-8"))["users"][0]["username"] == "alice"


def test_c90_failed_restore_post_loads_the_backup_and_exits_import_partial(env, kc, stubs, monkeypatch):  # noqa: F811
    # Criterion 90: the POST of the file fails after the DELETE. The backup is sent, and the code is import_partial.
    kc.realms[REALM] = _doc(["alice"])
    kc.fail_post_once = True
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _export_fake(monkeypatch, kc.realms[REALM])
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 1
    assert body["error"]["code"] == "import_partial"
    assert body["error"]["cause"] == "keycloak_rejected"
    assert body["error"]["restored"] is True
    assert Path(body["error"]["backup"]).exists()
    assert [u["username"] for u in kc.realms[REALM]["users"]] == ["alice"], "the backup put the old users back"


def test_c90_partial_failure_says_the_realm_is_not_back_when_the_backup_also_fails(env, kc, stubs, monkeypatch):  # noqa: F811
    kc.realms[REALM] = _doc(["alice"])
    kc.fail_post_always = True
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _export_fake(monkeypatch, kc.realms[REALM])
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 1
    assert body["error"]["code"] == "import_partial"
    assert body["error"]["restored"] is False
    assert Path(body["error"]["backup"]).exists(), "the backup must survive: it is the only copy"


def test_c91_the_signing_key_of_the_file_is_kept_after_the_replace(env, kc, stubs, monkeypatch):  # noqa: F811
    # Criterion 91: after the replace, the realm holds the signing key of the file.
    kc.realms[REALM] = _doc(["alice"], signing_key="OLD-KEY")
    stubs.install("podman")
    stubs.set("podman", ls_states=RUNNING_TWICE, container_inspect_stdout=inspect_json("running"))
    _export_fake(monkeypatch, kc.realms[REALM])
    new = _write_file(env.tmp / "new.json", _doc(["john"], signing_key="FILE-KEY"))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 0, body
    keys = kc.realms[REALM]["components"]["org.keycloak.keys.KeyProvider"][0]["config"]["privateKey"]
    assert keys == ["FILE-KEY"]


def test_c91_the_file_must_be_owner_only(env, kc, stubs):  # noqa: F811
    new = _write_file(env.tmp / "new.json", _doc(["john"]), mode=0o644)
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 2
    assert body["error"]["code"] == "unsafe_file_mode"


@pytest.mark.parametrize("content, code", [
    ("not json", "import_invalid"),
    ("[1, 2]", "import_invalid"),
    (json.dumps({"realm": REALM, "users": {}, "clients": []}), "import_invalid"),
])
def test_invalid_file_is_import_invalid_before_any_request(env, kc, stubs, content, code):  # noqa: F811
    path = env.tmp / "bad.json"
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)
    code_out, body = run_json("import-realm", "--realm", REALM, "--file", str(path), "--yes")
    assert code_out == 2
    assert body["error"]["code"] == code
    assert kc.calls == []


def test_import_without_yes_prints_the_counts_and_changes_nothing(env, kc, stubs):  # noqa: F811
    kc.realms[REALM] = _doc(["alice"])
    new = _write_file(env.tmp / "new.json", _doc(["john", "jane"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new))
    assert code == 1
    assert body["error"]["code"] == "confirm_required"
    assert "2 users" in body["error"]["message"] and "1 users" in body["error"]["message"]
    assert [u["username"] for u in kc.realms[REALM]["users"]] == ["alice"]


def test_import_refuses_the_admin_realm_before_reading_the_file(env, kc, stubs):  # noqa: F811
    code, body = run_json("import-realm", "--realm", "master", "--file", str(env.tmp / "missing.json"), "--yes")
    assert code == 2
    assert body["error"]["code"] == "admin_realm_refused"


def test_import_with_no_live_realm_creates_it_without_a_backup(env, kc, stubs):  # noqa: F811
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, body = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 0, body
    assert body["backup"] == "none"
    assert [u["username"] for u in kc.realms[REALM]["users"]] == ["john"]
    assert stubs.argv("podman") == [], "a realm that does not exist has nothing to back up or stop"


def test_import_audit_has_an_intent_and_a_result_record(env, kc, stubs):  # noqa: F811
    new = _write_file(env.tmp / "new.json", _doc(["john"]))
    code, _ = run_json("import-realm", "--realm", REALM, "--file", str(new), "--yes")
    assert code == 0
    lines = [json.loads(line) for line in env.audit.read_text(encoding="utf-8").splitlines()]
    assert [r["phase"] for r in lines] == ["intent", "result"]
    assert lines[0]["action"] == "import"
    assert PASSWORD not in env.audit.read_text(encoding="utf-8")
