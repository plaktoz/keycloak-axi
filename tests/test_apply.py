"""I7 acceptance: `apply` for a config file, spec sections 4.3, 5.6, 5.8 and 5.9, criteria 6, 18, 20, 21, 22, 24, 28,
33, 34, 37, 38, 62, 63, 70, 71 and 77.

The fake Keycloak keeps state, so a second `apply` sees what the first one wrote. It can reject a write with a
status, or drop the connection (the shape of a write that times out). Criteria 41 and 73 need the fault-injection
seam of I12 and are not tested here.
"""

from __future__ import annotations

import io
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from kc_axi import keycloak, secrets_store
from kc_axi.cli import main
from kc_axi.lock import RunLock

PASSWORD = "s3cret-admin-pw"
UUID1 = "7c1e0000-0000-4000-8000-000000000001"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="mode bits are ignored on Windows")


class StatefulKeycloak:
    """A Keycloak that applies writes. `rules` inject a failure: `{"method", "contains", "status"|"drop", "times"}`."""

    def __init__(self) -> None:
        self.realms: dict[str, dict] = {}
        self.writes: list[tuple[str, str, object]] = []
        self.rules: list[dict] = []
        self.before_write = None
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _send(self, status, body=None, headers=None):
                raw = b"" if body is None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

            def _read(self):
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length)

            def _handle(self, method):
                url = urllib.parse.urlsplit(self.path)
                raw = self._read()
                parts = [urllib.parse.unquote(p) for p in url.path.split("/") if p]
                query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
                if method == "POST" and parts[:1] == ["realms"]:
                    form = urllib.parse.parse_qs(raw.decode("utf-8"))
                    if form.get("password") == [PASSWORD]:
                        return self._send(200, {"access_token": "tok-1", "expires_in": 600})
                    return self._send(400, {"error": "invalid_grant"})
                body = json.loads(raw) if raw else None
                if method != "GET":
                    if fake.before_write:
                        fake.before_write(method, url.path)
                    fake.writes.append((method, url.path, body))
                    for rule in fake.rules:
                        if rule["method"] == method and rule["contains"] in url.path and rule.get("times", 1) > 0:
                            rule["times"] = rule.get("times", 1) - 1
                            if rule.get("drop"):
                                self.close_connection = True
                                return
                            return self._send(rule["status"], {"errorMessage": rule.get("message", "refused"),
                                                               "field": rule.get("field")})
                status, answer, headers = fake.route(method, parts, query, body)
                self._send(status, answer, headers)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PUT(self):
                self._handle("PUT")

            def do_DELETE(self):
                self._handle("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    # -- state

    def add_realm(self, name: str, *, clients=(), users=(), **info) -> None:
        builtin = [{"id": f"id-{b}", "clientId": b, "enabled": True, "publicClient": True}
                   for b in ("account", "admin-cli", "broker")]
        self.realms[name] = {
            "info": {"realm": name, "enabled": True, "displayName": None, "accessTokenLifespan": 300,
                     "registrationAllowed": False, **info},
            "clients": builtin + [dict(c) for c in clients], "users": list(users),
        }

    def client(self, realm: str, client_id: str) -> dict | None:
        return next((c for c in self.realms[realm]["clients"] if c["clientId"] == client_id), None)

    def written(self, method: str, contains: str = "") -> list[tuple[str, str, object]]:
        return [w for w in self.writes if w[0] == method and contains in w[1]]

    def route(self, method, parts, query, body):
        if parts == ["admin", "serverinfo"]:
            return 200, {"systemInfo": {"version": "26.6.4"}}, None
        if parts == ["admin", "realms"] and method == "POST":
            self.add_realm(body["realm"], **{k: v for k, v in body.items() if k != "realm"})
            return 201, None, {"Location": f"{self.url}/admin/realms/{body['realm']}"}
        realm = self.realms.get(parts[2]) if len(parts) > 2 else None
        if realm is None:
            return 404, {"error": "Realm not found."}, None
        tail = parts[3:]
        if not tail:
            if method == "PUT":
                realm["info"].update(body)
                return 204, None, None
            return 200, realm["info"], None
        if tail == ["users"]:
            return 200, realm["users"], None
        if tail == ["clients"]:
            if method == "POST":
                row = {"id": f"id-{body['clientId']}", **body}
                realm["clients"].append(row)
                return 201, None, {"Location": f"{self.url}/admin/realms/{parts[2]}/clients/{row['id']}"}
            rows = realm["clients"]
            if "clientId" in query:
                rows = [c for c in rows if c["clientId"] == query["clientId"]]
            return 200, rows, None
        row = next((c for c in realm["clients"] if tail[0] == "clients" and c["id"] == tail[1]), None)
        if row is None:
            return 404, {"error": "unknown"}, None
        if len(tail) == 2:
            if method == "PUT":
                kept = {"protocolMappers": row["protocolMappers"]} if "protocolMappers" in row else {}
                row.clear()
                row.update({**body, **kept})
                return 204, None, None
            if method == "DELETE":
                realm["clients"].remove(row)
                return 204, None, None
            return 200, row, None
        if tail[2:] == ["client-secret"]:
            return 200, {"type": "secret", "value": row.get("secret")}, None
        if tail[2:4] == ["protocol-mappers", "models"]:
            mappers = row.setdefault("protocolMappers", [])
            if len(tail) == 4:
                if method == "POST":
                    mappers.append({"id": f"m-{body['name']}", **body})
                    return 201, None, None
                return 200, mappers, None
            mapper = next((m for m in mappers if m["id"] == tail[4]), None)
            if method == "DELETE":
                mappers.remove(mapper)
            elif method == "PUT":
                mapper.update(body)
            return 204, None, None
        return 404, {"error": "unknown"}, None

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def live_client(client_id: str, *, owner: str | None = "acme", public: bool = False, mappers=None, secret="LIVE-SECRET", **extra):
    row = {"id": f"id-{client_id}", "clientId": client_id, "enabled": True, "publicClient": public,
           "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
           "redirectUris": [], "webOrigins": [], "attributes": {}, **extra}
    if owner:
        row["attributes"]["kc-axi.managed"] = owner
    if not public and secret:
        row["secret"] = secret
    if mappers is not None:
        row["protocolMappers"] = mappers
    return row


def live_mapper(name="aud", audience="api"):
    return {"id": f"m-{name}", "name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": audience, "access.token.claim": "true",
                       "introspection.token.claim": "true", "id.token.claim": "false"}}


@pytest.fixture
def kc():
    fake = StatefulKeycloak()
    yield fake
    fake.close()


@pytest.fixture
def env(kc, tmp_path, monkeypatch):
    """Paths of one run: `secrets`, `audit`. The tool config sets both."""
    secrets_dir, audit = tmp_path / "secrets", tmp_path / "audit.jsonl"
    config = tmp_path / "tool.yaml"
    config.write_text(
        f"schema_version: 1\nbase_url: {kc.url}\nport: {kc.port}\nsecrets_dir: {secrets_dir}\n"
        f"audit_path: {audit}\nrequest_timeout_seconds: 2\n", encoding="utf-8")
    monkeypatch.setenv("KC_AXI_CONFIG", str(config))
    monkeypatch.setenv("KC_ADMIN_PASSWORD", PASSWORD)
    for name in ("KC_AXI_REALM", "KC_AXI_SECRETS_DIR", "KC_AXI_AUDIT_PATH"):
        monkeypatch.delenv(name, raising=False)
    return type("Env", (), {"secrets": secrets_dir, "audit": audit, "config": config})()


def config_file(tmp_path: Path, text: str, name="acme.config.yaml") -> str:
    path = tmp_path / name
    path.write_text("schema_version: 1\nkind: config\nowner: acme\n" + text, encoding="utf-8")
    return str(path)


def run(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    code = main(["apply", *argv], out=out, err=err)
    return code, out.getvalue()


def run_json(*argv: str):
    code, text = run(*argv, "--json")
    return code, json.loads(text)


def error_of(parsed: dict) -> dict:
    return parsed["error"]


def audit_records(env) -> list[dict]:
    if not env.audit.exists():
        return []
    return [json.loads(line) for line in env.audit.read_text(encoding="utf-8").splitlines()]


WEB = "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, redirectUris: ['https://web/*']}\n"
API = "realm: {name: acme}\nclients:\n  - {clientId: api, publicClient: false, secret_managed: true}\n"


# ------------------------------------------------------------------------------ preview and confirmation (C6, C18)


def test_c6_without_yes_apply_prints_the_preview_and_changes_nothing(kc, env, tmp_path):
    kc.add_realm("acme")
    code, text = run("--file", config_file(tmp_path, WEB))
    assert code == 1
    assert text.startswith("status: confirm_required\n")
    assert "create,client,web" in text
    assert kc.writes == []
    assert not env.audit.read_text(encoding="utf-8") if env.audit.exists() else True


def test_c6_the_preview_as_json_is_an_apply_with_the_keys_of_plan(kc, env, tmp_path):
    kc.add_realm("acme")
    code, parsed = run_json("--file", config_file(tmp_path, WEB))
    assert code == 1 and parsed["status"] == "confirm_required" and parsed["command"] == "apply"
    assert parsed["total"] == 1 and len(parsed["plan_hash"]) == 16


def test_c18_a_second_apply_changes_nothing_and_says_already(kc, env, tmp_path):
    kc.add_realm("acme")
    file = config_file(tmp_path, WEB)
    assert run_json("--file", file, "--yes")[0] == 0
    writes = len(kc.writes)
    code, parsed = run_json("--file", file, "--yes")
    assert code == 0 and parsed["status"] == "already" and parsed["applied"] == 0
    assert len(kc.writes) == writes


def test_c6_already_needs_no_yes(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["https://web/*"])])
    code, parsed = run_json("--file", config_file(tmp_path, WEB))
    assert code == 0 and parsed["status"] == "already"


def test_apply_of_a_new_realm_creates_realm_and_client(kc, env, tmp_path):
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 0, parsed
    assert parsed["status"] == "applied" and parsed["applied"] == 2
    assert [(c["kind"], c["name"]) for c in parsed["created"]] == [("realm", "acme"), ("client", "web")]
    web = kc.client("acme", "web")
    assert web["attributes"]["kc-axi.managed"] == "acme"
    assert web["redirectUris"] == ["https://web/*"] and web["publicClient"] is True


# ------------------------------------------------------------------------------ plan_hash (C20, C21)


def test_c20_apply_with_the_expected_hash_makes_plan_exit_0(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["https://old/*"])])
    file = config_file(tmp_path, WEB)
    code, preview = run_json("--file", file)
    assert code == 1
    code, parsed = run_json("--file", file, "--yes", "--expect", preview["plan_hash"])
    assert code == 0 and parsed["status"] == "applied" and parsed["plan_hash"] == preview["plan_hash"]
    assert kc.client("acme", "web")["redirectUris"] == ["https://web/*"]
    out = io.StringIO()
    assert main(["plan", "--file", file], out=out, err=io.StringIO()) == 0


def test_c21_a_stale_hash_is_plan_changed_and_changes_nothing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["https://old/*"])])
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes", "--expect", "0123456789abcdef")
    assert code == 1 and error_of(parsed)["code"] == "plan_changed"
    assert "refusals" not in error_of(parsed)
    assert kc.writes == []


def test_a_malformed_expect_is_flag_not_valid_before_any_request(kc, env, tmp_path):
    kc.add_realm("acme")
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes", "--expect", "nope")
    assert code == 2 and error_of(parsed)["code"] == "flag_not_valid"
    assert kc.writes == [] and not env.secrets.exists()


# ------------------------------------------------------------------------------ declared fields only (C24)


def test_c24_a_field_the_file_does_not_declare_keeps_its_server_value(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["https://old/*"],
                                              description="kept", baseUrl="https://web")])
    assert run("--file", config_file(tmp_path, WEB), "--yes")[0] == 0
    web = kc.client("acme", "web")
    assert web["description"] == "kept" and web["baseUrl"] == "https://web"
    assert web["redirectUris"] == ["https://web/*"] and web["attributes"]["kc-axi.managed"] == "acme"


# ------------------------------------------------------------------------------ ownership and flags (C22, C33)


def test_c22_an_unmarked_declared_client_needs_adopt(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner=None, public=True)])
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "needs_adopt"
    assert error_of(parsed)["refusals"][0]["code"] == "needs_adopt"
    assert kc.writes == []


def test_c22_adopt_sets_the_marker_and_the_declared_fields(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner=None, public=True)])
    assert run("--file", config_file(tmp_path, WEB), "--yes", "--adopt")[0] == 0
    web = kc.client("acme", "web")
    assert web["attributes"]["kc-axi.managed"] == "acme" and web["redirectUris"] == ["https://web/*"]


def test_c22_a_managed_client_the_file_omits_is_removed_only_with_allow_delete(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("old", public=True)])
    file = config_file(tmp_path, "realm: {name: acme}\n")
    code, parsed = run_json("--file", file, "--yes")
    assert code == 1 and error_of(parsed)["code"] == "allow_delete_required" and kc.writes == []
    assert run("--file", file, "--yes", "--allow-delete")[0] == 0
    assert kc.client("acme", "old") is None


def test_c33_another_owners_client_is_never_removed(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("theirs", owner="other", public=True)])
    code, parsed = run_json("--file", config_file(tmp_path, "realm: {name: acme}\n"), "--yes", "--allow-delete")
    assert code == 0 and parsed["status"] == "already"
    assert kc.client("acme", "theirs") is not None


def test_a_declared_client_of_another_owner_is_owner_conflict(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner="other", public=True)])
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes", "--adopt", "--allow-delete")
    assert code == 1 and error_of(parsed)["code"] == "owner_conflict" and kc.writes == []


def test_several_refusals_are_all_listed_and_the_first_is_the_code(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner=None, public=True), live_client("old", public=True)])
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    error = error_of(parsed)
    assert code == 1 and error["code"] == "needs_adopt"
    assert [r["code"] for r in error["refusals"]] == ["needs_adopt", "allow_delete_required"]
    assert kc.writes == []


def test_flags_that_a_users_file_refuses_exit_2_flag_not_valid(kc, env, tmp_path):
    users = tmp_path / "acme.users.yaml"
    users.write_text(f"schema_version: 1\nkind: users\nrealm: acme\nusers:\n  - {{id: {UUID1}, username: amy}}\n",
                     encoding="utf-8")
    users.chmod(0o600)
    for flag in ("--adopt", "--allow-delete"):
        code, parsed = run_json("--file", str(users), "--yes", flag)
        assert code == 2 and error_of(parsed)["code"] == "flag_not_valid"
    assert kc.writes == []


# ------------------------------------------------------------------------------ remote guard (C28)


def test_c28_a_server_that_is_not_local_needs_allow_remote(kc, env, tmp_path, monkeypatch):
    # The fake speaks plain HTTP on loopback. Treat the host as remote, and skip the scheme check that would
    # refuse plain HTTP first (`insecure_url`), so that the write guard itself is what answers.
    monkeypatch.setattr(keycloak, "LOCAL_HOSTS", frozenset())
    monkeypatch.setattr(keycloak, "check_url_scheme", lambda url: None)
    kc.add_realm("acme")
    file = config_file(tmp_path, WEB)
    code, parsed = run_json("--file", file, "--yes")
    assert code == 1 and error_of(parsed)["code"] == "allow_remote_required" and kc.writes == []
    assert run("--file", file, "--yes", "--allow-remote")[0] == 0
    assert kc.client("acme", "web") is not None


# ------------------------------------------------------------------------------ mappers (C34)


MAPPED = ("realm: {name: acme}\nclients:\n  - {clientId: api, publicClient: true}\n"
          "  - clientId: web\n    publicClient: true\n    mappers:\n      - {name: aud, kind: audience, audience: api}\n")


def test_c34_a_mapper_is_created_after_its_client(kc, env, tmp_path):
    kc.add_realm("acme")
    code, parsed = run_json("--file", config_file(tmp_path, MAPPED), "--yes")
    assert code == 0, parsed
    paths = [w[1] for w in kc.writes if w[0] == "POST"]
    assert paths.index("/admin/realms/acme/clients") < paths.index(
        "/admin/realms/acme/clients/id-web/protocol-mappers/models")
    mapper = kc.client("acme", "web")["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.client.audience"] == "api"


def test_c34_a_mapper_is_removed_only_with_allow_delete(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", public=True),
                                  live_client("web", public=True, mappers=[live_mapper("aud"), live_mapper("extra")])])
    file = config_file(tmp_path, MAPPED)
    assert error_of(run_json("--file", file, "--yes")[1])["code"] == "allow_delete_required"
    assert run("--file", file, "--yes", "--allow-delete")[0] == 0
    assert [m["name"] for m in kc.client("acme", "web")["protocolMappers"]] == ["aud"]


def test_c34_a_client_with_no_mappers_key_keeps_its_mappers(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["https://web/*"],
                                              mappers=[live_mapper("keep")])])
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 0 and parsed["status"] == "already"
    assert [m["name"] for m in kc.client("acme", "web")["protocolMappers"]] == ["keep"]


def test_a_changed_mapper_audience_is_updated(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", public=True),
                                  live_client("web", public=True, mappers=[live_mapper("aud", audience="other")])])
    assert run("--file", config_file(tmp_path, MAPPED), "--yes")[0] == 0
    assert kc.client("acme", "web")["protocolMappers"][0]["config"]["included.client.audience"] == "api"


def test_a_mapper_for_an_audience_client_that_does_not_exist_is_not_found(kc, env, tmp_path):
    kc.add_realm("acme")
    text = ("realm: {name: acme}\nclients:\n  - clientId: web\n    publicClient: true\n    mappers:\n"
            "      - {name: aud, kind: audience, audience: ghost}\n")
    code, parsed = run_json("--file", config_file(tmp_path, text), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "not_found" and kc.writes == []


# ------------------------------------------------------------------------------ secrets (C37, C38, C62, C63)


@POSIX_ONLY
def test_c37_a_first_apply_writes_the_value_as_pending_before_the_client_and_active_after(kc, env, tmp_path):
    kc.add_realm("acme")
    seen = {}

    def before(method, path):
        if method == "POST" and path.endswith("/clients"):
            document = json.loads((env.secrets / "acme.secrets.json").read_text(encoding="utf-8"))
            seen["states"] = [g["state"] for g in document["generations"]]

    kc.before_write = before
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 0, parsed
    assert seen["states"] == ["pending"]
    document = json.loads((env.secrets / "acme.secrets.json").read_text(encoding="utf-8"))
    assert [g["state"] for g in document["generations"]] == ["active"]
    value = document["generations"][0]["clients"]["api"]["value"]
    assert kc.client("acme", "api")["secret"] == value
    assert (env.secrets / "acme.secrets.json").stat().st_mode & 0o077 == 0
    assert env.secrets.stat().st_mode & 0o077 == 0


def test_c37_no_secret_value_reaches_the_output_or_the_audit_file(kc, env, tmp_path):
    kc.add_realm("acme")
    code, text = run("--file", config_file(tmp_path, API), "--yes", "--json")
    value = secrets_store.read_secret(env.secrets, "acme", kc.url, "api")
    assert code == 0 and value not in text
    assert value not in env.audit.read_text(encoding="utf-8")


def test_c38_a_live_secret_client_with_no_value_in_the_file_is_secrets_missing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "secrets_missing" and kc.writes == []
    assert not (env.secrets / "acme.secrets.json").exists()


def test_c62_a_rebuilt_realm_gets_the_active_value_and_no_new_generation(kc, env, tmp_path):
    kc.add_realm("acme")
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "ACTIVE-VALUE"})
    secrets_store.mark_active(env.secrets, "acme", kc.url)
    assert run("--file", config_file(tmp_path, API), "--yes")[0] == 0
    assert kc.client("acme", "api")["secret"] == "ACTIVE-VALUE"
    assert [g["generation"] for g in secrets_store.list_generations(env.secrets, "acme", kc.url)["generations"]] == [1]
    code, _ = run("--file", config_file(tmp_path, API))
    assert code == 0


def test_c63_a_stale_generation_is_secrets_mismatch_and_changes_nothing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "FILE-VALUE"})
    secrets_store.mark_active(env.secrets, "acme", kc.url)
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "secrets_mismatch" and kc.writes == []


def test_a_secrets_file_that_cannot_be_parsed_is_the_refusal_secrets_unreadable(kc, env, tmp_path):
    kc.add_realm("acme")
    env.secrets.mkdir(mode=0o700)
    path = env.secrets / "acme.secrets.json"
    path.write_text("{not json", encoding="utf-8")
    path.chmod(0o600)
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "secrets_unreadable" and kc.writes == []


@POSIX_ONLY
def test_a_secrets_file_that_others_can_read_exits_2_before_the_lock(kc, env, tmp_path):
    kc.add_realm("acme")
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "v"})
    (env.secrets / "acme.secrets.json").chmod(0o644)
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 2 and error_of(parsed)["code"] == "unsafe_file_mode"
    assert kc.writes == [] and not (env.secrets / "kc-axi.lock").exists()


def test_finish_pending_when_the_live_value_is_the_active_one_sets_the_pending_value(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", secret="OLD")])
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "OLD"})
    secrets_store.mark_active(env.secrets, "acme", kc.url)
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "NEW"})
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes")
    assert code == 0, parsed
    assert kc.client("acme", "api")["secret"] == "NEW"
    assert secrets_store.read_secret(env.secrets, "acme", kc.url, "api") == "NEW"
    assert [r["action"] for r in audit_records(env) if r["phase"] == "intent"] == ["secret"]


def test_finish_pending_when_the_live_value_is_the_pending_one_writes_nothing_to_keycloak(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", secret="NEW")])
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "OLD"})
    secrets_store.mark_active(env.secrets, "acme", kc.url)
    secrets_store.write_pending(env.secrets, "acme", kc.url, ["api"], {"api": "NEW"})
    assert run("--file", config_file(tmp_path, API), "--yes")[0] == 0
    assert kc.writes == []
    assert secrets_store.read_secret(env.secrets, "acme", kc.url, "api") == "NEW"


def test_adopt_of_a_secret_client_captures_the_live_value_as_a_generation(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", owner=None, secret="HAND-MADE")])
    code, parsed = run_json("--file", config_file(tmp_path, API), "--yes", "--adopt")
    assert code == 0, parsed
    assert secrets_store.read_secret(env.secrets, "acme", kc.url, "api") == "HAND-MADE"
    assert kc.client("acme", "api")["secret"] == "HAND-MADE"
    assert kc.client("acme", "api")["attributes"]["kc-axi.managed"] == "acme"


# ------------------------------------------------------------------------------ partial runs (C70, C71)


TWO = ("realm: {name: acme}\nclients:\n  - {clientId: a-first, publicClient: true}\n"
       "  - {clientId: b-second, publicClient: true}\n")


def test_c70_the_second_action_fails_and_a_rerun_finishes_the_job(kc, env, tmp_path):
    kc.add_realm("acme")
    kc.rules.append({"method": "POST", "contains": "/clients", "status": 400, "message": "bad", "times": 1})
    file = config_file(tmp_path, TWO)
    # the first POST to /clients is refused: use the rule on the second call instead
    kc.rules[0]["times"] = 0
    calls = {"n": 0}

    def before(method, path):
        if method == "POST" and path.endswith("/clients"):
            calls["n"] += 1
            if calls["n"] == 2:
                kc.rules[0]["times"] = 1

    kc.before_write = before
    code, parsed = run_json("--file", file, "--yes")
    error = error_of(parsed)
    assert code == 1 and error["code"] == "apply_partial"
    assert error["applied"] == 1 and error["pending"] == 1 and error["cause"] == "keycloak_rejected"
    assert [(c["kind"], c["name"]) for c in error["created"]] == [("client", "a-first")]
    code, parsed = run_json("--file", file, "--yes")
    assert code == 0 and parsed["applied"] == 1 and kc.client("acme", "b-second") is not None


def test_c70_the_audit_file_marks_the_failed_action_as_an_error(kc, env, tmp_path):
    kc.add_realm("acme")
    kc.rules.append({"method": "POST", "contains": "/clients", "status": 400, "message": "bad"})
    assert run("--file", config_file(tmp_path, WEB), "--yes")[0] == 1
    records = audit_records(env)
    intent = next(r for r in records if r["phase"] == "intent")
    result = next(r for r in records if r["phase"] == "result" and r["id"] == intent["id"])
    assert result["outcome"] == "error" and result["code"] == "keycloak_rejected"


def test_c71_a_write_that_times_out_is_not_retried_and_counts_as_pending(kc, env, tmp_path):
    kc.add_realm("acme")
    kc.rules.append({"method": "POST", "contains": "/clients", "drop": True, "times": 99})
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    error = error_of(parsed)
    assert code == 1 and error["code"] == "apply_partial"
    assert error["cause"] == "keycloak_timeout" and error["applied"] == 0 and error["pending"] == 1
    assert len(kc.written("POST", "/clients")) == 1


# ------------------------------------------------------------------------------ re-enable guard (C77)


def disable_record(env, kind: str, name: str) -> None:
    record = {"schema_version": 1, "phase": "intent", "id": "x", "command": "disable-client", "kind": kind,
              "name": name, "action": "disable"}
    env.audit.write_text(json.dumps(record) + "\n", encoding="utf-8")


ENABLED = "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, enabled: true}\n"


def test_c77_apply_refuses_to_enable_a_client_that_disable_client_turned_off(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, enabled=False)])
    disable_record(env, "client", "web")
    code, parsed = run_json("--file", config_file(tmp_path, ENABLED), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "reenable_refused" and kc.writes == []


def test_c77_allow_reenable_lifts_it_and_writes_an_enable_record(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, enabled=False)])
    disable_record(env, "client", "web")
    assert run("--file", config_file(tmp_path, ENABLED), "--yes", "--allow-reenable")[0] == 0
    assert kc.client("acme", "web")["enabled"] is True
    records = audit_records(env)
    enable = [r for r in records if r["phase"] == "intent" and r.get("action") == "enable"]
    assert len(enable) == 1 and enable[0]["name"] == "web"
    assert any(r["phase"] == "result" and r["id"] == enable[0]["id"] and r["outcome"] == "ok" for r in records)


def test_a_later_enable_record_clears_the_guard(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, enabled=False)])
    disable_record(env, "client", "web")
    with env.audit.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"phase": "intent", "kind": "client", "name": "web", "action": "enable"}) + "\n")
    assert run("--file", config_file(tmp_path, ENABLED), "--yes")[0] == 0


# ------------------------------------------------------------------------------ audit, paths and the lock


def test_every_action_has_an_intent_before_and_a_result_after(kc, env, tmp_path):
    kc.add_realm("acme")
    assert run("--file", config_file(tmp_path, WEB), "--yes")[0] == 0
    records = audit_records(env)
    intents = [r for r in records if r["phase"] == "intent"]
    assert [(r["action"], r["kind"], r["name"]) for r in intents] == [("create", "client", "web")]
    assert records[0]["phase"] == "intent" and records[1]["phase"] == "result" and records[1]["outcome"] == "ok"
    assert intents[0]["command"] == "apply" and intents[0]["realm"] == "acme"


def test_no_audit_path_exits_2_before_the_lock_and_any_request(kc, env, tmp_path):
    env.config.write_text(f"schema_version: 1\nbase_url: {kc.url}\nport: {kc.port}\nsecrets_dir: {env.secrets}\n",
                          encoding="utf-8")
    kc.add_realm("acme")
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 2 and error_of(parsed)["code"] == "audit_required"
    assert not env.secrets.exists() and kc.writes == []


def test_a_secrets_dir_in_a_git_work_tree_is_unsafe_path_and_no_directory_is_made(kc, env, tmp_path, monkeypatch):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    monkeypatch.setenv("KC_AXI_SECRETS_DIR", str(tmp_path / "repo" / "secrets"))
    kc.add_realm("acme")
    code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 2 and error_of(parsed)["code"] == "unsafe_path"
    assert not (tmp_path / "repo" / "secrets").exists() and kc.writes == []


def test_a_run_that_holds_the_lock_makes_a_second_run_exit_1_locked(kc, env, tmp_path):
    kc.add_realm("acme")
    with RunLock.acquire(env.secrets):
        code, parsed = run_json("--file", config_file(tmp_path, WEB), "--yes")
    assert code == 1 and error_of(parsed)["code"] == "locked" and kc.writes == []
    assert run("--file", config_file(tmp_path, WEB), "--yes")[0] == 0  # the lock ended with the first holder


def test_a_bad_file_exits_2_before_the_audit_file_or_the_lock(kc, env, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema_version: 1\nkind: config\nowner: acme\nrealm: {name: acme}\nbogus: 1\n", encoding="utf-8")
    code, parsed = run_json("--file", str(bad), "--yes")
    assert code == 2 and error_of(parsed)["code"] == "unknown_field"
    assert not env.secrets.exists() and not env.audit.exists()


def test_a_config_file_without_owner_exits_2_owner_required(kc, env, tmp_path):
    path = tmp_path / "noowner.yaml"
    path.write_text("schema_version: 1\nkind: config\nrealm: {name: acme}\n", encoding="utf-8")
    code, parsed = run_json("--file", str(path), "--yes")
    assert code == 2 and error_of(parsed)["code"] == "owner_required"


# ------------------------------------------------------------------------------ realm change


def test_a_realm_change_sends_only_the_declared_fields_that_differ(kc, env, tmp_path):
    kc.add_realm("acme", displayName="Old")
    code, _ = run("--file", config_file(tmp_path, "realm: {name: acme, displayName: New}\n"), "--yes")
    assert code == 0
    assert kc.written("PUT") == [("PUT", "/admin/realms/acme", {"displayName": "New"})]
