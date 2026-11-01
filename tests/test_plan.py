"""I6 acceptance, plan half: spec sections 4.3 and 5.6 (steps 1 to 6), criteria 20, 21, 22, 23, 24, 25, 66, 68, 81.

A fake Keycloak copies the shapes that a live probe saw on 26.6.4 on 2026-10-27: `GET /clients` returns `secret`
and `protocolMappers` (the key is absent for a client with no mapper), and `GET /users/{id}/credentials` returns
an empty list for a user with no password. `plan` must never write, so the fake records every method.
"""

from __future__ import annotations

import io
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from kc_axi import secrets_store
from kc_axi.cli import main

PASSWORD = "s3cret-admin-pw"
LIVE_SECRET = "LIVE-CLIENT-SECRET-VALUE"
UUID1 = "7c1e0000-0000-4000-8000-000000000001"
UUID2 = "7c1e0000-0000-4000-8000-000000000002"
UUID3 = "7c1e0000-0000-4000-8000-000000000003"
AUD = {"included.client.audience": "api", "access.token.claim": "true", "introspection.token.claim": "true",
       "id.token.claim": "false"}


class FakeKeycloak:
    def __init__(self) -> None:
        self.realms: dict[str, dict] = {}
        self.methods: list[str] = []
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

            def do_POST(self):
                fake.methods.append("POST " + self.path)
                length = int(self.headers.get("Content-Length") or 0)
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
                if self.path.startswith("/realms/") and form.get("password") == [PASSWORD]:
                    return self._send(200, {"access_token": "tok-1", "expires_in": 60})
                self._send(400, {"error": "invalid_grant"})

            def do_PUT(self):
                fake.methods.append("PUT " + self.path)
                self._send(204)

            do_DELETE = do_PUT

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                fake.methods.append("GET")
                query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
                parts = [urllib.parse.unquote(p) for p in url.path.split("/") if p]
                if parts == ["admin", "serverinfo"]:
                    return self._send(200, {"systemInfo": {"version": "26.6.4"}})
                realm = fake.realms.get(parts[2]) if len(parts) > 2 else None
                if realm is None:
                    return self._send(404, {"error": "Realm not found."})
                tail = parts[3:]
                if not tail:
                    return self._send(200, realm["info"])
                if tail == ["clients"]:
                    rows = realm["clients"]
                    if "clientId" in query:
                        rows = [c for c in rows if c["clientId"] == query["clientId"]]
                    return self._send(200, rows)
                if tail == ["users"]:
                    rows = realm["users"]
                    if "username" in query:
                        rows = [u for u in rows if u["username"] == query["username"].lower()]
                    return self._send(200, rows)
                if len(tail) == 2 and tail[0] == "users":
                    user = next((u for u in realm["users"] if u["id"] == tail[1]), None)
                    return self._send(200, user) if user else self._send(404, {"error": "User not found"})
                if len(tail) == 3 and tail[0] == "users" and tail[2] == "credentials":
                    return self._send(200, realm["credentials"].get(tail[1], []))
                self._send(404, {"error": "unknown"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def add_realm(self, name: str, *, clients=(), users=(), credentials=None, **info) -> None:
        builtin = [{"id": f"id-{b}", "clientId": b, "enabled": True, "publicClient": True}
                   for b in ("account", "admin-cli", "broker")]
        self.realms[name] = {
            "info": {"realm": name, "enabled": True, "displayName": None, "accessTokenLifespan": 300,
                     "registrationAllowed": False, **info},
            "clients": builtin + list(clients),
            "users": list(users),
            "credentials": credentials or {},
        }

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def live_client(client_id: str, *, owner: str | None = "acme", public: bool = False, mappers=None, secret=True, **extra):
    row = {"id": f"id-{client_id}", "clientId": client_id, "enabled": True, "publicClient": public,
           "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
           "redirectUris": [], "webOrigins": [], "attributes": {}, **extra}
    if owner:
        row["attributes"]["kc-axi.managed"] = owner
    if not public and secret:
        row["secret"] = LIVE_SECRET
    if mappers is not None:
        row["protocolMappers"] = mappers
    return row


def live_mapper(name="aud", config=None):
    return {"id": f"m-{name}", "name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": dict(AUD if config is None else config)}


def live_user(user_id=UUID1, username="amy", **fields):
    return {"id": user_id, "username": username, "enabled": True, "emailVerified": False, **fields}


@pytest.fixture
def kc():
    fake = FakeKeycloak()
    yield fake
    fake.close()


@pytest.fixture
def env(kc, tmp_path, monkeypatch):
    secrets_dir = tmp_path / "secrets"
    config = tmp_path / "tool.yaml"
    config.write_text(
        f"schema_version: 1\nbase_url: {kc.url}\nport: {kc.port}\nsecrets_dir: {secrets_dir}\n", encoding="utf-8"
    )
    monkeypatch.setenv("KC_AXI_CONFIG", str(config))
    monkeypatch.setenv("KC_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("KC_AXI_REALM", raising=False)
    return secrets_dir


def desired(tmp_path: Path, text: str, name="acme.config.yaml") -> str:
    path = tmp_path / name
    path.write_text("schema_version: 1\nkind: config\nowner: acme\n" + text, encoding="utf-8")
    return str(path)


def users_file(tmp_path: Path, text: str) -> str:
    path = tmp_path / "acme.users.yaml"
    path.write_text("schema_version: 1\nkind: users\nrealm: acme\n" + text, encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def plan(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    code = main(["plan", *argv], out=out, err=err)
    text = out.getvalue()
    return code, text, err.getvalue()


def plan_json(*argv: str):
    code, text, _ = plan(*argv, "--json")
    return code, json.loads(text)


def rows(body: dict) -> list[tuple]:
    return [(a["action"], a["kind"], a["name"], a["detail"]) for a in body["actions"]]


# ------------------------------------------------------------------------------ status and exit code


def test_c68_a_realm_with_only_built_in_clients_and_none_declared_is_no_change(kc, env, tmp_path):
    kc.add_realm("acme")
    file = desired(tmp_path, "realm: {name: acme}\n")
    code, text, _ = plan("--file", file)
    assert code == 0
    assert text.startswith("status: no_change\n")
    assert "total: 0" in text
    assert "help[" not in text


def test_c20_a_changed_redirect_uri_is_drift_and_names_the_field(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["http://old/*"])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, redirectUris: ['http://new/*']}\n")
    code, text, _ = plan("--file", file)
    assert code == 1
    assert "status: drift" in text
    assert "change,client,web,redirectUris" in text
    assert "kc-axi apply --file" in text and "--expect" in text


def test_c20_after_the_server_matches_plan_exits_0(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["http://new/*"])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, redirectUris: ['http://new/*']}\n")
    assert plan("--file", file)[0] == 0


def test_a_missing_realm_is_a_create_and_has_no_clients_to_compare(kc, env, tmp_path):
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true}\n")
    code, body = plan_json("--file", file)
    assert code == 1
    assert rows(body) == [("create", "realm", "acme", ""), ("create", "client", "web", "")]


def test_a_realm_change_names_the_fields(kc, env, tmp_path):
    kc.add_realm("acme")
    file = desired(tmp_path, "realm: {name: acme, displayName: Acme, accessTokenLifespan: 900}\n")
    _, body = plan_json("--file", file)
    assert rows(body) == [("change", "realm", "acme", "accessTokenLifespan,displayName")]


def test_c24_a_field_the_file_does_not_declare_is_never_compared(kc, env, tmp_path):
    kc.add_realm("acme", displayName="Set by hand", accessTokenLifespan=1200,
                 clients=[live_client("web", public=True, redirectUris=["http://x/*"], standardFlowEnabled=True)])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true}\n")
    code, body = plan_json("--file", file)
    assert code == 0 and body["total"] == 0


def test_values_are_compared_after_normal_form(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", public=True, redirectUris=["b", "a"])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: 'true', redirectUris: [a, b, a]}\n")
    assert plan_json("--file", file)[0] == 0


def test_pkce_is_read_from_the_attribute(kc, env, tmp_path):
    web = live_client("web", public=True)
    kc.add_realm("acme", clients=[web])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, pkce: S256}\n")
    assert rows(plan_json("--file", file)[1]) == [("change", "client", "web", "pkce")]
    web["attributes"]["pkce.code.challenge.method"] = "S256"
    assert plan_json("--file", file)[0] == 0


def test_plan_writes_nothing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("old")])
    plan("--file", desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true}\n"))
    assert {m.split(" ")[0] for m in kc.methods} <= {"GET", "POST"}
    assert [m for m in kc.methods if m.startswith("POST")] == [m for m in kc.methods if "/protocol/openid-connect/token" in m]
    assert not any(m.startswith(("PUT", "DELETE")) for m in kc.methods)
    assert not env.exists()  # no secrets directory was made


# ------------------------------------------------------------------------------ ownership (C22, C66)


def test_c22_an_unmarked_client_is_unmanaged_and_not_an_action(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("hand", owner=None, public=True)])
    file = desired(tmp_path, "realm: {name: acme}\n")
    code, body = plan_json("--file", file)
    assert code == 0 and body["total"] == 0 and body["status"] == "no_change"
    assert body["unmanaged"] == [{"kind": "client", "name": "hand"}]


def test_c22_unmanaged_does_not_change_the_hash(kc, env, tmp_path):
    kc.add_realm("acme")
    file = desired(tmp_path, "realm: {name: acme}\n")
    before = plan_json("--file", file)[1]["plan_hash"]
    kc.realms["acme"]["clients"].append(live_client("hand", owner=None, public=True))
    assert plan_json("--file", file)[1]["plan_hash"] == before


def test_c22_a_declared_unmarked_client_is_adopt(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner=None, public=True, redirectUris=["http://old/*"])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, redirectUris: ['http://new/*']}\n")
    code, body = plan_json("--file", file)
    assert code == 1
    assert rows(body) == [("adopt", "client", "web", "redirectUris")]


def test_adopting_an_identical_client_still_sets_the_marker(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner=None, public=True)])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true}\n")
    assert rows(plan_json("--file", file)[1]) == [("adopt", "client", "web", "marker")]


def test_adopt_of_a_secret_client_says_capture(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", owner=None)])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, publicClient: false, secret_managed: true}\n")
    assert rows(plan_json("--file", file)[1]) == [("adopt", "client", "api", "marker,secret: capture")]


def test_c22_a_managed_client_the_file_does_not_declare_is_removed(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("stale", public=True)])
    code, body = plan_json("--file", desired(tmp_path, "realm: {name: acme}\n"))
    assert code == 1
    assert rows(body) == [("remove", "client", "stale", "")]
    assert body["unmanaged"] == []


def test_a_removed_client_does_not_list_its_mappers_again(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("stale", mappers=[live_mapper()])])
    assert rows(plan_json("--file", desired(tmp_path, "realm: {name: acme}\n"))[1]) == [("remove", "client", "stale", "")]


def test_c66_another_owners_client_is_owner_conflict(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("web", owner="zzz", public=True)])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true}\n")
    code, body = plan_json("--file", file)
    assert code == 1
    assert [r[0] for r in rows(body)] == ["owner_conflict"]


def test_another_owners_client_the_file_does_not_declare_is_unmanaged_not_removed(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("theirs", owner="zzz", public=True)])
    _, body = plan_json("--file", desired(tmp_path, "realm: {name: acme}\n"))
    assert body["total"] == 0
    assert body["unmanaged"] == [{"kind": "client", "name": "theirs"}]


def test_a_config_file_without_owner_exits_2_owner_required(kc, env, tmp_path):
    kc.add_realm("acme")
    path = tmp_path / "x.yaml"
    path.write_text("schema_version: 1\nkind: config\nrealm: {name: acme}\n", encoding="utf-8")
    code, text, _ = plan("--file", str(path))
    assert code == 2 and "error: owner_required" in text
    assert kc.methods == [] or all("GET" == m or "token" in m for m in kc.methods)


# ------------------------------------------------------------------------------ mappers


def test_a_mapper_is_created_when_missing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: [{name: aud, kind: audience, audience: api}]}\n")
    assert rows(plan_json("--file", file)[1]) == [("create", "mapper", "api/aud", "")]


def test_a_mapper_with_the_same_settings_is_no_change(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", mappers=[live_mapper()])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: [{name: aud, kind: audience, audience: api}]}\n")
    assert plan_json("--file", file)[0] == 0


def test_a_mapper_with_another_audience_is_a_change(kc, env, tmp_path):
    config = dict(AUD, **{"included.client.audience": "other"})
    kc.add_realm("acme", clients=[live_client("api", mappers=[live_mapper(config=config)])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: [{name: aud, kind: audience, audience: api}]}\n")
    assert rows(plan_json("--file", file)[1]) == [("change", "mapper", "api/aud", "audience")]


def test_a_mapper_with_other_claim_flags_is_a_change(kc, env, tmp_path):
    config = {"included.client.audience": "api"}
    kc.add_realm("acme", clients=[live_client("api", mappers=[live_mapper(config=config)])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: [{name: aud, kind: audience, audience: api}]}\n")
    assert rows(plan_json("--file", file)[1]) == [("change", "mapper", "api/aud", "claims")]


def test_c34_a_mapper_is_removed_only_when_the_client_has_a_mappers_key(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api", mappers=[live_mapper("old")])])
    keeps = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api}\n")
    assert plan_json("--file", keeps)[0] == 0
    removes = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: []}\n", "b.yaml")
    assert rows(plan_json("--file", removes)[1]) == [("remove", "mapper", "api/old", "")]


def test_a_mapper_that_is_not_an_audience_mapper_is_never_touched(kc, env, tmp_path):
    other = {"id": "m1", "name": "x", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": {}}
    kc.add_realm("acme", clients=[live_client("api", mappers=[other])])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: api, mappers: []}\n")
    assert plan_json("--file", file)[0] == 0


# ------------------------------------------------------------------------------ secrets


def seed_secrets(env: Path, kc: FakeKeycloak, value: str, state="active") -> None:
    secrets_store.write_pending(env, "acme", kc.url, ["api"], {"api": value})
    if state == "active":
        secrets_store.mark_active(env, "acme", kc.url)


API_FILE = "realm: {name: acme}\nclients:\n  - {clientId: api, publicClient: false, secret_managed: true}\n"


def test_a_live_secret_client_with_no_file_is_secret_missing(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    code, body = plan_json("--file", desired(tmp_path, API_FILE))
    assert code == 1
    assert rows(body) == [("secret_missing", "client", "api", "secret: not in the secrets file")]


def test_a_live_secret_that_equals_the_active_value_is_no_change(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    seed_secrets(env, kc, LIVE_SECRET)
    assert plan_json("--file", desired(tmp_path, API_FILE))[0] == 0


def test_a_live_secret_that_differs_from_the_active_value_is_a_secret_action(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    seed_secrets(env, kc, "another-value-in-the-file")
    code, body = plan_json("--file", desired(tmp_path, API_FILE))
    assert code == 1
    (action,) = rows(body)
    assert action[:3] == ("secret", "client", "api")
    assert secrets_store.fingerprint("another-value-in-the-file") in action[3]
    assert secrets_store.fingerprint(LIVE_SECRET) in action[3]


def test_a_pending_generation_is_a_finish_pending_row(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    seed_secrets(env, kc, LIVE_SECRET)
    secrets_store.write_pending(env, "acme", kc.url, ["api"], {"api": "next-value"})
    code, body = plan_json("--file", desired(tmp_path, API_FILE))
    assert code == 1 and rows(body)[0][:3] == ("finish_pending", "client", "api")


def test_a_create_of_a_secret_client_says_secret_new(kc, env, tmp_path):
    kc.add_realm("acme")
    assert rows(plan_json("--file", desired(tmp_path, API_FILE))[1]) == [
        ("create", "client", "api", "secret: new")
    ]


def test_a_secret_hash_holds_fingerprints_and_not_the_value(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    seed_secrets(env, kc, "another-value-in-the-file")
    file = desired(tmp_path, API_FILE)
    code, text, err = plan("--file", file)
    assert LIVE_SECRET not in text + err and "another-value-in-the-file" not in text + err


@pytest.mark.parametrize("extra", [[], ["--json"]])
def test_no_secret_value_reaches_any_output(kc, env, tmp_path, extra):
    kc.add_realm("acme", clients=[live_client("api"), live_client("other", owner=None)])
    seed_secrets(env, kc, "another-value-in-the-file")
    code, text, err = plan("--file", desired(tmp_path, API_FILE), *extra)
    for secret in (LIVE_SECRET, "another-value-in-the-file", PASSWORD):
        assert secret not in text + err


def test_a_secrets_file_for_another_server_exits_2(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("api")])
    secrets_store.write_pending(env, "acme", "http://elsewhere.example:8080", ["api"], {"api": "v"})
    code, text, _ = plan("--file", desired(tmp_path, API_FILE))
    assert code == 2 and "error: secrets_server_mismatch" in text


# ------------------------------------------------------------------------------ plan_hash (C21)


def test_the_hash_is_16_hex_digits_and_stable(kc, env, tmp_path):
    kc.add_realm("acme")
    file = desired(tmp_path, "realm: {name: acme, displayName: A}\n")
    first = plan_json("--file", file)[1]["plan_hash"]
    assert len(first) == 16 and int(first, 16) >= 0
    assert plan_json("--file", file)[1]["plan_hash"] == first


def test_c21_a_live_value_that_an_action_uses_changes_the_hash(kc, env, tmp_path):
    web = live_client("web", public=True, redirectUris=["http://old/*"])
    kc.add_realm("acme", clients=[web])
    file = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: web, publicClient: true, redirectUris: ['http://new/*']}\n")
    before = plan_json("--file", file)[1]["plan_hash"]
    web["redirectUris"] = ["http://changed/*"]
    after = plan_json("--file", file)[1]["plan_hash"]
    assert before != after


def test_a_different_file_gives_a_different_hash(kc, env, tmp_path):
    kc.add_realm("acme")
    one = plan_json("--file", desired(tmp_path, "realm: {name: acme, displayName: A}\n"))[1]["plan_hash"]
    two = plan_json("--file", desired(tmp_path, "realm: {name: acme, displayName: B}\n", "b.yaml"))[1]["plan_hash"]
    assert one != two


def test_crlf_and_lf_files_give_the_same_hash(kc, env, tmp_path):
    kc.add_realm("acme")
    text = "schema_version: 1\nkind: config\nowner: acme\nrealm: {name: acme, displayName: A}\n"
    lf = tmp_path / "lf.yaml"
    lf.write_bytes(text.encode("utf-8"))
    crlf = tmp_path / "crlf.yaml"
    crlf.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    assert plan_json("--file", str(lf))[1]["plan_hash"] == plan_json("--file", str(crlf))[1]["plan_hash"]


def test_the_hash_does_not_depend_on_the_order_of_clients_or_lists(kc, env, tmp_path):
    kc.add_realm("acme")
    a = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, redirectUris: [x, y]}\n  - {clientId: b}\n")
    b = desired(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: b}\n  - {clientId: a, redirectUris: [y, x]}\n", "b.yaml")
    assert plan_json("--file", a)[1]["plan_hash"] == plan_json("--file", b)[1]["plan_hash"]


def test_the_hash_names_the_server_so_two_servers_differ(kc, env, tmp_path, monkeypatch):
    kc.add_realm("acme")
    file = desired(tmp_path, "realm: {name: acme}\n")
    one = plan_json("--file", file)[1]["plan_hash"]
    other = FakeKeycloak()
    try:
        other.add_realm("acme")
        config = tmp_path / "tool2.yaml"
        config.write_text(f"schema_version: 1\nbase_url: {other.url}\nport: {other.port}\nsecrets_dir: {env}\n", encoding="utf-8")
        monkeypatch.setenv("KC_AXI_CONFIG", str(config))
        assert plan_json("--file", file)[1]["plan_hash"] != one
    finally:
        other.close()


# ------------------------------------------------------------------------------ output shape


def test_plan_never_truncates_actions_whatever_the_limit(kc, env, tmp_path):
    names = [f"c{i:02d}" for i in range(25)]
    kc.add_realm("acme", clients=[live_client(n, public=True) for n in names])
    _, text, _ = plan("--file", desired(tmp_path, "realm: {name: acme}\n"), "--limit", "3")
    assert "actions[25 of 25]" in text


def test_the_json_contract_of_plan(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("hand", owner=None, public=True)])
    code, body = plan_json("--file", desired(tmp_path, "realm: {name: acme, displayName: A}\n"))
    assert code == 1
    assert body["schema_version"] == 1 and body["command"] == "plan"
    assert set(body) >= {"status", "realm", "total", "shown", "actions", "unmanaged", "password_missing",
                         "profile_incomplete", "plan_hash"}
    assert body["actions"][0] == {"action": "change", "kind": "realm", "name": "acme", "detail": "displayName"}
    assert body["shown"] == body["total"] == 1  # `unmanaged` is not in total


def test_actions_follow_the_apply_order(kc, env, tmp_path):
    kc.add_realm("acme", clients=[live_client("stale", public=True), live_client("api", mappers=[live_mapper("old")])])
    file = desired(tmp_path, """realm: {name: acme, displayName: A}
clients:
  - {clientId: new, publicClient: true}
  - {clientId: api, mappers: [{name: aud, kind: audience, audience: api}]}
""")
    kinds = [(a[0], a[1]) for a in rows(plan_json("--file", file)[1])]
    assert kinds == [("change", "realm"), ("create", "client"), ("create", "mapper"), ("remove", "mapper"),
                     ("remove", "client")]


# ------------------------------------------------------------------------------ users file


def test_c81_a_declared_user_without_email_or_names_is_profile_incomplete(kc, env, tmp_path):
    kc.add_realm("acme")
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy, email: a@x.test}}\n")
    code, body = plan_json("--file", file)
    assert code == 1  # the create is an action
    assert body["profile_incomplete"] == [{"username": "amy", "missing": "firstName,lastName"}]
    assert rows(body) == [("create", "user", "amy", "")]


def test_c81_profile_incomplete_does_not_change_total_hash_or_exit_code(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user()], credentials={UUID1: [{"type": "password"}]})
    full = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy, email: a@x.test, firstName: A, lastName: B}}\n")
    kc.realms["acme"]["users"][0].update(email="a@x.test", firstName="A", lastName="B")
    ok_code, ok = plan_json("--file", full)
    assert ok_code == 0 and ok["profile_incomplete"] == []
    kc.realms["acme"]["users"][0].update(email=None, firstName=None, lastName=None)
    partial = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy}}\n")
    code, body = plan_json("--file", partial)
    assert code == 0 and body["total"] == 0
    assert body["profile_incomplete"] == [{"username": "amy", "missing": "email,firstName,lastName"}]


def test_a_live_value_fills_a_profile_field_the_file_leaves_out(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(email="a@x.test", firstName="A", lastName="B")], credentials={UUID1: [{"type": "password"}]})
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy}}\n")
    code, body = plan_json("--file", file)
    assert code == 0 and body["profile_incomplete"] == []


def test_password_missing_lists_a_user_with_no_password_and_a_variable(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(), live_user(UUID2, "bob")], credentials={UUID2: [{"type": "password"}]})
    file = users_file(tmp_path, f"""users:
  - {{id: '{UUID1}', username: amy, temporary_password_env: AMY_PW}}
  - {{id: '{UUID2}', username: bob, temporary_password_env: BOB_PW}}
  - {{id: '{UUID3}', username: cy}}
""")
    kc.realms["acme"]["users"].append(live_user(UUID3, "cy"))
    code, body = plan_json("--file", file)
    assert body["password_missing"] == [{"username": "amy"}]  # bob has one; cy names no variable
    assert code == 0 and body["total"] == 0  # informational only


def test_a_user_that_does_not_exist_is_a_create(kc, env, tmp_path):
    kc.add_realm("acme")
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy, email: a@x.test, firstName: A, lastName: B}}\n")
    assert rows(plan_json("--file", file)[1]) == [("create", "user", "amy", "")]


def test_a_user_with_a_different_field_is_a_change(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(email="old@x.test", firstName="A", lastName="B")])
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy, email: new@x.test, firstName: A, lastName: B, enabled: false}}\n")
    assert rows(plan_json("--file", file)[1]) == [("change", "user", "amy", "email,enabled")]


def test_c25_a_username_held_by_another_id_is_id_conflict(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(UUID2, "amy")])
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy}}\n")
    assert rows(plan_json("--file", file)[1]) == [("id_conflict", "user", "amy", "the username has another id")]


def test_c25_an_id_held_by_another_username_is_id_conflict(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(UUID1, "bob")])
    file = users_file(tmp_path, f"users:\n  - {{id: '{UUID1}', username: amy}}\n")
    assert rows(plan_json("--file", file)[1]) == [("id_conflict", "user", "amy", "the id has another username")]


def test_a_users_file_for_a_missing_realm_exits_1_realm_absent(kc, env, tmp_path):
    code, text, _ = plan("--file", users_file(tmp_path, "users: []\n"))
    assert code == 1 and "error: realm_absent" in text
    assert "kc-axi apply --file" in text


def test_the_users_file_is_never_removed_by_plan(kc, env, tmp_path):
    kc.add_realm("acme", users=[live_user(UUID2, "extra")])
    code, body = plan_json("--file", users_file(tmp_path, "users: []\n"))
    assert code == 0 and body["total"] == 0


# ------------------------------------------------------------------------------ flags and errors


def test_a_bad_file_exits_2_before_any_request(kc, env, tmp_path):
    bad = desired(tmp_path, "realm: {name: acme, sslRequired: all}\n")
    code, text, _ = plan("--file", bad)
    assert code == 2 and "error: unknown_field" in text
    assert kc.methods == []


def test_realm_flag_that_differs_exits_2_before_any_request(kc, env, tmp_path):
    code, text, _ = plan("--file", desired(tmp_path, "realm: {name: acme}\n"), "--realm", "other")
    assert code == 2 and "error: realm_mismatch" in text
    assert kc.methods == []


def test_file_is_required(kc, env):
    out = io.StringIO()
    assert main(["plan"], out=out, err=io.StringIO()) == 2
    assert "error:" in out.getvalue()


def test_missing_password_exits_2_credential_missing(kc, env, tmp_path, monkeypatch):
    monkeypatch.delenv("KC_ADMIN_PASSWORD")
    code, text, _ = plan("--file", desired(tmp_path, "realm: {name: acme}\n"))
    assert code == 2 and "error: credential_missing" in text


def test_unreachable_server_exits_1(kc, env, tmp_path):
    kc.close()
    code, text, _ = plan("--file", desired(tmp_path, "realm: {name: acme}\n"))
    assert code == 1 and "error: keycloak_unreachable" in text


def test_a_relative_file_path_is_read_from_the_working_directory(kc, env, tmp_path, monkeypatch):
    kc.add_realm("acme")
    desired(tmp_path, "realm: {name: acme}\n", "rel.yaml")
    monkeypatch.chdir(tmp_path)
    assert plan("--file", "rel.yaml")[0] == 0
