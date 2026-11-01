"""I5 acceptance: spec criteria 1, 2, 3 and 23 (read side), and the rules of sections 3.2, 4.2, 4.3 and 5.4.

A fake Keycloak copies the behaviour that a live probe saw on 26.6.4 on 2026-10-27 (see `kc_axi/reads.py`):
`GET /users` returns at most 100 rows, `GET /clients` returns a `secret` and no fixed order, an unknown realm
answers 404. Every request is recorded, so a test can check what the tool asked for.
"""

from __future__ import annotations

import io
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from kc_axi.cli import main
from kc_axi.credentials import admin_password, require_admin_password
from kc_axi.errors import KcAxiError

PASSWORD = "s3cret-admin-pw"
CLIENT_SECRET = "TOP-SECRET-CLIENT-VALUE"
BUILTINS = ["account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"]


class FakeKeycloak:
    def __init__(self) -> None:
        self.realms: dict[str, dict] = {}
        self.requests: list[str] = []
        self.version = "26.6.4"
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
                length = int(self.headers.get("Content-Length") or 0)
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
                if form.get("password") != [PASSWORD]:
                    return self._send(400, {"error": "invalid_grant"})
                self._send(200, {"access_token": "tok-1", "expires_in": 60})

            def do_GET(self):
                fake.requests.append(self.path)
                url = urllib.parse.urlsplit(self.path)
                query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
                parts = [urllib.parse.unquote(p) for p in url.path.split("/") if p]
                if not (self.headers.get("Authorization") or "").startswith("Bearer "):
                    return self._send(401, {"error": "no token"})
                if parts == ["admin", "serverinfo"]:
                    return self._send(200, {"systemInfo": {"version": fake.version}})
                if parts == ["admin", "realms"]:
                    return self._send(200, [dict(r["info"]) for r in fake.realms.values()])
                if parts[:2] != ["admin", "realms"] or len(parts) < 3:
                    return self._send(404, {"error": "unknown"})
                realm = fake.realms.get(parts[2])
                if realm is None:
                    return self._send(404, {"error": "Realm not found."})
                tail = parts[3:]
                if not tail:
                    return self._send(200, dict(realm["info"]))
                if tail == ["clients"]:
                    rows = list(realm["clients"])
                    if "clientId" in query:
                        rows = [c for c in rows if c["clientId"] == query["clientId"]]
                    return self._send(200, rows)
                if tail == ["users", "count"]:
                    return self._send(200, len(realm["users"]))
                if tail == ["users"]:
                    rows = sorted(realm["users"], key=lambda u: u["username"])
                    if "username" in query:
                        rows = [u for u in rows if u["username"] == query["username"].lower()]
                    first = int(query.get("first", 0))
                    rows = rows[first:first + int(query.get("max", 100))]  # Keycloak stops at 100 by itself
                    return self._send(200, rows[:100])
                self._send(404, {"error": "unknown"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def add_realm(self, name: str, *, users=(), clients=(), display: str | None = None) -> None:
        built = [
            {"id": f"id-{b}", "clientId": b, "enabled": True, "publicClient": b != "broker", "protocol": "openid-connect"}
            for b in BUILTINS
        ]
        self.realms[name] = {
            "info": {"realm": name, "enabled": True, "displayName": display, "accessTokenLifespan": 300},
            "clients": built + list(clients),
            "users": [
                {"id": f"u-{u}", "username": u, "enabled": True, "email": f"{u}@x.test", "emailVerified": False}
                for u in users
            ],
        }

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def client_row(client_id: str, *, public: bool = False, owner: str | None = None) -> dict:
    row = {
        "id": f"id-{client_id}", "clientId": client_id, "enabled": True, "publicClient": public,
        "protocol": "openid-connect",
    }
    if not public:
        row["secret"] = CLIENT_SECRET
    if owner:
        row["attributes"] = {"kc-axi.managed": owner}
    return row


@pytest.fixture
def kc():
    fake = FakeKeycloak()
    yield fake
    fake.close()


@pytest.fixture
def env(kc, tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(f"schema_version: 1\nbase_url: {kc.url}\nport: {kc.port}\n", encoding="utf-8")
    monkeypatch.setenv("KC_AXI_CONFIG", str(config))
    monkeypatch.setenv("KC_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.delenv("KC_AXI_REALM", raising=False)
    return config


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------- criterion 1, 2 and 3


def test_c1_empty_users_is_definitive(kc, env):
    kc.add_realm("acme")
    code, text, _ = run("users", "--realm", "acme")
    assert code == 0
    assert "status: empty" in text
    assert "total: 0" in text
    assert "users: none (realm acme, 0 users)" in text


def test_c1_empty_clients_says_built_ins_are_hidden(kc, env):
    kc.add_realm("acme")
    code, text, _ = run("clients", "--realm", "acme")
    assert code == 0
    assert "status: empty" in text
    assert "clients: none (realm acme, 0 clients, built-in clients hidden)" in text


def test_c2_twenty_one_users_show_twenty_and_name_the_next_command(kc, env):
    kc.add_realm("acme", users=[f"user{i:02d}" for i in range(21)])
    code, text, _ = run("users", "--realm", "acme")
    assert code == 0
    assert "items[20 of 21]{username,enabled}:" in text
    assert text.count("\n  user") == 20
    assert "kc-axi users --realm acme --limit 21" in text


def test_c2_limit_flag_shows_everything(kc, env):
    kc.add_realm("acme", users=[f"user{i:02d}" for i in range(21)])
    code, text, _ = run("users", "--realm", "acme", "--limit", "21")
    assert "items[21 of 21]" in text
    assert "help[" not in text


def test_c2_default_limit_comes_from_the_configuration_key(kc, env):
    env.write_text(env.read_text(encoding="utf-8") + "default_limit: 3\n", encoding="utf-8")
    kc.add_realm("acme", users=[f"user{i:02d}" for i in range(5)])
    _, text, _ = run("users", "--realm", "acme")
    assert "items[3 of 5]" in text


def test_a_long_user_list_is_not_cut_at_keycloaks_own_cap(kc, env):
    # Keycloak returns at most 100 users when asked for no maximum. The tool must report the real total.
    kc.add_realm("acme", users=[f"u{i:03d}" for i in range(109)])
    code, text, _ = run("users", "--realm", "acme", "--limit", "109", "--json")
    body = json.loads(text)
    assert (body["total"], body["shown"], len(body["items"])) == (109, 109, 109)


def test_users_header_counts_every_user_when_the_list_is_cut(kc, env):
    kc.add_realm("acme", users=[f"u{i:03d}" for i in range(109)])
    _, text, _ = run("users", "--realm", "acme", "--limit", "5")
    assert "items[5 of 109]" in text


def test_users_reads_one_page_not_the_whole_realm(kc, env):
    kc.add_realm("acme", users=[f"u{i:03d}" for i in range(109)])
    run("users", "--realm", "acme", "--limit", "5")
    user_calls = [r for r in kc.requests if "/users?" in r]
    assert len(user_calls) == 1
    assert "max=5" in user_calls[0]


def test_c3_a_value_with_comma_quote_and_space_keeps_the_count(kc, env):
    kc.add_realm("acme", clients=[client_row('we,ird "name" x', public=True)])
    code, text, _ = run("clients", "--realm", "acme")
    assert "items[1 of 1]" in text
    assert '"we,ird ""name"" x",true,null' in text


def test_max_cell_chars_from_the_configuration_cuts_long_values(kc, env):
    env.write_text(env.read_text(encoding="utf-8") + "max_cell_chars: 10\n", encoding="utf-8")
    kc.add_realm("acme", clients=[client_row("x" * 30, public=True)])
    _, text, _ = run("clients", "--realm", "acme")
    assert f"{'x' * 10}… (30 chars total)" in text


# --------------------------------------------------------------------- criterion 23 (read side)


def test_c23_built_in_clients_are_never_listed(kc, env):
    kc.add_realm("acme", clients=[client_row("acme-web", public=True)])
    _, text, _ = run("clients", "--realm", "acme")
    assert "acme-web" in text
    for name in BUILTINS:
        assert name not in text
    assert "items[1 of 1]" in text


def test_get_finds_a_built_in_client_when_it_is_named(kc, env):
    kc.add_realm("acme")
    code, text, _ = run("get", "client", "admin-cli", "--realm", "acme")
    assert code == 0
    assert "clientId: admin-cli" in text


# --------------------------------------------------------------------- secrets never reach an output


@pytest.mark.parametrize(
    "argv",
    [
        ("clients", "--realm", "acme"),
        ("clients", "--realm", "acme", "--json"),
        ("clients", "--realm", "acme", "--fields", "id,publicClient,protocol"),
        ("clients", "--realm", "acme", "--fields", "id,publicClient,protocol", "--json"),
        ("get", "client", "svc", "--realm", "acme"),
        ("get", "client", "svc", "--realm", "acme", "--json"),
        ("get", "client", "svc", "--realm", "acme", "--fields", "id,publicClient,protocol", "--json"),
    ],
)
def test_no_client_secret_in_any_output(kc, env, argv):
    kc.add_realm("acme", clients=[client_row("svc")])
    code, text, err = run(*argv)
    assert code == 0
    assert CLIENT_SECRET not in text + err
    assert PASSWORD not in text + err
    assert '"secret"' not in text


def test_secret_is_not_a_valid_field_name(kc, env):
    kc.add_realm("acme", clients=[client_row("svc")])
    code, text, _ = run("clients", "--realm", "acme", "--fields", "secret")
    assert code == 2
    assert "error: flag_not_valid" in text
    assert kc.requests == []  # refused before the first request


def test_a_bad_field_name_is_refused_before_login(kc, env):
    code, text, _ = run("users", "--realm", "acme", "--fields", "password")
    assert code == 2
    assert kc.requests == []


# --------------------------------------------------------------------- managed marker and sorting


def test_managed_column_shows_the_owner_or_null(kc, env):
    kc.add_realm("acme", clients=[client_row("b-api", owner="acme-team"), client_row("a-hand", public=True)])
    _, text, _ = run("clients", "--realm", "acme")
    assert "a-hand,true,null" in text
    assert "b-api,true,acme-team" in text


def test_clients_are_sorted_by_client_id_whatever_the_server_order(kc, env):
    kc.add_realm("acme", clients=[client_row(n, public=True) for n in ("zeta", "Alpha", "mid", "beta")])
    _, text, _ = run("clients", "--realm", "acme", "--json")
    assert [c["clientId"] for c in json.loads(text)["items"]] == ["Alpha", "beta", "mid", "zeta"]


def test_realms_lists_names_sorted(kc, env):
    kc.add_realm("zulu")
    kc.add_realm("acme", display="Acme Inc")
    _, text, _ = run("realms", "--fields", "displayName,accessTokenLifespan")
    assert text.index("acme") < text.index("zulu")
    assert "items[2 of 2]{name,enabled,displayName,accessTokenLifespan}:" in text
    assert "acme,true,Acme Inc,300" in text


# --------------------------------------------------------------------- get


def test_get_user_is_case_insensitive_and_shows_the_stored_name(kc, env):
    kc.add_realm("acme", users=["alice"])
    code, text, _ = run("get", "user", "Alice", "--realm", "acme")
    assert code == 0
    assert "username: alice" in text


def test_get_user_with_fields_adds_them(kc, env):
    kc.add_realm("acme", users=["alice"])
    _, text, _ = run("get", "user", "alice", "--realm", "acme", "--fields", "id,email")
    assert "email: alice@x.test" in text
    assert "id: u-alice" in text


def test_get_realm_needs_no_realm_flag(kc, env):
    kc.add_realm("acme", display="Acme Inc")
    code, text, _ = run("get", "realm", "acme", "--fields", "displayName")
    assert code == 0
    assert "displayName: Acme Inc" in text


def test_get_client_is_case_sensitive(kc, env):
    kc.add_realm("acme", clients=[client_row("Alpha", public=True)])
    assert run("get", "client", "Alpha", "--realm", "acme")[0] == 0
    code, text, _ = run("get", "client", "alpha", "--realm", "acme")
    assert code == 1
    assert "error: not_found" in text


def test_get_missing_object_is_not_found_with_a_hint(kc, env):
    kc.add_realm("acme")
    code, text, _ = run("get", "user", "nobody", "--realm", "acme")
    assert code == 1
    assert "error: not_found" in text
    assert "user nobody does not exist in realm acme" in text
    assert "kc-axi users --realm acme" in text


def test_get_json_has_the_envelope(kc, env):
    kc.add_realm("acme", users=["alice"])
    _, text, _ = run("get", "user", "alice", "--realm", "acme", "--json")
    body = json.loads(text)
    assert body["schema_version"] == 1 and body["command"] == "get"
    assert body["username"] == "alice"


# --------------------------------------------------------------------- realm resolution and errors


def test_unknown_realm_is_not_found_and_names_the_realm(kc, env):
    code, text, _ = run("clients", "--realm", "nope")
    assert code == 1
    assert "error: not_found" in text
    assert "realm nope does not exist" in text
    assert "kc-axi realms" in text


def test_no_realm_exits_2_realm_required_before_any_request(kc, env):
    code, text, _ = run("users")
    assert code == 2
    assert "error: realm_required" in text
    assert kc.requests == []


def test_realm_from_the_environment(kc, env, monkeypatch):
    kc.add_realm("acme", users=["alice"])
    monkeypatch.setenv("KC_AXI_REALM", "acme")
    code, text, _ = run("users")
    assert code == 0 and "alice" in text


def test_realm_from_default_realm_in_the_file(kc, env):
    env.write_text(env.read_text(encoding="utf-8") + "default_realm: acme\n", encoding="utf-8")
    kc.add_realm("acme", users=["alice"])
    assert "alice" in run("users")[1]


def test_json_output_for_a_list_has_the_contract_keys(kc, env):
    kc.add_realm("acme", users=["a", "b", "c"])
    _, text, _ = run("users", "--realm", "acme", "--limit", "2", "--json")
    body = json.loads(text)
    assert body["schema_version"] == 1 and body["command"] == "users"
    assert (body["status"], body["total"], body["shown"]) == ("active", 3, 2)


def test_realm_is_percent_encoded_in_the_path(kc, env):
    kc.add_realm("a b", users=["x"])
    code, text, _ = run("users", "--realm", "a b")
    assert code == 0
    assert any("/admin/realms/a%20b/" in r for r in kc.requests)


# --------------------------------------------------------------------- credentials and connection


def test_missing_password_exits_2_credential_missing_before_any_request(kc, env, monkeypatch):
    monkeypatch.delenv("KC_ADMIN_PASSWORD")
    code, text, _ = run("realms")
    assert code == 2
    assert "error: credential_missing" in text
    assert kc.requests == []


def test_wrong_password_exits_1_auth_failed_without_printing_it(kc, env, monkeypatch):
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "wrong-password-value")
    code, text, err = run("realms")
    assert code == 1
    assert "error: auth_failed" in text
    assert "wrong-password-value" not in text + err


def test_unreachable_server_exits_1_keycloak_unreachable(env, kc):
    kc.close()
    code, text, _ = run("realms")
    assert code == 1
    assert "error: keycloak_unreachable" in text


def test_a_server_outside_26_prints_a_warning_on_stderr_and_still_runs(kc, env):
    kc.version = "25.0.1"
    kc.add_realm("acme")
    code, text, err = run("realms")
    assert code == 0
    assert "warning:" in err and "25.0.1" in err
    assert "warning" not in text


def test_a_tested_server_prints_no_warning(kc, env):
    kc.add_realm("acme")
    assert run("realms")[2] == ""


def test_get_needs_a_kind_and_a_key(kc, env):
    code, text, _ = run("get", "user")
    assert code == 2
    assert kc.requests == []


def test_get_refuses_an_unknown_kind(kc, env):
    code, text, _ = run("get", "group", "x")
    assert code == 2


# --------------------------------------------------------------------- password sources (section 5.4)


def test_password_from_the_environment_wins_over_the_file(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file\n", encoding="utf-8")
    f.chmod(0o600)
    assert admin_password(f, {"KC_ADMIN_PASSWORD": "from-env"}) == "from-env"


def test_password_file_loses_one_trailing_lf(tmp_path):
    f = tmp_path / "pw"
    f.write_bytes(b"abc\n\n")
    f.chmod(0o600)
    assert admin_password(f, {}) == "abc\n"


def test_password_file_loses_one_trailing_crlf(tmp_path):
    f = tmp_path / "pw"
    f.write_bytes(b"abc\r\n")
    f.chmod(0o600)
    assert admin_password(f, {}) == "abc"


def test_password_file_readable_by_others_exits_2_unsafe_file_mode(tmp_path):
    f = tmp_path / "pw"
    f.write_text("abc", encoding="utf-8")
    f.chmod(0o644)
    with pytest.raises(KcAxiError) as caught:
        admin_password(f, {})
    assert caught.value.code == "unsafe_file_mode"
    assert caught.value.exit_code == 2
    assert "chmod 600" in caught.value.help[0]


def test_no_source_is_none_and_require_raises_credential_missing():
    assert admin_password(None, {}) is None
    with pytest.raises(KcAxiError) as caught:
        require_admin_password(None, {})
    assert caught.value.code == "credential_missing"


def test_an_empty_environment_variable_counts_as_not_set(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file", encoding="utf-8")
    f.chmod(0o600)
    assert admin_password(f, {"KC_ADMIN_PASSWORD": ""}) == "from-file"


def test_a_named_password_file_that_is_missing_is_credential_missing(tmp_path):
    with pytest.raises(KcAxiError) as caught:
        admin_password(tmp_path / "nope", {})
    assert caught.value.code == "credential_missing"


def test_password_file_is_used_by_the_cli(kc, env, tmp_path):
    kc.add_realm("acme")
    f = tmp_path / "pw"
    f.write_text(PASSWORD + "\n", encoding="utf-8")
    f.chmod(0o600)
    env.write_text(env.read_text(encoding="utf-8") + f"admin_password_file: {f}\n", encoding="utf-8")
    import os

    del os.environ["KC_ADMIN_PASSWORD"]
    code, text, _ = run("realms")
    assert code == 0 and "acme" in text
