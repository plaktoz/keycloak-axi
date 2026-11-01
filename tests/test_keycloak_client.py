"""Tests for the Keycloak REST client (task I3).

Unit tests use a fake HTTP server on loopback, so they need no container. Live tests carry the `runtime`
marker and skip when nothing answers on port 18083 or when no admin password is given in
`KC_AXI_I3_PASSWORD`.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kc_axi import keycloak
from kc_axi.errors import KcAxiError
from kc_axi.keycloak import (
    KeycloakClient,
    check_url_scheme,
    is_local_url,
    parse_major,
    probe,
    require_local_for_write,
    version_warning,
)

PASSWORD = "s3cret-pass-XYZ"
USER = "admin"


# --------------------------------------------------------------------------- fake server


class FakeKeycloak:
    """A small fake of the Keycloak endpoints the client uses. Records every request."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.token_requests = 0
        self.expires_in = 60
        self.version = "26.6.4"
        self.reject_next_tokens = 0  # answer the next N bearer-protected calls with 401
        self.always_401 = False
        self.login_status = 200  # status for a login with a good password
        self.delay: dict[str, float] = {}  # "METHOD path" -> seconds to wait before answering
        self.custom: dict[str, tuple[int, object]] = {}  # "METHOD path" -> (status, json body)
        self._issued = 0
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence
                pass

            def _send(self, status, body=None, headers=None):
                raw = b"" if body is None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                key = f"{self.command} {self.path}"
                with fake._lock:
                    fake.requests.append(
                        {"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"),
                         "body": raw}
                    )
                path = self.path.split("?")[0]
                if path.endswith("/protocol/openid-connect/token"):
                    form = urllib.parse.parse_qs(raw.decode("utf-8"))
                    with fake._lock:
                        fake.token_requests += 1
                        fake._issued += 1
                        n = fake._issued
                    if form.get("client_id") != ["admin-cli"] or form.get("grant_type") != ["password"]:
                        return self._send(400, {"error": "invalid_request"})
                    if form.get("password") != [PASSWORD]:
                        return self._send(
                            400, {"error": "invalid_grant", "error_description": "Invalid user credentials"}
                        )
                    if fake.login_status != 200:
                        return self._send(fake.login_status, {"error": "x"})
                    return self._send(
                        200,
                        {"access_token": f"tok-{n}", "expires_in": fake.expires_in, "refresh_token": "r",
                         "token_type": "Bearer"},
                    )
                if path.startswith("/realms/") and "/protocol/" not in path:
                    return self._send(200, {"realm": path.split("/")[2]})
                # Everything else needs a bearer token.
                with fake._lock:
                    reject = fake.always_401 or fake.reject_next_tokens > 0
                    if fake.reject_next_tokens > 0:
                        fake.reject_next_tokens -= 1
                if reject or not (self.headers.get("Authorization") or "").startswith("Bearer tok-"):
                    return self._send(401, {"error": "HTTP 401 Unauthorized"})
                wait = fake.delay.get(key)
                if wait:
                    time.sleep(wait)
                if key in fake.custom:
                    status, body = fake.custom[key]
                    return self._send(status, body)
                if path == "/admin/serverinfo":
                    return self._send(200, {"systemInfo": {"version": fake.version}})
                if self.command == "GET":
                    return self._send(200, [{"id": "1"}])
                if self.command == "POST":
                    return self._send(201, None, {"Location": "/x"})
                return self._send(204)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def api_requests(self, method: str | None = None) -> list[dict]:
        return [r for r in self.requests if "/protocol/" not in r["path"] and (method is None or r["method"] == method)]


@pytest.fixture
def fake():
    server = FakeKeycloak()
    yield server
    server.close()


def client_for(fake: FakeKeycloak, **kw) -> KeycloakClient:
    kw.setdefault("request_timeout", 3.0)
    return KeycloakClient(fake.url, USER, kw.pop("password", PASSWORD), **kw)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------------------- C4 unreachable


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_c4_nothing_listening_gives_keycloak_unreachable():
    client = KeycloakClient(f"http://127.0.0.1:{_closed_port()}", USER, PASSWORD, request_timeout=2.0)
    started = time.monotonic()
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "keycloak_unreachable"
    assert err.value.exit_code == 1
    assert time.monotonic() - started < 2.5


def test_c4_server_that_never_answers_gives_keycloak_unreachable_within_timeout():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        client = KeycloakClient(f"http://127.0.0.1:{port}", USER, PASSWORD, request_timeout=0.5)
        started = time.monotonic()
        with pytest.raises(KcAxiError) as err:
            client.get("/admin/realms")
        elapsed = time.monotonic() - started
    assert err.value.code == "keycloak_unreachable"
    assert elapsed < 1.5


def test_c4_unreachable_message_holds_no_secret():
    client = KeycloakClient(f"http://127.0.0.1:{_closed_port()}", USER, PASSWORD, request_timeout=1.0)
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert PASSWORD not in err.value.message
    assert all(PASSWORD not in line for line in err.value.help)


def test_probe_reports_status_or_none(fake):
    assert probe(fake.url) == 200
    assert probe(f"http://127.0.0.1:{_closed_port()}", timeout=1.0) is None


# --------------------------------------------------------------------------- C5 auth_failed


def test_c5_wrong_password_gives_auth_failed(fake):
    client = client_for(fake, password="not-the-password")
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "auth_failed"
    assert err.value.exit_code == 1
    assert "not-the-password" not in err.value.message
    assert PASSWORD not in err.value.message
    assert fake.api_requests() == []  # no admin call after a refused login


def test_login_is_a_password_grant_on_admin_cli(fake):
    client_for(fake).get("/admin/realms")
    first = fake.requests[0]
    assert first["method"] == "POST"
    assert first["path"] == "/realms/master/protocol/openid-connect/token"
    form = urllib.parse.parse_qs(first["body"].decode("utf-8"))
    assert form["grant_type"] == ["password"]
    assert form["client_id"] == ["admin-cli"]
    assert form["username"] == [USER]


def test_login_server_error_is_not_auth_failed(fake):
    fake.login_status = 500
    with pytest.raises(KcAxiError) as err:
        client_for(fake).get("/admin/realms")
    assert err.value.code == "keycloak_rejected"


# --------------------------------------------------------------------------- V4 token lifetime (fake clock)


def test_v4_token_is_renewed_before_it_expires(fake):
    clock = FakeClock()
    client = client_for(fake, clock=clock)
    client.get("/admin/realms")
    assert fake.token_requests == 1
    clock.now += 30  # still valid
    client.get("/admin/realms")
    assert fake.token_requests == 1
    clock.now += 25  # 55 s old: inside the 10 s leeway of the 60 s lifetime
    client.get("/admin/realms")
    assert fake.token_requests == 2
    assert fake.api_requests()[-1]["auth"] == "Bearer tok-2"


def test_v4_run_longer_than_60_seconds_keeps_working(fake):
    clock = FakeClock()
    client = client_for(fake, clock=clock)
    for _ in range(8):
        client.get("/admin/realms")
        clock.now += 20
    assert fake.token_requests >= 3
    assert all(r["auth"] and r["auth"].startswith("Bearer tok-") for r in fake.api_requests())


def test_expires_in_from_the_server_is_used(fake):
    fake.expires_in = 300
    clock = FakeClock()
    client = client_for(fake, clock=clock)
    client.get("/admin/realms")
    clock.now += 200
    client.get("/admin/realms")
    assert fake.token_requests == 1


# --------------------------------------------------------------------------- 401 handling


def test_read_after_401_logs_in_once_more_and_repeats(fake):
    client = client_for(fake)
    client.get("/admin/realms")
    fake.reject_next_tokens = 1
    resp = client.get("/admin/realms")
    assert resp.status == 200
    assert fake.token_requests == 2
    assert len(fake.api_requests("GET")) == 3  # first, rejected, repeated


def test_write_after_401_repeats_that_one_request_once(fake):
    client = client_for(fake)
    client.get("/admin/realms")
    fake.reject_next_tokens = 1
    resp = client.put("/admin/realms/acme/users/1", {"enabled": False})
    assert resp.status == 204
    assert fake.token_requests == 2
    assert len(fake.api_requests("PUT")) == 2  # the 401 changed nothing; one repeat


def test_second_401_gives_auth_failed_and_stops(fake):
    client = client_for(fake)
    client.get("/admin/realms")
    fake.always_401 = True
    with pytest.raises(KcAxiError) as err:
        client.put("/admin/realms/acme/users/1", {"enabled": False})
    assert err.value.code == "auth_failed"
    assert len(fake.api_requests("PUT")) == 2
    assert fake.token_requests == 2


def test_relogin_refused_gives_auth_failed(fake):
    client = client_for(fake)
    client.get("/admin/realms")
    fake.reject_next_tokens = 1
    client._password = "changed"
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "auth_failed"


# --------------------------------------------------------------------------- C71 writes are not retried


def test_c71_timed_out_write_gives_keycloak_timeout_and_is_sent_once(fake):
    client = client_for(fake, request_timeout=0.4)
    client.get("/admin/realms")  # token in place, so the login is not what times out
    fake.delay["PUT /admin/realms/acme/users/1"] = 1.5
    with pytest.raises(KcAxiError) as err:
        client.put("/admin/realms/acme/users/1", {"enabled": False})
    assert err.value.code == "keycloak_timeout"
    assert err.value.exit_code == 1
    time.sleep(1.8)  # let the slow handler finish, then count what the server saw
    assert len(fake.api_requests("PUT")) == 1


def test_c71_timed_out_post_is_sent_once(fake):
    client = client_for(fake, request_timeout=0.4)
    client.get("/admin/realms")
    fake.delay["POST /admin/realms/acme/partialImport"] = 1.5
    with pytest.raises(KcAxiError) as err:
        client.post("/admin/realms/acme/partialImport", {"users": []})
    assert err.value.code == "keycloak_timeout"
    time.sleep(1.8)
    assert len(fake.api_requests("POST")) == 1


def test_timed_out_read_is_keycloak_unreachable(fake):
    client = client_for(fake, request_timeout=0.4)
    client.get("/admin/realms")
    fake.delay["GET /admin/realms"] = 1.5
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "keycloak_unreachable"


def test_command_timeout_stops_the_run(fake):
    clock = FakeClock()
    client = client_for(fake, clock=clock, command_timeout=100)
    client.get("/admin/realms")
    clock.now += 101
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "keycloak_timeout"


# --------------------------------------------------------------------------- keycloak_rejected and not_found


def test_error_status_gives_keycloak_rejected_with_field(fake):
    client = client_for(fake)
    fake.custom["POST /admin/realms/acme/users"] = (
        409, {"errorMessage": "User exists with same username", "field": "username"})
    with pytest.raises(KcAxiError) as err:
        client.post("/admin/realms/acme/users", {"username": "u"})
    assert err.value.code == "keycloak_rejected"
    assert err.value.fields["field"] == "username"
    assert err.value.fields["status"] == 409
    assert "User exists with same username" in err.value.message


def test_http_500_gives_keycloak_rejected(fake):
    client = client_for(fake)
    fake.custom["POST /admin/realms/acme/partialImport"] = (500, {"error": "unknown_error"})
    with pytest.raises(KcAxiError) as err:
        client.post("/admin/realms/acme/partialImport", {})
    assert err.value.code == "keycloak_rejected"
    assert err.value.fields["status"] == 500


def test_404_gives_not_found(fake):
    client = client_for(fake)
    fake.custom["GET /admin/realms/nope"] = (404, {"error": "Realm not found."})
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms/nope")
    assert err.value.code == "not_found"


def test_ok_statuses_lets_a_404_through(fake):
    client = client_for(fake)
    fake.custom["GET /admin/realms/nope"] = (404, {"error": "Realm not found."})
    assert client.get("/admin/realms/nope", ok_statuses=(404,)).status == 404


def test_secret_echoed_by_the_server_is_removed_from_the_message(fake):
    client = client_for(fake)
    client.get("/admin/realms")
    fake.custom["PUT /admin/realms/acme/clients/1"] = (400, {"errorMessage": f"bad value {PASSWORD} and tok-1"})
    with pytest.raises(KcAxiError) as err:
        client.put("/admin/realms/acme/clients/1", {"secret": "x"})
    assert PASSWORD not in err.value.message
    assert "tok-1" not in err.value.message
    assert "***" in err.value.message


def test_request_body_is_never_in_an_error(fake):
    client = client_for(fake)
    fake.custom["PUT /admin/realms/acme/clients/1"] = (400, {"errorMessage": "invalid"})
    with pytest.raises(KcAxiError) as err:
        client.put("/admin/realms/acme/clients/1", {"secret": "client-secret-value"})
    assert "client-secret-value" not in err.value.message
    assert "client-secret-value" not in repr(err.value.fields)


def test_repr_hides_credentials(fake):
    text = repr(client_for(fake))
    assert PASSWORD not in text


def test_redirect_is_not_followed(fake):
    client = client_for(fake)
    fake.custom["GET /admin/realms"] = (302, {})
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "keycloak_rejected"


# --------------------------------------------------------------------------- C27 / C28 loopback guard


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8080", "http://127.0.0.1:18083", "http://[::1]:8080", "https://localhost", "http://LOCALHOST:8080"],
)
def test_local_urls(url):
    assert is_local_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://kc.example.com", "http://127.0.0.2:8080", "http://0.0.0.0:8080", "http://localhost.evil.com",
        "http://127.0.0.1.evil.com", "http://user@evil.com:80/@localhost", "http://[::2]:8080", "not a url", "",
    ],
)
def test_non_local_urls(url):
    assert not is_local_url(url)


def test_c27_c28_remote_write_without_flag_gives_allow_remote_required():
    with pytest.raises(KcAxiError) as err:
        require_local_for_write("https://kc.example.com", allow_remote=False)
    assert err.value.code == "allow_remote_required"
    assert err.value.exit_code == 1


def test_guard_passes_for_local_and_for_allow_remote():
    require_local_for_write("http://localhost:8080", allow_remote=False)
    require_local_for_write("https://kc.example.com", allow_remote=True)


def test_c27_c28_client_write_to_remote_is_refused_before_any_network_call():
    client = KeycloakClient("https://kc.invalid", USER, PASSWORD, request_timeout=1.0)
    for call in (
        lambda: client.put("/admin/realms/acme/users/1", {}),
        lambda: client.post("/admin/realms/acme/partialImport", {}),
        lambda: client.delete("/admin/realms/acme/clients/1"),
    ):
        with pytest.raises(KcAxiError) as err:
            call()
        assert err.value.code == "allow_remote_required"
    assert client.login_count == 0


def test_remote_read_is_not_refused_by_the_guard():
    # A read to a remote host is allowed without the flag; here it fails only because nothing answers.
    client = KeycloakClient("https://kc.invalid", USER, PASSWORD, request_timeout=1.0)
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "keycloak_unreachable"


def test_check_url_scheme():
    check_url_scheme("http://localhost:8080")
    check_url_scheme("https://kc.example.com")
    with pytest.raises(KcAxiError) as err:
        check_url_scheme("http://kc.example.com")
    assert err.value.code == "insecure_url"
    assert err.value.exit_code == 2
    with pytest.raises(KcAxiError) as err:
        check_url_scheme("ftp://localhost")
    assert err.value.code == "config_invalid"


# --------------------------------------------------------------------------- C72 version warning


@pytest.mark.parametrize("version", ["26.6.4", "26.0.0", "26.10.1-SNAPSHOT", "26"])
def test_c72_no_warning_inside_26x(version):
    assert version_warning(version) is None


@pytest.mark.parametrize("version", ["25.0.6", "27.0.0", "9.0.0", "", None, "nightly"])
def test_c72_warning_outside_26x(version):
    text = version_warning(version)
    assert isinstance(text, str) and "26.x" in text


def test_parse_major():
    assert parse_major("26.6.4") == 26
    assert parse_major("2600.1") == 2600
    assert parse_major("v26") is None


def test_c72_client_returns_the_warning_and_prints_nothing(fake, capsys):
    fake.version = "25.0.1"
    client = client_for(fake)
    version, warning = client.check_version()
    assert version == "25.0.1"
    assert warning and "25.0.1" in warning
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_c72_command_runs_after_the_warning(fake):
    fake.version = "27.1.0"
    client = client_for(fake)
    _, warning = client.check_version()
    assert warning
    assert client.get("/admin/realms").status == 200


def test_inside_range_has_no_warning(fake):
    assert client_for(fake).check_version() == ("26.6.4", None)


def test_missing_version_in_reply_gives_warning(fake):
    fake.custom["GET /admin/serverinfo"] = (200, {"systemInfo": {}})
    version, warning = client_for(fake).check_version()
    assert version is None and warning


# --------------------------------------------------------------------------- misc


def test_admin_path_encodes_each_part():
    assert KeycloakClient.admin_path("a b", "users", "x/y") == "/admin/realms/a%20b/users/x%2Fy"


def test_query_none_values_are_dropped(fake):
    client_for(fake).get("/admin/realms/acme/users", query={"max": 21, "first": 0, "q": None})
    path = fake.api_requests("GET")[-1]["path"]
    assert "max=21" in path and "first=0" in path and "q=" not in path


def test_module_source_is_standard_library_only():
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(keycloak.__file__).read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    import sys

    assert roots <= set(sys.stdlib_module_names) | {"kc_axi"}


# --------------------------------------------------------------------------- live (V4)

LIVE_URL = "http://127.0.0.1:18083"
LIVE_PASSWORD = os.environ.get("KC_AXI_I3_PASSWORD", "")


def _live_up() -> bool:
    return probe(LIVE_URL, timeout=1.0) == 200


live = pytest.mark.skipif(
    not (LIVE_PASSWORD and _live_up()),
    reason="no Keycloak on 127.0.0.1:18083 or KC_AXI_I3_PASSWORD not set",
)


def _raw_token(password: str) -> tuple[int, dict]:
    import urllib.error
    import urllib.request

    form = urllib.parse.urlencode(
        {"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": password}
    ).encode("utf-8")
    req = urllib.request.Request(f"{LIVE_URL}/realms/master/protocol/openid-connect/token", data=form, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


@pytest.mark.runtime
@live
def test_live_v4_token_grant_and_wrong_password():
    status, body = _raw_token(LIVE_PASSWORD)
    assert status == 200
    assert body["expires_in"] == 60
    assert body.get("refresh_token")
    bad_status, _ = _raw_token(LIVE_PASSWORD + "-wrong")
    assert bad_status == 400


@pytest.mark.runtime
@live
def test_live_wrong_password_maps_to_auth_failed():
    client = KeycloakClient(LIVE_URL, "admin", LIVE_PASSWORD + "-wrong", request_timeout=10)
    with pytest.raises(KcAxiError) as err:
        client.get("/admin/realms")
    assert err.value.code == "auth_failed"
    assert err.value.fields["status"] == 400


@pytest.mark.runtime
@live
def test_live_client_reads_version_and_survives_61_seconds():
    client = KeycloakClient(LIVE_URL, "admin", LIVE_PASSWORD, request_timeout=10)
    version, warning = client.check_version()
    assert version and version.startswith("26.")
    assert warning is None
    assert client.login_count == 1
    time.sleep(61)
    realms = client.get("/admin/realms").body
    assert any(r["realm"] == "master" for r in realms)
    assert client.login_count == 2  # the 60 s token was replaced, not reused
