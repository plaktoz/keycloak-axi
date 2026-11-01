"""Keycloak REST client (spec sections 4.4, 5.1, 5.4 and 6.2).

Standard library only (`urllib.request`). Values such as URLs, realm and timeouts come in as arguments;
this module does not read the configuration. It prints nothing: a warning is returned as a string and
the caller prints it on stderr.

Rules this module keeps:
- The admin token comes from a password grant on `admin-cli`. It lives 60 seconds (live check V4), so the
  client logs in again before it expires, and once more on HTTP 401. The token stays in memory only.
- A write is sent once. A write that times out or loses the connection gives `keycloak_timeout`; the caller
  decides what to do (criterion 71). The only repeat is after HTTP 401, where the server changed nothing.
- No password, token or request body appears in an error message.
- A write to a `base_url` that is not local needs `allow_remote` (criteria 27 and 28, guard part).
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .errors import KcAxiError

#: The three host names that count as local (spec section 5.4). Names are never resolved.
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: The tested major version of Keycloak (spec section 5.4).
TESTED_MAJOR = 26

#: Seconds before the token expires at which the client logs in again.
TOKEN_LEEWAY_SECONDS = 10.0

_ADMIN_CLIENT = "admin-cli"
_MAX_BODY = 8 * 1024 * 1024
_MAX_DETAIL = 400
_READ_METHODS = frozenset({"GET", "HEAD"})


# --------------------------------------------------------------------------- guards


def is_local_url(url: str) -> bool:
    """True when the host of `url` is one of the fixed local names. No DNS lookup."""
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    return host is not None and host in LOCAL_HOSTS


def require_local_for_write(base_url: str, allow_remote: bool) -> None:
    """The loopback guard (spec section 5.4). Commands call this in preflight, before any write.

    Raises `allow_remote_required` (exit 1) when the host is not local and `allow_remote` is false.
    """
    if allow_remote or is_local_url(base_url):
        return
    host = _host_of(base_url)
    raise KcAxiError(
        "allow_remote_required",
        f"The server host '{host}' is not local, and the command would write to it.",
        help=("Add --allow-remote to write to a server that is not local",),
        host=host,
    )


def check_url_scheme(base_url: str) -> None:
    """Refuse plain HTTP to a host that is not local (`insecure_url`, exit 2), and other schemes."""
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise KcAxiError(
            "config_invalid",
            "base_url must be an http or https URL with a host.",
            help=("Set base_url, for example http://localhost:8080",),
        )
    if parts.scheme == "http" and not is_local_url(base_url):
        raise KcAxiError(
            "insecure_url",
            f"base_url uses plain http for the host '{parts.hostname}', which is not local.",
            help=("Use an https base_url for a server that is not local",),
        )


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


# --------------------------------------------------------------------------- version


def parse_major(version: str | None) -> int | None:
    """The major number of a version string such as `26.6.4`, or None."""
    if not version:
        return None
    match = re.match(r"\s*(\d+)(?:\.|$|-)", version)
    return int(match.group(1)) if match else None


def version_warning(version: str | None) -> str | None:
    """A warning for a server outside the tested range (26.x), or None. The caller prints it on stderr."""
    major = parse_major(version)
    if major == TESTED_MAJOR:
        return None
    if major is None:
        return (
            f"The Keycloak server version could not be read. The tested range is {TESTED_MAJOR}.x. "
            "The command runs; behaviour outside the tested release is not promised."
        )
    return (
        f"Keycloak {version} is outside the tested range {TESTED_MAJOR}.x. "
        "The command runs; behaviour outside the tested release is not promised."
    )


# --------------------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the admin token to another host, so none is followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _make_opener(scheme: str, ca_file: str | None) -> urllib.request.OpenerDirector:
    # An empty ProxyHandler: environment proxies must not see admin credentials or change loopback traffic.
    handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if scheme == "https":
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def probe(base_url: str, *, realm: str = "master", timeout: float = 2.0, ca_file: str | None = None) -> int | None:
    """GET `<base_url>/realms/<realm>` and return the HTTP status, or None when nothing answers in time.

    This is the probe of `status` (2 seconds) and the readiness poll of `up`. It needs no login.
    """
    base = base_url.rstrip("/")
    scheme = urllib.parse.urlsplit(base).scheme
    url = f"{base}/realms/{urllib.parse.quote(realm, safe='')}"
    opener = _make_opener(scheme, ca_file)
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=timeout) as resp:
            resp.read(_MAX_BODY)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (OSError, http.client.HTTPException, ValueError):
        return None


@dataclass
class Response:
    """A successful answer. `body` is the parsed JSON, or None when the body is empty or not JSON."""

    status: int
    body: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- client


class KeycloakClient:
    """One admin session against one Keycloak server.

    `command_timeout` bounds the whole life of the client (spec section 6.2); None means no bound.
    `clock` is a monotonic clock in seconds; tests inject a fake one.
    """

    def __init__(
        self,
        base_url: str,
        admin_user: str,
        admin_password: str,
        *,
        admin_realm: str = "master",
        request_timeout: float = 10.0,
        command_timeout: float | None = None,
        allow_remote: bool = False,
        ca_file: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        check_url_scheme(base_url)
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_realm = admin_realm
        self.request_timeout = float(request_timeout)
        self.allow_remote = allow_remote
        self.login_count = 0
        self._password = admin_password
        self._clock = clock
        self._deadline = None if command_timeout is None else clock() + float(command_timeout)
        self._token: str | None = None
        self._expires_at = 0.0
        self._opener = _make_opener(urllib.parse.urlsplit(self.base_url).scheme, ca_file)

    def __repr__(self) -> str:  # never show the credential or the token
        return f"KeycloakClient(base_url={self.base_url!r}, admin_user={self.admin_user!r})"

    # -- public API

    @staticmethod
    def admin_path(realm: str, *segments: str) -> str:
        """`/admin/realms/<realm>/<segments...>` with every part percent-encoded."""
        parts = [urllib.parse.quote(str(p), safe="") for p in (realm, *segments)]
        return "/admin/realms/" + "/".join(parts)

    def get(self, path: str, query: Mapping[str, Any] | None = None, **kw: Any) -> Response:
        return self.request("GET", path, query=query, **kw)

    def post(self, path: str, json_body: Any = None, **kw: Any) -> Response:
        return self.request("POST", path, json_body=json_body, **kw)

    def put(self, path: str, json_body: Any = None, **kw: Any) -> Response:
        return self.request("PUT", path, json_body=json_body, **kw)

    def delete(self, path: str, **kw: Any) -> Response:
        return self.request("DELETE", path, **kw)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        json_body: Any = None,
        ok_statuses: tuple[int, ...] = (),
    ) -> Response:
        """Send one request to the admin API.

        A 2xx answer, or a status in `ok_statuses`, comes back as a `Response`. A 404 raises `not_found`,
        another error status raises `keycloak_rejected`. After HTTP 401 the client logs in once more and
        repeats the request once; a second 401 raises `auth_failed`.
        """
        method = method.upper()
        write = method not in _READ_METHODS
        if write:
            require_local_for_write(self.base_url, self.allow_remote)
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        data = None if json_body is None else json.dumps(json_body).encode("utf-8")

        self._ensure_token()
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, resp_headers, body = self._transport(method, url, headers, data, write=write)
            if status == 401 and attempt == 0:
                self._login()
                continue
            break

        if status == 401:
            raise KcAxiError(
                "auth_failed",
                "Keycloak refused the admin token again after a new login.",
                help=("Check the admin user and its roles in the admin realm",),
                status=401,
            )
        if 200 <= status < 300 or status in ok_statuses:
            return Response(status, self._parse(body, resp_headers), dict(resp_headers.items()))
        self._raise_for_status(method, path, status, body)
        raise AssertionError("unreachable")  # pragma: no cover

    def server_version(self) -> str | None:
        """The server version from `GET /admin/serverinfo`, or None when the reply has none."""
        info = self.get("/admin/serverinfo").body
        version = info.get("systemInfo", {}).get("version") if isinstance(info, dict) else None
        return version if isinstance(version, str) else None

    def check_version(self) -> tuple[str | None, str | None]:
        """Return `(version, warning)`. The warning is None inside 26.x. The caller prints it on stderr."""
        version = self.server_version()
        return version, version_warning(version)

    # -- token

    def _ensure_token(self) -> None:
        if self._token is None or self._clock() >= self._expires_at - TOKEN_LEEWAY_SECONDS:
            self._login()

    def _login(self) -> None:
        realm = urllib.parse.quote(self.admin_realm, safe="")
        url = f"{self.base_url}/realms/{realm}/protocol/openid-connect/token"
        form = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": _ADMIN_CLIENT,
                "username": self.admin_user,
                "password": self._password,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        # A login changes nothing on the server, so it counts as a read.
        status, resp_headers, body = self._transport("POST", url, headers, form, write=False)
        self.login_count += 1
        if status in (400, 401):
            raise KcAxiError(
                "auth_failed",
                f"Keycloak refused the admin login for user '{self.admin_user}' in realm '{self.admin_realm}'.",
                help=(
                    "The image may not read the KC_BOOTSTRAP_ADMIN_* variable names",
                    "A volume that already holds an admin user keeps the old password",
                ),
                status=status,
            )
        if status != 200:
            self._raise_for_status("POST", f"/realms/{self.admin_realm}/protocol/openid-connect/token", status, body)
        parsed = self._parse(body, resp_headers)
        token = parsed.get("access_token") if isinstance(parsed, dict) else None
        if not isinstance(token, str) or not token:
            raise KcAxiError(
                "keycloak_rejected", "The login answer from Keycloak holds no access token.", status=status
            )
        expires_in = parsed.get("expires_in")
        lifetime = float(expires_in) if isinstance(expires_in, (int, float)) and expires_in > 0 else 60.0
        self._token = token
        self._expires_at = self._clock() + lifetime

    # -- internals

    def _timeout(self) -> float:
        if self._deadline is None:
            return self.request_timeout
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise KcAxiError(
                "keycloak_timeout",
                "The command passed command_timeout_seconds.",
                help=("Raise command_timeout_seconds, or run the command again",),
            )
        return min(self.request_timeout, remaining)

    def _transport(
        self, method: str, url: str, headers: dict[str, str], data: bytes | None, *, write: bool
    ) -> tuple[int, Mapping[str, str], bytes]:
        """One HTTP exchange, no retry. Returns the status for every HTTP answer, error statuses included."""
        timeout = self._timeout()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers, resp.read(_MAX_BODY)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(_MAX_BODY)
            except (OSError, http.client.HTTPException):
                body = b""
            return exc.code, exc.headers, body
        except (OSError, http.client.HTTPException, ValueError) as exc:
            cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            raise self._transport_error(cause, write=write, timeout=timeout) from None

    def _transport_error(self, cause: object, *, write: bool, timeout: float) -> KcAxiError:
        # A refused connection, an unresolvable name or a malformed URL means the request was never sent.
        # Any other failure of a write may have happened after Keycloak got it, so the outcome is unknown and
        # the write is reported as keycloak_timeout (spec section 5.4, criterion 71). A timeout while connecting
        # also lands here, which is the conservative choice.
        sent_nothing = isinstance(cause, (ConnectionRefusedError, socket.gaierror, ValueError))
        if write and not sent_nothing:
            return KcAxiError(
                "keycloak_timeout",
                f"No complete answer from {self.base_url} within {timeout:g} seconds. "
                "The write may or may not have happened.",
                help=("Run plan to see the current state, then decide whether to run the command again",),
            )
        if isinstance(cause, ssl.SSLError):
            detail = "the TLS handshake failed"
        elif isinstance(cause, (TimeoutError, socket.timeout)):
            detail = f"no answer within {timeout:g} seconds"
        else:
            detail = f"{type(cause).__name__}"
        return KcAxiError(
            "keycloak_unreachable",
            f"No answer from {self.base_url}: {detail}.",
            help=("Check that the server is running: kc-axi status",),
        )

    @staticmethod
    def _parse(body: bytes, headers: Mapping[str, str]) -> Any:
        """The JSON body of a 2xx answer, or None. A successful write is not reported as failed because of its body."""
        if not body:
            return None
        ctype = (headers.get("Content-Type") or "").lower()
        if "json" not in ctype:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _scrub(self, text: str) -> str:
        for secret in (self._password, self._token):
            if secret:
                text = text.replace(secret, "***")
        text = re.sub(r"\s+", " ", text).strip()
        return text if len(text) <= _MAX_DETAIL else text[:_MAX_DETAIL] + "..."

    def _raise_for_status(self, method: str, path: str, status: int, body: bytes) -> None:
        field_name: str | None = None
        detail = ""
        try:
            parsed = json.loads(body.decode("utf-8")) if body else None
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            parsed = parsed[0]
        if isinstance(parsed, dict):
            raw_field = parsed.get("field")
            field_name = raw_field if isinstance(raw_field, str) else None
            for key in ("errorMessage", "error_description", "error"):
                if isinstance(parsed.get(key), str):
                    detail = parsed[key]
                    break
        bare_path = path.split("?", 1)[0]
        if status == 404:
            raise KcAxiError(
                "not_found",
                self._scrub(f"Keycloak has no resource at {bare_path} (HTTP 404). {detail}"),
                status=404,
                path=bare_path,
            )
        message = f"Keycloak refused {method} {bare_path} with HTTP {status}"
        message += f": {detail}" if detail else "."
        extra: dict[str, Any] = {"status": status, "path": bare_path}
        if field_name:
            extra["field"] = field_name
        raise KcAxiError("keycloak_rejected", self._scrub(message), **extra)
