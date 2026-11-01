"""Read commands: `realms`, `clients`, `users` and `get` (spec sections 3.2, 4.2, 4.3 and 5.1).

The functions take a `KeycloakClient` and return a payload for `output`. They print nothing.

Facts probed live on Keycloak 26.6.4 on 2026-10-27 (task I5):
- `GET /users` with no `max` returns at most 100 users. The tool pages with `first` and `max`, and takes the
  total from `/users/count`, so a long list is never cut without the header saying so.
- `GET /users` orders by username and keeps that order across pages. It does not list service-account users.
- `GET /clients` has no cap and no `/count`. Its order is not by `clientId`, so the tool sorts it.
- `GET /clients` returns the field `secret` for a confidential client. The tool copies only the fields of
  `CLIENT_FIELDS`, so no secret reaches an output (spec section 5.4).
- An exact `username` lookup ignores case (Keycloak stores usernames in lower case). An exact `clientId` lookup
  does not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .desired import BUILTIN_CLIENTS  # noqa: F401  (clients that Keycloak creates in every realm; never listed)
from .errors import KcAxiError
from .keycloak import KeycloakClient
from .output import DEFAULT_LIMIT, Records, list_payload, page
from .resources import KINDS, Kind, select_fields

#: The marker attribute that `apply` sets on a client it manages (spec section 3.4).
MANAGED_ATTRIBUTE = "kc-axi.managed"

#: The only client fields the tool copies. `secret` is not here (spec section 5.4).
CLIENT_FIELDS = ("id", "clientId", "enabled", "publicClient", "protocol", "attributes")

#: Users per request. Keycloak's own cap is 100.
USER_PAGE = 100


# ----------------------------------------------------------------------------- shaping


def client_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    """One client through the allow-list, with `managed` set to the owner name or None."""
    safe = {name: raw.get(name) for name in CLIENT_FIELDS if name in raw}
    attributes = safe.pop("attributes", None)
    owner = attributes.get(MANAGED_ATTRIBUTE) if isinstance(attributes, Mapping) else None
    safe["managed"] = owner if isinstance(owner, str) and owner else None
    return safe


def realm_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": raw.get("realm"),
        "enabled": raw.get("enabled"),
        "displayName": raw.get("displayName"),
        "accessTokenLifespan": raw.get("accessTokenLifespan"),
    }


def user_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {name: raw.get(name) for name in ("id", "username", "enabled", "email", "emailVerified")}


def _sorted(rows: Sequence[Mapping[str, Any]], key: str) -> list[Mapping[str, Any]]:
    return sorted(rows, key=lambda row: (str(row.get(key) or "").lower(), str(row.get(key) or "")))


def _project(rows: Sequence[Mapping[str, Any]], columns: Sequence[str]) -> list[dict[str, Any]]:
    return [{c: row.get(c) for c in columns} for row in rows]


def _realm_checked(realm: str, what: str, total: int) -> str:
    return f"realm {realm}, {total} {what}"


def require_realm(realm: str) -> str:
    """The realm name for a command that needs one. Exit 2, `realm_required`, with none."""
    if not realm:
        raise KcAxiError(
            "realm_required",
            "no realm: --realm, KC_AXI_REALM and default_realm are all empty",
            help=("kc-axi clients --realm <name>", "set default_realm in the configuration file"),
        )
    return realm


def _realm_missing(realm: str, err: KcAxiError) -> KcAxiError:
    """Keycloak answers 404 for an unknown realm. Say which realm, and what exists."""
    return KcAxiError(
        "not_found",
        f"realm {realm} does not exist",
        help=("kc-axi realms",),
        realm=realm,
    ) if err.code == "not_found" else err


# ----------------------------------------------------------------------------- lists


def list_realms(client: KeycloakClient, *, fields: str | None = None, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    columns = select_fields(KINDS["realm"], fields)
    rows = _sorted([realm_view(r) for r in client.get("/admin/realms").body or []], "name")
    return list_payload(
        "realms",
        _project(rows, columns),
        columns=columns,
        checked=f"{len(rows)} realms",
        limit=limit,
        more_help=f"kc-axi realms --limit {len(rows)}",
    )


def live_clients(client: KeycloakClient, realm: str) -> list[dict[str, Any]]:
    """Every client of the realm except the built-in ones, sorted by `clientId`. Secrets are dropped."""
    try:
        raw = client.get(KeycloakClient.admin_path(realm, "clients")).body or []
    except KcAxiError as err:
        raise _realm_missing(realm, err) from err
    shaped = [client_view(c) for c in raw if c.get("clientId") not in BUILTIN_CLIENTS]
    return [dict(c) for c in _sorted(shaped, "clientId")]


def list_clients(
    client: KeycloakClient, realm: str, *, fields: str | None = None, limit: int = DEFAULT_LIMIT
) -> dict[str, Any]:
    columns = select_fields(KINDS["client"], fields)
    rows = live_clients(client, realm)
    return list_payload(
        "clients",
        _project(rows, columns),
        columns=columns,
        checked=_realm_checked(realm, "clients, built-in clients hidden", len(rows)),
        limit=limit,
        more_help=f"kc-axi clients --realm {realm} --limit {len(rows)}",
    )


def _user_count(client: KeycloakClient, realm: str) -> int:
    body = client.get(KeycloakClient.admin_path(realm, "users", "count")).body
    return int(body) if isinstance(body, int) and not isinstance(body, bool) else 0


def list_users(
    client: KeycloakClient, realm: str, *, fields: str | None = None, limit: int = DEFAULT_LIMIT
) -> dict[str, Any]:
    """Users of the realm. One request fetches the first `limit` users, and `/users/count` gives the total."""
    columns = select_fields(KINDS["user"], fields)
    try:
        total = _user_count(client, realm)
    except KcAxiError as err:
        raise _realm_missing(realm, err) from err
    shown: list[dict[str, Any]] = []
    first = 0
    while len(shown) < min(limit, total):
        want = min(USER_PAGE, limit - len(shown))
        chunk = client.get(
            KeycloakClient.admin_path(realm, "users"), query={"first": first, "max": want}
        ).body or []
        if not chunk:
            break
        shown.extend(user_view(u) for u in chunk)
        first += len(chunk)
    rows = _project(shown, columns)
    if total == 0:
        return list_payload("users", [], columns=columns, checked=_realm_checked(realm, "users", 0))
    records = Records(tuple(rows), total, tuple(columns))
    payload: dict[str, Any] = {"status": "active", "total": total, "items": records}
    if records.shown < total:
        payload["help"] = [f"kc-axi users --realm {realm} --limit {total}"]
    return payload


# ----------------------------------------------------------------------------- get


def _one(kind: Kind, key: str, row: Mapping[str, Any] | None, realm: str | None) -> dict[str, Any]:
    if row is None:
        where = f" in realm {realm}" if realm else ""
        plural = {"realm": "realms", "client": "clients", "user": "users"}[kind.name]
        help_ = (f"kc-axi {plural}" + (f" --realm {realm}" if realm else ""),)
        raise KcAxiError("not_found", f"{kind.name} {key} does not exist{where}", help=help_, kind=kind.name, name=key)
    return {"status": "active", "kind": kind.name, **{k: row.get(k) for k in kind.fields}}


def get_object(
    client: KeycloakClient, kind_name: str, key: str, realm: str, *, fields: str | None = None
) -> dict[str, Any]:
    """One object by its human key (spec section 3.2). `get` shows the default fields, and `--fields` adds more."""
    kind = KINDS[kind_name]
    columns = select_fields(kind, fields)
    if kind_name == "realm":
        row = _find_realm(client, key)
        return _trim(_one(kind, key, row, None), kind, columns)
    realm = require_realm(realm)
    if kind_name == "client":
        return _trim(_one(kind, key, _find_client(client, realm, key), realm), kind, columns)
    row = _find_user(client, realm, key)
    return _trim(_one(kind, key, row, realm), kind, columns)


def _trim(result: dict[str, Any], kind: Kind, columns: Sequence[str]) -> dict[str, Any]:
    out = {"status": result["status"], "kind": result["kind"]}
    out.update({c: result.get(c) for c in columns})
    return out


def _find_realm(client: KeycloakClient, name: str) -> dict[str, Any] | None:
    try:
        raw = client.get(KeycloakClient.admin_path(name)).body
    except KcAxiError as err:
        if err.code == "not_found":
            return None
        raise
    return realm_view(raw) if isinstance(raw, Mapping) else None


def _find_client(client: KeycloakClient, realm: str, client_id: str) -> dict[str, Any] | None:
    """An exact `clientId` lookup (case-sensitive). `get` finds a built-in client too: lists hide them, a named lookup does not."""
    try:
        found = client.get(KeycloakClient.admin_path(realm, "clients"), query={"clientId": client_id}).body or []
    except KcAxiError as err:
        raise _realm_missing(realm, err) from err
    match = next((c for c in found if c.get("clientId") == client_id), None)
    return client_view(match) if match is not None else None


def _find_user(client: KeycloakClient, realm: str, username: str) -> dict[str, Any] | None:
    try:
        found = client.get(
            KeycloakClient.admin_path(realm, "users"), query={"username": username, "exact": "true"}
        ).body or []
    except KcAxiError as err:
        raise _realm_missing(realm, err) from err
    return user_view(found[0]) if found else None
