"""`plan`: the difference between a desired-state file and the server (spec sections 4.3 and 5.6, steps 1 to 6).

`make_plan` reads the live state and writes nothing. It takes no lock. It returns a `PlanResult`: the payload for
`output`, the exit code, and the facts that `apply` (I7, I9) reuses as its plan.

Facts probed live on Keycloak 26.6.4 on 2026-10-27 (task I6):
- `GET /clients` returns `protocolMappers` for a client that has any, and no such key for a client that has none.
  One request therefore gives the clients, their markers, their mappers and their secrets.
- `GET /users/{id}/credentials` returns an empty list for a user with no password.

A client secret goes only to `secrets_store.compare_live`, which answers with fingerprints. No secret value
reaches the plan, the hash or any output (spec section 5.4).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import secrets_store
from .desired import BUILTIN_CLIENTS, ConfigFile, UsersFile
from .errors import KcAxiError
from .keycloak import KeycloakClient
from .output import SCHEMA_VERSION, page
from .reads import MANAGED_ATTRIBUTE

PKCE_ATTRIBUTE = "pkce.code.challenge.method"
AUDIENCE_MAPPER = "oidc-audience-mapper"
AUDIENCE_KEY = "included.client.audience"
#: The claim flags that the tool sets on a mapper it creates (spec section 3.4).
MAPPER_CLAIMS = {"access.token.claim": "true", "introspection.token.claim": "true", "id.token.claim": "false"}
PROFILE_FIELDS = ("email", "firstName", "lastName")

# The order in which `apply` runs actions (spec section 5.6, apply step 9). The plan lists them in this order.
_PHASE = {
    "finish_pending": 0, "realm": 1, "client": 2, "mapper": 3, "user": 4, "remove-mapper": 5, "remove-client": 6,
}

_CLIENT_COMPARED = (
    "enabled", "publicClient", "standardFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled",
    "redirectUris", "webOrigins", "pkce",
)
_USER_COMPARED = ("enabled", "email", "emailVerified", "firstName", "lastName")


@dataclass
class PlanResult:
    """The result of `make_plan`.

    `body` is the payload for `output.emit`. `exit_code` is 0 for `no_change` and 1 for `drift`.
    `actions` are the rows of the plan with their hash detail. `live_clients` maps the `clientId` of every live
    client, built-in ones included, to its Keycloak `id`. `apply` uses it for the mapper targets and for the paths
    of its writes (I7).
    """

    body: dict[str, Any]
    exit_code: int
    plan_hash: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    live_clients: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------------------- helpers


def canonical_json(value: Any) -> str:
    """Sorted keys, `,` and `:` as separators, UTF-8 text (spec section 4.3, `plan_hash`)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _flag(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return default


def _action(
    action: str, kind: str, name: str, detail: str = "", *, phase: str | None = None, **hash_extra: Any
) -> dict[str, Any]:
    return {"phase": _PHASE[phase or kind], "action": action, "kind": kind, "name": name, "detail": detail, **hash_extra}


def _changes(have: Mapping[str, Any], want: Mapping[str, Any], names: tuple[str, ...]) -> dict[str, tuple[Any, Any]]:
    """The declared fields among `names` whose live value differs: `{field: (live, declared)}`."""
    return {n: (have.get(n), want[n]) for n in names if n in want and have.get(n) != want[n]}


def _from_to(changes: Mapping[str, tuple[Any, Any]]) -> dict[str, Any]:
    return {"from": {n: v[0] for n, v in changes.items()}, "to": {n: v[1] for n, v in changes.items()}}


def _live_realm(client: KeycloakClient, realm: str) -> Mapping[str, Any] | None:
    try:
        body = client.get(KeycloakClient.admin_path(realm)).body
    except KcAxiError as err:
        if err.code == "not_found":
            return None
        raise
    return body if isinstance(body, Mapping) else {}


# --------------------------------------------------------------------------------------- config file


def _realm_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "enabled": _flag(raw.get("enabled"), True),
        "registrationAllowed": _flag(raw.get("registrationAllowed")),
        "displayName": raw.get("displayName") or "",
        "accessTokenLifespan": raw.get("accessTokenLifespan"),
    }


def _client_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The compared fields of a live client, in the normal form of `desired.py`."""
    attributes = raw.get("attributes") if isinstance(raw.get("attributes"), Mapping) else {}
    view = {name: _flag(raw.get(name)) for name in _CLIENT_COMPARED if name not in ("redirectUris", "webOrigins", "pkce")}
    view["enabled"] = _flag(raw.get("enabled"), True)
    view["redirectUris"] = sorted(set(raw.get("redirectUris") or []))
    view["webOrigins"] = sorted(set(raw.get("webOrigins") or []))
    view["pkce"] = attributes.get(PKCE_ATTRIBUTE) or None
    return view


def _marker(raw: Mapping[str, Any]) -> str | None:
    attributes = raw.get("attributes")
    owner = attributes.get(MANAGED_ATTRIBUTE) if isinstance(attributes, Mapping) else None
    return owner if isinstance(owner, str) and owner else None


def _live_audience_mappers(raw: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """The mappers that the tool can manage: audience mappers, by name. Other mappers are never touched."""
    found = {}
    for mapper in raw.get("protocolMappers") or []:
        if isinstance(mapper, Mapping) and mapper.get("protocolMapper") == AUDIENCE_MAPPER and mapper.get("name"):
            found[mapper["name"]] = mapper
    return found


def _mapper_difference(live: Mapping[str, Any], declared: Mapping[str, Any]) -> dict[str, tuple[Any, Any]]:
    config = live.get("config") if isinstance(live.get("config"), Mapping) else {}
    changes: dict[str, tuple[Any, Any]] = {}
    if config.get(AUDIENCE_KEY) != declared["audience"]:
        changes["audience"] = (config.get(AUDIENCE_KEY), declared["audience"])
    claims = {k: config.get(k) for k in MAPPER_CLAIMS}
    if claims != MAPPER_CLAIMS:
        changes["claims"] = (claims, MAPPER_CLAIMS)
    return changes


def _plan_mappers(clientid: str, live_raw: Mapping[str, Any] | None, declared: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Mapper actions of one client that has a `mappers` key. A mapper is `remove` only when the key is present."""
    live = _live_audience_mappers(live_raw) if live_raw is not None else {}
    rows = []
    for mapper in declared:
        key = f"{clientid}/{mapper['name']}"
        if mapper["name"] not in live:
            rows.append(_action("create", "mapper", key, client=clientid, mapper=mapper["name"], audience=mapper["audience"]))
            continue
        changes = _mapper_difference(live[mapper["name"]], mapper)
        if changes:
            rows.append(_action("change", "mapper", key, ",".join(sorted(changes)), client=clientid, mapper=mapper["name"], **_from_to(changes)))
    declared_names = {m["name"] for m in declared}
    for name in sorted(set(live) - declared_names):
        rows.append(_action("remove", "mapper", f"{clientid}/{name}", phase="remove-mapper", client=clientid, mapper=name))
    return rows


def _secret_rows(
    owned: Mapping[str, Mapping[str, Any]], secrets_dir: Any, realm: str, base_url: str
) -> list[dict[str, Any]]:
    """Secret actions for the owned `secret_managed` clients that are live (spec section 5.8)."""
    live = {name: raw["secret"] for name, raw in owned.items() if isinstance(raw.get("secret"), str) and raw["secret"]}
    if not live:
        return []
    rows = []
    for name, answer in sorted(secrets_store.compare_live(secrets_dir, realm, base_url, live).items()):
        if answer["state"] == "match":
            continue
        if answer["state"] == "missing":
            rows.append(_action("secret_missing", "client", name, "secret: not in the secrets file", live=answer["live"]))
        elif answer["state"] == "finish_pending":
            rows.append(_action(
                "finish_pending", "client", name, f"pending generation {answer['pending']}", phase="finish_pending",
                file=answer["file"], live=answer["live"], pending=answer["pending"],
            ))
        else:
            rows.append(_action(
                "secret", "client", name, f"file {answer['file']}, live {answer['live']}",
                file=answer["file"], live=answer["live"],
            ))
    return rows


def _plan_config(
    client: KeycloakClient, desired: ConfigFile, secrets_dir: Any, base_url: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    realm = desired.realm_name
    owner = desired.owner
    actions: list[dict[str, Any]] = []
    live_realm = _live_realm(client, realm)
    all_clients: list[Mapping[str, Any]] = []
    if live_realm is None:
        actions.append(_action("create", "realm", realm))
        raw_clients: list[Mapping[str, Any]] = []
    else:
        changes = _changes(_realm_view(live_realm), desired.realm, tuple(n for n in desired.realm if n != "name"))
        if changes:
            actions.append(_action("change", "realm", realm, ",".join(sorted(changes)), **_from_to(changes)))
        all_clients = client.get(KeycloakClient.admin_path(realm, "clients")).body or []
        raw_clients = [c for c in all_clients if c.get("clientId") not in BUILTIN_CLIENTS]
    live = {c["clientId"]: c for c in raw_clients}
    declared_ids = {c["clientId"] for c in desired.clients}
    owned_secret_clients: dict[str, Mapping[str, Any]] = {}

    for declared in desired.clients:
        name = declared["clientId"]
        raw = live.get(name)
        if raw is None:
            detail = "secret: new" if declared.get("secret_managed") else ""
            actions.append(_action("create", "client", name, detail))
        else:
            marker = _marker(raw)
            if marker is not None and marker != owner:
                actions.append(_action("owner_conflict", "client", name, f"marker names another owner: {marker}"))
                continue
            changes = _changes(_client_view(raw), declared, _CLIENT_COMPARED)
            if marker is None:
                parts = sorted(changes) or ["marker"]
                if declared.get("secret_managed") and not _flag(raw.get("publicClient")):
                    parts.append("secret: capture")
                actions.append(_action("adopt", "client", name, ",".join(parts), **_from_to(changes)))
            else:
                if changes:
                    actions.append(_action("change", "client", name, ",".join(sorted(changes)), **_from_to(changes)))
                if declared.get("secret_managed"):
                    owned_secret_clients[name] = raw
        if "mappers" in declared:
            actions.extend(_plan_mappers(name, raw, declared["mappers"]))

    actions.extend(_secret_rows(owned_secret_clients, secrets_dir, realm, base_url))

    unmanaged = []
    for name in sorted(set(live) - declared_ids):
        if _marker(live[name]) == owner:
            actions.append(_action("remove", "client", name, phase="remove-client"))
            for mapper in sorted(_live_audience_mappers(live[name])):
                actions.append(_action("remove", "mapper", f"{name}/{mapper}", phase="remove-mapper", client=name, mapper=mapper, client_removed=True))
        else:
            unmanaged.append({"kind": "client", "name": name})
    # A mapper dies with its client. The client's own `remove` row says so, so the mapper rows are dropped.
    actions = [a for a in actions if not a.get("client_removed")]
    return actions, unmanaged, {c["clientId"]: c.get("id", "") for c in all_clients if c.get("clientId")}


# --------------------------------------------------------------------------------------- users file


def _user_view(raw: Mapping[str, Any]) -> dict[str, Any]:
    view = {name: raw.get(name) for name in ("email", "firstName", "lastName")}
    view["enabled"] = _flag(raw.get("enabled"), True)
    view["emailVerified"] = _flag(raw.get("emailVerified"))
    return view


def _has_password(client: KeycloakClient, realm: str, user_id: str) -> bool:
    body = client.get(KeycloakClient.admin_path(realm, "users", user_id, "credentials")).body or []
    return any(isinstance(c, Mapping) and c.get("type") == "password" for c in body)


def _plan_users(
    client: KeycloakClient, desired: UsersFile
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    realm = desired.realm_name
    if _live_realm(client, realm) is None:
        raise KcAxiError(
            "realm_absent",
            f"realm {realm} does not exist yet",
            help=("kc-axi apply --file <config file> creates the realm first",),
            realm=realm,
        )
    actions: list[dict[str, Any]] = []
    password_missing: list[str] = []
    incomplete: list[dict[str, str]] = []
    for declared in desired.users:
        name = declared["username"]
        live: Mapping[str, Any] | None
        try:
            live = client.get(KeycloakClient.admin_path(realm, "users", declared["id"])).body
        except KcAxiError as err:
            if err.code != "not_found":
                raise
            live = None
        if live is None:
            same_name = client.get(
                KeycloakClient.admin_path(realm, "users"), query={"username": name, "exact": "true"}
            ).body or []
            if same_name:
                actions.append(_action("id_conflict", "user", name, "the username has another id"))
            else:
                actions.append(_action("create", "user", name))
        elif str(live.get("username", "")).lower() != name.lower():
            actions.append(_action("id_conflict", "user", name, "the id has another username"))
        else:
            changes = _changes(_user_view(live), declared, _USER_COMPARED)
            if changes:
                actions.append(_action("change", "user", name, ",".join(sorted(changes)), **_from_to(changes)))
            if declared.get("temporary_password_env") and not _has_password(client, realm, declared["id"]):
                password_missing.append(name)
        effective = {f: declared[f] if f in declared else (live or {}).get(f) for f in PROFILE_FIELDS}
        missing = [f for f in PROFILE_FIELDS if not effective[f]]
        if missing:
            incomplete.append({"username": name, "missing": ",".join(missing)})
    return actions, password_missing, incomplete


# --------------------------------------------------------------------------------------- the plan


def make_plan(
    client: KeycloakClient,
    desired: ConfigFile | UsersFile,
    *,
    base_url: str,
    secrets_dir: Any,
    file_arg: str,
) -> PlanResult:
    """Read the live state and compare it with `desired`. Writes nothing. See the module text."""
    if isinstance(desired, ConfigFile):
        if not desired.owner:
            raise KcAxiError(
                "owner_required",
                "the config file has no owner. plan decides what to change or remove by the owner marker.",
                help=("add `owner: <name>` to the config file",),
            )
        actions, unmanaged, live_clients = _plan_config(client, desired, secrets_dir, base_url)
        password_missing: list[str] = []
        incomplete: list[dict[str, str]] = []
    else:
        actions, password_missing, incomplete = _plan_users(client, desired)
        unmanaged, live_clients = [], {}
    actions.sort(key=lambda a: (a["phase"], a["kind"], a["name"], a["action"]))

    server = secrets_store.normalise_base_url(base_url)
    document = {
        "schema_version": SCHEMA_VERSION,
        "realm": desired.realm_name,
        "base_url": server,
        "file": _sha256(canonical_json(desired.canonical())),
        "actions": [{k: v for k, v in a.items() if k != "phase"} for a in actions],
    }
    plan_hash = _sha256(canonical_json(document))[:16]

    rows = [{k: a[k] for k in ("action", "kind", "name", "detail")} for a in actions]
    drift = bool(actions)
    body: dict[str, Any] = {
        "status": "drift" if drift else "no_change",
        "realm": desired.realm_name,
        "total": len(actions),
        "actions": page(rows, columns=("action", "kind", "name", "detail"), limit=None),
        "unmanaged": page(unmanaged, columns=("kind", "name"), limit=None),
        "password_missing": page([{"username": u} for u in password_missing], columns=("username",), limit=None),
        "profile_incomplete": page(incomplete, columns=("username", "missing"), limit=None),
        "plan_hash": plan_hash,
    }
    if drift:
        body["help"] = [f"kc-axi apply --file {file_arg} --expect {plan_hash}"]
    return PlanResult(body, 1 if drift else 0, plan_hash, actions, live_clients)
