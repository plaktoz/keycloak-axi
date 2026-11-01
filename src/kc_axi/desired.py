"""The desired-state files (spec section 3.4): parse, check, and normalise.

`load_desired(path, ...)` reads one file and returns a `ConfigFile` or a `UsersFile`. It makes no network call.
Every problem exits 2 with a typed code, and no message repeats a value from the file: a key that is not
allowed is named only when it is close to an allowed key (a typo), so a secret placed in a key never reaches an
output.

Normal form (what `plan` compares and hashes): a boolean is a `bool` (the text `"true"` is accepted), a number is
an `int`, a set-like list is sorted, and only the fields that the file declares are present.
"""

from __future__ import annotations

import difflib
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import parse_yaml
from .credentials import check_owner_only
from .errors import KcAxiError
from .paths import check_outside_git

SUPPORTED_SCHEMA_VERSIONS = (1,)

#: Clients that Keycloak creates in every realm. A file cannot declare one (spec section 3.4).
BUILTIN_CLIENTS = frozenset(
    {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
)

REALM_FIELDS = ("name", "enabled", "displayName", "accessTokenLifespan", "registrationAllowed")
CLIENT_FIELDS = (
    "clientId", "enabled", "publicClient", "standardFlowEnabled", "directAccessGrantsEnabled",
    "serviceAccountsEnabled", "redirectUris", "webOrigins", "pkce", "secret_managed", "mappers",
)
MAPPER_FIELDS = ("name", "kind", "audience")
USER_FIELDS = (
    "id", "username", "enabled", "email", "emailVerified", "firstName", "lastName", "temporary_password_env",
)

_BOOLEAN_CLIENT_FIELDS = (
    "enabled", "publicClient", "standardFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled",
    "secret_managed",
)
_REALM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_KEY_SHAPE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_SPEC_HELP = "The fields and their values are in section 3.4 of the kc-axi specification."


@dataclass(frozen=True)
class ConfigFile:
    """`kind: config`. `realm` and each client hold the declared fields only. A client has `mappers` only when declared."""

    owner: str | None
    realm: dict[str, Any]
    clients: tuple[dict[str, Any], ...]

    kind = "config"

    @property
    def realm_name(self) -> str:
        return self.realm["name"]

    def canonical(self) -> dict[str, Any]:
        return {"kind": "config", "owner": self.owner, "realm": self.realm, "clients": list(self.clients)}


@dataclass(frozen=True)
class UsersFile:
    """`kind: users`. Each user holds the declared fields, with `id` and `username` always present."""

    realm_name: str
    users: tuple[dict[str, Any], ...]

    kind = "users"

    def canonical(self) -> dict[str, Any]:
        return {"kind": "users", "realm": self.realm_name, "users": list(self.users)}


# --------------------------------------------------------------------------------------- errors


def _invalid(path: Path, where: str, problem: str, code: str = "config_invalid") -> KcAxiError:
    return KcAxiError(code, f"{path}: {where}: {problem}.", help=(_SPEC_HELP,))


def _check_keys(mapping: Mapping[Any, Any], allowed: tuple[str, ...], where: str, path: Path) -> None:
    """Exit 2, `unknown_field`, for a key that is not allowed. Only a near miss of an allowed key is echoed."""
    for key in mapping:
        if isinstance(key, str) and key in allowed:
            continue
        near = difflib.get_close_matches(key, allowed, n=1, cutoff=0.8) if isinstance(key, str) and _KEY_SHAPE.match(key) else []
        if near:
            problem = f"unknown key {key!r}; did you mean {near[0]!r}"
        else:
            problem = "unknown key"
        raise KcAxiError(
            "unknown_field",
            f"{path}: {where}: {problem}.",
            help=(f"allowed keys here: {', '.join(allowed)}", _SPEC_HELP),
        )


# --------------------------------------------------------------------------------------- values


def _text(value: Any, where: str, path: Path, *, limit: int = 255) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\n" in value or "\r" in value:
        raise _invalid(path, where, f"must be one line of text, 1 to {limit} characters")
    return value


def _optional_text(value: Any, where: str, path: Path) -> str:
    """A text field that can be empty, such as `displayName` or `firstName`."""
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 255 or "\n" in value or "\r" in value:
        raise _invalid(path, where, "must be one line of text, up to 255 characters")
    return value


def _boolean(value: Any, where: str, path: Path) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise _invalid(path, where, "must be true or false")


def _integer(value: Any, where: str, path: Path, low: int, high: int) -> int:
    if isinstance(value, str) and re.fullmatch(r"\d{1,9}", value.strip()):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _invalid(path, where, f"must be a whole number from {low} to {high}")
    return value


def _text_set(value: Any, where: str, path: Path) -> list[str]:
    if not isinstance(value, list):
        raise _invalid(path, where, "must be a list of text")
    items = [_text(item, f"{where}[{i}]", path, limit=2048) for i, item in enumerate(value)]
    return sorted(set(items))


def _mapping(value: Any, where: str, path: Path) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _invalid(path, where, "must be a mapping of keys")
    return value


def _list(value: Any, where: str, path: Path) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _invalid(path, where, "must be a list")
    return value


# --------------------------------------------------------------------------------------- the two kinds


def _realm(raw: Any, path: Path, admin_realm: str) -> dict[str, Any]:
    section = _mapping(raw, "realm", path)
    _check_keys(section, REALM_FIELDS, "realm", path)
    if "name" not in section:
        raise _invalid(path, "realm", "name is required")
    name = section["name"]
    if not isinstance(name, str) or not _REALM_NAME.match(name):
        raise _invalid(path, "realm.name", "must use letters, digits, '-', '_' and '.', and start with a letter or digit")
    if name == admin_realm:
        raise KcAxiError(
            "admin_realm_refused",
            f"{path}: realm.name is the admin realm {admin_realm}. The tool does not manage it.",
            help=("Use a realm of your own.",),
        )
    out: dict[str, Any] = {"name": name}
    if "enabled" in section:
        out["enabled"] = _boolean(section["enabled"], "realm.enabled", path)
    if "registrationAllowed" in section:
        out["registrationAllowed"] = _boolean(section["registrationAllowed"], "realm.registrationAllowed", path)
    if "displayName" in section:
        out["displayName"] = _optional_text(section["displayName"], "realm.displayName", path)
    if "accessTokenLifespan" in section:
        out["accessTokenLifespan"] = _integer(section["accessTokenLifespan"], "realm.accessTokenLifespan", path, 1, 86400)
    return out


def _mappers(raw: Any, where: str, path: Path) -> list[dict[str, str]]:
    mappers: dict[str, dict[str, str]] = {}
    for index, item in enumerate(_list(raw, where, path)):
        place = f"{where}[{index}]"
        entry = _mapping(item, place, path)
        _check_keys(entry, MAPPER_FIELDS, place, path)
        for required in MAPPER_FIELDS:
            if required not in entry:
                raise _invalid(path, place, f"{required} is required")
        if entry["kind"] != "audience":
            raise _invalid(path, f"{place}.kind", "must be 'audience' (the only kind in this version)")
        name = _text(entry["name"], f"{place}.name", path)
        if name in mappers:
            raise _invalid(path, f"{place}.name", "is used by another mapper of this client")
        mappers[name] = {"name": name, "kind": "audience", "audience": _text(entry["audience"], f"{place}.audience", path)}
    return [mappers[name] for name in sorted(mappers)]


def _client(raw: Any, index: int, path: Path) -> dict[str, Any]:
    where = f"clients[{index}]"
    section = _mapping(raw, where, path)
    _check_keys(section, CLIENT_FIELDS, where, path)
    if "clientId" not in section:
        raise _invalid(path, where, "clientId is required")
    client_id = _text(section["clientId"], f"{where}.clientId", path)
    if client_id in BUILTIN_CLIENTS:
        raise KcAxiError(
            "builtin_client",
            f"{path}: {where}: the file declares a built-in client of Keycloak. Built-in clients cannot be declared.",
            help=("Remove it from the file. Built-in clients are never listed or changed.",),
            client=client_id,
        )
    out: dict[str, Any] = {"clientId": client_id}
    for name in _BOOLEAN_CLIENT_FIELDS:
        if name in section:
            out[name] = _boolean(section[name], f"{where}.{name}", path)
    for name in ("redirectUris", "webOrigins"):
        if name in section:
            out[name] = _text_set(section[name], f"{where}.{name}", path)
    public = out.get("publicClient", False)
    if out.get("secret_managed") and public:
        raise KcAxiError(
            "secret_managed_public",
            f"{path}: {where}: secret_managed is true on a public client. A public client has no secret.",
            help=("Set publicClient to false, or remove secret_managed.",),
            client=client_id,
        )
    if "pkce" in section:
        if section["pkce"] != "S256":
            raise _invalid(path, f"{where}.pkce", "must be S256")
        if not public:
            raise _invalid(path, f"{where}.pkce", "is for public clients only. Set publicClient to true")
        out["pkce"] = "S256"
    if "mappers" in section:
        out["mappers"] = _mappers(section["mappers"], f"{where}.mappers", path)
    return out


def _check_config(data: Mapping[str, Any], path: Path, admin_realm: str) -> ConfigFile:
    _check_keys(data, ("schema_version", "kind", "owner", "realm", "clients"), "top level", path)
    if "realm" not in data:
        raise _invalid(path, "top level", "realm is required")
    owner = _text(data["owner"], "owner", path) if data.get("owner") is not None else None
    realm = _realm(data["realm"], path, admin_realm)
    clients: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(_list(data.get("clients"), "clients", path)):
        client = _client(item, index, path)
        if client["clientId"] in clients:
            raise _invalid(path, f"clients[{index}].clientId", "is declared twice")
        clients[client["clientId"]] = client
    return ConfigFile(owner, realm, tuple(clients[name] for name in sorted(clients)))


def _user(raw: Any, index: int, path: Path) -> dict[str, Any]:
    where = f"users[{index}]"
    section = _mapping(raw, where, path)
    _check_keys(section, USER_FIELDS, where, path)
    for required in ("id", "username"):
        if required not in section:
            raise _invalid(path, where, f"{required} is required")
    raw_id = section["id"]
    try:
        if not isinstance(raw_id, str):
            raise ValueError
        user_id = str(uuid.UUID(raw_id))
    except ValueError:
        raise KcAxiError(
            "id_invalid",
            f"{path}: {where}.id: must be a UUID.",
            help=("Generate one with your tooling, for example: python -c \"import uuid; print(uuid.uuid4())\"",),
        ) from None
    out: dict[str, Any] = {"id": user_id, "username": _text(section["username"], f"{where}.username", path)}
    if "enabled" in section:
        out["enabled"] = _boolean(section["enabled"], f"{where}.enabled", path)
    if "emailVerified" in section:
        out["emailVerified"] = _boolean(section["emailVerified"], f"{where}.emailVerified", path)
    for name in ("email", "firstName", "lastName"):
        if name in section:
            out[name] = _optional_text(section[name], f"{where}.{name}", path)
    if section.get("temporary_password_env") is not None:
        variable = section["temporary_password_env"]
        if not isinstance(variable, str) or not _ENV_NAME.match(variable):
            # Never echo it: a value placed here by mistake could be a password.
            raise _invalid(path, f"{where}.temporary_password_env", "must be the name of an environment variable, not a password")
        out["temporary_password_env"] = variable
    return out


def _check_users(data: Mapping[str, Any], path: Path) -> UsersFile:
    _check_keys(data, ("schema_version", "kind", "realm", "users"), "top level", path)
    if "realm" not in data:
        raise _invalid(path, "top level", "realm is required")
    realm = data["realm"]
    if not isinstance(realm, str) or not _REALM_NAME.match(realm):
        raise _invalid(path, "realm", "must use letters, digits, '-', '_' and '.', and start with a letter or digit")
    users: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for index, item in enumerate(_list(data.get("users"), "users", path)):
        user = _user(item, index, path)
        if user["id"] in users:
            raise _invalid(path, f"users[{index}].id", "is declared twice")
        lowered = user["username"].lower()
        if lowered in names:
            raise _invalid(path, f"users[{index}].username", "is declared twice (names compare without regard to case)")
        users[user["id"]] = user
        names.add(lowered)
    return UsersFile(realm, tuple(users[key] for key in sorted(users)))


# --------------------------------------------------------------------------------------- entry point


def load_desired(
    path: Path,
    *,
    realm_flag: str | None = None,
    admin_realm: str = "master",
) -> ConfigFile | UsersFile:
    """Read and check one desired-state file. Exit 2 on any problem, before any request.

    `realm_flag` is the value of `--realm` when the operator gave one. A different realm in the file exits 2,
    `realm_mismatch`. A users file is also checked for its mode and for a git work tree (spec section 5.4).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise KcAxiError(
            "config_missing",
            f"The desired-state file {path} does not exist.",
            help=("Check the --file path.",),
        ) from None
    except (OSError, UnicodeDecodeError):
        raise KcAxiError(
            "config_invalid",
            f"The desired-state file {path} cannot be read as UTF-8 text.",
            help=("Check that the file is readable and is UTF-8.",),
        ) from None
    data = parse_yaml(text, path, _SPEC_HELP)
    if "schema_version" not in data:
        raise _invalid(path, "top level", "schema_version is required. Set it to 1")
    version = data["schema_version"]
    if type(version) is not int:
        raise _invalid(path, "schema_version", "must be a whole number")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(str(v) for v in SUPPORTED_SCHEMA_VERSIONS)
        raise KcAxiError(
            "schema_unsupported",
            f"{path}: schema_version {version} is not supported. This tool reads: {supported}.",
            help=("Upgrade kc-axi, or use a file this version reads.",),
        )
    kind = data.get("kind")
    if kind not in ("config", "users"):
        raise _invalid(path, "kind", "is required and must be 'config' or 'users'")
    if kind == "users":
        check_owner_only(path, "users file")
        check_outside_git(path, "users file")
        desired: ConfigFile | UsersFile = _check_users(data, path)
    else:
        desired = _check_config(data, path, admin_realm)
    if realm_flag and realm_flag != desired.realm_name:
        raise KcAxiError(
            "realm_mismatch",
            f"--realm {realm_flag} differs from the realm in {path}: {desired.realm_name}.",
            help=("Remove --realm, or use the file for that realm.",),
        )
    return desired
