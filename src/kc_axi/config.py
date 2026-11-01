"""The tool configuration file (spec sections 3.1, 4.1, 6.1 and 6.2).

Where the file lives: `default_config_path` and `resolve_config_path` (I1).
How values are loaded: `load_settings` (I2b).

Precedence for each value: flag, then environment variable, then the file, then the default.
Only the keys that section 4.1 or 6.1 give a flag or a variable have one. The other keys come from
the file or the default. An empty flag or variable counts as not given. A key that is present in the
file counts as given, even when empty: `volume: ""` means no persistence (section 6.1).
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

import yaml

from .errors import KcAxiError

APP_DIR = "kc-axi"
CONFIG_NAME = "config.yaml"
SECRETS_DIR_NAME = "secrets"
SUPPORTED_SCHEMA_VERSIONS = (1,)
RUNTIMES = ("auto", "docker", "podman")

_MERGE_TAG = "tag:yaml.org,2002:merge"
_KEY_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_HELP_KEYS = "The keys and their values are in section 6.1 of the kc-axi specification."


def default_config_path(env: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """The default path for the operating system. It reads no file."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform == "darwin":
        base = home / "Library" / "Application Support"
    elif platform.startswith("win"):
        base = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    else:
        base = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    return base / APP_DIR / CONFIG_NAME


def resolve_config_path(flag: str | None, env: Mapping[str, str] | None = None) -> Path:
    """Order: `--config`, then `KC_AXI_CONFIG`, then the default. `~` expands."""
    env = os.environ if env is None else env
    chosen = flag or env.get("KC_AXI_CONFIG")
    if not chosen:
        return default_config_path(env)
    return _to_path(chosen, Path.cwd(), env)


@dataclass(frozen=True)
class _Key:
    """One key of section 6.1. `kind` is text, path, int or runtime."""

    kind: str
    default: Any = ""
    minimum: int = 0
    maximum: int | None = None
    nonempty: bool = False
    variable: str | None = None
    flag: str | None = None


# Sources of `realm`, which is not a key of its own: the flag, then KC_AXI_REALM, then `default_realm`.
_SOURCES: dict[str, tuple[str | None, str | None, str]] = {
    "realm": ("--realm", "KC_AXI_REALM", "default_realm"),
}

# Defaults are the values of section 6.1 and 6.2. `secrets_dir` has its default computed (see _default).
_KEYS: dict[str, _Key] = {
    "base_url": _Key("text", "http://127.0.0.1:8080", nonempty=True, variable="KC_AXI_BASE_URL"),
    "hostname": _Key("text", ""),
    "admin_realm": _Key("text", "master", nonempty=True),
    "default_realm": _Key("text", "", variable="KC_AXI_REALM"),
    "admin_user": _Key("text", "admin", nonempty=True, variable="KC_ADMIN_USER"),
    "admin_password_file": _Key("path", None),
    "runtime": _Key("runtime", "auto", variable="KC_AXI_RUNTIME", flag="--runtime"),
    "container_name": _Key("text", "keycloak-dev", nonempty=True),
    "image": _Key("text", ""),
    "port": _Key("int", 8080, 1, 65535),
    "volume": _Key("text", "keycloak-dev-data"),
    "volume_options": _Key("text", ""),
    "java_opts": _Key("text", ""),
    "ca_file": _Key("path", None),
    "ready_timeout_seconds": _Key("int", 120, 1),
    "request_timeout_seconds": _Key("int", 10, 1),
    "command_timeout_seconds": _Key("int", 600, 1),
    "runtime_timeout_seconds": _Key("int", 30, 1),
    "pull_timeout_seconds": _Key("int", 600, 1),
    "default_limit": _Key("int", 20, 1),
    "max_cell_chars": _Key("int", 200, 1),
    "audit_path": _Key("path", None, variable="KC_AXI_AUDIT_PATH"),
    "secrets_dir": _Key("path", None, variable="KC_AXI_SECRETS_DIR"),
    "keep_generations": _Key("int", 5, 0),
}


@dataclass(frozen=True)
class Settings:
    """The tool configuration after precedence. Paths are absolute. An optional path that is not set is None.

    `default_realm` is the value from `KC_AXI_REALM`, then the file, then "". `realm` is the value from
    `--realm`, then `default_realm`, then "". A command that needs a realm checks `realm` itself
    (`realm_required`).
    """

    config_path: Path
    config_exists: bool
    base_url: str
    hostname: str
    admin_realm: str
    default_realm: str
    realm: str
    admin_user: str
    admin_password_file: Path | None
    runtime: str
    container_name: str
    image: str
    port: int
    volume: str
    volume_options: str
    java_opts: str
    ca_file: Path | None
    ready_timeout_seconds: int
    request_timeout_seconds: int
    command_timeout_seconds: int
    runtime_timeout_seconds: int
    pull_timeout_seconds: int
    default_limit: int
    max_cell_chars: int
    audit_path: Path | None
    secrets_dir: Path
    keep_generations: int


def load_settings(
    *,
    config_flag: str | None = None,
    realm_flag: str | None = None,
    runtime_flag: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Load the tool configuration. A missing file is not an error: every key takes its default.

    Raises KcAxiError for a file that is unreadable, not YAML, has a duplicate key, an unknown key,
    an unknown schema version, or a value of the wrong type or range.
    """
    env = os.environ if env is None else env
    config_path = resolve_config_path(config_flag, env)
    file_values = _read_file(config_path)
    values: dict[str, Any] = {}
    for name, key in _KEYS.items():
        flag = runtime_flag if name == "runtime" else None
        values[name] = _resolve(name, key, env, file_values, config_path, flag)
    realm = (realm_flag or "") or values["default_realm"]
    return Settings(config_path=config_path, config_exists=file_values is not None, realm=realm, **values)


def require(settings: Settings, name: str, code: str = "config_missing") -> Any:
    """Return a value that a command needs. Raise `code` when no source supplied it.

    `config_missing` (exit 2) is the default. The spec gives `realm` its own code, `realm_required`.
    """
    value = getattr(settings, name)
    if value is None or value == "":
        flag, variable, key_name = _SOURCES.get(name) or _sources_of_key(name)
        sources = [s for s in (flag, variable) if s] + [f"the key {key_name} in {settings.config_path}"]
        raise KcAxiError(
            code,
            f"{name} is not set. No flag, variable or configuration key supplies it.",
            help=(f"Set {name} with " + " or ".join(sources) + ".",),
        )
    return value


# --- Sources -----------------------------------------------------------------------------------


def _sources_of_key(name: str) -> tuple[str | None, str | None, str]:
    key = _KEYS.get(name)
    if key is None:
        return None, None, name
    return key.flag, key.variable, name


def _resolve(name: str, key: _Key, env: Mapping[str, str], file_values: dict | None,
             config_path: Path, flag: str | None) -> Any:
    if flag:
        return _from_text(name, key, flag, key.flag or name, Path.cwd(), env)
    if key.variable and env.get(key.variable):
        return _from_text(name, key, env[key.variable], key.variable, Path.cwd(), env)
    if file_values is not None and name in file_values:
        return _from_file(name, key, file_values[name], config_path, env)
    return _default(name, env)


def _default(name: str, env: Mapping[str, str]) -> Any:
    if name == "secrets_dir":
        # The user configuration directory, not the directory of the file in use (section 6.1).
        return default_config_path(env).parent / SECRETS_DIR_NAME
    return _KEYS[name].default


def _from_text(name: str, key: _Key, raw: Any, source: str, base: Path, env: Mapping[str, str]) -> Any:
    value = _checked(name, key, raw, source)
    if key.kind == "path":
        return _to_path(value, base, env)
    return value


def _from_file(name: str, key: _Key, raw: Any, config_path: Path, env: Mapping[str, str]) -> Any:
    source = str(config_path)
    value = _checked(name, key, raw, source)
    if key.kind == "path":
        if value == "":
            return _default(name, env)
        return _to_path(value, config_path.parent, env)
    return value


def _to_path(value: str, base: Path, env: Mapping[str, str]) -> Path:
    """Expand `~` from `env` (HOME, then USERPROFILE), then resolve a relative path from `base`."""
    home = env.get("HOME") or env.get("USERPROFILE")
    if home and (value == "~" or value.startswith(("~/", "~\\"))):
        return Path(home, value[2:])
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def _checked(name: str, key: _Key, value: Any, source: str) -> Any:
    """Check the type and range of one value. A failure is `config_invalid`. Values are never echoed."""
    if value is None and key.kind in ("text", "path"):
        value = ""  # a bare `key:` in YAML is null; it means empty
    if key.kind == "int":
        upper = key.maximum
        if type(value) is not int or value < key.minimum or (upper is not None and value > upper):
            bounds = f"from {key.minimum} to {upper}" if upper is not None else f"of at least {key.minimum}"
            _fail(name, source, f"must be a whole number {bounds}")
        return value
    if key.kind == "runtime":
        if value not in RUNTIMES:
            _fail(name, source, "must be one of auto, docker or podman")
        return value
    if not isinstance(value, str):
        _fail(name, source, "must be text")
    if key.nonempty and value == "":
        _fail(name, source, "must not be empty")
    if name == "base_url":
        _check_base_url(value, source)
    return value


def _check_base_url(value: str, source: str) -> None:
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        parts = None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        _fail("base_url", source, "must be an http or https URL with a host")
    if parts.username is not None or parts.password is not None:
        # The URL may hold a password. The message does not repeat it.
        _fail("base_url", source, "must not contain a user name or password")


def _fail(name: str, source: str, reason: str) -> NoReturn:
    raise KcAxiError(
        "config_invalid",
        f"{name} from {source} is not valid: {reason}.",
        help=(_HELP_KEYS,),
    )


# --- File -------------------------------------------------------------------------------------


def _read_file(path: Path) -> dict[str, Any] | None:
    """Return the file's values, or None when no file exists. The schema version is checked here."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError):
        raise KcAxiError(
            "config_invalid",
            f"The tool configuration file {path} cannot be read as UTF-8 text.",
            help=("Check that the file exists, is readable and is UTF-8.",),
        ) from None
    data = _parse(text, path)
    if "schema_version" not in data:
        raise KcAxiError(
            "config_invalid",
            f"{path}: schema_version is required. Set it to 1.",
            help=(_HELP_KEYS,),
        )
    version = data["schema_version"]
    if type(version) is not int:
        raise KcAxiError("config_invalid", f"{path}: schema_version must be a whole number.", help=(_HELP_KEYS,))
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(str(v) for v in SUPPORTED_SCHEMA_VERSIONS)
        raise KcAxiError(
            "schema_unsupported",
            f"{path}: schema_version {version} is not supported. This tool reads: {supported}.",
            help=("Upgrade kc-axi, or use a file this version reads.",),
        )
    for name in data:
        if name == "schema_version":
            continue
        if not isinstance(name, str) or name not in _KEYS:
            # Echo the name only when it looks like a key. A secret placed in key position must not leak.
            shown = repr(name) if isinstance(name, str) and _KEY_NAME.match(name) else "a key with a name that is not allowed"
            raise KcAxiError(
                "unknown_field",
                f"{path}: unknown key {shown}.",
                help=("Remove the key. Credentials are never kept in this file.", _HELP_KEYS),
            )
    return {name: value for name, value in data.items() if name != "schema_version"}


class _ParseProblem(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class _StrictLoader(yaml.SafeLoader):
    """The safe loader, with one change: a repeated key in a mapping is refused (`duplicate_key`)."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        if key_node.tag == _MERGE_TAG:
            continue
        line = key_node.start_mark.line + 1
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in seen
        except TypeError:
            raise _ParseProblem("config_invalid", f"line {line}: a key must be text") from None
        if duplicate:
            # The key is not echoed: a key can hold text that must stay out of messages.
            raise _ParseProblem("duplicate_key", f"line {line}: a key appears twice in one mapping")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _parse(text: str, path: Path, help_text: str = _HELP_KEYS) -> dict[str, Any]:
    try:
        data = yaml.load(text, Loader=_StrictLoader)
    except _ParseProblem as problem:
        raise KcAxiError(problem.code, f"{path}: {problem.detail}.", help=(help_text,)) from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        # The YAML parser's own message can quote file content, so it is not repeated.
        raise KcAxiError("config_invalid", f"{path}: not valid YAML{where}.", help=(help_text,)) from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise KcAxiError("config_invalid", f"{path}: the file must hold a mapping of keys.", help=(help_text,))
    return data


#: The strict YAML reader, shared with the desired-state files (spec section 3.4).
parse_yaml = _parse
