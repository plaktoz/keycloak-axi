"""I2b acceptance: spec criterion 65 and the loading rules of sections 3.1, 4.1, 6.1 and 6.2.

Every key of section 6.1 has a test for its default, one for the file, and one for each override the
spec names (a flag or a variable). Keys that have no flag or variable in the spec get no such test.
Test files are written as UTF-8 into pytest's tmp_path.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from kc_axi.config import Settings, load_settings, require
from kc_axi.errors import KcAxiError

# Defaults of section 6.1 and 6.2, one per key. `secrets_dir` has a computed default, see below.
DEFAULTS = {
    "base_url": "http://127.0.0.1:8080",
    "hostname": "",
    "admin_realm": "master",
    "default_realm": "",
    "admin_user": "admin",
    "admin_password_file": None,
    "runtime": "auto",
    "container_name": "keycloak-dev",
    "image": "",
    "port": 8080,
    "volume": "keycloak-dev-data",
    "volume_options": "",
    "java_opts": "",
    "ca_file": None,
    "ready_timeout_seconds": 120,
    "request_timeout_seconds": 10,
    "command_timeout_seconds": 600,
    "runtime_timeout_seconds": 30,
    "pull_timeout_seconds": 600,
    "default_limit": 20,
    "max_cell_chars": 200,
    "audit_path": None,
    "secrets_dir": None,
    "keep_generations": 5,
}

# A value per key, different from the default, written in the file. Relative paths resolve from the file.
FILE_VALUE = {
    "base_url": "http://localhost:9090",
    "hostname": "kc.local",
    "admin_realm": "ops",
    "default_realm": "acme",
    "admin_user": "root",
    "admin_password_file": "pw.txt",
    "runtime": "podman",
    "container_name": "kc-test",
    "image": "quay.io/keycloak/keycloak:26.6.4",
    "port": 9090,
    "volume": "kc-vol",
    "volume_options": "Z",
    "java_opts": "-Xmx512m",
    "ca_file": "ca.pem",
    "ready_timeout_seconds": 90,
    "request_timeout_seconds": 5,
    "command_timeout_seconds": 300,
    "runtime_timeout_seconds": 20,
    "pull_timeout_seconds": 400,
    "default_limit": 50,
    "max_cell_chars": 120,
    "audit_path": "audit.jsonl",
    "secrets_dir": "kc-secrets",
    "keep_generations": 3,
}

# Keys whose file value is a path. Their default is None, or a computed path for secrets_dir.
PATH_KEYS = {"admin_password_file", "ca_file", "audit_path", "secrets_dir"}

# Variables of section 4.1 and 6.1, with a value that differs from the file value and the default.
# Path variables use an absolute path, so the result does not depend on the working directory.
VARIABLE_KEYS = {
    "base_url": ("KC_AXI_BASE_URL", "http://localhost:7070"),
    "default_realm": ("KC_AXI_REALM", "from-var"),
    "admin_user": ("KC_ADMIN_USER", "varuser"),
    "runtime": ("KC_AXI_RUNTIME", "docker"),
    "audit_path": ("KC_AXI_AUDIT_PATH", "/var/kc/audit-from-var.jsonl"),
    "secrets_dir": ("KC_AXI_SECRETS_DIR", "/var/kc/secrets-from-var"),
}


def write(folder: Path, text: str, name: str = "config.yaml") -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def env_for(tmp_path: Path, **extra: str) -> dict[str, str]:
    """No kc-axi variable is set. HOME is inside tmp_path. XDG_CONFIG_HOME is unset."""
    return {"HOME": str(tmp_path / "home"), **extra}


def missing_file(tmp_path: Path) -> str:
    return str(tmp_path / "absent.yaml")


def load_from_file(tmp_path: Path, text: str, env: dict[str, str] | None = None) -> Settings:
    path = write(tmp_path, text)
    return load_settings(config_flag=str(path), env=env_for(tmp_path) if env is None else env)


def expect_code(code: str, fn) -> KcAxiError:
    with pytest.raises(KcAxiError) as info:
        fn()
    assert info.value.code == code, info.value.message
    return info.value


def yaml_value(value) -> str:
    # JSON strings and numbers are valid YAML, so json.dumps gives a safe literal.
    return json.dumps(value)


# --- Defaults ----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_c65_default_for_each_key(tmp_path, name):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    assert settings.config_exists is False
    if name == "secrets_dir":
        # Computed, not a constant: checked by test_c65_secrets_dir_default_* below.
        return
    assert getattr(settings, name) == DEFAULTS[name]


def test_c65_secrets_dir_default_is_under_the_user_configuration_folder(tmp_path):
    from kc_axi.config import default_config_path

    env = env_for(tmp_path)
    settings = load_settings(config_flag=missing_file(tmp_path), env=env)
    assert settings.secrets_dir == default_config_path(env).parent / "secrets"


def test_c65_default_secrets_dir_is_not_next_to_a_file_in_use(tmp_path):
    from kc_axi.config import default_config_path

    cfg = tmp_path / "cfg"
    cfg.mkdir()
    path = write(cfg, "schema_version: 1\n")
    env = env_for(tmp_path)
    settings = load_settings(config_flag=str(path), env=env)
    assert settings.secrets_dir == default_config_path(env).parent / "secrets"
    assert settings.secrets_dir != cfg / "secrets"


def test_c65_realm_default_is_empty(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    assert settings.realm == ""


def test_c65_schema_version_is_not_a_setting(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    assert not hasattr(settings, "schema_version")


# --- File override for each key ----------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_c65_file_override_for_each_key(tmp_path, name):
    text = f"schema_version: 1\n{name}: {yaml_value(FILE_VALUE[name])}\n"
    path = write(tmp_path, text)
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path))
    expected = path.parent / FILE_VALUE[name] if name in PATH_KEYS else FILE_VALUE[name]
    assert getattr(settings, name) == expected


def test_c65_file_override_for_port_is_an_int(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nport: 9090\n")
    assert settings.port == 9090


# --- Variable override for each key that has a variable ----------------------------------------


@pytest.mark.parametrize("name", sorted(VARIABLE_KEYS))
def test_c65_variable_override_for_each_key(tmp_path, name):
    variable, value = VARIABLE_KEYS[name]
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path, **{variable: value}))
    got = getattr(settings, name)
    if name in PATH_KEYS:
        assert got == Path(value)
    else:
        assert got == value


@pytest.mark.parametrize("name", sorted(VARIABLE_KEYS))
def test_c65_variable_beats_file_for_each_key(tmp_path, name):
    variable, value = VARIABLE_KEYS[name]
    path = write(tmp_path, f"schema_version: 1\n{name}: {yaml_value(FILE_VALUE[name])}\n")
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path, **{variable: value}))
    got = getattr(settings, name)
    assert got == (Path(value) if name in PATH_KEYS else value)
    assert got != (path.parent / FILE_VALUE[name] if name in PATH_KEYS else FILE_VALUE[name])


@pytest.mark.parametrize("name", sorted(VARIABLE_KEYS))
def test_empty_variable_counts_as_not_given(tmp_path, name):
    variable, _value = VARIABLE_KEYS[name]
    path = write(tmp_path, f"schema_version: 1\n{name}: {yaml_value(FILE_VALUE[name])}\n")
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path, **{variable: ""}))
    expected = path.parent / FILE_VALUE[name] if name in PATH_KEYS else FILE_VALUE[name]
    assert getattr(settings, name) == expected


def test_variable_beats_default_when_no_file(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path),
                             env=env_for(tmp_path, KC_AXI_BASE_URL="http://localhost:7070"))
    assert settings.base_url == "http://localhost:7070"


# --- Flag override -----------------------------------------------------------------------------


def test_c65_runtime_flag_beats_variable_and_file(tmp_path):
    path = write(tmp_path, "schema_version: 1\nruntime: podman\n")
    env = env_for(tmp_path, KC_AXI_RUNTIME="docker")
    settings = load_settings(config_flag=str(path), runtime_flag="auto", env=env)
    assert settings.runtime == "auto"


@pytest.mark.parametrize("flag", ["auto", "docker", "podman"])
def test_c65_runtime_flag_accepts_each_value(tmp_path, flag):
    settings = load_settings(config_flag=missing_file(tmp_path), runtime_flag=flag, env=env_for(tmp_path))
    assert settings.runtime == flag


def test_c65_runtime_flag_is_checked(tmp_path):
    expect_code("config_invalid", lambda: load_settings(
        config_flag=missing_file(tmp_path), runtime_flag="kubernetes", env=env_for(tmp_path)))


def test_realm_flag_beats_variable_and_file(tmp_path):
    path = write(tmp_path, "schema_version: 1\ndefault_realm: from-file\n")
    env = env_for(tmp_path, KC_AXI_REALM="from-var")
    settings = load_settings(config_flag=str(path), realm_flag="from-flag", env=env)
    assert settings.realm == "from-flag"


def test_realm_uses_variable_then_file_when_no_flag(tmp_path):
    path = write(tmp_path, "schema_version: 1\ndefault_realm: from-file\n")
    assert load_settings(config_flag=str(path), env=env_for(tmp_path)).realm == "from-file"
    env = env_for(tmp_path, KC_AXI_REALM="from-var")
    assert load_settings(config_flag=str(path), env=env).realm == "from-var"


def test_config_flag_beats_variable(tmp_path):
    flag_file = write(tmp_path, "schema_version: 1\nport: 1111\n", name="flag.yaml")
    var_file = write(tmp_path, "schema_version: 1\nport: 2222\n", name="var.yaml")
    settings = load_settings(config_flag=str(flag_file), env=env_for(tmp_path, KC_AXI_CONFIG=str(var_file)))
    assert settings.port == 1111
    assert settings.config_path == flag_file


def test_config_variable_used_when_no_flag(tmp_path):
    var_file = write(tmp_path, "schema_version: 1\nport: 2222\n", name="var.yaml")
    settings = load_settings(env=env_for(tmp_path, KC_AXI_CONFIG=str(var_file)))
    assert settings.port == 2222


# --- Missing value (config_missing) ------------------------------------------------------------


def test_require_gives_config_missing_for_an_unset_value(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    err = expect_code("config_missing", lambda: require(settings, "image"))
    assert "image" in err.message
    assert "image" in err.help[0]


def test_require_names_flag_and_variable_for_audit_path(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    err = expect_code("config_missing", lambda: require(settings, "audit_path"))
    assert "KC_AXI_AUDIT_PATH" in err.help[0]


def test_require_realm_uses_its_own_code(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    err = expect_code("realm_required", lambda: require(settings, "realm", "realm_required"))
    assert "--realm" in err.help[0]
    assert "KC_AXI_REALM" in err.help[0]


def test_require_returns_a_supplied_value(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path),
                             env=env_for(tmp_path, KC_AXI_BASE_URL="http://localhost:8080"))
    assert require(settings, "base_url") == "http://localhost:8080"


def test_require_returns_a_value_from_the_file(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nimage: \"quay.io/x/y:1.2.3\"\n")
    assert require(settings, "image") == "quay.io/x/y:1.2.3"


def test_empty_file_value_is_missing_when_required(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nimage: \"\"\n")
    expect_code("config_missing", lambda: require(settings, "image"))


def test_null_in_file_is_empty_text(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nimage:\n")
    assert settings.image == ""


def test_config_missing_message_names_no_secret(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path),
                             env=env_for(tmp_path, KC_ADMIN_PASSWORD="hunter2-env-secret"))
    err = expect_code("config_missing", lambda: require(settings, "image"))
    assert "hunter2-env-secret" not in err.message
    assert "hunter2-env-secret" not in " ".join(err.help)


# --- Duplicate key -----------------------------------------------------------------------------


def test_duplicate_key_is_refused(tmp_path):
    path = write(tmp_path, "schema_version: 1\nport: 1111\nport: 2222\n")
    err = expect_code("duplicate_key", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "line 3" in err.message


def test_duplicate_schema_version_is_refused(tmp_path):
    path = write(tmp_path, "schema_version: 1\nschema_version: 1\n")
    expect_code("duplicate_key", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_duplicate_key_message_does_not_echo_the_key(tmp_path):
    path = write(tmp_path, "schema_version: 1\nsecret-value-here: 1\nsecret-value-here: 2\n")
    err = expect_code("duplicate_key", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "secret-value-here" not in err.message
    assert "secret-value-here" not in " ".join(err.help)


def test_yaml_merge_key_is_not_a_duplicate(tmp_path):
    # `<<` merges a mapping into the top level. The merged key is still checked against the schema.
    settings = load_from_file(tmp_path, "schema_version: 1\n<<: {port: 9000}\n")
    assert settings.port == 9000


# --- Unknown key -------------------------------------------------------------------------------


def test_unknown_key_is_refused(tmp_path):
    path = write(tmp_path, "schema_version: 1\nprot: 8080\n")
    err = expect_code("unknown_field", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "prot" in err.message


def test_owner_key_in_tool_config_is_unknown_field(tmp_path):
    # Section 6.1: `owner` belongs to the config file only.
    path = write(tmp_path, "schema_version: 1\nowner: acme-platform\n")
    expect_code("unknown_field", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_admin_password_in_tool_config_is_unknown_field_and_not_echoed(tmp_path):
    # Section 5.4: a password in this file is refused. Its value must not reach the message.
    path = write(tmp_path, "schema_version: 1\nadmin_password: hunter2-secret\n")
    err = expect_code("unknown_field", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "hunter2-secret" not in err.message
    assert "admin_password" in err.message


def test_secret_in_key_position_is_not_echoed(tmp_path):
    path = write(tmp_path, "schema_version: 1\n\"sk-live-abc123 value\": 1\n")
    err = expect_code("unknown_field", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "sk-live-abc123" not in err.message
    assert "sk-live-abc123" not in " ".join(err.help)


def test_non_text_key_is_refused_as_unknown(tmp_path):
    path = write(tmp_path, "schema_version: 1\n1: 2\n")
    expect_code("unknown_field", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


# --- Schema version ----------------------------------------------------------------------------


def test_schema_version_1_loads(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\n")
    assert settings.config_exists is True


@pytest.mark.parametrize("version", [0, 2, 99])
def test_unknown_schema_version_is_unsupported(tmp_path, version):
    path = write(tmp_path, f"schema_version: {version}\n")
    err = expect_code("schema_unsupported", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert str(version) in err.message


def test_missing_schema_version_is_config_invalid(tmp_path):
    path = write(tmp_path, "port: 8080\n")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_schema_version_must_be_a_number(tmp_path):
    path = write(tmp_path, "schema_version: \"1\"\n")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_empty_file_is_config_invalid(tmp_path):
    path = write(tmp_path, "")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_schema_version_is_checked_before_unknown_keys(tmp_path):
    # A newer file may use keys this version does not know. That is a version error, not a typo.
    path = write(tmp_path, "schema_version: 2\nnew_key: 1\n")
    expect_code("schema_unsupported", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


# --- Bad schema (types, ranges, YAML) ----------------------------------------------------------


@pytest.mark.parametrize("line", [
    'port: "8080"',
    "port: 0",
    "port: 70000",
    "default_limit: 0",
    "keep_generations: -1",
    "request_timeout_seconds: 0",
    "request_timeout_seconds: 1.5",
    "request_timeout_seconds: true",
    "runtime: kubernetes",
    'base_url: "ftp://127.0.0.1"',
    'base_url: "localhost:8080"',
    'base_url: "http://user:pw@127.0.0.1:8080"',
    'container_name: ""',
    'admin_user: ""',
    "image: [a, b]",
    "port:",
])
def test_bad_value_is_config_invalid(tmp_path, line):
    path = write(tmp_path, f"schema_version: 1\n{line}\n")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_bad_value_message_does_not_echo_the_value(tmp_path):
    path = write(tmp_path, "schema_version: 1\nbase_url: \"http://user:hunter2-pw@127.0.0.1:8080\"\n")
    err = expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "hunter2-pw" not in err.message
    assert "hunter2-pw" not in " ".join(err.help)


def test_bad_variable_is_config_invalid(tmp_path):
    env = env_for(tmp_path, KC_AXI_RUNTIME="kubernetes")
    expect_code("config_invalid", lambda: load_settings(config_flag=missing_file(tmp_path), env=env))


def test_invalid_yaml_is_config_invalid_without_quoting_the_file(tmp_path):
    path = write(tmp_path, "schema_version: 1\nport: [8080\nhidden-token: x\n")
    err = expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))
    assert "hidden-token" not in err.message


def test_top_level_list_is_config_invalid(tmp_path):
    path = write(tmp_path, "- a\n- b\n")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_non_utf8_file_is_config_invalid(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_bytes(b"schema_version: 1\nimage: \xff\xfe\n")
    expect_code("config_invalid", lambda: load_settings(config_flag=str(path), env=env_for(tmp_path)))


def test_path_that_is_a_directory_is_config_invalid(tmp_path):
    directory = tmp_path / "config.yaml"
    directory.mkdir()
    expect_code("config_invalid", lambda: load_settings(config_flag=str(directory), env=env_for(tmp_path)))


def test_utf8_text_is_read(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nhostname: \"ö.example\"\n")
    assert settings.hostname == "ö.example"


# --- Relative and ~ paths ----------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(PATH_KEYS))
def test_relative_path_in_file_resolves_from_the_file_folder(tmp_path, name):
    folder = tmp_path / "project" / "conf"
    folder.mkdir(parents=True)
    path = write(folder, f"schema_version: 1\n{name}: \"data/file.txt\"\n")
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path))
    assert getattr(settings, name) == folder / "data" / "file.txt"


def test_relative_config_flag_resolves_from_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "schema_version: 1\nport: 3333\n", name="rel.yaml")
    settings = load_settings(config_flag="rel.yaml", env=env_for(tmp_path))
    assert settings.config_path == tmp_path / "rel.yaml"
    assert settings.port == 3333


def test_relative_path_in_variable_resolves_from_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = load_settings(config_flag=missing_file(tmp_path),
                             env=env_for(tmp_path, KC_AXI_AUDIT_PATH="audit/kc.jsonl"))
    assert settings.audit_path == tmp_path / "audit" / "kc.jsonl"


@pytest.mark.parametrize("name", sorted(PATH_KEYS))
def test_tilde_in_file_path_expands_from_home(tmp_path, name):
    env = env_for(tmp_path)
    path = write(tmp_path, f"schema_version: 1\n{name}: \"~/kc/thing\"\n")
    settings = load_settings(config_flag=str(path), env=env)
    assert getattr(settings, name) == tmp_path / "home" / "kc" / "thing"


def test_tilde_alone_expands_to_home(tmp_path):
    path = write(tmp_path, "schema_version: 1\nca_file: \"~\"\n")
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path))
    assert settings.ca_file == tmp_path / "home"


def test_tilde_in_variable_expands_from_home(tmp_path):
    env = env_for(tmp_path, KC_AXI_AUDIT_PATH="~/audit.jsonl")
    settings = load_settings(config_flag=missing_file(tmp_path), env=env)
    assert settings.audit_path == tmp_path / "home" / "audit.jsonl"


def test_tilde_in_config_flag_expands_from_home(tmp_path):
    settings = load_settings(config_flag="~/conf/config.yaml", env=env_for(tmp_path))
    assert settings.config_path == tmp_path / "home" / "conf" / "config.yaml"


def test_tilde_falls_back_to_userprofile(tmp_path):
    env = {"USERPROFILE": str(tmp_path / "profile")}
    path = write(tmp_path, "schema_version: 1\naudit_path: \"~/a.jsonl\"\n")
    settings = load_settings(config_flag=str(path), env=env)
    assert settings.audit_path == tmp_path / "profile" / "a.jsonl"


def test_absolute_path_in_file_is_kept(tmp_path):
    target = tmp_path / "abs" / "audit.jsonl"
    path = write(tmp_path, f"schema_version: 1\naudit_path: \"{target.as_posix()}\"\n")
    settings = load_settings(config_flag=str(path), env=env_for(tmp_path))
    assert settings.audit_path == target


def test_empty_path_in_file_gives_the_default(tmp_path):
    settings = load_from_file(tmp_path, "schema_version: 1\nca_file: \"\"\n")
    assert settings.ca_file is None


def test_empty_secrets_dir_in_file_gives_the_computed_default(tmp_path):
    env = env_for(tmp_path)
    settings = load_from_file(tmp_path, "schema_version: 1\nsecrets_dir: \"\"\n", env=env)
    from kc_axi.config import default_config_path

    assert settings.secrets_dir == default_config_path(env).parent / "secrets"


# --- Timeouts (section 6.2) --------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "request_timeout_seconds", "command_timeout_seconds", "ready_timeout_seconds",
    "runtime_timeout_seconds", "pull_timeout_seconds",
])
def test_timeout_default_and_file_override(tmp_path, name):
    default = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    assert getattr(default, name) == DEFAULTS[name]
    settings = load_from_file(tmp_path, f"schema_version: 1\n{name}: 42\n")
    assert getattr(settings, name) == 42


# --- Settings type -----------------------------------------------------------------------------


def test_settings_is_frozen(tmp_path):
    settings = load_settings(config_flag=missing_file(tmp_path), env=env_for(tmp_path))
    assert isinstance(settings, Settings)
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.port = 1  # type: ignore[misc]


def test_file_in_working_directory_is_not_read(tmp_path, monkeypatch):
    # The tool does not read a file in the working directory (section 6.1).
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "schema_version: 1\nport: 9999\n")
    settings = load_settings(env=env_for(tmp_path))
    assert settings.port == 8080
    assert settings.config_exists is False
