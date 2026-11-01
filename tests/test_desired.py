"""I6 acceptance, file half: spec section 3.4 and criteria 23, with the typed codes of section 4.4.

Every case here exits 2 before any request. No network is used.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from kc_axi.desired import ConfigFile, UsersFile, load_desired
from kc_axi.errors import KcAxiError

UUID1 = "7c1e0000-0000-4000-8000-000000000001"
UUID2 = "7C1E0000-0000-4000-8000-000000000002"


def write(tmp_path: Path, text: str, name: str = "f.yaml", mode: int = 0o600) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    path.chmod(mode)
    return path


def config(tmp_path: Path, body: str = "", head: str = "schema_version: 1\nkind: config\nowner: acme\n") -> Path:
    return write(tmp_path, head + textwrap.dedent(body).lstrip("\n"), "c.yaml", 0o644)


def users(tmp_path: Path, body: str, mode: int = 0o600) -> Path:
    return write(tmp_path, "schema_version: 1\nkind: users\nrealm: acme\n" + textwrap.dedent(body).lstrip("\n"), "u.yaml", mode)


def code_of(path: Path, **kw) -> str:
    with pytest.raises(KcAxiError) as caught:
        load_desired(path, **kw)
    assert caught.value.exit_code == 2
    return caught.value.code


# ------------------------------------------------------------------------------ config file


def test_a_full_config_file_is_normalised(tmp_path):
    path = config(tmp_path, """
        realm: {name: acme, enabled: "true", displayName: Acme, accessTokenLifespan: 900, registrationAllowed: false}
        clients:
          - {clientId: zeta, publicClient: true, pkce: S256, redirectUris: [b, a, a], webOrigins: ["http://x"]}
          - clientId: alpha
            publicClient: false
            secret_managed: "true"
            mappers:
              - {name: z-aud, kind: audience, audience: zeta}
              - {name: a-aud, kind: audience, audience: zeta}
    """)
    desired = load_desired(path)
    assert isinstance(desired, ConfigFile)
    assert desired.owner == "acme"
    assert desired.realm == {
        "name": "acme", "enabled": True, "displayName": "Acme", "accessTokenLifespan": 900, "registrationAllowed": False,
    }
    assert [c["clientId"] for c in desired.clients] == ["alpha", "zeta"]  # sorted by clientId
    assert desired.clients[0]["secret_managed"] is True  # "true" equals true
    assert [m["name"] for m in desired.clients[0]["mappers"]] == ["a-aud", "z-aud"]  # a set: sorted
    assert desired.clients[1]["redirectUris"] == ["a", "b"]  # a set: sorted, no duplicate


def test_only_declared_fields_are_present(tmp_path):
    desired = load_desired(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a}\n"))
    assert desired.realm == {"name": "acme"}
    assert desired.clients == ({"clientId": "a"},)  # no default is filled in, so plan never resets a field


def test_a_client_without_mappers_key_has_no_mappers_entry(tmp_path):
    desired = load_desired(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a}\n  - {clientId: b, mappers: []}\n"))
    assert "mappers" not in desired.clients[0]
    assert desired.clients[1]["mappers"] == []


def test_c23_a_declared_built_in_client_exits_2_builtin_client(tmp_path):
    for name in ("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"):
        path = config(tmp_path, f"realm: {{name: acme}}\nclients:\n  - {{clientId: {name}}}\n")
        assert code_of(path) == "builtin_client"


def test_unknown_realm_key_exits_2_unknown_field(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme, sslRequired: all}\n")) == "unknown_field"


def test_unknown_client_key_exits_2_unknown_field(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, secret: x}\n")) == "unknown_field"


def test_unknown_top_level_key_exits_2_unknown_field(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme}\nextra: 1\n")) == "unknown_field"


def test_a_typo_is_named_but_other_keys_are_not_echoed(tmp_path):
    with pytest.raises(KcAxiError) as typo:
        load_desired(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, publicClent: true}\n"))
    assert "publicClent" in typo.value.message and "publicClient" in typo.value.message
    with pytest.raises(KcAxiError) as other:
        load_desired(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, hunter2-the-password: x}\n"))
    assert "hunter2" not in other.value.message
    assert "hunter2" not in " ".join(other.value.help)


def test_duplicate_key_exits_2_duplicate_key(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, enabled: true, enabled: false}\n")
    assert code_of(path) == "duplicate_key"


def test_duplicate_client_exits_2_config_invalid(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a}\n  - {clientId: a}\n")) == "config_invalid"


def test_secret_managed_on_a_public_client_exits_2(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, publicClient: true, secret_managed: true}\n")
    assert code_of(path) == "secret_managed_public"


def test_pkce_on_a_confidential_client_exits_2_config_invalid(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, publicClient: false, pkce: S256}\n")
    assert code_of(path) == "config_invalid"


def test_pkce_other_than_s256_exits_2(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, publicClient: true, pkce: plain}\n")
    assert code_of(path) == "config_invalid"


def test_the_admin_realm_is_refused(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: master}\n")) == "admin_realm_refused"
    assert code_of(config(tmp_path, "realm: {name: ops}\n"), admin_realm="ops") == "admin_realm_refused"


def test_realm_flag_that_differs_exits_2_realm_mismatch(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme}\n"), realm_flag="other") == "realm_mismatch"
    assert load_desired(config(tmp_path, "realm: {name: acme}\n"), realm_flag="acme").realm_name == "acme"


@pytest.mark.parametrize("lifespan", ["0", "86401", "-5", "soon", "true", "1.5"])
def test_access_token_lifespan_outside_1_to_86400_exits_2(tmp_path, lifespan):
    assert code_of(config(tmp_path, f"realm: {{name: acme, accessTokenLifespan: {lifespan}}}\n")) == "config_invalid"


@pytest.mark.parametrize("name", ["", "a b", "a/b", "-acme", "ac\nme"])
def test_a_bad_realm_name_exits_2(tmp_path, name):
    path = write(tmp_path, f"schema_version: 1\nkind: config\nowner: o\nrealm:\n  name: {name!r}\n", "c.yaml", 0o644)
    assert code_of(path) == "config_invalid"


def test_a_mapper_of_another_kind_exits_2(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, mappers: [{name: m, kind: hardcoded, audience: x}]}\n")
    assert code_of(path) == "config_invalid"


def test_a_mapper_missing_a_field_exits_2(tmp_path):
    path = config(tmp_path, "realm: {name: acme}\nclients:\n  - {clientId: a, mappers: [{name: m, kind: audience}]}\n")
    assert code_of(path) == "config_invalid"


def test_two_mappers_with_one_name_exit_2(tmp_path):
    body = "realm: {name: acme}\nclients:\n  - clientId: a\n    mappers:\n      - {name: m, kind: audience, audience: x}\n      - {name: m, kind: audience, audience: y}\n"
    assert code_of(config(tmp_path, body)) == "config_invalid"


def test_a_boolean_field_with_a_word_exits_2(tmp_path):
    assert code_of(config(tmp_path, "realm: {name: acme, enabled: maybe}\n")) == "config_invalid"


def test_realm_is_required(tmp_path):
    assert code_of(config(tmp_path, "")) == "config_invalid"


def test_owner_may_be_absent_in_the_file(tmp_path):
    path = write(tmp_path, "schema_version: 1\nkind: config\nrealm: {name: acme}\n", "c.yaml", 0o644)
    assert load_desired(path).owner is None


# ------------------------------------------------------------------------------ header checks


def test_missing_file_exits_2_config_missing(tmp_path):
    assert code_of(tmp_path / "nope.yaml") == "config_missing"


def test_schema_version_is_required_and_checked(tmp_path):
    assert code_of(write(tmp_path, "kind: config\nrealm: {name: a}\n")) == "config_invalid"
    assert code_of(write(tmp_path, "schema_version: 2\nkind: config\nrealm: {name: a}\n")) == "schema_unsupported"
    assert code_of(write(tmp_path, "schema_version: '1'\nkind: config\nrealm: {name: a}\n")) == "config_invalid"


def test_kind_is_required_and_checked(tmp_path):
    assert code_of(write(tmp_path, "schema_version: 1\nrealm: {name: a}\n")) == "config_invalid"
    assert code_of(write(tmp_path, "schema_version: 1\nkind: other\n")) == "config_invalid"


def test_not_yaml_exits_2_without_quoting_the_content(tmp_path):
    path = write(tmp_path, "schema_version: 1\nkind: [unclosed top-secret-text\n")
    with pytest.raises(KcAxiError) as caught:
        load_desired(path)
    assert caught.value.code == "config_invalid"
    assert "top-secret-text" not in caught.value.message


def test_the_file_is_read_with_a_safe_loader(tmp_path):
    path = write(tmp_path, "schema_version: 1\nkind: !!python/object/apply:os.system ['true']\n")
    assert code_of(path) == "config_invalid"


# ------------------------------------------------------------------------------ users file


def test_a_users_file_is_normalised(tmp_path):
    path = users(tmp_path, f"""
        users:
          - {{id: "{UUID2}", username: Zed, email: z@x.test, enabled: "false"}}
          - {{id: "{UUID1}", username: amy, temporary_password_env: AMY_PW, emailVerified: true}}
    """)
    desired = load_desired(path)
    assert isinstance(desired, UsersFile)
    assert desired.realm_name == "acme"
    assert [u["id"] for u in desired.users] == [UUID1, UUID2.lower()]  # sorted, lower-case UUIDs
    assert desired.users[1]["enabled"] is False
    assert desired.users[0]["temporary_password_env"] == "AMY_PW"
    assert "email" not in desired.users[0]


def test_id_is_required_and_must_be_a_uuid(tmp_path):
    assert code_of(users(tmp_path, "users:\n  - {username: a}\n")) == "config_invalid"
    assert code_of(users(tmp_path, "users:\n  - {id: not-a-uuid, username: a}\n")) == "id_invalid"
    assert code_of(users(tmp_path, "users:\n  - {id: 12345, username: a}\n")) == "id_invalid"


def test_an_unknown_user_field_exits_2(tmp_path):
    assert code_of(users(tmp_path, f"users:\n  - {{id: '{UUID1}', username: a, password: x}}\n")) == "unknown_field"


def test_a_password_in_temporary_password_env_is_refused_and_not_echoed(tmp_path):
    path = users(tmp_path, f"users:\n  - {{id: '{UUID1}', username: a, temporary_password_env: 'Sup3r secret!'}}\n")
    with pytest.raises(KcAxiError) as caught:
        load_desired(path)
    assert caught.value.code == "config_invalid"
    assert "Sup3r" not in caught.value.message + " ".join(caught.value.help)


def test_a_repeated_id_or_username_exits_2(tmp_path):
    assert code_of(users(tmp_path, f"users:\n  - {{id: '{UUID1}', username: a}}\n  - {{id: '{UUID1}', username: b}}\n")) == "config_invalid"
    body = f"users:\n  - {{id: '{UUID1}', username: Amy}}\n  - {{id: '{UUID2}', username: amy}}\n"
    assert code_of(users(tmp_path, body)) == "config_invalid"


def test_users_realm_flag_must_match(tmp_path):
    assert code_of(users(tmp_path, "users: []\n"), realm_flag="other") == "realm_mismatch"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_a_users_file_readable_by_others_exits_2_unsafe_file_mode(tmp_path):
    assert code_of(users(tmp_path, "users: []\n", mode=0o644)) == "unsafe_file_mode"


def test_a_users_file_inside_a_git_work_tree_exits_2_unsafe_path(tmp_path):
    (tmp_path / ".git").mkdir()
    assert code_of(users(tmp_path, "users: []\n")) == "unsafe_path"


def test_a_config_file_inside_git_is_fine(tmp_path):
    (tmp_path / ".git").mkdir()
    assert load_desired(config(tmp_path, "realm: {name: acme}\n")).realm_name == "acme"


def test_a_users_file_may_have_no_users(tmp_path):
    assert load_desired(users(tmp_path, "users: []\n")).users == ()
    assert load_desired(users(tmp_path, "")).users == ()
