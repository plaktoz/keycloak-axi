"""Tests for the secrets file, the reader and the file-level secrets commands (spec 3.5, 4.2, 4.3, 5.8).

Criteria covered here: C37 (the secrets-file half), C39, C40, C43, C44, C45 and C75. Criteria C38, C41, C62, C63
and C73 need the apply flow and the fault-injection seam, so they are not tested here.

Each test writes only under pytest's `tmp_path`. No test calls Keycloak. No test prints a value.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from kc_axi import secrets_store as ss
from kc_axi.errors import KcAxiError

BASE = "http://127.0.0.1:8080"
REALM = "acme"
CLIENT = "svc-reports"
OTHER = "svc-billing"
POSIX_ONLY = pytest.mark.skipif(sys.platform.startswith("win"), reason="file modes are not checked on Windows")


def _secrets_dir(tmp_path: Path) -> Path:
    return tmp_path / "secrets"


def _file(tmp_path: Path, realm: str = REALM) -> Path:
    return _secrets_dir(tmp_path) / f"{realm}.secrets.json"


def _read_json(tmp_path: Path, realm: str = REALM) -> dict:
    return json.loads(_file(tmp_path, realm).read_text(encoding="utf-8"))


def _first_apply(tmp_path: Path, values: dict[str, str] | None = None) -> str:
    """Write a first pending generation with a value for each client, then mark it active. Returns the value."""
    value = ss.generate_value()
    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: value})
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    return value


# --- C37, the secrets-file half ------------------------------------------------------------------------

def test_c37_first_write_creates_pending_then_active_file(tmp_path):
    """C37: the first write creates the file. The value is `pending` before the client create, and `active` after.

    The test checks the file after each step. The Keycloak create is not run here.
    """
    value = ss.generate_value()
    assert not _file(tmp_path).exists()

    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: value})
    doc = _read_json(tmp_path)
    assert doc["active"] == 1
    assert doc["generations"][0]["state"] == "pending"
    assert doc["generations"][0]["clients"][CLIENT]["value"] == value
    assert doc["generations"][0]["clients"][CLIENT]["fingerprint"] == ss.fingerprint(value)
    with pytest.raises(KcAxiError) as pending:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert pending.value.code == "generation_pending"

    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    assert _read_json(tmp_path)["generations"][0]["state"] == "active"
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT) == value


@POSIX_ONLY
def test_c37_file_and_directory_are_owner_only(tmp_path):
    """C37: on Linux and macOS, the file and the directory the tool creates are owner-only.

    Verified on macOS arm64. Linux is verified by reading only, because the same POSIX calls are used.
    """
    _first_apply(tmp_path)
    assert (_file(tmp_path).stat().st_mode & 0o777) == 0o600
    assert (_secrets_dir(tmp_path).stat().st_mode & 0o777) == 0o700


# --- C39, the value recorded by capture ----------------------------------------------------------------

def test_c39_recorded_value_is_the_one_a_consumer_reads(tmp_path):
    """C39: a value written as a generation is the one the reader returns, and the reader returns it unchanged.

    This is the file-level half. `secrets capture` reads the live value from Keycloak, which needs I3. Here the
    test records a value through `write_pending` and `mark_active`, and checks that the reader returns it.
    It also checks that a second read gives the same value, and that the file's active generation is unchanged.
    """
    value = _first_apply(tmp_path)
    before = _read_json(tmp_path)
    first = ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    second = ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert first == second == value
    assert _read_json(tmp_path) == before


# --- C40, rotate and restore ---------------------------------------------------------------------------

def test_c40_rotate_gives_new_fingerprint_and_retires_old(tmp_path):
    """C40: a rotation gives a new fingerprint. The old generation becomes `retired`.

    The file-level half: `write_pending` with a new value, then `mark_active`. The Keycloak apply is not run.
    """
    old = _first_apply(tmp_path)
    new = ss.generate_value()
    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: new})
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)

    doc = _read_json(tmp_path)
    states = {gen["generation"]: gen["state"] for gen in doc["generations"]}
    assert states == {1: "retired", 2: "active"}
    assert doc["active"] == 2
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT) == new
    assert ss.fingerprint(new) != ss.fingerprint(old)


def test_c40_restore_copies_old_value_as_new_generation(tmp_path):
    """C40: `restore N` copies the values of generation N as a new generation. History is not edited."""
    old = _first_apply(tmp_path)
    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    history_before = _read_json(tmp_path)["generations"][0]

    payload = ss.restore_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], generation=1)
    assert payload["status"] == "done"
    assert payload["generation"] == 3
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)

    doc = _read_json(tmp_path)
    assert [gen["generation"] for gen in doc["generations"]] == [1, 2, 3]
    assert doc["generations"][0] == history_before
    assert doc["active"] == 3
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT) == old


def test_c40_restore_refuses_unknown_and_pruned_generations(tmp_path):
    """C40 (restore side of §4.4): an N never written gives generation_unknown; an N deleted by prune gives
    generation_pruned."""
    _first_apply(tmp_path)
    with pytest.raises(KcAxiError) as unknown:
        ss.restore_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], generation=9)
    assert unknown.value.code == "generation_unknown"

    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    ss.prune_generations(_secrets_dir(tmp_path), REALM, BASE, keep=0)
    with pytest.raises(KcAxiError) as pruned:
        ss.restore_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], generation=1)
    assert pruned.value.code == "generation_pruned"


# --- C43, server identity ------------------------------------------------------------------------------

def test_c43_reader_refuses_file_for_another_server(tmp_path):
    """C43 (reader half): a file for another `base_url` raises secrets_server_mismatch. The CLI half needs the
    command and is not tested here."""
    _first_apply(tmp_path)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, "http://127.0.0.1:9090", CLIENT)
    assert exc.value.code == "secrets_server_mismatch"


def test_c43_localhost_and_loopback_are_different_servers(tmp_path):
    """C43: spec 3.5 says `localhost` and `127.0.0.1` are two servers for this check."""
    _first_apply(tmp_path)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, "http://localhost:8080", CLIENT)
    assert exc.value.code == "secrets_server_mismatch"


def test_c43_normalisation_lowers_scheme_and_host_and_drops_one_slash(tmp_path):
    """C43: the server check compares the normalised `base_url`. Case of scheme and host is lowered, and one
    trailing slash is removed."""
    _first_apply(tmp_path)
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, "HTTP://127.0.0.1:8080/", CLIENT)
    assert ss.normalise_base_url("HTTPS://Example.COM:8443/") == "https://example.com:8443"


# --- C44, prune ------------------------------------------------------------------------------------------

def test_c44_prune_deletes_only_retired_generations(tmp_path):
    """C44: prune removes only `retired` generations. `active` and `pending` stay.

    Four rotations give generations 1 to 4 retired, and 5 active. Prune with keep 1 removes 1 to 3 and keeps 4
    (newest retired) and 5. Then a pending generation is refused, and nothing is removed.
    """
    _first_apply(tmp_path)
    for _ in range(4):
        ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
        ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    payload = ss.prune_generations(_secrets_dir(tmp_path), REALM, BASE, keep=1)
    assert payload["pruned"] == 3
    doc = _read_json(tmp_path)
    assert [(gen["generation"], gen["state"]) for gen in doc["generations"]] == [(4, "retired"), (5, "active")]

    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
    before = _read_json(tmp_path)
    with pytest.raises(KcAxiError) as exc:
        ss.prune_generations(_secrets_dir(tmp_path), REALM, BASE, keep=0)
    assert exc.value.code == "generation_pending"
    assert _read_json(tmp_path) == before


def test_c44_active_generation_survives_keep_zero(tmp_path):
    """C44: with keep 0, every retired generation goes, and the active one stays."""
    _first_apply(tmp_path)
    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
    ss.mark_active(_secrets_dir(tmp_path), REALM, BASE)
    ss.prune_generations(_secrets_dir(tmp_path), REALM, BASE, keep=0)
    doc = _read_json(tmp_path)
    assert [(gen["generation"], gen["state"]) for gen in doc["generations"]] == [(2, "active")]


# --- C45, realms -----------------------------------------------------------------------------------------

def test_c45_two_realms_on_one_server_have_two_files(tmp_path):
    """C45: each realm has its own file in `secrets_dir`. A write to one realm does not touch the other."""
    value_a = ss.generate_value()
    value_b = ss.generate_value()
    ss.write_pending(_secrets_dir(tmp_path), "acme", BASE, [CLIENT], {CLIENT: value_a})
    ss.mark_active(_secrets_dir(tmp_path), "acme", BASE)
    ss.write_pending(_secrets_dir(tmp_path), "beta", BASE, [CLIENT], {CLIENT: value_b})
    ss.mark_active(_secrets_dir(tmp_path), "beta", BASE)

    assert _file(tmp_path, "acme").exists() and _file(tmp_path, "beta").exists()
    assert ss.read_secret(_secrets_dir(tmp_path), "acme", BASE, CLIENT) == value_a
    assert ss.read_secret(_secrets_dir(tmp_path), "beta", BASE, CLIENT) == value_b


def test_c45_realm_name_cannot_escape_the_directory(tmp_path):
    """C45: a realm name with a path separator is refused, so no file lands outside `secrets_dir`."""
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), "../escape", BASE, CLIENT)
    assert exc.value.code == "config_invalid"


# --- C75, the reader ------------------------------------------------------------------------------------

def test_c75_missing_file_raises_secrets_unreadable(tmp_path):
    """C75: a missing file raises secrets_unreadable."""
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert exc.value.code == "secrets_unreadable"


def test_c75_unparsable_file_raises_secrets_unreadable(tmp_path):
    """C75: a file that is not JSON raises secrets_unreadable."""
    _secrets_dir(tmp_path).mkdir(parents=True)
    _file(tmp_path).write_text("{ not json", encoding="utf-8")
    if not sys.platform.startswith("win"):
        os.chmod(_file(tmp_path), 0o600)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert exc.value.code == "secrets_unreadable"


def test_c75_pending_generation_raises_generation_pending(tmp_path):
    """C75: the active generation is `pending`. The reader raises generation_pending, and does not return the value."""
    ss.write_pending(_secrets_dir(tmp_path), REALM, BASE, [CLIENT], {CLIENT: ss.generate_value()})
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert exc.value.code == "generation_pending"


def test_c75_client_with_no_entry_raises_secrets_missing(tmp_path):
    """C75: a client with no entry in the active generation raises secrets_missing."""
    _first_apply(tmp_path)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, OTHER)
    assert exc.value.code == "secrets_missing"


def test_c75_reader_prints_nothing(tmp_path, capsys):
    """C75: the reader prints nothing, on success and on each failure."""
    value = _first_apply(tmp_path)
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT) == value
    with pytest.raises(KcAxiError):
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, OTHER)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_c75_error_messages_never_contain_a_value(tmp_path):
    """Section 5.8 rule 6: a value never appears in an error. Each failure is raised with the value in the file."""
    value = _first_apply(tmp_path)
    cases = [
        (BASE, OTHER),
        ("http://127.0.0.1:9090", CLIENT),
    ]
    for base, client in cases:
        with pytest.raises(KcAxiError) as exc:
            ss.read_secret(_secrets_dir(tmp_path), REALM, base, client)
        assert value not in exc.value.message
        assert value not in str(exc.value)


@POSIX_ONLY
def test_c75_loose_file_mode_raises_unsafe_file_mode(tmp_path):
    """C75 (spec 5.8, rule 1): a file another user can read raises unsafe_file_mode, with `chmod 600` as help."""
    _first_apply(tmp_path)
    os.chmod(_file(tmp_path), 0o644)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert exc.value.code == "unsafe_file_mode"
    assert exc.value.exit_code == 2
    assert exc.value.help and "chmod 600" in exc.value.help[0]


@POSIX_ONLY
def test_c75_group_read_counts_as_unsafe(tmp_path):
    """Spec 3.5: group access counts. A file with mode 0640 is refused."""
    _first_apply(tmp_path)
    os.chmod(_file(tmp_path), 0o640)
    with pytest.raises(KcAxiError) as exc:
        ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)
    assert exc.value.code == "unsafe_file_mode"


def test_c75_windows_skips_mode_check_verified_by_reading(tmp_path, monkeypatch):
    """Spec 5.4: on Windows the tool does not check file modes. Faked platform, so this runs on macOS.

    Verified by reading only on Windows. The module under test sees a stand-in `sys` with platform "win32".
    """
    _first_apply(tmp_path)
    if sys.platform.startswith("win"):
        pytest.skip("already on Windows")
    os.chmod(_file(tmp_path), 0o644)
    monkeypatch.setattr(ss, "sys", SimpleNamespace(platform="win32"))
    assert ss.read_secret(_secrets_dir(tmp_path), REALM, BASE, CLIENT)


# --- supporting checks ---------------------------------------------------------------------------------

def test_list_generations_shows_fingerprints_and_no_values(tmp_path):
    """Spec 4.3 `secrets list`: the payload carries fingerprints, and no value appears in it."""
    value = _first_apply(tmp_path)
    payload = ss.list_generations(_secrets_dir(tmp_path), REALM, BASE)
    assert payload["status"] == "active"
    assert payload["active"] == 1
    assert payload["generations"][0]["clients"] == {CLIENT: ss.fingerprint(value)}
    assert value not in json.dumps(payload)


def test_list_generations_on_missing_file_is_definitive(tmp_path):
    """Spec 4.5 rule 4: no file gives `status: empty` and exit 0, not a failure."""
    payload = ss.list_generations(_secrets_dir(tmp_path), REALM, BASE)
    assert payload["status"] == "empty"


def test_fingerprint_is_eight_hex_digits():
    """Spec 3.5: a fingerprint is the first 8 hex digits of the SHA-256 of the value."""
    import hashlib

    digest = hashlib.sha256("abc".encode("utf-8")).hexdigest()
    assert ss.fingerprint("abc") == digest[:8]
    assert len(ss.generate_value()) == 43
