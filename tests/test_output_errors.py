"""I2a acceptance: spec criteria 1, 2, 3, 54 and 55, the golden files of the default views, and the error registry (section 4.4)."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from kc_axi.errors import EXIT_CODES, KcAxiError
from kc_axi.output import (
    SCHEMA_VERSION,
    Records,
    emit,
    error_payload,
    list_payload,
    page,
    render_compact,
    render_json,
    result_payload,
)
from kc_axi.resources import KINDS, select_fields

GOLDEN = Path(__file__).parent / "golden"
SPEC = Path(__file__).parents[1] / "README.md"


def golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8").rstrip("\n")


def users(n: int) -> list[dict]:
    return [{"username": f"user{i:02d}", "enabled": True} for i in range(n)]


# Criterion 1: an empty list prints status empty and total 0, exits 0, and says what it checked.
def test_c1_empty_list_is_definitive():
    payload = list_payload("users", [], columns=("username", "enabled"), checked="realm acme, 0 users")
    assert payload["status"] == "empty"
    assert payload["total"] == 0
    assert render_compact(payload).rstrip("\n") == golden("users_empty.txt")


# Criterion 2: 21 users show 20 items, the header reads `20 of 21`, and a help line names the next command.
def test_c2_list_shows_limit_and_names_the_next_command():
    payload = list_payload(
        "users",
        users(21),
        columns=("username", "enabled"),
        checked="realm acme, 21 users",
        limit=20,
        more_help="kc-axi users --realm acme --limit 21",
    )
    text = render_compact(payload)
    assert "items[20 of 21]{username,enabled}:" in text
    assert text.count("\n  user") == 20
    assert "help[1]:" in text


def test_c2_default_view_matches_golden_file():
    cols = ("username", "enabled")
    shown = ({"username": "alice", "enabled": True}, {"username": "bob", "enabled": False})
    payload = {
        "status": "active",
        "total": 21,
        "items": Records(shown, 21, cols),
        "help": ["kc-axi users --realm acme --limit 21"],
    }
    assert render_compact(payload).rstrip("\n") == golden("users_list.txt")


# Criterion 3: a comma, a space or a quote in a value keeps the counts and the truncation.
def test_c3_quoted_cell_keeps_counts():
    rows = [{"username": 'a,"b" c', "enabled": True}]
    text = render_compact({"items": page(rows, columns=("username", "enabled"))})
    assert text.rstrip("\n") == golden("quoted_cell.txt")
    assert "items[1 of 1]" in text


def test_c3_long_value_is_cut_with_its_length():
    long = "x" * 201
    text = render_compact({"items": page([{"username": long, "enabled": True}], columns=("username", "enabled"))})
    assert f"{'x' * 200}… (201 chars total)" in text


def test_c3_multiline_value_stays_on_one_line():
    text = render_compact({"items": page([{"username": "a\nb", "enabled": True}], columns=("username", "enabled"))})
    assert "a b,true" in text


# Criterion 54: JSON output has schema_version and the keys of section 4.3.
def test_c54_json_list_has_schema_version_status_total_shown_items():
    payload = list_payload("users", users(3), columns=("username", "enabled"), checked="realm acme", limit=2)
    body = result_payload("users", payload, as_json=True)
    parsed = json.loads(render_json(body))
    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["command"] == "users"
    assert parsed["status"] == "active"
    assert parsed["total"] == 3
    assert parsed["shown"] == 2
    assert len(parsed["items"]) == 2


def test_c54_json_error_envelope_has_code_message_help():
    err = KcAxiError("keycloak_unreachable", "no answer", help=("kc-axi status",), applied=0)
    parsed = json.loads(render_json(error_payload(err, "users", as_json=True)))
    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["error"] == {"code": "keycloak_unreachable", "message": "no answer", "help": "kc-axi status", "applied": 0}


def test_c54_emit_json_prints_one_line():
    out = io.StringIO()
    emit({"status": "ok"}, as_json=True, stream=out)
    assert json.loads(out.getvalue()) == {"status": "ok"}


# Criterion 55: every typed code of section 4.4 is registered with its exit code, and has a test.
def _spec_codes() -> dict[str, int]:
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("### 4.4 Exit codes", 1)[1].split("### 4.5 CLI rules", 1)[0]
    codes: dict[str, int] = {}
    for line in section.splitlines():
        if line.startswith("| 2 |"):
            for code in re.findall(r"`([a-z_]+)`", line.split("|")[3]):
                codes[code] = 2
        elif line.startswith("| `"):
            code = re.match(r"\| `([a-z_]+)`", line).group(1)
            codes[code] = 1
    return codes


@pytest.mark.skipif(not SPEC.exists(), reason="the spec is not in this checkout")
def test_c55_registry_equals_section_4_4_table():
    spec = _spec_codes()
    assert spec, "no codes parsed from section 4.4"
    assert EXIT_CODES == spec, "registry and section 4.4 disagree"


@pytest.mark.parametrize("code", sorted(EXIT_CODES))
def test_c55_every_registered_code_has_its_exit_code(code):
    err = KcAxiError(code, "message")
    assert err.exit_code == EXIT_CODES[code]
    assert err.exit_code in (1, 2)


def test_unregistered_code_is_refused():
    with pytest.raises(KeyError):
        KcAxiError("not_a_code", "message")


def test_error_is_printed_in_compact_form_with_help_limit():
    err = KcAxiError("keycloak_unreachable", "no answer", help=("a", "b", "c", "d"))
    text = render_compact(error_payload(err, "status", as_json=False))
    assert text.splitlines()[0] == "error: keycloak_unreachable"
    assert "help[3]:" in text  # at most three hint lines (section 4.5 rule 10)
    assert "  d" not in text


def test_error_compact_matches_golden_file():
    err = KcAxiError(
        "keycloak_unreachable",
        "no answer from http://127.0.0.1:8080 after 10 seconds",
        help=("kc-axi status",),
    )
    assert render_compact(error_payload(err, "status", as_json=False)).rstrip("\n") == golden("error_compact.txt")


def test_refusal_list_is_carried_in_the_error_fields():
    refusals = page([{"code": "needs_adopt", "kind": "client", "name": "a"}], columns=("code", "kind", "name"))
    err = KcAxiError("needs_adopt", "1 refusal", refusals=refusals)
    text = render_compact(error_payload(err, "apply", as_json=False))
    assert "error: needs_adopt" in text
    assert "refusals[1 of 1]{code,kind,name}:" in text
    assert "  needs_adopt,client,a" in text


# Criterion 1 and 2 at the resource level: field selection follows section 3.2.
def test_select_fields_adds_extra_fields_in_order():
    assert select_fields(KINDS["user"], "email,id") == ("username", "enabled", "email", "id")


def test_select_fields_refuses_unknown_name():
    with pytest.raises(KcAxiError) as info:
        select_fields(KINDS["user"], "password")
    assert info.value.code == "flag_not_valid"
    assert info.value.exit_code == 2


def test_limit_must_be_at_least_one():
    from kc_axi.output import resolve_limit

    with pytest.raises(KcAxiError):
        resolve_limit(0)
    assert resolve_limit(None) == 20
