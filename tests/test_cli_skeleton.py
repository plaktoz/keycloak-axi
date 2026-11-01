"""I1 acceptance: spec criteria 51, 52 and 53, and the default configuration path (section 6.1)."""

from __future__ import annotations

import io
import socket
import sys
from pathlib import Path

import pytest

from kc_axi import __version__
from kc_axi.cli import BIN, main
from kc_axi.config import default_config_path, resolve_config_path


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


def test_c51_no_argument_view_prints_bin_and_description(monkeypatch, tmp_path):
    # Criterion 51: no network, no runtime. The view prints bin and description.
    monkeypatch.setenv("KC_AXI_CONFIG", str(tmp_path / "missing.yaml"))

    def no_network(*args, **kwargs):
        raise AssertionError("the no-argument view opened a socket")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)

    code, text = run()

    assert code == 0
    assert text.startswith(f"bin: {BIN}\n")
    assert "description: " in text
    assert "config_exists: false" in text


def test_c51_no_argument_view_reports_existing_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("schema_version: 1\n", encoding="utf-8")
    monkeypatch.setenv("KC_AXI_CONFIG", str(cfg))

    code, text = run()

    assert code == 0
    assert "config_exists: true" in text


def test_c52_version_reads_no_file(monkeypatch, tmp_path, capsys):
    # Criterion 52: --version answers without reading any file. The configuration path points
    # at a file that must stay closed.
    tripwire = tmp_path / "tripwire.yaml"
    tripwire.write_text("this must not be read", encoding="utf-8")
    monkeypatch.setenv("KC_AXI_CONFIG", str(tripwire))
    opened = []
    real_read = Path.read_text

    def spy(self, *args, **kwargs):
        opened.append(self)
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", spy)

    code = main(["--version"])

    assert code == 0
    assert capsys.readouterr().out.strip() == f"{BIN} {__version__}"
    assert tripwire not in opened


def test_c52_version_text_on_stdout(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"{BIN} {__version__}"


def test_c53_unknown_flag_exits_2_and_lists_valid_flags():
    # Criterion 53: an unknown flag exits 2 with flag_not_valid, and lists the valid flags.
    code, text = run("clients", "--nope")

    assert code == 2
    assert text.startswith("error: flag_not_valid")
    assert "help[1]:" in text
    for flag in ("--realm", "--json", "--limit", "--yes", "--allow-remote"):
        assert flag in text


def test_c53_unknown_top_level_flag_exits_2():
    code, text = run("--nope")
    assert code == 2
    assert "error: flag_not_valid" in text


def test_unknown_command_is_a_usage_error():
    code, text = run("bogus-command")
    assert code == 2
    assert "error: usage" in text


def test_json_error_uses_the_envelope_of_section_4_3():
    import json

    code, text = run("clients", "--nope", "--json")
    payload = json.loads(text)
    assert code == 2
    assert payload["schema_version"] == 1
    assert payload["command"] == "clients"
    assert payload["error"]["code"] == "flag_not_valid"
    assert "help" in payload["error"]


def test_unbuilt_command_exits_2_until_its_task_lands():
    code, text = run("apply")  # I7 builds `apply`; change this when it lands
    assert code == 2
    assert "error: usage" in text


def test_default_config_path_macos():
    path = default_config_path({"HOME": "/Users/x"}, platform="darwin")
    assert path == Path("/Users/x/Library/Application Support/kc-axi/config.yaml")


def test_default_config_path_linux_honours_xdg():
    path = default_config_path({"HOME": "/home/x", "XDG_CONFIG_HOME": "/cfg"}, platform="linux")
    assert path == Path("/cfg/kc-axi/config.yaml")


def test_default_config_path_linux_without_xdg():
    path = default_config_path({"HOME": "/home/x"}, platform="linux")
    assert path == Path("/home/x/.config/kc-axi/config.yaml")


def test_default_config_path_windows_uses_appdata():
    path = default_config_path({"APPDATA": r"C:\Users\x\AppData\Roaming", "USERPROFILE": r"C:\Users\x"}, platform="win32")
    assert path.parts[-2:] == ("kc-axi", "config.yaml")
    assert "AppData" in str(path)


def test_flag_beats_variable_beats_default(tmp_path):
    env = {"KC_AXI_CONFIG": str(tmp_path / "env.yaml")}
    assert resolve_config_path(str(tmp_path / "flag.yaml"), env) == tmp_path / "flag.yaml"
    assert resolve_config_path(None, env) == tmp_path / "env.yaml"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX path check")
def test_relative_flag_resolves_from_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert resolve_config_path("rel.yaml", {}) == tmp_path / "rel.yaml"
