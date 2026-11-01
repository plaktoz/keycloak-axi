"""I4 acceptance: spec criteria 8, 9, 13, 14, 15, 16 and 64 (`up`, `down`, `status`).

Most tests run against stub `podman` and `docker` scripts on a PATH that holds only the stub directory. The
stubs read canned data from JSON files and log each call, so a test can check the arguments. The readiness
wait talks to a fake Keycloak on loopback. No test starts a real container. The one test marked `runtime` is
read-only, and it runs only when KC_AXI_RUNTIME_TESTS=1 is set.

The stub scripts are POSIX-only (shebang and executable bit). They are skipped on Windows, which is out of scope.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from kc_axi import runtime
from kc_axi.errors import KcAxiError
from kc_axi.runtime import RuntimeSettings, down, status, up

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stub runtimes are POSIX scripts (verified by reading on Windows)")

IMAGE = "quay.io/keycloak/keycloak:26.6.4"
NAME = "kc-axi-test"
PASSWORD = "pw-never-print-7f3a"
INSPECT_ENV = ["KC_HOSTNAME=localhost", "KC_BOOTSTRAP_ADMIN_USERNAME=admin"]

STUB = """#!{python}
import json, os, sys, time
from pathlib import Path

name = Path(__file__).name
state = Path(os.environ["KC_STUB_STATE"])
args = sys.argv[1:]
data_path = state / (name + ".json")
data = json.loads(data_path.read_text(encoding="utf-8")) if data_path.exists() else {{}}
log_path = state / (name + ".log")
seen = []
if log_path.exists():
    seen = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
keys = ("KC_BOOTSTRAP_ADMIN_USERNAME", "KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_HOSTNAME", "JAVA_OPTS_APPEND")
record = {{"argv": args, "env": {{k: os.environ[k] for k in keys if k in os.environ}}}}
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record) + "\\n")

if args == ["--version"]:
    key = "version"
else:
    key = "_".join(args[:2]) if args[:1] and args[0] in ("container", "volume") else (args[0] if args else "none")
joined = " ".join(args)
if data.get("sleep_on") and joined.startswith(data["sleep_on"]):
    time.sleep(float(data.get("sleep_seconds", 0)))

stdout = data.get(key + "_stdout", "")
if key == "container_ls":
    calls = sum(1 for r in seen if r["argv"][:2] == ["container", "ls"])
    states = data.get("ls_states", [""])
    stdout = (states[min(calls, len(states) - 1)] or "") + ("\\n" if states[min(calls, len(states) - 1)] else "")
sys.stdout.write(stdout)
sys.stderr.write(data.get(key + "_stderr", ""))
sys.exit(int(data.get(key + "_rc", 0)))
"""


class Stubs:
    """A PATH directory with stub runtimes. A runtime is installed when its stub file exists."""

    def __init__(self, root: Path):
        self.bin = root / "bin"
        self.state = root / "state"
        self.bin.mkdir(parents=True)
        self.state.mkdir(parents=True)

    def install(self, name: str) -> None:
        path = self.bin / name
        path.write_text(STUB.format(python=sys.executable), encoding="utf-8")
        path.chmod(0o755)

    def set(self, name: str, **data) -> None:
        (self.state / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")

    def records(self, name: str) -> list[dict]:
        log = self.state / f"{name}.log"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def argv(self, name: str) -> list[list[str]]:
        return [record["argv"] for record in self.records(name)]


@pytest.fixture
def stubs(tmp_path, monkeypatch):
    s = Stubs(tmp_path / "stubs")
    monkeypatch.setenv("PATH", str(s.bin))  # only the stubs are visible to the tool
    monkeypatch.setenv("KC_STUB_STATE", str(s.state))
    return s


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib name
        srv = self.server
        srv.hits += 1
        ready = srv.ready_after is not None and srv.hits > srv.ready_after
        body = json.dumps({"realm": "master"}).encode("utf-8") if ready else b"{}"
        self.send_response(200 if ready else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the test output quiet
        pass


class FakeKeycloak(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.ready_after: int | None = None  # None: never ready
        self.hits = 0

    def server_bind(self):
        # The stdlib calls socket.getfqdn here, a reverse lookup that takes about 35 seconds on this host.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]

    @property
    def port(self) -> int:
        return self.server_address[1]


@pytest.fixture
def keycloak():
    server = FakeKeycloak()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_settings(port: int, **over) -> RuntimeSettings:
    values = dict(
        base_url=f"http://127.0.0.1:{port}",
        port=port,
        image=IMAGE,
        container_name=NAME,
        runtime="auto",
        volume="kc-test-data",
        hostname="localhost",
        admin_password=PASSWORD,
        audit_path="/tmp/kc-axi-i4-audit.jsonl",
        ready_timeout_seconds=5,
        request_timeout_seconds=2,
        runtime_timeout_seconds=5,
        pull_timeout_seconds=5,
    )
    values.update(over)
    return RuntimeSettings(**values)


def inspect_json(state: str = "running", *, env=None, oom: bool = False, port: int = 8080) -> str:
    record = [{
        "Config": {"Image": IMAGE, "Env": list(INSPECT_ENV if env is None else env)},
        "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}},
        "State": {"Status": state, "OOMKilled": oom},
    }]
    return json.dumps(record)


def login_ok(version: str = "26.6.4"):
    return lambda: {"version": version}


# ------------------------------------------------------------------ C8: no password in runtime arguments


def test_c8_password_is_only_in_the_subprocess_environment(stubs, keycloak):
    # Criterion 8: the password is in no runtime argument and no file the tool writes.
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 0
    settings = make_settings(keycloak.port)

    result = up(settings, login=login_ok(), sleep=lambda s: None)

    assert result["status"] == "started"
    all_args = [arg for call in stubs.argv("podman") for arg in call]
    assert not any(PASSWORD in arg for arg in all_args)
    run = next(call for call in stubs.argv("podman") if call[0] == "run")
    assert "KC_BOOTSTRAP_ADMIN_PASSWORD" in run  # bare name: the runtime copies the value from the environment
    assert f"KC_BOOTSTRAP_ADMIN_PASSWORD={PASSWORD}" not in run
    env_seen = next(r["env"] for r in stubs.records("podman") if r["argv"][0] == "run")
    assert env_seen["KC_BOOTSTRAP_ADMIN_PASSWORD"] == PASSWORD  # the value does reach the runtime environment
    assert env_seen["KC_BOOTSTRAP_ADMIN_USERNAME"] == "admin"
    assert PASSWORD not in json.dumps(result)


def test_c8_runtime_error_text_is_redacted(stubs, keycloak):
    # A runtime that echoes the password in its error must not leak it (section 5.4, redaction).
    stubs.install("podman")
    stubs.set("podman", ls_states=[""], run_rc=125, run_stderr=f"Error: bad value {PASSWORD}\n")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert caught.value.code == "runtime_failed"
    assert PASSWORD not in str(caught.value) and PASSWORD not in json.dumps(caught.value.fields)


def test_c8_status_output_has_no_password(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json())
    result = status(make_settings(closed_port()), probe=lambda: {"server": "up", "version": "26.6.4"})
    assert PASSWORD not in json.dumps(result)


# ------------------------------------------------------------------ C9: image rules


@pytest.mark.parametrize(
    "image",
    ["", "keycloak:26.6.4", "quay.io/keycloak/keycloak", "quay.io/keycloak/keycloak:latest",
     "keycloak/keycloak:26.6.4", "quay.io/keycloak/keycloak:"],
)
def test_c9_bad_image_exits_2_before_any_runtime_call(stubs, image):
    # Criterion 9: no image, a short name, or the tag latest. The check runs before the runtime is called.
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), image=image), login=login_ok())
    assert caught.value.code == "image_invalid"
    assert caught.value.exit_code == 2
    assert stubs.records("podman") == []


def test_c9_fully_qualified_images_pass_the_check():
    runtime.check_image("quay.io/keycloak/keycloak:26.6.4")
    runtime.check_image("quay.io/keycloak/keycloak@sha256:" + "a" * 64)
    runtime.check_image("localhost:5000/keycloak/keycloak:26.6.4")


# ------------------------------------------------------------------ C13: start, already running, absent


def test_c13_up_on_a_stopped_container_starts_it(stubs, keycloak):
    # Criterion 13: `up` on a stopped container starts it and prints started.
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited", "running"], container_inspect_stdout=inspect_json("exited"))
    keycloak.ready_after = 0
    result = up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert result["status"] == "started"
    calls = stubs.argv("podman")
    assert ["start", NAME] in calls
    assert not any(call[0] == "run" for call in calls)


def test_c13_up_on_a_running_container_says_already_running(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running", "running"], container_inspect_stdout=inspect_json("running"))
    keycloak.ready_after = 0
    result = up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert result["status"] == "already_running"
    calls = stubs.argv("podman")
    assert not any(call[0] in ("run", "start") for call in calls)


def test_c13_down_with_no_container_is_already_absent(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=[""])
    result = down(make_settings(closed_port()))
    assert result == {"status": "already_absent", "runtime": "podman", "container": NAME, "volume": "kept"}
    assert not any(call[0] in ("stop", "rm") for call in stubs.argv("podman"))


# ------------------------------------------------------------------ C14: down --purge never removes a host path


def test_c14_purge_with_a_host_path_removes_nothing_from_the_host(stubs, tmp_path):
    # Criterion 14: a host-path volume is kept, with `down --purge --yes`.
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited"])
    data_dir = tmp_path / "realm-data"
    data_dir.mkdir()
    (data_dir / "keep.txt").write_text("realm", encoding="utf-8")
    result = down(make_settings(closed_port(), volume=str(data_dir)), purge=True, yes=True)
    assert result["volume"] == "kept"
    assert not any(call[:2] == ["volume", "rm"] for call in stubs.argv("podman"))
    assert (data_dir / "keep.txt").read_text(encoding="utf-8") == "realm"


def test_c14_purge_of_a_named_volume_removes_only_that_volume(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited"])
    result = down(make_settings(closed_port()), purge=True, yes=True)
    assert result["volume"] == "removed"
    calls = stubs.argv("podman")
    assert ["volume", "rm", "kc-test-data"] in calls
    assert calls.index(["rm", NAME]) < calls.index(["volume", "rm", "kc-test-data"])


def test_c14_missing_named_volume_is_absent(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=[""], volume_rm_rc=1, volume_rm_stderr='Error: no volume with name "kc-test-data" found: no such volume')
    result = down(make_settings(closed_port()), purge=True, yes=True)
    assert result["volume"] == "absent"


def test_c14_volume_in_use_is_runtime_failed(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited"], volume_rm_rc=1, volume_rm_stderr="Error: volume is in use by container abc")
    with pytest.raises(KcAxiError) as caught:
        down(make_settings(closed_port()), purge=True, yes=True)
    assert caught.value.code == "runtime_failed"


def test_c14_purge_needs_yes_and_calls_no_runtime(stubs):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        down(make_settings(closed_port()), purge=True, yes=False)
    assert caught.value.code == "confirm_required"
    assert stubs.records("podman") == []


def test_c14_empty_volume_needs_yes(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited"])
    with pytest.raises(KcAxiError) as caught:
        down(make_settings(closed_port(), volume=""), yes=False)
    assert caught.value.code == "confirm_required"


def test_down_with_neither_runtime_installed_is_already_absent(stubs):
    # Spec 5.2 and 7: no runtime and no purge, so nothing can exist to remove.
    result = down(make_settings(closed_port()))
    assert result["status"] == "already_absent"
    assert result["runtime"] is None


def test_down_with_a_named_runtime_that_is_not_installed_is_runtime_missing(stubs):
    # Owner decision 2026-10-27 (1C): a named runtime that is missing is an error, not "already absent".
    for name in ("podman", "docker"):
        with pytest.raises(KcAxiError) as caught:
            down(make_settings(closed_port(), runtime=name))
        assert caught.value.code == "runtime_missing"


def test_down_purge_with_both_runtimes_and_no_container_is_runtime_ambiguous(stubs):
    # Owner decision 2026-10-27 (2A): the volume's runtime is unknown, so nothing is deleted on a guess.
    stubs.install("podman")
    stubs.install("docker")
    with pytest.raises(KcAxiError) as caught:
        down(make_settings(closed_port()), purge=True, yes=True)
    assert caught.value.code == "runtime_ambiguous"
    assert any("--runtime podman" in line for line in caught.value.help)


def test_down_purge_with_neither_runtime_is_runtime_missing(stubs):
    with pytest.raises(KcAxiError) as caught:
        down(make_settings(closed_port()), purge=True, yes=True)
    assert caught.value.code == "runtime_missing"


# ------------------------------------------------------------------ C15: no automatic :Z or :U


def test_c15_host_path_gets_no_z_or_u_by_default(stubs, keycloak, tmp_path):
    # Criterion 15: the tool adds no :Z and no :U to a host path.
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 0
    host = tmp_path / "kc-data"
    up(make_settings(keycloak.port, volume=str(host)), login=login_ok(), sleep=lambda s: None)
    run = next(call for call in stubs.argv("podman") if call[0] == "run")
    mount = run[run.index("-v") + 1]
    assert mount == f"{host}:/opt/keycloak/data"
    assert not mount.endswith((":Z", ":U"))


def test_c15_volume_options_are_added_only_when_set(stubs, keycloak, tmp_path):
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 0
    host = tmp_path / "kc-data"
    up(make_settings(keycloak.port, volume=str(host), volume_options="Z"), login=login_ok(), sleep=lambda s: None)
    run = next(call for call in stubs.argv("podman") if call[0] == "run")
    assert run[run.index("-v") + 1] == f"{host}:/opt/keycloak/data:Z"


def test_c15_named_volume_mount_and_volume_create(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 0
    up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    calls = stubs.argv("podman")
    assert ["volume", "create", "kc-test-data"] in calls
    run = next(call for call in calls if call[0] == "run")
    assert run[run.index("-v") + 1] == "kc-test-data:/opt/keycloak/data"
    assert run[run.index("-p") + 1] == f"127.0.0.1:{keycloak.port}:8080"


@pytest.mark.parametrize("volume", ["bad:name", "~/data"])
def test_c15_colon_or_tilde_volume_is_refused(stubs, volume):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), volume=volume), login=login_ok())
    assert caught.value.code == "volume_invalid"
    assert caught.value.exit_code == 2


# ------------------------------------------------------------------ C16: early container_exited


def test_c16_container_that_stops_during_readiness_fails_early(stubs, keycloak):
    # Criterion 16: a stop during readiness exits with container_exited, well before ready_timeout_seconds.
    stubs.install("podman")
    stubs.set(
        "podman",
        ls_states=["running", "running", "exited"],
        container_inspect_stdout=inspect_json("exited", oom=False),
    )
    settings = make_settings(keycloak.port, ready_timeout_seconds=60)
    started = time.monotonic()
    with pytest.raises(KcAxiError) as caught:
        up(settings, login=login_ok())
    elapsed = time.monotonic() - started
    assert caught.value.code == "container_exited"
    assert caught.value.exit_code == 1
    assert caught.value.fields["state"] == "exited"
    assert caught.value.fields["oom_killed"] is False
    assert elapsed < 5, f"took {elapsed:.1f}s; the stop must be seen within 5 seconds"


def test_c16_oom_kill_names_the_state_and_suggests_java_opts(stubs, keycloak):
    stubs.install("podman")
    stubs.set(
        "podman",
        ls_states=["running", "exited"],
        container_inspect_stdout=inspect_json("exited", oom=True),
    )
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port, ready_timeout_seconds=60), login=login_ok())
    err = caught.value
    assert err.code == "container_exited"
    assert err.fields["oom_killed"] is True
    help_text = "\n".join(err.help)
    assert 'java_opts: "-Xms256m -Xmx640m"' in help_text
    assert "4 GiB" in help_text


def test_c16_readiness_timeout_passes_the_timeout_value(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json("running"))
    keycloak = FakeKeycloak()
    thread = threading.Thread(target=keycloak.serve_forever, daemon=True)
    thread.start()
    try:
        keycloak.ready_after = None  # never ready
        with pytest.raises(KcAxiError) as caught:
            up(make_settings(keycloak.port, ready_timeout_seconds=2), login=login_ok())
    finally:
        keycloak.shutdown()
        keycloak.server_close()
    assert caught.value.code == "keycloak_timeout"
    assert caught.value.fields["ready_timeout_seconds"] == 2


def test_up_ready_wait_returns_after_keycloak_answers(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 1
    result = up(make_settings(keycloak.port), login=login_ok("26.6.4"), sleep=lambda s: None)
    assert result["status"] == "started"
    assert result["version"] == "26.6.4"
    assert result["issuer"] == f"http://localhost:{keycloak.port}/realms/master"
    assert result["warnings"] == []


def test_up_warns_when_the_container_hostname_differs(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running", "running"], container_inspect_stdout=inspect_json("running", env=["KC_HOSTNAME=other"]))
    keycloak.ready_after = 0
    result = up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert len(result["warnings"]) == 1 and "other" in result["warnings"][0]


def test_up_auth_failure_names_both_causes(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", ls_states=["", "running"])
    keycloak.ready_after = 0

    def refused():
        raise KcAxiError("auth_failed", "admin login refused")

    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port), login=refused, sleep=lambda s: None)
    assert caught.value.code == "auth_failed"
    text = "\n".join(caught.value.help)
    assert "KC_BOOTSTRAP_ADMIN" in text and "volume" in text


def test_up_refuses_a_port_that_differs_from_base_url(stubs):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(9999, base_url=f"http://127.0.0.1:{closed_port()}"), login=login_ok())
    assert caught.value.exit_code == 2
    assert stubs.records("podman") == []


def test_up_refuses_plain_http_to_a_remote_host_as_insecure_url(stubs):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(8080, base_url="http://keycloak.example.org:8080"), login=login_ok())
    assert caught.value.code == "insecure_url"


def test_up_refuses_without_audit_path_or_credential(stubs):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), audit_path=""), login=login_ok())
    assert caught.value.code == "audit_required"
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), admin_password=""), login=login_ok())
    assert caught.value.code == "credential_missing"


def test_up_container_in_an_unhandled_state_is_container_state(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["paused"])
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port()), login=login_ok())
    assert caught.value.code == "container_state"


def test_port_in_use_is_reported(stubs, keycloak):
    stubs.install("podman")
    stubs.set(
        "podman",
        ls_states=[""],
        run_rc=125,
        run_stderr="Error: rootlessport listen tcp 127.0.0.1:8080: bind: address already in use",
    )
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert caught.value.code == "port_in_use"


def test_runtime_timeout_passes_runtime_timeout_seconds(stubs):
    stubs.install("podman")
    stubs.set("podman", sleep_on="container ls", sleep_seconds=3, ls_states=[""])
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), runtime_timeout_seconds=1), login=login_ok())
    assert caught.value.code == "runtime_timeout"
    assert caught.value.fields["runtime_timeout_seconds"] == 1


def test_pull_timeout_passes_pull_timeout_seconds(stubs, keycloak):
    stubs.install("podman")
    stubs.set("podman", sleep_on="run", sleep_seconds=3, ls_states=[""])
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port, pull_timeout_seconds=1), login=login_ok(), sleep=lambda s: None)
    assert caught.value.code == "runtime_timeout"
    assert caught.value.fields["pull_timeout_seconds"] == 1


# ------------------------------------------------------------------ runtime choice (spec 5.2)


def test_podman_machine_stopped_is_runtime_missing_with_help(stubs):
    stubs.install("podman")
    stubs.set("podman", info_rc=125, info_stderr="Cannot connect to Podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port()), login=login_ok())
    assert caught.value.code == "runtime_missing"
    assert "podman machine start" in caught.value.help


def test_no_runtime_installed_is_runtime_missing(stubs):
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port()), login=login_ok())
    assert caught.value.code == "runtime_missing"


def test_up_with_both_installed_and_no_container_is_ambiguous(stubs, keycloak):
    # Both installed, neither holds the container: up is ambiguous (section 5.2).
    stubs.install("podman")
    stubs.install("docker")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert caught.value.code == "runtime_ambiguous"
    assert "kc-axi up --runtime podman" in caught.value.help


def test_the_runtime_that_holds_the_container_is_used(stubs, keycloak):
    stubs.install("podman")
    stubs.install("docker")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json("running"))
    keycloak.ready_after = 0
    result = up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert result["runtime"] == "podman"
    assert not any(call[0] in ("run", "start") for call in stubs.argv("docker"))


def test_docker_is_used_when_only_docker_is_installed(stubs, keycloak):
    stubs.install("docker")
    stubs.set("docker", ls_states=["", "running"])
    keycloak.ready_after = 0
    result = up(make_settings(keycloak.port), login=login_ok(), sleep=lambda s: None)
    assert result["runtime"] == "docker"
    assert ["volume", "create", "kc-test-data"] in stubs.argv("docker")


def test_explicit_runtime_that_is_not_installed_is_runtime_missing(stubs):
    stubs.install("podman")
    with pytest.raises(KcAxiError) as caught:
        up(make_settings(closed_port(), runtime="docker"), login=login_ok())
    assert caught.value.code == "runtime_missing"


# ------------------------------------------------------------------ C64: status and the ambiguity rule


def test_c64_status_exits_1_when_both_runtimes_hold_the_container(stubs):
    # Criterion 64: both runtimes hold the container.
    stubs.install("podman")
    stubs.install("docker")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json("running"))
    stubs.set("docker", ls_states=["running"])
    with pytest.raises(KcAxiError) as caught:
        status(make_settings(closed_port()))
    assert caught.value.code == "runtime_ambiguous"
    assert caught.value.exit_code == 1


def test_c64_status_with_no_runtime_installed_exits_1(stubs):
    with pytest.raises(KcAxiError) as caught:
        status(make_settings(closed_port()))
    assert caught.value.code == "runtime_missing"
    assert caught.value.exit_code == 1


def test_c64_status_exits_0_when_the_server_does_not_answer(stubs):
    # Criterion 64: the server does not answer. status reports it and exits 0.
    stubs.install("podman")
    stubs.set("podman", ls_states=[""])
    result = status(make_settings(closed_port()))
    assert result["server"] == "down"
    assert result["version"] is None
    assert result["container"] == "missing"


def test_c64_status_exits_0_with_both_installed_and_no_container(stubs):
    stubs.install("podman")
    stubs.install("docker")
    result = status(make_settings(closed_port()))
    assert result["server"] == "down"
    assert result["container"] == "missing"


def test_c64_status_reports_server_down_from_the_default_probe(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json("running"))
    result = status(make_settings(closed_port()))
    assert result["status"] == "ok"
    assert result["server"] == "down"
    assert result["container"] == "running"
    assert result["credential"] == "present"


def test_status_of_a_running_container_reads_the_inspect_record(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["running"], container_inspect_stdout=inspect_json("running", port=8080))
    result = status(
        make_settings(8080, base_url="http://127.0.0.1:8080"),
        probe=lambda: {"server": "up", "version": "26.6.4"},
    )
    assert result["runtime"] == "podman"
    assert result["container"] == "running"
    assert result["image"] == IMAGE
    assert result["port"] == 8080
    assert result["hostname"] == "localhost"
    assert result["issuer"] == "http://localhost:8080/realms/master"
    assert result["server"] == "up"
    assert result["version"] == "26.6.4"
    assert "oom_killed" not in result


def test_status_of_a_stopped_container_reports_oom(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["exited"], container_inspect_stdout=inspect_json("exited", oom=True))
    result = status(make_settings(closed_port()), probe=lambda: {"server": "down", "version": None})
    assert result["container"] == "stopped"
    assert result["oom_killed"] is True


def test_status_without_a_credential_has_no_version(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=[""])
    result = status(make_settings(closed_port(), admin_password=""), probe=lambda: {"server": "up", "version": "26.6.4"})
    assert result["credential"] == "missing"
    assert result["version"] is None
    assert result["container"] == "missing"


def test_status_with_no_container_in_either_installed_runtime_is_missing(stubs):
    stubs.install("podman")
    stubs.install("docker")
    result = status(make_settings(closed_port()))
    assert result["runtime"] is None
    assert result["container"] == "missing"


def test_status_maps_an_unhandled_state_to_other(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=["paused"], container_inspect_stdout=inspect_json("paused"))
    result = status(make_settings(closed_port()))
    assert result["container"] == "other:paused"


def test_status_probe_that_fails_to_connect_reports_server_down(stubs):
    stubs.install("podman")
    stubs.set("podman", ls_states=[""])

    def unreachable():
        raise KcAxiError("keycloak_unreachable", "no answer")

    result = status(make_settings(closed_port()), probe=unreachable)
    assert result["server"] == "down"
    assert result["status"] == "ok"


# ------------------------------------------------------------------ real runtime (read-only, gated)


@pytest.mark.runtime
def test_status_against_a_real_runtime_is_read_only():
    # Needs a real runtime. Gated by KC_AXI_RUNTIME_TESTS=1 until the lead schedules real-runtime checks.
    if os.environ.get("KC_AXI_RUNTIME_TESTS") != "1":
        pytest.skip("real-runtime checks are scheduled by the lead (set KC_AXI_RUNTIME_TESTS=1)")
    if not (shutil.which("podman") or shutil.which("docker")):
        pytest.skip("no container runtime is installed")
    unique = f"kc-axi-i4-probe-{os.getpid()}"
    result = status(make_settings(closed_port(), container_name=unique, runtime="auto"))
    assert result["container"] == "missing"
    assert result["server"] == "down"
