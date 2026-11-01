"""Container runtime for `up`, `down` and `status` (spec sections 5.2, 5.3, 5.3.1, 5.5 and 5.10).

The runtime runs as a subprocess with an argument list. No shell runs. The admin password reaches the
container only through the subprocess environment, as a bare `-e NAME` (criterion 8).

The caller builds `RuntimeSettings` from the tool configuration (section 6.1) and resolves the password source
(section 5.4). `status` takes a `probe` function from the caller. It returns `{"server": "up" | "down", "version": ...}`.
The default probe only asks `GET <base_url>/realms/master`. `up` takes an optional `login` function. It returns
`{"version": ...}` after the admin login of section 5.3 step 7. The REST client (task I3) provides both.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import KcAxiError

RUNTIMES = ("podman", "docker")
CONTAINER_PORT = 8080
DATA_PATH = "/opt/keycloak/data"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
STOPPED_STATES = ("created", "exited", "stopped")
HANDLED_STATES = ("running",) + STOPPED_STATES
STOP_SECONDS = 10
POLL_SECONDS = 1
PROBE_SECONDS = 2
OOM_JAVA_OPTS = "-Xms256m -Xmx640m"
EXAMPLE_IMAGE = "quay.io/keycloak/keycloak:26.6.4"
INSTALL_HELP = "install Podman or Docker, or pass --runtime with the one you use"
PORT_IN_USE = re.compile(r"address already in use|port is already allocated|port is already in use", re.IGNORECASE)
NO_SUCH_VOLUME = re.compile(r"no such volume|no volume with name", re.IGNORECASE)  # Podman and Docker wording
VOLUME_NAME = re.compile(r"[A-Za-z0-9_.-]+")
VOLUME_OPTIONS = re.compile(r"[A-Za-z0-9_,=]+")
_LOOPBACK_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # a local host never uses a proxy
READY_PROBE_SECONDS = 2  # one readiness GET; keeps container_exited inside 5 seconds (criterion 16)


@dataclass(frozen=True)
class RuntimeSettings:
    """The settings that the runtime needs. The config loader fills them in (task I2b).

    `admin_password` holds the resolved value. It is never printed, never put in an argument and never repr'd.
    """

    base_url: str
    port: int
    image: str = ""
    container_name: str = "keycloak-dev"
    runtime: str = "auto"  # auto | docker | podman
    hostname: str = ""  # KC_HOSTNAME; empty means the host of base_url
    volume: str = "keycloak-dev-data"  # named volume, host path, or empty for no persistence
    volume_options: str = ""  # host path only, for example "Z"
    java_opts: str = ""  # JAVA_OPTS_APPEND; empty means none
    admin_user: str = "admin"
    admin_password: str = field(default="", repr=False)
    audit_path: str = ""  # required by up (section 5.3 step 1)
    ready_timeout_seconds: int = 120
    request_timeout_seconds: int = 10
    runtime_timeout_seconds: int = 30
    pull_timeout_seconds: int = 600


@dataclass(frozen=True)
class _Target:
    runtime: str | None  # None when no runtime holds the container and the choice is not needed
    state: str  # "" when no container


# ---------------------------------------------------------------- image and volume rules


def check_image(image: str) -> None:
    """Section 5.3 step 1: a fully qualified name, a tag or a digest, and no `latest`."""

    def refuse(why: str) -> None:
        raise KcAxiError("image_invalid", f"image {image or '(empty)'}: {why}", help=(f"set image, for example {EXAMPLE_IMAGE}",))

    if not image:
        refuse("no image is set")
    name, at, digest = image.partition("@")
    if at and not digest:
        refuse("the digest is empty")
    parts = name.split("/")
    if len(parts) < 2 or not all(parts):
        refuse("a registry host, a repository and a tag are needed")
    if not _is_registry(parts[0]):
        refuse("the first part must be a registry host; a short name can make the runtime ask for a registry")
    repo, _, tag = parts[-1].partition(":")
    if not repo:
        refuse("the repository is empty")
    if tag == "latest":
        refuse("the tag latest is not allowed")
    if not tag and not at:
        refuse("a tag is needed")


def _is_registry(part: str) -> bool:
    return "." in part or ":" in part or part == "localhost"


def _volume_mount(settings: RuntimeSettings) -> tuple[str, str | None]:
    """Section 5.3.1. Returns (`none` | `named` | `host`, the `-v` value or None)."""
    volume, options = settings.volume, settings.volume_options

    def refuse(why: str) -> None:
        raise KcAxiError("volume_invalid", f"volume {volume!r}: {why}", help=("set volume to a name, a host path, or empty",))

    if not volume:
        if options:
            refuse("volume_options needs a host path")
        return "none", None
    if ":" in volume or volume.startswith("~"):
        refuse("not accepted: a colon or a leading ~")
    if "/" in volume or "\\" in volume or volume.startswith("."):
        if sys.platform == "win32":
            refuse("a host path is not supported on Windows")
        if options and not VOLUME_OPTIONS.fullmatch(options):
            refuse(f"volume_options {options!r} has characters that are not allowed")
        spec = f"{volume}:{DATA_PATH}" + (f":{options}" if options else "")
        return "host", spec  # the tool never adds :Z or :U (section 5.3.1)
    if not VOLUME_NAME.fullmatch(volume):
        refuse("letters, digits, _, . and - only")
    if options:
        refuse("volume_options applies to a host path only")
    return "named", f"{volume}:{DATA_PATH}"


def _check_up(settings: RuntimeSettings) -> None:
    """Section 5.3 step 1. Every check runs before the runtime is called."""
    check_image(settings.image)
    parsed = urllib.parse.urlparse(settings.base_url)
    host = (parsed.hostname or "").lower()
    base_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if base_port != settings.port:
        raise KcAxiError(
            "config_invalid",
            f"port {settings.port} differs from the port of base_url ({base_port})",
            help=(f"set port: {base_port}",),
        )
    if host not in LOCAL_HOSTS:
        if parsed.scheme == "http":
            raise KcAxiError(
                "insecure_url",
                f"base_url uses http with a host that is not local: {host or 'none'}",
                help=("set base_url to http://127.0.0.1:<port>",),
            )
        raise KcAxiError(
            "config_invalid",
            f"up starts a local container, but base_url names {host or 'no host'}",
            help=("set base_url to http://127.0.0.1:<port>",),
        )
    if not settings.admin_password:
        raise KcAxiError(
            "credential_missing",
            "no admin password source",
            help=("set KC_ADMIN_PASSWORD, or admin_password_file",),
        )
    if not settings.audit_path:
        raise KcAxiError("audit_required", "audit_path is not set", help=("set audit_path in the configuration file",))
    _volume_mount(settings)


# ---------------------------------------------------------------- subprocess helpers


def _run(
    argv: list[str],
    *,
    timeout: int,
    timeout_key: str = "runtime_timeout_seconds",
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """One runtime call. Argument list, no shell, a timeout on every call."""
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise KcAxiError("runtime_missing", f"{argv[0]} is not installed", help=(INSTALL_HELP,)) from exc
    except subprocess.TimeoutExpired as exc:
        raise KcAxiError(
            "runtime_timeout",
            f"{' '.join(argv[:2])} gave no answer after {timeout} seconds",
            help=(f"raise {timeout_key} in the configuration file",),
            **{timeout_key: timeout},
        ) from exc
    except OSError as exc:
        raise KcAxiError("runtime_failed", f"{argv[0]} could not run: {exc.strerror or exc}") from exc


def _text(proc: subprocess.CompletedProcess[str], secrets: tuple[str, ...] = ()) -> str:
    """The runtime's own message, on one line, with secrets removed (section 5.4, redaction)."""
    raw = (proc.stderr or "").strip() or (proc.stdout or "").strip() or f"exit status {proc.returncode}"
    text = " ".join(raw.split())
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def _engine_status(runtime: str, timeout: int) -> str:
    """`ok`: installed and answering. `stopped`: installed, but the engine does not answer (for example a
    Podman machine that is stopped). `missing`: not installed."""
    try:
        version = _run([runtime, "--version"], timeout=timeout)
        if version.returncode != 0:
            return "missing"
        info = _run([runtime, "info"], timeout=timeout)
    except KcAxiError as err:
        if err.code == "runtime_missing":
            return "missing"
        raise
    return "ok" if info.returncode == 0 else "stopped"


def _read_state(runtime: str, name: str, timeout: int) -> str:
    """Section 5.2. Empty output means no container. A non-zero exit is `runtime_failed`."""
    proc = _run(
        [runtime, "container", "ls", "--all", "--filter", f"name=^{name}$", "--format", "{{.State}}"],
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc))
    states = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return states[0] if states else ""


def _inspect(runtime: str, name: str, settings: RuntimeSettings) -> dict[str, Any]:
    proc = _run([runtime, "container", "inspect", name], timeout=settings.runtime_timeout_seconds)
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc, (settings.admin_password,)))
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise KcAxiError("runtime_failed", "the runtime gave no readable container record") from exc
    if isinstance(data, list):
        data = data[0] if data else {}
    return data if isinstance(data, dict) else {}


def _env_of(info: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for entry in (info.get("Config") or {}).get("Env") or []:
        key, _, value = str(entry).partition("=")
        values[key] = value
    return values


def _published_port(info: Mapping[str, Any]) -> int | None:
    bindings = (info.get("HostConfig") or {}).get("PortBindings") or {}
    for entry in bindings.get(f"{CONTAINER_PORT}/tcp") or []:
        try:
            return int(entry["HostPort"])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _oom_killed(info: Mapping[str, Any]) -> bool:
    return (info.get("State") or {}).get("OOMKilled") is True


def _realm_ready(url: str, timeout: float) -> bool:
    """A GET that answers HTTP 200 is ready. Any other answer, or no answer, is not."""
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    try:
        if host in LOCAL_HOSTS:
            response = _LOOPBACK_OPENER.open(url, timeout=timeout)
        else:
            response = urllib.request.urlopen(url, timeout=timeout)
        with response:
            return response.status == 200
    except (OSError, http.client.HTTPException, ValueError):
        return False


def _base(settings: RuntimeSettings) -> str:
    return settings.base_url.rstrip("/")


def _hostname(settings: RuntimeSettings) -> str:
    return settings.hostname or urllib.parse.urlparse(settings.base_url).hostname or ""


def _issuer(scheme: str, hostname: str, port: int, realm: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{host}:{port}/realms/{realm}"


# ---------------------------------------------------------------- runtime choice (section 5.2)


def _unavailable(names: tuple[str, ...], engines: Mapping[str, str]) -> KcAxiError:
    stopped = [rt for rt in names if engines[rt] == "stopped"]
    detail = ", ".join(f"{rt} {engines[rt]}" for rt in names)
    if "podman" in stopped:
        help_ = ("podman machine start",)
    elif stopped:
        help_ = (f"start the {stopped[0]} engine",)
    else:
        help_ = (INSTALL_HELP,)
    return KcAxiError("runtime_missing", f"no usable container runtime ({detail})", help=help_)


def _resolve(settings: RuntimeSettings, *, action: str, purge: bool = False) -> _Target:
    """Pick the runtime (section 5.2). `action` is `up`, `down` or `status`."""
    names = RUNTIMES if settings.runtime == "auto" else (settings.runtime,)
    timeout = settings.runtime_timeout_seconds
    engines = {rt: _engine_status(rt, timeout) for rt in names}
    usable = [rt for rt in names if engines[rt] == "ok"]
    if not usable:
        # Owner decision 2026-10-27 (1C): only `auto` with nothing installed is idempotent. A runtime that the
        # operator named is an error when it is missing, because the container may sit in another runtime.
        if action == "down" and not purge and settings.runtime == "auto" and all(engines[rt] == "missing" for rt in names):
            return _Target(None, "")  # nothing installed: no container can be found, so nothing to remove
        raise _unavailable(names, engines)

    states = {rt: _read_state(rt, settings.container_name, timeout) for rt in usable}
    holding = [rt for rt in usable if states[rt]]
    if len(holding) > 1:
        raise KcAxiError(
            "runtime_ambiguous",
            f"both runtimes hold container {settings.container_name}",
            help=tuple(f"kc-axi {action} --runtime {rt}" for rt in holding),
        )
    if holding:
        return _Target(holding[0], states[holding[0]])
    if len(usable) > 1:
        if action == "up":
            raise KcAxiError(
                "runtime_ambiguous",
                f"both runtimes are installed and neither holds {settings.container_name}",
                help=tuple(f"kc-axi up --runtime {rt}" for rt in usable),
            )
        return _Target(None, "")  # status: missing; down: already_absent
    return _Target(usable[0], "")


# ---------------------------------------------------------------- up (section 5.3)


def _start(settings: RuntimeSettings, runtime: str) -> None:
    proc = _run([runtime, "start", settings.container_name], timeout=settings.runtime_timeout_seconds)
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc, (settings.admin_password,)))


def _run_argv(settings: RuntimeSettings, runtime: str, mount: str | None) -> list[str]:
    """Step 4. Each `-e NAME` has no value. The runtime copies the value from the subprocess environment."""
    argv = [
        runtime, "run", "-d", "--name", settings.container_name,
        "-p", f"127.0.0.1:{settings.port}:{CONTAINER_PORT}",
        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD", "-e", "KC_HOSTNAME",
    ]
    if settings.java_opts:
        argv += ["-e", "JAVA_OPTS_APPEND"]
    if mount:
        argv += ["-v", mount]
    argv += [settings.image, "start-dev"]
    return argv


def _run_env(settings: RuntimeSettings) -> dict[str, str]:
    env = dict(os.environ)
    env["KC_BOOTSTRAP_ADMIN_USERNAME"] = settings.admin_user
    env["KC_BOOTSTRAP_ADMIN_PASSWORD"] = settings.admin_password
    env["KC_HOSTNAME"] = _hostname(settings)
    if settings.java_opts:
        env["JAVA_OPTS_APPEND"] = settings.java_opts
    return env


def _create(settings: RuntimeSettings, runtime: str) -> None:
    """Steps 3 and 4. The image pull happens inside `run`, under pull_timeout_seconds."""
    kind, mount = _volume_mount(settings)
    secrets = (settings.admin_password,)
    if kind == "named":
        proc = _run([runtime, "volume", "create", settings.volume], timeout=settings.runtime_timeout_seconds)
        if proc.returncode != 0:
            raise KcAxiError("runtime_failed", _text(proc, secrets))
    proc = _run(
        _run_argv(settings, runtime, mount),
        timeout=settings.pull_timeout_seconds,
        timeout_key="pull_timeout_seconds",
        env=_run_env(settings),
    )
    if proc.returncode != 0:
        text = _text(proc, secrets)
        if PORT_IN_USE.search(text):
            raise KcAxiError("port_in_use", text, help=(f"free port {settings.port}, or change port and base_url",))
        raise KcAxiError("runtime_failed", text)


def _wait_ready(settings: RuntimeSettings, runtime: str, *, sleep: Callable[[float], None], clock: Callable[[], float]) -> None:
    """Step 6. Before each poll, read the container state. A container that is no longer running ends the wait."""
    name = settings.container_name
    url = f"{_base(settings)}/realms/master"
    deadline = clock() + settings.ready_timeout_seconds
    while True:
        state = _read_state(runtime, name, settings.runtime_timeout_seconds)
        if state != "running":
            info = _inspect(runtime, name, settings) if state else {}
            oom = _oom_killed(info)
            help_ = (
                (f'set java_opts: "{OOM_JAVA_OPTS}" in the configuration file',
                 "the container engine needs at least 4 GiB of memory")
                if oom
                else ("kc-axi status",)
            )
            raise KcAxiError(
                "container_exited",
                f"container {name} is {state or 'gone'}",
                help=help_,
                state=state or "missing",
                oom_killed=oom,
            )
        if _realm_ready(url, min(settings.request_timeout_seconds, READY_PROBE_SECONDS)):
            return
        if clock() >= deadline:
            raise KcAxiError(
                "keycloak_timeout",
                f"no ready server at {_base(settings)} after {settings.ready_timeout_seconds} seconds",
                help=("kc-axi status",),
                ready_timeout_seconds=settings.ready_timeout_seconds,
            )
        sleep(POLL_SECONDS)


AUTH_HELP = (
    "the image does not read KC_BOOTSTRAP_ADMIN_USERNAME and KC_BOOTSTRAP_ADMIN_PASSWORD",
    "the volume already holds an admin user with another password: kc-axi down --purge --yes deletes realm data",
)


def up(
    settings: RuntimeSettings,
    *,
    login: Callable[[], Mapping[str, Any]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Start the container if needed, and wait until ready (spec 5.3 `up`)."""
    _check_up(settings)
    target = _resolve(settings, action="up")
    runtime = target.runtime
    if runtime is None:  # _resolve returns no runtime for up only when it raises
        raise AssertionError("up resolved no runtime")
    name = settings.container_name
    warnings: list[str] = []

    if target.state == "running":
        result_status = "already_running"
    elif target.state in STOPPED_STATES or target.state == "":
        result_status = "started"
    else:
        raise KcAxiError(
            "container_state",
            f"container {name} is in state {target.state}",
            help=("kc-axi status",),
            state=target.state,
        )

    if target.state:
        env_hostname = _env_of(_inspect(runtime, name, settings)).get("KC_HOSTNAME", "")
        if env_hostname != _hostname(settings):
            warnings.append(
                f"container KC_HOSTNAME is {env_hostname or 'unset'}, configuration says {_hostname(settings)}; "
                "up does not change the container"
            )
        if target.state in STOPPED_STATES:
            _start(settings, runtime)
    else:
        _create(settings, runtime)

    _wait_ready(settings, runtime, sleep=sleep, clock=clock)

    version = None
    if login is not None:
        try:
            version = login().get("version")
        except KcAxiError as err:
            if err.code == "auth_failed":
                raise KcAxiError("auth_failed", err.message, help=AUTH_HELP) from err
            raise

    return {
        "status": result_status,
        "runtime": runtime,
        "container": name,
        "state": "running",
        "server": "up",
        "version": version,
        "issuer": _issuer(urllib.parse.urlparse(settings.base_url).scheme or "http", _hostname(settings), settings.port, "master"),
        "warnings": warnings,
    }


def _stop(settings: RuntimeSettings, runtime: str) -> None:
    proc = _run([runtime, "stop", "-t", str(STOP_SECONDS), settings.container_name], timeout=settings.runtime_timeout_seconds)
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc, (settings.admin_password,)))


# ---------------------------------------------------------------- down (section 5.3)


def _remove_volume(runtime: str, volume: str, timeout: int) -> str:
    """`removed`, or `absent` when the runtime says the volume does not exist. Any other failure exits 1."""
    proc = _run([runtime, "volume", "rm", volume], timeout=timeout)
    if proc.returncode == 0:
        return "removed"
    text = _text(proc)
    if NO_SUCH_VOLUME.search(text):
        return "absent"
    raise KcAxiError("runtime_failed", text, help=("stop or remove the container that still uses this volume",))


def down(settings: RuntimeSettings, *, purge: bool = False, yes: bool = False) -> dict[str, Any]:
    """Stop and remove the container. `--purge` removes a named volume only (section 5.3.1)."""
    kind, _ = _volume_mount(settings)
    name = settings.container_name
    kept_or_none = "none" if kind == "none" else "kept"
    if (purge or kind == "none") and not yes:
        # Both cases can delete realm data (section 5.3). Nothing has changed, and no runtime was called.
        raise KcAxiError(
            "confirm_required",
            "down with --purge, or with an empty volume, needs --yes. Nothing changed",
            help=("kc-axi down --purge --yes" if purge else "kc-axi down --yes",),
        )
    target = _resolve(settings, action="down", purge=purge)
    timeout = settings.runtime_timeout_seconds
    purge_named = purge and kind == "named"  # a host path is never removed (criterion 14)

    if not target.state:
        volume_result = kept_or_none
        if purge_named:
            # No container, but the volume can still hold an old admin user (section 5.10).
            if target.runtime is None:
                raise KcAxiError(
                    "runtime_ambiguous",
                    "both runtimes are installed and neither holds the container; the volume's runtime is not known",
                    help=tuple(f"kc-axi down --purge --yes --runtime {rt}" for rt in RUNTIMES),
                )
            volume_result = _remove_volume(target.runtime, settings.volume, timeout)
        return {"status": "already_absent", "runtime": target.runtime, "container": name, "volume": volume_result}

    if target.state not in HANDLED_STATES:
        raise KcAxiError(
            "container_state",
            f"container {name} is in state {target.state}",
            help=("kc-axi status",),
            state=target.state,
        )
    runtime = target.runtime
    if runtime is None:
        raise AssertionError("down found a container but no runtime")

    _stop(settings, runtime)
    proc = _run([runtime, "rm", name], timeout=timeout)
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc, (settings.admin_password,)))

    volume_result = _remove_volume(runtime, settings.volume, timeout) if purge_named else kept_or_none
    return {"status": "removed", "runtime": runtime, "container": name, "volume": volume_result}


# ---------------------------------------------------------------- offline export (spec 5.12, export steps 2 to 5)

EXPORT_DIR = "/tmp/kc-axi-export"  # inside the export run; the image user (1000) can write there
REALM_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")  # a leading "-" would read as an option of kc.sh


def _export_name(settings: RuntimeSettings) -> str:
    return f"{settings.container_name}-export"


def _export_remove(settings: RuntimeSettings, runtime: str) -> None:
    """Remove the one-off export container. Its result does not matter: the next run removes a leftover first."""
    try:
        _run([runtime, "rm", "-f", _export_name(settings)], timeout=settings.runtime_timeout_seconds)
    except KcAxiError:
        pass


def _export_run(settings: RuntimeSettings, runtime: str, mount: str, realm: str) -> None:
    """Step 4. The export runs offline on the data volume. No secret is passed: the export needs none."""
    _export_remove(settings, runtime)  # a container left by a crash would block the name
    argv = [
        runtime, "run", "--name", _export_name(settings), "-v", mount, settings.image,
        "export", "--realm", realm, "--users", "realm_file", "--dir", EXPORT_DIR,
    ]
    proc = _run(argv, timeout=settings.pull_timeout_seconds, timeout_key="pull_timeout_seconds")
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc))


def _export_copy(settings: RuntimeSettings, runtime: str, realm: str, workdir: Path) -> Path:
    """Copy the realm file out of the export container, owner-only. The file is the only thing copied."""
    target = workdir / f"{realm}-realm.json"
    source = f"{_export_name(settings)}:{EXPORT_DIR}/{realm}-realm.json"
    proc = _run([runtime, "cp", source, str(target)], timeout=settings.runtime_timeout_seconds)
    if proc.returncode != 0:
        raise KcAxiError("runtime_failed", _text(proc))
    if not target.is_file():
        raise KcAxiError("runtime_failed", "the export run wrote no realm file")
    os.chmod(target, 0o600)
    return target


def export_realm_offline(
    settings: RuntimeSettings,
    realm: str,
    workdir: Path,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Path:
    """Spec 5.12, export steps 2 to 5. Returns the path of the realm file inside `workdir`.

    `workdir` is a new, owner-only directory that the caller made and that the caller removes (step 6). The
    container starts again and becomes ready in a `finally`, also when the export fails (criterion 86). A failed
    export is reported first. A failed restart is reported only when the export succeeded.
    """
    if not REALM_NAME.fullmatch(realm):
        raise KcAxiError(
            "config_invalid",
            f"realm {realm!r} is not a plain realm name",
            help=("use letters, digits, _, . and -, and do not start with -",),
        )
    kind, mount = _volume_mount(settings)
    if mount is None:
        raise KcAxiError(
            "volume_invalid",
            "a full export reads the realm from the data volume, and volume is empty",
            help=("set volume to a name or a host path",),
        )
    target = _resolve(settings, action="status")
    if not target.state or target.runtime is None:
        raise KcAxiError("not_found", f"container {settings.container_name} does not exist", help=("kc-axi up",))
    if target.state != "running" and target.state not in STOPPED_STATES:
        raise KcAxiError("container_state", f"container {settings.container_name} is in state {target.state}", help=("kc-axi status",), state=target.state)
    runtime = target.runtime

    exported: Path | None = None
    failure: KcAxiError | None = None
    restart_failure: KcAxiError | None = None
    try:
        if target.state == "running":
            _stop(settings, runtime)
        _export_run(settings, runtime, mount, realm)
        exported = _export_copy(settings, runtime, realm, workdir)
    except KcAxiError as err:
        failure = err
    finally:
        _export_remove(settings, runtime)
        try:
            _start(settings, runtime)
            _wait_ready(settings, runtime, sleep=sleep, clock=clock)
        except KcAxiError as err:
            restart_failure = err

    if failure is not None:
        if restart_failure is not None:
            failure.fields["restart_code"] = restart_failure.code
        raise failure
    if restart_failure is not None:
        raise restart_failure
    assert exported is not None  # the export succeeded when neither error was raised
    return exported


# ---------------------------------------------------------------- status (section 5.3)


def _default_probe(settings: RuntimeSettings) -> dict[str, Any]:
    """Only the realm GET of step 2. It logs in to nothing, so the version stays unknown."""
    up_now = _realm_ready(f"{_base(settings)}/realms/master", PROBE_SECONDS)
    return {"server": "up" if up_now else "down", "version": None}


def _container_status(state: str) -> str:
    if not state:
        return "missing"
    if state == "running":
        return "running"
    if state in STOPPED_STATES:
        return "stopped"
    return f"other:{state}"


def status(
    settings: RuntimeSettings,
    *,
    realm: str = "master",
    probe: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Report the runtime, the container, the server and the issuer. Exit 0 when the server does not answer."""
    target = _resolve(settings, action="status")
    info = _inspect(target.runtime, settings.container_name, settings) if target.state and target.runtime else {}
    configured_host = _hostname(settings)
    hostname = _env_of(info).get("KC_HOSTNAME", configured_host) if info else configured_host
    image = ((info.get("Config") or {}).get("Image") if info else None) or settings.image
    port = (_published_port(info) if info else None) or settings.port
    scheme = urllib.parse.urlparse(settings.base_url).scheme or "http"

    credential = "present" if settings.admin_password else "missing"
    try:
        result = (probe or (lambda: _default_probe(settings)))()
    except KcAxiError as err:
        # Section 4.4: status exits 0 when the server does not answer. A refused login leaves the version unknown.
        result = {"server": "down" if err.code in ("keycloak_unreachable", "keycloak_timeout") else "up", "version": None}
    server = "up" if result.get("server") == "up" else "down"
    version = result.get("version") if credential == "present" and server == "up" else None

    container = _container_status(target.state)
    payload: dict[str, Any] = {
        "status": "ok",
        "runtime": target.runtime,
        "container": container,
        "image": image,
        "port": port,
        "hostname": hostname,
        "issuer": _issuer(scheme, hostname, port, realm),
        "server": server,
        "version": version,
        "credential": credential,
        "permissions": "not_checked" if sys.platform == "win32" else "checked",
    }
    if container == "stopped":
        payload["oom_killed"] = _oom_killed(info)
    return payload
