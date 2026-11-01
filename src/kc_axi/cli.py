"""Command-line entry point (spec sections 4.1, 4.2 and 4.5).

I1 builds the parser, the no-argument view, `--version` and the unknown-flag rule. The other
commands are registered so their names parse. Each one exits 2 with `usage` until its task builds it.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import __version__, apply as applying, fullrealm, plan as planning, reads
from .config import Settings, load_settings, resolve_config_path
from .credentials import require_admin_password
from .audit import require_audit_path
from .desired import UsersFile, load_desired
from .errors import KcAxiError
from .keycloak import KeycloakClient
from .output import emit, error_payload, resolve_limit, result_payload
from .resources import KINDS, select_fields

BIN = "kc-axi"
DESCRIPTION = "Run a local Keycloak and manage one realm as desired state, through an agent-friendly CLI."

# Commands of spec section 4.2. Their own flags are added by their tasks.
COMMANDS = (
    "up", "down", "status", "realms", "clients", "users", "get", "plan", "apply",
    "export-realm", "import-realm", "secrets", "reset-password", "disable-user", "disable-client",
)


class _Parser(argparse.ArgumentParser):
    """Turns argparse errors into typed codes (spec 4.5 rule 9)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        if message.startswith("unrecognized arguments"):
            raise KcAxiError("flag_not_valid", message, help=(valid_flags_help(self),))
        raise KcAxiError("usage", message, help=(f"{BIN} --help",))


def valid_flags_help(parser: argparse.ArgumentParser) -> str:
    flags = sorted(
        opt
        for action in parser._actions
        for opt in action.option_strings
        if opt.startswith("--") and opt not in ("--help", "--version")
    )
    return f"valid flags: {', '.join(flags)}"


def _add_common(parser: argparse.ArgumentParser, *, subcommand: bool) -> None:
    """Global flags. On a subcommand, defaults are suppressed so they do not overwrite a top-level value."""
    keep = {"default": argparse.SUPPRESS} if subcommand else {}
    parser.add_argument("--config", metavar="PATH", help="Tool configuration file", **keep)
    parser.add_argument("--realm", metavar="R", help="Realm for the command", **keep)
    parser.add_argument("--runtime", choices=("docker", "podman", "auto"), help="Container runtime", **keep)
    parser.add_argument("--json", action="store_true", help="Print the JSON contract", **keep)
    parser.add_argument("--fields", metavar="a,b", help="Add fields to a list or a get view", **keep)
    parser.add_argument("--limit", metavar="N", type=int, help="Items to show in a list (default 20)", **keep)
    parser.add_argument("--yes", action="store_true", help="Confirm a write", **keep)
    parser.add_argument("--allow-remote", action="store_true", help="Allow a write to a server that is not local", **keep)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=BIN, description=DESCRIPTION, add_help=True)
    _add_common(parser, subcommand=False)
    parser.add_argument("--version", action="version", version=f"{BIN} {__version__}")
    subs = parser.add_subparsers(dest="command", parser_class=_Parser, metavar="COMMAND")
    for name in COMMANDS:
        sub = subs.add_parser(name, help=name)
        _add_common(sub, subcommand=True)
        if name == "get":
            sub.add_argument("kind", choices=("realm", "client", "user"), help="Kind of object")
            sub.add_argument("key", metavar="KEY", help="The name, the clientId or the username")
        if name == "plan":
            sub.add_argument("--file", metavar="F", required=True, help="Desired-state file (config or users)")
        if name == "export-realm":
            sub.add_argument("--scope", choices=("config", "users", "full"), required=True, help="What to write")
            sub.add_argument("--out", metavar="PATH", required=True, help="Output file")
        if name == "import-realm":
            sub.add_argument("--file", metavar="F", required=True, help="Full realm file written by export-realm --scope full")
        if name == "apply":
            sub.add_argument("--file", metavar="F", required=True, help="Desired-state file (config or users)")
            sub.add_argument("--expect", metavar="H", help="Refuse unless plan_hash equals H")
            sub.add_argument("--adopt", action="store_true", help="Take over a declared client without a marker")
            sub.add_argument("--allow-delete", action="store_true", help="Remove managed clients and mappers the file omits")
            sub.add_argument("--allow-reenable", action="store_true", help="Enable an object that disable-* turned off")
    return parser


READ_COMMANDS = ("realms", "clients", "users", "get")


def connect(settings: Settings, *, allow_remote: bool = False, err: TextIO | None = None) -> KeycloakClient:
    """A logged-out client for the configured server. The password comes from section 5.4. Nothing is sent yet.

    Exit 2, `credential_missing`, when no source supplies a password: this happens before any request.
    """
    password = require_admin_password(settings.admin_password_file)
    return KeycloakClient(
        settings.base_url,
        settings.admin_user,
        password,
        admin_realm=settings.admin_realm,
        request_timeout=settings.request_timeout_seconds,
        command_timeout=settings.command_timeout_seconds,
        allow_remote=allow_remote,
        ca_file=str(settings.ca_file) if settings.ca_file else None,
    )


def warn_version(client: KeycloakClient, err: TextIO) -> None:
    """Spec section 5.4: a server outside 26.x prints a warning on stderr, then the command runs."""
    _, warning = client.check_version()
    if warning:
        print(f"warning: {warning}", file=err)


def run_read(args: argparse.Namespace, settings: Settings, err: TextIO) -> dict:
    """`realms`, `clients`, `users` and `get`. A bad flag exits 2 before the first request."""
    limit = resolve_limit(args.limit if args.limit is not None else settings.default_limit)
    fields = args.fields
    command = args.command
    kind = args.kind if command == "get" else {"realms": "realm", "clients": "client", "users": "user"}[command]
    select_fields(KINDS[kind], fields)  # an unknown field name exits 2 before the first request
    if command == "realms":
        reads_call = lambda c: reads.list_realms(c, fields=fields, limit=limit)  # noqa: E731
    elif command == "get":
        realm = "" if args.kind == "realm" else reads.require_realm(settings.realm)
        reads_call = lambda c: reads.get_object(c, args.kind, args.key, realm, fields=fields)  # noqa: E731
    else:
        realm = reads.require_realm(settings.realm)
        lister = reads.list_clients if command == "clients" else reads.list_users
        reads_call = lambda c: lister(c, realm, fields=fields, limit=limit)  # noqa: E731
    # Check the flags that need no server first (spec section 4.5 rule 9), then log in.
    client = connect(settings)
    warn_version(client, err)
    return reads_call(client)


def run_plan(args: argparse.Namespace, settings: Settings, err: TextIO) -> planning.PlanResult:
    """`plan --file F`. The file is checked first, so a bad file exits 2 before any request (spec section 5.6, step 1)."""
    path = Path(args.file).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    desired = load_desired(path, realm_flag=args.realm, admin_realm=settings.admin_realm)
    client = connect(settings)
    warn_version(client, err)
    return planning.make_plan(
        client, desired, base_url=settings.base_url, secrets_dir=settings.secrets_dir, file_arg=args.file
    )


def run_apply(args: argparse.Namespace, settings: Settings, err: TextIO) -> applying.ApplyResult:
    """`apply --file F`. Flags and the file are checked before any request (spec section 5.6, apply steps 1 and 2)."""
    path = Path(args.file).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    desired = load_desired(path, realm_flag=args.realm, admin_realm=settings.admin_realm)
    if isinstance(desired, UsersFile) and (args.adopt or args.allow_delete):
        flag = "--adopt" if args.adopt else "--allow-delete"
        raise KcAxiError("flag_not_valid", f"{flag} is not valid with a users file", help=("Remove the flag.",))
    require_audit_path(settings.audit_path)
    client = connect(settings, allow_remote=args.allow_remote)
    warn_version(client, err)
    return applying.apply_config(
        client, desired, settings=settings, file_arg=args.file, expect=args.expect, adopt=args.adopt,
        allow_delete=args.allow_delete, allow_reenable=args.allow_reenable, allow_remote=args.allow_remote,
        yes=args.yes,
    )


def run_export_full(args: argparse.Namespace, settings: Settings) -> dict:
    """`export-realm --scope full --out PATH` (spec 5.12). The admin password is required: the file is checked for it."""
    realm = reads.require_realm(settings.realm)
    password = require_admin_password(settings.admin_password_file)
    out = Path(args.out).expanduser()
    if not out.is_absolute():
        out = Path.cwd() / out
    return fullrealm.export_full(settings, realm, out, password, yes=args.yes)


def run_import(args: argparse.Namespace, settings: Settings, err: TextIO) -> dict:
    """`import-realm --file F` (spec 5.12). The file is checked before the first request."""
    realm = reads.require_realm(settings.realm)
    path = Path(args.file).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    fullrealm.preflight_import(settings, realm, path, allow_remote=args.allow_remote)  # exit 2 before any login
    password = require_admin_password(settings.admin_password_file)
    client = connect(settings, allow_remote=args.allow_remote)
    warn_version(client, err)
    return fullrealm.import_full(settings, client, realm, path, password, yes=args.yes, allow_remote=args.allow_remote)


def no_argument_view(config_path: Path, out: TextIO) -> None:
    """Spec 4.5 rule 7: `bin`, `description`, the configuration path and whether it exists. No network."""
    emit(
        {
            "bin": BIN,
            "description": DESCRIPTION,
            "config": str(config_path),
            "config_exists": config_path.exists(),
            "help": [f"{BIN} --help"],
        },
        as_json=False,
        stream=out,
    )


def main(argv: Sequence[str] | None = None, out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    args_list = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args_list
    max_cell_chars = 200
    # Name the command before parsing, so a parse error still reports it (spec 4.3 envelope).
    command = next((a for a in args_list if a in COMMANDS), None)
    try:
        args = build_parser().parse_args(args_list)
        command = args.command
        if command is None:
            no_argument_view(resolve_config_path(getattr(args, "config", None)), out)
            return 0
        if command in READ_COMMANDS:
            settings = load_settings(
                config_flag=args.config, realm_flag=args.realm, runtime_flag=args.runtime
            )
            max_cell_chars = settings.max_cell_chars
            body = run_read(args, settings, err)
            emit(result_payload(command, body, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
            return 0
        if command == "plan":
            settings = load_settings(config_flag=args.config, realm_flag=args.realm, runtime_flag=args.runtime)
            max_cell_chars = settings.max_cell_chars
            result = run_plan(args, settings, err)
            emit(result_payload(command, result.body, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
            return result.exit_code
        if command == "apply":
            settings = load_settings(config_flag=args.config, realm_flag=args.realm, runtime_flag=args.runtime)
            max_cell_chars = settings.max_cell_chars
            applied = run_apply(args, settings, err)
            emit(result_payload(command, applied.body, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
            return applied.exit_code
        if command == "import-realm":
            settings = load_settings(config_flag=args.config, realm_flag=args.realm, runtime_flag=args.runtime)
            max_cell_chars = settings.max_cell_chars
            body = run_import(args, settings, err)
            emit(result_payload(command, body, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
            return 0
        if command == "export-realm" and args.scope == "full":
            settings = load_settings(config_flag=args.config, realm_flag=args.realm, runtime_flag=args.runtime)
            max_cell_chars = settings.max_cell_chars
            body = run_export_full(args, settings)
            emit(result_payload(command, body, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
            return 0
        raise KcAxiError("usage", f"{command} is not built yet", help=(f"{BIN} --help",))
    except KcAxiError as e:
        emit(error_payload(e, command or BIN, as_json=as_json), as_json=as_json, stream=out, max_cell_chars=max_cell_chars)
        return e.exit_code
    except SystemExit as e:
        # argparse exits 0 for --help and --version. Those are not failures.
        return int(e.code or 0)
