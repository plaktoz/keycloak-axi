"""`apply` for a config file (spec sections 4.3, 5.6, 5.8 and 5.9, task I7).

`apply_config` runs the steps of section 5.6 in order: check the file and the paths (nothing is written), open the
audit file, take the lock, plan, refuse in preflight, preview or run the actions, and stop at the first failure.

A failed run is `apply_partial` with `applied`, `pending`, `cause` and `created`. A write that times out is not
retried: its action counts as `pending`, and `cause` is `keycloak_timeout` (decision 1A, criterion 71).

No secret value reaches the output, the audit file or an error message. A value goes from `secrets_store` to one
Keycloak request body and nowhere else. Messages from Keycloak are scrubbed of every value this run handled.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import plan as planning, secrets_store
from .audit import AuditTrail, require_audit_path, toggle_states
from .config import Settings
from .desired import ConfigFile, UsersFile
from .errors import KcAxiError
from .keycloak import KeycloakClient, require_local_for_write
from .lock import RunLock
from .output import page
from .paths import check_outside_git
from .reads import MANAGED_ATTRIBUTE

#: The order of the top-level `code` of a refusal (spec section 5.6, apply step 6).
REFUSAL_ORDER = (
    "needs_adopt", "owner_conflict", "allow_delete_required", "allow_remote_required", "secrets_mismatch",
    "secrets_missing", "reenable_refused", "id_conflict", "email_duplicate", "secrets_unreadable",
    "temporary_password_missing", "realm_absent", "not_found",
)

_HINTS = {
    "needs_adopt": "Run again with --adopt to take over the client, or leave it out of the file.",
    "owner_conflict": "The client carries the marker of another owner. Use that owner, or leave the client out of the file.",
    "allow_delete_required": "Run again with --allow-delete to remove it, or declare it in the file.",
    "allow_remote_required": "Run again with --allow-remote to write to a server that is not local.",
    "secrets_mismatch": "kc-axi secrets capture keeps the live value. kc-axi secrets rotate or restore applies the file's value.",
    "secrets_missing": "kc-axi secrets capture --realm R --client C --yes records the live value.",
    "reenable_refused": "Run again with --allow-reenable, or set enabled: false in the file.",
    "id_conflict": "The username and the id disagree with the server. Fix the file.",
    "secrets_unreadable": "Fix or move the secrets file, then run the command again.",
    "not_found": "Declare the audience client in the file, or create it first.",
}

_AUDIT_ACTION = {"finish_pending": "secret"}
_CLIENT_FIELDS = (
    "enabled", "publicClient", "standardFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled",
)
_SET_FIELDS = ("redirectUris", "webOrigins")


@dataclass
class ApplyResult:
    """The payload for `output.emit` and the exit code."""

    body: dict[str, Any]
    exit_code: int


class _Stop(Exception):
    """The first failure of step 9. `error` is the cause."""

    def __init__(self, error: KcAxiError, row: Mapping[str, Any]):
        super().__init__(error.code)
        self.error = error
        self.row = row


def _row_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return row["kind"], row["name"]


# --------------------------------------------------------------------------------------- preflight


def _refusals(
    result: planning.PlanResult,
    desired: ConfigFile,
    *,
    adopt: bool,
    allow_delete: bool,
    allow_reenable: bool,
    allow_remote: bool,
    base_url: str,
    audit_path: Any,
    unreadable: bool,
) -> tuple[list[dict[str, str]], set[tuple[str, str]]]:
    """Step 6. Returns the refusals in the order of `REFUSAL_ORDER`, and the objects that `--allow-reenable` lifts."""
    found: list[dict[str, str]] = []

    def refuse(code: str, kind: str, name: str, field: str = "") -> None:
        found.append({"code": code, "kind": kind, "name": name, "field": field})

    declared_ids = {c["clientId"] for c in desired.clients}
    declared_mappers = {
        (c["clientId"], m["name"]): m for c in desired.clients for m in c.get("mappers", ())
    }
    states = toggle_states(audit_path)
    lifted: set[tuple[str, str]] = set()
    for row in result.actions:
        action, kind, name = row["action"], row["kind"], row["name"]
        if action == "adopt" and not adopt:
            refuse("needs_adopt", kind, name)
        elif action == "owner_conflict":
            refuse("owner_conflict", kind, name)
        elif action == "remove" and not allow_delete:
            refuse("allow_delete_required", kind, name)
        elif action == "secret":
            refuse("secrets_mismatch", kind, name)
        elif action == "secret_missing":
            refuse("secrets_missing", kind, name)
        elif action == "id_conflict":
            refuse("id_conflict", kind, name)
        if action in ("change", "adopt") and kind == "client" and (row.get("to") or {}).get("enabled") is True:
            if states.get(("client", name)) == "disable":
                if allow_reenable:
                    lifted.add(("client", name))
                else:
                    refuse("reenable_refused", kind, name, "enabled")
        if action in ("create", "change") and kind == "mapper":
            mapper = declared_mappers.get((row["client"], row["mapper"]))
            audience = mapper["audience"] if mapper else None
            if audience is not None and audience not in declared_ids and audience not in result.live_clients:
                refuse("not_found", kind, name, "audience")
    if result.actions and not allow_remote:
        try:
            require_local_for_write(base_url, allow_remote)
        except KcAxiError as err:
            if err.code == "allow_remote_required":
                refuse("allow_remote_required", "server", base_url)
            else:
                raise
    if unreadable:
        refuse("secrets_unreadable", "secrets_file", desired.realm_name)
    order = {code: i for i, code in enumerate(REFUSAL_ORDER)}
    found.sort(key=lambda r: order[r["code"]])
    return found, lifted


def _raise_refusals(found: list[dict[str, str]]) -> None:
    hints: list[str] = []
    for code in dict.fromkeys(r["code"] for r in found):
        if code in _HINTS and _HINTS[code] not in hints:
            hints.append(_HINTS[code])
    count = len(found)
    raise KcAxiError(
        found[0]["code"],
        f"{count} refusal{'s' if count != 1 else ''} before the first write. Nothing was changed.",
        help=tuple(hints[:3]),
        refusals=page(found, columns=("code", "kind", "name", "field")),
    )


# --------------------------------------------------------------------------------------- the runner


def _location_id(headers: Mapping[str, str]) -> str | None:
    for key, value in headers.items():
        if key.lower() == "location" and value:
            return value.rstrip("/").rsplit("/", 1)[-1]
    return None


class _Runner:
    """Step 9. Holds the state of one run: counts, created objects, and the Keycloak ids."""

    def __init__(
        self,
        client: KeycloakClient,
        desired: ConfigFile,
        audit: AuditTrail,
        settings: Settings,
        ids: Mapping[str, str],
        lifted: set[tuple[str, str]],
    ):
        self.client = client
        self.desired = desired
        self.audit = audit
        self.settings = settings
        self.realm = desired.realm_name
        self.ids = dict(ids)
        self.lifted = lifted
        self.declared = {c["clientId"]: c for c in desired.clients}
        self.applied = 0
        self.created: list[dict[str, str]] = []
        self._values: set[str] = set()

    # -- helpers

    def _path(self, *segments: str) -> str:
        return KeycloakClient.admin_path(self.realm, *segments)

    def _known(self, value: str) -> str:
        """Remember a secret value, so that `scrub` can remove it from a message."""
        self._values.add(value)
        return value

    def scrub(self, text: str) -> str:
        for value in self._values:
            text = text.replace(value, "***")
        return text

    def _client_id(self, name: str) -> str:
        if name not in self.ids:
            found = self.client.get(self._path("clients"), query={"clientId": name}).body or []
            match = next((c for c in found if c.get("clientId") == name), None)
            if match is None:
                raise KcAxiError("not_found", f"client {name} does not exist", client=name)
            self.ids[name] = match["id"]
        return self.ids[name]

    def _full_client(self, name: str) -> dict[str, Any]:
        rep = dict(self.client.get(self._path("clients", self._client_id(name))).body or {})
        rep.pop("protocolMappers", None)  # Keycloak is told nothing about mappers in a client update
        return rep

    def _put_client(self, name: str, rep: Mapping[str, Any]) -> None:
        self.client.put(self._path("clients", self._client_id(name)), json_body=dict(rep))

    def _mark_created(self, kind: str, name: str, identifier: str | None) -> None:
        self.created.append({"kind": kind, "name": name, "id": identifier or name})

    def _secret_value(self, name: str) -> str:
        """Section 5.8, create path, step 1 and 2: the active value, else the pending one, else a new one (staged)."""
        args = (self.settings.secrets_dir, self.realm, self.settings.base_url)
        for state in ("active", "pending"):
            value = secrets_store.generation_value(*args, state, name)
            if value is not None:
                return self._known(value)
        value = self._known(secrets_store.generate_value())
        secrets_store.stage_values(*args, {name: value})
        return value

    def _live_secret(self, name: str) -> str:
        body = self.client.get(self._path("clients", self._client_id(name), "client-secret")).body
        value = body.get("value") if isinstance(body, Mapping) else None
        if not isinstance(value, str) or not value:
            raise KcAxiError("keycloak_rejected", f"Keycloak returned no secret for client {name}", client=name)
        return self._known(value)

    def _stage_live(self, name: str) -> None:
        secrets_store.stage_values(
            self.settings.secrets_dir, self.realm, self.settings.base_url, {name: self._live_secret(name)}
        )

    # -- actions

    def finish_pending(self, row: Mapping[str, Any]) -> None:
        name = row["name"]
        args = (self.settings.secrets_dir, self.realm, self.settings.base_url)
        pending = secrets_store.generation_value(*args, "pending", name)
        if pending is None:
            raise KcAxiError("secrets_missing", f"client {name} has no pending value", client=name)
        self._known(pending)
        if row["live"] != secrets_store.fingerprint(pending):
            rep = self._full_client(name)  # the live value equals the active one: set the pending value
            rep["secret"] = pending
            self._put_client(name, rep)

    def realm_create(self, row: Mapping[str, Any]) -> None:
        body = {"realm": self.realm, "enabled": True}
        body.update({k: v for k, v in self.desired.realm.items() if k != "name"})
        response = self.client.post("/admin/realms", json_body=body)
        self._mark_created("realm", self.realm, _location_id(response.headers))

    def realm_change(self, row: Mapping[str, Any]) -> None:
        self.client.put(self._path(), json_body=dict(row["to"]))

    def client_create(self, row: Mapping[str, Any]) -> None:
        declared = self.declared[row["name"]]
        body: dict[str, Any] = {"clientId": declared["clientId"], "protocol": "openid-connect"}
        body.update({k: declared[k] for k in _CLIENT_FIELDS if k in declared})
        body.update({k: list(declared[k]) for k in _SET_FIELDS if k in declared})
        attributes = {MANAGED_ATTRIBUTE: self.desired.owner}
        if declared.get("pkce"):
            attributes[planning.PKCE_ATTRIBUTE] = declared["pkce"]
        body["attributes"] = attributes
        if declared.get("secret_managed"):
            body["secret"] = self._secret_value(declared["clientId"])
        response = self.client.post(self._path("clients"), json_body=body)
        identifier = _location_id(response.headers)
        if identifier:
            self.ids[declared["clientId"]] = identifier
        self._mark_created("client", declared["clientId"], identifier)

    def client_change(self, row: Mapping[str, Any]) -> None:
        name = row["name"]
        if row["action"] == "adopt" and "secret: capture" in row["detail"]:
            self._stage_live(name)
        rep = self._full_client(name)
        attributes = dict(rep.get("attributes") or {})
        for field, value in (row.get("to") or {}).items():
            if field == "pkce":
                attributes.pop(planning.PKCE_ATTRIBUTE, None)
                if value:
                    attributes[planning.PKCE_ATTRIBUTE] = value
            elif field in _SET_FIELDS:
                rep[field] = list(value)
            else:
                rep[field] = value
        if row["action"] == "adopt":
            attributes[MANAGED_ATTRIBUTE] = self.desired.owner
        rep["attributes"] = attributes
        self._put_client(name, rep)

    def client_remove(self, row: Mapping[str, Any]) -> None:
        self.client.delete(self._path("clients", self._client_id(row["name"])))

    def _mapper_body(self, name: str, audience: str) -> dict[str, Any]:
        config = {planning.AUDIENCE_KEY: audience, **planning.MAPPER_CLAIMS}
        return {
            "name": name, "protocol": "openid-connect", "protocolMapper": planning.AUDIENCE_MAPPER, "config": config,
        }

    def _mapper_id(self, client_name: str, mapper_name: str) -> str:
        path = self._path("clients", self._client_id(client_name), "protocol-mappers", "models")
        for mapper in self.client.get(path).body or []:
            if mapper.get("name") == mapper_name and mapper.get("protocolMapper") == planning.AUDIENCE_MAPPER:
                return mapper["id"]
        raise KcAxiError("not_found", f"mapper {mapper_name} does not exist on client {client_name}")

    def mapper_create(self, row: Mapping[str, Any]) -> None:
        declared = next(m for m in self.declared[row["client"]]["mappers"] if m["name"] == row["mapper"])
        path = self._path("clients", self._client_id(row["client"]), "protocol-mappers", "models")
        self.client.post(path, json_body=self._mapper_body(declared["name"], declared["audience"]))

    def mapper_change(self, row: Mapping[str, Any]) -> None:
        declared = next(m for m in self.declared[row["client"]]["mappers"] if m["name"] == row["mapper"])
        identifier = self._mapper_id(row["client"], row["mapper"])
        body = {"id": identifier, **self._mapper_body(declared["name"], declared["audience"])}
        path = self._path("clients", self._client_id(row["client"]), "protocol-mappers", "models", identifier)
        self.client.put(path, json_body=body)

    def mapper_remove(self, row: Mapping[str, Any]) -> None:
        identifier = self._mapper_id(row["client"], row["mapper"])
        self.client.delete(self._path("clients", self._client_id(row["client"]), "protocol-mappers", "models", identifier))

    def handler(self, row: Mapping[str, Any]) -> Callable[[Mapping[str, Any]], None]:
        action, kind = row["action"], row["kind"]
        table: dict[tuple[str, str], Callable[[Mapping[str, Any]], None]] = {
            ("finish_pending", "client"): self.finish_pending,
            ("create", "realm"): self.realm_create,
            ("change", "realm"): self.realm_change,
            ("create", "client"): self.client_create,
            ("adopt", "client"): self.client_change,
            ("change", "client"): self.client_change,
            ("remove", "client"): self.client_remove,
            ("create", "mapper"): self.mapper_create,
            ("change", "mapper"): self.mapper_change,
            ("remove", "mapper"): self.mapper_remove,
        }
        return table[(action, kind)]

    def uses_generation(self, row: Mapping[str, Any]) -> bool:
        """True when the action reads or writes a value of the pending generation (section 5.8)."""
        action = row["action"]
        if action == "finish_pending":
            return True
        if row["kind"] != "client":
            return False
        if action == "create":
            return bool(self.declared[row["name"]].get("secret_managed"))
        return action == "adopt" and "secret: capture" in row["detail"]

    # -- the loop

    def audit_fields(self, row: Mapping[str, Any]) -> list[str]:
        if row["action"] == "create" and row["kind"] == "client":
            return sorted(k for k in self.declared[row["name"]] if k not in ("clientId", "mappers"))
        if row["action"] == "create" and row["kind"] == "realm":
            return sorted(k for k in self.desired.realm if k != "name")
        return sorted(row.get("to") or [])

    def run(self, actions: list[dict[str, Any]]) -> None:
        last_use = max((i for i, row in enumerate(actions) if self.uses_generation(row)), default=-1)
        for index, row in enumerate(actions):
            self.step(row, mark_active=index == last_use)

    def _intent(self, row: Mapping[str, Any], action: str) -> str:
        return self.audit.intent(
            command="apply", action=action, kind=row["kind"], name=row["name"],
            base_url=self.settings.base_url, realm=self.realm, fields=self.audit_fields(row),
        )

    def step(self, row: Mapping[str, Any], *, mark_active: bool) -> None:
        records: list[str] = []
        try:
            records.append(self._intent(row, _AUDIT_ACTION.get(row["action"], row["action"])))
            if _row_key(row) in self.lifted:  # section 5.9: a re-enable has its own intent and result pair
                records.append(self._intent({**row, "to": {"enabled": True}}, "enable"))
            self.handler(row)(row)
            if mark_active:
                secrets_store.mark_active(self.settings.secrets_dir, self.realm, self.settings.base_url)
        except KcAxiError as err:
            for record in records:
                self.audit.record_error(record, err.code)
            raise _Stop(err, row) from err
        self.applied += 1
        try:
            for record in records:
                self.audit.result(record)
        except KcAxiError as err:  # the change was made: audit_incomplete stops the run, and the action counts
            raise _Stop(err, row) from err


# --------------------------------------------------------------------------------------- entry point


def _preview(result: planning.PlanResult, file_arg: str) -> dict[str, Any]:
    body = dict(result.body)
    body["status"] = "confirm_required"
    body["help"] = [f"kc-axi apply --file {file_arg} --expect {result.plan_hash} --yes"]
    return body


def apply_config(
    client: KeycloakClient,
    desired: ConfigFile | UsersFile,
    *,
    settings: Settings,
    file_arg: str,
    expect: str | None = None,
    adopt: bool = False,
    allow_delete: bool = False,
    allow_reenable: bool = False,
    allow_remote: bool = False,
    yes: bool = False,
) -> ApplyResult:
    """Run `apply --file F` for a config file. See the module text and spec section 5.6."""
    # Step 1: flags.
    if isinstance(desired, UsersFile):
        if adopt or allow_delete:
            flag = "--adopt" if adopt else "--allow-delete"
            raise KcAxiError(
                "flag_not_valid", f"{flag} is not valid with a users file",
                help=("Remove the flag. A users file never adopts or deletes.",),
            )
        raise KcAxiError("usage", "apply of a users file is not built yet", help=("kc-axi plan --file F shows the plan",))
    audit_path = require_audit_path(settings.audit_path)
    if not desired.owner:
        raise KcAxiError(
            "owner_required",
            "the config file has no owner. apply marks every client it manages with the owner.",
            help=("add `owner: <name>` to the config file",),
        )
    if expect is not None and not (len(expect) == 16 and all(c in "0123456789abcdef" for c in expect)):
        raise KcAxiError(
            "flag_not_valid", "--expect takes the 16 hex digits of plan_hash", help=("kc-axi plan --file F prints plan_hash",)
        )

    # Step 2: nothing is written. A secrets file that cannot be parsed is the refusal `secrets_unreadable` of step 6.
    secrets_dir = Path(settings.secrets_dir)
    check_outside_git(secrets_dir, "secrets_dir")
    unreadable = False
    try:
        secrets_store.check_file(secrets_dir, desired.realm_name, settings.base_url)
    except KcAxiError as err:
        if err.code != "secrets_unreadable":
            raise  # unsafe_file_mode, secrets_server_mismatch and the like exit 2 before the lock
        unreadable = True

    # Steps 3 and 4: audit file, then the lock.
    with AuditTrail.open(audit_path) as audit, RunLock.acquire(secrets_dir):
        # Step 5.
        try:
            result = planning.make_plan(
                client, desired, base_url=settings.base_url, secrets_dir=secrets_dir, file_arg=file_arg
            )
        except KcAxiError as err:
            if err.code != "secrets_unreadable":
                raise
            _raise_refusals([{"code": "secrets_unreadable", "kind": "secrets_file", "name": desired.realm_name, "field": ""}])
        if expect is not None and expect != result.plan_hash:
            raise KcAxiError(
                "plan_changed",
                "the plan is not the one you checked. Nothing was changed.",
                help=(f"kc-axi plan --file {file_arg}",),
                expected=expect, actual=result.plan_hash,
            )
        # Step 6.
        found, lifted = _refusals(
            result, desired, adopt=adopt, allow_delete=allow_delete, allow_reenable=allow_reenable,
            allow_remote=allow_remote, base_url=settings.base_url, audit_path=audit_path, unreadable=unreadable,
        )
        if found:
            _raise_refusals(found)
        # Steps 7 and 8.
        if not result.actions:
            return ApplyResult(
                {"status": "already", "applied": 0, "created": page([], columns=("kind", "name", "id")),
                 "plan_hash": result.plan_hash},
                0,
            )
        if not yes:
            return ApplyResult(_preview(result, file_arg), 1)
        # Steps 9 to 11.
        runner = _Runner(client, desired, audit, settings, result.live_clients, lifted)
        try:
            runner.run(result.actions)
        except _Stop as stop:
            cause = stop.error
            total = len(result.actions)
            fields: dict[str, Any] = {
                "applied": runner.applied, "pending": total - runner.applied, "cause": cause.code,
                "created": page(runner.created, columns=("kind", "name", "id")),
            }
            if isinstance(cause.fields.get("field"), str):
                fields["field"] = cause.fields["field"]
            raise KcAxiError(
                "apply_partial",
                runner.scrub(
                    f"stopped at {stop.row['action']} {stop.row['kind']} {stop.row['name']}: "
                    f"{cause.code}. {cause.message}"
                ),
                help=(f"kc-axi plan --file {file_arg} shows what is left. Run apply again to finish.",),
                **fields,
            ) from cause
        return ApplyResult(
            {"status": "applied", "applied": runner.applied,
             "created": page(runner.created, columns=("kind", "name", "id")), "plan_hash": result.plan_hash},
            0,
        )
