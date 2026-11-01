# kc-axi

> Standalone library spec · Draft v0.4 · Moved on 2026-11-01 from `libs/kc-axi/` in the agentzero-v2-dev repo (UMAS)
> **Independence:** no dependency on any consuming project, AI model or other library. The tool talks to a Keycloak server. For `up`, `down` and `status`, it calls a Docker or Podman CLI. It keeps no database. It keeps two kinds of local file: desired-state files and a secrets directory.
>
> **Revision:** v0.4 applies the owner answers of 2026-10-27 and closes the non-decision findings of the round 2 caller assessments. Reports: `docs/assessments/caller-assessment-kc-axi-*-round2-2026-10-27.md`.

---

## Build and run

This section is about the code in `src/kc_axi/`. The numbered sections below are the spec.

**Build.** Python 3.11 or later. The one dependency is PyYAML.

```bash
cd keycloak-axi
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'     # editable: the code you edit is the code that runs
.venv/bin/kc-axi --version
```

**Test.** The suite uses stub runtimes and a fake Keycloak, so it needs no container. It takes about two minutes. Tests that need a real container runtime skip when none is present.

```bash
.venv/bin/pytest -q
```

**Configure.** A command that talks to Keycloak reads a YAML file. The path comes from `--config PATH`, then `KC_AXI_CONFIG`, then the OS default (`~/Library/Application Support/kc-axi/config.yaml` on macOS, `$XDG_CONFIG_HOME/kc-axi/config.yaml` on Linux). Every key is in section 6.1. A minimal file for a local server:

```yaml
schema_version: 1
base_url: http://127.0.0.1:8080
port: 8080
default_realm: my-realm
runtime: podman                        # podman | docker | auto
container_name: keycloak-dev
image: quay.io/keycloak/keycloak:26.6.4
volume: keycloak-dev-data
admin_password_file: ~/.config/kc-axi/admin-password   # mode 0600; or set KC_ADMIN_PASSWORD
audit_path: ~/.config/kc-axi/audit.jsonl
secrets_dir: ~/.config/kc-axi/secrets
```

**Run.** Add `--json` to any command for the JSON form.

```bash
kc-axi --config ./config.yaml realms
kc-axi --config ./config.yaml --realm my-realm users
kc-axi --config ./config.yaml plan  --file my-realm.config.yaml
kc-axi --config ./config.yaml apply --file my-realm.config.yaml --yes
# Whole realm in one file, with users' password hashes and signing keys (section 5.12).
# The container stops for about 10 seconds. --out must lie outside any git work tree.
kc-axi --config ./config.yaml --realm my-realm export-realm --scope full --out ~/keycloak-exports/my-realm.json --yes
# Replace the realm with that file. Without --yes it prints the counts and changes nothing.
# It backs the live realm up into secrets_dir first, deletes it, then loads the file.
kc-axi --config ./config.yaml --realm my-realm import-realm --file ~/keycloak-exports/my-realm.json --yes
```

The full file holds password hashes and realm signing keys. Keep it owner-only and out of git. The tool writes it with mode 0600.

**Status of the commands (2026-11-01).** Wired in the CLI: `realms`, `clients`, `users`, `get`, `plan`, `apply` (config file only), `export-realm --scope full`, `import-realm`. Not wired yet, so they exit 2 `usage` ("not built yet"): `up`, `down`, `status`, `export-realm --scope config|users`, `secrets`, `reset-password`, `disable-user`, `disable-client`. `docs/tasks-kc-axi-implementation.md` lists the tasks and their state.

---

## 1. Purpose

The tool does two jobs:

1. **Run** a local Keycloak server in a Docker or Podman container, repeatably.
2. **Manage** one realm as desired state. A file declares what Keycloak must contain. `plan` shows the difference from the live server. `apply` removes the difference.

An agent or a script calls the tool. The output is short. No command waits for input. No command prints a secret.

The output follows the CLI rules in section 4.5. Those rules restate the AXI principles in section "CLI Conventions (AXI)" of `libs/README.md` in agentzero-v2-dev.

## 2. Scope and Non-Goals

**In scope**

- `up`, `down` and `status` for one Keycloak container, with Podman (primary) or Docker.
- List and get for realms, clients and users, through the Keycloak admin REST API.
- Desired state for one realm. Realm settings and clients are in a **config file**. Users are in a **users file** (section 3.4).
- `plan` (read-only) and `apply` for both files.
- `export-realm`. It writes the live state of a realm as desired-state files.
- A **secrets directory** with one secrets file per realm. The file holds numbered generations (section 3.5).
- An **audit file** of writes (section 3.3).
- Local scope only. A write to a server that is not local needs `--allow-remote` (section 5.4).
- Full export and import of one realm in one file, for backup and restore (section 5.12).

**Non-goals**

- Authorisation. Keycloak answers who a person is. What that person can do belongs to the consuming application.
- Production deployment of Keycloak. This covers clustering, an external database, TLS termination and backups. `up` starts a development instance only.
- Roles, groups, identity brokering and themes. Temporary passwords are in scope (section 5.11).
- Deleting a realm, except as the replace step of `import-realm` (section 5.12). Deleting a user. A user is disabled, never deleted.
- Replacing the Keycloak admin console.
- The sign-in flow of an end-user CLI. The consuming project chooses its own client and flow.
- A public Python API in v1. Consumers call the command line. Consumers read the secrets file by the format in section 5.8.

## 3. Concepts and Data Model

### 3.1 Tool configuration

The tool reads one configuration file. It is separate from the desired-state files. Section 6.1 lists every key and its default.

The admin password is never in this file. It comes from the environment or from `admin_password_file` (section 5.4). A password in this file is refused (`unknown_field`).

### 3.2 Resource keys and views

Each object has one human key. Commands use the key. The output shows the Keycloak `id` only when asked with `--fields id`.

| Kind | Key | Default fields | `--fields` adds |
|------|-----|----------------|-----------------|
| realm | `name` | `name`, `enabled` | `displayName`, `accessTokenLifespan` |
| client | `clientId` | `clientId`, `enabled`, `managed` | `id`, `publicClient`, `protocol` |
| user | `username` | `username`, `enabled` | `id`, `email`, `emailVerified` |

No view contains a secret. `id` is the Keycloak UUID.

### 3.3 Audit records

An audit record is one JSON line. The file is set by `audit_path`. Every write command follows this order:

1. **Preflight.** Open the audit file for append. A failure exits 1, `audit_failed`, before any change. `apply`, `disable-*`, `reset-password` and the container and secrets writes run this check during preflight.
2. Append an `intent` record. A failed write exits 1, `audit_failed`. Nothing has changed yet.
3. Make the change.
4. Append a `result` record.

```json
{ "schema_version": 1, "ts": "2026-10-27T09:14:02Z", "phase": "intent", "id": "a1f0...",
  "actor": "alice", "base_url": "http://127.0.0.1:8080", "realm": "acme",
  "command": "apply", "kind": "client", "name": "acme-web", "action": "change",
  "fields": ["redirectUris"] }
```

- `ts` is RFC 3339 in UTC.
- `actor` is the operating-system user name.
- `action` is one of `create`, `change`, `adopt`, `remove`, `disable`, `enable`, `secret`, `capture`, `rotate`, `restore`, `prune`, `password`, `up`, `down`, `export`, `import`.
- `fields` lists field names only. No value is written.
- A `result` record repeats the `id`. It adds `"phase": "result"` and `"outcome": "ok"` or `"error"`. An error result also has the typed code.

If step 3 succeeds and step 4 fails, the tool exits 1 with `audit_incomplete`. The `intent` record stays in the file as evidence.

The audit file has no size limit and no rotation in v1. It is local to one machine. A second machine does not see its records.

The tool creates a new audit file with owner-only mode (0600) on Linux and macOS. An existing file keeps its mode. The tool does not check the audit file for `unsafe_file_mode`, because a record holds no secret. It also does not refuse an `audit_path` inside a git work tree (owner decision, section 11, item 39). Git can remove or rewind such a file, and then the re-enable guard (section 5.9) loses its history. Keep the audit file outside any work tree that runs `git clean` or `git checkout`.

### 3.4 Desired-state files

Two files describe one realm. They differ in content and in where they can live.

| | Config file `<realm>.config.yaml` | Users file `<realm>.users.yaml` |
|---|-----------------------------------|----------------------------------|
| Holds | Realm settings and clients | Users |
| Personal data | None | Usernames and emails |
| Credentials | None | None. The file names an environment variable for a temporary password |
| Where it lives | In the operator's project, under version control | Outside any git work tree. The operator sets the path. No default |
| Removal by `apply` | Managed clients and their mappers, with `--allow-delete` | Never |

Both files are UTF-8 YAML. Each file is read with a safe loader. Each file starts with `schema_version` and `kind`. A duplicate key is refused (exit 2, `duplicate_key`).

**Config file (`kind: config`)**

```yaml
# acme.config.yaml
schema_version: 1
kind: config
owner: acme-platform             # required by apply and export-realm; set only in this file
realm:
  name: acme                     # must equal --realm when given (realm_mismatch)
  enabled: true
  displayName: "Acme"
  accessTokenLifespan: 900       # seconds
  registrationAllowed: false
clients:
  - clientId: acme-web
    enabled: true
    publicClient: true
    standardFlowEnabled: true
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: false
    pkce: S256                   # sets the attribute pkce.code.challenge.method; public clients only
    redirectUris: ["http://127.0.0.1:3000/*"]
    webOrigins: ["http://127.0.0.1:3000"]
  - clientId: acme-api
    enabled: true
    publicClient: false
    secret_managed: true         # the value lives in the secrets file (section 3.5)
    standardFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: false
  - clientId: svc-reports
    enabled: true
    publicClient: false
    secret_managed: true
    standardFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: true
    mappers:                     # a client without this key has no managed mappers (rule below)
      - { name: acme-api-audience, kind: audience, audience: acme-api }
```

**Realm fields.** `name`, `enabled`, `displayName`, `accessTokenLifespan`, `registrationAllowed`. No other realm key is accepted. The tool does not set the token signature algorithm. It keeps the Keycloak default.

**Client fields.** `clientId`, `enabled`, `publicClient`, `standardFlowEnabled`, `directAccessGrantsEnabled`, `serviceAccountsEnabled`, `redirectUris`, `webOrigins`, `pkce`, `secret_managed`, `mappers`. The tool field `secret_managed` is not sent to Keycloak.

**Mapper fields.** Only `kind: audience` is accepted in v1. It creates a Keycloak `oidc-audience-mapper`. Fields: `name`, `kind`, `audience`. The `audience` value is the `clientId` of the target client. The tool sets `access.token.claim=true`, `introspection.token.claim=true` and `id.token.claim=false`. An `audience` that names a client neither declared nor live exits 1, `not_found`, in preflight.

**Built-in clients** (`account`, `account-console`, `admin-cli`, `broker`, `realm-management`, `security-admin-console`) cannot be declared. A file that names one exits 2, `builtin_client`.

**Users file (`kind: users`)**

```yaml
# acme.users.yaml, kept outside git
schema_version: 1
kind: users
realm: acme                      # must equal --realm and the config realm name when given (realm_mismatch)
users:
  - id: "7c1e0000-0000-4000-8000-000000000001"   # required, UUID, generated by the operator's tooling
    username: admin1
    enabled: true
    email: admin1@example.invalid
    emailVerified: true
    firstName: "Ada"
    lastName: "Admin"
    temporary_password_env: ACME_ADMIN1_TEMP_PASSWORD   # the variable name only, never a value
```

**User fields.** `id` (required, UUID), `username`, `enabled`, `email`, `emailVerified`, `firstName`, `lastName`, `temporary_password_env`. No other user key is accepted. An `id` that is not a UUID exits 2, `id_invalid`.

The default Keycloak user profile requires `email`, `firstName` and `lastName` for a user to sign in. A user without them gets `invalid_grant` ("Account is not fully set up") at the first sign-in. A second user with the same `email` makes `partialImport` return HTTP 500. Section 11, items 37 and 38 give the live results. The tool refuses duplicate emails in preflight and lists an incomplete profile in `plan` (item 38).

**Types and defaults**

| Key | Type | Default when omitted on create | Note |
|-----|------|--------------------------------|------|
| `realm.name` | string | required | Letters, digits, `-`, `_` and `.` |
| `realm.enabled` | boolean | `true` | |
| `realm.displayName` | string | Keycloak default (empty) | |
| `realm.accessTokenLifespan` | integer | Keycloak default (300) | Seconds, from 1 to 86400 |
| `realm.registrationAllowed` | boolean | `false` | |
| `clientId` | string | required | Keycloak accepts a colon. The tool does not test it (section 11) |
| `enabled` | boolean | `true` | |
| `publicClient` | boolean | `false` | |
| `standardFlowEnabled`, `directAccessGrantsEnabled`, `serviceAccountsEnabled` | boolean | `false` | |
| `redirectUris`, `webOrigins` | list of strings | `[]` | Compared as sets |
| `pkce` | `S256`, or absent | absent | Exit 2, `config_invalid`, on a confidential client |
| `secret_managed` | boolean | `false` | `true` on a public client exits 2, `secret_managed_public` |
| `mappers` | list | absent | Absent means the tool manages no mappers on that client |
| `owner` | string | required | Config file only. Required by `plan`, `apply` and `export-realm` (`owner_required`) |
| `id` (user) | UUID | required | Section 5.6 explains the create path |

**Built-in clients are never listed.** `plan` and `export-realm` skip them.

**Rules for both files**

- **Declared fields only.** `plan` compares only the fields that the file declares. A field removed from the file keeps its server value. The tool never resets a field to a Keycloak default.
- **Lists are sets.** `redirectUris`, `webOrigins` and `mappers` compare as sets. Order does not cause a difference.
- **Mappers are managed only when the key is present.** A client without `mappers` keeps every mapper it has. A client with `mappers: []` loses its managed mappers, with `--allow-delete`. Keycloak can add mappers of its own to a client that has service accounts. Whether the tool sees such mappers is **not verified** (section 11).
- **Values are normalised before comparison.** The string `"true"` equals the boolean `true`. Numbers compare as numbers.
- **Unknown keys are refused.** Exit 2, `unknown_field`. A typo never passes as a no-op.
- **Managed clients.** `apply` sets the client attribute `kc-axi.managed` to the owner name when it creates or adopts a client. A file changes or removes only the clients whose marker equals its owner. A declared client whose marker names another owner exits 1, `owner_conflict`, in preflight.
- **Owner.** The owner comes only from the `owner` key of the config file. The tool configuration has no `owner` key. A value given there exits 2, `unknown_field`.
- **Service-account users** belong to their client. A users file never lists them. `export-realm` never writes them.
- **No secret value** appears in either file.
- **Users carry no marker.** A live check did not store a user attribute (section 11). Ownership of a user is the `realm` of the users file and the `id` that the file declares.

### 3.5 Secrets directory and file

The secrets directory holds one secrets file for each realm. It also holds one lock file. Each change of a value is a new numbered generation. A bad rotation can be undone.

The directory is set by `secrets_dir`. An empty `secrets_dir` means the `kc-axi/secrets` folder of the user configuration directory (section 6.1). The file for a realm is `<realm>.secrets.json` inside that directory.

```json
{ "schema_version": 1, "realm": "acme", "server": "http://127.0.0.1:8080", "active": 3,
  "generations": [
    { "generation": 3, "created_at": "2026-10-27T09:14:02Z", "state": "active",
      "clients": { "svc-reports": { "value": "...", "fingerprint": "ab12cd34" } } },
    { "generation": 2, "created_at": "2026-10-20T08:00:00Z", "state": "retired",
      "clients": { "svc-reports": { "value": "...", "fingerprint": "5e6f7a8b" } } }
  ] }
```

**Fields**

- `server` is the `base_url` after normalisation. Normalisation lowers the case of the scheme and the host, and removes one trailing slash. `localhost` and `127.0.0.1` are two different servers for this check. Use one spelling for each server.
- `active` is the number of the generation that Keycloak holds. While a `pending` generation exists, the tool sets `active` to the pending number at write time. `state` tells the two cases apart. A reader that finds `state: pending` in the generation named by `active` must not use the value (section 5.8).
- A secrets file whose `realm` names another realm exits 1, `secrets_unreadable`. `secrets list` on a realm with no secrets file prints `status: empty` and exits 0.
- **Missing file, by command.** A missing file is not an error for `apply` and `plan`. The first `apply` that needs the file creates it (section 5.8, create path). `plan` treats a missing file as empty, so each `secret_managed` client shows `secret_missing`. `secrets capture` and `export-realm --capture-secrets` create the file. `secrets prune` on a missing file prints `status: already` and exits 0. A missing file for a reader, for `secrets rotate` or for `secrets restore` is `secrets_unreadable` (section 5.8 and section 7).
- Generation numbers are `max(existing) + 1`. `prune` never deletes an `active` or a `pending` generation, so a gap in the numbers means that `prune` deleted those generations. `secrets restore N` uses the gap to tell `generation_pruned` from `generation_unknown`.
- `state` is one of three values. `pending` means the value is written locally and is not yet confirmed on Keycloak. `active` means the value is the one Keycloak holds. `retired` means an older value.
- Each generation holds every `secret_managed` client of the realm. A client that is not rotated keeps its active value in the new generation.
- `fingerprint` is the first 8 hex digits of the SHA-256 of the value. A fingerprint is a label. It is not safe to publish for a weak, chosen value.
- A generated value is 32 random bytes from `secrets.token_bytes`. It is encoded as base64url without padding.

**Rules**

- **Created on first write.** The first write that needs the file creates the file. The tool creates the directory with owner-only permissions on Linux and macOS. On Windows the tool does not check modes (section 5.4).
- **Never in a git work tree.** A `secrets_dir` inside a git work tree exits 2, `unsafe_path`. Detection walks up the directories and looks for a `.git` entry. A directory or a file both count. The tool does not need the `git` program.
- **Owner-only mode.** On Linux and macOS, the tool exits 2, `unsafe_file_mode`, when another user can read or write a file. Group access counts.
- **Server check.** The `server` value must equal the normalised `base_url` of the command. Otherwise the command exits 2, `secrets_server_mismatch`.
- **Lock file.** The lock file is `kc-axi.lock` in `secrets_dir`. Section 5.6 explains the lock.

**Consumers.** A consumer reads this file by the rules of section 5.8. Any language can implement those rules. The file format is the interface. The tool has no command that prints a value.

## 4. Interface

### 4.1 Global flags and environment

| Flag | Environment | Meaning |
|------|-------------|---------|
| `--config PATH` | `KC_AXI_CONFIG` | Tool configuration file. Order: flag, then variable, then the default for the operating system (section 6.1) |
| `--realm R` | `KC_AXI_REALM` | Realm for the command. Order: flag, then variable, then `default_realm`. With none, exit 2, `realm_required` |
| `--runtime docker\|podman\|auto` | `KC_AXI_RUNTIME` | Container runtime for `up`, `down` and `status` |
| `--json` | none | Print the JSON contract (section 4.3) |
| `--fields a,b` | none | Add fields to a list or a get view |
| `--limit N` | none | Items to show in a list. Default 20 |
| `--yes` | none | Confirm a write (section 4.2) |
| `--allow-remote` | none | Allow a write to a server that is not local (section 5.4) |
| `--help`, `--version` | none | `--version` answers without reading any file |

The tool never prompts. No flag reads a value from standard input.

Connection and credential variables: `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`, `KC_AXI_BASE_URL`, `KC_AXI_AUDIT_PATH`, `KC_AXI_SECRETS_DIR`. Each variable overrides the matching key in the tool configuration file. Section 5.4 gives the order for the password.

Paths given on the command line (`--file`, `--out`) and paths given in `KC_*` environment variables resolve from the working directory. Paths in the tool configuration file resolve from the directory of that file. `~` expands in both places.

### 4.2 Commands

| Command | Effect | Changes state | Needs `--yes` |
|---------|--------|---------------|---------------|
| `kc-axi` | No-argument view (section 4.5) | No | No |
| `kc-axi up` | Start the container if needed, and wait until ready | Local container | No |
| `kc-axi down [--purge]` | Stop and remove the container. `--purge` also removes the named volume | Local | With `--purge`, or when `volume` is empty |
| `kc-axi status` | Runtime, container, server, version and issuer | No | No |
| `kc-axi realms` | List realms | No | No |
| `kc-axi clients [--realm R]` | List clients | No | No |
| `kc-axi users [--realm R]` | List users | No | No |
| `kc-axi get realm\|client\|user KEY [--realm R]` | One object. `KEY` is the name, the `clientId` or the `username` | No | No |
| `kc-axi plan --file F` | Show the difference from the server | No | No |
| `kc-axi apply --file F [--expect H] [--adopt] [--allow-delete] [--allow-reenable] [--allow-remote] [--yes]` | Make the server match the file | Keycloak and local | Yes, when there is at least one action |
| `kc-axi export-realm --realm R --scope config\|users --out PATH [--owner NAME] [--include-unmanaged] [--capture-secrets] [--yes]` | Write the live state as one desired-state file | Local files, and the secrets file with `--capture-secrets` | Yes, when the file exists |
| `kc-axi export-realm --realm R --scope full --out PATH [--yes]` | Stop the container, export the whole realm to one file, and start the container again (section 5.12) | Local files, and the container | Yes, when the file exists |
| `kc-axi import-realm --realm R --file PATH [--yes] [--allow-remote]` | Replace the realm with the contents of one file, after a backup of the live realm (section 5.12) | Keycloak and local | Yes |
| `kc-axi secrets list [--realm R]` | Generations, states and fingerprints | No | No |
| `kc-axi secrets capture --realm R --client C [--yes] [--allow-remote]` | Record the live value of one client as a new generation | Local | Yes |
| `kc-axi secrets rotate --file F [--client C] [--yes] [--allow-remote]` | Write new values and apply them | Keycloak and local | Yes |
| `kc-axi secrets restore N [--realm R] [--yes] [--allow-remote]` | Copy generation N as a new generation, and apply it | Keycloak and local | Yes |
| `kc-axi secrets prune [--keep N] [--realm R] [--yes]` | Delete the oldest retired generations | Local | Yes |
| `kc-axi reset-password USERNAME --file F [--realm R] [--yes] [--allow-remote]` | Set a temporary password for one existing user (section 5.11) | Keycloak | Yes |
| `kc-axi disable-user USERNAME [--realm R] [--yes] [--allow-remote]` | Disable one user and end its sessions (section 5.9) | Keycloak | Yes |
| `kc-axi disable-client CLIENTID [--realm R] [--yes] [--allow-remote]` | Disable one client (section 5.9) | Keycloak | Yes |

**Confirmation.** A write with at least one action and no `--yes` changes nothing. It prints the keys of `plan` as a preview, and it exits 1 with `confirm_required`. A write with no action exits 0 with `already`, with or without `--yes`.

**Flag rules**

- `--adopt` and `--allow-delete` on a users file exit 2, `flag_not_valid`.
- `--allow-reenable` is valid on `apply` for both files. It lifts the guard of section 5.9.
- `--capture-secrets` on `export-realm` writes the secrets file. It needs `--yes`.
- `export-realm --scope` is required. The tool has no default scope.
- `export-realm --scope config` needs `--owner`, or the owner from the file named by `--file`, if any. Without an owner, the command exits 2, `owner_required`.
- `reset-password` reads the variable named in `temporary_password_env` from the users file given by `--file`. A variable that is not set exits 1, `temporary_password_missing`.

### 4.3 Output

**Default view.** Lists and objects print in the compact list form (section 4.5, rule 1). Each list header states `shown of total`. `plan` and `apply` never truncate their actions. `--limit` does not apply to them.

```
status: drift
realm: acme
total: 3
actions[3 of 3]{action,kind,name,detail}:
  create,client,svc-reports,
  change,client,acme-web,redirectUris
  remove,mapper,acme-api-audience,
unmanaged[1]{kind,name}:
  client,legacy-tool
plan_hash: 91f3c2a0
help[1]:
  kc-axi apply --file acme.config.yaml --expect 91f3c2a0
```

`unmanaged` lists live clients that the file does not declare and that carry no marker of this owner. Built-in clients are never listed. `unmanaged` is informational. It is not an action. It is not in `total`, `plan_hash` or the exit code (section 5.6, step 5).

`password_missing` is informational in the same way. It lists users with no password whose `temporary_password_env` is set. The repair is `reset-password` (section 5.11).

`profile_incomplete` is informational in the same way. It lists declared users that lack `email`, `firstName` or `lastName`. The default Keycloak user profile requires all three for sign-in (section 11, item 37). The list does not change `total`, `plan_hash` or the exit code.

**Errors** go to stdout in the same form:

```
error: keycloak_unreachable
message: no answer from http://127.0.0.1:8080 after 10 seconds
help[1]:
  kc-axi status
```

**Preview of a refused write.** A write without `--yes` prints the same keys as `plan`. The header line is `status: confirm_required`. Nothing changes.

**JSON contract.** Every JSON output has `schema_version: 1` and `command`. An error uses one envelope:

```json
{ "schema_version": 1, "command": "apply",
  "error": { "code": "apply_partial", "message": "...", "help": "...",
             "applied": 2, "pending": 3, "cause": "keycloak_rejected",
             "field": "redirectUris",
             "created": [{"kind": "client", "name": "acme-web", "id": "..."}] } }
```

- An error object has `code`, `message` and `help`. It can also have `applied` (a count), `pending` (a count), `cause` (a typed code), `field`, `created` and `refusals`.
- A run with several preflight refusals puts each one in `refusals`. Each entry has `code`, `kind`, `name` and `field` where they apply. The top-level `code` is the code of the first refusal, in the order of section 5.6 step 6. A single refusal has the same shape. The caller reads `refusals` for the others.
- A partial run is always an error. No `status: partial` value exists.

Keys per command (besides `schema_version` and `command`):

| Command | Keys |
|---------|------|
| `up` | `status` (`started`, `already_running`), `runtime`, `container`, `state`, `server`, `version`, `issuer`, `warnings` (list of strings) |
| `down` | `status` (`removed`, `already_absent`), `runtime`, `container`, `volume` (`kept`, `removed`, `absent`, `none`) |
| `status` | `status` (`ok`), `runtime`, `container` (the state of section 5.3), `image`, `port`, `hostname`, `issuer`, `server` (`up`, `down`), `version` (string or null), `credential` (`present`, `missing`), `permissions` (`checked`, `not_checked`), `oom_killed` (boolean, stopped containers only) |
| `realms`, `clients`, `users`, `get` | `status` (`empty`, `active`), `total`, `shown`, `items` (objects with the fields of section 3.2) |
| `plan` | `status` (`no_change`, `drift`), `realm`, `total`, `shown`, `actions` (list of `action`, `kind`, `name`, `detail`), `unmanaged` (list of `kind`, `name`), `password_missing` (list of `username`), `profile_incomplete` (list of `username`, `missing`), `plan_hash` |
| `apply` | `status` (`already`, `applied`), `applied` (count), `created` (list of `kind`, `name`, `id`), `plan_hash` |
| `export-realm` | `status` (`written`), `path`, `kind`, `skipped` (count of skipped clients), `unmanaged_included` (count) |
| `export-realm --scope full` | `status` (`written`), `path`, `kind` (`full`), `realm`, `users` (count), `clients` (count) |
| `import-realm` | `status` (`replaced`), `realm`, `users` (count), `clients` (count), `backup` (path of the backup written before the replace) |
| `secrets list` | `status`, `realm`, `active`, `generations` (list of `generation`, `state`, `created_at`, and `clients` as `name` to `fingerprint`) |
| `secrets capture`, `rotate`, `restore`, `prune` | `status` (`already`, `done`), `generation`, `applied` (count), `pruned` (count) |
| `reset-password` | `status` (`already`, `done`), `username`, `id` |
| `disable-user`, `disable-client` | `status` (`already`, `disabled`), `kind`, `name`, `id` |

In `plan`, `detail` is a string: the field names, separated by commas. In an error, `applied` and `pending` are counts, not lists.

**`plan_hash`.** The first 16 hex digits of the SHA-256 of a canonical JSON document. Canonical means three rules. Object keys are sorted. Separators are `,` and `:`, with no spaces. Text is UTF-8. Lists of sets are sorted. The document holds:

- `schema_version`, `realm` and the normalised `base_url`;
- the SHA-256 of the canonical JSON of the parsed desired-state file. The raw bytes are not used, so a CRLF checkout and an LF checkout give the same hash;
- the sorted list of actions. A `change` holds `from` (the live value) and `to` (the value in the file). A `secret` or `finish_pending` action holds the two fingerprints. A create of a `secret_managed` client holds the text `secret: new`. No random value enters the hash.

The hash holds the live values. A server change between `plan` and `apply` changes the hash when it affects an action. `--expect` then refuses the run.

### 4.4 Exit codes

The tool follows the library rule in `libs/README.md` in agentzero-v2-dev, section CLI Conventions. Exit 0 is a success. Exit 1 is a failure with a typed code. Exit 2 is a usage or configuration error. Every failure prints its typed code in `error:`, or in `error.code` with `--json`.

| Exit | Meaning | Typed codes |
|------|---------|-------------|
| 0 | Success. Includes an empty result, `already`, `no_change`, and `status` for an unreachable server | none |
| 1 | The command failed, or a judging command found a difference | See the table below |
| 2 | Usage or configuration | `usage`, `flag_not_valid`, `config_missing`, `config_invalid`, `unknown_field`, `duplicate_key`, `schema_unsupported`, `realm_required`, `realm_mismatch`, `owner_required`, `admin_realm_refused`, `builtin_client`, `credential_missing`, `insecure_url`, `image_invalid`, `volume_invalid`, `audit_required`, `unsafe_path`, `unsafe_file_mode`, `secrets_server_mismatch`, `secret_managed_public`, `id_invalid`, `import_invalid` |

Exit 1 codes:

| Typed code | Meaning |
|------------|---------|
| `drift` | `plan` found a difference. `status: drift` is in the output. Judging commands only |
| `confirm_required` | A write with at least one action and no `--yes`. Nothing changed. The preview is in the output |
| `plan_changed` | `--expect` differs from the new plan hash. Nothing changed |
| `needs_adopt` | A declared client exists without the marker, and `--adopt` is absent. Refused in preflight |
| `owner_conflict` | A declared client carries the marker of another owner. Refused in preflight |
| `allow_delete_required` | A managed client or mapper would be removed, and `--allow-delete` is absent. Refused in preflight |
| `allow_remote_required` | A `base_url` that is not local, without `--allow-remote`. Refused in preflight |
| `reenable_refused` | A user or client has a `disable` record and no later `enable` record, and `--allow-reenable` is absent. Refused in preflight |
| `secrets_mismatch` | An active generation differs from the live secret of a `secret_managed` client. Refused in preflight (section 5.8) |
| `secrets_missing` | A live `secret_managed` client has no value in the secrets file, and `--adopt` does not capture it. Refused in preflight |
| `generation_pending` | A `pending` generation exists, and the command cannot run until `apply` or `rotate` finishes it. The secret reader also returns this code |
| `generation_unknown` | `secrets restore N` names a generation that does not exist |
| `generation_pruned` | `secrets restore N` names a generation that `prune` deleted |
| `temporary_password_missing` | The variable named in `temporary_password_env` is not set, for a user to be created or for `reset-password`. Refused in preflight |
| `runtime_missing` | Neither runtime is installed, or the Podman machine is stopped. For `status`, this is exit 1 |
| `runtime_failed` | The runtime returned an error |
| `runtime_timeout` | A runtime call passed `runtime_timeout_seconds` or `pull_timeout_seconds` |
| `runtime_ambiguous` | Both runtimes hold a container, or neither holds one and both are installed (`up`). For `status`, this is exit 1 |
| `container_state` | The container is in a state the tool does not handle |
| `container_exited` | The container stopped during `up`. The output names the state and `oom_killed` |
| `port_in_use` | The runtime reported the port as taken |
| `keycloak_unreachable` | No answer from `base_url` in time, for any command except `status` |
| `keycloak_timeout` | `up` did not see a ready server within `ready_timeout_seconds`, or a command passed `command_timeout_seconds` |
| `auth_failed` | The admin login was refused. The output names the causes in section 5.3 |
| `keycloak_rejected` | Keycloak refused a request. The output names the field. Used only after Keycloak received the request |
| `id_conflict` | A users-file `id` belongs to another username, or a username has another `id`. Refused in preflight |
| `email_duplicate` | A declared `email` equals the `email` of another declared user. It can also equal the `email` of a live user with another `id`. The tool compares in lower case. Refused in preflight, because Keycloak answers a duplicate with HTTP 500 (section 11, item 38) |
| `not_found` | The realm, client or user does not exist, or a mapper names a missing target client |
| `realm_absent` | A users file names a realm that does not exist yet. Refused in preflight |
| `secrets_unreadable` | The secrets file is missing, cannot be read, or cannot be parsed |
| `audit_failed` | The audit file cannot be opened. Checked before any change (section 5.6 step 3). Nothing changed |
| `audit_incomplete` | The write happened, and the result record could not be written |
| `locked` | Another run holds the lock (section 5.6) |
| `file_failed` | A local file cannot be written, for example on a full disk. The message names the path |
| `secret_in_export` | An export contains a secret value. The output file is deleted |
| `apply_partial` | A write failed after at least one change. `applied`, `pending` and `cause` give the counts and the failing code |
| `import_partial` | The realm was deleted and the new file did not load. The error gives `backup`, the path of the backup. Run `import-realm` with that file to restore the realm |

**Partial runs.** `apply` stops at the first failure. Its exit is 1 and its code is `apply_partial`. The error object gives `applied`, `pending` and `cause`. Keycloak has no transactions. Running `apply` again finishes the job. A run never exits 0 while an action is pending.

**Judging commands.** `plan` exits 0 when there is no difference. It exits 1 with `status: drift` when there is one. `status` exits 1 only for `runtime_ambiguous` and `runtime_missing`. It exits 0 when the server does not answer. A caller branches on the exit code, then reads `status`.

### 4.5 CLI rules

The tool follows these AXI principles. Each rule restates a rule in section "CLI Conventions (AXI)" of `libs/README.md` in agentzero-v2-dev.

1. **Compact default view.** Keys and values print in the compact list form of section 4.3. A free-text value longer than `max_cell_chars` (200) is cut, with `… (N chars total)`. `--fields` adds fields. Use `--json` to read a full value.
2. **Minimal default schema.** Three or four fields per row (section 3.2). `--fields a,b` adds fields.
3. **Count and truncation.** Each list states `shown of total`. The default limit is 20. A list that is cut prints `help` with the next command.
4. **Definitive empty states.** An empty list prints `status: empty` and `total: 0`. It says what it checked, for example `users: none (realm acme, 0 users)`. Exit 0.
5. **Errors on stdout.** `error:`, `message:` and `help:` print on stdout. Progress text prints on stderr. The `--json` error envelope prints on stdout.
6. **Idempotent writes.** A write with no action exits 0 and prints `already`, with the reason.
7. **No-argument view.** `kc-axi` with no arguments prints `bin`, `description`, the configuration path and whether that file exists. It reads no network and calls no runtime.
8. **Help.** Each command has `--help`. `--version` prints the version and reads no file.
9. **Unknown flags.** Exit 2, `flag_not_valid`, with the valid flags listed.
10. **Hints.** At most three `help` lines, with real values. A hint appears only when a next step exists.
11. **No prompts.** The tool never waits for input.

**Recorded deviation.** The tool has no `--full` flag. The `--json` output gives the full value. Section 10 records the reason.

## 5. Behaviour

### 5.0 First run on an empty machine

Run these steps in order:

1. Install the runtime. For Podman, run `podman machine init`, then `podman machine start`. Give the machine at least **4 GiB** of memory. The command `podman machine set --memory 4096` sets it while the machine is stopped. This command is **not verified** on this host (section 11).
2. Write the tool configuration file (section 6.1). The minimum keys are `base_url`, `port`, `image`, `container_name`, `audit_path` and `secrets_dir`. Give `image` a fully qualified tag. The tested tag is `quay.io/keycloak/keycloak:26.6.4`.
3. Set the admin password in `KC_ADMIN_PASSWORD`. Section 5.4 gives the other sources.
4. Run `kc-axi up`. Wait for `status: started`.
5. Run `kc-axi status`. Check that `server: up`, that `version` is shown, and that `issuer` has the expected value.
6. Write the config file and, if needed, the users file. Run `kc-axi plan --file <file>`. Then run `kc-axi apply --file <file> --yes`.
7. Run `kc-axi secrets list`. Check that each `secret_managed` client has an active generation.

### 5.1 Reading and counting

The tool parses the JSON response of Keycloak, counts the items, and cuts the list to the limit. It does not parse text with line tools. A value with a comma, a space or a nested object cannot change the count.

Facts probed on Keycloak 26.6.4 (2026-10-27) that the read commands rely on:

- `GET /users` returns at most 100 users when no `max` is given. `users` reads `/users/count` for the total, then fetches only `limit` rows with `first` and `max`. The header `shown of total` is always true.
- `GET /clients` has no cap, no count and no fixed order. `clients` sorts by `clientId`.
- `GET /clients` returns `secret` for a confidential client. The tool copies only an allow-list of fields, so no secret reaches an output.
- A username lookup ignores case. A `clientId` lookup does not.
- An unknown realm answers 404. The tool reports `not_found` and names the realm.
- `get client` finds a built-in client when it is named. The lists never show built-in clients.
- The `managed` column holds the owner name, or `null` for a client with no marker.

### 5.2 Choosing a container runtime

Podman is the primary target for development and testing. Docker is supported under the same contract. Docker was **not tested** (section 11).

The tool finds a container with the same command for both runtimes:

```
<runtime> container ls --all --filter name=^<container_name>$ --format "{{.State}}"
```

Empty output means no container. A non-zero exit means the runtime failed (exit 1, `runtime_failed`). The tool does not use `docker inspect` to look for containers, because that command also matches images and volumes.

The tool detects an installed runtime with `<runtime> --version`. A missing program, or a Podman machine that is stopped, exits 1, `runtime_missing`. The help line says `podman machine start`. One exception: plain `down` with `runtime: auto` and neither program installed exits 0, `already_absent`. No container can exist, so teardown stays safe to repeat. A runtime that the operator names (`--runtime` or `runtime:`) and that is missing always exits 1, `runtime_missing`, because the container may sit in the other runtime.

With `runtime: auto`:

- A command that acts on an existing container uses the runtime that holds `container_name`.
- `up` with one installed runtime uses that runtime.
- `up` with both runtimes installed, and neither holding the container, exits 1, `runtime_ambiguous`. The help line asks for `--runtime`.
- `down` with no container exits 0 with `already_absent`.
- `down --purge` with both runtimes installed and neither holding the container exits 1, `runtime_ambiguous`. The volume lives in one runtime, and with no container the tool cannot tell which. It deletes nothing on a guess. The help lines name `--runtime podman` and `--runtime docker`.
- `status` reports `missing` for both runtimes.
- When both runtimes hold the container, every command exits 1, `runtime_ambiguous`.

The tool does not guess. Docker and Podman keep separate container stores.

The tool starts a runtime as a subprocess with an argument list. It never uses a shell. This avoids quoting differences between shells. It keeps credentials out of shell history.

Every runtime call has a timeout. The timeout is `runtime_timeout_seconds`, and `pull_timeout_seconds` for the image pull inside `run`.

### 5.3 `up`, `down` and `status`

#### `up`

1. Check the configuration. Exit 2 when a check fails:
   - `image` is set. The tool has **no default image tag**.
   - `image` is fully qualified: a registry host, a repository, and a tag or a digest. The tag is not `latest`. A short name can make the runtime ask for a registry, and the tool never waits for input (`image_invalid`).
   - `port` equals the port of `base_url` (`config_invalid`). The host of `base_url` is local (section 5.4): `up` starts a local container, so a host that is not local with `https` also exits 2, `config_invalid`. The scheme is `http` only for a local host (`insecure_url`).
   - The admin credential has a source (section 5.4). Otherwise exit 2, `credential_missing`, before any request.
   - `audit_path` is set (`audit_required`).
2. Acquire the lock (section 5.6, step 2). Then read the container state (section 5.2).
   - `running`: print `already_running`. Go to step 6.
   - `created`, `exited` or `stopped`: start the container with `<runtime> start <container_name>`. Print `started`. Go to step 6.
   - Empty: go to step 3.
   - Any other state: exit 1, `container_state`, and print the state.
   - 2a. For an existing container, read its environment with `<runtime> container inspect`. When its `KC_HOSTNAME` differs from `hostname`, add a warning to `warnings`. The tool does not change the container.
3. Resolve `volume` (section 5.3.1). For a named volume, run `<runtime> volume create <volume>`. This command is safe to repeat.
4. Run the container in development mode:

   ```
   <runtime> run -d --name <container_name> -p 127.0.0.1:<port>:8080
       -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD -e KC_HOSTNAME
       [-e JAVA_OPTS_APPEND] [-v <volume spec>] <image> start-dev
   ```

   - `KC_BOOTSTRAP_ADMIN_USERNAME` takes the value of `admin_user`, or of `KC_ADMIN_USER`. `KC_BOOTSTRAP_ADMIN_PASSWORD` takes the value of the password source (section 5.4). `KC_HOSTNAME` takes `hostname`. When `hostname` is empty, the host of `base_url` is used. `KC_HOSTNAME` is a container variable only. The tool does not read it from its own environment.
   - `-e JAVA_OPTS_APPEND` is added only when `java_opts` is set.
   - The tool sets the values in the subprocess environment. Each `-e NAME` has **no value**. The runtime copies the value from that environment. The password is not in the argument list (criterion 8).
   - The runtime keeps that environment in the container record. Anyone who can read the record can read the password with `<runtime> inspect`. The record is removed by `down` (section 5.4). This is the normal behaviour of both runtimes. It is **not verified** on this host for Docker.
   - The image pull happens inside `run`. It uses `pull_timeout_seconds`. It does not count against `ready_timeout_seconds`.
5. A port conflict or another runtime error exits 1 with the runtime's message.
6. Poll `GET <base_url>/realms/master` once a second until HTTP 200, or until `ready_timeout_seconds` passes. Before each poll, read the container state. When the container is no longer running, exit 1, `container_exited`, within 5 seconds of the state change. The output names the state and `oom_killed`. When `oom_killed` is true, the help line prints the suggested setting `java_opts: "-Xms256m -Xmx640m"`. It also states the 4 GiB engine minimum of section 5.0. On timeout, exit 1, `keycloak_timeout`. The container is left as it is.
7. Log in once as the admin user, with the password grant of the built-in client `admin-cli`. This grant is not tested as a separate step (section 11). A failure exits 1, `auth_failed`. The message names two causes:
   - The image does not read the `KC_BOOTSTRAP_ADMIN_*` names.
   - The volume already holds an admin user with a different password. Keycloak creates the admin user only on a new volume (section 11).

An existing container is not changed by `up`. `status` shows its image, port, `hostname` and issuer. To change any of them, the operator runs `down`, then `up`.

#### 5.3.1 Volume rules

| `volume` value | Meaning | Argument |
|----------------|---------|----------|
| empty | No persistence | none |
| letters, digits, `_`, `.` and `-` only | Named volume (the default) | `-v <volume>:/opt/keycloak/data` |
| contains `/` or `\`, or starts with `.` | Host path | `-v <path>:/opt/keycloak/data[:<volume_options>]` |
| contains `:` or starts with `~` | Not accepted | Exit 2, `volume_invalid` |

- `volume_options` applies to a host path only. With an empty or a named `volume`, a set `volume_options` exits 2, `volume_invalid`.
- The tool **never adds** `:Z` or `:U`. Both change the labels or the ownership of the host directory. The operator sets `volume_options` (for example `Z`) when an SELinux host needs it.
- A host path on Windows exits 2, `volume_invalid`. The engine runs in a virtual machine, and its path forms differ.
- A host path outside the shared mounts of the machine (macOS `podman machine`) fails in the runtime. The tool exits 1, `runtime_failed`, with the runtime's message.
- Rootless Podman maps the container user to a different host UID. Whether a named volume needs no extra step is **not verified** on native Linux (section 11).
- Persistence across a restart is **not verified**. It is a release gate (section 11).

#### `down`

1. Acquire the lock. Read the container state (section 5.2). With no container, print `already_absent` and exit 0. An empty `volume` still needs `--yes` (see below).
2. Stop and remove the container: `<runtime> stop -t 10 <container_name>`, then `<runtime> rm <container_name>`. The runtime removes the container record. The record holds the environment copied at `up`.
3. With `--purge` and a **named** volume, run `<runtime> volume rm <volume>`. A missing volume is reported as `absent`. A volume in use exits 1, `runtime_failed`. A host path is never removed.

`down` needs `--yes` in two cases: with `--purge`, and when `volume` is empty. Both cases can delete realm data.

#### `status`

1. Read the container state (section 5.2). Map it: `running` is `running`. `created`, `exited` and `stopped` are `stopped`. Empty is `missing`. Any other state is printed as `other:<state>`.
2. Probe `GET <base_url>/realms/master` with a 2-second timeout.
3. Print the runtime and the container state. Print the image and the port from `container inspect`. Print the `hostname`, the issuer, whether the server answers, the server version and `credential`.
   - The issuer is `<scheme>://<hostname>:<port>/realms/<realm>`. The `hostname` is the value that `KC_HOSTNAME` holds in the container. A consumer that checks the `iss` claim uses this value. The discovery document is at `<issuer>/.well-known/openid-configuration`. That path is the standard OpenID Connect path. It is **not tested** by this check.
   - The version needs an admin login. Without a credential, `version` is `null` and the line is `version: unknown (no credential)`.
   - For a stopped container, add `oom_killed`, read from `container inspect` (`State.OOMKilled`). A container killed for memory exits 137 (section 11).
   - On Windows, each local file line prints `permissions: not_checked`. Elsewhere it prints `checked`.
4. `status` exits 0 when it can report, even when the server does not answer. It exits 1 with `runtime_ambiguous` or `runtime_missing`.

### 5.4 Safety, credentials and locality

- **Read by default.** A write with at least one action and no `--yes` changes nothing. It prints the preview and exits 1 with `confirm_required`.
- **Local scope.** A write to a `base_url` whose host is not local is refused in preflight. It exits 1, `allow_remote_required`. A local host is one of the three fixed names `localhost`, `127.0.0.1` and `::1`. The tool does not resolve names, so the result never depends on DNS. `--allow-remote` lifts the refusal. This rule covers every write to Keycloak: `apply`, `disable-user`, `disable-client`, `reset-password`, every `secrets` write and `export-realm --capture-secrets`. Remote and CI use are a later phase (section 11).
- **Plain HTTP.** `http` is allowed only for a local host (`insecure_url`). An `https` `base_url` uses the system CA store, or `ca_file`.
- **Server version.** The tested range is Keycloak 26.x, starting with 26.6.4 (section 11). A server outside 26.x prints a warning on stderr. The command then runs. Behaviour outside the tested release is not promised.
- **No secret in output**, with or without `--fields` or `--json`. No password, client secret, token or temporary password appears. Fingerprints are allowed.
- **Keycloak returns client secrets in plain text.** `GET /admin/realms/{realm}/clients` includes the field `secret`. The tool reads clients through an allow-list of fields, so the value never reaches the output (section 11).
- **Redaction.** Before any print, the tool removes secrets from the message. Secrets are the admin password, every client secret and every temporary password. This includes Keycloak's own error messages.
- **No prompts.** The tool never waits for input.
- **Credentials never on the command line.** The sources, in order:
  1. The environment variable `KC_ADMIN_PASSWORD`.
  2. The file named by `admin_password_file`.

  A password in the tool configuration file exits 2, `unknown_field`.
- **One trailing newline is removed** from `admin_password_file`. The newline is one LF or one CRLF.
- **Writes are not retried.** Section 5.6 gives the rule for a write that times out.
- **One login per call.** The tool gets a short-lived admin token. It discards the token at the end of the command. It writes no token to disk. When a read gets HTTP 401, the tool logs in once more and repeats that read. When a write gets HTTP 401, the server changed nothing. The tool logs in once more and repeats that one request. If the second login fails, the command exits 1, `auth_failed`, with the `applied` and `pending` counts.
- **Local file modes (Linux and macOS).** The tool checks the password, users and secrets files. A file that another user can read or write exits 2, `unsafe_file_mode`. The help line names `chmod 600`. A file created with the common default mode 644 fails on the first run.
- **Secret files are created in one step** with owner-only permissions on Linux and macOS. The tool does not change the mode afterwards.
- **Windows.** The tool does not check file modes. `status` prints `permissions: not_checked`. The secrets directory sits under `%APPDATA%`, which Windows restricts to the user by default. This is a default, not a check. A roaming profile can sync that folder to other machines. Windows is out of scope for now (section 11). Its statements are **verified by reading only**.
- **Admin credentials bypass the access rules** of the application that uses Keycloak. Run the tool as an administrator, or as an agent that acts for one. Do not make the tool reachable from a sandbox that runs untrusted agent code.

### 5.5 Platform matrix

| Concern | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Install | Python package. Minimum Python version is not set (section 11) | Python package | Python package. Out of scope for now |
| Container engine | Podman or Docker runs containers directly. Podman is the first target. **Not verified** (section 11) | Podman runs Linux containers in a virtual machine (`podman machine`). **Verified** on Podman 6.1.4. Docker not tested | Docker Desktop or Podman. **Verified by reading only** |
| Port on `127.0.0.1` | Direct. **Verified by reading only** | Forwarded by the machine. **Verified** | Forwarded by the engine. **Verified by reading only** |
| SELinux labels | Only with `volume_options`. **Not verified** | Not applicable | Not applicable |
| Shell | None required | None required | None required. No `bash`, `jq`, `grep` or `tr` |
| Paths | `/`-separated | `/`-separated | Accepts either separator in arguments. Never builds a path inside the container |
| Line endings | LF written | LF written | LF written. CRLF accepted on read. **Verified by reading only** |
| File replace | `os.replace` | `os.replace` | `os.replace`. A reader that holds the file open can make it fail. **Verified by reading only** |
| Lock | `fcntl` advisory lock | `fcntl` advisory lock | `msvcrt` lock. **Verified by reading only** |

The first release targets Linux with Podman and macOS with Podman (section 11). Windows is out of scope for now.

### 5.6 `plan` and `apply`

`plan --file F` writes nothing. It takes no lock.

1. Load the file. Check `schema_version`, `kind`, the keys and the types. Exit 2 on any problem. Refuse a config file whose realm is `admin_realm` (exit 2, `admin_realm_refused`). Refuse a `--realm` that differs from the file's realm (`realm_mismatch`).
2. Log in once. Read the live state: the realm, each client through the allow-list of fields, and the users. Read the mappers of each managed client too.
3. For each declared object, decide one action:
   - `create`: the object does not exist.
   - `adopt`: a declared client exists without any marker. `apply` refuses it without `--adopt`.
   - `owner_conflict`: a declared client exists with the marker of another owner. `apply` refuses it.
   - `change`: the object exists and a declared field differs. `detail` lists the fields.
   - `finish_pending`: a `secret_managed` client has a `pending` generation, and its live secret equals the pending value or the active value. `apply` finishes the generation (section 5.8, step 9.1).
   - `secret`: a `secret_managed` client's live secret equals neither the active value nor, when a `pending` generation exists, the pending value. `apply` refuses it with `secrets_mismatch` (section 5.8).
   - `secret_missing`: a `secret_managed` client exists live and has no value in the secrets file. `apply` refuses it unless `--adopt` captures the value (section 5.8).
   - `create`, `change` or `remove` for a mapper, under its client. A mapper is `remove` only when the client has a `mappers` key.
4. List each live client with this owner's marker that the file does not declare, as `remove`. `apply` removes it only with `--allow-delete`.
5. List the following as informational. They are not actions, and they are not in `total`, `plan_hash` or the exit code:
   - `unmanaged`: live clients that the file does not declare and that carry no marker of this owner. Built-in clients are never listed.
   - `password_missing`: declared users with no password credential whose `temporary_password_env` is set.
   - `profile_incomplete`: declared users that lack `email`, `firstName` or `lastName`. Each entry names the missing fields.
6. Print the actions, the informational lists and `plan_hash`. Exit 0 with `status: no_change` when there are no actions. Otherwise exit 1 with `status: drift`.

**Implementation notes for `plan` (task I6, 2026-10-27).**

- A config file without `owner` exits 2, `owner_required`, because step 4 and the `adopt` and `owner_conflict` decisions need an owner.
- A conflict is an action row: `owner_conflict` for a client, `id_conflict` for a user. `plan` exits 1 with `status: drift` for it. `apply` turns the row into a refusal (step 6 of `apply`).
- A users file for a realm that does not exist exits 1, `realm_absent`, in `plan` as well.
- `plan` compares the declared fields only, with lists as sets and `"true"` equal to `true`. `pkce` is read from the client attribute `pkce.code.challenge.method`. A mapper is compared by its `audience` and its three claim flags.
- Only mappers of the kind `audience` are managed. Other mappers on a client are never listed, changed or removed.
- `plan_hash` is the first 16 hex digits of the SHA-256 of canonical JSON (sorted keys, `,` and `:` separators). The JSON holds `schema_version`, the realm, the normalised `base_url`, the SHA-256 of the canonical declared file, and the sorted actions with their live and declared values. A secret enters as its 8-hex fingerprint only.
- Live check, 2026-10-27, Keycloak 26.6.4: `GET /clients` returns `protocolMappers` for a client that has any and no such key for a client with none, so one request gives clients, markers, mappers and secrets. `GET /users/{id}/credentials` returns `[]` for a user with no password. A service-account client has no mappers that Keycloak added, before or after its first token (item 28 and 30 are repeated through `plan`).

`apply --file F` runs as follows:

1. Check the flags. `--adopt` and `--allow-delete` are invalid with a users file (`flag_not_valid`). Check that `audit_path` is set (exit 2, `audit_required`).
2. Check the file (`plan` step 1) and the `secrets_dir` path (`unsafe_path`, with no directory created). For an existing `secrets_dir` or secrets file, check the mode (`unsafe_file_mode`) and the `server` (`secrets_server_mismatch`). Both exit 2. Nothing is written in this step. A bad file or a bad path exits 2 here, before the lock.
3. Open the audit file for append (`audit_failed`). Nothing is written to it yet.
4. Create `secrets_dir` if it is missing, then acquire the lock, `kc-axi.lock` in `secrets_dir`. A lock held by another run exits 1, `locked`. The lock is an OS advisory lock. It ends with the process, so no stale lock remains. The lock is taken before the first read (criterion 67).
5. Run `plan` steps 2 to 5 under the lock. The plan that `apply` uses is this plan.
6. Run preflight. Refuse before the first write when any of these is true. List each refusal in `refusals`. The list order below is the order of the top-level `code` (section 4.3):
   - `needs_adopt`, `owner_conflict`, `allow_delete_required`, `allow_remote_required`, `secrets_mismatch`, `secrets_missing`, each without the flag that lifts it;
   - `reenable_refused` (section 5.9);
   - `id_conflict`, including a declared `username` that differs from the stored `username` of the same `id`;
   - `email_duplicate`, for a users file only;
   - `secrets_unreadable`, for a secrets file that exists and cannot be parsed (section 5.8). A missing file is not a refusal. Section 3.5 gives the rule per command;
   - `temporary_password_missing`, for a user to be created whose variable is not set;
   - `realm_absent`, for a users file whose realm does not exist;
   - `not_found`, for a mapper whose target client is neither declared nor live.

   A changed plan hash with `--expect` gives `plan_changed`, and it is not in `refusals`. `audit_failed` is not in this list: step 3 raises it before the lock. `generation_pending` is not a refusal of `apply`: a `pending` generation is finished by the `finish_pending` row (section 5.8).
7. When there are no actions, print `status: already` and exit 0. This holds with or without `--yes`.
8. When there are actions and no `--yes`, print the preview of section 4.3 and exit 1, `confirm_required`.
9. Run the actions in this order. Each action writes its `intent` record before the change (section 3.3):
   1. Secrets: `finish_pending`, one row per client (section 5.8). Each row writes one `secret` intent and result pair.
   2. Realm: `create` or `change`.
   3. Client: `create` (section 5.8 gives the secret rule), then `adopt` and `change`.
   4. Mappers, after their target client exists.
   5. Users (section below).
   6. Removals: mappers, then clients.

   The pending generation is marked `active` once, after the last action that uses one of its values (section 5.8).
10. Stop at the first failure. Exit 1 with `apply_partial`. The error object gives `applied`, `pending`, `cause` and `created`. Running `apply` again finishes the job.
11. Print `applied: N`. Exit 0.

**Writes that time out.** A write whose response does not arrive in time has an unknown outcome. The tool does not retry it. The run stops with `apply_partial`, and the action counts as `pending`. A re-run reads the live state before it decides, so it does not repeat a finished change.

**Users file.** `apply` follows the same steps, with these differences:

- It never removes a user. A user absent from the file is left alone. A user with `enabled: false` is disabled.
- `--adopt` and `--allow-delete` exit 2, `flag_not_valid`.
- A user is created with `POST /admin/realms/{realm}/partialImport` and `ifResourceExists: SKIP`. The plain create endpoint ignores the `id`, which would break the stored `sub` (section 11). After the call, the tool reads the user back and compares the `id`. A difference stops the run with `apply_partial`, `cause: id_conflict`.
- Every `id` in the file is checked against the server in preflight (`id_conflict`). A username with another `id`, or an `id` with another username, stops the run before any write.
- An existing user is changed with `PUT /admin/realms/{realm}/users/{id}`. Only the declared fields that differ are sent. The tool never uses `partialImport` with `OVERWRITE`. `OVERWRITE` replaces the whole user and drops fields (section 11).
- A declared `username` that differs from the stored one for the same `id` is refused in preflight (`id_conflict`). Keycloak also refuses the change, and the tool does not send it.
- A new user gets the required action `UPDATE_PASSWORD`. The tool sends `requiredActions: ["UPDATE_PASSWORD"]` in the create call. The flag `temporary: true` on a credential does not set the action (section 11, item 22). When `temporary_password_env` names a variable, the tool sends its value as a temporary password credential in the same `partialImport` call. Live check, 2026-10-27: this sets a password on a new user, and it keeps the `id` (section 11, item 22). The variable must be set. Preflight checks it for a user that is created. An unset variable exits 1, `temporary_password_missing`, before any change. A user with no `temporary_password_env` is created with `UPDATE_PASSWORD` and no password. Such a user has no password until an operator runs `reset-password`. `plan` does not list such a user under `password_missing`, because the file names no variable.
- `apply` never writes a credential to an existing user. A user with no password is repaired by `reset-password` (section 5.11).
- A users file for a realm that does not exist exits 1, `realm_absent`. Run `apply` on the config file first.

**Run order for a new realm.** Run `up`. Then run `apply` on the config file, which creates the realm and the clients and writes their first secret values. Then run `apply` on the users file, which creates the users. Then run `secrets list` to check the generations. The `secrets capture`, `rotate` and `restore` commands are for later changes.

### 5.7 `export-realm`

1. Refuse the `admin_realm` (exit 2, `admin_realm_refused`). Refuse `--scope config` without an owner (exit 2, `owner_required`).
2. Run every check before the first write:
   - the output path, which exits 2, `unsafe_path`, when it lies inside a git work tree;
   - the output path, which exits 1, `confirm_required`, when the file exists and `--yes` is absent;
   - the secrets directory, when `--capture-secrets` is set;
   - the lock, when `--capture-secrets` is set.
3. Read the live state. Write only the fields of section 3.4, so an unknown field never reaches the file.
4. Write one file to `--out`. `--scope config` writes the config file. The `owner` key holds the value of `--owner`. The file holds only the clients whose marker equals that owner.
5. Skip the built-in clients and all service-account users. Skip hand-made clients too (clients without a marker, or with another owner's marker). The output states the count as `skipped: N`. A skipped client is not in the file, so `plan` on the same server exits 0 (criterion 19).
6. With `--include-unmanaged`, write the hand-made clients too, with `secret_managed` unset. Then `plan` lists them under `unmanaged`, and `apply --adopt` takes them over. The output states the count as `unmanaged_included`.
7. Check the written text against each known secret value. Known values are the admin password and each client secret read for `--capture-secrets`. A match deletes the output file and exits 1, `secret_in_export`.
8. With `--capture-secrets`, record each confidential client's current secret as a new generation in the secrets file. Set `secret_managed: true` for that client in the written config file. This writes the secrets file, and it needs `--yes`.
9. `--scope users` writes the users file to `--out`. The output path must lie outside any git work tree (`unsafe_path`). The file gets owner-only permissions on Linux and macOS.

Export a whole realm with two calls, one for each scope, and two output paths. `--scope full` writes the whole realm in one file instead (section 5.12).

### 5.8 Secrets

**The file format is the interface.** A consumer reads the secrets file in the format of section 3.5. A consumer follows these rules:

1. On Linux and macOS, check that the file is owner-only (`unsafe_file_mode`). Skip the check on Windows.
2. Parse the JSON. A missing or unparsable file is `secrets_unreadable`.
3. Compare `server` with the normalised `base_url` that the consumer expects. A difference is `secrets_server_mismatch`.
4. Read `active`, then the generation with that number. Its `state` must be `active`. A `pending` state is `generation_pending`. The consumer must **not start** while a generation is `pending`.
5. Read the value of the client in that generation. A client with no entry is `secrets_missing`.
6. Never print or log the value. Pass it to the one service that needs it, in that service's environment.

The reader needs no lock. Reads do not change the file.

**Reference reader.** The Python package ships `read_secret(secrets_dir, realm, base_url, client) -> str`. It follows the rules above. It raises `KcAxiError`, which has a `code` attribute. The codes are `secrets_unreadable`, `unsafe_file_mode`, `secrets_server_mismatch`, `secrets_missing` and `generation_pending`. These are the codes of section 4.4. The reader prints nothing. Other languages implement the same rules without this function.

**Launcher.** This library ships no launcher. A launcher or a deployment script reads a value with the reader. It passes the value to one service, in that service's environment. Other processes do not read the file. Any process that runs as the same operating-system user can still read the file. Section 9 gives the rule for sandboxed agents.

**Create path.** When `apply` creates a `secret_managed` client, it uses this order. Each step is durable before the next step runs.

1. Choose the value:
   - If the file holds an `active` value for the client, use it. This covers a rebuilt realm. No new generation is written (criterion 62).
   - If the file holds a `pending` value for the client, use it.
   - Otherwise generate a new value.
2. If the value is new, write a `pending` generation to the file. Use fsync, then rename.
3. Create the client with that value in the create call.
4. Mark the generation `active`.

A crash after step 2 leaves a `pending` value. The next `apply` finds the client absent, and creates it with the pending value (criterion 41). A crash after step 3 leaves a live client whose value is in the file. Nothing is lost.

**Pending generations.** A `pending` generation is finished by the next `apply` or `rotate`. `plan` shows one `finish_pending` row for each live `secret_managed` client of the generation, in one of two cases. Each row holds the two fingerprints, so it enters `plan_hash`. `apply` runs these rows first (section 5.6, step 9.1):

- The live secret equals the pending value. The change reached Keycloak. `apply` writes nothing to Keycloak. It marks the generation `active` after its last action that uses one of its values.
- The live secret equals the active value. The change did not reach Keycloak. `apply` sets the pending value on Keycloak, then marks the generation `active` the same way.

Each `finish_pending` row writes one audit `secret` intent record and one result record. `apply` without `--yes` shows the rows in the preview and changes nothing. A live secret that equals neither value gives a `secret` row, and `apply` refuses it with `secrets_mismatch` (section 5.6, step 6).

A `secrets` write exits 1, `generation_pending`, while a pending generation exists. The operator finishes the pending change with `apply`.

**Window after a Keycloak change.** A crash after the Keycloak change leaves the file one step behind. The `active` mark is the missing step. Until the next `apply` finishes the change, a consumer that reads the file finds `pending`, and it must not start. The owner accepted this window (section 11).

**Live client, no value in the file.** The tool does not overwrite a live secret that it does not know. `apply` refuses with `secrets_missing` in preflight. The two recovery paths are:

- `secrets capture --realm R --client C --yes`. It reads the live value and records it as a new generation. Consumers keep working.
- `secrets rotate --file F --client C --yes`. It writes a new value and applies it. Every consumer of that client must receive the new value.

**Adopting a client with a live secret.** `apply --adopt` captures the live value as a new generation, then manages the client. `--adopt` lifts `secrets_missing` for that client only. The live value is not overwritten. `plan` shows `adopt` with the detail `secret: capture`.

**Stale generation.** The live secret of a `secret_managed` client can differ from its active value. In that case, `apply` refuses in preflight with `secrets_mismatch` (exit 1). Nothing changes. The help line names the two recoveries:

- `secrets capture`, when the live value is right.
- `secrets rotate` or `secrets restore N`, when the file is right.

This case covers a rotation on another machine, a restored backup, or an unfinished pending change.

**`secrets rotate --file F [--client C]`** writes a new generation and applies it. `--file` gives the set of declared clients. `--client` limits the rotation to one declared client. Every other `secret_managed` client keeps its active value in the new generation. A client not declared in the file exits 2, `not_found`.

**`secrets capture --realm R --client C`** reads the live value of one client, and records it as a new generation. It takes no `--file`.

**`secrets restore N`** copies the values of generation N as a new generation, and applies them. A client absent from generation N keeps its active value. History is never edited. If N was never written, exit 1, `generation_unknown`. If N was deleted by `prune`, exit 1, `generation_pruned`.

**`secrets prune [--keep N]`** deletes the oldest `retired` generations. It keeps the newest N retired generations. The `active` and `pending` generations are never deleted. Without `--keep`, the value of `keep_generations` (default 5) applies. `rotate` and `restore` never prune.

**Client removed, or changed to `secret_managed: false`.** The entries stay in the generations that hold them. `apply` does not delete secret entries. `prune` removes them when their generation is removed.

**Consumer impact.** A rotated or restored value breaks each consumer that has not received it. The consumer must restart with the new value. Rotate one client at a time, and restart its consumers before the next change.

**Writes need the lock** (section 5.6). Every `secrets` write takes it. So do `disable-*`, `up`, `down`, `reset-password` and `export-realm --capture-secrets`.

**Fingerprints** are labels. Compare them only with values that the tool wrote.

Every `secrets` command takes `--realm` (or `default_realm`). It finds the file of that realm inside `secrets_dir`.

### 5.9 `disable-user` and `disable-client`

`disable-user USERNAME` runs as follows:

1. Check the flags and `audit_path` (exit 2, `audit_required`). Acquire the lock.
2. Run the audit preflight (`audit_failed`).
3. Write the `intent` record (section 3.3).
4. Set `enabled: false` with `PUT /admin/realms/{realm}/users/{id}`.
5. Call `POST /admin/realms/{realm}/users/{id}/logout`. This ends the sessions of the user.
6. Write the `result` record.

Live check, 2026-10-27: after the disable, introspection of the access token of the user returned `active: false`. The logout returned HTTP 204. The effect of the logout on refresh tokens is **not tested** (section 11).

`disable-client CLIENTID` runs the same steps. Step 4 uses `PUT /admin/realms/{realm}/clients/{id}`.

Live check, 2026-10-27: after the client was disabled, introspection of its token returned `active: false`. A new token request returned HTTP 401.

Neither command deletes anything.

**The re-enable guard.** `apply` reads the audit file in preflight. For each user or client whose last `disable` or `enable` record is `disable`, `apply` refuses when its file declares `enabled: true`. The refusal code is `reenable_refused`. The refusal applies to users and clients. `apply --allow-reenable` lifts the refusal. When `apply` sets `enabled: true` under that flag, it writes an `enable` record for the object. That record has an intent and a result pair. A missing or unreadable audit file exits 1, `audit_failed`, in preflight. A missing `audit_path` exits 2, `audit_required`. In both cases `apply` stops before any change.

### 5.10 Admin password change

kc-axi does not change the admin password. The operator does this by hand:

1. Sign in to the Keycloak admin console with the current admin password.
2. Change the password of the admin user.
3. Update the password source (the environment variable or `admin_password_file`) to the new value.
4. Run `kc-axi status` to confirm that the server answers and that `version` appears.

`up` never sets the admin password on an existing volume. Keycloak creates the admin user only on a new volume (section 11). A new volume with a new password needs `down --purge --yes`, which deletes the realm data.

### 5.11 `reset-password`

`reset-password USERNAME --file F` sets a temporary password for one existing user. It runs as follows:

1. Check the flags and `audit_path` (exit 2, `audit_required`). Acquire the lock.
2. Read the declared user with that `username` in `F`. The variable named in its `temporary_password_env` supplies the password. An unset variable exits 1, `temporary_password_missing`. A user with no `temporary_password_env` exits 2, `config_missing`, because the command has no value to set.
3. Run the audit preflight. Write the `intent` record.
4. Call `PUT /admin/realms/{realm}/users/{id}/reset-password` with `temporary: true`. Keycloak then requires the user to choose a new password at the next sign-in.
5. Write the `result` record. Print `status: done`.

Live check, 2026-10-27: `reset-password` with `temporary: true` sets the required action `UPDATE_PASSWORD`.

A password set with `partialImport` on an existing user is **not tested** (section 11). The owner decided to test that call first. `reset-password` is the repair path until the test passes.

### 5.12 Full export and import of one realm

A full file holds one realm in one JSON file. It has the realm settings, the clients, the roles, the groups, the users with their password hashes, and the realm signing keys. It is a backup and restore format. It is not a desired-state file, so the rules of section 3.4 do not apply to it. The admin password must still not appear in it (section 5.7, step 7). The file is Keycloak's own realm JSON, so `kc.sh import` also reads it.

Both commands follow the audit order of section 3.3: the `intent` record is written before the first change, and the `result` record after the last one.

**Export.** `export-realm --realm R --scope full --out PATH [--yes]`

1. Refuse the `admin_realm` (exit 2, `admin_realm_refused`). Refuse an `--out` inside a git work tree (exit 2, `unsafe_path`). Check `audit_path` (exit 2, `audit_required`). An existing file without `--yes` exits 1, `confirm_required`. None of these checks changes anything.
2. Take the lock. Run the audit preflight. The container must exist, otherwise the command exits 1, `not_found`. Run `up` first.
3. Write the `intent` record, with the action `export`, before the container stops.
4. Stop the container, if it runs. Run the image of `image` once, as a one-off container `<container>-export` on the data volume of section 5.3.1, with `export --realm R --users realm_file --dir /tmp/kc-axi-export`. The export runs offline, because the admin REST API never returns password hashes. No host path is mounted, and no secret is passed. Copy `R-realm.json` out with the runtime's `cp` into a new owner-only directory under `secrets_dir`, then remove the one-off container, also when a step fails. R must be a plain realm name: letters, digits, `_`, `.` and `-`, and it does not start with `-`. A failed export exits 1, `runtime_failed`.
5. Start the container and wait until it is ready, as in `up`. This runs even when step 4 fails. A start that fails exits with its own error, and nothing is written to `--out`.
6. Check the exported file: it must be JSON, and its `realm` must equal R. The admin password must not appear in it. A match exits 1, `secret_in_export`, and nothing is written to `--out`. Otherwise write the file to `--out` with owner-only permissions on Linux and macOS, then delete the directory of step 4.
7. Write the `result` record and print `status: written`.

**Import.** `import-realm --realm R --file PATH [--yes] [--allow-remote]`

1. Refuse the `admin_realm` (exit 2, `admin_realm_refused`). Check the file: owner-only mode (exit 2, `unsafe_file_mode`); parsed as JSON (exit 2, `import_invalid`); `realm` equal to R (exit 2, `realm_mismatch`); `users` and `clients` present as lists (exit 2, `import_invalid`). Check `audit_path` (exit 2, `audit_required`). Apply the local-scope guard (exit 1, `allow_remote_required`).
2. Without `--yes`, the command exits 1, `confirm_required`, and prints the counts of the file and of the live realm. Nothing changes.
3. Take the lock. Run the audit preflight. When the realm exists, the container must exist, because the backup of step 5 needs it (exit 1, `not_found`).
4. Write the `intent` record, with the action `import`, before any change.
5. When the realm exists, back it up: steps 4 to 6 of the export, with the file written to `secrets_dir` instead of `--out`. The backup is named with R and the UTC time, and is owner-only. A realm that does not exist has no backup. A failed backup exits with its error before the realm is changed.
6. When the realm exists, call `DELETE /admin/realms/{R}`. Then call `POST /admin/realms` with the file. Keycloak restores the users with their password hashes, the clients and the realm signing keys. Sessions and tokens of the old realm end. A failed `DELETE` exits with its own error, and the realm is not replaced.
7. When the `POST` fails after the `DELETE`, and a backup exists, send the backup through the same `POST`. The command then exits 1 with `import_partial`. The error gives `backup` (the path) and `cause` (the code of the failed `POST`). Keycloak has no transactions. When the restore `POST` also fails, the backup file is the only copy of the realm. Without a backup, the `POST` error exits as it is.
8. Write the `result` record and print `status: replaced`. When a step fails, the `intent` record gets the outcome `error` and the typed code.

**Security note.** The full file holds the realm signing private keys and the password hashes, so it is as sensitive as the secrets file. Keep it owner-only and outside git. Section 11, item 30, gives the evidence. The test status of each step is in section 8.

## 6. Configuration

### 6.1 Tool configuration file

The location is, in order: `--config`, `KC_AXI_CONFIG`, then the default for the operating system. The defaults are `$XDG_CONFIG_HOME/kc-axi/config.yaml` or `~/.config/kc-axi/config.yaml` on Linux, `~/Library/Application Support/kc-axi/config.yaml` on macOS, and `%APPDATA%\kc-axi\config.yaml` on Windows. The tool does not read a file in the working directory.

When no file exists, a command that needs a value that no flag, variable or key supplies exits 2, `config_missing`. The help line names the value. `status`, `--version` and the no-argument view run without a file.

```yaml
schema_version: 1
base_url: "http://127.0.0.1:8080"
hostname: ""                       # KC_HOSTNAME; empty means the host of base_url
admin_realm: "master"              # up requires master
default_realm: ""                  # used when --realm is absent
admin_user: "admin"
admin_password_file: ""            # empty means only KC_ADMIN_PASSWORD is used
runtime: auto                      # auto | docker | podman
container_name: "keycloak-dev"
image: ""                          # required for up; fully qualified; no latest
port: 8080                         # must equal the port of base_url
volume: "keycloak-dev-data"        # named volume; empty means no persistence
volume_options: ""                 # host path only, for example "Z"; never added by default
java_opts: ""                      # passed as JAVA_OPTS_APPEND; empty means none
ca_file: ""                        # CA bundle for an https base_url; empty means the system store
ready_timeout_seconds: 120
request_timeout_seconds: 10
command_timeout_seconds: 600       # total time for plan, apply, export-realm, reset-password and secrets writes
runtime_timeout_seconds: 30
pull_timeout_seconds: 600
default_limit: 20
max_cell_chars: 200
audit_path: ""                     # required by every write command (exit 2, audit_required)
secrets_dir: ""                    # empty means the kc-axi/secrets folder of the user configuration directory
keep_generations: 5
```

The `owner` key is not a tool configuration key. It belongs to the config file only (section 3.4). A value given here exits 2, `unknown_field`.

Environment variables override the file. They are `KC_AXI_BASE_URL`, `KC_AXI_RUNTIME`, `KC_AXI_REALM`, `KC_ADMIN_USER`, `KC_ADMIN_PASSWORD`, `KC_AXI_CONFIG`, `KC_AXI_AUDIT_PATH` and `KC_AXI_SECRETS_DIR`.

### 6.2 Timeouts

| Key | Default | Used by |
|-----|---------|---------|
| `request_timeout_seconds` | 10 | Every Keycloak request |
| `command_timeout_seconds` | 600 | The whole of `plan`, `apply`, `export-realm`, `reset-password` and the `secrets` writes. When it passes, `plan` exits 1 with `keycloak_timeout`, and `apply` exits 1 with `apply_partial` |
| `ready_timeout_seconds` | 120 | Readiness poll of `up` |
| `runtime_timeout_seconds` | 30 | Every runtime call except `run` |
| `pull_timeout_seconds` | 600 | The image pull inside `run` |
| 2 seconds | fixed | The probe of `status` |

The worst case for `up` is the pull, plus the readiness wait, plus the runtime calls and one login. With the defaults, `up` can take 600 + 120 seconds, plus up to 30 seconds for each runtime call. A caller that runs `up` as a subprocess must allow that time.

## 7. Failure Modes

| Condition | Behaviour |
|-----------|-----------|
| Keycloak not reachable | Exit 1, `keycloak_unreachable`, within `request_timeout_seconds`. `status` exits 0 and reports `server: down` |
| Wrong admin credentials | Exit 1, `auth_failed` |
| Admin credential missing (no source) | Exit 2, `credential_missing`, before any request |
| Image ignores `KC_BOOTSTRAP_ADMIN_*`, or the volume holds an older admin user | `up` ends with `auth_failed` after the readiness poll. The message names both causes |
| Container killed for memory (exit 137, `OOMKilled`) | `up` exits 1, `container_exited`, with `oom_killed: true`. The help line suggests `java_opts`, and states the 4 GiB engine minimum. `status` reports it later |
| Container stopped during `up` for another reason | Exit 1, `container_exited`, with the state |
| Runtime missing, or Podman machine stopped | Exit 1, `runtime_missing`. Help line: `podman machine start` |
| Neither Docker nor Podman installed | Exit 1, `runtime_missing` for `up`, `down --purge` and `status`. Plain `down` with `runtime: auto` exits 0, `already_absent`. Plain `down` with a named runtime exits 1, `runtime_missing` |
| Both installed, container not found | `up` exits 1, `runtime_ambiguous`. `down` exits 0. `down --purge` exits 1, `runtime_ambiguous`. `status` reports `missing` and exits 0 |
| Both runtimes hold the container | Every command exits 1, `runtime_ambiguous`. `status` exits 1 |
| Container in an unhandled state (for example `paused`, `restarting`, `dead`, `configured`, `stopping`, `removing`) | Exit 1, `container_state`, with the state. Help line: `kc-axi status` |
| Container exists but stopped | `up` starts it. `status` reports `stopped` |
| Existing container differs from the configuration | `up` does not change it. It adds a warning when `hostname` differs. `status` shows the image, port, `hostname` and issuer |
| Port already in use | Exit 1, `port_in_use`, with the runtime's message |
| Image name short, or tag `latest` | Exit 2, `image_invalid` |
| `base_url` is not local and uses `http` | Exit 2, `insecure_url` |
| Write to a `base_url` that is not local, without `--allow-remote` | Exit 1, `allow_remote_required`, in preflight |
| Write command with no `audit_path` | Exit 2, `audit_required`, before any change |
| Audit file not writable | Exit 1, `audit_failed`, in preflight. Nothing changed |
| Audit result record cannot be written after a change | Exit 1, `audit_incomplete` |
| Secrets file missing, for a reader, `secrets rotate` or `secrets restore` | Exit 1, `secrets_unreadable`. Nothing changed |
| Secrets file present but unreadable or unparsable | Exit 1, `secrets_unreadable`, in preflight. Nothing changed |
| Secrets file readable by others (Linux, macOS) | Exit 2, `unsafe_file_mode` |
| Secrets file for another server | Exit 2, `secrets_server_mismatch` |
| `secrets_dir`, users file or export path inside a git work tree | Exit 2, `unsafe_path`, before any write |
| Live `secret_managed` client, no value in the file | Exit 1, `secrets_missing`, in preflight. Recovery in section 5.8 |
| Live secret differs from the active generation | Exit 1, `secrets_mismatch`, in preflight. Nothing changed |
| A `pending` generation exists during a `secrets` write | Exit 1, `generation_pending`. Run `apply` to finish it |
| Consumer reads a `pending` generation | The reader raises `generation_pending`. The consumer must not start (section 5.8) |
| `secrets restore N` with an unknown N | Exit 1, `generation_unknown` |
| Unknown `schema_version` | Read N and N-1. A newer version exits 2, `schema_unsupported` |
| Unknown field in a desired-state file | Exit 2, `unknown_field` |
| Duplicate key in a desired-state file | Exit 2, `duplicate_key` |
| `id` that is not a UUID | Exit 2, `id_invalid` |
| `--realm` differs from the realm in a file | Exit 2, `realm_mismatch` |
| Declared built-in client | Exit 2, `builtin_client` |
| `secret_managed` on a public client, or `pkce` on a confidential client | Exit 2, `secret_managed_public` or `config_invalid` |
| Mapper target client neither declared nor live | Exit 1, `not_found`, in preflight |
| Declared client with another owner's marker | Exit 1, `owner_conflict`, in preflight |
| Unset `temporary_password_env` variable for a user to be created, or for `reset-password` | Exit 1, `temporary_password_missing`, in preflight |
| Keycloak returns a field that the tool does not know | Unknown fields are ignored. Only the fields of sections 3.2 and 3.4 are shown |
| `apply` stops partway | Exit 1, `apply_partial`, with `applied`, `pending` and `cause`. Run `apply` again |
| A write times out | Not retried. Exit 1, `apply_partial`, with the action counted as `pending` |
| `--expect` differs from the new plan hash | Exit 1, `plan_changed`. Nothing changed |
| Keycloak rejects a request | Exit 1, `keycloak_rejected`, with the field name and Keycloak's message after redaction |
| Admin token expires during a run | One login and one repeat of the request (section 5.4). A second failure exits 1, `auth_failed` |
| Another run holds the lock | Exit 1, `locked`. Nothing changed |
| Command runs past `command_timeout_seconds` | `plan` exits 1, `keycloak_timeout`. `apply` exits 1, `apply_partial` |
| Export output would contain a secret value | The output file is deleted. Exit 1, `secret_in_export` |
| Local file cannot be written (for example a full disk) | Exit 1, `file_failed`, with the path in `message` |
| User with no password | `plan` lists it under `password_missing`. `reset-password` repairs it |
| Two users with the same `email`, in the file or live | Exit 1, `email_duplicate`, in preflight. `refusals` lists each refusal |
| Declared user without `email`, `firstName` or `lastName` | `plan` lists it under `profile_incomplete`. `apply` still creates it |
| Server outside 26.x | A warning on stderr. The command runs (section 5.4) |

### Error records

The tool keeps its own typed codes. A consumer that wants one error vocabulary can express them as `error-classifier` (a UMAS library) records. That is a data format, not a dependency. The suggested `recoverability` values are:

| Typed code | Suggested recoverability |
|------------|--------------------------|
| `runtime_missing`, `runtime_failed`, `runtime_timeout`, `port_in_use`, `keycloak_unreachable`, `keycloak_timeout`, `container_exited`, `locked`, `plan_changed`, `apply_partial`, `file_failed` | `transient` |
| `auth_failed`, `credential_missing`, `temporary_password_missing`, `keycloak_rejected`, `id_conflict`, `email_duplicate`, `id_invalid`, `secret_in_export`, `unsafe_file_mode`, `unsafe_path`, `secrets_server_mismatch`, `secrets_mismatch`, `secrets_missing`, `secrets_unreadable`, `generation_pending`, `generation_unknown`, `generation_pruned`, `builtin_client`, `owner_conflict`, `audit_failed`, `audit_incomplete`, `audit_required`, `realm_absent`, `realm_mismatch`, `not_found`, `config_invalid`, `config_missing`, `unknown_field`, `reenable_refused`, `allow_remote_required` | `permanent` until the input, file, credential or flag changes |
| `drift`, `confirm_required` | Not an error. The operator decides whether to apply |

## 8. Acceptance Criteria

Each criterion has a status. A criterion marked `not run` has no test yet. A criterion marked `run on 2026-10-27` has a live check. Criteria that need a Linux or Docker host depend on the release gates in section 11.

The numbers of criteria 1 to 57 are the same as in draft v0.3. Criteria 58 and later are new.

**Connection and reading**

1. `kc-axi clients` with a realm that has no clients prints `status: empty` and `total: 0`, exits 0, and needs no `bash` or `jq`. Status: not run.
2. `kc-axi users` with 21 users prints 20 items. The header reads `shown of total` as `20 of 21`. A `help` line gives the next command. Status: not run.
3. A value with a comma, a space or a quote does not change the counts or the truncation. Status: not run.
4. With Keycloak stopped, every command except `status` exits 1 with `keycloak_unreachable` within `request_timeout_seconds`. `status` exits 0 and reports `server: down`. Status: not run.
5. A wrong admin password exits 1 with `auth_failed`. Status: not run.

**Output and secrets**

6. A write with at least one action and no `--yes` changes nothing. It exits 1 with `confirm_required`. It prints the keys of `plan` as a preview. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
7. No command prints a password, a client secret, a temporary password or a token. This holds with and without `--fields` and `--json`. The list covers `plan`, `apply`, `export-realm`, `reset-password` and `secrets list`. Status: not run.
8. The admin password does not appear in any runtime call argument. It does not appear in any file that the tool writes. The runtime's container record holds the password until `down` (section 5.3). The test checks the arguments and the tool's files only. Status: not run.
9. `up` with no `image`, a short image name, or the tag `latest` exits 2 with `image_invalid`. Status: not run.
10. `up`, `status` and `down` give the same results with Docker and with Podman. Status: not run. Docker is not installed on the check host (section 11, release gate K12).
11. Each acceptance case passes on every platform that section 5.5 marks as verified. Each run states its platform. Linux runs are a separate task (K11). Windows is out of scope for now. Status: partly run on macOS with Podman, for the cases that the live checks cover.

**Container and volumes**

12. With the audit file unwritable, `apply`, `disable-*`, `reset-password`, `up` and `down` refuse in preflight with `audit_failed`, before any change. Status: not run.
13. `up` on a stopped container starts it and prints `started`. `up` on a running container prints `already_running`. `down` with no container exits 0 with `already_absent`. Status: not run.
14. `down --purge` with a host-path `volume` removes nothing from the host. Status: not run.
15. `up` makes no automatic `:Z` or `:U` change to a host path. Status: not run.
16. `up` on a container that stops during readiness exits 1 with `container_exited` within 5 seconds of the state change. It does not wait for the full readiness timeout. Status: not run.
17. A named volume keeps its realm after `down` and `up`. Status: not run. Release gate K11 (section 11).
18. `apply` twice on the same file: the second run changes nothing, prints `status: already`, and exits 0. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).

**Desired state**

19. After `export-realm --scope config --owner X` and `export-realm --scope users`, `plan` on both files against the same server exits 0 with `status: no_change`. Status: not run.
20. `plan` with a changed redirect URI exits 1 with `status: drift`, and names the field. `apply --yes --expect H` then makes `plan` exit 0. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
21. A live value that an action uses changes `plan_hash` when it changes. `apply --expect H` with the old hash refuses with `plan_changed`, and changes nothing. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
22. An unmarked client is listed under `unmanaged`. It is never changed or removed. It does not change `total`, `plan_hash` or the exit code. A declared unmarked client needs `--adopt` for its change. A managed client that the file does not declare is removed only with `--allow-delete`. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
23. A declared built-in client exits 2 with `builtin_client`. Status: passed (task I6, 2026-10-27). The file check exits 2 before any request.
24. A field that the file does not declare keeps its server value after `apply`. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
25. A users file with an `id` used by another username exits 1 with `id_conflict`. `id_conflict` is also the first entry of `refusals`. No change happens. Status: `plan` half passed (task I6, 2026-10-27): an `id_conflict` row. The `apply` refusal needs I7.
26. A user that already exists is not changed by `partialImport` (`SKIP`). The stored `id` is read back and compared. Status: not run.
27. `apply` of a users file to a `base_url` that is not local, without `--allow-remote`, exits 1 with `allow_remote_required`. No change happens. Status: not run.
28. `apply` of a config file to a `base_url` that is not local, without `--allow-remote`, exits 1 with `allow_remote_required`. No change happens. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
29. `apply` of a users file with `--adopt` or `--allow-delete` exits 2 with `flag_not_valid`. Status: not run.
30. A users file creates a user. A second run changes nothing. Status: not run.
31. A new user whose `temporary_password_env` names an unset variable exits 1 with `temporary_password_missing`, which is also the first entry of `refusals`, before any change. A new user with no `temporary_password_env` is created with `UPDATE_PASSWORD` and no password. Status: not run.
32. A users file for a realm that does not exist exits 1 with `realm_absent`, before any change. Status: not run.
33. Two owners with separate config files do not remove each other's clients. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
34. A mapper is created after its target client. A mapper removed from a client with a `mappers` key is removed only with `--allow-delete`. A client with no `mappers` key keeps its mappers. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
35. A token of `svc-reports` has `acme-api` in its `aud` claim, in the access token and in the introspection response. The check is membership, because `aud` is a string for a user token and a list for a service token. Status: partly run on 2026-10-27 (section 11, item 18).
36. The `iss` of a token from `localhost` equals the `iss` of a token from `127.0.0.1` when `hostname` is set. Status: run on 2026-10-27 (section 11, item 19).
37. A first `apply` with a `secret_managed` client and no secrets file creates the file. The file holds the value as `pending` before the client create, and then as `active`. On Linux and macOS, the file is owner-only. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
38. A live `secret_managed` client with no value in the file exits 1 with `secrets_missing` in preflight, and changes nothing. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
39. `secrets capture` records the live value. A consumer that reads the secret gets the same value. The live value does not change. Status: not run.
40. `secrets rotate` gives a new fingerprint. The old generation becomes `retired`. `secrets restore` brings the old value back as a new generation. Status: not run.
41. `apply` is killed after the `pending` write and before the client create. The next `apply` uses the pending value. It writes no second value. This test needs the fault-injection seam of section 11. Status: not run.
42. A client secret in a fixture realm never appears in the exported files, the audit file or any command output. The test-suite gate K16 runs this check once the tool exists (section 11). Status: not run.
43. A secrets file for another `base_url` exits 2 with `secrets_server_mismatch`, for the CLI and for the reader. Status: not run.
44. `secrets prune` deletes only `retired` generations. The `active` and `pending` generations stay. Status: not run.
45. The `secrets` commands take `--realm`. Two realms on one server have two files in `secrets_dir`. Status: not run.

**Users and disable**

46. `disable-user` disables the user. The user's access token is inactive at once (`active: false`). Status: run on 2026-10-27 (section 11, item 19).
47. After `disable-user`, `apply` of a users file that declares `enabled: true` refuses with `reenable_refused`, in preflight. `apply --allow-reenable` lifts the refusal and writes an `enable` record. Status: not run.
48. `disable-client` makes new token requests fail with HTTP 401. Status: run on 2026-10-27 (section 11, item 20). The `apply` guard for clients is criterion 77.
49. `disable-user`, `disable-client` and `reset-password` without `audit_path` exit 2 with `audit_required`. Status: not run.
50. A password set with `reset-password` and `temporary: true` makes the user set a new password at the next sign-in. Status: partly run on 2026-10-27 (section 11, item 15). The required action `UPDATE_PASSWORD` is set.

**Output and CLI**

51. The no-argument view runs with no network and no runtime. It prints `bin` and `description`. Status: not run.
52. `kc-axi --version` prints the version and reads no file. Status: not run.
53. An unknown flag exits 2 with `flag_not_valid` and lists the valid flags. Status: not run.
54. The JSON output of each command has `schema_version` and the keys of section 4.3. Status: not run.
55. Every typed code of section 4.4 appears in at least one test with its exit code. Status: not run.
56. A write that is interrupted while the audit `result` record is written exits 1 with `audit_incomplete`. This test needs the fault-injection seam of section 11. Status: not run.

**Independence**

57. No file of this library names a consuming project outside section 9. A test reads a list of names from a file outside this library. It searches this file for each name, outside section 9. Status: not run.

**New criteria**

58. `reset-password` on a user with no password sets a temporary password. The audit file holds one `intent` record and one `result` record. Status: not run.
59. The `sub` claim of a user token equals the `id` that the users file declares for that user. Status: partly run on 2026-10-27 (section 11, item 27). The tool itself is not built.
60. A token issued to a client without the API audience does not contain the API `clientId` in `aud`. The check is membership. Status: not run.
61. A token has `iss`, `exp`, `iat` and `jti`. `exp` minus `iat` equals `accessTokenLifespan`. Status: partly run on 2026-10-27. The live token had 900 seconds (section 11, item 18).
62. A rebuilt realm has a `secret_managed` client with an `active` value in the file. `apply` creates the client with that value. The secret is the same after `apply`, and no new generation is written. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
63. A stale generation (the live secret differs from the active value) exits 1 with `secrets_mismatch`, and changes nothing. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
64. `status` exits 1 with `runtime_ambiguous` when both runtimes hold the container. `status` exits 0 when the server does not answer. Status: not run.
65. A command that needs a value that no flag, variable or key supplies exits 2 with `config_missing`. The message names the value. Status: not run.
66. A declared client with another owner's marker exits 1 with `owner_conflict` in preflight, and changes nothing. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
67. The lock is taken before the first read of `plan` in `apply`. A second `apply` that starts while the first holds the lock exits 1 with `locked`. Status: not run.
68. A realm whose only clients are built-in clients, and whose config file declares no clients, returns `status: no_change` with exit 0. Status: passed (task I6, 2026-10-27), on a fake server and on Keycloak 26.6.4.
69. A `secrets_dir` inside a git work tree exits 2 with `unsafe_path` before any write. An export to a users-file path inside a git work tree exits 2 with `unsafe_path` before any file is written. Status: not run.
70. An `apply` in which the second action fails exits 1 with `apply_partial`. The error object gives `applied: 1` and the cause. A re-run finishes the job. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
71. A write that times out is not retried. It is counted as `pending`, and the command exits 1 with `apply_partial`. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
72. A server outside 26.x makes the command print a warning on stderr, and the command runs. Status: not run.
73. A `pending` generation is finished by the next `apply`, in each of the three cases of section 5.8. Status: not run. The cases need the fault-injection seam of section 11.
74. `export-realm` writes no hand-made clients by default. With `--include-unmanaged`, it writes them, and `plan` lists them under `unmanaged`. `apply --adopt` then takes them over. Status: not run.
75. The reader follows the rules of section 5.8. A missing file raises `secrets_unreadable`. A `pending` generation raises `generation_pending`. A client with no entry raises `secrets_missing`. The reader prints nothing. Status: not run.
76. `apply` without `audit_path` exits 2 with `audit_required` before the lock is taken. Status: not run.
77. After `disable-client`, `apply` of a config file that declares `enabled: true` refuses with `reenable_refused`. `apply --allow-reenable` lifts the refusal and writes an `enable` record. Status: passed against a fake Keycloak (task I7, 2026-10-27, `tests/test_apply.py`). Not run against a real Keycloak (task I13).
78. `apply` of a users file never deletes a user, even when the file omits the user. Status: not run.
79. A new user with a set `temporary_password_env` gets a password credential and the action `UPDATE_PASSWORD` from the create call. The tool sends the action in `requiredActions`. The stored `id` equals the declared `id`. `apply` on an existing user with no password changes no credential. Status: partly run on 2026-10-27 (section 11, item 22). The tool itself is not built.
80. A users file with two users that have the same `email` exits 1 with `email_duplicate`. `email_duplicate` is also the first entry of `refusals`. No change happens. A declared `email` that a live user with another `id` holds is refused the same way. Status: not run (section 11, item 38). The 500 itself was seen live on 2026-10-27.
81. `plan` lists a declared user without `email`, `firstName` or `lastName` under `profile_incomplete`, and names the missing fields. The list does not change `total`, `plan_hash` or the exit code. `apply` still creates the user. Status: `plan` half passed (task I6, 2026-10-27, section 11, item 38). The `apply` half needs I7.
82. Plain `down` with `runtime: auto` and neither program installed exits 0, `already_absent`. Plain `down` with `--runtime docker` or `--runtime podman` and that program missing exits 1, `runtime_missing`. Status: passed with stub runtimes on 2026-10-27 (task I4).
83. `down --purge --yes` with both runtimes installed and neither holding the container exits 1, `runtime_ambiguous`. No volume is removed. Status: passed with stub runtimes on 2026-10-27 (task I4).
84. `export-realm --realm R --scope full --out PATH --yes` writes one JSON file with the realm, its clients, roles, groups, users and password hashes. The file's `realm` equals R, and the admin password does not appear in it. Status: passed through the tool on 2026-11-01 (Keycloak 26.6.4, throw-away server): the file held 2 users with argon2 hashes, 7 clients and the signing keys, and the admin password did not appear in it.
85. The full export refuses an `--out` inside a git work tree with `unsafe_path`, before the container stops. Status: not run.
86. When the runtime export fails, the full export starts the container again and exits 1, `runtime_failed`. Status: not run.
87. `import-realm` replaces the realm. After it, the users and clients of the file exist, a user absent from the file is gone, and each user signs in with the password it had before the export. Status: passed through the tool on 2026-11-01. A user added after the export (`bob`) was gone after the replace, an email changed after the export was back, and alice and john signed in with their old passwords. A wrong password was refused.
88. `import-realm` with a file whose `realm` differs from `--realm` exits 2 with `realm_mismatch`. Nothing changes. Status: passed through the tool on 2026-11-01 (exit 2, nothing sent).
89. `import-realm` writes the backup before the delete. A failed backup exits 1 and the realm is unchanged. Status: passed through the tool on 2026-11-01. The backup file was written with mode 0600 (the order, backup before delete, is covered by a stub test). With an unwritable `secrets_dir` the first live run showed a traceback (an uncaught `PermissionError` from the backup work directory); that is fixed and now exits 1 `file_failed` with the realm unchanged.
90. When the second call of the replace fails, `import-realm` loads the backup and exits 1 with `import_partial`. Status: passed through the tool on 2026-11-01. A file with a duplicate username was rejected by Keycloak after the delete; the reply said `restored: true`, the realm had its two users, its client secret and the same signing key ids again.
91. After a replace, the realm keeps the signing keys of the file. The signing certificate in the file is the one the restored server publishes at its JWKS endpoint. Status: passed through the tool on 2026-11-01 for the key ids (the same two signing key ids before and after the replace). The JWKS certificate was checked by hand on the same date.
92. A confidential client's secret in the file is the same after the replace. Status: passed through the tool on 2026-11-01. The live secret was changed to another value after the export, and the replace set it back to the value in the file.

## 9. Known Consumers

> This section names known consuming projects. The library does not depend on any of them.

| Consumer need | Mapping |
|---------------|---------|
| Identity provider for people (OIDC) | Keycloak, started by `up` for development. A production deployment is a later phase |
| One realm for the system | `apply --file <realm>.config.yaml`. The realm name and the clients are in that file, not in this library |
| API client (resource server) | A confidential client (`secret_managed: true`). The API introspects each token with it |
| Service principals | One `secret_managed` client for each service, with `serviceAccountsEnabled: true`. The stable key of a principal is `clientId`. The token `azp` equals it. A rename creates a new principal. The launcher reads the value with the reader (section 5.8) and passes it to that service only |
| First admin user | A users file with one user. The operator generates its `id`. The consumer keeps that `id` as the Keycloak `sub` |
| Existing admin | `get user <username> --fields id` returns the `id`, so a re-run finds the same user |
| Roles and bindings | Not in Keycloak. They live in the consumer's data. The API reads the token claims `sub`, `iss`, `aud`, `iat`, `exp`, `jti` and `azp` |
| Who can run it | An operator, or an agent that acts for the operator, for set-up and maintenance. Runtime agents of the consumer never use it. The command must not be reachable from a sandbox that runs untrusted agent code |
| Removal of a service | The operator sets `enabled: false` in the config file, then runs `apply`. `apply` never deletes a client without `--allow-delete` |
| Emergency stop | `disable-user` and `disable-client`, with the audit file. A disabled identity stays disabled on later `apply` runs, unless `--allow-reenable` is given |
| Audit of identity changes | `audit_path`, a file that the consumer can ingest into `event-log` (a UMAS library) |
| Pinned image | The consumer records the Keycloak image tag in one place and passes it as `image` |
| Keeping files out of git | The consumer adds the users file and the secrets directory to its ignore rules. This library never edits `.gitignore` |
| Keycloak restart and rebuild | A rebuilt realm has new signing keys. A consumer that caches the JWKS refreshes it after a rebuild |

See `umas/TECHNICAL-DESIGN-SPEC.md` Appendix A.5.6 to A.5.9 in agentzero-v2-dev for the RBAC decisions that this table serves.

## 10. Source Material and Deviations

Source material: a proposal for a Bash wrapper over `kcadm.sh`, with a Podman container.

| Deviation | Why |
|-----------|-----|
| Python package instead of a Bash script | The script needs `bash`, `grep`, `tr`, `head` and `echo`. It does not run natively on Windows |
| REST API instead of `exec` into the container for `kcadm.sh` | Removes the container-runtime dependency from every admin command. Works against a remote Keycloak. Avoids path and quoting problems |
| Docker and Podman both supported, never guessed | The two keep separate container stores. Guessing could act on the wrong one |
| Admin credentials from the environment or a file | A password typed into a command or a script ends up in git and in agent transcripts |
| Admin password passed as `-e NAME` with no value | A value in the command line would show in the process list |
| No default image tag, fully qualified name | A tag such as `latest` changes behaviour between runs. A short name can make the runtime ask for a registry |
| JSON parsing instead of text tools | Text parsing breaks on commas, spaces and nested objects, and it cuts by line, not by item |
| Desired state (`plan`, `apply`) instead of one-off create commands | One-off writes cause drift that nobody sees. A file in a repository is reviewed like code. `apply` repeats safely |
| Users in a separate file | A users file holds personal data. It stays out of git. The config file holds none |
| A secrets directory with generations | A rebuilt realm needs the same client secrets. Local generations allow a rollback without putting secrets in git |
| Exit codes 0, 1 and 2 with typed codes | Follows the library rule in `libs/README.md` in agentzero-v2-dev. Callers branch on the typed code, which is in the output |
| `plan` exits 1 with `status: drift` | The library rule says a judging command exits 1 when the verdict is not a pass. Callers also read `status` |
| Compact list form, not a second format | The form follows the uniform-array shape described in `libs/README.md` in agentzero-v2-dev. The format is not TOON. The rules of section 4.3 are the contract |
| No `--full` flag | `--fields` adds fields. The `--json` output gives the full value of every field. The rule in `libs/README.md` in agentzero-v2-dev asks for `--full` in the default view. The default view cuts long text at `max_cell_chars`, and `--json` removes the cut. This is a deviation, not a gap |
| Write confirmation, audit and a no-secrets rule | Not in the source material. A tool that changes an identity server needs all three |
| Local scope only | Remote writes need a separate design for trust and TLS. `--allow-remote` is the explicit override |

## 11. Open Questions and Evidence

**Owner decisions (2026-10-27)**

The owner answered each decision below. The task list `docs/tasks-kc-axi-podman-spec.md` records each answer.

1. **Scope.** Local only. A write to a `base_url` that is not local needs `--allow-remote` (section 5.4).
2. **Release gates.** Persistence across a restart (item 9) and Docker (item 11) must pass before the first release. Linux with Podman is a separate task (K11). Windows is out of scope for now.
3. **Admin password.** Changed by hand, then the password source is updated (section 5.10).
4. **Repair of a user with no password.** `reset-password` (section 5.11). `apply` never writes a credential to an existing user.
5. **View format.** The compact list form. The format is not TOON (section 10).
6. **Secret-leak check.** A test in the test suite (criterion 42, gate K16). The criterion stays `not run` until the test exists.
7. **Secret access.** A documented file format (section 5.8). There is no command that prints a secret, and no `secrets exec` or `secrets get` command.
8. **Unmanaged clients.** Informational. They have their own key, `unmanaged`. They are outside `actions`, `total`, `plan_hash` and the exit code.
9. **Client re-enable.** `disable-client` is sticky, as `disable-user` is. `apply` refuses to re-enable either one without `--allow-reenable`.
10. **Down.** `down` needs `--yes` when `volume` is empty.
11. **Password test.** Done 2026-10-27. `partialImport` sets a password on a new user. It sets none on an existing user. `reset-password` is the repair path (section 11, item 22).
12. **Owner location.** The `owner` key is in the config file only.
13. **Export of hand-made clients.** Opt-in with `--include-unmanaged`.
14. **Server version.** A server outside 26.x prints a warning on stderr, and the command runs.
15. **Secrets location.** `secrets_dir` is a directory. Each realm has `<realm>.secrets.json` inside it.
16. **Loopback.** A fixed list of three names: `localhost`, `127.0.0.1` and `::1`. The tool does not resolve names.
17. **Audit guard.** `apply` refuses with exit 2, `audit_required`, when `audit_path` is empty. `enable` is an audit action. The guard covers users and clients.
18. **Secret reader errors.** The reader raises errors that carry the codes of section 4.4.
19. **Partial runs.** The counts `applied`, `pending` and `cause` sit in the error object. `status: partial` does not exist.
20. **Preview.** A write without `--yes` prints the keys of `plan`.
21. **Status exit codes.** `status` exits 1 for `runtime_ambiguous` and `runtime_missing`. It exits 0 when the server does not answer.
22. **Remote guard.** Applies to every write to Keycloak (section 5.4).
23. **Missing configuration.** `config_missing`, exit 2, for any value that no flag or variable supplies.
24. **Owner conflict.** A declared client with another owner's marker exits 1, `owner_conflict`, before any write.
25. **Lock.** Taken before the first read of `plan`. It covers `apply`, `disable-*`, `up`, `down`, `reset-password`, the `secrets` writes, `export-realm --capture-secrets`, and the full export and `import-realm` (section 5.12).
26. **Service principal key.** `clientId`, which equals the token `azp` (section 9).
27. **Crash window.** The owner accepted the window after a Keycloak secret change. Consumers must not start while a generation is `pending`. The next `apply` finishes the job (section 5.8).
28. **Sign-in flow.** Not a decision of this library. The consuming project decides its own sign-in flow.
29. **Memory.** The engine needs 4 GiB. When a container is killed for memory, `up` prints a suggested `java_opts` value. No default heap cap is set (section 5.3).
30. **Full realm file (2026-11-01).** The owner asked for one file that holds a whole realm, with users' password hashes, so the realm can be restored with its passwords. The file holds the realm signing private keys and the password hashes. It is JSON, owner-only, and outside git. The export runs offline, because the admin REST API does not return password hashes: on Keycloak 26.6.4 the users list has no `credentials`. The export and the replace were run through the tool on 2026-11-01 against a throw-away server, with a realm that had two users, a confidential client and the default signing keys (section 8, criteria 84 and 87 to 92). The confidential client secret came back after a replace. The run found one defect: an unwritable `secrets_dir` made the backup step end in a traceback instead of exit 1 `file_failed`. It is fixed and has a test. Section 8 criteria 85 and 86 were not run live. Section 5.12 gives the rules.

**Defaults applied without a separate owner answer.** Each default follows from an owner answer or from the rules above. The owner can narrow any of them.

- Every write command requires `audit_path`, not only `apply` and `disable-*`. This follows the audit-before-change rule.
- `reset-password` takes `--file`. The variable named in `temporary_password_env` is in the users file, so the command needs that file. The owner confirmed this on 2026-10-27.
- The lock file is one file, `kc-axi.lock`, in `secrets_dir`. All writes share it.
- `secrets rotate --client C` covers one declared client. Other clients keep their active values in the new generation.
- A pending change left by an interrupted `rotate` or `restore` is finished by the next `apply` (section 5.8).

**Live facts (2026-10-27)**

The checks ran Keycloak 26.6.4 (`quay.io/keycloak/keycloak:26.6.4`) in rootless Podman 6.1.4 on a macOS arm64 host. The Podman machine runs Linux with SELinux enforcing. Each run used a throw-away container and volume, which were removed afterwards. Docker is not installed on that host.

- Item 6. Keycloak facts.
  - `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD` create the admin user. The older names `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD` also work, with a deprecation warning. This spec uses the new names.
  - Keycloak creates the admin user only on a new data volume. A volume from an earlier run keeps its old admin password.
  - `GET /realms/master` on port 8080 answers HTTP 200 with no extra setting.
  - `/health/ready` on port 9000 answers HTTP 200 only with `KC_HEALTH_ENABLED=true`. Port 9000 is not published, so the readiness path is `/realms/master`.
  - Not checked: the licence, production requirements, and the release that removes the old names.
- Item 8. A user `id` on create.
  - `POST /admin/realms/{realm}/users` with an `id` returns 201 and **ignores** the id.
  - `POST /admin/realms/{realm}/partialImport` with an `id` keeps the id. A realm import with a `users` list keeps it too.
  - Users are created with `partialImport` (section 5.6).
- Item 9. Named volume under rootless Podman, on the Podman machine only. The server started on a new named volume, and the log had no permission error. A later container on the same volume did not create the admin user again, which suggests that the data persisted. A realm created before the restart was not read back. Persistence is **not verified**. Native Linux with rootless Podman is not tested. Native Linux with SELinux and a host path is not tested.
- Item 10. Client attributes, secrets and mappers.
  - A client attribute `kc-axi.managed` is stored and returned. The client marker works.
  - A user attribute `kc-axi.managed` was **not stored**, through `partialImport` or `PUT`. The realm's user profile reported no `unmanagedAttributePolicy`, which is the likely cause. This is not confirmed. Users carry no marker.
  - A client created with a `secret` keeps that secret. `GET .../client-secret` returns the same value.
  - `GET /admin/realms/{realm}/clients` returns the secret in plain text, in the field `secret`. The tool removes it from every output.
  - `POST .../partial-export?exportClients=true` did **not** contain the secret. The check searched for the exact value. This was tested on the Keycloak endpoint, not on the tool's own output. Criterion 42 covers the tool's output, and it is `not run`.
  - An `oidc-audience-mapper` is created with status 201.
  - Service-account users are hidden from the plain user list. `GET .../clients/{id}/service-account-user` returns the user.
  - `PUT /admin/realms/{realm}/clients/{id}` with a new `secret` sets the secret (item 14).
- Item 11. Docker: not installed on the check host. The use of `-e NAME` under Docker is **not verified**.
- Item 13. Memory. The first container was killed by the kernel (exit 137, `OOMKilled=true`) on a Podman machine with 2 GiB of memory. A second container ran stably at about 534 MB with `JAVA_OPTS_APPEND="-Xms256m -Xmx640m"`. The owner decided on a 4 GiB minimum for the engine, with the `java_opts` hint in the help line. No default heap cap is set. Whether the memory command in section 5.0 works on this host is **not verified**.
- Item 14. Setting a client secret on an existing client.
  - `PUT` with the full representation and a new `secret` returns 204. The client-secret endpoint then returns the new value.
  - `PUT` without a `secret` field leaves the secret unchanged.
  - `POST .../client-secret` generates a random value. `secrets rotate` does not use it, because the value comes from the secrets file.
- Item 15. Updating users.
  - `partialImport` with `ifResourceExists: SKIP` leaves an existing user unchanged. It reports `SKIPPED`.
  - `partialImport` with `OVERWRITE` keeps the `id` but **replaces the user**. It lost `firstName` and cleared `requiredActions`. The tool never uses it.
  - `PUT .../users/{id}` with a partial body changes only the fields sent. `{"enabled": false}` disables the user and keeps the email.
  - `PUT` with a different `username` returns 400 `error-user-attribute-read-only`.
  - `reset-password` with `temporary: true` sets the required action `UPDATE_PASSWORD`.
  - `requiredActions` sent in the import are stored.
- Item 16. Users with a permanent credential, and a very large users file: **not tested**. An existing user with no password is repaired by `reset-password` (section 5.11).
- Item 18. Token audience (2026-10-27, Keycloak 26.6.4). With an `oidc-audience-mapper` set to `acme-api`:
  - The client-credentials token of `svc-reports` has `aud: ["acme-api", "account"]` and `azp: svc-reports`. Its `exp - iat` is 900 seconds.
  - The password-grant token of a user has `aud: "acme-api"`.
  - Introspection with the confidential client `acme-api` returns `active: true`, with the `sub`, the `aud` and the `azp`, for both tokens.
  - `GET .../clients/{id}/service-account-user` returns the `id` that is the `sub` of the service token.
- Item 19. Issuer and sessions.
  - Without `hostname`, the issuer follows the host that the client used. A token from `localhost` has `iss` with `localhost`. A token from `127.0.0.1` has `iss` with `127.0.0.1`.
  - With `KC_HOSTNAME=127.0.0.1`, both host names give the same `iss`, `http://127.0.0.1:<port>/realms/<realm>`.
  - After `PUT enabled: false`, introspection returns `active: false` for the user's token.
  - `POST .../users/{id}/logout` returns 204. The effect on refresh tokens is not tested.
  - A login for a disabled user returns HTTP 400.
- Item 20. Client disable and ids.
  - After `PUT enabled: false` on a client, introspection of its token returns `active: false`. A new client-credentials request returns HTTP 401.
  - A client created with an `id` keeps that `id`. `GET` by `clientId` returns it. The check did not cover `down --purge` followed by `up`.

**Open items**

Each item needs a test, a decision, or a release gate.

- Item 2. Windows. Out of scope for now. Its statements stay `verified by reading only`.
- Item 9. Persistence across a restart on native Linux with rootless Podman. Task K11. Required before the first release.
- Item 11. Docker. Task K12. Required before the first release.
- Item 21. Closed 2026-10-27. Live check on Keycloak 26.6.4. The password grant of `admin-cli` on the `master` realm returns HTTP 200. The reply holds a bearer token, `expires_in: 60` and a refresh token. A wrong password returns HTTP 400. The tool must fetch a new token for a run that lasts longer than 60 seconds.
- Item 22. Closed 2026-10-27, corrected the same day. Live check on Keycloak 26.6.4. `partialImport` with a temporary credential sets a password on a **new** user. It keeps the `id`. It does **not** set `UPDATE_PASSWORD`: a user created with `temporary: true` and no `requiredActions` has `requiredActions: []` and signs in at once. The tool must send `requiredActions: ["UPDATE_PASSWORD"]`. With the action sent, the sign-in returns `invalid_grant` ("Account is not fully set up"), which is the expected gate. An earlier version of this item credited the action to the credential flag. The payload of that test had sent the action itself. On an **existing** user with no password, `SKIP` reports `SKIPPED` and sets nothing. So `apply` cannot repair a user with no password. `reset-password` is the repair path. A direct-grant login with the temporary password returns `invalid_grant` ("Account is not fully set up"). That is the expected gate for `UPDATE_PASSWORD`.
- Item 23. Closed 2026-10-27. Live check on Keycloak 26.6.4, public client with direct grants. A refresh token works before `disable-user`. After `PUT enabled: false`, a refresh returns HTTP 400 `invalid_grant` ("User disabled"), without a logout. A new password grant also returns 400. A refresh also returns 400 `invalid_grant` ("Session not active") after a user logout. It returns the same after an admin logout of a disabled user. A disabled user keeps no usable refresh token. The `disable-user` command needs no extra step to cut off refresh tokens.
- Item 24. Native Linux with SELinux and a host path (section 5.3.1). Not tested.
- Item 25. Decided 2026-10-27: the fault-injection seam for criteria 41, 56 and 73 is one test-only environment variable, `KC_AXI_TEST_STOP_AT=<step>`. When set, it stops the run at the named step with `apply_partial` or `audit_incomplete`. It is read only when set. It is documented as test-only. The step names are set when the tool is built. It is not implemented.
- Item 26. Decided 2026-10-27: the minimum Python version is 3.11. The package name is `kc-axi`.
- Item 27. Closed 2026-10-27. Live check on Keycloak 26.6.4. A user created by `partialImport` with a fixed `id` gets a user token whose `sub` equals that `id`. Criterion 59 stays `not run` until the tool exists.
- Item 28. Closed 2026-10-27. Live check on Keycloak 26.6.4. A client with service accounts carries no protocol mappers. This holds after create and after its first token. It also holds after a `PUT` sets `serviceAccountsEnabled` on an existing client. `plan` has no Keycloak-added mapper to ignore.
- Item 29. Memory. The 4 GiB minimum follows from one failure. A preflight memory check was considered and deferred until the Docker test (section 5.3).
- Item 30. Closed 2026-10-27 with item 28. A client created through the REST API with service accounts carries no mappers. Its attributes hold only `realm_client: "false"`. The service-account user is `service-account-<clientId>`.
- Item 31. A colon in a `clientId`. Keycloak accepts it. The tool does not test it.
- Item 32. The sign-in flow of an end-user CLI (section 2). The consuming project decides it. Session and refresh lifespans are not realm fields in this spec (section 3.4).
- Item 33. Windows roaming profile sync of `%APPDATA%`. Verified by reading only.
- Item 34. Audit file size and rotation. None in v1 (section 3.3).
- Item 35. Closed 2026-10-27: the owner confirmed that `reset-password` takes `--file` (section 4.2). The variable name has one source, the users file.
- Item 36. Closed 2026-10-27. The tool creates `secrets_dir` with owner-only mode on first need. This includes the lock file of `up`.
- Item 37. Live result, 2026-10-27, Keycloak 26.6.4. The default user profile requires `email`, `firstName` and `lastName` for the `user` role. A user without them, created by `partialImport` with a password, gets `invalid_grant` ("Account is not fully set up") at sign-in. The cause is the profile, not a required action: `requiredActions` is empty. The same user with the three fields signs in at once.
- Item 38. Decided 2026-10-27: option A. `apply` refuses a duplicate `email` in preflight (exit 1, `email_duplicate`, the first entry of `refusals`; item 41). This covers a duplicate in the file and a duplicate of a live user with another `id`. `plan` lists a declared user without `email`, `firstName` or `lastName` under `profile_incomplete`, as information. `apply` still creates such a user. The finding behind it: a second user with the same `email` makes `partialImport` return HTTP 500 (`NullPointerException` in `UsersPartialImport.getModelId`). The first user is created. Three cases are not tested. An email that differs only in case. A `PUT` that changes an existing user to a used email. A realm whose user profile does not require the three fields. The tool compares emails in lower case, which is a guess about Keycloak's own rule. The realm setting `duplicateEmailsAllowed` is not a field of the users file in v1. The 500 was seen on one server version. The behaviour for an existing user under `SKIP` was not tested.
- Item 39. Decided 2026-10-27, owner answers 1C, 2A and 3A.
  - 1C: plain `down` is idempotent only for `runtime: auto` with nothing installed. A named runtime that is missing exits 1, `runtime_missing` (section 5.2).
  - 2A: `down --purge` with both runtimes and no container exits 1, `runtime_ambiguous`. The operator adds `--runtime` (section 5.2). A wrong guess would delete data that cannot be restored.
  - 3A: no `unsafe_path` check on `audit_path`. The audit file holds no secret. Git can still remove it, and so can `rm` (section 3.3).
  - Defaults accepted with them: a failed intent write is `audit_failed`. Relative paths in `KC_*` variables resolve from the working directory. `KC_HOSTNAME` is a container variable only. The audit file is created with mode 0600. `secrets list` with no file is `status: empty`. A secrets file for another realm is `secrets_unreadable`. `active` points to the pending generation at write time. Generation gaps mean pruned generations, with no `pruned` list. `up` checks the port and the host of `base_url`. `volume_options` needs a host path. `port_in_use` and out-of-memory detection match the runtime's message text, and Podman's wording is **not verified** (task I4, real-runtime check 1).
- Item 40. Decided 2026-10-27: option (a). The pending-generation finish is a `finish_pending` action row in `plan`, with its own entry in `plan_hash`. `apply` runs it first (step 9.1). It writes an audit `secret` intent and result pair. A live secret that equals the pending value needs no Keycloak write. A live secret that equals the active value gets the pending value. A live secret that equals neither gives `secrets_mismatch`. Source: the caller assessment of `apply` for the config file (2026-10-27, `docs/assessments/caller-assessment-kc-axi-apply-config-2026-10-27.md`, blocker B1). Criteria 73 and 41 need the fault-injection seam (item 25) to run.
- Item 41. Decided 2026-10-27: option (a). The top-level `code` of a run with refusals is the code of the first refusal in the order of section 5.6 step 6. Every refusal is in `refusals`. The code `refused` is removed from the registry. Criteria 25, 31 and 80 now name the first refusal. Source: the same assessment (blocker B4).
