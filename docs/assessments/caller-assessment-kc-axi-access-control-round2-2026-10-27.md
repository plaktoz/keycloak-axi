# Caller assessment, round 2, kc-axi spec, by access-control

Date: 2026-10-27
Spec under review: `libs/kc-axi/README.md` (Draft v0.3)
Caller: `umas/modules/access-control/access-control-spec.md` (sections 2, 3.1, 4, 5.3, 5.6, 8, 9, AXI section)
Round 1 report: `docs/assessments/caller-assessment-kc-axi-access-control-2026-10-27.md` (REJECTED: 5 blockers, 16 majors, 14 minors)
Live facts of 2026-10-27 are treated as true. Owner decisions are not raised as gaps. Their application is checked in section 3.

## 1. Verdict

**ACCEPTED WITH OPEN ITEMS.**

No blocker remains. The seed step of `umas init` (start Keycloak, apply the config file, apply the users file with a consumer-generated `id`, then the secrets) can be built against v0.3. All five round 1 blockers are resolved.

Twelve majors remain (N1 to N12). Seven owner decisions are needed (section 4, D1 to D7). The rest are spec edits. Before the caller builds its secret launcher, its emergency-stop path or its re-run test, these must be fixed: N1, N2, N3, N4, N5, N6 and N12.

## 2. Round 1 blocker and major status

| # | Round 1 item | Status | Proof, and what is left |
|---|--------------|--------|--------------------------|
| 1 | Field allow-list (blocker) | Resolved | 3.4 "Realm fields", "Client fields", "Mapper fields", "User fields"; `pkce` example and attribute mapping (3.4 config example); `unknown_field` (3.4 rules). |
| 2 | Config discovery, key list, default realm (blocker) | Resolved | 4.1 (`--config`, `KC_AXI_CONFIG`, OS default); 6.1 (full key list, `default_realm`, `admin_user`, `admin_password_file`); `realm_required` (4.1). |
| 3 | Missing secrets file exits 7 on first run (blocker) | Resolved | Exit 7 is gone. 5.8 "New client, no value in the file"; criterion 37. Left: no sentence says an absent file is created on first write (m8). |
| 4 | Admin `sub` path (blocker) | Resolved | 3.4 users file: `id` required, UUID; 4.2 `get user KEY`; 4.3 `apply` JSON `created` has `id`; 9 "First Admin user" and "Existing Admin". |
| 5 | Mapper definition (blocker) | Resolved | 3.4 "Mapper fields" (`kind: audience`, token claim flags); 5.6 apply step 4.3; criterion 34, 35; 11 item 18. Left: `aud` shape is only observed (m11). |
| 6 | `--json` contract for `plan` and `apply` (major) | Partly resolved | 4.3 JSON table and error envelope. Left: failure shape of `apply` (N8); secret reader has no signature (N4). |
| 7 | `plan` exit for `needs --adopt` (major) | Resolved | 5.6 `plan` step 3 (`adopt` is an action), step 5 (exit 0 or 1). `needs_adopt` is an `apply` refusal only (4.4). |
| 8 | `--limit` and `plan_hash` (major) | Resolved | 4.3 "`plan` and `apply` never truncate their actions"; `plan_hash` covers the full list. |
| 9 | Partial run and skipped `remove` (major) | Resolved | 4.4 "Partial runs", `apply_partial`; 5.6 apply step 3 refuses a `remove` without `--allow-delete` before any write. |
| 10 | `get` key meaning (major) | Resolved | 4.2: "`KEY` is the name, `clientId` or `username`". |
| 11 | Stable key for a service principal (major) | Partly resolved | 3.4 "Service-account users belong to their client"; 11 item 20 shows client `id` kept on create only. The spec never says that `clientId` (token `azp`) is the stable key. See N11, D2. |
| 12 | Missing admin credential (major) | Resolved | 5.3 `up` step 1; 7 "Admin credential missing"; 4.4 exit 2 `credential_missing`, "before any request". |
| 13 | `temporary_password_env` paths (major) | Partly resolved | (a) Resolved: 5.6 checks the variable "only when a user is created". (b) Documented manual step only: 5.6 "A user that exists without a password is not repaired by `apply`"; 11 item 22 is open. See N7, D1. |
| 14 | Read contract for secrets (major) | Partly resolved | Resolved: `active` is read (5.8); generation copies (3.5, 5.8 `restore`); `--realm` on every `secrets` command (5.8 last line, criterion 45); window described (5.8 "The window"). Left: reader has no signature, errors or path resolver (N4); crash window open (N3, D6). |
| 15 | Live client, no value in the file (major) | Resolved | 5.8 "Live client, no value in the file"; `secrets_missing`; 5.6 apply step 3; criteria 38, 39. The rebuild and crash cases are open (N2, N3). |
| 16 | Threat model, secrets reach services (major) | Partly resolved | 5.8 launcher rule ("passes the value to that service only"); 9 "Who may run it". Left: 3.5 ("Consumers read the file only through the secret reader") and 5.8 describe option (b) of round 1 decision 2, but the owner has not recorded it (D7). Any process of the same OS user can still read the file. No note for agent-execution sandboxing. |
| 17 | Audit actor, order, format (major) | Resolved | 3.3 (`actor`, `base_url`, RFC 3339 UTC `ts`, check before first change, `audit_incomplete`); criteria 12, 56. Access-control section 8's "same position" claim is now true. |
| 18 | Issuer stability (major) | Resolved | 5.3 `up` step 4 (`KC_HOSTNAME` from `hostname`); 6.1 `hostname`; 11 item 19; criterion 36. |
| 19 | Token and disable live tests (major) | Partly resolved | 11 items 18 to 20; criteria 35, 36, 46, 48. Left: user-token `sub` equal to the users-file `id` (N9a); `iss`, `exp`, `iat`, `jti` (N9b); negative case (N9c). |
| 20 | `aud` missing from section 9 (major) | Resolved | 9 "Roles and bindings": "The API reads the token's `sub`, `iss`, `aud`, `iat`, `exp`, `jti` and `azp`." |
| 21 | Bootstrap order (major) | Resolved on the kc-axi side | 5.6 "Run order for a new realm"; `realm_absent` (5.6 users bullets); criterion 32. Caller side still open (m21). |

Round 1 minors (22 to 34): resolved, except these. Item 25: environment overrides still lack `secrets_path` and `audit_path` (4.1 and 6.1 env lists). Item 26: TLS options are present (`ca_file`, 6.1), but the admin login grant is not named (5.3 step 7). Item 28: the temporary-admin note is missing (5.3 step 4, 5.10). Item 32: the users file has no default path by design (3.4 "The path is set by the owner, with no default"); the unsafe-path check now covers it (section 7). Item 35: caller-side stale claims (m19). Carried in m27.

Round 1 blocker and major status, all 21 items: resolved 15 (item 21 only on the kc-axi side), partly resolved 6 (items 6, 11, 13, 14, 16, 19), not resolved 0.

## 3. New findings for round 2

### Majors

**N1. Built-in and hand-made clients make `plan` drift on every run.**
- Sections: 5.6 `plan` steps 4 and 5; 4.3 example; 3.4 "Built-in clients"; 5.7 step 5; criteria 18 to 20.
- Quote (5.6 step 4): "A client without a marker, or with another owner's marker, is `unmanaged`. It is never changed." Step 5: "Exit 0 with `status: no_change` when there are no actions. Otherwise exit 1 with `status: drift`." 4.3 example: `actions[3 of 3]` includes `unmanaged,client,legacy-tool,`.
- Missing: Every realm holds six built-in clients that carry no marker and cannot be declared (3.4). Read literally, they are `unmanaged` actions, so `plan` never returns `no_change`, `apply` never returns `already`, and criteria 18 to 20 cannot pass. The export skips them (5.7 step 5), but `plan` does not. `plan_hash` also changes when someone adds a hand-made client.
- Needed: State that built-in clients are excluded from step 4. State that `unmanaged` is shown in its own count and is not an action, so it adds to neither drift nor `plan_hash`.

**N2. A rebuilt realm: the client is absent live, but the file has a value for it.**
- Sections: 5.8 ("New client, no value in the file"), 5.6 apply step 4.2, 3.5 "Generation copies", 10 ("A rebuilt realm needs the same client secrets").
- Quote (10): "A rebuilt realm needs the same client secrets. Local generations allow a rollback."
- Missing: After `down --purge`, `up` and `apply`, the client does not exist, and the `active` generation holds a value. The spec does not say whether `create` sets that value or a new one. A new one breaks every running service. No criterion covers it.
- Needed (spec fix, no owner choice, since section 10 already states the purpose): `create` sets the `active` value when the file has one, and writes a new generation only when it has none. Add a criterion.

**N3. Create ordering, and the crash window after a Keycloak change.**
- Sections: 5.6 apply step 4.2 ("Client `create`, then `adopt` and `change`, then secrets"); 5.8 "New client", "The window"; 4.4 `apply_partial`; 5.6 apply step 5 ("Running `apply` again finishes the job").
- Quote (5.8): "The window is milliseconds long, and it is inside the lock. Consumers restart after `apply` finishes."
- Missing (a): If the process dies after the client `create` and before the secret is written, the client is live and carries this owner's marker, with no value in the file. The next run hits `secret_missing` and refuses ("with no capture yet", 5.6 step 3). "Run again" does not finish the job. The spec must write the `pending` generation first and send the value in the create call.
- Missing (b): If the process dies after the Keycloak change and before the `active` mark, the window stays open. The file says `active` = old value and Keycloak holds the new one, until someone runs `apply` again. "Milliseconds" holds only for a normal run. Decision D6.
- Needed: Spec fix for (a). A decision for (b).

**N4. The secret reader has no contract.**
- Sections: 5.8 first paragraph; 2 (the only exception to the no-public-API rule); 3.5 "Location"; 4.5 rule 7.
- Quote (5.8): "The secret reader takes the secrets path, the realm and one client key. It returns the value of that client in the `active` generation. It prints nothing."
- Missing: The function name, module path and signature. The exception types for: file missing; client missing from the `active` generation; file unreadable or unparseable; file mode unsafe; server mismatch. Whether the reader takes the lock. The default path is computed inside the tool (3.5 "Location"), but nothing prints it (4.5 rule 7 prints the config path only). The launcher would copy the OS rules, which the spec says must not happen (3.5, 5.5).
- Needed: A signature and exception list, and either a path resolver, or the rule "the launcher sets `secrets_path` explicitly".

**N5. The emergency stop does not cover clients, and section 9 says it does.**
- Sections: 9 "Emergency stop" and "Removal of a service"; 5.9 last paragraph; 4.2 `disable-client`; owner decision 10.
- Quote (9): "A disabled identity stays disabled on later `apply` runs." Quote (5.9): "For each user whose last `disable` record has no later `enable` record, `apply` refuses to set `enabled: true`."
- Missing: Owner decision 10 and 5.9 cover users only. `disable-client` writes the same audit records, but no rule stops a config-file `apply` from setting `enabled: true` on that client again. If the caller's config still says `enabled: true` for a disabled service, the next `umas init` re-enables it. The spec and section 9 disagree. Decision D5.

**N6. The emergency-stop memory depends on the audit file, and its failure paths are not given.**
- Sections: 5.9; 3.3; 6.1 (`audit_path` empty means no audit file); 5.6 apply step 3; 4.4; 3.3 action list.
- Missing (a): `disable-user` requires `audit_path` (5.9 step 1), but `apply` does not. If `audit_path` is empty, or points to another file, `apply` cannot see the disable and re-enables the user. The spec does not say so.
- Missing (b): What `apply` does when the audit file is unreadable, truncated or holds a bad line. No fail-closed rule.
- Missing (c): 5.9 says the refusal is `keycloak_rejected` with `user_disabled_by_audit`. Keycloak rejected nothing, and `user_disabled_by_audit` is not in the 4.4 table.
- Missing (d): The refusal is not in the list of refusals "before the first write" (5.6 apply step 3). So it can arrive as `apply_partial`, after the realm and client changes.
- Missing (e): 5.9 says "The next `enable` record is written by `apply`", but `enable` is not in the action list of 3.3.
- Needed: Spec fixes for (c) to (e). Decision D4 for (a) and (b).

**N7. An Admin user with no password cannot be detected.**
- Sections: 5.6 users bullets; 11 items 16 and 22; criterion 50 (`not run`).
- Quote (5.6): "A user that exists without a password is not repaired by `apply`. The owner sets a password by hand in the admin console."
- Missing: `partialImport` can succeed and `reset-password` can fail. The next `apply` reports `already` (no declared field differs), and `umas init` reports success. `plan`, `status` and `get` do not show the fault. The manual repair needs the admin console, which an agent-driven set-up cannot use. Decision D1.

**N8. The failed-`apply` output has no single shape.**
- Sections: 4.3 JSON table (`apply` row), 4.3 error envelope, 4.4 "Partial runs", 5.4 "with the `applied` and `pending` counts", 5.6 `keycloak_rejected`.
- Quote (4.3): "`apply` | `status` (`already`, `applied`, `partial`), `applied`, `pending`, `created` ...". Quote (4.3): "Errors use one envelope: `{ "error": { "code", "message", "help" } }`."
- Missing: For `apply_partial`, `keycloak_rejected` and `auth_failed` after a change, a caller cannot tell whether to read `status: partial` or `error`. `cause`, `field`, `applied`, `pending` and `created` are not in the envelope. `created` is not stated for a failed run, so the caller cannot learn which ids were created before the failure.
- Needed: One shape for a failed `apply`: the envelope plus `applied`, `pending`, `created`, `cause` and `field` where they apply. Remove `partial` from `status`, or say it is the same output.

**N9. Token-claim coverage is thinner than the module reads.**
- Sections: 11 items 18 to 20; criteria 35, 36, 46, 48; access-control 3.1 ("`sub`, `iss`, `aud`, `iat`, `exp`, `jti`").
- Missing (a): The live test shows that the service token `sub` equals the service-account user id (11 item 18). It does not show that a user token `sub` equals the `id` given to `partialImport` (11 item 8 covers only the stored id). That equality is the basis of the Admin `external_id` (access-control 5.6 step 3). No criterion states it.
- Missing (b): Introspection was shown to return `active`, `sub`, `aud` and `azp` (11 item 18). `iss`, `exp`, `iat` and `jti` are not listed. The module reads all of them (access-control 3.1, 2 step 1).
- Missing (c): No negative case. A token without the API audience, checked by the API client, may return `active: true` with a different `aud`. The caller then has to check `aud` itself. The spec does not say which.
- Needed: Three criteria and their results in 11.

**N10. The sign-in flow for `umas auth login` cannot be seeded or ruled out.**
- Sections: 3.4 "Client fields" (closed list, no raw `attributes`); 3.4 `pkce`; access-control "Human sign-in"; 11 item 15 (`UPDATE_PASSWORD`).
- Missing: The spec does not say which grant the CLI uses. The client fields allow `standardFlowEnabled`, `directAccessGrantsEnabled` and `pkce`, but nothing about the device grant. The example sets `directAccessGrantsEnabled: false`, so the password grant is not used. A new user's `UPDATE_PASSWORD` required action is, as I understand Keycloak, a further block on the password grant. The spec does not test this, so the caller must not rely on it without a live test. The browser flow needs a loopback redirect with a free port; the spec does not say how Keycloak 26.6.4 matches a changing port in `http://127.0.0.1/*`. Session and refresh lifespans are not realm fields (3.4), so the length of a CLI sign-in cannot be set. Decision D3.

**N11. The stable key of a service principal is still undecided.**
- Sections: 3.4 ("Service-account users belong to their client"); 11 item 20 ("did not cover `down --purge` followed by `up`"); 9 "Service principals"; access-control 9 item 6 and N6 of round 1.
- Missing: The service token `sub` is the service-account user id (11 item 18). Client ids were not shown to survive `down --purge` and `up`. The config file has no `id` for a client. A binding keyed on that `sub` breaks after a rebuild. The spec does not say that `clientId` (token `azp`) is the stable key. Decision D2.

**N12. A stale secrets generation: the `secret` plan action has no apply behaviour.**
- Sections: 5.6 `plan` step 3 (`secret`); 5.6 apply steps 3 and 4; 3.5 "State" ("`active` is the value Keycloak holds"); 5.8.
- Quote (5.6 step 3): "`secret`: a `secret_managed` client has an active generation whose fingerprint differs from the live secret."
- Missing: The spec does not say what `apply` does for a `secret` action. It may push the `active` value, create a new generation, refuse or do nothing. The cases are real: `rotate` on another machine, a restored backup, or a `pending` value that was never confirmed. The `pending` rule (5.8) covers only the `pending` state. The `secret_missing` rule does not cover this case, because a generation exists.
- Needed: One rule. Recommendation (no owner choice, consistent with 5.8's "The tool does not overwrite it"): refuse with a typed code such as `secrets_mismatch` (exit 1) before any write, and name the recovery: `secrets capture` if the live value is right, `secrets rotate` or `restore` if the file is right. Add to 4.4 and to criteria.

### Minors

| # | Section | Finding |
|---|---------|---------|
| m1 | 3.4 (rules, line "Duplicate keys ... `config_invalid`"; line "`secret_managed: true` on a public client ... `config_invalid`") | 4.4 and 7 give `duplicate_key` and `secret_managed_public` for the same cases. A test cannot satisfy both. |
| m2 | 5.4 "Writes are never retried" and "A call that fails with HTTP 401 logs in once more and retries that call" | Contradiction for a write. A write that times out has an unknown outcome, and no rule gives its `applied` and `pending` counts. |
| m3 | 4.4 `credential_missing`; 5.3; 5.6 users bullets | The same code covers a missing admin credential and an unset `temporary_password_env` variable. Criterion 31 ("without `temporary_password_env` set") is ambiguous. |
| m4 | 9 "Existing Admin" versus 3.2 and 4.2 | "`get user <username>` returns the `id`". The default view (3.2) has no `id`; the caller needs `--fields id`. |
| m5 | 5.6 "Run order for a new realm" ("then `secrets` if the config has `secret_managed` clients") | `apply` already writes the first secrets (5.8). Say that `secrets` commands are for `capture`, `rotate` and `restore`. |
| m6 | 5.6 apply steps 1 and 2 | The plan is built before the lock is taken, so `--expect` and the actions can rest on a state another run has changed. Re-read the plan after the lock. |
| m7 | 3.5 "Server identity" | "normalised `base_url`" is not defined. `localhost` against `127.0.0.1` would give `secrets_server_mismatch`, which is the host problem `hostname` solves for `iss`. |
| m8 | 3.5 "Location", 5.8 | No sentence says that an absent secrets file is created on the first write, with its directory and mode. Only criterion 37 implies it. Round 1 item 3 asked for this sentence. |
| m9 | 4.2 `export-realm` and `secrets capture`; 5.7 step 7 | `--capture-secrets` writes a generation without `--yes`, but `secrets capture` needs `--yes`. Owner decision 14 names neither. Pick one rule. |
| m10 | 8 criteria 35, 41, 56, 57 | 41 and 56 need a fault-injection hook that the spec does not define. 57 says the word `umas` must not appear, and criterion 57 itself contains it (line in section 8). 35 has no negative case (N9c). |
| m11 | 11 item 18; 9 | `aud` is a string for a user token and a list for a service token, and the service list also carries `account`. Observed only. Add a rule: `aud` may be a string or a list, and the check is membership. |
| m12 | 5.3 `up` step 4; 5.3 `status` | An existing container keeps its old `KC_HOSTNAME`, and `status` does not show `hostname` or the issuer. A changed `hostname` is silent. |
| m13 | 3.4 realm fields; 6.1 | The signature algorithm is neither set nor checked. Access-control 4 assumes `RS256`. Say that kc-axi relies on the Keycloak default. |
| m14 | 3.4 `owner`; 6.1 `owner` | Two `owner` keys, no precedence rule. The word also names the person who owns the deployment. |
| m15 | 7, last row | "a file error with `message` naming the path" has no typed code. |
| m16 | 5.6 apply step 3; 5.8 "Adopting" | An adopted client with a live secret is both `adopt` and `secret_missing`. Step 3 refuses "with no capture yet", and `--adopt` captures. Say that `--adopt` lifts that refusal. |
| m17 | 5.8 | No rule for a client that changes from `secret_managed: true` to `false`, or is removed. Its entries stay in old generations and in copies. |
| m18 | 6.1 `audit_path` | With `audit_path` empty, `disable-user` fails with `audit_required` at the moment it is needed. See D4. |
| m19 | Caller side and `libs/README.md` | Stale claims. Access-control 3.1 "Init credential" row says `umas init` calls "the Keycloak admin REST API", which owner decision 6 replaced. Access-control 4 lacks the kc-axi keys `audit_path`, `secrets_path`, `java_opts` and the timeouts. Access-control 8 "same case as kc-axi exit 4" (no exit 4 exists) and its exit 2 for unreachable (kc-axi uses exit 1, `keycloak_unreachable`). Access-control AXI section: "stderr errors and exit codes 3 to 7". `libs/README.md` line 160 repeats "exit codes 3 to 7, default limit 3". Access-control item 12 (loopback is not external) is not recorded in kc-axi. |
| m20 | 5.4 "created with owner-only permissions in one step" | Not true on Windows, where the same section says modes are not checked. State the Windows limit here. |
| m21 | Access-control 5.6 | The caller's bootstrap has no `kc-axi up` and no config-file `apply` before step 3, and step 6 creates clients outside `apply`. Caller-side edit. |
| m22 | 3.4 `clientId` | Not stated whether `clientId` may contain `:`. The caller names principals `svc:<process>`. |
| m23 | 3.4 `id` | No rule for a value that is not a UUID, and no typed code in 4.4 for it. |
| m24 | 3.4 users file `realm`; 4.1 `--realm` | No rule when the users file's `realm` differs from `--realm` or from the config file's `realm.name`. |
| m25 | 8 criterion 11 | Requires the acceptance cases to pass on Linux and Windows. Owner decision 2 says those are "verified by reading" until a machine exists. The criterion cannot be met as written. |
| m26 | 3.4 mapper fields; 3.4 `pkce` | Not stated: the error when a mapper's target `audience` client is not declared or does not exist, and whether `pkce` is valid on a confidential client. |
| m27 | Round 1 carry-overs | Item 25: environment overrides lack `secrets_path` and `audit_path` (4.1, 6.1). Item 26: the admin login grant is not named (5.3 step 7). Item 28: no note that the bootstrap admin is temporary (5.3 step 4, 5.10). |

### Owner decisions applied

| Decision | Applied? |
|----------|----------|
| Local only; `--allow-remote` | Yes (4.2, 4.4 `allow_remote_required`, criteria 27, 28). |
| `hostname`; config discovery order | Yes (5.3 step 4, 6.1, 4.1). |
| Subprocess with `--json`; no public API except the reader | Yes in 2 and 11 item 7. The reader has no contract (N4). |
| `id` required, consumer-generated | Yes (3.4, `id_conflict`). |
| No delete without `--allow-delete`; removed service becomes `enabled: false` | Yes (3.4 table; 9 "Removal of a service"). |
| `disable-user`, `disable-client` as emergency stop; `apply` does not re-enable without `--allow-reenable` | Users: yes (5.9). Clients: no (N5). The memory depends on the audit file (N6). |
| `--yes` on every write that changes Keycloak or deletes local data | Mostly. `--capture-secrets` (m9). |
| AXI conformance | Yes. 4.5 lists no deviation except the encoding (11 item 21). |
| Keycloak 26.x, tested at both ends | Yes (11 items 11 and 25). |
| Adopting a client with a live secret captures it | Yes (5.8), with m16. |
| Admin password changed by hand | Yes (5.10). |

## 4. Items that need an owner decision

**D1. Repair of a user that exists with no password (N7; 11 item 22).**
- (a) `plan` reads each user's credentials. A user with `temporary_password_env` set, with no password credential, gets a `password` action, and `apply` runs `reset-password` again. Changes: one read per user and one new action. Idempotent, with no new command.
- (b) A command `kc-axi reset-password USERNAME --yes`. Changes: a new write command, an audit action, and a manual step for the caller.
- (c) Keep the admin-console step. Changes nothing in the tool. An agent cannot repair the Admin.
- **Recommendation: (a).** A re-run of `umas init` repairs itself, and `plan` shows the fault.

**D2. Stable key of a service principal (N11; owner decision 1 was not in the decision list).**
- (a) Map by `clientId`, read from the token's `azp`. It survives `down --purge`. Changes: one sentence in kc-axi section 9.
- (b) Map by the service-account `sub`. Changes: kc-axi exposes the service-account user id and keeps client ids across a rebuild. No test covers the rebuild.
- **Recommendation: (a).**

**D3. Sign-in flow of `umas auth login` (N10).**
- (a) Browser code flow with PKCE and a loopback redirect. Changes: none in kc-axi. Needs a live test of how Keycloak 26.6.4 matches a changing loopback port.
- (b) Device grant. Changes: one new boolean client field and a live test. Works without a browser on the same host.
- (c) Direct password grant. Blocked by `UPDATE_PASSWORD` (as I understand Keycloak; not tested) and against the example's `directAccessGrantsEnabled: false`.
- **Recommendation: (a), if the live test passes. Otherwise (b).**

**D4. Where the emergency-stop memory lives (N6; m18).**
- (a) Keep the audit file. Give `audit_path` a default in the user configuration directory, as for the secrets file. Make `apply` read it and fail closed when it cannot read it. Changes: one default path and one refusal code.
- (b) Keep it as written. The module must always set `audit_path`, and `apply` may still re-enable a user if it does not.
- (c) Also store a `kc-axi.disabled` client attribute (11 item 10 shows the client marker is stored). Users still need the audit file, because a user attribute was not stored.
- **Recommendation: (a).** One mechanism covers users and clients.

**D5. Re-enabling a client disabled by `disable-client` (N5).**
- (a) Extend the rule of 5.9 to clients: `apply` refuses `enabled: true` for a client with a `disable` record and no later `enable`, unless `--allow-reenable` is given. Changes: owner decision 10 widens from users to clients.
- (b) Narrow section 9 to users. The module must keep `enabled: false` in the config file for a disabled service, so each `umas init` sets it again.
- **Recommendation: (a).** A compromised service client should stay disabled after a re-run of `umas init`.

**D6. Crash after the Keycloak secret change and before the `active` mark (N3(b)).**
- (a) Readers take `pending` when `active` fails. Changes: the reader cannot know whether Keycloak took the new value, so it may hand out a value that Keycloak has rejected.
- (b) Accept the window. 5.8 says consumers restart after `apply` finishes. Changes: one sentence in 5.8 that says a consumer must not start while a generation is `pending`. `secrets list` already shows each generation's `state` (4.3).
- (c) The launcher checks the value against Keycloak before it passes it on. Changes: one extra call per start, and the launcher needs the client credentials to make it.
- **Recommendation: (b).** The reader stays simple, and the Admin can see the state.

**D7. How client secrets reach each service (round 1 decision 2; not in the owner's answers).**
- (a) Each service reads the shared secrets file. Changes: none in kc-axi. Every service can read every secret, and the file must be hidden from Worker sandboxes.
- (b) The UMAS launcher calls the secret reader (5.8) for one client and passes the value to that service only, in its environment. Changes: the reader contract (N4). Services never open the file. This is what 3.5 and 5.8 already say.
- (c) An OS keychain per client. Changes: a cross-platform keychain dependency in kc-axi.
- **Recommendation: (b).** The spec already reads that way. The owner should record it, because the owner's answers do not mention it.

## 5. Counts by severity

- Blockers: 0
- Majors: 12 (N1 to N12). Seven owner decisions (D1 to D7). N12 has a recommendation, but needs no owner answer.
- Minors: 27 (m1 to m27)
- Round 1 items: 15 resolved, 6 partly resolved, 0 not resolved.
