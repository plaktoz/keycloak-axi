# Caller assessment, round 2: kc-axi interfaces

**Verdict: REJECTED.** Three blockers remain: N1 (secret reader has no contract), N2 (re-enable guard is incomplete), N3 (a partial run has no JSON shape).

- Spec: `libs/kc-axi/README.md`, draft v0.3 (938 lines).
- Caller: interfaces module, `umas/modules/interfaces/interfaces-spec.md`.
- Round 1: `docs/assessments/caller-assessment-kc-axi-interfaces-2026-10-27.md` (REJECTED, against v0.2).
- Section numbers are kc-axi sections. Line numbers are lines of `libs/kc-axi/README.md` unless a file is named.
- Sibling specs were checked by grep for the cited lines. They were not read in full.

Severity: **BLOCKER** = the module cannot write a UI or launcher step without a decision. **MAJOR** = the module can write it but would guess a behaviour that matters. **MINOR** = wording, completeness or testability.

---

## 1. Round 1 blockers and majors

| # | Item | Status | Proof, or what is still open |
|---|------|--------|------------------------------|
| B1 | JSON shapes, `schema_version`, error object | Partly resolved | Per-command keys and `schema_version` in 4.3 (lines 285–303). Open: N3 (error envelope has no place for partial-run or structured fields). |
| B2 | Config discovery, `image`, complete flag table | Resolved | Order in 4.1 (line 218) and 6.1 (line 634). `image` in 6.1 (line 647). Per-command flags in 4.2 (lines 233–252). Open detail: N8. |
| B3 | First-run secrets file | Partly resolved | New client without a value: `pending` then `active` (5.8 line 576). Live client without a value: `secret_missing`, exit 1 (5.8 line 580; 5.6 step 3). Open: missing file in the reader (N1). Create-path window (N12). |
| B4 | One secret location | Partly resolved | kc-axi: file in 3.5 (line 208), reader in 5.8 (line 572), consumers in 9 (line 820). Open: `access-control-spec.md` line 126 still says "kept in the environment or a secret store". |
| B5 | One integration path | Partly resolved | kc-axi: CLI with `--json` (2, line 39; 11.7, line 865). The reader is the only Python entry point. Open: `access-control-spec.md` line 154 says `umas init` calls the REST API itself. `interfaces-spec.md` line 454 says kc-axi is "Not used by `umas`". |
| 6 | `--realm` default and `secrets` realm | Resolved | Order in 4.1 line 219, with `realm_required` exit 2. Rows in 4.2 lines 240–249. 5.8 line 598. |
| 7 | `plan` and `apply` truncation | Resolved | 4.3 line 260: "`plan` and `apply` never truncate their actions, and `--limit` does not apply to them." |
| 8 | Skipped removal and exit code | Resolved | 5.6 apply step 3 (lines 531–536) refuses a `remove` before the first write. Exit 6 is gone; 4.4 (line 309) uses only 0, 1 and 2. |
| 9 | No-op rule per write command | Partly resolved | Without `--yes`, 4.2 line 254 and 5.4 line 477 say exit 1 `confirm_required`. 4.5 rule 6 line 362 says a satisfied write exits 0. These conflict for a no-op `apply` without `--yes`. Statuses `already` are listed in 4.3 for `secrets` and `disable-*`, but no rule says when each applies. |
| 10 | Write list and `--yes` | Resolved | "Needs --yes" column in 4.2 (lines 233–252). Owner list item 14 (line 872). |
| 11 | Exit and typed code for each failure | Resolved | 4.4 lists every code (lines 315–347). Permission refusals are exit 2 (5.4 line 490). Two gaps remain in N13. |
| 12 | `status` keys and exit | Partly resolved | Keys in 4.3 line 296. Exit is contradictory (N5). `image` and `port` are not in the JSON keys. |
| 13 | Plain examples and progress lines | Not resolved | Examples exist only for `plan` (lines 262–272) and errors (lines 278–283). 4.5 rule 5 (line 361) says progress goes to stderr but names no progress line. `up` can run for 730 s (6.2 line 677) with no signal. |
| 14 | `temporary_password_env` on every `apply` | Resolved | 5.6 line 552: the variable is checked and reset only when a user is created. Conflict with acceptance 31 is N11. |
| 15 | Realm action and missing realm | Resolved | 5.6 step 4.1 (line 538). `realm_absent` (line 554). Run order (line 556). Minor: the plan action list in step 3 does not name `realm`. |
| 16 | Field table for each file | Partly resolved | Field lists (lines 150, 176). Rules (lines 179–187). `pkce` mapping (line 129). Missing: types, required flags for realm, client and mapper, allowed `pkce` values, defaults for omitted fields. |
| 17 | Audit pre-check and record shape | Partly resolved | Pre-check and result failure are in 3.3 (lines 73–91). Missing: the `enable` action (N2). Record fields for `up`, `down` and `secrets` are not stated. |
| 18 | Users file outside git | Resolved | 3.4 line 104. Refusal `unsafe_path` in 7 line 703 and 4.4 line 315. No acceptance test (N17). |
| 19 | Remote guard for config and users files | Partly resolved | 5.6 step 3 line 535 covers both `apply` modes. Not applied to `disable-*` or `secrets` writes (N4). |
| 20 | AXI conformance and deviations | Resolved | 4.5 (lines 357–368). Exit codes 0, 1, 2 (4.4). Errors on stdout (4.5 rule 5). Minor gap: `--full` (N20). kc-axi is still missing from the libs fit table (caller and libs task). |
| 21 | Docker claim | Partly resolved | 5.3 step 4 line 431 says "not tested". Unmarked claims remain in 2 (line 22), 5.2 (line 379) and 10 (line 842). Acceptance 10 is not marked. |
| 22 | Secret-in-export test on the tool's output | Resolved (test not run) | Acceptance 42 (line 785) covers exported files, audit file and command output. 11.17 (line 914) marks it not run. |
| 23 | REST timeout and worst case for `up` | Resolved | `request_timeout_seconds` (6.1 line 654). Worst case for `up` (6.2 line 677). Open: `apply`, `plan` and `export-realm` have no bound (N14). |
| 24 | Admin user and password sources | Resolved | 5.3 step 4 line 428. 5.4 lines 482–486. 6.1 lines 643–644. |
| 25 | Created user id in `apply` | Resolved | `created` with `id` in 4.3 line 299. Plain output is not defined (row 13). |
| 26 | Exit 8 for `plan` | Resolved | Exits 0, 1, 2 only (4.4). `plan` exits 1 with `status: drift` (line 351). |
| 27 | Embedded Python API | Resolved | 2 line 39: no public API except the reader. The API section is gone. The reader's contract is open (N1). |

Round 1 minors (28–40), briefly: 28 resolved (4.1 line 221; 5.4). 29 resolved (4.3 line 260; 4.5 rule 4). 30 partly (N18). 31 partly (N18). 32 resolved (9 line 819). 33 partly (acceptance 57, line 809; the list is not named). 34 not resolved (acceptance 11, line 745, still says "pass on Linux, macOS and Windows"; 11.2, line 860, says some are "verified by reading"). 35 partly (5.3 step 4 line 471 covers each file; Windows creation of the secrets file is not defined, line 492). 36 partly (endpoint is named in 11.10 and 11.14, not in 5.6). 37 not resolved (9, "First Admin user", line 821, has no mark). 38 resolved, minor gap for `secrets restore N` (N18). 39 resolved. 40 partly (limit is 20, line 223; the TOON deviation is "not verified" in section 10, line 852, not a deviation entry).

**Round 1 totals.** Blockers: 1 resolved, 4 partly. Majors (6–27): 15 resolved, 6 partly, 1 not resolved (13).

---

## 2. New findings

### BLOCKER

**N1. The secret reader has no contract.**
- Section 5.8, line 572: "The secret reader takes the secrets path, the realm and one client key. It returns the value of that client in the active generation. It prints nothing."
- Missing: the return type and the error channel (exception or code). The file-absent case is not covered. Section 7 (line 700) covers only "unreadable or unparseable". Section 3.5 (line 203) says a server mismatch is refused "for a command", but the reader receives no `base_url`, so that check cannot run. It is also unclear whether the reader applies the mode check (5.4 line 490), what the default path is when the caller passes none (3.5 line 208 defines it only for the tool), and what happens for a client absent from the file or a pruned generation.
- Why it blocks: the launcher must decide whether to start a service. It cannot do that without knowing whether "no file" means start-with-nothing, fail, or `secrets_missing`.

**N2. The re-enable guard depends on an optional file, and covers users only.**
- Section 5.9, line 611: "`apply` reads the audit file... For each user whose last `disable` record has no later `enable` record, `apply` refuses to set `enabled: true`."
- Section 6.1, line 659: `audit_path` defaults to empty.
- Section 9, line 826: "A disabled identity stays disabled on later `apply` runs." This covers clients too. Section 5.9 implements the guard for users only. Line 613 says `disable-client` writes the same audit records, but no `apply` rule uses them.
- Section 3.3, line 87: the `action` enum has no `enable`. Line 611 says apply writes an `enable` record.
- Missing: what `apply` does when `audit_path` is empty or the file is missing, unreadable or rotated. With no audit file, `apply` cannot see the disable and will re-enable the user. The live check (5.9, line 609) proves that disabling works, not that the guard works.
- Owner decision 10 says `apply` does not re-enable a user disabled by `disable-user`. The spec does not implement that for an unconfigured or lost audit file, and does not implement it for clients.

**N3. A partial run and a confirmation have no JSON shape.**
- Section 4.3, lines 285–290: the error envelope has `code`, `message` and `help` only.
- Section 4.4, line 347: `apply_partial` "gives `applied`, `pending` and `cause`". Section 5.6 step 5, line 542, says the same. Section 5.3 step 6, line 434, says `container_exited` names `oom_killed`. Section 4.4, line 336, says `keycloak_rejected` "names the field". None of these has a place in the JSON envelope.
- Section 4.3, line 299, gives `apply` a status `partial`. Section 4.4 uses the error code `apply_partial` with exit 1. The spec does not say which form `--json` uses, or whether both.
- Why it blocks: a UI cannot show what a failed `apply` changed. The launcher cannot tell which changes are pending.

### MAJOR

**N4. The remote guard is applied to `apply` only.**
- Owner decision 6: "Remote writes are refused unless `--allow-remote`."
- Section 4.2 rows for `disable-user` (line 251), `disable-client` (line 252), and `secrets capture`, `rotate` and `restore` (lines 247–249) have no `--allow-remote`. Section 5.6 step 3 (line 535) is in the `apply` path only. Section 5.9 (lines 602–613) has no check.
- Result: `disable-user` against a non-loopback `base_url` runs with no guard.

**N5. `status` contradicts itself on exit codes, and its JSON keys do not match its text.**
- Section 5.3, line 473: "`status` exits 0 when it can report, whether or not the server answers."
- Section 5.2, line 397: "When both runtimes hold the container, every command exits 1, `runtime_ambiguous`."
- Section 7, line 690: "Neither Docker nor Podman installed | Exit 1, `runtime_missing` for `up`, `down --purge` and the container line of `status`."
- Acceptance 4, line 738: "every command that calls Keycloak exits 1 with `keycloak_unreachable`". `status` calls Keycloak, so this conflicts with line 473.
- Section 4.3, line 296, lists the `status` keys. Missing: `image` (5.3 step 3, line 468), `port` (7 line 439 says `status` shows port) and `permissions` (5.3 step 4, line 471). The `status` key and the `state` key are not defined as value sets.

**N6. A write without `--yes` does not show what it would change.**
- Section 4.2, line 254: "It prints what it would do and exits 1, `confirm_required`." Section 5.4, line 477, says the same.
- Section 4.3 has no key or layout for that preview. A UI that confirms a change cannot show it unless it runs `plan` first, and the spec does not say to do so.

**N7. `secrets_path` is one value, but each realm has its own file.**
- Section 3.5, line 208: "`secrets_path`. The default is `<realm>.secrets.json`."
- Section 6.1, line 660: `secrets_path` is one key.
- Section 5.8, line 598: "finds the file of that realm through `secrets_path`".
- Acceptance 45, line 788: "Two realms on one server have two files."
- Missing: whether `secrets_path` is a file or a directory. With one value it cannot name two files.

**N8. The tool configuration file may be absent, and the spec does not say what happens.**
- Section 6.1, line 634: the lookup order is given, and "There is no default in the working directory."
- Section 4.4, line 315, has the code `config_missing` for exit 2, but nothing says when it is raised. No row in section 7 covers it.
- Missing: whether a command with no file runs on defaults, fails with `config_missing`, or runs only if `KC_AXI_BASE_URL` and the other variables supply each value it needs.

**N9. Locking does not cover every write, and `apply` reads state before it locks.**
- Section 5.6 step 1 (line 529) runs the plan reads. Step 2 (line 530) takes the lock. A `disable-user` between the two is overwritten by `apply`, because `apply` already read the user as enabled.
- Section 5.8, line 594: "Writes need the lock... and so does every `secrets` write." Section 5.9 (`disable-user`, `disable-client`), section 5.3 (`up`, `down`) and section 5.7 step 7 (`export-realm --capture-secrets`, which writes the secrets file) do not mention a lock.

**N10. Adopt, unmanaged and another owner's marker contradict each other.**
- Section 3.4, line 183: "An unmarked client is listed as `unmanaged` and never changed."
- Section 5.6, line 517: `adopt` is "a client with the declared `clientId` exists without the marker of this owner. A run without `--adopt` is refused." `apply --adopt` then changes it.
- Acceptance 22, line 762: "A client without a marker needs `--adopt` for its change."
- Section 3.4, line 184: "Two files with different owners do not touch each other's clients." Section 5.6 does not say what happens when a declared `clientId` carries another owner's marker. Under line 517 it would be `adopt`, which would take over that client.

**N11. Acceptance 31 contradicts section 5.6.**
- Section 5.6, line 552: the variable is checked "only when a user is created", and only "when `temporary_password_env` names a variable".
- Acceptance 31, line 771: "A new user without `temporary_password_env` set exits 2 with `credential_missing`."
- The spec does not say whether a new user with no `temporary_password_env` is created at all, or what state it is left in.

**N12. The create path does not match the "file first" claim.**
- Section 5.8, line 576: "The file holds the value before Keycloak does. A crash cannot lose it."
- Section 5.6 step 4.2, line 539: "Client `create`, then `adopt` and `change`, then secrets." The client is created on Keycloak before the secrets step writes the file.
- The spec does not say whether the create payload carries a tool-generated secret. If it does not, a crash between create and the file write leaves a live `secret_managed` client with no file entry. The next run reports `secret_missing`, and `secrets capture` recovers the value. Nothing is lost, but line 576 and acceptance 41 (line 784) do not describe this path.

### MINOR

**N13. Two failures have no typed code.** Section 5.2, line 403, has a runtime timeout, and section 7, line 717, has "a file error with `message` naming the path". Section 4.4, line 309, says every failure prints its typed code.

**N14. Durations are not bounded for most commands.** Section 6.2, line 677, gives the worst case for `up` only. It omits the runtime calls of section 5.2 (`volume create`, `start`, state reads, each up to 30 s). `apply`, `plan` and `export-realm` have no bound, which a subprocess caller needs. The 2-second status probe (5.3 line 467) is not in the table in 6.2.

**N15. The issuer value is not normative.** Section 11.19, lines 921–922, gives `http://127.0.0.1:<port>/realms/<realm>` as the issuer with `hostname` set. Sections 6 and 9 do not give it. The API has to know the `iss` it will accept.

**N16. Some acceptance criteria are not testable as written.**
- Acceptance 2, line 736, expects "`shown: 20`, `total: 21`". Section 4.3, line 260, uses "shown of total".
- Acceptance 8, line 742: "never appears... in a file" is too wide to test as written.
- Acceptance 16, line 753: "does not wait for the full timeout" has no threshold.
- Acceptance 11, line 745: see round 1 item 34.

**N17. Several rules have no acceptance test.** Missing: `unsafe_path` (7 line 703), `apply_partial` (5.6 step 5), `locked` (5.6 step 2), client re-enable (N2), `plan` for a users file whose realm is absent (5.6 line 554), config discovery precedence (4.1), and the `status` exit code (N5).

**N18. Edge cases in export and secrets.**
- `export-realm --scope` has no default (4.2, line 245).
- Section 5.7 step 3 does not say what happens to written files when a later file fails.
- `secrets prune --keep N` is required in the 4.2 table (line 250), but 5.8 line 590 says it defaults to `keep_generations`. This is round 1 item 30.
- `secrets restore N` with an unknown `N` has no code. Section 5.8 line 588 covers only a pruned generation.
- `apply` JSON `applied` and `pending` may be counts or lists. Section 4.3 line 299 does not say.

**N19. The mapper type is not named.** Section 3.4, line 154, says `kind: audience` maps to an audience mapper. Section 11.18, line 916, shows the live check used `oidc-audience-mapper`. The normative text does not name it.

**N20. `--full` is a deviation that section 10 does not record.** Section 4.5 rule 1, line 357, says "`--fields` (not `--full`)". The libs rule 3 says `--full` removes the cut. Section 4.5, line 369, says "Deviations. None in v1", which is wrong.

---

## 3. Sibling specs that still disagree with kc-axi v0.3

These are not kc-axi gaps. The owners of the sibling specs must amend them to match.

- `umas/modules/access-control/access-control-spec.md` line 126: "The client secret is kept in the environment or a secret store, never in the repo." Conflicts with kc-axi 3.5 and 5.8.
- Same file, line 154: "Keycloak admin REST API, called by `umas init`." Conflicts with kc-axi 2 and owner decision 1. Line 155 says kc-axi is a subprocess used "out of runtime", which is correct.
- `umas/modules/interfaces/interfaces-spec.md` line 454: kc-axi is "Not used by `umas`." Section 5.9 has no Keycloak steps.
- `umas/modules/interfaces/interfaces-spec.md` has no secret or launcher section. The launcher is named as unspecified in `umas/TECHNICAL-DESIGN-SPEC.md` gap 3 (line 1745).
- `libs/README.md` line 160 repeats the stale kc-axi description. kc-axi is not in the fit table.

---

## 4. Owner decisions needed

**D1. Re-enable guard (N2).**
- (a) `apply` refuses (exit 2, `audit_required`) when the desired-state file declares users or clients and `audit_path` is empty. Add `enable` to the audit actions, and refuse when the audit file is unreadable. Covers users and clients.
- (b) Store the disable on the Keycloak object. This works for clients (a client attribute is stored, per 11.10). It does not work for users, because a user attribute was not stored (11.10, line 892).
- (c) Accept the gap and document it.
- Recommendation: (a) now, and (b) for clients later.

**D2. Secret reader error model (N1).**
- (a) Raise a typed exception that carries a section 4.4 code: `secrets_unreadable` for a missing or unreadable file, `secrets_missing`, `unsafe_file_mode`, `secrets_server_mismatch`.
- (b) Return `None` on any failure. The launcher then cannot tell a missing file from a missing client.
- Recommendation: (a). Also decide whether the reader takes the resolved path or the tool configuration file.

**D3. Partial-run and error JSON (N3).**
- (a) The error object gains `applied`, `pending`, `cause`, `oom_killed` and `field` where the code names them. `apply` uses exit 1 and code `apply_partial`, and the `status: partial` value is removed.
- (b) Keep the error object as it is and add a `result` object to `apply`.
- Recommendation: (a).

**D4. Preview on a write without `--yes` (N6).**
- (a) A write without `--yes` prints the plan with the `plan` keys, and exits 1 `confirm_required`.
- (b) The caller always runs `plan` first. Nothing changes in kc-axi.
- Recommendation: (a).

**D5. `status` exit code (N5).**
- (a) `status` exits 0 for any answer, and the runtime problem is a field.
- (b) `status` exits 1 for `runtime_ambiguous` and `runtime_missing`, and 0 when the server is unreachable.
- Recommendation: (b). A script must see a broken runtime, and an unreachable server is a report.

**D6. Remote guard scope (N4).**
- (a) Every Keycloak write refuses a non-loopback `base_url` without `--allow-remote`.
- (b) Only `apply`, as now.
- Recommendation: (a), which is what owner decision 6 says.

**D7. Shape of `secrets_path` (N7).**
- (a) A directory. The file is `<realm>.secrets.json` inside it.
- (b) A path template with `{realm}`.
- Recommendation: (a).

**D8. Missing tool configuration (N8).**
- (a) `config_missing` (exit 2) for any command that needs a value that no flag or variable supplies. `status` and the no-argument view may run without a file.
- (b) Every command runs on defaults.
- Recommendation: (a).

**D9. Adopt and another owner's marker (N10).**
- (a) A declared, unmarked client is `adopt`, and needs `--adopt`. A declared client with another owner's marker is refused with a new code, `owner_conflict` (exit 1). Correct line 183 of 3.4.
- (b) A declared, unmarked client is always refused.
- Recommendation: (a).

**D10. Lock scope and order (N9).**
- (a) Take the lock before the plan reads. `disable-user`, `disable-client`, `up`, `down` and `export-realm --capture-secrets` take the lock too.
- (b) Leave as is.
- Recommendation: (a).

---

## 5. Counts

| Severity | New in round 2 | Carried from round 1 and still open |
|----------|----------------|-------------------------------------|
| BLOCKER | 3 (N1, N2, N3) | 4 partly resolved (B1, B3, B4, B5) |
| MAJOR | 9 (N4–N12) | 6 partly resolved, 1 not resolved (items 9, 12, 13, 16, 17, 19, 21) |
| MINOR | 8 (N13–N20) | round 1 minors 30, 31, 33–37, 40 |

**Verdict: REJECTED.** Resolve N1, N2 and N3 to move to ACCEPTED WITH OPEN ITEMS. The sibling corrections in section 3 are required before the interfaces module can implement `umas init`.
