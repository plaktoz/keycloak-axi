# Tasks: kc-axi spec, Podman and desired state (started 2026-10-25, revised 2026-10-27)

Scope: revise `libs/kc-axi/README.md` to draft v0.4 (current). v0.3 and v0.2 are superseded.
- Podman is the primary runtime, with exact `up`, `down` and `status` behaviour.
- Realm settings, clients and users are managed as desired state (`plan`, `apply`), in two files.
- Client secrets are kept in a local secrets file with numbered generations.
- The library stays independent of UMAS and general enough for reuse elsewhere.

Nothing in this list is committed. Commit only when asked.

The implementation task list is `docs/tasks-kc-axi-implementation.md` (written 2026-10-27).

## Decisions taken (2026-10-27)

All recommended defaults were accepted by the owner ("accept defaults"), plus these explicit answers:
- Desired-state configuration (item 5). Structure B: one tool, one format, two files (config and users).
- `export-realm` is in scope, full realm including users, with users in the separate file.
- Secrets: a separate plain file outside the repository, owner-only, with local numbered generations ("version it").
- Keep kc-axi independent and general. It will be reused outside UMAS.
- No web search tool (CLAUDE.md, Rules).

Owner answers to the 14 open decisions and Q14/Q15 (2026-10-27), applied in v0.3:
- Scope local only; remote writes refused unless `--allow-remote` (guard). Decision 1.
- `KC_HOSTNAME` set through the `hostname` key (6a). Subprocess with `--json` (7). Marker holds the owner name (8b).
- v1 field lists fixed; removed fields keep their server value (9a, 9c). Emergency disable refuses re-enable unless `--allow-reenable` (10a).
- Keycloak 26.x, tested at both ends, starting with 26.6.4 (11b). Adopt captures the live secret (12a).
- Admin password changed by hand, then copied back into the password source (13a). `id` required on every user, username lookup for existing admins (3, 4).
- Q14: `--yes` on every write that changes Keycloak or deletes local data, and on `down --purge`, `secrets rotate|restore|prune`, `disable-user`, `disable-client`.
- Q15: AXI conformance; deviate only where not possible. Section 10 lists deviations.
- Defaults applied from the owner's default list: preflight refusals before writes, exit 1 `apply_partial` with counts, canonical `plan_hash`, git-work-tree refusal (exit 2), lock file, audit before change, mapper actions after their client, export skips hand-made clients, duplicate keys refused, timeouts as keys, no retry on writes, Windows permissions stated.
- Memory sizing (section 11, item 13), decided 2026-10-27: option D. Spec states a 4 GiB engine minimum, no default heap cap. When `oom_killed` is true, `container_exited` prints the suggested `java_opts` value in its help line. Revisit a preflight check (option C) after the Docker test. Done in v0.4 (2026-10-27): the "owner accepts this as the default" wording is gone, and the help line of `container_exited` prints the suggested `java_opts` value when `oom_killed` is true (sections 4.4, 5.3, 7; section 11 item 29).

New live facts (2026-10-27) recorded in section 11, items 6 to 20 of v0.3:
- `KC_HOSTNAME=127.0.0.1` gives the same `iss` for `localhost` and `127.0.0.1` (closes access-control gap 18).
- Service-account user `id` equals the service token `sub`. User token `aud` is a string, service token `aud` is a list.
- Disabled user: introspection `active: false` at once. Logout returns 204. Disabled client: introspection `active: false`, new token request 401.
- Client created with a fixed `id` keeps it. `POST /users` ignores `id`; `partialImport` keeps it. `OVERWRITE` drops fields.

## Tasks

- [-] **K1. Specify the Podman CLI execution model.** Reopened 2026-10-27. The first pass passed the admin password as `-e NAME=<value>`, which put it in the process list. It also claimed edits to section 5.4 and section 5.5 that were not made. Superseded by K6.
- [-] **K2. Rootless execution, SELinux labels, credential injection.** Reopened 2026-10-27. The first pass added `:Z` automatically to every host path and stated rootless UID mapping as fact without a test. Superseded by K6.
- [x] **K3. Record Podman as the primary runtime.** Section 11, item 1. Verified by reading.
- [x] **K4. Repository consistency.** `libs/README.md` still matches (one row, language row, build order). Re-check after K9. Verified by grep.
- [-] **K5. Caller assessment (first pass).** Not valid. It was not a separate subagent, it had no report file, and it missed the password in the process list. Replaced by K8.
- [x] **K6. Rewrite the spec as draft v0.2.**
  - Acceptance: the spec has sections 3.4 (desired-state files), 3.5 (secrets file), 5.3 (`up`, `down`, `status`, volume rules), 5.6 (`plan`, `apply`), 5.7 (`export-realm`) and 5.8 (secrets). It also has criteria 13 to 26 and the section 11 decisions.
  - Acceptance: the section numbers cited by `umas/modules/access-control/access-control-spec.md` (4, 5.2, 5.3, 5.4, 6, 7, 9) still exist.
  - Result: done. Verified by reading and by grep for the cited section headings.
- [x] **K7. Live check of the open questions.**
  - Acceptance: each of section 11, items 6, 8, 9, 10, 14 and 15 records a result from a real run, or says what was not tested.
  - Result: done on 2026-10-27. Keycloak 26.6.4 ran in rootless Podman 6.1.4 on macOS arm64, in a Podman machine with SELinux enforcing. Throw-away containers and volumes were removed afterwards. The pulled image `quay.io/keycloak/keycloak:26.6.4` is kept.
  - Findings that changed the spec:
    - The plain user create ignores `id`. `partialImport` keeps it.
    - `OVERWRITE` drops fields.
    - Client `GET` returns the secret in plain text.
    - A 2 GiB Podman machine killed the container for lack of memory.
  - Not tested: Docker (not installed, item 11), native Linux (item 9), Windows.
- [x] **K6a. Independence.** Example data and the open question that named UMAS are made generic. One general safety rule moved from section 9 into section 5.4. Criterion 26 added.
  - Acceptance: a case-insensitive search for UMAS terms outside section 9 finds only the header independence statement.
  - Result: verified by grep on 2026-10-27.
- [x] **K6b. Rewrite the spec as draft v0.3.** Applies the owner answers above. Acceptance: every round-1 blocker has a section that answers it, and section 8 criteria cite the live facts. Result: written 2026-10-27. Verified by reading only. Not yet checked by a caller (K8 round 2).
- [ ] **K8. Caller assessment gate.** Three separate devil's-advocate subagents, one for each caller. Round 1 (done, REJECTED three times) is below. Round 2 runs on v0.3 with fresh subagents. Stop after round 2 and take the remaining gaps to the owner.
  - Round 2 status: `[x]` done on 2026-10-27, on draft v0.3. Reports: `docs/assessments/caller-assessment-kc-axi-<caller>-round2-2026-10-27.md`.
    - interfaces: REJECTED. 3 blockers (N1 secret reader contract, N2 re-enable guard, N3 partial-run JSON), 9 majors, 8 minors. Disposition: each blocker has an owner answer (K18). Applied in v0.4.
    - external-reuse: REJECTED. 2 blockers (B1 unmanaged as action, B2 reader contract), 17 majors, 19 minors. Disposition: B1 and B2 have owner answers (K17). Applied in v0.4.
    - access-control: ACCEPTED WITH OPEN ITEMS. 0 blockers, 12 majors (N1 to N12), 27 minors. Disposition: owner answers D2 and D6 (K19). The other open items are applied in v0.4 or stay in section 11.
    - Owner decided on 2026-10-27: stop after round 2. No round 3 (option 1).
    - Caveat: the non-decision majors and minors of the three reports are applied in v0.4 by a single rewrite. Each finding is not re-verified one by one against the report text. A round 3 would check that, and the owner declined it.
  - Round 1, for reference:
  - access-control: `docs/assessments/caller-assessment-kc-axi-access-control-2026-10-27.md`. Verdict: REJECTED. 5 blockers, 16 majors, 14 minors. Six items need an owner decision (report, "Needs a user decision"). Revision waits for those decisions.
  - interfaces: `docs/assessments/caller-assessment-kc-axi-interfaces-2026-10-27.md`. Verdict: REJECTED. 5 blockers, 22 majors, 13 minors (the report's own counts; its table has 40 rows). Decisions 1 to 6 of the interfaces report merge into the owner decision list below. Revision waits for those decisions.
  - external reuse (a consumer outside UMAS, because the library is to be reused): `docs/assessments/caller-assessment-kc-axi-external-reuse-2026-10-27.md`. Verdict: REJECTED. 5 blockers, 33 majors, 17 minors (the report's own counts; its table has 55 rows). Nine items need an owner decision (report, "Needs a user decision"). Revision waits for those decisions.
  - Next if any verdict is REJECTED: revise the spec, then round 2 with fresh subagents. Stop after round 2 and bring the remaining gaps to the owner.
- [ ] **K11. Linux and Podman verification (separate task).** Decided 2026-10-27 (decision 2, option B, with changes from the owner: "ignore windows for now. focus on linux and podman first. do that separately").
  - Scope: native Linux with rootless Podman. Persistence across restart on a named volume (section 11, item 9), and criterion 17. Windows is out of scope for now. Docker is a later task.
  - Acceptance: on a Linux host, `up`, create a realm and a client, `down`, `up`, and the realm and client are still there. Record the command output, the Linux distribution, the Podman version and the SELinux mode in this file.
  - Status: not run. This needs a Linux host or VM. The current host is macOS only. No person has run this check yet.
- [ ] **K12. Docker verification (separate task, after K11).** Decided 2026-10-27. Acceptance: criterion 10 on a host with Docker installed. Status: not run.
- [-] **K13. Windows verification.** Not run. Excluded for now by owner decision 2 (2026-10-27): "ignore windows for now". Windows statements in the spec stay marked "verified by reading".
- [x] **K14. Add `reset-password` command (decision 3, option A, 2026-10-27).** Owner answer: "A. Dedicated command". Written into v0.4 (sections 4.2, 5.11, criterion 58). The test acceptance below stays open until the tool exists.
  - Spec change needed: add `kc-axi reset-password USERNAME [--realm R] [--yes]` to section 4.2. It sets the temporary password from `temporary_password_env` with `reset-password` and `temporary: true`. It writes audit records (section 3.3). `apply` never writes a credential to an existing user. Remove the "documented gap" wording in section 5.6 and section 11 item 16, and add a criterion to section 8.
  - Acceptance: a test shows a user with no password is repaired by `reset-password`, with one audit `intent` and one `result` record. Status: not run.
- [ ] **K15. Remove the TOON claim (decision 4, option A, 2026-10-27).** Owner answer: "A. Drop the TOON claim".
  - Spec change needed: rename "compact form" to "compact list form" everywhere. Remove "subset of TOON" and the TOON-compliance row in section 10. Remove open item 21 in section 11. State the rules in section 4.3 as the contract. Keep the uniform-array shape described in `libs/README.md`, and check the wording against that file.
  - Acceptance: a case-insensitive search for "TOON" in `libs/kc-axi/README.md` finds nothing except a note that the format is not TOON. Status: not run.
- [ ] **K16. Secret-leak test gate (decision 5, option A, 2026-10-27).** Owner answer: "A. Test-suite gate".
  - Acceptance: once the tool exists, a test puts a known secret into a fixture realm. It runs every command with and without `--json`, and it fails if the secret appears in any output, the export files, or the audit file. Criterion 42 stays `not run` until this test passes. Status: not run, and blocked on the tool existing.
- [ ] **K17. Round 2, external-reuse: fixes from owner decisions (2026-10-27).** Report: `docs/assessments/caller-assessment-kc-axi-external-reuse-round2-2026-10-27.md`. Verdict REJECTED: 2 blockers, 17 majors, 19 minors.
  - B2 (secret access). Owner answer: option 2, documented file format. Spec change: section 3.5 and 5.8 define the file as the consumer interface. State the JSON shape, the path rules, the file mode check, the `pending` rule (a reader uses only `active`), and the rule that a reader never prints the value. Remove "the only library function" wording for the reader. No `secrets exec`, no `secrets get`.
  - B1 (unmanaged clients). Owner answer: option 1, informational. Spec change: section 5.6 step 4 and section 4.3 plan output. Unmanaged clients go under their own key, `unmanaged`. They are outside `actions`, `total`, `plan_hash` and the exit code. Built-in clients are never listed.
  - Acceptance: a realm with only managed clients and the built-in clients returns `status: no_change` and exit 0. Status: not run.
  - Owner answers to the external-reuse decisions (2026-10-27):
    - D3 `disable-client` is sticky, like users. `apply` does not re-enable it unless `--allow-reenable`.
    - D4 `down` needs `--yes` when the volume is not persistent.
    - D5 Test whether `partialImport` with a credential sets a password on an existing user. Fall back to `reset-password` (K14) if it does not. Test not run.
    - D6 `owner` lives in the config file only. The tool config file no longer holds it.
    - D7 Opt-in: `export-realm --include-unmanaged` writes hand-made clients, marked `unmanaged`, so `apply` does not change them. Default skips them.
    - D8 Non-26 server: owner answer "Warn and continue". The reviewer recommended refusing with exit 2. The owner chose the warning. Record the tested range in the spec, and print a warning on stderr when the server is outside 26.x. Tested behaviour is not promised outside 26.6.4.
    - D9 `secrets_path` is a directory. Each realm has `<realm>.secrets.json` inside it.
    - D10 Loopback is a fixed list: `127.0.0.1`, `::1`, `localhost`. No DNS lookup. Other hosts need `--allow-remote`.
- [ ] **K18. Round 2, interfaces: REJECTED (3 new blockers).** Report: `docs/assessments/caller-assessment-kc-axi-interfaces-round2-2026-10-27.md`. Counts: 3 blockers (N1 secret reader contract, N2 re-enable guard, N3 partial-run JSON), 9 majors, 8 minors.
  - Owner answers (2026-10-27):
    - D1 (N2): guard with audit. `apply` refuses when `audit_path` is empty (exit 2). `enable` is an audit action. The guard covers clients as well as users.
    - D2 (N1): typed errors. The secret reader raises errors that carry the section 4.4 codes.
    - D3 (N3): partial-run counts sit in the `error` object. `status: partial` is removed.
    - D4: a refused write without `--yes` prints the `plan` keys as a preview.
  - More owner answers (2026-10-27):
    - D5 `status` exits 1 for `runtime_ambiguous` and `runtime_missing`. It exits 0 when the server is unreachable.
    - D6 The remote guard applies to every Keycloak write: `disable-user`, `disable-client`, the `secrets` writes and `export-realm`.
    - D8 `config_missing` (exit 2) is the typed code for any value that no flag or variable supplies.
    - D9 A declared client with another owner's marker exits 1 with `owner_conflict`, before any write.
    - D10 The lock is taken before the plan read. It covers `apply`, `disable-*`, `up`, `down` and `export-realm --capture-secrets`.
- [ ] **K19. Round 2, access-control: ACCEPTED WITH OPEN ITEMS.** Report: `docs/assessments/caller-assessment-kc-axi-access-control-round2-2026-10-27.md`. Counts: 0 blockers, 12 majors, 27 minors. All five round-1 blockers resolved.
  - Owner answers (2026-10-27):
    - D2 The service principal key is `clientId`. The token `azp` equals it. A rename is a new principal.
    - D6 Accept the crash window. Consumers must not start while a generation is `pending`. The next `apply` finishes the job.
  - Already answered elsewhere: D1 (K14 `reset-password`), D4 and D5 (emergency-stop memory and client re-enable, by the interfaces D1 answer), D7 (launcher reads one value and passes it to one service, section 5.8).
  - Not a kc-axi decision: D3, the `umas auth login` sign-in flow. It belongs to the access-control module. Owner decides it in that module's process.
  - Edits before the caller builds its seed and secret paths: N1 (built-in and hand-made clients), N2 (rebuilt realm with a file value), N3 (crash after client create), N4 (secret reader signature), N5 and N6 (emergency stop covers users only), N8 (failed `apply` output shape), N12 (`secret` plan action has no apply rule).
- [x] **K20. Close the pre-implementation decisions (2026-10-27).** Owner answers, all matching the recommendations:
  - D1 `reset-password` keeps `--file F`. The variable name has one source, the users file (section 4.2, section 11 item 35).
  - D2 Minimum Python is 3.11. Package name is `kc-axi` (section 11 item 26).
  - D3 Crash tests use one test-only variable, `KC_AXI_TEST_STOP_AT=<step>` (section 11 item 25). Step names are set at build time.
  - D4 `partialImport` test run live on Keycloak 26.6.4 (Podman 6.1.4, 2 GiB machine with `-Xmx640m`, throw-away container removed). A new user gets the password, `id` and `UPDATE_PASSWORD` from the create call. An existing user with no password stays unchanged under `SKIP`. `reset-password` is the repair path. Spec changes: section 5.6, section 11 items 22 and 11, new criterion 79.
  - Default applied: `secrets_dir` is created on first need, including for the `up` lock (section 11 item 36).
  - Test method note: a first run of part B failed on my own error (usernames of 2 characters, minimum 3). It was redone with valid names, and the result above comes from the redo.
  - Four unverified facts were checked live later the same day: items 21, 23, 27, and 28 with 30. Results are in spec section 11 and in `docs/tasks-kc-axi-implementation.md`.
  - Correction (2026-10-27): the D4 result above is partly wrong. `temporary: true` does not set `UPDATE_PASSWORD`. The D4 test had sent `requiredActions` itself. Spec section 5.6, item 22 and criterion 79 are corrected.
  - New item 38 (duplicate email returns HTTP 500 from `partialImport`, and missing profile fields block sign-in). Decided 2026-10-27, option A: refuse duplicate emails in preflight (`email_duplicate`), list incomplete profiles in `plan` (`profile_incomplete`). Criteria 80 and 81 added.
- [x] **K6c. Rewrite the spec as draft v0.4.** Applies every owner answer of K14 to K19, and the non-decision fixes of the three round-2 reports. Acceptance: (a) the case-insensitive word search for "umas" outside section 9 finds nothing; (b) criterion 57 does not contain the word; (c) "TOON" appears only in the note that the format is not TOON; (d) `reset-password` has a section, a command row and a criterion; (e) criterion 11 requires no Linux or Windows host. Result: written 2026-10-27. Checks (a) to (c) passed by grep. The (d) and (e) items were checked by reading. The word "umas" appears once in section 9 and once in the word "umask", which was then reworded.
- [x] **K9. ste-docs pass and HTML twin.** Done 2026-10-27 on draft v0.4.
  - Result: 28 sentences over 20 words were rewritten. A re-run counts 4 remaining, all code-list table cells (JSON key lists and error-code lists), not prose. Banned-word search: 0 hits in the `.md` file and 0 in the visible text of the `.html` file.
  - Result: HTML tags balanced; 11 internal links, 0 broken; 11 `h2` and 25 `h3` in both files, with equal text; 0 Mermaid blocks and 0 `svg` blocks (the spec has no diagram). Headless Chrome rendered the page. Two converter faults (an escaped pipe, and wrapping in narrow table cells) were fixed and re-rendered. A viewed part of the page covers sections 1 to 4.4. Sections 4.5 to 11 were checked by the structure checks only, not by eye.
  - Deviation: the template `mods/cache-warm/README.html` does not exist in this repo, and a search of the home directory was stopped. The HTML uses a head and a style block written for this file, with light and dark theme tokens. It is built by a stdlib-only script at `/tmp/kcaxi_build/md2html.py`, which is not kept in the repo. Regenerate it by hand if the spec changes, or move a converter into the repo first.
  - Not run: the `ste-docs` section 8 of `technical.md` (eight-section layout, line-number table). The repo convention keeps the library spec layout.
  - Acceptance: sentences of 20 words or fewer, and zero banned words.
  - Acceptance: `libs/kc-axi/README.html` exists with the same headings.
  - Acceptance: the section 7 checks of the `ste-docs` skill pass, with real output recorded here.
  - Note: the repo convention (CLAUDE.md, structure reference `libs/hook-store/README.md`) keeps the library spec layout, not the skill's eight-section layout.
- [-] **K10. Sync the documents that cite kc-axi.** Partly done 2026-10-27. `libs/README.md` is synced (kc-axi row, fit table row, AXI open point 1). The three UMAS files are not edited: each belongs to its own module process. Their stale lines are listed in the next bullet for the module owners.
  - Stale lines, UMAS side:
    - `umas/modules/access-control/access-control-spec.md` line 126 and line 154 (command and section cites); line 155 (kc-axi section 4 and 9); lines 203 to 210 (kc-axi parameter rows: add `hostname`, `audit_path`, `secrets_dir`, `volume_options`, `java_opts`; `owner` is in the config file only); line 210 (`umas init` credential: add that `reset-password` repairs a user with no password); line 391 (kc-axi exit 4 no longer exists: exit codes are 0, 1 and 2 with typed codes); line 554 ("plain key-value output, stderr errors and exit codes 3 to 7" is stale).
    - `umas/modules/interfaces/interfaces-spec.md` line 454 (still correct: not used by the runtime); lines 588 and 603 (cite kc-axi exit codes 3 to 7, stderr errors and default limit 3, which v0.4 no longer has).
    - `umas/TECHNICAL-DESIGN-SPEC.md` A.2.1 (line 1236): "optional frozen build for Linux and Windows" is stale (Python package; Windows out of scope for now).
  - Acceptance: these files match draft v0.4 (round 2 is closed, and the owner chose no round 3). `libs/README.md` (kc-axi row, AXI open point 1), `umas/modules/access-control/access-control-spec.md` (section 5.3 and 5.6 seed steps, kc-axi parameter rows), `umas/modules/interfaces/interfaces-spec.md` (kc-axi remarks), and `umas/TECHNICAL-DESIGN-SPEC.md` A.2.1.
  - Owner: the module that owns each file. A change there follows that module's own process.
