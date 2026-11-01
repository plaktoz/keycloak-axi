# Tasks: kc-axi implementation (written 2026-10-27)

Spec: `libs/kc-axi/README.md`, draft v0.4. Spec history and decisions K1 to K20 are in `docs/tasks-kc-axi-podman-spec.md`.
Criteria are cited as `C<n>` (section 8 of the spec). Spec sections are cited as `§`.

Nothing in this list is committed. Commit only when the owner asks. Once asked, commit after each task.

## State markers

`[ ]` open · `[x]` done · `[-]` not done, with the reason. Each task records its result and how it was verified.

## Standing rules for every task

- Language: Python, minimum 3.11. Package name `kc-axi`. Console script `kc-axi` (K20 D2).
- Cross-platform: the code must run on Linux and macOS. Windows is out of scope, but do not block it. Review each task for `/` path joins, `HOME` without `USERPROFILE`, POSIX-only shell calls, `python3`-only calls, missing `encoding="utf-8"` and CRLF handling. Mark what no one ran as "verified by reading".
- Independence: no UMAS name, path or import in the package, tests or docs outside spec §9. C57 enforces this.
- No secret in any output, export, audit record or log (C7, C8, C42).
- Test seam: crash tests use only `KC_AXI_TEST_STOP_AT=<step>` (K20 D3). Step names are set at build time and listed in the package README.
- The agent doing a task tests it against that task's acceptance criteria. Tests that need a container runtime carry a marker and skip when no runtime is present. A skipped test is not a pass.
- Sub-agents: I2a ran first, because the others share its modules. I2b, I2c, I3, I4 and I8 ran in parallel on 2026-10-27, one subagent each, each in its own module (`config.py`, `audit.py`/`lock.py`/`paths.py`, `keycloak.py`, `runtime.py`, `secrets_store.py`). All five reported. The lead re-ran each test file and the whole suite (417 passed, 4 skipped). Only I3 ran a live Keycloak (container `kc-axi-i3`, removed). Still open: wire the I2c lock and `unsafe_path` into I8, and the CLI wiring for I2b, I3 and I4.

## Defaults picked (the owner can change them)

- Layout: `libs/kc-axi/pyproject.toml`, source in `libs/kc-axi/src/kc_axi/`, tests in `libs/kc-axi/tests/`. No other lib has code yet, so there is no precedent.
- HTTP: the standard library (`urllib.request`). Reason: spec §1 promises a small tool. Change only if a test shows a gap.
- Runtime dependencies: allowed. Decided by the owner 2026-10-27: add `PyYAML`, and drop the earlier "no runtime dependency" rule. Keep the list short. Record each new dependency here with its reason.
  - `PyYAML`: the spec requires YAML with a safe loader (§3.4, §6.1), and the standard library has no YAML parser.
- Tests: `pytest`, as a dev dependency only.
- Build backend: `hatchling`. Reason: it is a standard, pure-Python backend.

## Gate

- [x] **I0. Owner go-ahead to start code.** CLAUDE.md step 1 and 2a.
  - Caller gate status: spec v0.4 had two rounds. Round 2 gave interfaces REJECTED, external-reuse REJECTED, access-control ACCEPTED WITH OPEN ITEMS. The owner chose no round 3 (K8). v0.4 has had no caller review.
  - Acceptance: the owner confirms that code starts on v0.4 without a round 3. Record the answer here.
  - Status: `[x]` done 2026-10-27. Owner answer: "Go ahead and start I1". Taken as the go-ahead to start code on v0.4. The owner did not ask for a round 3. Item 38 was decided before (option A).

## Build tasks

- [x] **I1. Scaffold, CLI skeleton and exit codes.** Spec §4.1, §4.5, §10.
  - Does: `pyproject.toml`, package, console script, argument parser with the full command list, `--version`, no-argument view, unknown-flag handling.
  - Acceptance: C51 (no-argument view needs no network or runtime, prints `bin` and `description`). C52 (`--version` reads no file). C53 (unknown flag exits 2 with `flag_not_valid` and lists the valid flags). `pip install` of the package in a clean venv gives a working `kc-axi` command on Python 3.11.
  - Status: `[x]` done 2026-10-27.
  - Result: `libs/kc-axi/pyproject.toml`, `src/kc_axi/` (`cli.py`, `errors.py`, `output.py`, `config.py`), `tests/test_cli_skeleton.py`. No runtime dependency.
  - Verified: `pytest` 15 passed on Python 3.11.17 (macOS arm64). A non-editable install into a clean 3.11 venv gave a working `kc-axi`. The no-argument view, `--version`, `python -m kc_axi` and the unknown-flag error (default view and `--json`) were run by hand with the expected exit codes 0, 0, 0 and 2.
  - Scaffold choices: commands not built yet exit 2 with `usage` ("not built yet"). `errors.py` and `output.py` hold only what I1 needs. I2a extends them.
  - Cross-platform: the config path has a `USERPROFILE` fallback and uses `%APPDATA%` on Windows. Path joins use `pathlib`, and test files are written as UTF-8. Linux and Windows are verified by reading only. The Linux and Windows path tests are unit tests with a faked platform.
  - For I2b: I2b adds `PyYAML` (`safe_load`, with a loader that refuses duplicate keys). The owner approved it on 2026-10-27 (see "Defaults picked").
- [x] **I2a. Output encoder and error registry.** Spec §4.3, §4.4, §7 (Error records).
  - Does: the compact list form, `--json`, `--fields`, `--limit`, `shown of total` header, definitive empty states, errors on stdout, one typed-code table with exit codes.
  - Acceptance: C2, C3, C54, C55 (every typed code in §4.4 has a test with its exit code). A golden-file test for each default view.
  - Depends on: I1.
  - Status: `[x]` done 2026-10-27. Done by the main agent, not a subagent: I2b to I8 all depend on its shared modules (`errors.py`, `output.py`, `cli.py`).
  - Result: `errors.py` holds the full §4.4 table (59 codes: 22 exit 2, including `usage` and `flag_not_valid`, and 37 exit 1). `resources.py` holds the §3.2 field sets and `--fields` selection. `output.py` adds `Records`, `page()` (`shown of total`), `list_payload()` (empty and cut lists), CSV-quoted rows, 200-character cells and JSON with `schema_version`. `render_compact` refuses raw row lists, so a list cannot skip its count.
  - Verified: `pytest` 91 passed on Python 3.11.17 (macOS arm64), 15 from I1 and 76 new. C1, C2 and C3 have tests with golden files in `tests/golden/`. C54 has JSON tests. C55 reads the §4.4 table from `libs/kc-axi/README.md` and compares it with `EXIT_CODES`, so a spec change that is not in code fails the test.
  - Not run: the golden files cover the default views only. The real list commands (I5) are not built, so C1 to C3 are `partly run` in the spec until I5 uses these functions.
- [x] **I2b. Configuration loading.** Spec §3.1, §4.1, §6.1, §6.2.
  - Does: precedence flag, variable, tool config file, default. `config_missing` for a value no source supplies. Timeouts as keys. Unknown keys refused.
  - Acceptance: C65. Each key of §6.1 has a test for its default and for each override source.
  - Depends on: I1.
  - Status: `[x]` done 2026-10-27.
  - Result: `config.py` gains `load_settings`, `require`, the frozen `Settings` dataclass, a strict YAML loader (duplicate keys refused), `~` and relative-path rules. `default_config_path` and `resolve_config_path` keep their signatures. `pyproject.toml` adds `PyYAML>=6.0.3` (approved by the owner). `tests/test_config_loading.py`.
  - Verified: `153 passed` (re-run by the lead with I1: `168 passed`). C65 passes. Each §6.1 key has a default test and a file-override test. Keys with a flag or variable also have a variable test.
  - Not run: Linux and Windows, verified by reading only (the Windows `~\` branch and the `USERPROFILE` fallback).
  - Open: `KC_ADMIN_PASSWORD` is not read here, and no task reads it yet (§5.4). The spec's `hostname` comment names `KC_HOSTNAME`, which no variable table lists. Owner decision: add `KC_HOSTNAME` to §6.1 (recommended), or drop the comment. Relative paths in variables resolve from the working directory, as flags do (recommended, owner to confirm).
- [x] **I2c. Audit file, lock and safe paths.** Spec §3.3, §5.4, §5.8 (lock).
  - Does: JSON-lines audit with `intent` before and `result` after. `audit_required`, `audit_failed` preflight, `audit_incomplete`. Lock file `kc-axi.lock` in `secrets_dir`, created on first need (K20 default). `unsafe_path` for a path inside a git work tree. Owner-only file modes on Linux and macOS.
  - Acceptance: C12, C49, C56 (needs the seam), C67, C69, C76. A test shows `secrets_dir` is created on first need.
  - Depends on: I1.
  - Status: `[x]` module-level done 2026-10-27. The commands that call these modules are not built yet, so C12, C49, C67, C69 and C76 are proven at module level only.
  - Result: `src/kc_axi/audit.py`, `lock.py` (fcntl on POSIX, msvcrt by reading), `paths.py` (git work-tree check by walking up for `.git`, a directory or a file), `tests/test_audit_lock_paths.py`.
  - Verified: `29 passed` (re-run by the lead). C12, C49, C67, C69 and C76 pass. C56 is partly run: a failed result write gives `audit_incomplete`, but the interrupted-process case needs the I12 seam.
  - Open: the spec does not give a code for a failed intent write (the agent used `audit_failed`). It does not set the audit file mode (the agent used 0600). It does not say whether missing parent directories get mode 0700 (the agent gave 0700 only to the last directory). Owner decision: keep `audit_failed` for the intent write (recommended), and confirm whether `audit_path` gets the git work-tree check (recommended: no for v1).
- [x] **I3. Keycloak REST client.** Spec §4.4, §5.1, §5.4, §6.2.
  - Does: admin token (password grant on `admin-cli`), timeouts, no retry on writes, typed errors (`keycloak_unreachable`, `auth_failed`), loopback guard with the fixed list (`localhost`, `127.0.0.1`, `::1`) and `--allow-remote`, server version warning outside 26.x.
  - Acceptance: C4, C5, C27 and C28 (guard part), C71 (a timed-out write is not retried), C72.
  - Check V4 (item 21) is done as a live check: the admin token lives 60 seconds, so the client must fetch a new token on a long run.
  - Depends on: I1.
  - Status: `[x]` done 2026-10-27.
  - Result: `src/kc_axi/keycloak.py` (standard library only, no proxy, no redirects) and `tests/test_keycloak_client.py`. Fake HTTP server for the unit tests. Three live tests marked `runtime`.
  - Verified: without a container, `63 passed, 3 skipped`. With a live Keycloak 26.6.4 on port 18083, `66 passed`. Re-run by the lead: `63 passed, 3 skipped`, and no container left (`podman ps -a` empty).
  - V4 live: good password gives 200, `expires_in` 60, refresh token. Wrong password gives 400, mapped to `auth_failed`. A run of 61 seconds logs in a second time and still reads. Container `kc-axi-i3` removed.
  - Criteria: C4, C5, C71, C72 pass. C27 and C28 pass in the guard part only, the command-level refusal waits for the commands.
  - Open: §7 says a timed-out write gives `apply_partial`, but the client gives `keycloak_timeout`. `apply` must map it (owner decision, see the report). Podman machine memory is 2 GiB here, and the §5.0 minimum of 4 GiB is not confirmed.
- [x] **I4. Container runtime: `up`, `down`, `status`.** Spec §5.2, §5.3, §5.3.1, §5.5, §5.10. Done 2026-10-27, stub tests only. The real-runtime checks wait for the lead (see below).
  - Result: `src/kc_axi/runtime.py` and `tests/test_runtime.py`. Stub `podman` and `docker` scripts on PATH (POSIX only). A fake Keycloak for the ready wait. No container was started.
  - Verified: `56 passed, 1 skipped` (the skip needs `KC_AXI_RUNTIME_TESTS=1`). Re-run by the lead: `56 passed, 1 skipped`. C8, C9, C13, C14, C15, C16, C64 pass with stubs.
  - Not run: C10 (Docker) and C17 (persistence) stay open, as the task says. Real-runtime checks, in order: (1) read-only `KC_AXI_RUNTIME_TESTS=1 .venv/bin/python -m pytest -q tests/test_runtime.py -m runtime`; (2) live `up`, `status`, `down --purge --yes`, after the CLI wiring; (3) C10 and C17 on hosts that have them.
  - Decided by the owner 2026-10-27 (spec §11 item 39): 1C, plain `down` is idempotent only for `runtime: auto` with nothing installed, and a named runtime that is missing gives `runtime_missing` (code changed in `_resolve`); 2A, `down --purge` with both runtimes and no container gives `runtime_ambiguous` (already the behaviour); 3A, no `unsafe_path` check on `audit_path`. Both runtime rules have tests (C82, C83): `58 passed, 1 skipped`.
  - Open: the Podman machine is now 4 GiB, so the real `up` can run. The `port_in_use` and OOM checks match runtime message text, and Podman's wording is not verified. Real-runtime check 1 verifies it.
  - Does: runtime choice (Podman first, Docker), `runtime_ambiguous` and `runtime_missing`, image rules, no password in any runtime argument, volume rules, readiness with early `container_exited`, `down --purge` rules, `down` needing `--yes` on a non-persistent volume, `java_opts` hint when `oom_killed`, admin password change flow.
  - Acceptance: C8, C9, C13, C14, C15, C16, C64. C17 and C10 stay open until K11 and K12.
  - Note: `status` calls I3 for the server probe. The probe is passed in as a callable, so the CLI wiring must supply it.
- [x] **I5. Read commands.** Spec §4.2, §5.1.
  - Does: `realms`, `clients`, `users`, `get`, with counting and truncation.
  - Acceptance: C1, C2, C3, C23 (read side, built-in clients hidden from lists).
  - Depends on: I2a, I3.
  - Result: `src/kc_axi/credentials.py` (admin password: `KC_ADMIN_PASSWORD`, then `admin_password_file`, owner-only check), `src/kc_axi/reads.py`, the read path in `src/kc_axi/cli.py` (`connect`, `warn_version`, `run_read`), and `max_cell_chars` in `output.py`. Tests: `tests/test_read_commands.py` (51 tests, a fake Keycloak that copies the probed behaviour).
  - Verified: `470 passed, 4 skipped` for the whole suite. Live run against Keycloak 26.6.4 in Podman (throwaway realm with 109 clients and 109 users): counts and the `shown of total` header, the 100-user cap, no client secret in any output (0 hits), case-insensitive user lookup, `not_found`, `realm_required`. C1, C2, C3 and C23 (read side) pass.
  - Live facts (probed 2026-10-27): `/users` returns at most 100 rows without `max`, has `/users/count`, orders by username, omits service-account users. `/clients` has no cap and no count, has no fixed order, and returns `secret` for confidential clients. A username lookup ignores case; a `clientId` lookup does not. An unknown realm answers 404.
  - Defaults taken (veto in one reply):
    1. `managed` shows the owner name, or `null` for a client with no marker.
    2. `get client` finds a built-in client when it is named; only the lists hide them.
    3. `users` fetches one page of `limit` rows plus `/users/count`, not the whole realm. `clients` reads all clients and sorts them by `clientId`, because Keycloak gives no order.
    4. `get user` matches the username without regard to case and shows the stored (lower-case) name.
    5. A server outside 26.x prints `warning: ...` on stderr and the command still runs.
    6. `--fields` is checked before the login: a bad field exits 2 with no request.
  - Not run: Windows and Docker. The owner-only password-file check is skipped on Windows (verified by reading only).
  - Cleanup: the throwaway container `kc-axi-i5` and `/tmp/kc-axi-i5-probe` are removed.
- [x] **I6. Desired-state files and `plan`.** Spec §3.2, §3.4, §5.6, §4.3 (plan output).
  - Does: parse and validate both files, resource keys, field lists, `builtin_client`, duplicate-key refusal, marker and owner rules (`owner_conflict`), `unmanaged` list outside `actions`, `password_missing` list, canonical `plan_hash` with live values, exit 0 `no_change` and exit 1 `drift`.
  - Acceptance: C20 (plan part), C21 (hash part), C22, C23, C24, C25, C66, C68, C81. The `apply` halves of these criteria need I7.
  - Check V3 (items 28 and 30) is done as a live check: Keycloak adds no mappers to a service-account client. Repeat it through the tool.
  - Item 38 (option A) adds `profile_incomplete` to the `plan` output and `email_duplicate` to preflight. Acceptance adds C80 and C81. C80 (the preflight refusal) belongs to I9.
  - Depends on: I2a, I2b, I3.
  - Result: `src/kc_axi/desired.py` (load, check and normalise both files; no network), `src/kc_axi/plan.py` (`make_plan`, `PlanResult`, `canonical_json`), `compare_live` in `src/kc_axi/secrets_store.py` (fingerprints only), the `plan --file` command in `src/kc_axi/cli.py`. The shared strict YAML loader is `config.parse_yaml`. Tests: `tests/test_desired.py` (47) and `tests/test_plan.py` (59, a fake Keycloak with the probed shapes).
  - Verified: `576 passed, 4 skipped` for the whole suite. Live run against Keycloak 26.6.4 in Podman (realms with clients, mappers, secrets and users): all plan actions, a stable hash across runs, hash change when a live value changes, 0 secret hits in 3 outputs. V3 repeated through the tool: a new service-account client has no `protocolMappers` before or after its first client-credentials token, and `plan` with `mappers: []` shows no mapper row.
  - Live facts (probed 2026-10-27): `GET /clients` carries `protocolMappers` (only when present) and `secret`; `/users/{id}/credentials` returns `[]` for a user with no password; the mapper list lacks `userinfo.token.claim` while the per-client mapper endpoint returns it. Recorded in spec §5.6.
  - Defaults taken (veto in one reply):
    1. `plan` on a config file without `owner` exits 2, `owner_required`.
    2. Conflicts (`owner_conflict`, `id_conflict`) and secret situations are action rows, so `plan` exits 1 for them. `apply` turns them into refusals.
    3. `plan` on a users file for a missing realm exits 1, `realm_absent`.
    4. A users file is checked for mode and git work tree when `plan` loads it (exit 2).
    5. Usernames in one users file are unique without regard to case.
    6. A message names an unknown key only when it is close to an allowed key (a typo). Any other key is not echoed, so a secret put in a key never reaches an output.
    7. Only `audience` mappers are managed. Other mappers on a client are never touched.
  - Not run: Windows and Docker. The owner-only check on the users file is skipped on Windows (verified by reading only).
  - Cleanup: the throwaway container `kc-axi-i6` and `/tmp/kc-axi-i6-probe` are removed.
- [ ] **I8. Secrets store and reader.** Spec §3.5, §5.8.
  - Does: file format with generations `pending`, `active`, `retired`, 8-hex fingerprints, `server` identity check, owner-only mode check, the commands `secrets list|capture|rotate|restore|prune`, and the reference reader `read_secret(secrets_dir, realm, base_url, client)` that raises `KcAxiError` with a `code`. No command prints a secret.
  - Acceptance: C37 (the secrets-file half), C39, C40, C43, C44, C45, C75. C38, C41, C62, C63 and C73 need I7 and the seam.
  - Depends on: I2a, I2c. The commands that touch Keycloak need I3.
  - Status: `[ ]` partly done 2026-10-27. The file half is built and tested, and the lock and `unsafe_path` are not wired yet.
  - Result: `src/kc_axi/secrets_store.py` and `tests/test_secrets_store.py`. Covers the file format, `read_secret`, `write_pending`, `mark_active`, `restore_pending`, `prune_generations` and `list_generations`. No prints.
  - Verified: `25 passed` (re-run by the lead). Criteria C37 (file half), C39, C40 (file half), C43 (reader half), C44, C45, C75 pass.
  - Wired in I7 (2026-10-27): `unsafe_path` runs in `_write_document`; the caller holds the lock (`apply` does). The five `TODO(I2c)` markers are gone. I7 adds `check_file`, `has_pending`, `generation_value` and `stage_values`. Still missing: the `secrets` commands in `cli.py`, which take the lock themselves, and the Keycloak half of `capture`, `rotate` and `restore` (I8).
  - Spec gap: the file does not record pruned generation numbers, so `generation_pruned` is inferred from gaps. Owner decision: keep a `pruned` list in the file (recommended), or keep inferring.
- [x] **I7. `apply` for the config file.** Spec §5.6, §5.8 (apply rules). Done 2026-10-27, except C41 and C73 (they need the I12 seam).
  - Does: preflight refusals before any write, `--yes`, `--expect`, `--adopt`, `--allow-delete`, `--allow-reenable`, `--allow-remote`, mapper order, `secret_managed` flow, `apply_partial`, `plan_changed`, `confirm_required` with the preview.
  - Acceptance: C6, C18, C20, C21, C22, C24, C28, C33, C34, C37, C38, C41, C62, C63, C70, C71, C73, C77. C27 and C47 are users-file criteria and moved to I9.
  - Depends on: I2c, I3, I6, I8.
  - Caller assessment gate (2a): round 1 on 2026-10-27 rejected the spec, 4 blockers (B1 to B4). Report: `docs/assessments/caller-assessment-kc-axi-apply-config-2026-10-27.md`.
    - B2 (lock before safety checks) and B3 (missing secrets file) are fixed in spec §5.6 (steps 1 to 11) and §3.5, §7. Defaults taken: the file check, the `secrets_dir` path check and the audit open come before the lock; the directory and lock file are created only after them; a missing secrets file is not an error for `apply` and `plan`; an existing file that is unreadable or for another server is a preflight refusal.
    - B1 (pending-generation finish) and B4 (top-level code of a refusal) are open owner decisions: spec §11 items 40 and 41.
    - Owner decided 2026-10-27: item 40 option (a), a `finish_pending` row in `plan` (phase 0, first in apply step 9, audit `secret` pair, fingerprints in the hash). Item 41 option (a), the top-level code is the first refusal's code, every refusal in `refusals`, and `refused` is removed from the registry. Applied to spec §4.3, §4.4, §5.6, §5.8, §7, criteria 25, 31, 80, `plan.py`, `errors.py` and the two tests. Suite: 575 passed, 4 skipped (`test_output_errors.py` has one parametrised code fewer). The mechanical defaults from the gate note (below) are also applied in the spec (§5.6 steps 2 and 6, §3.5 missing-file rule). The owner has not reviewed them. They stand until the owner vetoes them.
    - Round 2 (fresh subagent, B2 and B3 only), 2026-10-27: not fixed. B2(a), B3(a), B3(b) and B3(c) remain, and the fixes created 2 new contradictions (`audit_failed` listed twice, `generation_pending` as an `apply` refusal). The gate stops after two rounds, so the remaining blockers are owner decisions. Verdict so far: **rejected**, 4 blockers open. Report: same file, section "Round 2".
    - Proposed defaults for the mechanical part (owner can veto): (1) `unsafe_file_mode` and `secrets_server_mismatch` stay exit 2, as §4.4, §3.5 and §7 say, and are checked in step 2 without a lock, read-only, so they leave the preflight list; (2) `audit_failed` leaves the preflight list, because step 3 raises it; (3) `generation_pending` is not a refusal in `apply`, it is the finish rule of item 40; (4) a missing secrets file: `apply` and `plan` treat it as empty, `secrets capture` and `export-realm --capture-secrets` create it, `secrets prune` answers `already`, `secrets rotate`, `restore` and the reader answer `secrets_unreadable`.
    - Majors M1 to M7 and the minors are in the report. They go to the fix list and are not reviewed one by one.
  - Owner accepted the four mechanical defaults ("ok", 2026-10-27). Gate closed by owner decision: B1 and B4 decided, mechanical defaults accepted, no third round. Implementation may start.
  - Owner answers 2026-10-27: 1A (a timed-out write is `keycloak_timeout`, no `ERR_TIMEOUT`), 2A (`secrets_dir` is set in the user's own config file; no code change), 3A (admin password from `KC_ADMIN_PASSWORD` or an owner-only `admin_password_file`; tests set the variable through `monkeypatch`, so no test depends on the machine).
  - Status: `[x]` done for the config file, except C41 and C73. Users-file `apply` is I9: it exits 2 `usage` ("not built yet") after the `--adopt`/`--allow-delete` check.
  - Result: `src/kc_axi/apply.py` (preflight, runner, `apply_config`), the `apply` command and flags in `cli.py`, `plan.py` (live client ids, `client` and `mapper` keys on mapper rows), `secrets_store.py` (four helpers), `audit.py` (`toggle_states`), `output.py` (`Records` inside an error object becomes a JSON array), `tests/test_apply.py` (45 tests, with a stateful fake Keycloak).
  - Verified: full suite `620 passed, 4 skipped` (the lead re-ran it). Passed through a fake Keycloak: C6, C18, C20, C21, C22, C24, C28, C33, C34, C37, C38, C62, C63, C70, C71, C77, and the `finish_pending` cases, `--adopt` capture, the lock, `audit_required`, `unsafe_path` and `unsafe_file_mode` before the lock. Not run against a real Keycloak: I13 repeats them. Windows: the lock branch is verified by reading only.
  - Not done: C41 and C73 (fault-injection seam, I12). The `secrets_missing` refusal applies to a client that already has the marker; an unmarked client with a live secret is `adopt` with `secret: capture`, which `--adopt` lifts.
  - Next: I9 (users file), I8 (the `secrets` commands), I12 (seam).
- [ ] **I9. `apply` for the users file.** Spec §3.4, §5.6.
  - Does: creates through `partialImport` with `SKIP`, partial `PUT` for changes, no delete, no `OVERWRITE`, `id` conflict refusal, temporary password on create, `UPDATE_PASSWORD`, read-back of the stored `id`.
  - Acceptance: C25, C26, C29, C30, C31, C32, C47, C78, C79, C80.
  - Check V2 (item 27, C59) is done as a live check. Repeat it through the tool.
  - The tool sends `requiredActions: ["UPDATE_PASSWORD"]` on create (item 22 correction). The test reads `requiredActions` from the stored user.
  - Item 38 (option A): preflight refuses `email_duplicate` for the file and for live users. Acceptance adds C80 and C81.
  - Depends on: I6, I7.
  - Status: not started.
- [ ] **I10. `export-realm`.** Spec §5.7.
  - Does: `--scope config|users`, `--owner`, skip hand-made clients, `--include-unmanaged`, `--capture-secrets`, `unsafe_path` check before any file is written.
  - Acceptance: C19, C42 (export half), C69 (export half), C74.
  - Depends on: I6, I8.
  - Status: not started.
- [ ] **I11. `disable-user`, `disable-client`, `reset-password`.** Spec §5.9, §5.11.
  - Does: the three commands with `--yes`, audit and the remote guard. `reset-password USERNAME --file F` (K20 D1).
  - Acceptance: C46, C48, C49, C50, C58. A test shows a user with no password is repaired by `reset-password` with one `intent` and one `result` record.
  - Check V1 (item 23) is done as a live check: a disabled user's refresh token fails. Repeat it through the tool.
  - Depends on: I2c, I3.
  - Status: not started.
- [ ] **I12. Fault-injection seam.** Spec §11 item 25.
  - Does: `KC_AXI_TEST_STOP_AT=<step>`. The tool stops at the named step with a documented exit. The variable is ignored when unset. The step names are listed in the package README.
  - Acceptance: C41, C56 and C73 run through the seam. A test shows that no other test hook exists.
  - Depends on: I2c, I7, I8. Build the hook points together with those tasks.
  - Status: not started.

- [x] **I19. Offline export helper in the runtime.** Spec §5.12 (export steps 4 and 5), §5.3.1.
  - Does: a stop helper for the container. A run of the image on the data volume, with `export --realm R --users realm_file --dir <dir>`, into a new owner-only directory under `secrets_dir`. The container starts again in a `finally`, also when the export fails. The check of the exported file and the removal of its directory are the callers' work (I20, I21). Refuse `--realm` values that are not a plain realm name, before any argument reaches the runtime.
  - Acceptance: C86 (restart on a failed export). Runtime stub tests. A live check of the export with the real image, on the throw-away server, is in I22.
  - Depends on: I4, I8.
  - Status: `[x]` done 2026-11-01. `runtime.export_realm_offline` stops the container, runs the image once as `<container>-export` on the data volume, copies `R-realm.json` out with `cp` (no host path is mounted, so no uid mapping problem on rootless Podman), and always removes the one-off container and starts the server again. A failed export is reported before a failed restart. A realm name that is not plain exits 2 `config_invalid` before any runtime call. Also registered `import_invalid`, `import_partial` and the `import` audit action, which the C55 registry test needed once the spec listed them. Spec §5.12 step 4 now describes the `cp` design. Verified: 11 new stub tests in `tests/test_export_offline.py`; full suite 633 passed, 4 skipped. Not run against a real runtime yet (I22).
- [x] **I20. `export-realm --scope full`.** Spec §5.12 (export), §4.1, §4.3, §5.7.
  - Does: `--scope full --out PATH`. Refuses `admin_realm`, an `--out` inside a git work tree (`unsafe_path`), a missing audit path, and an existing `--out` without `--yes`. Takes the lock, writes the `intent` record with action `export`, calls I19, checks the file (JSON, `realm` equals R, no admin password in it), writes it owner-only and removes the directory, then writes the `result` record. Output `status: written`. Any failure leaves no file at `--out`.
  - Acceptance: C84, C85, C86, and the export half of C69. The `scope` values `config` and `users` keep their I10 behaviour.
  - Depends on: I10, I19.
  - Status: `[x]` done 2026-11-01 for `--scope full` only. New `src/kc_axi/fullrealm.py` (`export_full`, `write_private`, `runtime_settings`), CLI flags `--scope` and `--out`, and `import-realm --file` parse. `--scope config|users` still exits 2 `usage` ("not built yet") until I10. The intent record is written through a `before_stop` hook, after the `not_found` check and before the container stops. The output file is written by temp file and rename, 0600, so a failure leaves nothing at `--out`. Verified: 8 tests in `tests/test_export_full.py`; mutation check (leak check removed, git check removed) makes the C84 leak test and the C85 test fail; full suite 641 passed, 4 skipped. Not run against a real runtime yet (I22).
- [x] **I21. `import-realm`.** Spec §5.12 (import), §4.1, §4.3, §5.7.
  - Does: `--realm R --file PATH [--yes] [--allow-remote]`. Checks the file before any change: owner-only mode (`unsafe_file_mode`), JSON (`import_invalid`), `realm` equals R (`realm_mismatch`), `users` and `clients` are lists (`import_invalid`). Local-scope guard (`allow_remote_required`). Without `--yes`, prints the counts of the file and of the live realm and exits 1 `confirm_required`. When the realm exists: backup through I19 and I20 steps (into `secrets_dir`, before any delete), `DELETE /admin/realms/{R}`, `POST /admin/realms` with the file. If the `POST` fails after the `DELETE`, sends the backup through the same `POST` and exits 1 `import_partial` with `backup` and `cause`. Output `status: replaced`.
  - Acceptance: C87, C88, C89, C90, C91. Rows for the codes `import_invalid` and `import_partial` in `errors.py`, and the `import` action in `audit.py`.
  - Depends on: I3, I19, I20, and the codes of I2a and the actions of I2c.
  - Status: `[x]` done 2026-11-01. `fullrealm.import_full` and `preflight_import`, CLI `import-realm --file`. All file, audit-path, admin-realm and local-scope checks run before the first request (exit 2 for the file). Without `--yes` it exits 1 `confirm_required` with the file and live counts. With a live realm: backup through `export_realm_offline` (intent record written before the stop), `DELETE`, `POST`; a `POST` failure sends the backup and exits 1 `import_partial` with `backup`, `cause` and `restored`. A realm that does not exist is created with no backup and no container stop. Verified: 15 tests in `tests/test_import_full.py` against a stateful fake of the two realm calls; mutation checks (delete before backup, no restore POST) make the C89 and C90 tests fail. Not verified: the real `DELETE` and `POST` on Keycloak (I22), and `restored: true` against a real server.
- [x] **I22. Live check of the full file.** Spec §5.12, §8 criteria 84, 87, 91 and 92.
  - Does: runs export and import against a throw-away Keycloak on port 8081, with a realm that has users with passwords, a signing key and a confidential client. Records the result of C92, which has not run yet. Removes the throw-away server and its volume after the run. Never touches the `keycloak-dev` data volume. Marked as needing a container runtime, so it skips without one.
  - Acceptance: C84, C87, C88, C89, C90, C91, C92 run through the tool. Each test result is written into the spec §8 status fields and the section 11 item 30 evidence.
  - Depends on: I13, I20, I21.
  - Status: `[x]` done 2026-11-01. Run on a throw-away server on port 8082 (container `kc-axi-i22`, volume `kc-axi-i22-data`); `up` is not wired yet, so podman started it. C84, C87, C88, C89, C90, C91 (key ids) and C92 passed through the tool. The run found a defect: an unwritable `secrets_dir` ended the backup step in a traceback. Fixed in `fullrealm._take_backup` (exit 1 `file_failed`) with a test whose mutation check fails without the fix. C85 and C86 were not run live. The port is 8082, not 8081 as planned, because `keycloak-restore` holds 8081.
- [x] **I23. Docs sync for the full file.** Spec §4.1, §5.7, §5.12, §8, §11 item 30.
  - Does: the package README (exit codes, the `import_invalid` and `import_partial` rows, the step names of I19), the spec status fields, and `python3 -I scripts/md2html.py README.md README.html`.
  - Acceptance: the code cross-check test of `errors.py` against spec §7 passes. The HTML twin is regenerated from the final spec.
  - Depends on: I20, I21, I22.
  - Status: `[x]` done 2026-11-01. Spec §4.1 `--runtime` row covers the full export and import. §7 recoverability table now lists `import_invalid` (permanent) and `import_partial` (transient); before this task the table lacked 17 registered codes, two of them new; 15 older codes are still missing and are not added here. §8 C85 and C86 record stub-test status, not live. The §4.4 cross-check (`tests/test_output_errors.py`) passes. README.html regenerated.

- [x] **I24. README tutorial.** README section "Tutorial: a throw-away Keycloak in 10 minutes".
  - Does: copy-and-paste steps for setup, a container named `keycloak-tutorial` on port 8081, `plan` and `apply`, full export and restore, a check after each step, and cleanup with checks. `up` is not wired, so step 3 uses `podman run`.
  - Status: `[x]` done 2026-11-01.
  - Verified: the bash blocks were extracted from the README and run in a fresh zsh on macOS, Podman 6.1.4, Keycloak 26.6.4. Output matched. The cleanup left no container, volume or folder, and `keycloak-dev` on 8080 kept running. Not run: Docker, Linux. No code changed, so the test count is unchanged.
  - Note: the owner removed `README.html` on 2026-11-01. I17 no longer needs to regenerate it.

## Test and release tasks

- [ ] **I13. Integration fixture.** Starts a throw-away Keycloak 26.6.4 with the tool's own `up`, and removes it after the run.
  - Acceptance: a command runs the integration suite on a host with Podman. On a host with no runtime, the suite skips and says why.
  - Depends on: I4.
  - Status: not started.
- [ ] **I14. Secret-leak test (K16).** Spec C7, C8, C42.
  - Acceptance: a test puts a known secret into a fixture realm, runs every command with and without `--json`, and fails if the secret appears in any output, export file or audit file. C42 stays `not run` until this passes.
  - Depends on: I5 to I11, I13.
  - Status: not started.
- [ ] **I15. Independence test.** Spec C57.
  - Acceptance: a test reads a list of names from a file outside the library and finds none of them outside spec §9.
  - Status: not started.
- [ ] **I16. Cross-platform review.**
  - Acceptance: the list of checks under "Standing rules" is run over the whole package. Each finding is fixed or recorded. Every part that no one ran on Linux is marked "verified by reading".
  - Depends on: I1 to I12.
  - Status: not started.
- [ ] **I17. Docs sync and HTML twin.**
  - Done early (2026-10-27): the HTML converter is now `scripts/md2html.py`. Run `python3 -I scripts/md2html.py libs/kc-axi/README.md libs/kc-axi/README.html` after each spec change.
  - Does: update spec status fields and criteria with real results. Check `libs/kc-axi/README.md`, then `libs/README.md`, for stale claims. Regenerate `libs/kc-axi/README.html`. Run the `ste-docs` section 7 checks.
  - Acceptance: criteria statuses match the test results. The `.md` and `.html` headings match. Zero banned words.
  - Depends on: all build tasks.
  - Status: not started. The converter move can be done at any time.
- [ ] **I18. Release gates K11 and K12.** Tracked in `docs/tasks-kc-axi-podman-spec.md`.
  - Acceptance: K11 (native Linux with rootless Podman, persistence across restart, C17) and K12 (Docker, C10) are done and recorded. Until then, the README must say these two are not verified.
  - Status: not started. Needs a Linux host and a Docker host.

## Unverified-fact checks

The owner asked to write the task list first and run these checks afterwards. All four ran on 2026-10-27 against a throw-away Keycloak 26.6.4 in rootless Podman 6.1.4 on macOS arm64. The container is removed. Each result is in spec §11. The tool is not built, so the criteria stay `partly run`. Each task below must repeat its check through the tool.

- [x] **V1. Refresh tokens after `disable-user` (§11 item 23).** Result: a refresh after `PUT enabled: false` returns 400 `invalid_grant` ("User disabled"). A new password grant also fails. After logout the refresh returns 400 ("Session not active"). `disable-user` needs no extra step. I11 repeats the check through the tool.
- [x] **V2. `sub` equals the users-file `id` (§11 item 27, C59).** Result: the `sub` of the user token equals the `id` sent in `partialImport`. I9 repeats the check through the tool.
- [x] **V3. Keycloak's own mappers on service-account clients (§11 items 28 and 30).** Result: no mappers after create, after the first token, or after a `PUT` that enables service accounts. `plan` has nothing to ignore. I6 repeats the check through the tool.
- [x] **V4. Separate `admin-cli` password grant (§11 item 21).** Result: HTTP 200, `expires_in: 60`, with a refresh token. A wrong password gives 400. I3 must fetch a new token on a run longer than 60 seconds.

### Findings from the checks that change the spec or the build

- **Correction to item 22 (spec §5.6, §11).** `temporary: true` on a credential does not set `UPDATE_PASSWORD`. The K20 test had sent `requiredActions` itself, so the earlier result was wrong about the cause. The spec now says the tool sends `requiredActions: ["UPDATE_PASSWORD"]`. I9 must do this. The test of C79 must check `requiredActions` on the stored user.
- **New item 37.** The default user profile requires `email`, `firstName` and `lastName`. A user without them cannot sign in ("Account is not fully set up"). This cause is separate from the required action.
- **Item 38, decided 2026-10-27: option A.** A second user with the same `email` makes `partialImport` return HTTP 500. `apply` now refuses duplicate emails in preflight (exit 1, `refused`, `email_duplicate`). `plan` lists a user without `email`, `firstName` or `lastName` under `profile_incomplete`, as information. Spec changes: §3.4, §4.3, §4.4, §5.6, §7, new criteria 80 and 81, item 38. The gate on I6 and I9 is lifted. Not tested: case-only email differences, a `PUT` to a used email, and a realm whose profile does not require the three fields.
- **A test mistake of mine.** The first duplicate-email run looked like a general `partialImport` fault. I reused one email across users. The 500 came from that, not from `requiredActions`. A matrix on a fresh realm with a unique email per user showed it.

Task I11 note: the `reset-password` endpoint was not retested on 2026-10-27. Spec §11 item 15 still stands for it.

## Order

1. I0.
2. I1.
3. In parallel: I2a, I2b, I2c, I3, I4, I8 (secrets file half).
4. I5, I6.
5. I7, I10, I11.
6. I9, I12.
7. I19, then I20, then I21 (full file, §5.12).
8. I13, then I22 (live check of the full file), I14, I15, I16, I17, I23.
9. I18 when the hosts exist.
