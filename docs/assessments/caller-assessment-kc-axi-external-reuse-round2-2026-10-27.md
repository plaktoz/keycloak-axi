# Caller assessment: kc-axi, external reuse, round 2

Date: 2026-10-27 · Spec assessed: [libs/kc-axi/README.md](../../libs/kc-axi/README.md) (Draft v0.3) · Round 1: [caller-assessment-kc-axi-external-reuse-2026-10-27.md](./caller-assessment-kc-axi-external-reuse-2026-10-27.md)
Perspective: a team with a Python or TypeScript service, a local Keycloak for development, and an operator who is not the author. No knowledge of UMAS. Linux, Windows or macOS.

Method: the spec was read in full and checked against itself, against `libs/README.md`, and against `libs/event-log/README.md` section 4.1. Nothing was run. Owner decisions and live facts were treated as true and were not raised as gaps. Section numbers and line numbers refer to the v0.3 file as read today.

## 1. Verdict

**REJECTED.** Two blockers remain.

- B1: `plan` can never exit 0 on a real realm, because `unmanaged` clients are listed as actions.
- B2: the one function a consumer must call (the secret reader) has no interface, and no form that a TypeScript service, a shell, or a compose file can use.

Round 1 progress is large. The schema lists, the first-run secret cases, the preflight list, the export skip rule, the JSON table, the exit-code table, the lock and the redaction rule all exist now. Most of the remaining gaps are contradictions inside v0.3, not missing sections.

## 2. Round 1 blocker and major status

| R1 # | Item | Status | Proof section |
|------|------|--------|---------------|
| 1 | Schema undefined | Partly resolved | 3.4: field lists for realm, client, mapper, user; `unknown_field` is now enforceable. Types, defaults, allowed values and Keycloak paths are still not tabulated (m18) |
| 2 | First-run secrets | Resolved | 5.8 "New client, no value in the file", "Live client, no value in the file"; criterion 37. A residual crash window remains (M8) |
| 3 | `plan_hash` missed value changes | Partly resolved | 4.3 line 305 now hashes the file SHA and "its values, normalised". Canonical form undefined, live versus desired ambiguous (M1) |
| 4 | Export then plan fails for hand-made clients | Partly resolved | Export side resolved: 5.7 step 5. Plan side contradicts it: `unmanaged` is listed as an action (B1) |
| 5 | Refusals after writes | Partly resolved | 5.6 step 3 preflights five refusals. Two refusals still happen after writes (M3, M4). Skipped actions no longer exist because the whole run is refused |
| 6 | Credential sources | Resolved | 5.4 order; 6.1 `admin_user: admin`; `admin_password` gone from 3.1 |
| 7 | Config location, global flags, timeouts | Resolved | 4.1, 6.1, 6.2. Owner decision applied correctly |
| 8 | Users `id` rule | Partly resolved | 3.4: required. The `id_conflict` remedy appears only in section 9 (m16) |
| 9 | Realm lifecycle | Resolved | 5.6 apply order step 4.1; `realm_absent`; run order for a new realm |
| 10 | Temporary password cases | Partly resolved | 5.6 line 552 gives the create case. Field absent, and a failed `reset-password`, leave an unusable user (M8; spec open item 22) |
| 11 | Plan truncated by limit | Resolved | 4.3 line 260 |
| 12 | No-op write without `--yes` | Not resolved | 4.2 line 254 versus 4.5 rule 6. Neither says what `apply` on a satisfied file without `--yes` returns (m5) |
| 13 | Writes not classified | Partly resolved | 4.2 table. `down` without `--purge` on `volume: ""` deletes all data with no `--yes` (M10) |
| 14 | Emergency disable reversed | Partly resolved | Users: 5.9, criterion 47, logout verified. Clients: not sticky (M9) |
| 15 | Secrets file has no server identity | Resolved | 3.5 line 203; criterion 43 |
| 16 | Rebuild and adopt secret cases | Partly resolved | 5.8 lines 584, 580. The adopt case conflicts with the preflight (M6). The rebuild case is implied by the `secret` action and never stated (m18) |
| 17 | Mappers | Resolved | 3.4 mapper fields; 5.6 steps 3, 4, 4.3. Omitted-`mappers` rule is unclear (M5) |
| 18 | Ownership | Partly resolved | 3.4 `owner` and marker. `owner` is defined in two places (M2, M17) |
| 19 | Built-in clients | Resolved | 3.4 line 156, `builtin_client` |
| 20 | `--allow-remote` scope | Partly resolved | Applies to every apply (5.6 step 3, criteria 27, 28). "Loopback" is never defined (M11) |
| 21 | Concurrency | Resolved | 5.6 step 2, `locked`. Minor time-of-check gap (m13) |
| 22 | Windows protection, git detection | Resolved | 5.4 line 491 states the limit. 3.5 line 209 gives the detection method |
| 23 | Default persistence unproven | Partly resolved | Disclosed: 5.3.1, criterion 17, item 23 as release gate. The default is still a named volume |
| 24 | Criteria that cannot pass yet | Partly resolved | Item 17 labels all. Criteria 10 and 11 are not marked, and there is no first-release gate list (m7) |
| 25 | Admin password in the container record | Not resolved | 5.3 line 430, criterion 8 (M15) |
| 26 | `up` ignores container exit | Resolved | 5.3 step 6, criterion 16 |
| 27 | Audit after change | Resolved | 3.3 intent then result |
| 28 | JSON contract | Partly resolved | 4.3 table. Partial and multi-refusal shapes undefined (M14) |
| 29 | AXI rules claimed, not implemented | Resolved | 4.5. `--full` is dropped without a recorded deviation (m6) |
| 30 | Exit-code table | Resolved | 4.4. Code names disagree between sections (m1) |
| 31 | Runtime states | Resolved | 5.2, 7 |
| 32 | TLS | Resolved by scope | `ca_file` in 6.1; local-only decision |
| 33 | Version range | Partly resolved | Owner decision recorded (item 11). No version gate and no behaviour outside the tested set (m9) |
| 34 | Redaction | Resolved | 5.4 line 480 |
| 35 | Token expiry | Resolved | 5.4 line 489 |
| 36 | Field ownership, sets, normalisation | Resolved | 3.4 "Rules for both files" |
| 37 | Criteria miss behaviours | Partly resolved | Many added. None for lock contention, token expiry, `secrets_path` use, or the reader |
| 38 | Not standalone | Partly resolved | Line 4 is clean. Criterion 57 contains the forbidden word (m7). Links point into the repo (m14) |

## 3. New findings for round 2

### Blockers

**B1. `plan` cannot return `no_change` on any real realm.**
- Sections: 5.6 steps 4 and 5, 4.3 example, 4.4 "Partial runs", 5.7 step 5, criteria 18, 19, 20.
- Quotes. Step 4: "A client without a marker, or with another owner's marker, is `unmanaged`. It is never changed." Step 5: "Exit 0 with `status: no_change` when there are no actions. Otherwise exit 1 with `status: drift`." The example puts it in the action list: `actions[3 of 3]{...}` with `unmanaged,client,legacy-tool,`. Line 349: "A run never ends with exit 0 while a listed action is pending."
- Problem. Step 4 lists "the live clients that the file does not declare". Every Keycloak realm holds the six built-in clients (`account`, `broker`, `realm-management` and so on), which carry no marker and cannot be declared (3.4 line 156). If `unmanaged` counts as an action, `plan` exits 1 on a fresh realm and `apply` never reaches `status: already`. If it does not count, the example and line 349 are wrong. Export skips these clients (5.7 step 5), so criterion 19 ("`plan` ... exits 0") fails the same way.
- Missing. Say whether `unmanaged` is an action, how it counts in `total`, `plan_hash` and the exit code, and whether built-ins are hidden. Give the JSON key for it.

**B2. The secret reader has no interface a consumer can call.**
- Sections: 5.8 first paragraph, 3.5 "Consumers" bullet, 2 line 39, 4.2.
- Quotes. 5.8: "The secret reader takes the secrets path, the realm and one client key. It returns the value of that client in the `active` generation." 3.5: "Consumers read the file only through the secret reader (section 5.8). No command prints a value." 2: "No public Python API in v1 ... The one exception is the secret reader."
- Problem. This is the only function the consumer must call, and it has no package or module name, no function name, no signature, no error type (no `active` generation, `pending` only, file unreadable, wrong server, unsafe mode), and no statement of whether it applies the `unsafe_file_mode` check or takes the lock. A TypeScript service, a shell script, a compose file or a systemd unit cannot call a Python function, and no command prints a value. The only route left is to parse the JSON file, which 3.5 forbids. Section 5.8 also assumes a "launcher" that starts the service. A consumer without one has no way to deliver the secret.
- Missing. A defined reader contract: name, signature, errors, which reads the check covers. And a form for non-Python consumers (see decision D1), or an explicit statement that the file format in 3.5 is a stable contract that any language may read.

### Majors

**M1. `plan_hash` is still under-specified.** Section 4.3 line 305: "a canonical JSON document ... the sorted actions. Each action holds its values, normalised."
- "Its values" does not say desired, live, or both. If only desired values, a change of the live value between `plan` and `apply` (the case `--expect` exists for) leaves the hash unchanged when the action type and fields are the same. Only a change of the input file changes the hash, through the file SHA.
- "Canonical JSON" has no rules: key order, separators, number form, string encoding, list order, null handling. Two platforms can disagree.
- The file SHA is over raw bytes, so a CRLF checkout on Windows gives a different hash from a LF checkout on Linux for the same content. `--expect` then fails across machines.
- A `create` of a `secret_managed` client has no value yet at plan time. The spec does not say what enters the hash for it. A random value would make the hash differ between `plan` and `apply`.
- Criterion 21 ("A changed value ... changes `plan_hash`") passes through the file SHA alone. It does not test the live-state case. A criterion is missing for it.

**M2. `owner` is defined in two places with different rules.** Section 3.4 lines 115 and 184: required in the config file, "Two files with different owners do not touch each other's clients." Section 6.1 line 638: `owner: ""` in the tool configuration, and line 664: "`owner` is in this file for the owner's convenience only. It is also required in the config file." Line 183: "the running owner" is never defined.
- Missing. Which source wins, what happens when they differ, and what `owner` in the tool configuration does. The `managed` column in `clients` (3.2) cannot be computed without an owner context, because `kc-axi clients` takes no `--file`.

**M3. Two refusals still occur after the first write.**
- Section 5.9 line 611: "The refusal is `keycloak_rejected` with `field: enabled` and `user_disabled_by_audit`." Section 5.6 step 3 lists five preflight refusals and this is not one of them. A users-file `apply` can change user A, then refuse on user B. The code `keycloak_rejected` also means "Keycloak refused" (4.4), and here Keycloak never saw the request. `plan` does not show the refusal, so the operator sees `change user enabled` and then a failure.
- Section 3.3 step 1 checks the audit file "before a write", per write. Step 3 of 5.6 does not preflight it. A failure at write 5 gives `apply_partial` with a different cause from criterion 12's `audit_failed` "before any change".
- Missing. Add both to the step 3 list, give the first its own typed code, and show it in `plan`.

**M4. One case, two codes, in the users flow.**
- Section 5.6 line 549: "An `id` with another username, stops the run with `id_conflict`, before any write." Line 551: "A declared `username` that differs from the stored one for the same `id` ... The run stops with `keycloak_rejected`." Section 4.4 line 337: `id_conflict` is "A users-file `id` belongs to another username".
- These describe the same state: an id that exists with a different username. One is preflight, the other happens on `PUT`, after earlier writes.
- Missing. One rule and one code, found before the first write.

**M5. A client with no `mappers` key: untouched, or stripped?**
- Section 3.4 line 179: "A field removed from the file keeps its server value." Section 5.6 line 525: "A mapper that is not declared on a managed client is `remove`."
- Missing. Whether an omitted `mappers` key means "do not manage mappers" or "declare none". A consumer who omits `mappers` can lose mappers, or never see them. A related risk is not covered by the live check (item 18): Keycloak may add its own mappers to a client when service accounts are enabled. They would show as `remove` and block every `apply` with `allow_delete_required`. Whether a client created through the REST API carries such mappers is not stated and was not checked. Mark it as unverified.

**M6. Adopting a client with a secret conflicts with the preflight.**
- Section 5.8 line 584: "`apply --adopt` records the live value as a new generation, then manages it." Section 5.6 step 3: refuse "a `secret_missing` client, with no capture yet".
- An adopted `secret_managed` client has a live secret and no entry in the file, so by 5.6 line 520 it is `secret_missing`, and the preflight refuses before adopt can capture. The owner decision (capture on adopt) is stated in 5.8 but not carried into 5.6.
- Missing. State that `--adopt` turns `secret_missing` into a capture step, and what `plan` prints for it.

**M7. `rotate`, `restore` and `capture` have no source for the client set.**
- Section 4.2 lines 247 to 249 take no `--file`. Section 5.8 line 586: "A client missing from the file gets a new value." Section 3.5 line 204: each generation holds "every `secret_managed` client of the realm".
- `secret_managed` lives in the config file only (3.4 line 152) and is not in the marker. Without `--file`, the tool cannot know which clients are `secret_managed`, or that a new client exists. Missing: the source of the client set and what `rotate` does for a client the secrets file has never seen.

**M8. "Run `apply` again finishes the job" (line 542) is false in two places.**
- Secrets. Section 5.6 step 4.2 orders "Client `create`, then `adopt` and `change`, then secrets". Section 5.8 line 576 writes the pending generation first, but does not say whether this is before the client is created. If the client is created first and the process dies before the pending write, the next run finds a live client with no value: `secrets_missing`, with a random Keycloak-made secret that nobody has. Recovery is `secrets capture`, not a re-run. Criterion 41 covers only the window after the pending write.
- Users. Section 5.6 lines 548 and 552: the user is created with `partialImport`, then `reset-password` is called. If the second call fails, the user exists and the variable is "checked ... only when a user is created", so a re-run does not repair it. Spec open item 22 acknowledges the gap. Without `temporary_password_env`, a new user is created with `UPDATE_PASSWORD` and no password, so it can never sign in. Criterion 31 ("without `temporary_password_env` set") is ambiguous between a missing field and an unset variable.
- Missing. Order the pending write before the client create and add a criterion. Decide item 22 (D5).

**M9. `disable-client` is not sticky.**
- Section 5.9 and the owner decision cover users only. Section 9 line 826 claims "A disabled identity stays disabled on later `apply` runs". For a client, `apply` sends the declared `enabled: true` and re-enables the client that the operator disabled in an emergency. Criterion 47 tests users only. Decision D3.

**M10. `down` can destroy all data with no `--yes`.**
- Section 4.2 line 237: `down` needs `--yes` "With `--purge`". Section 5.3.1 line 445: an empty `volume` means "No persistence". `down` removes the container (5.3 `down` step 2), and with it the data. The owner rule is `--yes` on "every write that ... deletes local data". Decision D4.

**M11. "Loopback" is undefined.** It is used in 4.4 line 326, 5.3 line 412, 5.6 step 3, section 7 and criteria 27, 28. Is `localhost` loopback? `[::1]`? `127.0.0.2`? A hostname that resolves to loopback? A consumer who writes `http://localhost:8080` meets `insecure_url` or `allow_remote_required` without knowing why. Decision D10.

**M12. `secrets_path` is a file or a directory?** Section 3.5 line 208 and 6.1 line 660 describe one key. Section 5.8 line 598: "finds the file of that realm through `secrets_path` and the default name". Criterion 45: "Two realms on one server have two files." If `secrets_path` is a file, it holds one realm and the `realm` field of the file (3.5) collides for a second realm. If it is a directory, the key name is wrong and the rule is unwritten. Also the lock file's place depends on it (5.6 step 2). Decision D9.

**M13. First run on an empty machine is not walkable.**
- No `init`, no minimal configuration. Section 6.1 lists defaults and says `image` is "required for up", with no value. The only image tag named is `quay.io/keycloak/keycloak:26.6.4`, in the preface of the answered list in section 11 (line 877), not in section 5.3 or 6.1. The memory prerequisite of 4 GiB sits in section 11 item 13 (line 901), not in section 5.3 or 7. The live check used a 2 GiB machine, and a new consumer on a similar machine reaches `container_exited` first.
- Not stated: whether a missing configuration file is `config_missing` when the environment variables alone would work; whether the configuration directory and the secrets directory are created, and with which mode; which keys are required in the tool configuration.
- Missing. A "first run" subsection, ordered: runtime, machine memory, configuration file (minimal example with a real image), admin password source, `up`, `apply`, reading the secret.

**M14. The JSON error envelope cannot carry the partial-run data.**
- Section 4.3 lines 285 to 290: the envelope has `code`, `message`, `help`. Section 4.4 line 347 and 349: `apply_partial` outputs `applied`, `pending` and `cause`. Section 5.4 line 489: `auth_failed` "with the `applied` and `pending` counts". Section 5.6 step 3: "print every refusal", but the envelope holds one error. Section 4.3 table has `status: partial` for `apply` while the exit is 1 with an error code.
- Missing. Whether a partial run prints the success shape or the error envelope, where `applied`, `pending`, `cause` go, and how several refusals are listed (an `errors` array, or the first one).

**M15. Criterion 8 and the admin-password claim are false as written.**
- Section 5.3 line 430: "Each `-e NAME` has no value ... The password is not in an argument (criterion 8)." Criterion 8: the password never appears "in the process list, in the arguments of any runtime call, or in a file." The runtime stores the environment of a container in its own record (a file or database on the host), and `podman inspect` or `docker inspect` prints it. `down` step 2 says "The runtime removes the container record, and with it the environment", which admits it, but the spec never warns the operator and criterion 8 says "in a file".
- Missing. State that the value is in the container record until `down`. Reword criterion 8. Name who can read it (anyone with runtime access).

**M16. `export-realm` finds refusals after it has written, and mixes the two file kinds.**
- Section 5.7: step 3 writes the files, step 6 checks them, step 7 (with `--capture-secrets`) writes the secrets file and edits the config file to add `secret_managed: true`. A failure in step 7 (`unsafe_path`, `unsafe_file_mode`, `secrets_server_mismatch`, `locked`, `secrets_unreadable`) happens after the files exist. The check in step 6 runs before the edit of step 7.
- `--scope all` writes both files into one `--out-dir`. Section 3.4 table requires the users file to live "Outside any git work tree", while the config file is meant to be "In the consumer's repository". One directory cannot satisfy both. Section 5.7 does not say whether `unsafe_path` is checked before the config file is written.
- Missing. Order the checks before the first write. Allow two output directories or say that `all` refuses an `--out-dir` in a git work tree.

**M17. Export and the owner marker.**
- Section 5.7 line 568: "Export does not write `owner` into the config file." Export writes the clients that carry a marker (step 5). The marker holds an owner name (3.4 line 183). The tool does not tell the operator which owner to enter. If the operator enters another name, every exported client becomes another owner's client, so `plan` lists them as `unmanaged` and `apply` changes nothing. If the realm holds clients of two owners, one file holds both, and the separation of 3.4 line 184 is lost.
- Missing. Export should write the owner, or take `--owner`, and write only that owner's clients.

### Minors

- **m1. Typed codes disagree.** 3.4 line 107: duplicate keys give `config_invalid`; 4.4 and section 7 give `duplicate_key`. 3.4 line 152: `secret_managed` on a public client gives `config_invalid`; 4.4 and section 7 give `secret_managed_public`. A consumer branching on the code needs one.
- **m2. `--realm` against the file.** A config file holds `realm.name`; a users file holds `realm:`. `plan --file F --realm R` with different values has no rule. No rule says whether `default_realm` applies when `--file` is given.
- **m3. Relative paths.** `secrets_path`, `audit_path`, `admin_password_file` and `--file` have no base directory rule (working directory, or the configuration file's directory) and no `~` rule.
- **m4. Audit details.** Section 5.9 uses an "`enable` record", and the action list in 3.3 line 87 has no `enable`. Line 611 says the flag "is added to the list of `apply` flags in section 4.2" though it is already there (stale sentence). `--allow-reenable` on a config file has no stated result (`flag_not_valid`?). The audit file has no size or rotation rule, yet `apply` reads it on every run. The audit file is local, so a second machine does not see a `disable`.
- **m5. A satisfied write without `--yes`** (R1 #12). 4.2 line 254 and 4.5 rule 6 still disagree.
- **m6. `--full` is missing.** `libs/README.md` rule 3 has `--full`. 4.5 rule 1 replaces it with `--fields`, and line 369 says "Deviations. None in v1". This is a deviation and is not recorded in section 10. Free text cut at 200 characters, such as a Keycloak error message, has no way to be read in full.
- **m7. Criteria that cannot be tested as written.** Criterion 4 (line 738) says every command that calls Keycloak exits 1 when it is stopped, while 5.3 line 473 says `status` exits 0 when the server does not answer. Both can hold only if `status` is excluded from criterion 4, which is not written. 21 passes through the file SHA (see M1). 31 is ambiguous (see M8). 41 and 56 need a way to stop the process at an exact point; no test seam is named. 57 contains the word `umas` outside section 9, so it fails its own test, and "the names of any other consuming project" has no list. 10 and 11 cannot run until Docker, Linux and Windows exist and are not marked. No first-release gate list names the criteria that must pass.
- **m8. Platform claims written as fact.** Section 5.5 labels the macOS port as verified and the Windows port as not verified, which is correct. Other rows are stated as fact with no "verified by reading" label, as the repo rule requires: the Windows engine row ("runs Linux containers in a virtual machine (WSL2 or equivalent)"), the `msvcrt` lock row, "Shell: None required" on Windows, and the frozen-build row for each architecture. Section 5.4 line 491 says `%APPDATA%` is restricted to the user by default and calls it "a default, not a check", which is labelled. Its location is the roaming profile, which can sync secrets to other machines; the spec does not note this. A Windows reader that holds the secrets file open may make `os.replace` in the writer fail, which the spec does not consider. `unsafe_file_mode` on WSL with files under a Windows drive may give results that do not reflect real access. All of these need "verified by reading" until a Windows run exists.
- **m9. No version gate.** Item 11 says 26.x with the tested range set later. Nothing says what the tool does on 25.x, 27.x, or an untested 26.x: refuse, warn, or run. The built-in client list (3.4 line 156), port 8080 and `/opt/keycloak/data` (5.3 step 4) are fixed.
- **m10. The word "owner" has three meanings.** The client marker name (3.4), the person who operates the tool ("The owner sets `volume_options`", "The owner runs `down`", "The owner adds it", 5.3.1, 5.7, 5.10), and the decision maker (section 11).
- **m11. Installation is unstated.** No package name, minimum Python, dependencies, entry-point name, or import path for the reader. A consumer cannot write a requirements line.
- **m12. Users file must be outside git, with no override.** A team that keeps synthetic users (`example.invalid` addresses) cannot share the file in its repository. Section 7 applies `unsafe_path` to the users file; the table in 3.4 gives no override and no reason beyond personal data. `unsafe_file_mode` says "readable by others"; group-readable is not stated. A hand-made file at the default umask (644) fails on the first run, so the error message needs the `chmod` hint.
- **m13. Lock is taken after the read.** 5.6 step 1 reads live state, step 2 takes the lock. A run that finishes between the two leaves the first run with a stale plan. Re-read after the lock.
- **m14. Other files out of sync.** `libs/README.md` line 26 says "on Linux and Windows" (macOS is the first target), line 160 says kc-axi "still deviates (stderr errors, exit codes 3 to 7, default limit 3)", and line 90 repeats "Linux and Windows". Spec lines 3, 17 and 355 link to `libs/README.md` and section 7 links to `../error-classifier/README.md`, which an outside reader may not have. The rule is in the repo's `CLAUDE.md` "Keep in sync".
- **m15. JSON gaps.** `export-realm` says `skipped: N unmanaged clients` in the text (5.7) but the JSON has no `skipped`. The `status` values for `up`, `down` and `status` are not listed. `detail` is a string or a list: not stated. `created` lists only creates.
- **m16. Brownfield and remedy.** Export skips every hand-made client, so on an existing realm it writes an empty `clients` list. The path to adopt them is to write the file by hand and use `--adopt`. The remedy for `id_conflict` (read the real id with `get user X --fields id` and copy it) is only in section 9 line 822, which a generic consumer may skip.
- **m17. Codes after writes.** The read-back `id_conflict` (5.6 line 548) happens after a write, so it should be `apply_partial` with `cause`. A full disk or other local file error has no typed code (section 7 last row).
- **m18. Schema types and defaults.** Missing: types and units (`accessTokenLifespan` integer seconds, range), allowed values of `pkce`, defaults on create when a field is omitted, and the Keycloak path of each field. The rebuild case (a client created from the secrets file's active value) is implied by the `secret` action and never written.
- **m19. Issuer and wiring.** The consumer needs the `iss` string, token endpoint and discovery URL to configure its service. The rules are in section 11 item 19 (an answered question). No command prints them, and `hostname` is described only as `KC_HOSTNAME`.

## 4. Items that need an owner decision

**D1. How non-Python consumers and launcher-less consumers get a secret (B2).**
- a) A command that runs a child with the value in its environment: `kc-axi secrets exec --client C --env NAME -- <command>`. Works for any language, compose, systemd. The value never prints. Adds one command and keeps "no command prints a value" true.
- b) A command that writes an owner-only env file or value file. Works for compose. Leaves a second copy of the secret on disk.
- c) The reader stays a Python function, and the JSON file format in 3.5 becomes a documented contract that any language may read. Cheapest. A TypeScript service must open the file itself, which the spec forbids today.
- Recommendation: a, plus c as the documented fallback, and define the Python function's name, signature and errors.

**D2. How `unmanaged` and built-in clients count (B1).**
- a) Informational only: a separate `unmanaged` key and a count, not in `actions`, not in `total`, not in the hash, no effect on the exit code. Built-ins hidden.
- b) Counted as drift. Then `no_change` is unreachable, and CI cannot use `plan`.
- Recommendation: a.

**D3. Make `disable-client` sticky (M9).**
- a) Same rule as users: `apply` refuses to re-enable a client with a later-`disable` audit record unless `--allow-reenable`. Matches section 9 line 826.
- b) Clients stay as written; fix section 9 and warn in 5.9.
- Recommendation: a. It costs one more audit scan and removes a way for an automated run to undo an emergency stop.

**D4. `--yes` for `down` with no persistence (M10).**
- a) `--yes` when `--purge` is set or `volume` is empty.
- b) `--yes` for every `down`.
- c) As written.
- Recommendation: a. It follows the owner rule (deletes local data) and keeps a normal restart free.

**D5. A user left without a password (M8, open item 22).**
- a) Test whether `partialImport` accepts a temporary credential with the user, so creation is one call. Then no gap exists.
- b) If not, let `apply` re-run `reset-password` for a user that has no credential and a `temporary_password_env` that is set.
- c) A manual step in the admin console (today).
- Recommendation: a, with b as the fallback. c leaves "run `apply` again" untrue.

**D6. Where `owner` lives (M2, M17).**
- a) In the config file only; remove it from the tool configuration; export writes it, or takes `--owner`.
- b) In the tool configuration as the default, with the file overriding.
- Recommendation: a. Two sources invite mismatch, and the marker belongs to the file's clients.

**D7. Export and hand-made clients (m16).**
- a) Skip, as today.
- b) Add `--include-unmanaged`, which writes them and lets `plan` show `adopt`.
- Recommendation: b. Skip stays the default, and a brownfield consumer gets a start.

**D8. What happens outside the tested Keycloak set (m9).**
- a) Refuse any non-26 server (exit 2); warn on untested 26.x.
- b) Warn only.
- c) Say nothing (today).
- Recommendation: a.

**D9. Meaning of `secrets_path` (M12).**
- a) A directory (rename to `secrets_dir`); the file is `<realm>.secrets.json` in it; the lock sits there.
- b) A file for one realm; criterion 45 then needs one configuration per realm.
- Recommendation: a.

**D10. Definition of loopback (M11).**
- a) A fixed list: `localhost`, `127.0.0.0/8`, `::1`, with no name resolution.
- b) Resolve the name and test the address.
- Recommendation: a. It is predictable and testable, and b depends on the machine's DNS.

## 5. Counts by severity

| Severity | Count | IDs |
|----------|-------|-----|
| BLOCKER | 2 | B1, B2 |
| MAJOR | 17 | M1 to M17 |
| MINOR | 19 | m1 to m19 |

Owner decisions applied correctly: scope and `--allow-remote` (with M11), config discovery order, `hostname`, subprocess use (with B2), users `id` required, `--allow-delete`, `disable-user` stickiness, AXI conformance (with m6), live-secret capture (with M6), admin password by hand (5.10). Applied only in part: `--yes` on every deleting write (M10), Keycloak 26.x range (m9), emergency stop (M9).
