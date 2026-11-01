# Caller assessment: `apply` for the config file (task I7), round 1

Date: 2026-10-27. Assessor: one subagent, devil's advocate, read-only. Spec under review: `libs/kc-axi/README.md`, the apply parts of §3.4, §4.2, §4.3, §4.4, §5.6, §5.8, §5.9, §6.2, §7 and criteria 6, 18, 20, 21, 22, 24, 27, 28, 33, 34, 37, 38, 41, 47, 62, 63, 67, 70, 71, 73, 77.

Verdict: **rejected. Blocker count: 4** (B1 to B4).

## Blockers

**B1. Pending-generation finish contradicts itself and is not part of the run.** §5.6 (the `secret` row, "apply refuses it") and §5.8 case 2 (the tool "sets the pending value on Keycloak") disagree. §3.5 makes `active` the pending number, so "the active generation" in `plan` is ambiguous. The finish is not an action in §5.6 step 3, not in the plan hash, and not in the step 7 order. Case 1 (live equals pending) is a local file write only, produces no action, and leaves the generation `pending` forever. The spec does not say whether the finish needs `--yes`, `--allow-remote` or an audit pair, or when case 3 (`secrets_mismatch`) is raised. C73 cannot be built without new rules.

**B2. The lock is a write before the safety checks.** The lock file lives in `secrets_dir`. The directory is created on first need. `unsafe_path` for `secrets_dir` is checked only in step 4, after the lock exists. This breaks "before any write" (§7, C69). Step 1 says the audit file is checked first, but steps 1 to 4 check only that `audit_path` is set. The file is opened in step 4. File validation (exit 2) runs under the lock, so a `locked` exit 1 can hide a `config_invalid` exit 2.

**B3. A missing secrets file has two meanings.** §4.4 and §7 make a missing file `secrets_unreadable` (exit 1). §3.5 and C37 say the first `apply` creates it. Plan step 3 reads it, and the outcome is unspecified on a fresh machine. `secrets_unreadable`, `secrets_server_mismatch` and `generation_pending` are not in the preflight list, so it is unclear whether they stop at once or go into `refusals`.

**B4. The top-level code of a refusal is contradictory.** §4.3 and §4.4 say the top-level code is `refused`. C25, C31 and C80 expect `refused`. C38, C63, C66, C27 and C28 expect the specific code. §7 gives `owner_conflict` in one row and `refused` in another. An agent caller branches on this code.

## Majors

1. No write contracts for config objects (realm create and change, client create, change and delete, mapper create, change and remove). Not stated: full or partial `PUT`, whether the marker and `pkce` survive a `PUT`, whether `secret` is sent. C24 cannot be tested without this.
2. Realms carry no owner marker. Any owner's file can change an existing realm, including a hand-made one.
3. `apply_partial` is contradictory. §4.4 says "after at least one change". §5.6 says "first failure". §6.2 and §7 give it when the command timeout passes during reads. A first-write `keycloak_rejected` is not covered. Line 604 retries a write after a 401, but line 603 says writes are not retried.
4. The re-enable guard is under-specified: records are not keyed by `base_url` and `realm`; an `intent` without a `result` is not defined; it refuses even when the live object is already `enabled: true`; a recreated client stays blocked.
5. Pending granularity: one generation holds all clients. A `pending` entry for a client later removed from the file has no abandon path. `--adopt` capture is not in the step 7 order.
6. The order of `--expect`, refusals, `already` and `confirm_required` is not given. The order of the intent record and the pending write is not stated.
7. The test seam and I7 are circular: C41 and C73 need the seam (I12), which I7 does not depend on.

## Minors

- Tasks file, I7 entry: lists C47 (config half), which does not exist, and C27, which is a users-file criterion.
- Plan step 2 reads all users for a config file.
- A `--expect` format error has no code.
- `interfaces-spec.md` and `access-control-spec.md` still cite kc-axi exit codes 3 to 7 and stderr errors.
- The generated secret must be in the redaction set.
- `created` in the success output for mappers is not specified.

## Status after this report

- B2 and B3: fixed in the spec with stated defaults (see the I7 entry in `docs/tasks-kc-axi-implementation.md`). Round 2 checks them with a fresh subagent.
- B1 and B4: open decisions for the owner. Recorded as spec §11 items 40 and 41.
- Majors and minors: recorded in the I7 entry as open items. Not reviewed one by one.

# Round 2 (2026-10-27): B2 and B3 only, fresh subagent

Verdict: **not fixed. 2 new contradictions.** The gate stops after two rounds (CLAUDE.md, step 2a). The remaining blockers go to the owner as decisions.

| Check | Result | Why |
|-------|--------|-----|
| B2(a) no write before the no-lock checks | NOT FIXED | `unsafe_file_mode` for an existing `secrets_dir` or secrets file is still a step 6 preflight item, after the lock |
| B2(b) `unsafe_path` before the directory is created | FIXED | step 2 checks the path with no directory created |
| B2(c) audit file opened before lock and reads | FIXED | step 3 |
| B2(d) a bad file cannot be masked by `locked` | FIXED | step 2 exits 2 before the lock |
| B3(a) one meaning of a missing secrets file per command | NOT FIXED | §3.5 cites §5.8 for `rotate` and `restore`, and §5.8 does not say it. `capture`, `prune` and `export-realm --capture-secrets` are not assigned. "The first write that needs the file creates the file" conflicts with it |
| B3(b) which secrets-file failures stop the run | NOT FIXED | `secrets_server_mismatch` and `unsafe_file_mode` are exit 2 in §4.4, §3.5 and §7, but a refusal in the new preflight list. `generation_pending` is a refusal there, but §5.8 says `apply` finishes a pending generation |
| B3(c) preflight list and failure table agree | NOT FIXED | same two codes, and `generation_pending` |

New contradictions created by the round-1 fixes:

1. `audit_failed` is now raised in step 3, before the lock, and is still in the step 6 preflight list.
2. `generation_pending` in the `apply` refusal list contradicts §5.8 ("`apply` finishes a pending generation").

Open for the owner: B1 (spec §11 item 40), B4 (item 41), and the mechanical fixes above, taken as defaults in the I7 entry of `docs/tasks-kc-axi-implementation.md`.
