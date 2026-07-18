# Phase 1: Incident-Class Gaps (audit #1, #2; #3 context)

> The audit's top priority: the two findings that map directly onto documented mass-slashing incidents.
> #1 (Keymanager `DELETE` no-op → a "deleted" key keeps signing — RockLogic/Lido 2023) and #2
> (doppelganger inert in production → a duplicate live instance double-signs — Staked 2021 / SSV-Ankr
> 2025). Milestone **M1**.
>
> Authoritative inputs: [`../prd.md`](../prd.md), [`../project-plan.md`](../project-plan.md), the audit.
> All file:line references verified against HEAD `develop` v0.6.0 (`ffdb49b`).

## Phase Overview

- **Goal:** Make the Keymanager API operate on the *real* signing registry so a `DELETE` actually stops
  signing and survives restart (#1), and enable the forward-looking `ForwardWindowMachine` +
  `SigningGate` in the production signing path so a key cannot sign during its startup liveness window
  (#2). Both mechanisms already exist in-tree — this phase *wires* them, it does not build them.
- **Issue count:** 5 issues, 15 points.
- **Estimated duration:** ~8–13 days single-stream; ~6 days with 2 developers (Stream A does #1,
  Stream B does #2, in parallel).
- **Entry criteria:** working tree on `develop`, green on the standing invariant
  (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace`).
- **Exit criteria (M1):**
  - [ ] A boot-loaded key (keystore-dir) deleted via the Keymanager API stops signing and, after a
        simulated restart, does not re-activate (regression tests).
  - [ ] `GET /eth/v1/keystores` lists boot-loaded keys; `DELETE` returns the key's real EIP-3076
        interchange and an honest status.
  - [ ] `bin/rvc` constructs `ForwardWindowMachine`; the production `SignerService` signing path
        consults the enablement gate; a key inside its window cannot obtain a signature.
  - [ ] Workspace green on the standing invariant.

## Assumptions (verified against HEAD)

- **A1 — The real signing registry is enumerable.** `CompositeSigner::public_keys()` exists
  (`crates/crypto/src/composite_signer.rs`, used at `:298`,`:735`) and per-backend removal exists
  (`remove_local_key` `:98`, `remove_remote_key` `:82`, `remove_grpc_remote_key` `:54`). SEC-1 calls
  this, it does not build a new registry.
- **A2 — `tracked_keys` is the partial view.** `KeystoreManagerAdapter.tracked_keys`
  (`crates/rvc/src/keymanager_adapters.rs:30`) is populated **only** by `import_keystore` (`:264`).
  `list_keys` (`:172-174`), `has_key` (`:176-178`), and `delete_keystore` (`:277-317`, returns
  `Ok(false)` at `:315`) all key off it. This is the root of #1 (audit "recurring pattern" #2).
- **A3 — The handler already stops signing on `Ok(true)`.** `crates/keymanager-api/src/handlers.rs`
  calls `remove_validator` + `stop_monitoring` in the `Ok(true)` arm (`:398-399`) but **not** the
  `Ok(false)` arm (`:405-415`). So making `delete_keystore` return `Ok(true)` for boot-loaded keys is
  most of the fix; the honest-status mapping is the rest.
- **A4 — The forward-looking machinery is complete and unused.** `ForwardWindowMachine`
  (`crates/doppelganger/src/forward_window.rs:61`, `new` at `:74`) implements `SigningEnablement`
  (`:320`). `SigningGate` (`crates/signer/src/gate.rs:115`) composes slashing + the enablement gate +
  BLS and already returns `BlockedByDoppelganger` (`:245-252`). But the production orchestrator uses
  `SignerService` (`crates/rvc/src/config/builder.rs:210-211`), which runs its own stage→sign→commit
  loops and **bypasses the gate** (doc comment `crates/signer/src/lib.rs:95-100` defers to "Issue
  2.10b"). `ForwardWindowMachine::new` is constructed nowhere outside tests.
- **A5 — Liveness infra exists.** `BeaconLivenessAdapter` (`crates/rvc/src/doppelganger_adapter.rs:25`)
  implements `LivenessChecker` over the beacon `post_validator_liveness` endpoint
  (`crates/beacon/src/client.rs:689`). The backward one-shot `DoppelgangerService`
  (`crates/doppelganger/src/service.rs`, `current_epoch-1` at `:195`) is wired at
  `bin/rvc/src/main.rs:1315-1355`.
- **A6 — Config flag exists.** `no_doppelganger_detection` / `doppelganger_detection`
  (`bin/rvc/src/main.rs:99-101`,`:616`,`:1040`); the phase extends it, not introduces it.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| SEC-1a | Keymanager list/delete/has_key on the real signing registry | 3 | bugfix | — | A |
| SEC-1b | Persistent deletion denylist across all key sources | 3 | bugfix | SEC-1a | A |
| SEC-2a | Route production `SignerService` signing through the enablement gate | 3 | bugfix | — | B |
| SEC-2b | Construct + wire `ForwardWindowMachine` in `bin/rvc` startup | 3 | feature | SEC-2a | B |
| SEC-2c | Liveness loop + replace one-shot service + tracker reconcile | 3 | feature | SEC-2b | B |

**Total: 5 issues, 15 points.**

## Execution Plan

Two streams in parallel. Stream A: `SEC-1a → SEC-1b` (registry seam, then the denylist that reuses it).
Stream B: `SEC-2a → SEC-2b → SEC-2c` (consult the gate, construct the machine, drive it). The two
streams touch disjoint files except `bin/rvc/src/main.rs` (SEC-1b denylist wiring and SEC-2b/2c
doppelganger wiring); they coordinate the startup-sequence ordering once at kickoff.

## Dependency Map

```text
SEC-1a (real registry) ──▶ SEC-1b (denylist consulted at the same seam)     [Stream A]

SEC-2a (signer consults gate) ──▶ SEC-2b (construct machine) ──▶ SEC-2c (liveness loop)   [Stream B]
```

## Phase Risk Flags

- **SEC-2a blast radius:** adding enablement to `SignerService` ripples to ~8 construction sites. Use an
  additive `with_enablement()` + fail-closed default so existing sites compile unchanged and any
  un-wired path fails *closed*. A construction-site audit is an acceptance criterion.
- **SEC-1 must not weaken the atomic gate or the delete-handler cancel-token handling.** The existing
  `doppelganger_state_lock` + `cancel_tokens` logic in `handlers.rs:366-423` is preserved verbatim.
- **`bin/rvc/src/main.rs` is a hotspot** (SEC-1b + SEC-2b/2c here, SEC-3/SEC-9 later). Each adds a
  distinct startup step; land Phase-1 edits first.
- **SEC-2c multi-BN liveness wrapping** is a minor unknown (could push 3 → 5) — flagged in-issue.

---

## Issues

### Issue SEC-1a: Keymanager list/delete/has_key operate on the real signing registry

- **Points:** 3
- **Type:** bugfix
- **Priority:** P0
- **Audit source:** #1 [HIGH] (orchestrator-verified against HEAD)
- **Blocked by:** none
- **Blocks:** SEC-1b (the denylist is consulted at the seam this issue unifies)
- **Scope:** 1.5–2 days
- **Stream:** A

**Description:**
Make `KeystoreManagerAdapter`'s `list_keys` / `has_key` / `delete_keystore` operate on the real signing
registry (`CompositeSigner::public_keys()` + `ValidatorStore`) instead of the partial `tracked_keys`
view, so the Keymanager API sees every key the VC can sign with regardless of how it was loaded (API
import, `--keystore-path` dir, or secret-provider). After this issue, a `DELETE` on a boot-loaded key
returns `Ok(true)` → the handler's existing `Ok(true)` arm stops signing (`remove_validator` +
`stop_monitoring`), and the response carries the key's real EIP-3076 interchange and an honest status.
This is the registry-unification half of #1; the restart-resurrection half is SEC-1b.

**Files to touch (verified):**
- `crates/rvc/src/keymanager_adapters.rs`
  - `list_keys` `:172-174`, `has_key` `:176-178` — delegate to the real registry (union of
    `composite_signer.public_keys()` and any dir/provider-loaded set), not `tracked_keys`.
  - `delete_keystore` `:277-317` — locate the key in the real registry; remove from `composite_signer`
    (`remove_local_key`/`remove_remote_key`/`remove_grpc_remote_key` as applicable) and delete the
    keystore-dir file if present; return `Ok(true)`. Keep the `Ok(false)` branch only for a truly
    never-known pubkey.
  - `KeystoreManagerAdapter` struct `:27-33` and `with_pubkey_map` `:46-54` — thread whatever registry
    handle is needed (the adapter already holds `composite_signer: Arc<CompositeSigner>` at `:29` and an
    optional `pubkey_map` at `:31`).
- `crates/keymanager-api/src/handlers.rs`
  - DELETE handler `:391-423` — the `Ok(true)`/`Ok(false)` mapping; ensure `deleted` vs `not_found`
    status is honest (the real-interchange export at `:340-359` already runs before deletion — confirm
    it exports the deleted key's real history, not an empty interchange).
  - `list_keystores` handler (same file) — returns the now-complete key set; align `readonly` semantics
    with `docs/keymanager-api.openapi.yaml` for keys not managed via the API import path.
- `crates/crypto/src/composite_signer.rs` — read-only reference for `public_keys()` (`:298` usage) and
  the `remove_*` methods (`:54`,`:82`,`:98`).

**Implementation outline:**
1. **RED:** add a test that boot-loads a key via the keystore-dir path (not `import_keystore`), calls
   the adapter's `list_keys`/`has_key` → assert the key is present (currently absent). Add a test that
   `delete_keystore` on that key returns `Ok(true)` (currently `Ok(false)`).
2. Change `list_keys`/`has_key` to return the union of the real registry
   (`composite_signer.public_keys()` + validator-store-tracked keys). Decide the canonical source of
   truth (recommend `composite_signer.public_keys()` as the "can sign with" set) and document it.
3. Change `delete_keystore` to look up the key in the real registry, remove it from the correct
   `composite_signer` backend, delete the keystore-dir file + `.import_meta.json` sidecar if present
   (reuse the existing `import_meta_path` helper `:66`), update `pubkey_map`, and return `Ok(true)`.
   Preserve the file-first-then-memory ordering (`:280-300`) so IO failure leaves state consistent.
4. In the handler, ensure the `deleted` status and the **real** EIP-3076 interchange are returned for
   these keys; keep `not_found` only for never-known pubkeys.
5. **GREEN/REFACTOR:** all new + existing keymanager tests pass; the `doppelganger_state_lock` +
   `cancel_tokens` handling (`handlers.rs:366-423`) is untouched.

**Test plan (named tests, in `crates/rvc/src/keymanager_adapters.rs` `#[cfg(test)]` +
`crates/keymanager-api` handler tests):**
- `test_list_keys_includes_boot_loaded_keystore_dir_key`
- `test_has_key_true_for_boot_loaded_key`
- `test_delete_boot_loaded_key_returns_ok_true_and_stops_signing` (assert no further sign succeeds for
  the pubkey; via the handler, assert `remove_validator`/`stop_monitoring` were called)
- `test_delete_returns_real_eip3076_interchange_for_key_with_history`
- `test_delete_never_known_pubkey_returns_not_found_no_side_effects`
- Existing keymanager import/export tests still pass (stop-before-import, additive-only inserts).

**Acceptance criteria:**
- [x] `list_keys`/`has_key` return boot-loaded keys (keystore-dir and secret-provider sources).
- [x] `DELETE` on a boot-loaded key stops signing (no further sign succeeds for that pubkey), status
      `deleted`, interchange contains the key's real history.
- [x] `DELETE` of a never-known pubkey → `not_found`, no side effects.
- [x] The atomic stage→sign→commit gate and the delete-handler cancel-token handling are unchanged.
- [x] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo nextest run --workspace` green.

**Risks / unknowns:**
- Whether the dir-loaded and secret-provider-loaded keys are fully captured by
  `composite_signer.public_keys()` at delete time, or whether a supplementary source-set is needed —
  confirm during step 2. If `public_keys()` is authoritative, this stays 3 pts.
  **Resolved:** used `local_public_keys()` / `has_local_key()` (boot + dynamic local only; remotes stay on `/remotekeys`).

---

### Issue SEC-1b: Persistent deletion denylist across all key sources

- **Points:** 3
- **Type:** bugfix
- **Priority:** P0
- **Audit source:** #1 [HIGH] restart-resurrection variant (orchestrator-verified)
- **Blocked by:** SEC-1a
- **Blocks:** none
- **Scope:** 1.5–2 days
- **Stream:** A

**Description:**
Persist a deletion denylist so a key deleted via the Keymanager API does not silently return on the next
boot. `KeySourceManager::load_all` (`crates/secret-provider/src/key_source_manager.rs:31-161`) re-loads
every provider key with no denylist (`key_manager.insert(secret_key)` at `:115`), so a legitimately
deleted secret-provider (GCP) key resurrects on restart — the textbook RockLogic pattern. This issue
adds durable denylist storage, writes to it on `DELETE`, and consults it in every key-loading path
(secret-provider `load_all` and the keystore-dir loader).

**Files to touch (verified):**
- `crates/secret-provider/src/key_source_manager.rs`
  - `load_all` `:31-161`; the per-key insert at `:115` must skip denylisted pubkeys.
- `crates/rvc/src/keymanager_adapters.rs`
  - `delete_keystore` `:277-317` — write the pubkey to the denylist on successful delete.
  - the keystore-dir startup loader (the code that scans `keystore_dir` and populates
    `composite_signer` — locate via the `import_meta` re-arm helper `:70-168` and the startup loader in
    `bin/rvc`/`config/builder.rs`) — skip denylisted pubkeys.
- `bin/rvc/src/main.rs` — wire the denylist store path into `load_all` and the dir loader (startup
  hotspot; add a distinct step).
- Denylist storage: a new small module (recommend alongside the keystore dir or the slashing DB dir so
  it shares the operator's durable volume). Format: append-only pubkey list, `0o600`, mirroring the
  existing `.import_meta.json` sidecar convention (`keymanager_adapters.rs:63-68`).

**Implementation outline:**
1. **RED:** test that a key deleted via the adapter, then a simulated `load_all` re-run (same providers),
   is **not** re-inserted into the `KeyManager`. Add the keystore-dir analogue.
2. Add durable denylist storage (a `DeletionDenylist` type: `contains`, `insert`, load-on-start,
   `0o600`). Choose the path (recommend `<data_dir>/.rvc.deleted_keys`), documented.
3. Write to the denylist in `delete_keystore` after a successful real-registry removal.
4. Consult the denylist in `KeySourceManager::load_all` before `key_manager.insert` and in the
   keystore-dir loader before adding to `composite_signer`.
5. **GREEN/REFACTOR:** denylist survives restart; a genuinely new key (never deleted) is unaffected.

**Test plan:**
- `test_deleted_secret_provider_key_not_resurrected_on_reload`
- `test_deleted_keystore_dir_key_not_resurrected_on_restart`
- `test_denylist_persists_across_reload` (write, drop, reload store, assert `contains`)
- `test_never_deleted_key_loads_normally`
- `test_denylist_file_permissions_0600` (unix)

**Acceptance criteria:**
- [x] After `DELETE`, a simulated restart (re-run key loading for both secret-provider and keystore-dir)
      does not re-activate the key.
- [x] Denylist storage survives process restart and is consulted for every key source.
- [x] A never-deleted key loads normally; the denylist is additive-only (no accidental un-delete).
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- A denylist is a new persistent artifact; an operator who *intends* to re-add a deleted key needs a
  documented un-denylist path (re-import via the API should clear the entry). Handle re-import clearing
  the denylist entry as part of step 3; document it.

---

### Issue SEC-2a: Route production `SignerService` signing through the doppelganger enablement gate

- **Points:** 3
- **Type:** bugfix
- **Priority:** P0
- **Audit source:** #2 [HIGH] = repo C-4 CRITICAL (orchestrator-verified)
- **Blocked by:** none
- **Blocks:** SEC-2b
- **Scope:** 1.5–2 days
- **Stream:** B

**Description:**
The production `SignerService` (`crates/signer/src/lib.rs`, used by every orchestrator module) runs its
own stage→sign→commit loops and **never consults doppelganger** — the live signing path has no gate at
all. The correct `SigningEnablement` trait and `SigningGate` already exist. This issue makes
`SignerService::sign_block`/`sign_attestation` (and all duty signing) consult an
`Arc<dyn SigningEnablement>` **before** signing, fail-closed (unknown/blocked → refuse). To avoid
churning the ~8 construction sites, the enablement is added as an **additive** `with_enablement()`
builder with a fail-closed default, so a `SignerService` built without it refuses to sign any key that
isn't explicitly enabled — and every un-wired path fails *closed*.

**Files to touch (verified):**
- `crates/signer/src/lib.rs`
  - `SignerService` struct `:101-105`; add `enablement: Arc<dyn SigningEnablement>` (re-exported at
    `:17`).
  - `SignerService::new` (the ~8-callsite constructor) — keep signature stable; add
    `with_enablement(self, Arc<dyn SigningEnablement>)`.
  - `sign_block` / `sign_attestation` (and the other duty signers) — consult
    `enablement.is_signing_enabled(pubkey)` before the stage step; on `false` return a
    `BlockedByDoppelganger`-style error. Keep the doc comment `:95-100` accurate (it currently defers to
    "Issue 2.10b" — update it to reflect this wiring).
  - default: a fail-closed enablement (unknown pubkey → `false`), matching the `SigningEnablement`
    contract (`crates/doppelganger/src/enablement.rs:14-25`).
- **Construction sites to audit (must all compile + get the enablement where it exists):**
  `crates/rvc/src/config/builder.rs:210-211`, `crates/rvc/src/orchestrator/duty_management.rs:503`,
  `.../aggregation.rs:714`, `.../sync_committee.rs:603`,`:1042`,
  `crates/rvc/src/keymanager_adapters.rs:1823`, `bin/rvc/src/commands/prepare_exit.rs:101`,
  `bin/rvc/src/commands/voluntary_exit.rs:118`.

**Implementation outline:**
1. **RED:** test that a `SignerService` whose enablement returns `false` for a pubkey refuses to sign a
   block and an attestation (no signature, typed error), and that the default (no enablement wired)
   also refuses an unknown key (fail-closed).
2. Add the `enablement` field + `with_enablement()` + fail-closed default.
3. Insert the enablement check at the top of each duty-signing method, **before** the slashing stage
   step (never after commit) — mirror `SigningGate::gate_decision` (`crates/signer/src/gate.rs:169-190`).
4. Audit every construction site; the exit commands and test constructors get the fail-closed default;
   the orchestrator/builder path receives the real machine in SEC-2b.
5. **GREEN/REFACTOR:** all orchestrator tests pass with the default enablement (which must enable the
   test keys — provide an "all-enabled" test enablement helper).

**Test plan (in `crates/signer/src/lib.rs` `#[cfg(test)]`):**
- `test_sign_block_refused_when_enablement_false`
- `test_sign_attestation_refused_when_enablement_false`
- `test_default_enablement_is_fail_closed_for_unknown_key`
- `test_enablement_check_precedes_slashing_stage` (assert the stage step is not reached when blocked)

**Acceptance criteria:**
- [x] A closed gate refuses to sign (block + attestation); the check runs before the slashing stage,
      never after commit.
- [x] The default (un-wired) `SignerService` fails closed for unknown keys.
- [x] All ~8 construction sites compile; a compile-time/inventory note lists them as audited.
- [x] The atomic slashing gate ordering is intact.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- The orchestrator tests build `SignerService` directly and expect signing to succeed; they need an
  all-enabled test enablement. Budgeted in the 3 pts (this is the main test-fallout surface).
  **Resolved:** `always_enabled()` behind cfg(test)/test-helpers; production fail-closed until SEC-2b.

---

### Issue SEC-2b: Construct + wire `ForwardWindowMachine` in `bin/rvc` startup

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Audit source:** #2 [HIGH]
- **Blocked by:** SEC-2a
- **Blocks:** SEC-2c
- **Scope:** 1.5–2 days
- **Stream:** B

**Description:**
Construct the `ForwardWindowMachine` in `bin/rvc` startup and hand it to the production `SignerService`
as its `SigningEnablement`, so on start (and on any key becoming newly active — including keymanager
import) the VC observes N full epochs of network liveness for each key before the gate opens. Register
all loaded keys, apply the epoch-0 (pre-genesis) bypass that already exists for the one-shot service,
and make doppelganger on-by-default with the existing opt-out.

**Files to touch (verified):**
- `bin/rvc/src/main.rs`
  - the doppelganger startup block `:1294-1358` (currently builds the one-shot service via
    `build_doppelganger_service` `:1316` and calls `run_doppelganger_detection` `:1340`) — construct
    `ForwardWindowMachine::new` here and pass it into the signer (`with_enablement`).
  - the epoch-0 bypass (`:1331-1336`) — preserve; `ForwardWindowMachine` also applies an epoch-0 bypass.
  - config gating `:1040`,`:1295`,`:1357` — on-by-default with opt-out (`no_doppelganger_detection`
    `:99-101`).
- `crates/rvc/src/config/builder.rs` — `build_signer` `:210-211` receives the machine (or the wiring
  happens in main.rs after the signer is built; pick one and document).
- `crates/doppelganger/src/forward_window.rs` — read-only reference: `new` `:74`, `register` `:99`,
  `status` `:301`, `SigningEnablement` impl `:320`.
- `crates/rvc/src/keymanager_adapters.rs` — the M-12 import re-arm path (`:70-168`) already re-arms a
  time-based gate; ensure keymanager-imported keys also `register` with the `ForwardWindowMachine`.

**Implementation outline:**
1. **RED:** an integration/startup test asserting `bin/rvc` constructs a `ForwardWindowMachine` and the
   signer's enablement is that machine (not the fail-closed default), and that a freshly registered key
   reports a not-yet-open status.
2. Construct `ForwardWindowMachine::new` with the configured window (default 2–3 epochs), register all
   loaded keys, wire it as the signer's enablement.
3. Apply the epoch-0 bypass; gate the whole thing behind the on-by-default config with opt-out.
4. Ensure keymanager-imported keys `register` with the machine at import time.
5. **GREEN/REFACTOR:** startup wires the machine; existing doppelganger tests pass.

**Test plan:**
- `test_bin_rvc_constructs_forward_window_machine` (startup wiring test)
- `test_registered_key_gate_closed_until_window_elapses`
- `test_keymanager_imported_key_registers_with_machine`
- `test_epoch0_bypass_preserved`

**Acceptance criteria:**
- [x] `bin/rvc` (not just `bin/rvc-signer`) constructs `ForwardWindowMachine`, verified by a startup or
      integration test.
- [x] A key added at epoch E cannot obtain a signature before the configured window elapses with no
      external liveness.
- [x] A keymanager-imported key goes through the same window.
- [x] Doppelganger on-by-default with a working opt-out; the ~2-3 epoch missed-duty cost is documented.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- The exact hand-off point (main.rs vs builder) depends on construction order (the signer is built in
  `builder.rs`, the beacon client / epoch are resolved in main.rs). Resolve in step 2; either works.
  **Resolved:** machine built in builder/main wiring; liveness loop deferred to SEC-2c (fail-safe closed).

---

### Issue SEC-2c: Liveness-observation loop + replace the one-shot service + tracker reconcile

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Audit source:** #2 [HIGH] + hygiene tracking gap
- **Blocked by:** SEC-2b
- **Blocks:** none
- **Scope:** ~2 days
- **Stream:** B

**Description:**
Drive the `ForwardWindowMachine` with real network liveness: a background loop that `tick`s the machine
per slot and feeds it `observe_liveness` from the beacon liveness endpoint via the bn-manager (respecting
multi-BN failover), so detected liveness for a monitored key keeps the gate permanently closed (or shuts
the VC down, matching the in-tree machine semantics) and a clean window opens the gate. Replace/subsume
the backward-looking one-shot `DoppelgangerService` wiring so there is one coherent mechanism in
production. Add a correction to the audit tracker (v0.5.0 release notes claim C-4 fixed; it wasn't —
note it is fixed at this commit without rewriting the old note).

**Files to touch (verified):**
- `bin/rvc/src/main.rs` `:1294-1358` — replace the one-shot `run_doppelganger_detection` call with the
  new liveness loop; keep the `build_doppelganger_service` scaffolding only if the loop reuses its
  clock/index resolution.
- `crates/rvc/src/doppelganger_adapter.rs` `:25-` — `BeaconLivenessAdapter::check_liveness`; drive it
  from the loop (per-epoch), feed results to `ForwardWindowMachine::observe_liveness` (`forward_window.rs:231`)
  and `tick` (`:167`).
- `crates/bn-manager/` — confirm the liveness call goes through the multi-BN manager (the beacon client
  method is `post_validator_liveness`, `crates/beacon/src/client.rs:689`); respect `query_first`/failover
  semantics.
- `crates/doppelganger/src/service.rs` — the one-shot service (`:195` `current_epoch-1`) is subsumed;
  keep it only if referenced elsewhere.
- `docs/releases/` — a short correction line reconciling the C-4 tracker claim.

**Implementation outline:**
1. **RED:** test that `observe_liveness` reporting a monitored key live during the window keeps its gate
   closed (no signing), and that a clean window opens it. Test that the loop routes through the bn-manager.
2. Add the per-slot/epoch liveness loop (a `tokio` task) that ticks the machine and observes liveness via
   the adapter → bn-manager.
3. Remove the backward one-shot wiring; ensure a single coherent mechanism.
4. Add the tracker-correction line (do not rewrite old release-note history).
5. **GREEN/REFACTOR.**

**Test plan:**
- `test_detected_liveness_in_window_keeps_gate_closed`
- `test_clean_window_opens_gate_and_signing_proceeds`
- `test_liveness_loop_routes_through_bn_manager_failover`
- `test_single_doppelganger_mechanism_in_production` (one-shot service no longer wired)

**Acceptance criteria:**
- [ ] Detected liveness for a key during the window → gate stays closed for that key (or VC shuts down,
      matching the machine's semantics) — no signing.
- [ ] After a clean window, the gate opens and signing proceeds.
- [ ] Liveness observation goes through the bn-manager (multi-BN failover respected).
- [ ] The backward one-shot `DoppelgangerService` is no longer the production mechanism; tracker
      correction added.
- [ ] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- **Multi-BN liveness wrapping** could be heavier than a single beacon call if bn-manager has no
  liveness pass-through yet — if a new bn-manager method is required, this issue rises 3 → 5. Confirm at
  step 2 (the endpoint exists on the beacon client; the risk is only the manager-level wrapping).
- The machine's "detected → permanently closed vs VC shutdown" behavior is defined in-tree
  (`forward_window.rs`); the loop honors whatever it returns — no new policy decision here.
