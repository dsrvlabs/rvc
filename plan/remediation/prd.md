# PRD: rs-vc Security & Correctness Remediation

**Owner:** rs-vc engineering
**Date:** 2026-06-13
**Source of truth:** `docs/2026-06-13-adversarial-code-review.md` (46 verified findings)
**Status:** Draft, pre-review

---

## 1. Problem statement

rs-vc is the Validator Client (VC) for an Ethereum staking stack. A VC exists to provide exactly two guarantees:

1. **Never produce a slashable signature** (no double-block, no double-vote, no surround vote).
2. **Reliably perform validator duties** (attestation, block proposal, sync committee, aggregation, exit, registration).

An adversarial code review (`docs/2026-06-13-adversarial-code-review.md`) confirmed 46 verified findings — **1 Critical, 13 High, 13 Medium, 14 Low, 5 Info** — that defeat both guarantees as currently shipped on the `develop` branch. The headline failure modes are:

- **Slashing-protection bypass (Critical):** the standalone signer's deprecated v1 raw-root gRPC `sign(signing_root, pubkey)` handler is `add_service`-d on the live listener and performs zero EIP-3076 consultation. Any reachable client (buggy or compromised VC) can request a BLS signature over any 32-byte root for any loaded key with no double-block/double-vote/surround check and no DB record — the exact threat a remote signer's slashing DB defends against. (SS-1)
- **Signing-correctness defects that make duties fail outright against a spec-compliant beacon node:**
  - `BeaconBlock` body is tree-hashed as `List[byte]` instead of as the `BeaconBlockBody` container, so every block proposal across all forks is signed over a non-spec root and rejected by every spec-compliant BN. (E-1)
  - `Bitlist` is merkleized to `next_power_of_two(bytes)` instead of the SSZ `Bitlist[N]` chunk-count limit, so aggregator duties for real mainnet committees produce a wrong `AggregateAndProof` root and are rejected. (E-2)
  - Deneb+ SSZ publish reconstruction splices `kzg_proofs`/`blobs` bytes into the signed `SignedBeaconBlock`, so any locally-produced blob-carrying block is published malformed. (B-1/T-1)
  - `bls-to-execution-change` is signed with the Capella fork version instead of `GENESIS_FORK_VERSION`, so every withdrawal-credential update from `rvc-keygen` is silently dropped by BNs. (KG-1)
  - The signer wrongly runs attestation slashing protection on `sign_aggregate_and_proof`, deterministically breaking aggregator duties whenever the aggregator also attests for the same target epoch, and polluting attestation watermarks with non-attestation data. (SS-2/SS-3)
- **Real double-sign hazards:**
  - DVT per-peer-CN slashing namespacing lets two coordinators each collect threshold partials over conflicting messages for one validator at one slot → real slashing. (DVT-1)
  - Doppelganger detection observes only past epochs and never withholds signing for a forward window. (D-1)
  - The doppelganger enable-gate is consulted only on attestation; block proposal, sync committee, and aggregation sign fail-open inside the post-import window. (D-3)
  - DELETE `/eth/v1/keystores` fails open on slashing-protection export error, deleting keys while returning an empty interchange, so the destination VC has no record of prior signed blocks/attestations. (KM-1)
- **Availability/correctness defects that disable duties for runtime-imported keys, optimistic BNs, SSE, and sync committee:** BN-1, DT-1, S-2, SSE-1, S-5.

These cluster into a coherent remediation: close the slashing-protection boundary; fix the SSZ/tree-hash/domain bugs that make duties fail; restore the doppelganger window as a real signing gate; and restore dynamic key-management to actually wire imported keys into the duty path.

---

## 2. Goals & non-goals

### Goals

- **G1.** Remediate all 46 findings (SS-1 through TEL-1 and the 5 Info items) to a verified, tested state. Each fix lands with a RED regression test that reproduces the defect before the fix and a GREEN test that proves the fix.
- **G2.** Restore the two VC guarantees: (a) no signing path can bypass EIP-3076; (b) block proposal, attestation, aggregation, sync-committee, voluntary-exit, and validator-registration duties succeed end-to-end against a spec-compliant beacon node.
- **G3.** Encode regressions as spec-vector tests for the SSZ/tree-hash/domain bugs (E-1, E-2, B-1/T-1, KG-1) so future changes cannot silently reintroduce them.
- **G4.** Land every fix on `develop` with `cargo test`, `cargo clippy`, `cargo fmt` green, and each commit referencing its finding ID (e.g. `fix(signer): SS-1 — remove v1 raw-root gRPC sign handler from listener`).
- **G5.** Cut a release once all P0 and P1 findings are closed; P2 findings may roll into a follow-up release.

### Non-goals

- New features not implied by a finding (no new APIs, no new RPCs, no new key formats).
- Refactors beyond what a specific fix requires (no broad rearchitecture of crates not implicated by a finding).
- Re-architecting the slashing DB, the orchestrator coordinator loop, or the SSZ deserializer beyond what each cited fix demands.
- Changing the public CLI/HTTP/gRPC surface except where a finding directly requires it (e.g. SS-1 unregistering the v1 service, KM-3 hardening the keymanager bind).
- Adding new dependencies unless a fix has no in-tree alternative.

---

## 3. Target users & stakeholders

| Role | Stake in this project |
|---|---|
| Validator operators (mainnet + testnets) | Their stake is at risk from every Critical/High finding. SS-1, KM-1, DVT-1, D-1, D-3 are direct slashing exposures. E-1, E-2, B-1/T-1, KG-1, SS-2/3, BN-1, DT-1, S-2, SSE-1, S-5 are missed-duty / reward-loss exposures. |
| rs-vc engineering team | Owns the remediation. Must land fixes with regression coverage and gate the next release on completion of P0+P1. |
| Downstream integrators (Web3Signer-compatible callers, DVT coordinators, keymanager API consumers) | Affected by SS-1, SS-2/3, DVT-1, KM-1, KM-2, KM-3, URL-1, URL-2 changes. Compatibility surface must be preserved where it is correct and changed where it is wrong (deprecating SS-1 v1 endpoint). |
| Security reviewers / auditors | Will re-verify the remediation; need each finding ID traceable to commit(s), test(s), and acceptance criterion. |

---

## 4. Success metrics

- **M1.** All 46 findings closed: each finding has (a) a RED regression test committed before the fix, (b) the same test GREEN after the fix, (c) a commit message referencing the finding ID, (d) a one-line entry in a remediation tracker (per-finding state: fixed / verified / shipped).
- **M2.** Block proposal succeeds against a spec-compliant beacon node for: pre-Deneb (Bellatrix/Capella) blocks, Deneb blocks with **and** without blob commitments, and Electra+ blocks. Verified via a spec-vector regression test cross-checked against a known client's (Lighthouse or Lodestar) `tree_hash_root` output for at least one fixture per fork.
- **M3.** Aggregator duty succeeds for at least one real-committee-size `aggregation_bits` Bitlist that previously failed (E-2 regression vector), cross-checked against a known `AggregateAndProof` `tree_hash_root` fixture.
- **M4.** No signing path on the standalone signer (`rvc-signer`) can produce a signature without EIP-3076 consultation for slashable message types (blocks, attestations). Verified by:
  - Enumeration test: every registered gRPC service method on the live listener is either (a) a non-slashable message type, or (b) routed through `ScopedSlashingDb` + `stage_block`/`stage_attestation` + `commit`.
  - SS-1 regression test: two v1 `sign(signing_root, pubkey)` requests with conflicting roots for the same slot/epoch — both fail closed (Unimplemented or the service is unregistered).
- **M5.** `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green on `develop` after each merge and on the release branch.
- **M6.** Doppelganger window enforced at every signing entry point: `maybe_propose_block`, `maybe_produce_sync_messages`, `maybe_produce_sync_contributions`, `maybe_produce_aggregations`, attestation path. Verified by per-path tests: a validator with `is_signing_enabled == false` must not produce a signature on any of these paths.
- **M7.** Runtime keymanager import is observably end-to-end working: `POST /eth/v1/keystores` → duty fetch includes the new validator index → orchestrator selects it → signing path produces a valid signature within the configured doppelganger window expiry. Verified by an integration test driving the import API and asserting downstream duty/sign behavior.
- **M8.** P0 findings closed before any release; P1 findings closed before the release that supersedes v0.4.0; P2 findings tracked and either closed in the same release or explicitly deferred with rationale.

---

## 5. Prioritized requirements

Every finding is assigned a priority (P0/P1/P2), the affected crate(s), a one-line problem restatement, and an acceptance criterion describing what the regression test must prove. **Each requirement implies a RED test first** (failing for the right reason) per the cross-cutting TDD requirement (Section 6).

The prioritization below uses the review's release-blocker assessment as a starting point. SS-1, E-1, E-2, B-1/T-1, KG-1, SS-2/3, DVT-1, D-1, D-3, KM-1 are P0 because they each either (a) defeat the no-slashing guarantee, or (b) make a duty class fail outright against a spec-compliant BN. Highs and Mediums are P1; Lows and Info are P2.

### P0 — Release blockers (must be fixed before the next release)

| ID | Crate(s) / file | One-line problem | Acceptance criterion |
|---|---|---|---|
| SS-1 | `bin/rvc-signer` (`service.rs:234-312`, `main.rs:439,507`) | v1 raw-root `sign(signing_root, pubkey)` is on the live listener with zero EIP-3076 consultation. | (a) The v1 `SignerServiceServer` is no longer `add_service`-d on the live listener. (b) If a legacy v1 handler remains compiled, it returns `Status::unimplemented` unless an explicit, separately-bound, off-by-default insecure/legacy opt-in is set. (c) Regression test: two v1 sign requests with conflicting roots for one slot — both fail closed. (d) Enumeration test (M4) green. |
| E-1 | `crates/eth-types` (`block.rs:333-379`, `tree_hash_utils.rs:9-14`); consumer `crates/block-service`, `crates/crypto/src/block_signing.rs` | `BeaconBlock` body leaf tree-hashed as `List[byte]` instead of the `BeaconBlockBody` container. | (a) Body leaf is the real `hash_tree_root(BeaconBlockBody)` per the active fork's schema. (b) Spec-vector regression test: `BeaconBlock::tree_hash_root()` matches a Lighthouse/Lodestar fixture for at least one block per fork (Bellatrix, Capella, Deneb, Electra). (c) Existing comment at `block-service/src/service.rs:411` updated or removed. |
| E-2 | `crates/eth-types` (`tree_hash_utils.rs:16-42`, `aggregation.rs:20,105`) | `bitlist_tree_hash_root` merkleizes to `next_power_of_two(bytes)` instead of `chunk_count(Bitlist[N])`. | (a) Merkleization uses the SSZ type's chunk-count limit (`(N+255)/256`); for `Attestation.aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE=2048]` that is 8 chunks. (b) Spec-vector regression test: `AggregateAndProof::tree_hash_root()` for a real-committee-size `aggregation_bits` (e.g. 63 bytes) matches a known fixture. |
| B-1 / T-1 | `crates/block-service` (`service.rs:287-385,370-382`), `crates/beacon` (`ssz_deser.rs`) | Deneb+ SSZ publish splices kzg/blob bytes into the signed `SignedBeaconBlock`; framing is wrong for `SignedBlockContents`. | (a) Published block bytes are bounded at `kzg_offset`. (b) Deneb+ payloads serialize as proper `SignedBlockContents` (three variable offsets, then the bounded `SignedBeaconBlock`, then `kzg_proofs`, then `blobs`). (c) Regression test driving the propose pipeline with non-empty kzg/blob regions, asserting the published bytes deserialize to a `SignedBlockContents` whose inner block tree-hashes to the signed root. (d) L-9 ignored tests un-ignored as positive regression tests. |
| KG-1 | `bin/rvc-keygen` (`bls_to_execution.rs:51-59`) | `bls-to-execution-change` signed with `capella_fork_version` instead of `GENESIS_FORK_VERSION`. | (a) Domain built as `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, network.genesis_fork_version, network.genesis_validators_root)`. (b) The two existing tests (`test_bls_to_execution_uses_capella_fork_version`, `test_bls_to_execution_uses_actual_genesis_root`) flipped to assert genesis-version behavior. (c) Cross-checked against a staking-deposit-cli fixture. |
| SS-2 / SS-3 | `bin/rvc-signer` (`service.rs:698-740`) | `sign_aggregate_and_proof` runs attestation slashing protection, breaking aggregator duty and polluting watermarks. | (a) Handler no longer calls `require_db()`/`ScopedSlashingDb`/`stage_attestation`/commit; signs the `AggregateAndProof` root directly via `backend.sign`. (b) `tests/sign_aggregate_v2.rs` updated to assert **no** attestation row is committed. (c) End-to-end aggregator flow test: attest for (source, target) then aggregate for the same target — both succeed. |
| DVT-1 | `bin/rvc-signer` (`dvt/peer_service.rs:244,377`), `crates/slashing` (`stage.rs:353-378,505-509`) | DVT `ScopedSlashingDb` is keyed by requesting peer CN, so two coordinator CNs each get an independent namespace and can double-sign one validator/slot. | (a) DVT partial signing scopes the slashing watermark by **validator aggregate pubkey (+ GVR)**, not requesting-peer CN. (b) Per-CN multi-tenancy may remain as a secondary namespace, but a pubkey-global conflict check is enforced before releasing any partial. (c) Regression test: two distinct allow-listed peer CNs request partials for the same aggregate pubkey at the same slot with different block roots — the second is rejected as DoubleProposal. |
| D-1 | `crates/doppelganger` (`service.rs:166-258`); orchestration in `bin/rvc/src/main.rs:1264-1287` | Detection observes only PAST epochs and never withholds signing for a forward window. | (a) On startup, signing is blocked for monitored validators while liveness is polled for the next `monitoring_epochs` future epochs. (b) A validator is marked safe only after the full forward window elapses with no unexplained `is_live`. (c) Per-validator result is wired into the signing gate (see D-3). (d) Regression test: a doppelganger active in the current/future epoch is detected and the affected validator never signs. |
| D-3 | `crates/rvc/src/orchestrator/{coordinator.rs:591-618, sync_committee.rs:54,137,294, aggregation.rs}`, `crates/validator-store/src/store.rs:218-220` | Doppelganger enable-gate consulted **only** on attestation; block-proposal, sync, and aggregate sign fail-open. | (a) The gate is consulted at every signing entry point (`maybe_propose_block`, `filter_sync_duties`, `maybe_produce_aggregations`, attestation). Preferably centralized in the signer/typed-signer layer so no orchestrator path can sign for a key still inside its window. (b) `is_attesting_enabled` (or a renamed `is_signing_enabled`) for an unknown pubkey returns `false` (fail-closed). (c) Per-path tests: a validator with the gate off must not produce a signature on any of the four paths. |
| KM-1 | `crates/keymanager-api` (`handlers.rs:244-313`) | DELETE `/eth/v1/keystores` swallows slashing-protection export errors and returns an empty interchange while still deleting keys. | (a) Export failure is a hard error: **no** keystore is deleted on `export_interchange` error. The whole request aborts with 500, or each affected key is marked `error` and its deletion is skipped. (b) The `unwrap_or_else(|e| empty_interchange())` is removed. (c) Regression test: simulate an export error → assert no deletions and no empty interchange in response. |

**P0 count: 10 finding entries covering 11 individual findings (SS-2/SS-3 merged).**

### P1 — High availability/correctness + all Mediums

| ID | Crate(s) / file | One-line problem | Acceptance criterion |
|---|---|---|---|
| BN-1 | `crates/bn-manager` (`sync_status.rs:65-83,155-178`) | Optimistic BNs treated as fully Synced. | (a) `tier()` caps an optimistic node at Unsynced for EL-dependent duties. (b) Orchestrator rejects produce/attestation/duty responses whose `execution_optimistic` is true before signing. (c) Regression test with a mock BN returning `is_optimistic=true, is_syncing=false, sync_distance=0` — node is not selected. |
| DT-1 | `crates/duty-tracker` (`tracker.rs:63-82,91-95,181-185,297-301,419-423`) | `validator_indices` frozen at construction; runtime-imported validators never get duties. | (a) Index list stored behind `RwLock<Vec<String>>` (or `ArcSwap`) with an `update_validator_indices` setter. (b) Setter called by the keymanager import/delete path. (c) Regression test: import a key at runtime → duties for it are fetched on the next refresh. |
| S-2 | `bin/rvc/src/main.rs:1432-1435,1467-1470,1522-1536`, `crates/rvc/src/keymanager_adapters.rs:46-54,442-450`, `crates/rvc/src/orchestrator/coordinator.rs:167-197`, `crates/rvc/src/orchestrator/utils.rs:198-227` | Keymanager-imported keystores/remote keys never added to orchestrator's `pubkey_map`; throwaway `key_gen_tx` is dropped. | (a) Real `(key_gen_tx, key_gen_rx)` channel created, `pubkey_map.clone()`/`key_gen_tx.clone()` passed to both adapters via `.with_pubkey_map(...)`. (b) Orchestrator built with `new_with_key_gen(..., key_gen_rx, ...)`. (c) Regression test: import via the API → orchestrator sees the key → duty fetched (combine with DT-1 + C-1). |
| SSE-1 | `crates/bn-manager` (`sse.rs:173-178,297-307`) | After a callback panic, SSE consumer task never re-created; all future events silently dropped. | (a) Channel and consumer task created **inside** the reconnect path, or callback wrapped in `catch_unwind`. (b) Regression test asserts delivery actually resumes after a single callback panic; updated to remove the "second TCP connection only" assertion. |
| S-5 | `crates/rvc/src/orchestrator/{slot_context.rs:40-60, sync_committee.rs:62-71,145-154}` | Sync-committee `head_root` captured via slot-qualified `get_block_root(N)` at t=0; block N does not exist yet. | (a) `head_root` captured via `get_block_root("head")`, or falls back to slot N-1 when slot N has no block. (b) Regression test with a mock returning 404 for the current slot's `block_id` — sync messages/contributions still produced. |
| KS-1 | `crates/crypto` (`keystore.rs:41-44,198-251`), `crates/keymanager-api` (`keymanager_adapters.rs:185-190`) | Scrypt/PBKDF2 parameter ceiling permits ~8 GiB single-allocation DoS from untrusted keystore import. | (a) Reject when `n.saturating_mul(r).saturating_mul(128)` exceeds a hard cap (~1 GiB). (b) Per-field maxima aligned to EIP-2335 defaults (n=2^18, r=8). (c) Effective-cost gate applied **before** decrypt on the import path. (d) Memory-estimate helper corrected. (e) Regression test: a keystore at `n=4194304, r=16` is rejected immediately at the import API. |
| KM-2 | `crates/keymanager-api` (`handlers.rs:160-195,259-272`) | Doppelganger cancel-token map overwritten without cancellation on concurrent delete+re-import. | (a) `insert` always cancels the displaced token (`if let Some(old) = map.insert(...) { old.cancel(); }`). (b) One lock held across the delete's keystore-removal and token-removal. (c) Window-elapsed branch prunes its own entry. (d) Regression test for the concurrent delete+re-import race. |
| URL-1 | `crates/keymanager-api` (`url_validator.rs:84-121`) | SSRF deny-list omits `0.0.0.0/8` and other reserved IPv4/IPv6 ranges. | (a) Reject the full `0.0.0.0/8` plus `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, IPv4 multicast; on IPv6 normalize IPv4-compatible `::a.b.c.d` and reject other reserved ranges. (b) Same applies to runtime DNS results. (c) Regression test: `https://0.0.0.1:5052` rejected. |
| URL-2 | `crates/keymanager-api` (`url_validator.rs:29-70`), `crates/crypto` (`remote_signer.rs:157`) | DNS-rebinding protection ineffective: import-time IP validated but never pinned for the signing connection. | (a) Validated IP pinned (reqwest `resolve_to_addrs`/fixed `SocketAddr`) for the long-lived signing connection. (b) Deny-list re-validated inside the signer's connection path on every sign. (c) Doc comment updated to match. (d) Regression test with a rebinding DNS mock. |
| BN-2 | `crates/bn-manager` (`sync_status.rs:90-92,65-67`, `manager.rs:257-338`) | Before the first sync poll all BNs are Unknown and used as if synced. | (a) Synchronous `check_sync_status()` before serving duties, or `Unknown` treated distinctly so `synced_indices` does not fall through to Unknown nodes until at least one poll succeeds. (b) Startup-window regression test. |
| C-1 | `crates/rvc/src/orchestrator/coordinator.rs:317-320,147,181,211,278` | `key_gen_rx.has_changed()` used without consuming; either never fires (production) or re-clears every slot (wired). | (a) Use `borrow_and_update()` (or drive via `select!` on `changed()`). (b) Wired together with S-2 so a single import → exactly one `clear_cache()`. (c) Regression test: import → one clear → no re-clear next slot. |
| GVR-1 | `crates/slashing` (`db.rs:950-955,1562-1585,292-312`, `startup.rs:100-116`) | `import()` compares `genesis_validators_root` by raw string equality while pinned GVR is normalized; two inconsistent schemes. | (a) Both sides normalized through `parse_gvr_hex` (or a shared canonicalizer) before comparing. (b) Regression test with a 0x-prefixed, mixed-case interchange against a stripped, lowercased pinned value — same chain compares equal. |
| IMP-1 | `crates/slashing` (`db.rs:960-995,634-638`) | `import()` does not validate `source_epoch <= target_epoch`; `INSERT OR IGNORE` indexes exclude `signing_root`, silently dropping conflicting-root rows. | (a) Reject `source>target` as `InvalidInterchangeFormat`. (b) Before `INSERT OR IGNORE`, detect existing row at same key with differing `signing_root` and record it as a slashable-history marker (or raise the watermark). (c) Regression tests for both: an inverted pair is rejected; a conflicting-root second insert raises the watermark. |
| CN-1 | `bin/rvc-signer` (`slashing/scope.rs:41-88`), `crates/slashing` (`stage.rs:354-360,501-517`) | Main `SignerService` namespaces slashing per client CN; same key loaded once but used by two CNs gets no cross-CN double-block/double-vote detection. | (a) Non-DVT signer: scope by validator pubkey only **or** enforce a pubkey→CN binding and reject signing for a key under a second CN. (b) Regression test: two CNs requesting block signatures for the same pubkey/slot/different roots — the second is rejected. |
| KG-2 | `bin/rvc-keygen` (`new_mnemonic.rs:182-220`) | Keystore self-verification failure is ignored; deposit data is still written and process exits 0. | (a) `FAILED`/`MISMATCH` is a hard error: return `Err` before writing deposit data, **or** skip deposit-data emission and delete the bad keystore, so the process exits non-zero. (b) Regression test injecting a verification failure asserts non-zero exit and no `deposit_data-*.json` written for the affected validator. |
| VS-1 | `crates/validator-store` (`store.rs:343-346`) | Atomic config write does not fsync the parent directory after rename — not crash-durable. | (a) After `persist`, `File::open(parent)?.sync_all()?`. (b) Test asserts parent dir is fsync'd (mock filesystem or platform-equivalent). |
| BLD-1 | `crates/builder` (`service.rs:88-106,215-227`) | Builder validator registrations are cached by content and never refreshed; relays drop them after expiry. | (a) Re-registrations on a bounded cadence regardless of content change (per-pubkey last-submitted timestamp inside relay TTL, or unconditional resubmit each epoch as within-epoch dedup). (b) Embedded `timestamp` refreshed each time. (c) Regression test asserts a `(fee_recipient, gas_limit)`-unchanged validator is re-registered before TTL. |
| KM-3 | `bin/rvc/src/main.rs:1417-1429` | Keymanager API binds to non-loopback over plaintext HTTP with only a `warn!`; metrics server hard-refuses by contrast. | (a) Apply the same `InsecureGate(Refuse)` opt-in (`RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true`) and/or require TLS on the keymanager bind. (b) Regression test: non-loopback bind without opt-in fails closed at startup. |
| EXIT-1 | `bin/rvc/src/commands/{voluntary_exit.rs:93-142, prepare_exit.rs:76-125}` | Exit subcommands sign with an unvalidated GVR (defaults to Mainnet). | (a) Fetch `get_genesis()` from the connected BN and verify effective GVR (and genesis time) before signing. (b) Regression test: exit against a non-mainnet BN without `--network`/`--genesis-validators-root` fails closed with a clear error. |

**P1 count: 19 findings (BN-1, DT-1, S-2, SSE-1, S-5 from High; KS-1, KM-2, URL-1, URL-2, BN-2, C-1, GVR-1, IMP-1, CN-1, KG-2, VS-1, BLD-1, KM-3, EXIT-1 from Medium).**

### P2 — Lows + Info

| ID | Crate(s) / file | One-line problem | Acceptance criterion |
|---|---|---|---|
| L-1 | `crates/crypto` (`remote_signer.rs:35-42`) | Case-sensitive `starts_with("https://")` rejects valid mixed-case HTTPS URL. | Compare normalized `parsed.scheme()` against `"https"`. Test: `Https://...` accepted under `InsecureMode::Refuse`. |
| L-2 | `crates/crypto` (`pubkey.rs:54-58`) | `CanonicalPubkey::from_str` accepts double `0x` prefix and does no hex validation. | Use `strip_prefix_strict`, validate even-length ASCII hex, change `Err` to a real error. Test: `"0x0xABCD"` rejected. |
| L-3 | `crates/slashing` (`db.rs:292-312,318-368,1562-1585`) | All-zeros GVR pins a value that `pinned_gvr()` later rejects, blocking all signing. | Validate at pin time, **or** treat a stored all-zeros value as "no chain-swap check". Test: all-zeros GVR network signs successfully. |
| D-2 | `crates/doppelganger` (`service.rs:207-242`) | Incomplete liveness response silently treated as 'not live' (fail-open). | Require a liveness entry for every requested index; any missing index = inconclusive → fail closed. Test: response missing an index → that validator remains blocked. |
| L-4 | `crates/rvc/src/orchestrator/aggregation.rs:130-181` | Aggregation path signs BN `AttestationData` without `validate_attestation_data` sanity check. | Apply `validate_attestation_data` to BN response before computing root and signing. Test: invalid BN response → skip+warn, no signature. |
| S-3 | `bin/rvc/src/main.rs:1264-1287` | Startup doppelganger detection fully skipped when `current_epoch == 0`. | Always call `run_doppelganger_detection` (service handles epoch 0 conservatively), or special-case pre-genesis explicitly with logged decision. Test: epoch 0 path still invokes detection. |
| L-5 | `crates/rvc` (`monitoring.rs:88-90`) | Linux RSS computation can overflow-panic (debug) or wrap (release) on sysconf failure. | Check `> 0` before casting, use `saturating_mul`, apply to `_SC_CLK_TCK` too. Test with mock sysconf returning -1. |
| DVT-2 | `bin/rvc-signer` (`dvt/peer_client.rs:217,276-280`, `main.rs:506-520`) | DVT aggregator speaks v1 raw-root PartialSign while only the v2 typed server is registered. | Migrate to v2 typed RPCs; delete the v1 raw-root server impl and `lib.rs` export. Test: DVT threshold > 1 sign succeeds; no v1 raw-root path exists. |
| DVT-3 | `bin/rvc-signer` (`backend/dvt.rs:166-244`) | One faulty/malicious peer partial poisons threshold aggregation. | Verify each partial against its share pubkey before inclusion; combine over a chosen valid threshold-sized subset; drop and retry on failure. Test: one invalid partial → aggregation still succeeds. |
| DVT-4 | `bin/rvc-signer` (`dvt/peer_client.rs:227-237,287-293`) | Aggregator trusts peer-reported `share_index` without binding to peer identity. | Pin expected `share_index` per peer; reject mismatches before combining. Test: peer reporting wrong index → rejected. |
| DVT-5 | `bin/rvc-signer` (`dvt/lagrange.rs:25-45,58-92`) | Lagrange interpolation accepts share index 0 (the secret's x-coordinate). | Reject `index == 0` in combine; validate non-zero indices at load/allow-list time. Test: index 0 → rejected. |
| SIG-1 | `bin/rvc-signer` (`main.rs:666-678`) | `--password-dir` always fails (`read_to_string` on a directory) and does not trim trailing newline. | Implement per-keystore lookup (`<dir>/<pubkey>.txt`) **or** read a shared file with `trim_end_matches('\n')`. End-to-end test for `--password-dir`. |
| KG-3 | `bin/rvc-keygen` (`new_mnemonic.rs:123-127`, `bls_to_execution.rs:67`, `exit.rs:42`) | Keygen output directories created with default umask (not 0700). | `DirBuilder::new().recursive(true).mode(0o700)` for all three output dirs. Test asserts directory mode is 0700 on Linux. |
| SP-1 | `crates/secret-provider` (`refresh.rs:54-67`) | Refresh skip trusts unverified name-derived pubkey; can silently drop a new key. | Drop the name-derived early-skip (always fetch, dedupe by derived pubkey), or validate `pubkey_hex` and treat post-fetch mismatch as an error. Test: secret with name-collision but different payload → loaded. |
| TIM-1 | `crates/timing` (`clock.rs:52-54,97-106`) | `SystemSlotClock::time_until_slot` truncates current time to whole seconds, waking late by up to ~1s. | Mirror the ms arithmetic used by `time_until_attestation` (`as_millis()` / `slot_start_ms`). Test: sub-second offset preserved. |
| SYNC-1 | `crates/sync-service` (`lib.rs:251-260`), `crates/rvc/src/orchestrator/sync_committee.rs:208-243` | `produce_contributions` does not validate BN-returned contribution slot/subcommittee_index. | Validate `subcommittee_index`/`slot`/`beacon_block_root` against requested values; skip+warn on mismatch. Test: BN returns mismatching contribution → skipped, no signature. |
| GRPC-1/2/3 | `crates/grpc-signer` (`client.rs:115-159,183-188,124-159,291-302`) | Misleading `tls_enabled` log; partial TLS silently degrades to plaintext; no connect/RPC timeouts. | (a) `tls_enabled` computed from branch actually taken. (b) Require all three TLS fields together or error. (c) `connect_timeout` + per-RPC deadline below slot deadline. Tests for all three. |
| CLI-1 | `bin/rvc/src/main.rs:280-299` | Bearer tokens / API keys accepted as plaintext CLI args (visible via `/proc/<pid>/cmdline`). | Add `*-token-file`/env intake mirroring `--password-file`; documentation discourages inline form. Test for file-based intake. |
| TEL-1 | `crates/telemetry` (`config.rs:95-108`) | `redact_endpoint` only strips userinfo; misses query/path tokens and mishandles `@` in path. | Parse with `url::Url`, strip username/password, redact known-sensitive query keys. Test fixture covering each case. |
| L-9 (Info) | `crates/block-service` (`service.rs:2597-2622,2641-2661`) | Stale `#[ignore]` annotations claim an SSZ body-bleed bug that no longer exists. | Remove ignores and false comments; relabel as positive regression tests. (Closed alongside B-1/T-1.) |
| Info-1 | `crates/slashing` (`db.rs:769-870,1036-1095`) | `is_safe_to_propose`/`is_safe_to_sign` diverge from production EIP-3076 logic. | Delete or reimplement to delegate to a single source of truth. |
| Info-2 | `crates/slashing` (`db.rs:1222-1226,1481-1486`) | Per-row `genesis_validators_root` column written but never read. | Drop the column or assert it at check time. |
| Info-3 | `crates/rvc` (`monitoring.rs:104-109,77-90`) | macOS reports peak (`ru_maxrss`) not current RSS; `/proc/self/stat` fixed-index parsing fragile to `comm` whitespace/parens. | Query current RSS; split after the last `)`. |
| Info-4 | `crates/beacon` (`client.rs:250-256,338-343,402-435`) | Beacon-supplied GVR/fork-version strings not length/hex-validated; SSZ block path accepts empty/garbage `Eth-Consensus-Version`. | Validate 32-byte/4-byte hex at the boundary; validate `Eth-Consensus-Version` against known fork names. |
| Info-5 | `crates/beacon` (`ssz_deser.rs:115-143`), `crates/secret-provider` (`gcp.rs:49-62`), `bin/rvc/src/main.rs:1629-1634`, `crates/crypto` (`insecure.rs:249-330`) | `extract_block_header_from_ssz` dead public API lacking kzg-offset bound; GCP secret payload not zeroized in SDK buffer; metrics server bind/serve failure silently swallowed; `insecure.rs` tests mutate process-global env without serialization. | Each closed individually: delete/bound dead API; zeroize SDK buffer; log+surface metrics bind error; serialize tests with `serial_test` or env-mutex. |

**P2 count: 17 finding entries covering 25 individual findings (Lows + Info; GRPC-1/2/3 group as one entry; Info-5 groups four sub-items).**

### Finding totals
- **P0:** 10 entries / 11 findings (SS-2/SS-3 merged into one entry)
- **P1:** 19 findings
- **P2:** 17 entries / 25 findings (GRPC-1/2/3 + Info-5 each group multiple sub-items)
- **Total:** 46 individual findings, accounted for end-to-end against the review document.

---

## 6. Cross-cutting requirements

These apply to every finding above.

### 6.1 TDD discipline (Kent Beck RED → GREEN → REFACTOR)

Per `CLAUDE.md` Testing section, each finding's fix lands in three commits at minimum:

1. **RED commit:** `test(<crate>): <ID> — RED test reproduces <one-line>` — adds a failing regression test that reproduces the defect described in the review. The test must fail "for the right reason" (i.e. it asserts the spec-correct behavior and the current code violates that assertion).
2. **GREEN commit:** `fix(<crate>): <ID> — <one-line fix>` — the minimum code change to make the RED test pass. No unrelated refactors.
3. **REFACTOR commit (optional, when applicable):** `refactor(<crate>): <ID> — <improvement>` — clean up duplication, naming, structure, while keeping the test green.

Commit messages reference the finding ID. Per-finding RED-first ordering is mandatory; the reviewer at the pre-merge gate verifies the RED commit existed and failed before the GREEN commit landed.

### 6.2 Spec-vector regression tests

For SSZ/tree-hash/domain bugs (E-1, E-2, B-1/T-1, KG-1), the regression test must use a fixture sourced from a known spec-compliant implementation (Lighthouse, Lodestar, or `staking-deposit-cli`), not a value computed by rs-vc itself. Fixtures live in `crates/eth-types/tests/fixtures/` (or the analogous test-data directory in the affected crate) and are checked into the repo with provenance documented in a sibling `README` or comment.

Minimum fixture coverage:
- E-1: one `BeaconBlock` per fork (Bellatrix, Capella, Deneb, Electra) with `tree_hash_root` expected value.
- E-2: at least one `AggregateAndProof` with a real-committee-size `aggregation_bits` (e.g. 63 bytes covering ~500 validators) plus a sync `Contribution` for completeness.
- B-1/T-1: one Deneb+ block with ≥1 blob commitment, plus the expected `SignedBlockContents` SSZ bytes.
- KG-1: one `SignedBLSToExecutionChange` produced by `staking-deposit-cli` or equivalent, with the expected signing root and signature.

### 6.3 Fail-closed discipline on slashing/key-confidentiality boundaries

Every fix that touches a slashing-protection or key-confidentiality boundary must default to fail-closed: on error, refuse to sign / refuse to delete / refuse to load, rather than substituting a permissive default. This applies in particular to KM-1 (export error → no deletion), D-2 (incomplete liveness → not safe), D-3 (unknown pubkey → not enabled), L-3 (all-zeros GVR → defined behavior, not silent block-all), KS-1 (oversized params → reject), URL-1/URL-2 (unresolved/rebound → reject), CN-1 (cross-CN conflict → reject), EXIT-1 (GVR mismatch → reject), KM-3 (non-loopback without opt-in → refuse), SIG-1 (`--password-dir` failure → refuse start).

### 6.4 Git workflow

Per the user's persisted preference and `CLAUDE.md`:

- All work lands on feature branches off `develop`.
- Merges to `develop` are **fast-forward only** (`git rebase` feature branch onto `develop`, then `git merge --ff-only`). No `--no-ff` merges to bypass conflicts.
- Each finding-fix gets its own branch named `fix/<ID>-<short-slug>` (e.g. `fix/SS-1-remove-v1-raw-root`).
- Once `develop` has all P0 + P1 fixes, a release branch off `develop` is cut.

### 6.5 Pre-merge gates (per branch)

Before each fix branch can merge to `develop`:

- `cargo build` green.
- `cargo test` green (RED test from step 6.1.1 must be the new test, now passing).
- `cargo clippy -- -D warnings` green.
- `cargo fmt --check` green.
- Commit messages reference the finding ID(s).
- For P0 fixes: an explicit reviewer Approve on the PR/branch.

### 6.6 Finding-tracker artifact

A single tracker file (e.g. `plan/remediation/tracker.md`) lists every finding ID, current state (Open / RED-landed / GREEN-landed / Verified / Shipped), commit hashes, and the test file/name. Updated as each fix lands. This is the auditor-facing artifact.

---

## 7. Risks, dependencies, and finding clusters

Several findings share root causes and should be fixed as units. Splitting them risks landing partial fixes that don't actually close the hazard.

### 7.1 Clusters (fix as units)

| Cluster | Findings | Why together |
|---|---|---|
| **Doppelganger end-to-end** | D-1 + D-2 + D-3 (+ S-3) | D-1 implements the forward window; D-3 wires the gate at every signing entry point; D-2 makes the safe-decision honest; S-3 covers epoch-0. Without all four, the window is still bypassable. |
| **Dynamic key import end-to-end** | S-2 + DT-1 + C-1 (+ KM-2) | S-2 wires `pubkey_map`/`key_gen_tx`; DT-1 makes duty fetch see the new index; C-1 makes the change signal consume correctly; KM-2 closes the cancel-token race so the doppelganger-window state is consistent. Any one alone leaves runtime import broken. |
| **DVT slashing namespacing** | DVT-1 + CN-1 | Same root cause (`client_cn` in the WHERE clause). DVT-1 fixes the multi-coordinator default; CN-1 closes the analogous single-signer hole. |
| **SSZ block publish** | B-1/T-1 + L-9 | The ignored tests at `service.rs:2597/2641` are the natural positive regression tests for B-1/T-1; un-ignore as part of the fix. |
| **SSRF / DNS rebinding** | URL-1 + URL-2 | URL-1 closes static deny-list gaps; URL-2 ensures runtime resolution honors them. Either alone leaves an SSRF path open. |
| **Slashing-protection import correctness** | GVR-1 + IMP-1 | Both touch `crates/slashing/src/db.rs:import()` and the import test surface; co-locating the fix avoids two churning edits to the same function. |
| **Remote signer transport hardening** | URL-1 + URL-2 + GRPC-1/2/3 + L-1 | All bear on the remote-signer connection surface. Worth sequencing together so the test matrix covers HTTPS-correct + IP-pinned + TLS-required + timeouts in one pass. |
| **Aggregator duty correctness** | SS-2/3 + E-2 + L-4 | All three are paths through `sign_aggregate_and_proof`; fixing one without the others leaves aggregator broken (E-2) or weakened (L-4). |
| **Keygen tool correctness** | KG-1 + KG-2 + KG-3 | All in `bin/rvc-keygen`, all touch the same output dirs / verification path. |

### 7.2 Dependencies and sequencing risks

- **Spec-vector availability:** E-1, E-2, B-1/T-1, KG-1 need test fixtures sourced from another client (Lighthouse/Lodestar/staking-deposit-cli). If sourcing those is delayed, the fix can land with a self-consistent test, but acceptance criterion M2/M3 is not met until the cross-checked fixture lands. Mitigation: source fixtures from the official `consensus-spec-tests` repo (released per-fork) as the first work item of each P0 SSZ/domain finding.
- **D-3 depends on D-1's signaling:** D-3 wires the gate, but the gate's semantics depend on D-1's forward-window completion. Land D-1 first (or in the same branch); centralize the gate in the signer/typed-signer layer so future signing paths can't bypass it.
- **S-2 depends on C-1's `borrow_and_update`:** Without C-1's consume fix, S-2's wired `key_gen_tx` causes `clear_cache()` to fire every slot. Land C-1 first or together.
- **KM-1 vs KM-2 vs D-3:** KM-2's stale `set_validator_enabled(true)` only causes a realized double-sign if D-3 remains broken (so the flag actually gates signing). Land D-3 first; KM-1 and KM-2 are still required for the keymanager surface to be safe in their own right.
- **CN-1 + DVT-1 schema risk:** Changing the slashing WHERE clauses from `(client_cn, pubkey, ...)` to `(pubkey, ...)` may interact with existing on-disk slashing DBs. The fix must include a migration path (or a documented operator action) so an existing DB is not silently re-keyed. Mitigation: explicit migration logic in `crates/slashing/src/db.rs` with a regression test on a captured pre-migration DB fixture.
- **Build/test latency:** With ~26 separate fix branches (P0 + P1), CI throughput may bottleneck. Mitigation: batch P2 fixes that touch the same file into shared branches where the review trail still per-finding-traces commits.
- **No new external dependencies:** No fix in this PRD requires adding a new crate. If a fix proves otherwise (e.g. an SSZ helper), the team adds it through the normal Cargo workspace review.

### 7.3 Out-of-scope follow-ups (called out by the reviewer but not in this PRD)

The review's "Residual gaps" section flagged five areas not yet finding-confirmed:
1. End-to-end doppelganger/window race auditing beyond D-3 (covered indirectly by D-1+D-3+KM-2+D-2 together).
2. Signing-domain module review (`crates/crypto/src/{signing.rs, sync_signing.rs, aggregation_signing.rs, block_signing.rs, voluntary_exit_signing.rs, builder_signing.rs}`).
3. `crates/signer/src/lib.rs` non-slashable methods unification with the centralized gate (covered by D-3's centralization preference).
4. `crates/propagator/src` and `crates/sync-service` resubmit-path / partial-failure-as-success auditing.
5. `crates/crypto/src/bls.rs`, `validator-store/src/block_selection.rs`, slashing `stage.rs` (reviewer-cleared, no action).

Items 1, 3 are absorbed by the centralization in D-3. Items 2 and 4 are recommended as a **follow-up audit pass after the P0+P1 release** and are explicitly out of scope for this remediation project. They are not finding-traced and would expand the project boundary.

---

## 8. Assumptions

The following are reasonable assumptions made when this PRD was derived from the review document. Each is recorded so the user can correct any at the review gate.

1. **Severity = priority mapping.** P0 = the 11 findings flagged as release blockers (the Critical SS-1 plus the duty-failure Highs E-1, E-2, B-1/T-1, KG-1, SS-2/3 and the double-sign Highs DVT-1, D-1, D-3, KM-1). P1 = the remaining 5 Highs plus all 13 Mediums. P2 = all 14 Lows + 5 Info. The user can re-bucket individual findings (e.g. promote BLD-1 to P0 if MEV revenue loss is unacceptable, or promote KS-1 to P0 if untrusted multi-tenant keymanager exposure is a concern in production).
2. **Spec vectors come from `consensus-spec-tests`.** Per-fork fixtures for E-1/E-2/B-1/T-1 are sourced from the official `ethereum/consensus-spec-tests` repository tag matching the active spec, with Lighthouse or Lodestar as a secondary cross-check if a particular fixture isn't available. KG-1's BLS-to-execution-change fixture is sourced from `staking-deposit-cli` since the spec-tests don't ship signed-message fixtures.
3. **One finding = one branch, fast-forward merged.** Per the persisted preference, all merges to `develop` are fast-forward only. Each finding gets its own branch with the RED→GREEN→REFACTOR commits inside it.
4. **No deprecation period for SS-1.** The v1 raw-root sign service is unregistered immediately (not deprecated with a grace period). If any internal/external consumer is known to depend on it, the operator-facing release notes must call this out; this PRD assumes no such consumer exists in production.
5. **DVT-1 / CN-1 keying change is forward-only.** Slashing DBs already on disk are migrated by an automatic, idempotent step on first startup after the upgrade. Operators are not asked to re-run an import. If this is incorrect, the migration design must be revisited.
6. **D-3 centralization is preferred.** The gate is centralized in the signer/typed-signer layer rather than scattered across orchestrator entry points, on the assumption that the signer trusts the orchestrator only for non-slashable messages and explicitly checks `is_signing_enabled` for slashable ones. If the team prefers the orchestrator-level fix (less invasive but more error-prone for future paths), this can be flipped.
7. **`is_attesting_enabled` rename.** Since the gate is being broadened beyond attestation (D-3), the method is renamed `is_signing_enabled` and its default for unknown pubkeys is flipped to `false`. Call sites are updated as part of D-3's GREEN commit.
8. **Doppelganger forward-window length is unchanged.** The number of epochs to observe (`monitoring_epochs`) is kept at its current configured value (typically 2 epochs ≈ 12.8 minutes). Adjusting it is out of scope.
9. **KM-1 is fixed by aborting the whole DELETE on export error**, not by per-key marking. The simpler behavior (return 500, delete nothing) is preferred. The per-key fallback is acceptable if a future user request prefers it.
10. **No release of v0.4.x or v0.5.x until all P0+P1 fixes are merged to `develop` and a release branch is cut.** P2 fixes may slip into the release that supersedes v0.4.0 or roll to the next.
11. **TDD ordering is enforced via commit history, not via CI gate.** The pre-review gate confirms the RED commit existed and failed; CI cannot enforce this directly. If the team wants an automated check, it would be added later (out of scope).
12. **Tracker artifact location.** `plan/remediation/tracker.md` is created alongside this PRD as a single sheet. Updated as each finding closes. Auditors read this file.
13. **No new public crate API outside the workspace.** All fixes stay within the existing crate boundary and respect existing public/private visibility unless the fix specifically requires a new public method (e.g. DT-1's `update_validator_indices`).
14. **`cargo clippy -- -D warnings` is the standard.** The repo already uses warnings-as-errors selectively (see recent CQ commits); this PRD raises it to all-warnings-as-errors for the duration of the remediation.
15. **No external code-signing or release-signing changes.** Tag signing, supply-chain hygiene, and release ceremonies are unchanged. Only behavior fixes land.
16. **Info-5 sub-items are individually closed.** Each of the four sub-items (`extract_block_header_from_ssz`, GCP zeroize, metrics-bind swallow, `insecure.rs` test env) gets its own commit-level entry in the tracker even though they share a single PRD row.
17. **No formal external audit during remediation.** The internal review report is the authoritative gate. A re-verification pass by the same reviewer (or an analog) happens after P0+P1 close.

---

## 9. Out of scope

- New duty types or new BN APIs.
- A new slashing-protection database format.
- Migration off SQLite for the slashing DB.
- Rearchitecting the orchestrator phases.
- Performance optimizations not implied by a finding.
- Documentation overhaul beyond per-finding doc-comment fixes (L-1, URL-2 doc comment, etc.).
- The reviewer's "Residual gaps" items 2 and 4 (signing-domain module review and propagator/sync-service deeper audit).
- Any change to the v1 raw-root signer endpoint other than removing it from the live listener (no v1.5, no grace-period flag beyond the optional separately-bound legacy opt-in noted in SS-1's acceptance criterion).

---

## 10. Open questions

These are explicitly carried forward for the review gate.

- **Q1.** Is a v1 raw-root legacy gRPC service even allowed to remain compiled (returning `Unimplemented`), or should the entire `service.rs:234-312` block be deleted? (Default assumption: it returns Unimplemented unless an off-by-default insecure opt-in is set, per the review's recommended fix.)
- **Q2.** For DVT-1's pubkey-global slashing scope, is a single-watermark-per-pubkey-per-GVR (regardless of CN) acceptable, or do operators rely on per-CN namespaces for multi-tenancy auditing? (Default assumption: pubkey-global primary, CN secondary for audit-trail only.)
- **Q3.** Are existing on-disk slashing DBs in production? If so, the CN-1/DVT-1 migration design must accommodate them. (Default assumption: yes; migration is automatic and tested against a captured fixture.)
- **Q4.** Should D-3's centralized gate live in `crates/signer` or remain orchestrator-scattered? (Default assumption: centralized in `crates/signer`.)
- **Q5.** Are there validator operators using `--password-dir` today (SIG-1)? If yes, the chosen semantic (per-pubkey file vs shared file) must match expectations. (Default assumption: per-keystore `<dir>/<pubkey>.txt`, since `--password-file` exists for the shared case.)
- **Q6.** Should P2 fixes be included in the next release or deferred to a follow-up? (Default assumption: all P2 fixes that are no-risk drop-ins are included; any P2 that requires a non-trivial behavior change can be deferred individually with rationale in the tracker.)

---

## 11. Milestones & phasing

The remediation runs in three sequential milestones. Each milestone closes a coherent set of clusters from Section 7.1 and produces a verifiable artifact.

### Milestone M1 — Slashing-safety floor (P0 set 1)

**Scope:** SS-1, KM-1, DVT-1, D-1, D-3, D-2, KM-2, S-3, CN-1.

**Exit criteria:**
- No signing path on `rvc-signer` bypasses EIP-3076 (M4 verified).
- Doppelganger forward window enforced at every signing entry point.
- DVT and non-DVT slashing namespacing scoped correctly.
- All findings in this milestone closed with RED + GREEN tests.

### Milestone M2 — Duty correctness floor (P0 set 2 + P1 duty correctness)

**Scope:** E-1, E-2, B-1/T-1, KG-1, SS-2/3, L-9, BN-1, DT-1, S-2, C-1, S-5, SSE-1, BN-2, GVR-1, IMP-1, KG-2, EXIT-1, BLD-1, L-4, SYNC-1, KS-1.

**Exit criteria:**
- Block proposal succeeds end-to-end against a spec-compliant BN for all forks (M2).
- Aggregator duty succeeds for real-committee `aggregation_bits` (M3).
- Runtime keymanager import is observably end-to-end working (M7).
- Sync-committee participation succeeds at normal cadence.
- Spec-vector fixtures committed and cross-checked.

### Milestone M3 — Hardening + P2 cleanup

**Scope:** All P2 findings (Lows + Info), plus KM-3, URL-1, URL-2, VS-1.

**Exit criteria:**
- All 46 findings closed (M1, M8).
- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green on `develop` and on the release branch (M5).
- Tracker artifact reflects every finding ID with commit hashes and test references.
- Release notes drafted, identifying each finding ID closed and any operator-facing behavior changes (SS-1 unregistered, KM-3 opt-in, EXIT-1 BN cross-check, SIG-1 password semantics, slashing DB migration if applicable).

**Release gate:** P0 (M1) + P1 (M2) closed. P2 (M3) may roll into a follow-up at the user's discretion.

---

## 12. Operator-facing release-note checklist

Drafted at M3 exit. Must call out:

- SS-1: v1 raw-root sign endpoint removed from live listener. If an integrator depends on it, action required.
- KG-1: previous `bls-to-execution-change` outputs from `rvc-keygen` are invalid (wrong fork version) and must be regenerated.
- DVT-1 / CN-1: slashing DB schema migration on first start (if applicable). Backup recommended.
- KM-3: keymanager bind requires `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` for non-loopback addresses (parity with metrics).
- SIG-1: `--password-dir` semantic finalized (per-keystore file).
- EXIT-1: voluntary exit subcommands now require a reachable BN to validate GVR before signing.
- BLD-1: builder registrations now re-sent on a bounded cadence; relay traffic increases proportionally.
