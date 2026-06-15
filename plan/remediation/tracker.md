# rs-vc Security Remediation Tracker

Single auditor-facing artifact tracking every finding from the security review through
RED → GREEN → Verified → Shipped. One row per finding. Referenced by
`plan/remediation/project-plan.md` (Prerequisites) and populated per PRD §6.6.

**State legend:** `Open` → `Pre-work-landed` → `RED-landed` → `GREEN-landed` →
`Verified` → `Shipped`.

---

## Phase-1 pre-work deliverables

Additive seams/traits and question-resolutions every M1 fix consumes. Landed with zero
behavior change on `develop`.

| Issue | Deliverable | State |
|-------|-------------|-------|
| 1.0 | `plan/remediation/tracker.md` (this file) | Pre-work-landed (`4789be0`) |
| 1.1 | `eth-types::canonical` newtypes + `parse_pubkey_hex` / `parse_gvr_hex` / `parse_signing_root_hex` / `eq_gvr` | Pre-work-landed (`fa45d6a`) |
| 1.2 | `eth-types::insecure::InsecureGate { Refuse, Warn, Allow }` + `Decision` + `from_env` | Pre-work-landed (`349aaba`) |
| 1.3 | `signer::SigningEnablement` + `signer::FailClosedDefault` traits | Pre-work-landed (`d85a978`) |
| 1.4 | `slashing::SlashingDbReader` read-only trait (fail-closed on unpinned/mismatched GVR) | Pre-work-landed (`2b36e0f`, `a1682c1`) |
| 1.5 | `signer → doppelganger` Cargo dep edge | Pre-work-landed (`d1a6834`) |
| 1.6 | `tests/architecture_no_cycles.rs` standing CI gate | Pre-work-landed (`6ba3c4e`) |
| 1.7 | `crates/signer-registry` dev-only crate skeleton | Pre-work-landed (`97f7ec6`) |
| 1.8a | Q3 determination spike (production on-disk slashing DBs?) | Resolved — Outcome A (no production DBs) |
| 1.8b | Anonymized pre-migration fixture capture (conditional on Outcome B) | Skipped (Outcome A) |
| 1.9 | Q7 resolution (B-1/T-1 actual landed state) | Resolved — State X3 (deserialize half landed) |

**Open questions**

- **Q3** (gates 2.4 migration test): are there production on-disk slashing DBs? **Resolved by 1.8a → Outcome A.**
  - **Outcome: A (no production on-disk slashing DBs assumed).** Phase 2 Task 2.4's migration regression test runs against a **synthetic fixture generated inline in Rust**; Issue 1.8b is **skipped**.
  - **Method:** No operator channel is available in this autonomous execution; per the 1.8a SLA escalation path, the determination defaults to Outcome A with a deployment-config inspection as the secondary signal. Repo inspection found **no deployment infrastructure** (no helm/k8s/compose/`deploy*` dirs, no PersistentVolume/`*.sqlite` mounts). The only `slashing_db_path` references are config *examples* (`config.example.toml:40`, `README.md:45` → `./slashing_protection.sqlite`), i.e. a local default path, not a populated production DB artifact.
  - **Residual risk:** If a real production deployment with a populated `slashing.sqlite` later surfaces, Phase 2 Task 2.4's migration must be re-validated against a captured fixture (re-open 1.8b). The migration is designed idempotent/transactional so this is a re-test, not a redesign.
- **Q7** (gates 4.3/4.5 RED baseline): is B-1/T-1 partially landed? **Resolved by 1.9 → State X3 (for the L-9 deserialize tests).**
  - **Evidence:** The two `#[ignore]`d tests in `crates/block-service/src/service.rs` (`test_ssz_deser_block_contents_with_kzg_proofs` @2598, `test_ssz_deser_multiple_blobs_deneb` @2642) **PASS** when run with `cargo test -p rvc-block-service -- --ignored` (`2 passed; 0 failed`). `crates/beacon/src/ssz_deser.rs` already has `resolve_block_region_end()` which bounds the block region at the **kzg_proofs offset** for `BlockContents` (and `bytes.len()` for raw `BeaconBlock`) — the correct framing. `deserialize_block_fields` enforces this bound.
  - **Interpretation:** The **deserialize-side** body-bleed fix is **landed**; the `#[ignore]` annotations + their "Known body-bleed bug" comments are **stale**. → Phase 4 Task 4.7 (L-9) is a **relabel** job: remove the `#[ignore]`s and false comments, keep the two tests as positive regression tests.
  - **Still open for Phase 4 (Task 4.5 / B-1+T-1):** the **publish/serialize-side** `SignedBlockContents` framing at `crates/block-service/src/service.rs:287-385,370-382` is NOT covered by the deserialize tests above. Phase 4 Task 4.5's RED must target the publish path: drive the propose pipeline with non-empty kzg/blob regions and assert the **published** bytes deserialize to a `SignedBlockContents` whose inner block tree-hashes to the signed root (PRD B-1/T-1 acceptance criterion c). Per Research R3, expect to invert/extend rather than write from scratch where the deserialize round-trip already passes.

---

## Findings

| ID | Priority | Crate | One-line problem | State | RED commit | GREEN commit | Test file | Seam/trait consumed | Notes |
|----|----------|-------|------------------|-------|------------|--------------|-----------|---------------------|-------|
| SS-1 | P0 | `bin/rvc-signer` | v1 raw-root `sign(signing_root, pubkey)` on live listener with zero EIP-3076 consultation. | GREEN-landed | `17bf9b5` | `0b157cf`,`90f0ef9`,`ecd8d17` | `bin/rvc-signer/tests/v1_raw_root_bypass.rs`, `bin/rvc-signer/tests/signing_path_enumeration.rs` | `signer-registry` (1.7) | Phase 2 / 2.1–2.2. v1 unregistered + returns Unimplemented; M4 enumeration gate live; grpc-signer client migrated to v2 ListPublicKeys. |
| E-1 | P0 | `crates/eth-types` | `BeaconBlock` body leaf tree-hashed as `List[byte]` not `BeaconBlockBody` container. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.1–4.2 |
| E-2 | P0 | `crates/eth-types` | `bitlist_tree_hash_root` merkleizes to `next_power_of_two(bytes)` not chunk-count. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.3–4.4 |
| B-1 | P0 | `crates/block-service`, `crates/beacon` | Deneb+ SSZ publish splices kzg/blob bytes into signed `SignedBeaconBlock`; wrong framing. | Open | | | | Q7 (1.9) | Phase 4 / 4.5–4.7 (cluster B-1+T-1+L-9) |
| T-1 | P0 | `crates/block-service`, `crates/beacon` | `SignedBlockContents` framing wrong for Deneb+ payloads. | Open | | | | Q7 (1.9) | Phase 4 / 4.5–4.7 (cluster B-1+T-1+L-9) |
| KG-1 | P0 | `bin/rvc-keygen` | `bls-to-execution-change` signed with `capella_fork_version` not `GENESIS_FORK_VERSION`. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.8 |
| SS-2 | P0 | `bin/rvc-signer` | `sign_aggregate_and_proof` runs attestation slashing protection (breaks aggregator duty). | GREEN-landed | (n/a) | `789fd07`,`a1c3abc` | `bin/rvc-signer/tests/sign_aggregate_v2.rs` | `SigningGate` (2.9b) | Closed EARLY via 2.10a: aggregate handler routes through `gate.sign_aggregate_and_proof` (non-slashable, no `stage_attestation`). e2e attest→aggregate-same-target flow verification = Phase 4 / 4.9. |
| SS-3 | P0 | `bin/rvc-signer` | aggregate signing pollutes attestation watermarks. | GREEN-landed | (n/a) | `789fd07`,`a1c3abc` | `bin/rvc-signer/tests/sign_aggregate_v2.rs` | `SigningGate` (2.9b) | Closed EARLY via 2.10a (no attestation staging on aggregate path). e2e flow = Phase 4 / 4.9. |
| DVT-1 | P0 | `bin/rvc-signer`, `crates/slashing` | DVT `ScopedSlashingDb` keyed by peer CN → two CNs double-sign one validator/slot. | Verified | `1658149` | `c4b17d4`,`6a41ec1`,`80ae187` | `crates/slashing/tests/pubkey_scope_cross_cn.rs`, `crates/slashing/tests/migration_v3_cases.rs`, `bin/rvc-signer/src/dvt/peer_service.rs` (cross-peer test) | `PubkeyScopedDb` (2.4) | Phase 2 / 2.4 (schema v2→v3: pubkey+gvr unique indices, client_cn audit-only, 5-case resolution, non-NULL gvr on every insert, fails-closed) + 2.5 (drop client_cn from stage_*, delete ScopedSlashingDb, audit_log). DVT cross-peer shared-DB double-block rejected. |
| D-1 | P0 | `crates/doppelganger` | Detection observes only PAST epochs; never withholds signing for a forward window. | GREEN-landed | `df88377` | `0486585`,`6b84b1b` | `crates/doppelganger/tests/forward_window_satisfaction.rs` | `slashing::SlashingDbReader` (1.4); `SigningEnablement` (relocated to doppelganger in 2.6) | Phase 2 / 2.6. ForwardWindowMachine state machine (Unmonitored→Pending→Safe/Detected); Safe only at last slot of satisfaction epoch (or after, missed-tick); is_signing_enabled fail-closed (Safe only); restart-safe-skip requires RECENT attestation; observe in-window guard. SigningEnablement moved signer→doppelganger (cycle fix); legacy doppelganger reader renamed LegacySlashingHistoryReader. |
| D-3 | P0 | `crates/rvc`, `crates/validator-store` | Doppelganger gate consulted only on attestation; block/sync/aggregate fail-open. | GREEN-landed | `f13b657`,`d74e034`; `589f241` (2.10b); `b2887b4` (2.11) | `0dd44bc`,`cae7518` (2.9a); `4e00812`,`4f25d1a` (2.9b); `789fd07`,`a1c3abc` (2.10a); `7b73b03`,`8cf3b66` (2.10b); `392da00` (2.11) | `crates/signer/tests/gate_*.rs`, `crates/signer/tests/no_direct_composite_signer_outside_signer.rs`, orchestrator per-path D-3 tests (coordinator/sync_committee/aggregation), `post_import_doppelganger_signing_block_m12.rs`, builder no-availability-regression tests | `SigningEnablement` (doppelganger), `PubkeyScopedDb`, `ForwardWindowMachine`, `FailClosedDefault` | Phase 2 / 2.9a+2.9b: SigningGate complete. 2.10a: every `rvc-signer` typed handler routed through gate (SS-2/SS-3 closed early). 2.10b: orchestrator gates block/sync/aggregate per-pubkey via infallible `to_bytes()`; grep-gate Live. **2.11 DONE** (reviewer APPROVED, both sub-agents): `ValidatorStore::is_attesting_enabled`→`is_signing_enabled` everywhere; unknown-pubkey default flipped `true`→`false` (fail-closed); `ServiceBuilder::register_loaded_validators` (called in `build_services` + production `main.rs:1309`, after fail-stop doppelganger detection, before orchestrator) registers keystore-loaded keys so the flip causes NO availability regression. D-3 finding CLOSED for block/sync/aggregate/attestation-gate-present. Residual hardening (NOT original-finding blockers) → FUP-6 (attestation decode-fail-open, fold into 2.13/M6), FUP-7 (doppelganger restart-window store gap), FUP-3 (ForwardWindowMachine live wiring). |
| KM-1 | P0 | `crates/keymanager-api` | DELETE `/eth/v1/keystores` swallows export errors, returns empty interchange, deletes keys. | GREEN-landed | `2491a8f` | `399485c`,`125aec1` | `crates/keymanager-api/tests/delete_export_error_fail_closed.rs` | — | Phase 2 / 2.3. DELETE fails closed (500, no deletion) on export error; `SlashingDb::export` made a single-held-lock consistent snapshot (ADR-008 atomic); interchange now includes an empty record for every requested key. Pre-existing `has_key`→`delete` TOCTOU noted as follow-up. |
| BN-1 | P1 | `crates/bn-manager` | Optimistic BNs treated as fully Synced. | Open | | | | — | Phase 4 / 4.11–4.12 |
| DT-1 | P1 | `crates/duty-tracker` | `validator_indices` frozen at construction; runtime-imported validators never get duties. | Open | | | | — | Phase 4 / 4.13 (cluster DT-1+S-2+C-1) |
| S-2 | P1 | `bin/rvc`, `crates/rvc` | Keymanager-imported keys never added to orchestrator `pubkey_map`; `key_gen_tx` dropped. | Open | | | | — | Phase 4 / 4.13–4.14 (cluster DT-1+S-2+C-1) |
| SSE-1 | P1 | `crates/bn-manager` | After callback panic, SSE consumer task never re-created; events silently dropped. | Open | | | | — | Phase 4 / 4.18 |
| S-5 | P1 | `crates/rvc` | Sync-committee `head_root` captured via slot-qualified `get_block_root(N)` at t=0. | Open | | | | — | Phase 4 / 4.17 |
| KS-1 | P1 | `crates/crypto`, `crates/keymanager-api` | Scrypt/PBKDF2 ceiling permits ~8 GiB single-allocation DoS from keystore import. | Open | | | | — | Phase 4 / 4.25 |
| KM-2 | P1 | `crates/keymanager-api` | Doppelganger cancel-token map overwritten without cancellation on delete+re-import. | Open | | | | `ForwardWindowMachine` (2.6) | Phase 2 / 2.12 |
| URL-1 | P1 | `crates/keymanager-api` | SSRF deny-list omits `0.0.0.0/8` and other reserved IPv4/IPv6 ranges. | Open | | | | `net-policy` crate (Phase 5) | Phase 6 / 6.2a (release-blocking) |
| URL-2 | P1 | `crates/keymanager-api`, `crates/crypto` | DNS-rebinding protection ineffective: IP validated at import but never pinned for signing. | Open | | | | `net-policy` crate (Phase 5) | Phase 6 / 6.2b (release-blocking) |
| BN-2 | P1 | `crates/bn-manager` | Before first sync poll all BNs are Unknown and used as if synced. | Open | | | | — | Phase 4 / 4.11–4.12 |
| C-1 | P1 | `crates/rvc` | `key_gen_rx.has_changed()` used without consuming; never fires or re-clears every slot. | Open | | | | — | Phase 4 / 4.14 (cluster DT-1+S-2+C-1) |
| GVR-1 | P1 | `crates/slashing` | `import()` compares GVR by raw string equality while pinned GVR is normalized. | Open | | | | `eth-types::canonical::eq_gvr` (1.1) | Phase 4 / 4.19 (cluster GVR-1+IMP-1) |
| IMP-1 | P1 | `crates/slashing` | `import()` skips `source<=target` validation; `INSERT OR IGNORE` drops conflicting roots. | Open | | | | `eth-types::canonical` (1.1) | Phase 4 / 4.20 (cluster GVR-1+IMP-1) |
| CN-1 | P1 | `bin/rvc-signer`, `crates/slashing` | Main signer namespaces slashing per CN; same key under two CNs gets no cross-CN check. | Verified | `1658149` | `c4b17d4`,`6a41ec1`,`80ae187` | `crates/slashing/tests/pubkey_scope_cross_cn.rs` | `PubkeyScopedDb` (2.4) | Phase 2 / 2.4 (schema) + 2.5 (call-site rekey: stage_* drop client_cn; ScopedSlashingDb deleted; audit-only via audit_log). Cross-CN double-block & double-vote rejected (incl. DVT shared-DB). |
| KG-2 | P1 | `bin/rvc-keygen` | Keystore self-verification failure ignored; deposit data written and exit 0. | Open | | | | — | Phase 4 / 4.21 |
| VS-1 | P1 | `crates/validator-store` | Atomic config write does not fsync parent directory after rename — not crash-durable. | Open | | | | — | Phase 6 / 6.4 (release-blocking) |
| BLD-1 | P1 | `crates/builder` | Builder validator registrations cached by content, never refreshed; relays drop them. | Open | | | | — | Phase 4 / 4.23 |
| KM-3 | P1 | `bin/rvc` | Keymanager API binds non-loopback over plaintext HTTP with only a `warn!`. | Open | | | | `eth-types::insecure::InsecureGate` (1.2) | Phase 6 / 6.1 (release-blocking) |
| EXIT-1 | P1 | `bin/rvc` | Exit subcommands sign with an unvalidated GVR (defaults to Mainnet). | Open | | | | `eth-types::canonical` (1.1) | Phase 4 / 4.22 |
| L-1 | P2 | `crates/crypto` | Case-sensitive `starts_with("https://")` rejects valid mixed-case HTTPS URL. | Open | | | | `eth-types::insecure::InsecureGate` (1.2) | Phase 6 / 6.3 (cluster GRPC+L-1) |
| L-2 | P2 | `crates/crypto` | `CanonicalPubkey::from_str` accepts double `0x` prefix, no hex validation. | Open | | | | `eth-types::canonical::parse_pubkey_hex` (1.1) | Phase 6 / 6.5 |
| L-3 | P2 | `crates/slashing` | All-zeros GVR pins a value `pinned_gvr()` later rejects, blocking all signing. | Open | | | | — | Phase 6 / 6.x |
| D-2 | P2 | `crates/doppelganger` | Incomplete liveness response silently treated as 'not live' (fail-open). | GREEN-landed | `2dc2641` | `6b8bae6`,`3316eeb` | `crates/doppelganger/tests/forward_window_missing_liveness.rs` | `ForwardWindowMachine` (2.6) | Phase 2 / 2.7. observe_liveness fails closed (IncompleteLiveness{epoch,missing_count}) on any missing in-window validator; Safe requires COMPLETE window observation; dup-sample OR-fold; DoppelgangerError #[must_use]. Pubkey-hex sample-key contract documented (translation = FUP-3 @ 2.10). |
| L-4 | P2 | `crates/rvc` | Aggregation path signs BN `AttestationData` without `validate_attestation_data`. | Open | | | | — | Phase 4 / 4.9 (cluster SS-2+SS-3+L-4) |
| S-3 | P2 | `bin/rvc` | Startup doppelganger detection fully skipped when `current_epoch == 0`. | GREEN-landed | `e5ab9f7` | `2bdf929`,`6920e51` | `crates/doppelganger/tests/forward_window_pre_genesis.rs`, `crates/rvc` startup tests | `ForwardWindowMachine` (2.6) | Phase 2 / 2.8. main.rs epoch-0 guard removed; explicit pre-genesis bypass in `startup::run_doppelganger_detection` (returns all-safe, NO BN query — fixes a startup-abort regression) + in `ForwardWindowMachine::register`; idempotency wins (Detected/Safe not overridden). Clock-skew defense deferred to 2.10 (FUP-3). |
| L-5 | P2 | `crates/rvc` | Linux RSS computation can overflow-panic/wrap on sysconf failure. | Open | | | | — | Phase 6 / 6.x |
| DVT-2 | P2 | `bin/rvc-signer` | DVT aggregator speaks v1 raw-root PartialSign while only v2 typed server registered. | Open | | | | SS-1 unregister pattern (2.2) | Phase 6 / 6.8a–6.8b |
| DVT-3 | P2 | `bin/rvc-signer` | One faulty/malicious peer partial poisons threshold aggregation. | Open | | | | — | Phase 6 / 6.x |
| DVT-4 | P2 | `bin/rvc-signer` | Aggregator trusts peer-reported `share_index` without binding to peer identity. | Open | | | | — | Phase 6 / 6.x |
| DVT-5 | P2 | `bin/rvc-signer` | Lagrange interpolation accepts share index 0 (the secret's x-coordinate). | Open | | | | — | Phase 6 / 6.x |
| SIG-1 | P2 | `bin/rvc-signer` | `--password-dir` always fails (`read_to_string` on a directory); no newline trim. | Open | | | | `eth-types::insecure::InsecureGate` (1.2) | Phase 6 / 6.13 |
| KG-3 | P2 | `bin/rvc-keygen` | Keygen output directories created with default umask (not 0700). | Open | | | | — | Phase 6 / 6.x |
| SP-1 | P2 | `crates/secret-provider` | Refresh skip trusts unverified name-derived pubkey; can silently drop a new key. | Open | | | | — | Phase 6 / 6.x |
| TIM-1 | P2 | `crates/timing` | `SystemSlotClock::time_until_slot` truncates to whole seconds, waking ~1s late. | Open | | | | — | Phase 6 / 6.x |
| SYNC-1 | P2 | `crates/sync-service`, `crates/rvc` | `produce_contributions` does not validate BN-returned contribution slot/subcommittee. | Open | | | | — | Phase 6 / 6.x |
| GRPC-1 | P2 | `crates/grpc-signer` | Misleading `tls_enabled` log computed from wrong branch. | Open | | | | `net-policy` crate (Phase 5) | Phase 6 / 6.3 (cluster GRPC+L-1) |
| GRPC-2 | P2 | `crates/grpc-signer` | Partial TLS silently degrades to plaintext. | Open | | | | `net-policy` crate (Phase 5) | Phase 6 / 6.3 (cluster GRPC+L-1) |
| GRPC-3 | P2 | `crates/grpc-signer` | No connect/RPC timeouts (slot-deadline unbounded). | Open | | | | — | Phase 6 / 6.3 (cluster GRPC+L-1) |
| CLI-1 | P2 | `bin/rvc` | Bearer tokens/API keys accepted as plaintext CLI args (visible via `/proc`). | Open | | | | — | Phase 6 / 6.x |
| TEL-1 | P2 | `crates/telemetry` | `redact_endpoint` misses query/path tokens, mishandles `@` in path. | Open | | | | — | Phase 6 / 6.x |
| L-9 | P2 (Info) | `crates/block-service` | Stale `#[ignore]` annotations claim an SSZ body-bleed bug that no longer exists. | Open | | | | Q7 (1.9) | Phase 4 / 4.7 (closed with B-1/T-1) |
| Info-1 | P2 (Info) | `crates/slashing` | `is_safe_to_propose`/`is_safe_to_sign` diverge from production EIP-3076 logic. | Open | | | | — | Phase 6 / 6.x |
| Info-2 | P2 (Info) | `crates/slashing` | Per-row `genesis_validators_root` column written but never read. | Open | | | | — | Phase 6 / 6.x |
| Info-3 | P2 (Info) | `crates/rvc` | macOS reports peak (`ru_maxrss`) not current RSS; fragile `/proc/self/stat` parse. | Open | | | | — | Phase 6 / 6.x |
| Info-4 | P2 (Info) | `crates/beacon` | BN-supplied GVR/fork-version strings not length/hex-validated at the boundary. | Open | | | | `eth-types::canonical::parse_fork_version_hex` (see 6.21 note) | Phase 6 / 6.21 |
| Info-5 | P2 (Info) | `crates/beacon`, `crates/secret-provider`, `bin/rvc`, `crates/crypto` | Dead unbounded SSZ API; GCP buffer not zeroized; metrics bind error swallowed; env-mutating tests. | Open | | | | — | Phase 6 / 6.22a–6.22d |

**Total: 46 findings (1 Critical + 13 High + 13 Medium + 14 Low + 5 Info).**

Row count by priority: P0 = 12 rows (11 findings; SS-2/SS-3 split into two rows, B-1/T-1
split into two rows), P1 = 19, P2 = 25 rows (GRPC-1/2/3 and Info-5 sub-items enumerated).
Sum of finding rows = 56 rows representing 46 individual findings after cluster expansion;
the canonical individual-finding count is **46** per PRD §5 "Finding totals".

---

## Standing CI gates

| Gate | Introduced | Status |
|------|------------|--------|
| `crates/architecture-tests/tests/architecture_no_cycles.rs` | Phase 1 / 1.6 | Live (`6ba3c4e`) |
| `bin/rvc-signer/tests/signing_path_enumeration.rs` | Phase 2 / 2.2 (strict flip 2.13) | Live (`90f0ef9`); weaker invariant + count gate, strict flip pending 2.13 |
| `crates/signer/tests/no_direct_composite_signer_outside_signer.rs` | Phase 2 / 2.10b | Live (`7b73b03`,`8cf3b66`); string-literal-aware brace scanner + stacked-attr handling + bypass patterns (`crypto::sign_*`, `SecretKey::sign`); 12 self-tests |

---

## Milestone verification (PRD §4)

| Milestone | Closed by | State |
|-----------|-----------|-------|
| M4 (no signing path bypasses EIP-3076) | Phase 2 / 2.13 | Open |
| M6 (doppelganger window enforced at every entry point) | Phase 2 / 2.13 | Open |
| M2/M3/M5/M7 (duty correctness) | Phase 4 | Open |
| M1/M8 (all findings closed; release gate) | Phase 6 | Open |

---

## Discovered follow-ups (out-of-scope of their finding; tracked for later)

| ID | Discovered in | Description | Disposition |
|----|---------------|-------------|-------------|
| FUP-1 | SS-1 review (Issue 2.2) | v2 typed sign handlers in `bin/rvc-signer/src/service.rs` never increment the Prometheus `sign_total` / `sign_duration_seconds` / `sign_errors_total` counters (these were only wired on the now-removed v1 path). Counters are registered + scraped but always zero — an observability blind spot. **Pre-existing** (v2 never recorded them); not a regression of SS-1. | Defer to a follow-up: wire metrics into the 10 v2 handlers (helper or Tower layer). Not part of SS-1 acceptance criteria. |
| FUP-2 | SS-1 review (Issue 2.2) | v2 typed sign handlers log via `tracing::info!` with full (untruncated) pubkey hex and without the `audit=true` flag, diverging from the M-5 `audit::log_audit` path used by the (now-removed) v1 handler. SIEM rules keyed on `audit=true` miss v2 sign events. **Pre-existing.** | Defer: route v2 handlers through `audit::log_audit` (truncated pubkey, audit flag) + add a v2-side audit test. |
| FUP-4 | 2.10a review | `crypto::PublicKey::from_bytes` uses blst `from_bytes` (no subgroup/`key_validate` check), accepting rogue/identity-subgroup pubkeys. Pre-existing + cross-cutting (crypto crate); now load-bearing since the gate keys per-pubkey state on `pubkey.to_bytes()`. | Follow-up: switch to `key_validate` with its own RED test (rogue/identity pubkey rejected); verify no test relies on invalid pubkeys. Also: `with_sign_timeout` is not yet CLI/TOML-configurable (doc corrected; wire later). |
| FUP-3 | D-2 review (Issue 2.7) | **MUST resolve at Issue 2.10 wiring.** `ForwardWindowMachine::observe_liveness` expects `ValidatorLivenessData.index` to be the lowercase pubkey-hex (`hex::encode(pubkey.to_bytes())`), but the beacon node returns NUMERIC validator indices. When wiring the machine into the orchestrator (2.10), the adapter MUST translate numeric index → pubkey-hex and treat an untranslatable index as a missing entry (fail-closed). Add an end-to-end integration test (real adapter + mocked BN). Contract is documented in `traits.rs`/`forward_window.rs`; translation is NOT yet wired. | **Hard prerequisite for 2.10.** Without it, ForwardWindowMachine wired to the BN would stick every validator Pending (or tempt a fail-open workaround). |
| FUP-6 | 2.11 review (security-auditor SEC-001 / bug-hunter BUG-001) | **Attestation gate fails OPEN on a non-decoding / non-48-byte duty pubkey.** `crates/rvc/src/orchestrator/attestation.rs:104-124` re-decodes the raw beacon pubkey string and falls through to `true` (duty proceeds, gate skipped) when `hex::decode` fails or `len != 48`. The three sibling paths (sync/aggregate/coordinator) were fixed in 2.10b to resolve via `utils::find_pubkey` + infallible `to_bytes()`; attestation is the lone path still re-decoding. `strip_prefix("0x")` is lowercase-only while `find_pubkey` is case-insensitive, so an uppercase `0X` pubkey can skip the gate yet still resolve for signing. **Pre-existing (M-12 commit); 2.11 only renamed the call; low reachability (duties pre-filtered to registered keys that decode cleanly); no compensating control since deferred.** Also: stale comment at attestation.rs:98-103 still describes the old fail-open semantics; `info!` at builder.rs:362 labels an enabled-only count as `tracked_total`. | **Fold into Issue 2.13 (M6 "gate per path" verification).** Mirror the sibling pattern: resolve via `find_pubkey`, gate on `to_bytes()`, return `false` (skip, fail-closed) on any unresolved/non-decoding pubkey; use `TruncatedPubkey` in the warn!; fix the stale comment + log label. M6 suite should assert attestation is fail-closed. |
| FUP-7 | 2.11 review (bug-hunter BUG-002) | **Doppelganger restart-window gap (slashing-safety).** `scan_and_rearm_gate` (`crates/rvc/src/keymanager_adapters.rs`) re-arms the `DoppelgangerMonitor` gate on restart but never sets `store.set_enabled(pk, false)`; the orchestrator duty loop gates ONLY on `validator_store.is_signing_enabled` (the store flag), never on the gate. So after a restart mid-window, `register_loaded_validators` re-adds the keystore key `enabled=true` and it signs immediately, skipping the residual doppelganger window. **Pre-existing & NOT regressed by 2.11** (verified against `develop`: old fail-open default `unwrap_or(true)` produced the identical enable-on-restart end-state). The `scan_and_rearm_gate` doc-comment claim that the gate blocks the restarted process is inaccurate for the production wiring. | Dedicated follow-up issue: add a startup `scan_and_disable_in_window` pass that sets in-window keys `enabled=false` in the store and spawns the residual re-enable task (mirroring `handlers.rs:174-194`), so the orchestrator's store-based gate honors the residual window. Higher-value safety fix than FUP-6. |
| FUP-5 | 2.10b verification | **Test-infra fragility, NOT a product defect.** `cargo test --workspace` deadlocks/crawls due to tests that drive control flow with real wall-clock timers on per-test current-thread tokio runtimes: (a) `rvc-bn-manager` — all 238 tests pass individually but starve/deadlock when run in-binary-parallel; (b) orchestrator integration tests (`sync_independent_of_attesting`, `gate_per_validator_lock`) hang under CPU contention via unbounded `run_task.await` after `shutdown()`. Verified independent of any Phase-2 change (these crates/tests are outside the 2.10b diff). Also: repeated interrupted rebuilds leave many stale `tests/<name>-<hash>` binaries in `target/debug/deps` (old hashes hang); only the current fingerprint is run by cargo. | Defer: (1) cap bn-manager parallelism or migrate its timer tests to `tokio::time::pause()`/virtual clock; (2) wrap orchestrator-`run()` integration tests in an outer `tokio::time::timeout`; (3) `cargo clean` periodically to clear stale deps binaries. Until then, verify per-crate (parallel, default threads) or workspace with `--test-threads=1` on an unloaded machine. |
