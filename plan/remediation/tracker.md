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
| 1.0 | `plan/remediation/tracker.md` (this file) | Open |
| 1.1 | `eth-types::canonical` newtypes + `parse_pubkey_hex` / `parse_gvr_hex` / `parse_signing_root_hex` / `eq_gvr` | Open |
| 1.2 | `eth-types::insecure::InsecureGate { Refuse, Warn, Allow }` + `Decision` + `from_env` | Open |
| 1.3 | `signer::SigningEnablement` + `signer::FailClosedDefault` traits | Open |
| 1.4 | `slashing::SlashingDbReader` read-only trait | Open |
| 1.5 | `signer → doppelganger` Cargo dep edge | Open |
| 1.6 | `tests/architecture_no_cycles.rs` standing CI gate | Open |
| 1.7 | `crates/signer-registry` dev-only crate skeleton | Open |
| 1.8a | Q3 determination spike (production on-disk slashing DBs?) | Open |
| 1.8b | Anonymized pre-migration fixture capture (conditional on Outcome B) | Open |
| 1.9 | Q7 resolution (B-1/T-1 actual landed state) | Open |

**Open questions**

- **Q3** (gates 2.4 migration test): are there production on-disk slashing DBs? Resolved by 1.8a.
- **Q7** (gates 4.3/4.5 RED baseline): is B-1/T-1 partially landed? Resolved by 1.9.

---

## Findings

| ID | Priority | Crate | One-line problem | State | RED commit | GREEN commit | Test file | Seam/trait consumed | Notes |
|----|----------|-------|------------------|-------|------------|--------------|-----------|---------------------|-------|
| SS-1 | P0 | `bin/rvc-signer` | v1 raw-root `sign(signing_root, pubkey)` on live listener with zero EIP-3076 consultation. | Open | | | | `eth-types::insecure::InsecureGate` (1.2); `signer-registry` (1.7) | Phase 2 / 2.1–2.2 |
| E-1 | P0 | `crates/eth-types` | `BeaconBlock` body leaf tree-hashed as `List[byte]` not `BeaconBlockBody` container. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.1–4.2 |
| E-2 | P0 | `crates/eth-types` | `bitlist_tree_hash_root` merkleizes to `next_power_of_two(bytes)` not chunk-count. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.3–4.4 |
| B-1 | P0 | `crates/block-service`, `crates/beacon` | Deneb+ SSZ publish splices kzg/blob bytes into signed `SignedBeaconBlock`; wrong framing. | Open | | | | Q7 (1.9) | Phase 4 / 4.5–4.7 (cluster B-1+T-1+L-9) |
| T-1 | P0 | `crates/block-service`, `crates/beacon` | `SignedBlockContents` framing wrong for Deneb+ payloads. | Open | | | | Q7 (1.9) | Phase 4 / 4.5–4.7 (cluster B-1+T-1+L-9) |
| KG-1 | P0 | `bin/rvc-keygen` | `bls-to-execution-change` signed with `capella_fork_version` not `GENESIS_FORK_VERSION`. | Open | | | | spec-vector fixtures (Phase 3) | Phase 4 / 4.8 |
| SS-2 | P0 | `bin/rvc-signer` | `sign_aggregate_and_proof` runs attestation slashing protection (breaks aggregator duty). | Open | | | | `SigningGate` (2.9a/2.9b) | Phase 4 / 4.9 (cluster SS-2+SS-3+L-4) |
| SS-3 | P0 | `bin/rvc-signer` | aggregate signing pollutes attestation watermarks. | Open | | | | `SigningGate` (2.9a/2.9b) | Phase 4 / 4.9 (cluster SS-2+SS-3+L-4) |
| DVT-1 | P0 | `bin/rvc-signer`, `crates/slashing` | DVT `ScopedSlashingDb` keyed by peer CN → two CNs double-sign one validator/slot. | Open | | | | `PubkeyScopedDb` (2.4); fixture (1.8b) | Phase 2 / 2.4–2.5 (cluster DVT-1+CN-1) |
| D-1 | P0 | `crates/doppelganger` | Detection observes only PAST epochs; never withholds signing for a forward window. | Open | | | | `SlashingDbReader` (1.4); `SigningEnablement` (1.3) | Phase 2 / 2.6 |
| D-3 | P0 | `crates/rvc`, `crates/validator-store` | Doppelganger gate consulted only on attestation; block/sync/aggregate fail-open. | Open | | | | `SigningEnablement`+`FailClosedDefault` (1.3) | Phase 2 / 2.9a–2.11 |
| KM-1 | P0 | `crates/keymanager-api` | DELETE `/eth/v1/keystores` swallows export errors, returns empty interchange, deletes keys. | Open | | | | — | Phase 2 / 2.3 |
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
| CN-1 | P1 | `bin/rvc-signer`, `crates/slashing` | Main signer namespaces slashing per CN; same key under two CNs gets no cross-CN check. | Open | | | | `PubkeyScopedDb` (2.4) | Phase 2 / 2.4–2.5 (cluster DVT-1+CN-1) |
| KG-2 | P1 | `bin/rvc-keygen` | Keystore self-verification failure ignored; deposit data written and exit 0. | Open | | | | — | Phase 4 / 4.21 |
| VS-1 | P1 | `crates/validator-store` | Atomic config write does not fsync parent directory after rename — not crash-durable. | Open | | | | — | Phase 6 / 6.4 (release-blocking) |
| BLD-1 | P1 | `crates/builder` | Builder validator registrations cached by content, never refreshed; relays drop them. | Open | | | | — | Phase 4 / 4.23 |
| KM-3 | P1 | `bin/rvc` | Keymanager API binds non-loopback over plaintext HTTP with only a `warn!`. | Open | | | | `eth-types::insecure::InsecureGate` (1.2) | Phase 6 / 6.1 (release-blocking) |
| EXIT-1 | P1 | `bin/rvc` | Exit subcommands sign with an unvalidated GVR (defaults to Mainnet). | Open | | | | `eth-types::canonical` (1.1) | Phase 4 / 4.22 |
| L-1 | P2 | `crates/crypto` | Case-sensitive `starts_with("https://")` rejects valid mixed-case HTTPS URL. | Open | | | | `eth-types::insecure::InsecureGate` (1.2) | Phase 6 / 6.3 (cluster GRPC+L-1) |
| L-2 | P2 | `crates/crypto` | `CanonicalPubkey::from_str` accepts double `0x` prefix, no hex validation. | Open | | | | `eth-types::canonical::parse_pubkey_hex` (1.1) | Phase 6 / 6.5 |
| L-3 | P2 | `crates/slashing` | All-zeros GVR pins a value `pinned_gvr()` later rejects, blocking all signing. | Open | | | | — | Phase 6 / 6.x |
| D-2 | P2 | `crates/doppelganger` | Incomplete liveness response silently treated as 'not live' (fail-open). | Open | | | | `ForwardWindowMachine` (2.6) | Phase 2 / 2.7 |
| L-4 | P2 | `crates/rvc` | Aggregation path signs BN `AttestationData` without `validate_attestation_data`. | Open | | | | — | Phase 4 / 4.9 (cluster SS-2+SS-3+L-4) |
| S-3 | P2 | `bin/rvc` | Startup doppelganger detection fully skipped when `current_epoch == 0`. | Open | | | | `ForwardWindowMachine` (2.6) | Phase 2 / 2.8 |
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
| `tests/architecture_no_cycles.rs` | Phase 1 / 1.6 | Pending |
| `bin/rvc-signer/tests/signing_path_enumeration.rs` | Phase 2 / 2.2 (strict flip 2.13) | Pending |
| `crates/signer/tests/no_direct_composite_signer_outside_signer.rs` | Phase 2 / 2.10b | Pending |

---

## Milestone verification (PRD §4)

| Milestone | Closed by | State |
|-----------|-----------|-------|
| M4 (no signing path bypasses EIP-3076) | Phase 2 / 2.13 | Open |
| M6 (doppelganger window enforced at every entry point) | Phase 2 / 2.13 | Open |
| M2/M3/M5/M7 (duty correctness) | Phase 4 | Open |
| M1/M8 (all findings closed; release gate) | Phase 6 | Open |
