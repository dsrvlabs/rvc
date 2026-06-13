# Phase 6: M3 Fixes — Hardening + P2 Cleanup

## Phase Overview

- **Goal:** Close all remaining P2 findings (Lows + Info) plus the four M3-promoted P1 release-blockers (URL-1, URL-2, KM-3, VS-1), satisfying PRD M1 (all 46 findings closed) and PRD M8 (full closeout). The release is cut after Task 6.4 per DL-5; Tasks 6.5+ are the deferrable pure-P2 tail.
- **Issue count:** 27 issues, 44 total points.
- **Estimated duration:** ~26 working days (single-stream).
- **Entry criteria:**
  - Phase 5 complete: `crates/net-policy` skeleton merged with `DenyList`, `UrlPolicy`, `validate_url`, `PinnedResolver` all compiling with zero production consumers and unit tests green.
  - Phase 4 (M2 fixes) merged to `develop`: P0 + all M2-resident P1 closed.
  - `develop` four-gate suite green (`cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`).
  - Standing CI gates active: `tests/architecture_no_cycles.rs` and `bin/rvc-signer/tests/signing_path_enumeration.rs`.
  - `eth-types::insecure::InsecureGate` (from Phase 1 Task 1.2) and `eth-types::canonical` helpers (from Phase 1 Task 1.1) are landed and usable.
  - ADR-010 SS-1 deletion-vs-shell decision finalized on `develop` so that Issues 6.8a and 6.8b can apply the same v1-removal pattern Phase 2 Task 2.2 used (delete outright vs keep compiled returning `Status::unimplemented`).
  - Tracker file `plan/remediation/tracker.md` reflects all P0+M2-P1 findings closed.
- **Exit criteria:**
  - All 46 findings closed; tracker shows RED commit hash + GREEN commit hash + test file per finding (PRD M1, M8).
  - PRD M5 verified: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green on `develop` and on the release branch.
  - Release notes drafted per PRD §12: SS-1 v1 removal, KG-1 regeneration call-out, DVT-1/CN-1 schema migration call-out, KM-3 env-var opt-in, SIG-1 password semantics, EXIT-1 BN reachability requirement, BLD-1 increased relay traffic, URL-2 IP-pinning escape note.
  - Final release cut (combining P0+P1+P2) or P2 carry-over to follow-up release explicitly documented.

### Assumptions Recorded for This Phase

1. **PRD §8 + project-plan assumptions carried in full.** No re-litigation of severity mapping, FF-only one-finding-one-branch, no SS-1 deprecation period, KM-1 atomic abort, D-3 centralization, `is_signing_enabled` rename, KM-1/KM-2/Info-5 sub-item policy, no new external deps.
2. **Phase 5 net-policy crate is available** as a Level-2 workspace member with the deny-list, URL policy, validator, and pinned resolver primitives. URL-1+URL-2 (Task 6.2) and GRPC-1/2/3+L-1 (Task 6.3) wire production consumers to it.
3. **Release gate is "P0 + ALL P1"** per DL-5: release is cut after Task 6.4 (i.e. after 6.1, 6.2a, 6.2b, 6.3, 6.4) completes. Tasks 6.5+ are the deferrable pure-P2 tail and may roll to a follow-up at the user's discretion (PRD §11).
4. **PRD §7.1 cluster branches preserved as one-branch-per-finding splits where the blast-radius warrants it.** URL-1 (Task 6.2a) and URL-2 (Task 6.2b) ship as two adjacent branches against the same `net-policy` shared surface; GRPC-1/2/3+L-1 ships as one branch (Task 6.3); DVT-2 splits into 6.8a (client migration) + 6.8b (server removal) so the v1-deletion blast radius mirrors Phase 2 Task 2.2's SS-1 pattern under ADR-010; Info-5 sub-items each land on their own branch (Tasks 6.22a–6.22d) because "four crates on one branch" violates the architecture's max-2-file blast-radius rule.
5. **Cluster branches still apply TDD per finding**: each clustered finding lands its own RED commit before any of the cluster's GREEN commits, with the finding ID in the commit message (PRD §6.1). For the URL-1/URL-2 split this is naturally enforced (one branch per finding).
6. **Sequencing inside Phase 6:** the five release-blocking issues (6.1, 6.2a, 6.2b, 6.3, 6.4) are ordered first. 6.2a (URL-1) lands before 6.2b (URL-2) because both add the `net-policy` dep to a Level-3 consumer crate and 6.2a's keymanager-api consumer establishes the surface 6.2b's remote-signer reuses. Within the deferrable tail (6.5+), DVT and keygen findings are grouped to minimize churn in the same files; Info-5 sub-items are landed last because their per-tracker-row policy fans out across four crates.
7. **No new external dependencies.** Env-mutex for Info-5d uses `std::sync::Mutex<()>` per ADR-011, **not** `serial_test`. SSRF deny-list and TEL-1 redactor use existing `url` and stdlib types only.
8. **All P2 fixes touch ≤2 files per the architecture's "max blast radius" column.** Info-4 (boundary-hex spans `crates/beacon` at multiple call sites) is the only intentional exception. Info-5 was previously a single-branch exception spanning four crates; that violates the rule and is split here into 6.22a–6.22d (one crate per branch). Each issue's "Files likely affected" reflects this.
9. **Estimation scale:** 1 = trivial (≤½ day), 2 = small (1 day), 3 = medium (1–2 days), 5 = large (2–3 days, must be justified or split). No issue exceeds 5 points in this phase.

---

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 6.1 | KM-3 — Keymanager non-loopback InsecureGate | 2 | Phase 1 Task 1.2 | 1 day | `bin/rvc/src/main.rs` |
| 6.2a | URL-1 — `keymanager-api` consumes `net-policy::validate_url` | 3 | Phase 5 Task 5.1 | 1–2 days | `crates/keymanager-api/src/url_validator.rs`, `crates/keymanager-api/Cargo.toml` |
| 6.2b | URL-2 — `crypto::remote_signer` IP-pin via `PinnedResolver` | 3 | 6.2a (shared `net-policy` consumer surface) | 1–2 days | `crates/crypto/src/remote_signer.rs`, `crates/crypto/Cargo.toml` |
| 6.3 | GRPC-1/2/3 + L-1 cluster — gRPC TLS/deadlines/scheme | 3 | 6.2b for GRPC-3 only; L-1 independent | 1–2 days | `crates/grpc-signer/src/client.rs`, `crates/crypto/src/remote_signer.rs` |
| 6.4 | VS-1 — fsync parent directory on persist | 1 | — | ½ day | `crates/validator-store/src/store.rs` |
| 6.5 | L-2 — Strict pubkey hex parse | 1 | Phase 1 Task 1.1 | ½ day | `crates/crypto/src/pubkey.rs` |
| 6.6 | L-3 — Treat all-zeros pinned GVR as None | 1 | — | ½ day | `crates/slashing/src/db.rs` |
| 6.7 | L-5 — Linux RSS sysconf overflow | 1 | — | ½ day | `crates/rvc/src/monitoring.rs` |
| 6.8a | DVT-2 — Migrate DVT aggregator client to v2 typed PartialSign RPCs | 2 | Phase 2 Task 2.2 v1-removal pattern; ADR-010 finalized | 1 day | `bin/rvc-signer/src/dvt/peer_client.rs`, `bin/rvc-signer/src/main.rs` |
| 6.8b | DVT-2 — Delete v1 raw-root server impl + `lib.rs` export | 1 | 6.8a; ADR-010 finalized | ½ day | `bin/rvc-signer/src/lib.rs`, `bin/rvc-signer/src/service.rs` |
| 6.9 | DVT-3 — Verify each partial before combining | 3 | — | 1–2 days | `bin/rvc-signer/src/backend/dvt.rs` |
| 6.10 | DVT-4 — Pin expected share_index per peer | 2 | shared DVT test fixtures with 6.9 / 6.11 (see issue body) | 1 day | `bin/rvc-signer/src/dvt/peer_client.rs` |
| 6.11 | DVT-5 — Reject Lagrange index 0 | 1 | — | ½ day | `bin/rvc-signer/src/dvt/lagrange.rs` |
| 6.12 | KG-3 — Keygen output dirs at 0700 | 1 | — | ½ day | `bin/rvc-keygen/src/{new_mnemonic,bls_to_execution,exit}.rs` |
| 6.13 | SIG-1 — Implement --password-dir per-pubkey | 2 | Phase 1 Task 1.2 (`InsecureGate` reused for fail-closed startup) | 1 day | `bin/rvc-signer/src/main.rs` |
| 6.14 | SP-1 — Drop name-derived skip; dedupe by pubkey | 2 | — | 1 day | `crates/secret-provider/src/refresh.rs` |
| 6.15 | TIM-1 — ms-precision in time_until_slot | 1 | — | ½ day | `crates/timing/src/clock.rs` |
| 6.16 | CLI-1 — token-file / env intake for bearer tokens | 2 | — | 1 day | `bin/rvc/src/main.rs` |
| 6.17 | TEL-1 — Redact tokens in query/path | 2 | — | 1 day | `crates/telemetry/src/config.rs` |
| 6.18 | Info-1 — Collapse duplicate EIP-3076 paths | 2 | — | 1 day | `crates/slashing/src/db.rs` |
| 6.19 | Info-2 — Drop or assert per-row GVR column | 1 | — | ½ day | `crates/slashing/src/db.rs` |
| 6.20 | Info-3 — macOS current RSS + comm parse | 1 | — | ½ day | `crates/rvc/src/monitoring.rs` |
| 6.21 | Info-4 — Validate hex / fork name at BN boundary | 2 | Phase 1 Task 1.1 (+ discovered Phase 1 scope addition: `canonical::parse_fork_version_hex`) | 1 day | `crates/beacon/src/client.rs` |
| 6.22a | Info-5a — Delete dead `extract_block_header_from_ssz` | 1 | — | ½ day | `crates/beacon/src/ssz_deser.rs` |
| 6.22b | Info-5b — Zeroize GCP SDK buffer | 1 | — | ½ day | `crates/secret-provider/src/gcp.rs` |
| 6.22c | Info-5c — Surface metrics-bind error (no silent swallow) | 1 | — | ½ day | `bin/rvc/src/main.rs` |
| 6.22d | Info-5d — Env-mutex in `crypto::insecure` tests via `std::sync::Mutex<()>` | 1 | — | ½ day | `crates/crypto/src/insecure.rs` |

**Total: 27 issues, 44 points.**

> Release-blocking subset: 6.1, 6.2a, 6.2b, 6.3, 6.4 (12 points, ~5–6 days). Cut the release after 6.4.

---

## Phase Execution Plan

| Day | Issue |
|-----|-------|
| 1 | 6.1 KM-3 keymanager InsecureGate |
| 2 | 6.2a URL-1 keymanager-api consumes `net-policy::validate_url` (RED + GREEN) |
| 3 | 6.2a cont. + REFACTOR; kickoff 6.2b URL-2 RED test |
| 4 | 6.2b URL-2 GREEN (`PinnedResolver` + per-connect recheck) + REFACTOR |
| 5 | 6.3 GRPC-1/2/3 + L-1 cluster (L-1 independent of 6.2b; GRPC-3 deadline integrates with `PinnedResolver`) |
| 6 | 6.3 cont. + 6.4 VS-1 fsync (cut release after this slot) |
| 7 | 6.5 L-2 + 6.6 L-3 + 6.7 L-5 (three trivials in one day) |
| 8 | 6.8a DVT-2 migrate aggregator client to v2 typed PartialSign |
| 9 | 6.8b DVT-2 delete v1 raw-root server + `lib.rs` export + 6.11 DVT-5 |
| 10 | 6.9 DVT-3 verify partials |
| 11 | 6.9 cont. + 6.10 DVT-4 pin share_index |
| 12 | 6.10 cont. + 6.12 KG-3 dir mode |
| 13 | 6.13 SIG-1 password-dir |
| 14 | 6.14 SP-1 refresh dedupe |
| 15 | 6.15 TIM-1 + 6.19 Info-2 + 6.20 Info-3 (trivials) |
| 16 | 6.16 CLI-1 token-file |
| 17 | 6.17 TEL-1 redactor |
| 18 | 6.18 Info-1 collapse EIP-3076 paths (with new RED divergence test) |
| 19 | 6.21 Info-4 boundary hex/fork validation |
| 20 | 6.22a Info-5a ssz dead delete + 6.22b Info-5b gcp zeroize |
| 21 | 6.22c Info-5c metrics-bind error surface + 6.22d Info-5d insecure env-mutex (with flake-detection loop test) |
| 22 | Tracker reconciliation + release notes for P2 carry-over (if any) |

---

## Issues

### Issue 6.1: KM-3 — Keymanager non-loopback bind requires InsecureGate opt-in

- **Points:** 2
- **Type:** feature (security hardening)
- **Priority:** P1 (release-blocker)
- **Blocked by:** Phase 1 Task 1.2 (`eth-types::insecure::InsecureGate` landed)
- **Blocks:** release cut (must land before release alongside 6.2, 6.3, 6.4)
- **Scope:** 1 day

**Description:**
The keymanager HTTP API today binds to non-loopback addresses with only a `warn!` log, while the metrics server hard-refuses by default. Bring keymanager-API to parity: non-loopback bind must require `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` (or TLS, in a follow-up). Fail closed at startup when the opt-in is absent.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs` (around the existing keymanager bind code at `:1417-1429` per PRD).
- Approach: Use `eth-types::insecure::InsecureGate::from_env("RVC_KEYMANAGER_ALLOW_NON_LOOPBACK", InsecureGate::Refuse)` and call `evaluate` with `condition_is_insecure = !is_loopback(bind_addr)`. On `Decision::Refuse` return `anyhow::Error` from `main`.
- Mirror the metrics-server pattern (already uses `InsecureGate(Refuse)`) so operators see consistent semantics across the two HTTP services.
- Update the existing `warn!` site to either `InsecureGate::Warn` (when opt-in is set) or remove if the gate already logs.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (committed first): integration test that constructs the bin entry with a non-loopback bind config (e.g., `0.0.0.0:5052`) and no opt-in env var, asserts startup returns an error — currently fails because today only a warning is emitted.
- [ ] GREEN: same test passes after wiring `InsecureGate`.
- [ ] Loopback bind (`127.0.0.1`, `[::1]`) without opt-in succeeds.
- [ ] Non-loopback bind with `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` succeeds and logs a `warn!` once.
- [ ] Commit message references `KM-3`.
- [ ] Release notes entry drafted: "Keymanager API requires `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` for non-loopback bind, mirroring metrics."
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.

**Testing Notes:**
- Mock the bind step or use a test harness around the entrypoint; do not actually open a listening socket if it complicates CI.
- Verify behavior for both IPv4 and IPv6 non-loopback (e.g., `0.0.0.0`, `[::]`).

---

### Issue 6.2a: URL-1 — Wire `net-policy::validate_url` into keymanager-api

- **Points:** 3
- **Type:** feature (security hardening)
- **Priority:** P1 (release-blocker)
- **Blocked by:** Phase 5 Task 5.1 (`crates/net-policy` available)
- **Blocks:** 6.2b (shared `net-policy` consumer surface; 6.2a establishes the dep edge and validator pattern 6.2b reuses)
- **Scope:** 1–2 days

**Description:**
PRD §7.1 cluster, URL-1 half. Wire `crates/net-policy::validate_url` into `crates/keymanager-api/src/url_validator.rs` so the import-time URL validation rejects the full set of reserved ranges (`0.0.0.0/8`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, IPv4 multicast `224.0.0.0/4`, plus IPv4-mapped/`::a.b.c.d` normalization and IPv6 reserved ranges per RFC 6890). Re-validate against DNS resolution results via `validate_url_runtime`. URL-2's per-connect IP pinning is **out of scope here** and lands in 6.2b.

Originally PRD §7.1 put URL-1 and URL-2 in a single 5pt cluster branch. The split into 6.2a (3pt) + 6.2b (3pt) gives each finding its own RED→GREEN→REFACTOR cycle with a focused, reviewable diff, while still landing them back-to-back so the shared test matrix is exercised within one phase slot.

**Implementation Notes:**
- Files likely affected: `crates/keymanager-api/src/url_validator.rs`, `crates/keymanager-api/Cargo.toml` (add `net-policy` dep).
- Approach: Add `net-policy = { path = "../net-policy" }` to `crates/keymanager-api/Cargo.toml` (Level 3 → Level 2 edge is allowed per the level-graded DAG). Replace the existing IPv4 deny-list in `url_validator.rs` with a single `net_policy::validate_url(&url, &UrlPolicy { allow_http: false, allow_loopback: false })` call; for DNS-resolved IPs, use `validate_url_runtime` and reject if any resolved IP is in the deny-list.
- Watch out for: `tests/architecture_no_cycles.rs` must stay green after the new dep edge; verify after the GREEN commit. Existing `crates/keymanager-api/tests/` URL-validator tests must be migrated to the new API.
- New files to create: none. Tests live under `crates/keymanager-api/tests/`.

**Acceptance Criteria:**
- [ ] RED test (committed first): `https://0.0.0.1:5052`, `https://192.0.2.5/`, and an IPv6 link-local URL (`https://[fe80::1]/`) are all rejected by `keymanager-api`'s URL validator. Currently the first one is accepted (per PRD §5 P1 row URL-1 acceptance criterion).
- [ ] GREEN: same test passes after wiring `net_policy::validate_url`.
- [ ] Existing keymanager URL-validator positive cases (valid HTTPS to public IPs) still pass.
- [ ] `tests/architecture_no_cycles.rs` green after the new `keymanager-api → net-policy` dep edge.
- [ ] Commit message references `URL-1` (one RED commit, one GREEN commit, optional REFACTOR commit).
- [ ] Release notes entry drafted (consolidated with 6.2b): "Remote signer URLs validated against expanded SSRF deny-list (RFC 6890 + IANA) and IP-pinned for connection lifetime."

**Testing Notes:**
- Drive `validate_url_runtime` with a fake DNS resolver returning a deny-listed IP; assert the validation fails.
- Property test for arbitrary reserved-range IPv4 inputs lives in `net-policy`; the consumer test here is integration-flavored.

---

### Issue 6.2b: URL-2 — `crypto::remote_signer` IP-pin via `net-policy::PinnedResolver`

- **Points:** 3
- **Type:** feature (security hardening)
- **Priority:** P1 (release-blocker)
- **Blocked by:** 6.2a (shared `net-policy` consumer surface — 6.2a adds the validator path and the `net-policy` dep pattern; 6.2b reuses both)
- **Blocks:** release cut (must land before release per DL-5)
- **Scope:** 1–2 days

**Description:**
PRD §7.1 cluster, URL-2 half. Wire `net-policy::PinnedResolver` into `crates/crypto/src/remote_signer.rs` so the validated import-time IP is pinned for the long-lived signing connection and the deny-list is re-checked on every connect. Update the existing doc comment that overstates the rebinding protection.

> **Note on the 6.3 dependency:** Only the GRPC-3 (per-RPC deadline) portion of 6.3 touches `crypto::remote_signer` and depends on `PinnedResolver` being plumbed here. L-1 (mixed-case scheme) is a pure `parsed.scheme()` change with no `net-policy` interaction and is **not** gated on 6.2b — see 6.3's dependency note.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/remote_signer.rs`, `crates/crypto/Cargo.toml` (add `net-policy` dep).
- Approach: Add `net-policy = { path = "../net-policy" }` to `crates/crypto/Cargo.toml`. Build the `reqwest::Client` with `.dns_resolver(Arc::new(PinnedResolver::pin(validated_url)))` from the validated-at-import `ValidatedUrl`. Add a `pinned_resolver.recheck()` call inside the transport's connect hook (or just before every sign) that re-validates the pinned `SocketAddr` against the deny-list and returns `Err(NetPolicyError::Denied)` if any IP rotated into a reserved range.
- Watch out for: `tests/architecture_no_cycles.rs` must stay green after the new `crypto → net-policy` dep edge. The doc comment currently claims "DNS rebinding protected" without IP pinning — update to reflect the actual behavior.
- New files to create: none. Tests live under `crates/crypto/tests/`.

**Acceptance Criteria:**
- [ ] RED test (committed first): a rebinding DNS mock that returns a public IP at import (passes `validate_url`) but a deny-listed private IP at sign time (e.g., `127.0.0.1`, `192.168.x.x`) is rejected on the second resolve. Currently the connection succeeds.
- [ ] GREEN: same test passes after wiring `PinnedResolver` + per-connect `recheck`.
- [ ] `crypto::remote_signer` doc comment updated to match actual behavior (no overclaim of rebinding protection independent of `PinnedResolver`).
- [ ] `tests/architecture_no_cycles.rs` green after the new dep edge.
- [ ] Existing positive-case integration tests against a stable HTTPS endpoint still pass.
- [ ] Commit message references `URL-2`.
- [ ] Release notes entry (consolidated with 6.2a; PRD §12 URL-2 IP-pinning escape note included).

**Testing Notes:**
- Use a fake DNS resolver implementing `reqwest::dns::Resolve` to drive the rebinding mock. The first resolution returns a public IP; subsequent resolutions return a deny-listed IP — assert the second sign fails closed with a `Denied` error.
- Verify TLS is still negotiated normally when the resolver is overridden.

---

### Issue 6.3: GRPC-1/2/3 + L-1 cluster — gRPC TLS log accuracy, partial-TLS error, deadlines, mixed-case scheme

- **Points:** 3
- **Type:** chore (correctness + observability)
- **Priority:** P2
- **Blocked by:** L-1 portion (`crypto::remote_signer` mixed-case scheme) is independent and only needs Phase 5 Task 5.1's `net-policy` skeleton; the GRPC-3 portion (per-RPC deadline integrating with `PinnedResolver`) is blocked by 6.2b. GRPC-1 and GRPC-2 are independent of both. Sequenced after 6.2b for one churn pass on `crates/crypto/src/remote_signer.rs`.
- **Blocks:** release cut (must land before release per DL-5)
- **Scope:** 1–2 days

**Description:**
PRD §7.1 cluster (GRPC-1, GRPC-2, GRPC-3, L-1). Four small fixes in the gRPC client + remote signer:
- **GRPC-1:** `tls_enabled` log line is computed from input config, not the branch actually taken; misleading on partial-TLS configs. Compute from the branch.
- **GRPC-2:** Partial TLS (one or two of `ca`/`cert`/`key`) silently degrades to plaintext. Require all three together or error at startup.
- **GRPC-3:** No connect timeout, no per-RPC deadline. Add `connect_timeout` and a per-RPC deadline strictly below the slot deadline (e.g., 2s for a 12s slot). Integrates with `PinnedResolver` from 6.2b for the per-connection deadline.
- **L-1:** `crates/crypto/src/remote_signer.rs` rejects `Https://` (mixed-case scheme) under `InsecureMode::Refuse`. Compare `parsed.scheme()` against `"https"` (already lowercased by `url::Url`). **L-1 has no `net-policy` interaction and is not gated on 6.2b** — it is sequenced here for one churn pass on `remote_signer.rs`, not because of a logical dependency.

**Implementation Notes:**
- Files likely affected: `crates/grpc-signer/src/client.rs` (GRPC-1/2/3), `crates/crypto/src/remote_signer.rs` (L-1 + the per-connection deadline integration with `PinnedResolver` from 6.2b).
- Approach: For GRPC-2, return `anyhow::Error` if `ca` is `Some` and either `cert` or `key` is `None`, or vice versa. For GRPC-3, plumb `connect_timeout(Duration::from_secs(2))` into the tonic `Endpoint::builder()` and add `Request::set_timeout` (or equivalent) on every per-RPC call. For L-1, replace the `starts_with("https://")` check with `parsed.scheme().eq_ignore_ascii_case("https")` or rely on `url::Url`'s scheme lowercase normalization.
- Watch out for: existing tests that pass partial TLS configs may need updating to either supply all three fields or expect an error.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED tests (one per finding):
  - GRPC-1: assertion-based unit test that drives a partial-TLS config and inspects the structured log field for `tls_enabled` — currently `true`, must be `false` after fix.
  - GRPC-2: integration test with `ca: Some, cert: None, key: None` asserts startup returns an error.
  - GRPC-3: integration test against a slow `tonic` mock server (sleep > 2s); the client times out and returns a deadline-exceeded error.
  - L-1: unit test that `Https://signer.example:9000` parses and passes the InsecureMode::Refuse check.
- [ ] GREEN: all four tests pass.
- [ ] No regression on the existing fully-configured TLS happy path.
- [ ] Four commit messages reference GRPC-1, GRPC-2, GRPC-3, L-1 respectively (one branch).
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.

**Testing Notes:**
- For GRPC-3, the slow mock server can use `tokio::time::sleep` inside a service method; assert the client returns within `connect_timeout + per_rpc_deadline + epsilon`.
- For L-1, no network call needed — just call the URL parser and check the InsecureMode branch.

---

### Issue 6.4: VS-1 — fsync parent directory after atomic persist

- **Points:** 1
- **Type:** bug (crash durability)
- **Priority:** P1 (release-blocker)
- **Blocked by:** —
- **Blocks:** release cut (last release-blocker before cut)
- **Scope:** ½ day

**Description:**
`crates/validator-store/src/store.rs::persist` does an atomic rename but does not fsync the parent directory, so the rename is not durable across a crash on most filesystems. After the rename, open the parent directory and call `sync_all()`.

**Implementation Notes:**
- Files likely affected: `crates/validator-store/src/store.rs` (around `:343-346` per PRD).
- Approach: After the final `fs::rename(tmp, target)?` call, `let dir = std::fs::File::open(parent)?; dir.sync_all()?;`. On Windows the call is a no-op (fine).
- Use `parent = target.parent().ok_or(...)?` defensively.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (committed first): a test that mocks the filesystem (or instruments via a trait) asserting the parent directory's `sync_all` is invoked after rename — currently not called, test fails.
- [ ] GREEN: same test passes.
- [ ] On platforms without parent-directory fsync semantics (Windows), the call still compiles and runs (no-op).
- [ ] Commit message references `VS-1`.
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.

**Testing Notes:**
- If a full filesystem mock is too heavy, extract a small `Persister` trait around `rename` + `fsync_parent`, mock the trait in the test, and assert call ordering.
- Alternatively, on Linux test runners, use `strace` style instrumentation — but the trait extraction is preferable for portability.

---

### Issue 6.5: L-2 — Strict pubkey hex parse via canonical helper

- **Points:** 1
- **Type:** chore (input hygiene)
- **Priority:** P2
- **Blocked by:** Phase 1 Task 1.1 (`eth-types::canonical::parse_pubkey_hex` landed)
- **Scope:** ½ day

**Description:**
`CanonicalPubkey::from_str` in `crates/crypto/src/pubkey.rs` accepts a double `0x` prefix and skips ASCII-hex validation. Replace with `eth-types::canonical::parse_pubkey_hex`, change the `Err` variant to a real error type.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/pubkey.rs` (around `:54-58` per PRD).
- Approach: Use `eth_types::canonical::parse_pubkey_hex(s).map_err(...)`. The helper already does strict single-`0x` strip, even-length, ASCII-hex validation.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: `CanonicalPubkey::from_str("0x0xABCD...")` returns an error — currently accepts.
- [ ] GREEN: same test passes.
- [ ] Existing positive cases (well-formed 48-byte hex with single `0x`) still parse.
- [ ] Commit message references `L-2`.

**Testing Notes:**
- Cover: double `0x`, odd length, non-hex character, missing `0x` (should still fail per `parse_pubkey_hex` strict semantics).

---

### Issue 6.6: L-3 — Treat all-zeros pinned GVR as "no chain-swap check"

- **Points:** 1
- **Type:** bug
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`SlashingDb::pinned_gvr()` returns the stored value verbatim. If a network has been pinned with all-zeros GVR, later checks fail and block all signing. Either reject all-zeros at pin time, or treat a stored all-zeros value as `None` (no chain-swap check).

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (around `:292-312`, `:318-368`, `:1562-1585` per PRD).
- Approach: Per architecture, treat all-zeros as `None`. Change the `pinned_gvr()` return path to map all-zeros bytes to `None`.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: a network with all-zeros GVR pinned signs successfully (currently blocked).
- [ ] GREEN: same test passes.
- [ ] Negative test: non-zero pinned GVR mismatch still rejects.
- [ ] Commit message references `L-3`.

**Testing Notes:**
- Verify that the SQLite-stored value is still inspectable for debugging (we map at the read-side only, not at write-side).

---

### Issue 6.7: L-5 — Linux RSS sysconf overflow

- **Points:** 1
- **Type:** bug
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`crates/rvc/src/monitoring.rs` casts `sysconf` results and multiplies without checking for `-1` (sysconf error). Can overflow-panic in debug or wrap in release. Apply to both `_SC_PAGE_SIZE` and `_SC_CLK_TCK`.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/monitoring.rs` (around `:88-90` per PRD).
- Approach: Guard `if page_size > 0 { ... } else { return None; }` and use `saturating_mul` for the RSS bytes computation.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: mock sysconf returning `-1`; the function returns `None` cleanly (currently overflow-panics in debug).
- [ ] GREEN: same test passes.
- [ ] Commit message references `L-5`.

**Testing Notes:**
- If sysconf cannot be mocked easily, extract a small `SysconfProvider` trait or a `#[cfg(test)]` injection point.

---

### Issue 6.8a: DVT-2 — Migrate DVT aggregator client to v2 typed PartialSign RPCs

- **Points:** 2
- **Type:** feature (security boundary)
- **Priority:** P2
- **Blocked by:** Phase 2 Task 2.2 (SS-1 v1-removal pattern established and reused here per Phase Overview entry criteria); ADR-010 SS-1 deletion-vs-shell decision finalized.
- **Blocks:** 6.8b (server-side deletion is only safe after the last client caller is gone)
- **Scope:** 1 day

**Description:**
DVT-2 client-side half. The DVT aggregator client (`bin/rvc-signer/src/dvt/peer_client.rs`) currently speaks v1 raw-root `PartialSign` to peer signers while only the v2 typed server is registered on production listeners. Migrate the aggregator client to call the v2 typed `partial_sign_attestation` / `partial_sign_block` / etc. methods so the v1 raw-root client path has zero callers; the server-side deletion lands in 6.8b.

The original DVT-2 issue was a 3pt single-branch fix covering both client and server. Split into 6.8a (client migration, ≤2pt) + 6.8b (server removal, 1pt) so:
1. The blast-radius per branch matches the architecture's max-2-file rule.
2. The "no callers left" precondition for the server delete is structurally enforced by branch ordering (6.8a merges first; 6.8b's RED then GREEN remove the now-dead server impl).
3. The same Phase 2 Task 2.2 v1-removal pattern is reused: the choice between outright delete and `Status::unimplemented`-shell depends on the ADR-010 finalization (entry criterion).

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/dvt/peer_client.rs` (replace v1 raw-root send sites around `:217`, `:276-280` with typed v2 calls); `bin/rvc-signer/src/main.rs` (`:506-520`, update the client-construction wiring to the v2 typed stub).
- Approach: Update each v1 raw-root `PartialSign` call site to invoke the corresponding v2 typed RPC (`partial_sign_attestation`, `partial_sign_block`, `partial_sign_aggregate_and_proof`, etc.). Keep the v1 client stub compiled if ADR-010 chose `Unimplemented`-shell; remove if ADR-010 chose deletion. Either way no callers remain after this issue.
- Watch out for: the `signer-registry` enumeration test (PRD M4) must still cover every remaining handler; assert no v1 client method names appear in production code paths.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: a DVT-aggregator two-peer integration test that asserts the v2 typed handler is invoked (e.g., via a counter, capture, or `tonic` in-process mock route). Currently the test would observe v1 raw-root being called; after fix, v2 typed only.
- [ ] GREEN: same test passes; `bin/rvc-signer/tests/signing_path_enumeration.rs` (standing gate) stays green.
- [ ] No remaining production caller of the v1 raw-root client method names in `bin/rvc-signer/src/`.
- [ ] Commit message references `DVT-2` (client migration half).
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.

**Testing Notes:**
- The two-peer integration test from Phase 2 may be adaptable; otherwise use a tonic in-process mock for each peer.

---

### Issue 6.8b: DVT-2 — Delete v1 raw-root server impl + `lib.rs` export

- **Points:** 1
- **Type:** chore (dead-code removal closing the security boundary)
- **Priority:** P2
- **Blocked by:** 6.8a (no callers left); ADR-010 SS-1 deletion-vs-shell decision finalized (Phase Overview entry criterion) so the chosen pattern — delete outright vs keep compiled returning `Status::unimplemented` — is applied consistently with Phase 2 Task 2.2's SS-1 fix.
- **Blocks:** —
- **Scope:** ½ day

**Description:**
DVT-2 server-side half. With 6.8a's client migration complete, delete the v1 raw-root server `PartialSign` impl from `bin/rvc-signer` and remove the corresponding `lib.rs` re-export, applying the same v1-removal pattern Phase 2 Task 2.2 used for SS-1 (per ADR-010: either outright delete or keep the handler compiled returning `Status::unimplemented` with an off-by-default insecure-gate listener).

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/lib.rs` (remove the v1 `PartialSign` server export); `bin/rvc-signer/src/service.rs` or the equivalent service-impl file holding the v1 raw-root server `PartialSign` impl.
- Approach: Apply ADR-010's chosen pattern. If the SS-1 v1-removal decision in Phase 2 Task 2.2 was `delete outright`, do the same here: delete the server impl and the `lib.rs` re-export. If it was `keep compiled returning Unimplemented`, transform the v1 server impl to return `Status::unimplemented` and gate behind the SS-1 insecure-gate listener (`InsecureGate::Allow`). The `signer-registry` enumeration test asserts the v1 raw-root method is NOT on the live router either way.
- Watch out for: the `signer-registry` enumeration test (PRD M4 standing gate) and `tests/architecture_no_cycles.rs` must stay green.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: a unit/compile-time assertion that the v1 raw-root server impl symbol is not in the `add_service` chain on the live listener (i.e., it's either deleted or only added under the off-by-default `InsecureGate::Allow` branch). Currently the impl is in `lib.rs` and reachable.
- [ ] GREEN: the v1 raw-root server is structurally absent from the live router; `bin/rvc-signer/tests/signing_path_enumeration.rs` enumeration is unchanged or shrinks.
- [ ] The chosen pattern matches Phase 2 Task 2.2 / ADR-010.
- [ ] Commit message references `DVT-2` (server-removal half) and links to the ADR-010 decision.
- [ ] `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green.

**Testing Notes:**
- The standing `signing_path_enumeration.rs` test is the structural barrier here — no v1 method appears on the live router.

---

### Issue 6.9: DVT-3 — Verify each partial against share pubkey before combining

- **Points:** 3
- **Type:** bug (DVT safety)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** 1–2 days

**Description:**
DVT aggregator combines threshold partials without verifying each partial against its share pubkey. One faulty or malicious peer poisons the aggregation. Verify each partial individually; combine over a chosen valid threshold-sized subset; drop and retry on failure.

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/backend/dvt.rs` (`:166-244` per PRD).
- Approach: For each partial received, call `bls_verify(share_pubkey, message_root, partial_sig)`. Collect only valid partials. If we have ≥ threshold valid, proceed; else return an error indicating which peers were invalid (for diagnostics).
- Watch out for: peer share pubkeys must be known per allow-list entry; verify the data model exposes them.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: three-peer DVT with threshold 2, one peer returns a partial that does not verify against its share pubkey. Currently aggregation succeeds and produces a bad signature; after fix, the bad partial is dropped and the other two combine to a valid signature.
- [ ] GREEN: same test passes.
- [ ] Negative test: with threshold not reached after dropping invalid partials, the aggregator returns an error.
- [ ] Commit message references `DVT-3`.

**Testing Notes:**
- Use a BLS test harness where one peer's secret is rotated mid-test to force a verify failure.

---

### Issue 6.10: DVT-4 — Pin expected share_index per peer

- **Points:** 2
- **Type:** bug (DVT safety)
- **Priority:** P2
- **Blocked by:** — (logically independent of 6.9 and 6.11; see Testing Notes for the explicit shared-fixture relationship)
- **Scope:** 1 day

**Description:**
Aggregator trusts `share_index` reported by the peer. A peer reporting a wrong index can mis-bind to the wrong Lagrange coefficient. Pin expected `share_index` per peer in the allow-list; reject mismatches before combining.

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/dvt/peer_client.rs` (`:227-237`, `:287-293` per PRD).
- Approach: Add `expected_share_index: u32` to the per-peer allow-list config; compare the peer-reported value at receive time; reject if mismatched.
- New files to create: none (extend existing config schema).

**Acceptance Criteria:**
- [ ] RED test: peer reports share_index 2 but allow-list says 1 — currently accepted; after fix rejected.
- [ ] GREEN: same test passes.
- [ ] Commit message references `DVT-4`.

**Testing Notes:**
- **Shared-fixture relationship with 6.9 (DVT-3) and 6.11 (DVT-5):** all three DVT issues benefit from a common multi-peer DVT test harness (BLS share-pubkey-aware mock peers with configurable share indices and partial signatures). The fixture itself is independent — each issue tests an orthogonal property:
  - 6.9 (DVT-3) — invalid partial verified against share pubkey.
  - 6.10 (DVT-4) — peer-reported `share_index` ≠ allow-list `expected_share_index`.
  - 6.11 (DVT-5) — `share_index == 0` rejected at Lagrange combine.
- Author the shared harness once (whichever of 6.9 / 6.10 / 6.11 lands first), then reuse. No logical dependency between the three issues; they may land in any order.

---

### Issue 6.11: DVT-5 — Reject Lagrange share index 0

- **Points:** 1
- **Type:** bug (DVT cryptographic safety)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
Lagrange interpolation accepts share index 0 (the secret's x-coordinate). A peer with index 0 leaks the secret directly. Reject `index == 0` in combine; validate non-zero at allow-list load time.

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/dvt/lagrange.rs` (`:25-45`, `:58-92` per PRD).
- Approach: Early return error if any index is 0 in the combine function; allow-list parser rejects 0-indexed peers at load.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: combine with one index 0 — currently proceeds; after fix returns an error.
- [ ] GREEN: same test passes.
- [ ] Allow-list config with a 0-indexed peer fails to load.
- [ ] Commit message references `DVT-5`.

**Testing Notes:**
- Pure-function unit test; no network needed.

---

### Issue 6.12: KG-3 — Keygen output directories at mode 0700

- **Points:** 1
- **Type:** chore (security)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
Keygen output directories are created with the default umask, potentially world-readable. Use `DirBuilder` with mode 0700 on Linux for `new_mnemonic`, `bls_to_execution`, and `exit` output dirs.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/new_mnemonic.rs` (`:123-127`), `bin/rvc-keygen/src/bls_to_execution.rs` (`:67`), `bin/rvc-keygen/src/exit.rs` (`:42`).
- Approach: Use `std::os::unix::fs::DirBuilderExt`:
  ```rust
  use std::os::unix::fs::DirBuilderExt;
  std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&path)?;
  ```
  On non-Unix, fall back to current behavior (`#[cfg(unix)]` guard).
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (Linux-only): assert resulting dir's mode is 0700 — currently default umask.
- [ ] GREEN: same test passes.
- [ ] Commit message references `KG-3`.

**Testing Notes:**
- Use `#[cfg(unix)]` on the test so it does not run on Windows CI.

---

### Issue 6.13: SIG-1 — Implement --password-dir per-keystore lookup

- **Points:** 2
- **Type:** bug
- **Priority:** P2
- **Blocked by:** Phase 1 Task 1.2 (`eth-types::insecure::InsecureGate` landed). The SIG-1 fix-closed-on-missing-password-file behavior matches the `InsecureGate::Refuse` pattern — if Phase 1 Task 1.2 has not landed, `bin/rvc-signer/src/main.rs` cannot import `InsecureGate`. (Previously the dependency was hedged as "may be reused"; tightened here to a concrete blocker because the fix uses `InsecureGate::from_env(... InsecureGate::Refuse)` semantics for the missing-file path, mirroring the architecture's recommendation for SIG-1 in §"Failure Modes / Refuse start".)
- **Scope:** 1 day

**Description:**
`--password-dir` today always fails because `read_to_string` is called on a directory. Per PRD Assumption #5, implement per-keystore lookup `<dir>/<pubkey>.txt`; fail closed (refuse start) on missing file.

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/main.rs` (`:666-678` per PRD).
- Approach: When `--password-dir <dir>` is provided, for each loaded keystore at startup, read `<dir>/<keystore.pubkey>.txt`, `trim_end_matches('\n')`, and use it for decrypt. If any file is missing or unreadable, return `anyhow::Error` from `main` (consistent with the `InsecureGate::Refuse` fail-closed-at-startup semantics).
- Filename format: lowercase 96-char hex (no `0x`) of the keystore's pubkey, with `.txt` suffix. Document in code comment.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: bin entry with `--password-dir /tmp/passwords` and a single keystore; the file `/tmp/passwords/<pubkey>.txt` is present with the correct password — currently fails to read; after fix succeeds.
- [ ] GREEN: same test passes.
- [ ] Negative test: missing password file → bin returns error at startup.
- [ ] Negative test: `<pubkey>.txt` with trailing newline still decrypts correctly (trim).
- [ ] Commit message references `SIG-1`.
- [ ] Release notes entry: "`--password-dir` semantics finalized to per-keystore `<dir>/<pubkey>.txt`."

**Testing Notes:**
- Use `tempfile::tempdir` for the password directory in tests.

---

### Issue 6.14: SP-1 — Refresh dedupe by derived pubkey, not name

- **Points:** 2
- **Type:** bug
- **Priority:** P2
- **Blocked by:** —
- **Scope:** 1 day

**Description:**
Secret-provider refresh skip trusts the unverified name-derived pubkey. A name-collision with a different payload silently drops a new key. Drop the early-skip; always fetch; dedupe by the derived pubkey post-fetch; treat post-fetch mismatch as an error.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/refresh.rs` (`:54-67` per PRD).
- Approach: Remove the early-skip branch keyed on name. Always fetch the secret. Compute derived pubkey from the payload. Dedupe at insertion time using the derived pubkey as the key. If `secret.metadata.pubkey_hex` is present and disagrees with the derived pubkey, log an error and reject the secret.
- Watch out for: the GCP backend may rate-limit; check that always-fetching does not blow the API budget (likely fine; refresh cadence is slow).
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: a refresh pass where the secret backend returns a payload with a different pubkey than the secret name suggests. Currently the new key is silently dropped; after fix it is loaded.
- [ ] GREEN: same test passes.
- [ ] Negative test: `pubkey_hex` metadata mismatch with derived → error returned, secret rejected.
- [ ] Commit message references `SP-1`.

**Testing Notes:**
- Use a `MockSecretProvider` (likely already present in the crate).

---

### Issue 6.15: TIM-1 — ms-precision in time_until_slot

- **Points:** 1
- **Type:** bug
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`SystemSlotClock::time_until_slot` truncates current time to whole seconds; waking late by up to ~1s. Mirror the ms arithmetic used by the existing `time_until_attestation`.

**Implementation Notes:**
- Files likely affected: `crates/timing/src/clock.rs` (`:52-54`, `:97-106` per PRD).
- Approach: Use `as_millis()` (`u128`) and `slot_start_ms` arithmetic. Convert back to `Duration` at the end. The existing `time_until_attestation` is the template.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: a slot-clock configured at a non-integer-second offset (e.g., 500 ms into the slot); `time_until_slot` returns the correctly-aligned duration with sub-second resolution. Currently truncates.
- [ ] GREEN: same test passes.
- [ ] Existing whole-second tests still pass.
- [ ] Commit message references `TIM-1`.

**Testing Notes:**
- Drive `MockTimeSource` or equivalent with a fractional-second `now()`.

---

### Issue 6.16: CLI-1 — Bearer-token-file and env intake

- **Points:** 2
- **Type:** chore (security hardening)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** 1 day

**Description:**
Bearer tokens / API keys accepted as plaintext CLI args are visible via `/proc/<pid>/cmdline`. Add `*-token-file` and env-var intake mirroring `--password-file`; the inline-arg form remains accepted but is documented as discouraged.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs` (`:280-299` per PRD).
- Approach: For each existing `--<name>-token` flag, add `--<name>-token-file` and `RVC_<NAME>_TOKEN` env var. Precedence: file > env > inline (or document the chosen precedence). `trim_end_matches('\n')` on file reads.
- Update CLI help text and the README example to recommend the file form.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: integration test that drives `--<name>-token-file` with a tempfile, asserts the token is loaded; currently the flag does not exist.
- [ ] GREEN: same test passes.
- [ ] Env-var form also tested.
- [ ] Documentation comment in `main.rs` discourages inline form.
- [ ] Commit message references `CLI-1`.

**Testing Notes:**
- `tempfile::NamedTempFile` for the token-file test.

---

### Issue 6.17: TEL-1 — Redact tokens in query/path of telemetry endpoint

- **Points:** 2
- **Type:** bug (security/observability)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** 1 day

**Description:**
`redact_endpoint` only strips userinfo; tokens embedded in query keys (e.g., `?token=...`) or paths leak. Parse with `url::Url`; strip username/password; redact known-sensitive query keys; handle `@` in path safely.

**Implementation Notes:**
- Files likely affected: `crates/telemetry/src/config.rs` (`:95-108` per PRD).
- Approach: Parse with `url::Url::parse`. Strip `username()` and `password()` (set to empty). Iterate `query_pairs_mut()`; replace values for keys matching known patterns (`token`, `key`, `secret`, `api_key`, case-insensitive). Preserve scheme/host/port/path unchanged.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED tests covering each case:
  - `https://user:pass@host/x` → `https://host/x`
  - `https://host/x?token=abc` → `https://host/x?token=REDACTED`
  - `https://host/@cool/path` → preserved (no `@` mishandling)
  - `https://host/x?normal=ok&secret=hidden` → `https://host/x?normal=ok&secret=REDACTED`
- [ ] GREEN: all four pass.
- [ ] Commit message references `TEL-1`.

**Testing Notes:**
- Table-driven test with input/expected pairs.

---

### Issue 6.18: Info-1 — Collapse duplicate EIP-3076 logic paths

- **Points:** 2
- **Type:** refactor (single-source-of-truth restoration)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** 1 day

**Description:**
`is_safe_to_propose`/`is_safe_to_sign` in `crates/slashing/src/db.rs` reimplement EIP-3076 logic that diverges from the production `stage_block`/`stage_attestation` paths. Either delete and route all callers through `stage_*`, or reimplement as thin delegators. Architecture principle P5 forbids "two logical checks of the same EIP-3076 rule" — this is duplication, not defense-in-depth.

The previous draft of this issue had no RED test, violating the CLAUDE.md RED→GREEN→REFACTOR policy. The acceptance criteria below now add an explicit RED divergence test: a property/unit test asserting that for some input there exists a divergence between `is_safe_to_propose`/`is_safe_to_sign` and the production `stage_block`/`stage_attestation` predicate. That test must FAIL before the fix (proving the duplication exists with observably different behavior) and pass after the delete-or-delegate refactor.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (`:769-870`, `:1036-1095` per PRD).
- Approach: Audit callers of `is_safe_to_propose` / `is_safe_to_sign`. If only used by tests, delete them and update tests to use `stage_*`. If used by production, make them delegate to the staging path's predicate (single source of truth lives in `stage_*`).
- New files to create: none. RED test lives at `crates/slashing/tests/info_1_eip3076_single_source_of_truth.rs` (or similar).

**Acceptance Criteria:**
- [ ] **RED test (committed first):** a property/unit test enumerating EIP-3076-relevant input shapes (block slot+root pairs and attestation source+target+root tuples; include both "obviously safe" and "boundary" cases like same-slot/different-root, surround-vote pairs, and equal-source+equal-target+different-root pairs). For each input, compare `is_safe_to_propose`/`is_safe_to_sign` against the predicate exercised by `stage_block`/`stage_attestation` (e.g., "does staging succeed without recording a slashable conflict?"). The test asserts the two return values are equal for every input. Currently fails on at least one input because the two paths diverge — this is the Info-1 defect made observable.
- [ ] **GREEN:** same test passes after the delete-or-delegate refactor (single source of truth in `stage_*`).
- [ ] All caller sites of `is_safe_to_propose` / `is_safe_to_sign` identified and either updated or removed (use `rg 'is_safe_to_propose|is_safe_to_sign'` to enumerate).
- [ ] No remaining duplication of EIP-3076 logic in `crates/slashing/src/db.rs` (architecture P5: duplication-of-rules is forbidden; this is "duplication" not "defense-in-depth" per the architecture's distinction).
- [ ] `cargo test` and `cargo clippy -- -D warnings` green.
- [ ] Commit message references `Info-1` (one RED commit + one GREEN commit minimum; optional REFACTOR commit if the delegate path benefits from naming cleanup).

**Testing Notes:**
- The RED divergence test should be authored as either a `proptest` property test (preferred — `proptest` is already in dev-deps per the architecture) or a table-driven unit test with hand-picked boundary cases. The property formulation is "∀ (input). is_safe_to_propose(input) == stage_block_predicate(input)" and similarly for attestations.
- If the delete-and-update-tests path is chosen, the RED test still lands first against the legacy `is_safe_*` API, then the GREEN refactor either makes both functions delegate (test still works) or removes them and the test is rewritten to assert there is no `is_safe_*` symbol in the public API.

---

### Issue 6.19: Info-2 — Drop or assert per-row GVR column

- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
The per-row `genesis_validators_root` column is written but never read for any check. Either drop the column (schema migration) or add an assertion at check time so the value is meaningful.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (`:1222-1226`, `:1481-1486` per PRD).
- Approach: Cheapest path is to assert at check time — on every `stage_*` read of a row, assert the row's GVR matches the pinned GVR. Drops the duplication risk without a schema migration.
- Watch out for: existing rows from before the assertion may have inconsistent GVR; the assertion must be lenient on legacy rows or include a one-shot data fix.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test: inject a row with mismatched per-row GVR vs pinned GVR; stage path returns an error (currently silent).
- [ ] GREEN: same test passes.
- [ ] No new schema version needed if assertion-only.
- [ ] Commit message references `Info-2`.

**Testing Notes:**
- Use direct SQL via the test harness to plant the mismatched row.

---

### Issue 6.20: Info-3 — macOS current RSS + comm whitespace-safe parse

- **Points:** 1
- **Type:** bug (observability)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
On macOS, `ru_maxrss` reports peak RSS, not current. On Linux, fixed-index parsing of `/proc/self/stat` is fragile to `comm` whitespace/parens. Fix both.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/monitoring.rs` (`:104-109`, `:77-90` per PRD).
- Approach: macOS → query current RSS via `mach_task_basic_info` or `task_info`. Linux → split `stat` after the last `)`, then split the remainder on whitespace and index from the post-`comm` field onward.
- Watch out for: `task_info` requires Mach calls. If too heavy, fall back to `proc_pidinfo` via `libc`. Verify on a macOS CI runner.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED tests:
  - macOS: a process with growing-then-shrinking memory — current RSS goes down, peak does not. Currently reports peak.
  - Linux: a synthetic `/proc/self/stat` with parens in `comm` is parsed correctly.
- [ ] GREEN: both pass.
- [ ] Commit message references `Info-3`.

**Testing Notes:**
- Linux side can be tested in isolation by extracting the parser to a pure function and feeding fixture strings.

---

### Issue 6.21: Info-4 — Validate hex/fork name at BN boundary

- **Points:** 2
- **Type:** bug (input hygiene)
- **Priority:** P2
- **Blocked by:** Phase 1 Task 1.1 (`canonical` helpers for hex validation: `parse_pubkey_hex`, `parse_gvr_hex`, `parse_signing_root_hex`). **Discovered scope addition:** `parse_fork_version_hex` (a 4-byte-hex variant) is NOT among the Phase 1 Task 1.1 helpers — Phase 1 Task 1.1's scope per `project-plan.md:47` and `issues/01-phase-1.md` only ships the three pubkey/gvr/signing-root newtypes. This issue requires `parse_fork_version_hex` as well; see Implementation Notes for the resolution path.
- **Scope:** 1 day (assumes the scope addition lands in Phase 1 or as a tiny prerequisite issue; if implemented inline here, scope grows to 2 days / 3pt — flag at review).
- **Flagged Phase 1 scope addition:** `eth-types::canonical::parse_fork_version_hex` (returns `Result<[u8; 4], ParseError>`; strict single `0x` prefix; ASCII-hex; even length 8 chars).

**Description:**
Beacon-API responses provide GVR / fork-version strings unvalidated; SSZ block path accepts an empty or garbage `Eth-Consensus-Version` header. Validate at the boundary.

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/client.rs` (`:250-256`, `:338-343`, `:402-435` per PRD), and (if the scope addition is implemented inline) `crates/eth-types/src/canonical/fork_version_hex.rs` + `crates/eth-types/src/canonical/mod.rs`.
- Approach:
  - GVR: 32-byte hex via `canonical::parse_gvr_hex` (already in Phase 1 Task 1.1).
  - Fork version: 4-byte hex. **Resolution path:** preferred is to add `canonical::parse_fork_version_hex` as a tiny Phase 1 retroactive extension (one new file in the canonical module mirroring `signing_root_hex.rs`'s structure) and consume it here. Fallback: inline `<[u8; 4]>::from_hex` with `0x` strip and `len == 8` check at this site, with a TODO to promote later. Flag the chosen path at the review gate.
  - `Eth-Consensus-Version`: case-insensitive match against a known set (`bellatrix`, `capella`, `deneb`, `electra`); else reject with descriptive error.
- Watch out for: tests may have used invalid header values that now break; update.
- New files to create: optionally `crates/eth-types/src/canonical/fork_version_hex.rs` (if the scope addition path is chosen).

**Acceptance Criteria:**
- [ ] RED tests:
  - BN returns malformed GVR (`"not-hex"`) → client returns error.
  - BN returns malformed fork version (`"0x123"` — odd length) → client returns error.
  - BN returns `Eth-Consensus-Version: foo` → client returns error.
- [ ] GREEN: all three pass.
- [ ] Positive tests for each known fork still pass.
- [ ] If `parse_fork_version_hex` is added to `eth-types::canonical`, its unit test (strict-hex, double-`0x` rejection, even-length) lives alongside the other canonical-helper tests.
- [ ] Tracker entry notes whether the scope addition landed in Phase 1 retroactively or inline here.
- [ ] Commit message references `Info-4` (and the scope-addition issue if a separate Phase 1 extension was filed).

**Testing Notes:**
- Use the existing BN mock to drive malformed responses.

---

### Issue 6.22a: Info-5a — Delete dead `extract_block_header_from_ssz` API

- **Points:** 1
- **Type:** chore (dead-code removal)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`extract_block_header_from_ssz` in `crates/beacon/src/ssz_deser.rs` (`:115-143` per PRD) is a dead public API that lacks a kzg-offset bound. No production caller exists. Delete it; or, if a downstream test reaches for it, replace with a clearly-bounded alternative.

The original Info-5 issue collapsed four sub-items across four crates (`beacon`, `secret-provider`, `bin/rvc`, `crypto`) into one branch. That violates the architecture's max-2-file blast-radius rule and the architectural principle that one branch = one focused diff. Split into 6.22a–6.22d (one branch per crate / sub-item), each landing its own RED+GREEN+optional REFACTOR commits. Per PRD Assumption #16, the tracker shows four individual rows closed.

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/ssz_deser.rs`, possibly `crates/beacon/src/lib.rs` (re-export).
- Approach: `rg 'extract_block_header_from_ssz'` to confirm no production consumers; remove the function and any `pub` re-export. If used by tests, either delete the tests or replace the call with a bounded `from_ssz_bytes::<BeaconBlockHeader>` slice.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (committed first): a compile-time reference `_ = beacon::extract_block_header_from_ssz;` in a test (or a `cargo doc`-assertion script) that fails after the function is removed.
- [ ] GREEN: the public API is deleted; the RED test is removed or rewritten to assert absence (compile-fail test or doc-scrape).
- [ ] No remaining production callers (rg-confirmed).
- [ ] Commit message references `Info-5a`.
- [ ] `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green.

**Testing Notes:**
- Alternative formulation: a small `tests/info_5a_deleted.rs` that uses `trybuild` or a simple compile-fail comment. The simplest variant: deleting the function makes the RED reference fail to compile, and the GREEN commit removes the reference.

---

### Issue 6.22b: Info-5b — Zeroize GCP SDK secret buffer

- **Points:** 1
- **Type:** bug (key-confidentiality hygiene)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`crates/secret-provider/src/gcp.rs` (`:49-62` per PRD) reads a BLS-key secret from the GCP SDK into an SDK-owned `Vec<u8>` buffer that is dropped without zeroization. Wrap the SDK output in `Zeroizing<Vec<u8>>` (the `zeroize` crate is already used elsewhere in `crates/crypto`) so the secret bytes are scrubbed on drop, matching the rest of the key-handling discipline.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/gcp.rs`.
- Approach: Where the SDK returns `Vec<u8>` (or equivalent), immediately wrap in `Zeroizing::new(...)` or copy into a `Zeroizing<Vec<u8>>` and drop the SDK-owned `Vec`. If the SDK gives access to its internal buffer, manually zeroize after copy.
- Watch out for: confirm `zeroize` is already in `secret-provider`'s deps (or transitively); if not, add via path/version matching `crypto`'s current usage (NOT a new external dep per principle P6 — `zeroize` is in-tree).
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (committed first): a unit test that loads a known-pattern byte sequence through the GCP secret path (mocked SDK), captures the buffer address, and asserts the bytes are still readable after the operation (i.e., zeroization has NOT happened). Currently passes (buffer is readable).
- [ ] GREEN: same test asserts the bytes are zero after drop; passes after wrapping with `Zeroizing`.
- [ ] Commit message references `Info-5b`.
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.

**Testing Notes:**
- Reading freed memory is UB; structure the test around `Zeroizing`'s observable `Drop` (e.g., wrap a `Vec` inside a scope, take a raw pointer before drop, then check post-drop using `unsafe` — or use the `zeroize::Zeroize` trait's direct call in the test rather than relying on `Drop` observation).

---

### Issue 6.22c: Info-5c — Surface metrics-server bind/serve error (no silent swallow)

- **Points:** 1
- **Type:** bug (observability)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`bin/rvc/src/main.rs` (`:1629-1634` per PRD) spawns the metrics HTTP server in a way that swallows bind/serve errors. Operators see no error when the metrics endpoint silently fails. Surface the error: log + non-zero exit at startup if the initial bind fails, and `error!`-log at runtime if `serve` returns an error (with the option to escalate to process exit if the user wants strict semantics).

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs` (`:1629-1634`).
- Approach: At the metrics-server spawn site, propagate the bind result. If the spawn task's `JoinHandle` is held, drive it from `main` with `select!` so a server error becomes a `main` error. Simpler: do the bind synchronously in `main` before `tokio::spawn`-ing the serve loop; surface the bind error directly.
- Watch out for: do not change the metrics-server endpoint semantics (it already uses `InsecureGate::Refuse` for non-loopback per PRD); this is purely about error visibility.
- New files to create: none.

**Acceptance Criteria:**
- [ ] RED test (committed first): an integration test that pre-occupies the metrics-bind port via `std::net::TcpListener::bind`, then drives the `bin/rvc` entrypoint. Currently the bin starts successfully and silently has no metrics. After fix, the bin returns a non-zero exit code with a clear error log mentioning the port.
- [ ] GREEN: same test passes after the surface-the-error change.
- [ ] No regression on the happy path (free port → metrics server starts cleanly).
- [ ] Commit message references `Info-5c`.

**Testing Notes:**
- The pre-occupied port should be acquired in the test via `TcpListener::bind("127.0.0.1:0")` then read the assigned port back so the test does not depend on a hard-coded port number.

---

### Issue 6.22d: Info-5d — Env-mutex in `crypto::insecure` tests via `std::sync::Mutex<()>` (ADR-011)

- **Points:** 1
- **Type:** chore (test hygiene; flake-fix)
- **Priority:** P2
- **Blocked by:** —
- **Scope:** ½ day

**Description:**
`crates/crypto/src/insecure.rs` tests (`:249-330` per PRD) mutate process-global env vars (e.g., `RVC_ALLOW_INSECURE_*`) without serialization, so they race when `cargo test` runs them in parallel. Architecture ADR-011 explicitly mandates a process-global `std::sync::Mutex<()>` at module scope acquired by every env-mutating test; `serial_test` is **explicitly rejected** per architecture principle P6 (no new external dependencies).

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/insecure.rs` (test module) and optionally `crates/crypto/src/insecure/test_env.rs` for the helper.
- Approach: Define `static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());` at module scope in the test-helpers location. Every env-mutating test calls `let _guard = ENV_MUTEX.lock().expect("env mutex poisoned");` as its first line. The guard's lifetime covers the entire test body so env writes serialize.
- Do **NOT** use `serial_test` (rejected per ADR-011 / principle P6).
- Watch out for: poison recovery — `expect("env mutex poisoned")` is acceptable here because a poisoned mutex signals a prior test panic mid-env-mutation, which is itself a bug to surface, not silently ignore.
- New files to create: optionally `crates/crypto/src/insecure/test_env.rs` for the `ENV_MUTEX` static + a small helper function.

**Acceptance Criteria:**
- [ ] **RED test (committed first):** a flake-detection loop test that runs the existing env-mutating insecure tests N times (e.g., 50 iterations) under `cargo test -- --test-threads 8`; without the mutex, the loop observes a failure within N iterations (race-condition manifest). Specifically: spawn N threads that each `std::env::set_var` + `InsecureGate::from_env` + assertion; without serialization, at least one assertion fails.
- [ ] **GREEN:** after introducing `ENV_MUTEX` + acquiring it in every env-mutating test, the same loop test runs to completion with zero failures.
- [ ] `serial_test` is NOT added to `Cargo.toml` (architecture principle P6 / ADR-011).
- [ ] Commit message references `Info-5d` and cites ADR-011.
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` green.
- [ ] Tracker entry shows Info-5 has four individual rows closed (6.22a–6.22d) per PRD Assumption #16.

**Testing Notes:**
- The flake-detection loop test is a one-time RED commit; once Info-5d is green, future contributors who add an env-mutating test without acquiring `ENV_MUTEX` will see the flake re-emerge. Optionally keep the loop test in a `#[ignore]`-gated form for periodic re-validation.
