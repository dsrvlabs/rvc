# Phase 5: M3 Shared Pre-Work — `net-policy` Crate

## Phase Overview

- **Goal:** Land the `crates/net-policy` crate that the URL-1+URL-2 cluster (Phase 6 Task 6.2) and the remote-signer transport-hardening sequence (Phase 6 Task 6.3) consume. New crate, zero behavior change in production code: nothing imports `net-policy` until Phase 6 starts. Crate compiles, unit tests pass, `tests/architecture_no_cycles.rs` stays green with the new crate at Level 2.
- **Issue count:** 7 issues, 12 total points.
- **Estimated duration:** ~7 working days (single-stream).
- **Entry criteria:**
  - Phase 4 (M2 fixes — duty-correctness floor) merged FF-only to `develop`; CI four-gate suite green.
  - The release branch from Phase 4 may be cut in parallel with this phase starting (per project-plan DL-5: Phase 5 is on the pre-release critical path because it unblocks the four remaining P1 findings in Phase 6 Tasks 6.1–6.4).
  - `develop` builds clean: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green.
  - Standing CI gates from Phase 1 (`tests/architecture_no_cycles.rs`) and Phase 2 (`bin/rvc-signer/tests/signing_path_enumeration.rs`) green.
  - Workspace dependency conventions confirmed: new crate added to `[workspace.members]` and `[workspace.dependencies]` per the pattern established by existing internal crates.
- **Exit criteria:**
  - `crates/net-policy` compiles as a workspace member and is listed in root `Cargo.toml`'s `[workspace.dependencies]`.
  - Unit + integration tests for `DenyList` IPv4, `DenyList` IPv6, mixed-case scheme acceptance (L-1 substrate), DNS-rebinding `recheck`, and the reserved-ranges property test all green.
  - Zero consumers in production code (no `keymanager-api` or `crypto` `Cargo.toml` references `net-policy` yet — those land in Phase 6).
  - `tests/architecture_no_cycles.rs` updated to assert `net-policy` sits at Level 2 with zero outbound internal-crate edges at this phase exit (the architecture's documented `net-policy → eth-types::canonical` Level-2 edge is *not* established in Phase 5 — no Phase 5 issue consumes a canonical helper; the edge will be added by a future post-Phase-5 consumer), and is not depended upon by any Level 0/1 crate.
  - `prep/M3-shared` merged FF-only to `develop`; CI green.
  - Citation-correctness items from research R6 (RFC 6890 + IANA IPv4 Special-Purpose registry for IPv4 ranges; IANA IPv6 Multicast / RFC 4291 §2.7 for `ff00::/8`; IPv6 Special-Purpose registry for unicast reserved ranges) appear in module-level doc comments / README.
- **Recorded assumptions:**
  1. The four traits/modules from Phase 1 (`eth-types::canonical`, `eth-types::insecure`, `signer::SigningEnablement`, `slashing::SlashingDbReader`) are present on `develop`. In this phase `net-policy` does NOT consume `eth-types::canonical`: `validate_url` operates only on `&str` and `url::Url`, and the deny-list works on `std::net::{Ipv4Addr, Ipv6Addr, IpAddr}`. The architecture DAG's `net-policy → eth-types::canonical` edge (architecture §Level 2) is therefore *not* established in Phase 5; it lights up only when a future call site needs canonical-helper parsing of URL components. Issue 5.7's no-cycles assertion is written to that reality.
  2. `reqwest = "0.12"` with `rustls-tls` feature is already in `[workspace.dependencies]` (confirmed in root `Cargo.toml`); `url = "2"` likewise. No new external dependency is introduced — strict PRD §2 / architecture P6.
  3. `tokio` is the runtime; `PinnedResolver` integrates via `reqwest::dns::Resolve` (already-available trait surface in `reqwest 0.12`).
  4. Existing `crates/keymanager-api/src/url_validator.rs` (validate + DNS-rebinding) is the working specimen the new crate displaces in Phase 6. This phase ports the logic into `net-policy` (greenfield API surface) but does NOT delete the existing file — Phase 6 Task 6.2 deletes it.
  5. Issue 5.1 (skeleton + workspace wiring) must land first; subsequent issues build on it but can be sequenced freely.
  6. No production crate gains a `[dependencies]` entry on `net-policy` in this phase. The `tests/architecture_no_cycles.rs` assertion changes are pure DAG additions (Level 2 slot creation), not consumer wirings.
  7. Two integration tests already in `crates/keymanager-api/src/url_validator.rs` cover material substrate for L-1 / URL-1 / URL-2; this phase mirrors them in `crates/net-policy/tests/` with the corrected case-insensitive scheme check and the architecture's expanded deny-list (TEST_NET ranges, IPv4 multicast, IPv4-compatible `::a.b.c.d`).
  8. **Precondition — `tests/architecture_no_cycles.rs` location.** Phase 1 Task 1.6 lands `tests/architecture_no_cycles.rs` at the **repository root** (per project-plan §Prerequisites and §Phase 1 Task 1.6). Phase 5 issues 5.1 and 5.7 reference that root path directly; no "equivalent location" branch exists. If Phase 1 deviated and the test lives elsewhere, that is a Phase 1 regression and must be resolved before Phase 5 starts, not absorbed into a Phase 5 issue.
  9. The deny-list is a `const` table compiled into the binary. There is no operator-driven runtime mutation of the deny-list in this phase; "rebinding resistance" is delivered by re-resolution / re-validation of the destination at connect time (via `PinnedResolver::recheck` evaluating the pinned `SocketAddr`s against the same `const` table), not by reloading the table itself. Any future "operator-driven deny-list reload" capability is out of scope for Phase 5.

---

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 5.1 | Scaffold `crates/net-policy` workspace member + workspace deps | 1 | — | 0.5–1 day | `Cargo.toml`, `crates/net-policy/Cargo.toml`, `crates/net-policy/src/lib.rs`, `crates/net-policy/src/error.rs` |
| 5.2 | Implement `DenyList` IPv4 deny-list (RFC 6890 + IANA + TEST-NET + multicast) with unit tests | 2 | 5.1 | 1–1.5 days | `crates/net-policy/src/deny_list.rs`, `crates/net-policy/tests/deny_list_ipv4.rs` |
| 5.3 | Implement `DenyList` IPv6 deny-list (mapped/`::a.b.c.d` normalisation, ULA, link-local, multicast) with unit tests | 2 | 5.2 | 1–1.5 days | `crates/net-policy/src/deny_list.rs`, `crates/net-policy/tests/deny_list_ipv6.rs` |
| 5.4 | Implement `UrlPolicy` + `validate_url` (case-insensitive scheme; ValidatedUrl newtype) | 2 | 5.2, 5.3 | 1 day | `crates/net-policy/src/url_policy.rs`, `crates/net-policy/tests/mixed_case_scheme.rs` |
| 5.5 | Implement `validate_url_runtime` (DNS resolve + per-IP deny-list re-check) | 2 | 5.3, 5.4 | 1 day | `crates/net-policy/src/url_policy.rs`, `crates/net-policy/tests/url_runtime_dns.rs` |
| 5.6 | Implement `PinnedResolver` (`reqwest::dns::Resolve` impl + per-connect `recheck()`) | 2 | 5.5 | 1 day | `crates/net-policy/src/pinned_resolver.rs`, `crates/net-policy/tests/rebinding_recheck.rs` |
| 5.7 | Add reserved-ranges property test; update `tests/architecture_no_cycles.rs`; provenance README | 1 | 5.6 | 0.5–1 day | `crates/net-policy/tests/reserved_ranges_property.rs`, `crates/net-policy/README.md`, `tests/architecture_no_cycles.rs` |

**Phase totals:** 7 issues, 12 points.

## Phase Execution Plan

| Day | Issue |
|-----|-------|
| 1 | 5.1 Scaffold + workspace deps |
| 2 | 5.2 DenyList IPv4 |
| 3 | 5.2 cont. + start 5.3 |
| 4 | 5.3 DenyList IPv6 |
| 5 | 5.4 UrlPolicy + validate_url |
| 6 | 5.5 validate_url_runtime + 5.6 PinnedResolver start |
| 7 | 5.6 cont. + 5.7 property test, README, no-cycles assertion |

---

## Issues

### Issue 5.1: Scaffold `crates/net-policy` workspace member + workspace deps

- **Points:** 1
- **Type:** chore
- **Priority:** P0 (blocks every other issue in this phase)
- **Blocked by:** none
- **Blocks:** 5.2, 5.3, 5.4, 5.5, 5.6, 5.7
- **Scope:** 0.5–1 day

**Description:**

Create the `crates/net-policy` workspace member with `lib.rs`, `error.rs`, and the package name + version + edition + license aligned to the workspace conventions (`rvc-net-policy` per the pattern of `rvc-eth-types`, `rvc-signer`, etc.). Add to root `Cargo.toml`'s `[workspace.members]` and `[workspace.dependencies]` so other crates can declare it in Phase 6 with the workspace-inherited path.

`lib.rs` exports a stub public API (`pub use error::NetPolicyError;`); `error.rs` defines `NetPolicyError` as a `thiserror`-derived enum with variants `Denied { reason: String }`, `InvalidScheme(String)`, `DnsResolutionFailed(String)`, `EmptyResolution(String)`, `Parse(String)`, `Internal(String)`. No business logic yet.

The crate must compile clean (`cargo build -p rvc-net-policy`) and pass clippy with `-D warnings`. The existing `tests/architecture_no_cycles.rs` (root-level path landed by Phase 1 Task 1.6 per assumption #8) must remain green — at this stage the crate has no incoming edges and no outgoing edges (no `eth-types` dependency in Phase 5 per assumption #1), so it sits as an isolated Level 2 node.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/Cargo.toml`
  - `crates/net-policy/src/lib.rs`
  - `crates/net-policy/src/error.rs`
- Files to modify:
  - root `Cargo.toml`: append `"crates/net-policy"` to `[workspace.members]`; add `net-policy = { path = "crates/net-policy", package = "rvc-net-policy" }` to `[workspace.dependencies]` alphabetically.
- `crates/net-policy/Cargo.toml` should:
  - Use `package.name = "rvc-net-policy"`.
  - Inherit `version`, `edition`, `rust-version`, `license`, `repository` from `workspace = true`.
  - Declare dependencies from workspace: `thiserror`, `url`. (Do NOT add `reqwest`/`tokio`/`eth-types` yet; those land in subsequent issues that need them.)
- Approach: mirror `crates/timing/Cargo.toml` or `crates/eth-types/Cargo.toml` as a structural template.
- Key decisions: keep the crate strictly Level 2 in the architecture DAG. The architecture's documented `net-policy → eth-types::canonical` edge is *not* added in Phase 5: no issue 5.1–5.7 consumes a canonical helper. The edge lights up only when a future call site needs canonical-helper parsing of URL components — at which point that issue (post-Phase 5) adds the dependency. Phase 5 ships `net-policy` with zero outgoing internal-crate edges.
- Watch out for:
  - Forgetting to register the crate in the workspace `[workspace.members]` results in non-discovery by `cargo build` from root.
  - Package name `rvc-net-policy` must match the pattern of other crates (the path is `crates/net-policy` but the published name is `rvc-net-policy`).
- The crate name `net-policy` is the internal workspace-dependency alias; the published-package name `rvc-net-policy` matches the existing convention. Downstream consumers in Phase 6 declare `net-policy = { workspace = true }` in their `Cargo.toml`.

**Acceptance Criteria:**

- [ ] `cargo build -p rvc-net-policy` succeeds.
- [ ] `cargo clippy -p rvc-net-policy -- -D warnings` succeeds.
- [ ] `cargo fmt --check` succeeds.
- [ ] `crates/net-policy` is listed in root `Cargo.toml` `[workspace.members]`.
- [ ] Root `Cargo.toml` `[workspace.dependencies]` contains a `net-policy = { ... }` entry pointing at `crates/net-policy` with package `rvc-net-policy`.
- [ ] `cargo build` from the workspace root still succeeds with all crates.
- [ ] `tests/architecture_no_cycles.rs` (repository-root path landed by Phase 1 Task 1.6) remains green.
- [ ] `NetPolicyError` exported from `lib.rs` and derives `Debug`, `thiserror::Error`.

**Testing Notes:**

- No unit tests required at this stage beyond a trivial smoke test that constructs each `NetPolicyError` variant to confirm the enum compiles. The substantive tests land in subsequent issues alongside the code under test.

---

### Issue 5.2: Implement `DenyList` IPv4 deny-list (RFC 6890 + IANA + TEST-NET + multicast) with unit tests

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 5.1
- **Blocks:** 5.3, 5.4, 5.5
- **Scope:** 1–1.5 days

**Description:**

Implement `DenyList::contains_ipv4(Ipv4Addr) -> Option<&'static str>` (returns the human-readable name of the matching CIDR if denied, `None` otherwise) covering the full architecture-mandated IPv4 set. The architecture lists (PRD URL-1 acceptance + architecture module detail):

- `0.0.0.0/8` (the entire range, not just `0.0.0.0`).
- `127.0.0.0/8` (loopback).
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private).
- `100.64.0.0/10` (CGNAT, RFC 6598; substrate of existing `is_cgnat`).
- `169.254.0.0/16` (link-local).
- `192.0.2.0/24` (TEST-NET-1).
- `198.18.0.0/15` (benchmark).
- `198.51.100.0/24` (TEST-NET-2).
- `203.0.113.0/24` (TEST-NET-3).
- `240.0.0.0/4` (reserved future use).
- `224.0.0.0/4` (IPv4 multicast).
- Broadcast `255.255.255.255`.

The implementation should be data-driven (a `const` table of `(Ipv4Network, &'static str)` pairs evaluated by a single matcher) rather than a long `if`/`else` chain — keeps the table auditable against the citations and the property test in Issue 5.7 trivial.

Author unit tests `crates/net-policy/tests/deny_list_ipv4.rs` enumerating one positive (denied) and one negative (allowed) representative per range. The PRD URL-1 acceptance criterion explicitly calls out `https://0.0.0.1:5052` — that case must be a test fixture.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/src/deny_list.rs` (module; `pub use` from `lib.rs`).
  - `crates/net-policy/tests/deny_list_ipv4.rs` (integration test).
- Files to modify:
  - `crates/net-policy/src/lib.rs`: add `pub mod deny_list;`.
- Approach:
  - Use `std::net::Ipv4Addr` and bit-mask matching; no new crate (`ipnet` etc.) required. Each CIDR encoded as `(u32 network, u32 mask)`; match is `(ip.to_bits() & mask) == network`.
  - Public API: `pub fn deny_ipv4_reason(addr: Ipv4Addr) -> Option<&'static str>` returning a stable, citation-aligned label (e.g. `"0.0.0.0/8 (RFC 6890: 'This network')"`).
  - Existing logic in `crates/keymanager-api/src/url_validator.rs::validate_ip` is the working specimen — port the substrate but expand to cover the new ranges (`0.0.0.0/8`, TEST-NETs, `240.0.0.0/4`, multicast). The existing `is_cgnat` helper is folded in.
- Key decisions:
  - Return `Option<&'static str>` (not `bool`) so the reason is auditable in logs and tests; aligns with `NetPolicyError::Denied { reason }`.
  - Each range entry is a `const` so the table is reviewable in one file against the architecture's bullet list and the research R6 citations.
  - Do NOT call into `Ipv4Addr::is_loopback()` / `is_private()` / etc. — those are stdlib helpers that may shift definitions across Rust versions. Encode ranges explicitly for citation discipline.
- Watch out for:
  - `0.0.0.0/8` covers the entire 0/8 not just `0.0.0.0` — the PRD-cited test case `0.0.0.1` must be denied. Existing stdlib `is_unspecified()` only matches the exact `0.0.0.0`.
  - `240.0.0.0/4` shadows `255.255.255.255` (broadcast); the table can list both or rely on the `/4` mask alone — verify with the broadcast test case.
  - IPv4 multicast `224.0.0.0/4` is denied per architecture; not covered by existing `validate_ip`.
- The deny-list module exports nothing fork-aware; no `eth-types` dependency required at this stage.

**Acceptance Criteria:**

- [ ] `deny_ipv4_reason(Ipv4Addr::new(127, 0, 0, 1))` returns `Some(_)` with a reason containing "127.0.0.0/8" or "loopback".
- [ ] `deny_ipv4_reason(Ipv4Addr::new(0, 0, 0, 1))` returns `Some(_)` (covers PRD URL-1 case `https://0.0.0.1:5052`).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(10, 0, 0, 1))` returns `Some(_)` (RFC 1918).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(172, 16, 0, 1))` returns `Some(_)`.
- [ ] `deny_ipv4_reason(Ipv4Addr::new(192, 168, 1, 1))` returns `Some(_)`.
- [ ] `deny_ipv4_reason(Ipv4Addr::new(100, 64, 0, 1))` returns `Some(_)` (CGNAT).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(169, 254, 1, 1))` returns `Some(_)` (link-local).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(192, 0, 2, 1))` returns `Some(_)` (TEST-NET-1).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(198, 18, 0, 1))` returns `Some(_)` (benchmark).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(198, 51, 100, 1))` returns `Some(_)` (TEST-NET-2).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(203, 0, 113, 1))` returns `Some(_)` (TEST-NET-3).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(240, 0, 0, 1))` returns `Some(_)` (reserved).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(224, 0, 0, 1))` returns `Some(_)` (multicast).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(255, 255, 255, 255))` returns `Some(_)` (broadcast).
- [ ] `deny_ipv4_reason(Ipv4Addr::new(8, 8, 8, 8))` returns `None`.
- [ ] `deny_ipv4_reason(Ipv4Addr::new(93, 184, 216, 34))` returns `None` (example.com).
- [ ] `cargo test -p rvc-net-policy --test deny_list_ipv4` green.
- [ ] `cargo clippy -p rvc-net-policy -- -D warnings` green.

**Testing Notes:**

- One positive test per CIDR; one negative (allowed) test for a known public IP.
- The reason strings are stable test fixtures: if a citation gets corrected in Issue 5.7's README, the strings update too — keep them in one `const` table.

---

### Issue 5.3: Implement `DenyList` IPv6 deny-list (mapped/`::a.b.c.d` normalisation, ULA, link-local, multicast) with unit tests

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 5.2
- **Blocks:** 5.4 (introduces the shared `deny_ip_reason(IpAddr)` entry point `UrlPolicy::validate_url` dispatches through for IPv6 literals), 5.5
- **Scope:** 1–1.5 days

**Description:**

Implement `deny_ipv6_reason(Ipv6Addr) -> Option<&'static str>` covering the architecture-mandated IPv6 set:

- `::1/128` (loopback).
- `::/128` (unspecified).
- `fe80::/10` (link-local).
- `fc00::/7` (ULA, unique local addressing, replaces deprecated site-local).
- `ff00::/8` (multicast — research R6 cites IANA IPv6 Multicast Address Space / RFC 4291 §2.7).
- IPv4-mapped `::ffff:a.b.c.d` (delegate to `deny_ipv4_reason`).
- IPv4-compatible `::a.b.c.d` (deprecated form — same delegation, PRD URL-1 explicitly calls out "normalize IPv4-compatible `::a.b.c.d` and reject other reserved ranges").

The IPv4-compatible form is the PRD's specific new requirement vs. the existing `crates/keymanager-api/src/url_validator.rs` which only handles `to_ipv4_mapped`. Implement both: detect addresses where the first 96 bits are zero, extract the lower 32 bits as `Ipv4Addr`, and run them through `deny_ipv4_reason`.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/tests/deny_list_ipv6.rs`.
- Files to modify:
  - `crates/net-policy/src/deny_list.rs`: add `deny_ipv6_reason` next to the IPv4 path; share the `IpAddr` entry point `pub fn deny_ip_reason(IpAddr) -> Option<&'static str>` that dispatches based on the variant.
- Approach:
  - Use `Ipv6Addr::segments()` (`[u16; 8]`).
  - Loopback: full equality with `Ipv6Addr::LOCALHOST` or `segments == [0,0,0,0,0,0,0,1]`.
  - Unspecified: all zeros.
  - Link-local: `segments[0] & 0xffc0 == 0xfe80`.
  - ULA: `segments[0] & 0xfe00 == 0xfc00`.
  - Multicast: `segments[0] & 0xff00 == 0xff00`.
  - IPv4-mapped: `to_ipv4_mapped()` Some → delegate to `deny_ipv4_reason`.
  - IPv4-compatible: `segments[0..6] == [0; 6] && segments[6] != 0` (excluding the unspecified and loopback cases already caught above) → reconstruct an `Ipv4Addr` from the lower 32 bits and delegate to `deny_ipv4_reason`. Per the IPv4-mapped variant, the architecture wants this case also denied if the underlying IPv4 lands in the IPv4 deny-list.
- Key decisions:
  - The `deny_ip_reason(IpAddr)` entry point is the public boundary that `UrlPolicy::validate_url` (Issue 5.4) and `validate_url_runtime` (Issue 5.5) and `PinnedResolver::recheck` (Issue 5.6) all call. Keep the per-family helpers `pub(crate)` if you prefer; export `deny_ip_reason` as `pub`.
  - Re-cite `ff00::/8` against RFC 4291 §2.7 / IANA IPv6 Multicast (per research R6).
- Watch out for:
  - IPv4-compatible address `::1.2.3.4` is structurally identical to `Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0102, 0x0304)`; checking `segments[0..6] == [0; 6]` is necessary but insufficient — must also exclude `::` (unspecified, all-zero) and `::1` (loopback, lower 16 bits = 0x0001).
  - `Ipv6Addr::is_unicast_link_local_strict` exists in nightly but not stable; use bit-mask compare.

**Acceptance Criteria:**

- [ ] `deny_ip_reason(Ipv6Addr::LOCALHOST.into())` returns `Some(_)`.
- [ ] `deny_ip_reason(Ipv6Addr::UNSPECIFIED.into())` returns `Some(_)`.
- [ ] `deny_ip_reason("fe80::1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (link-local).
- [ ] `deny_ip_reason("fc00::1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (ULA).
- [ ] `deny_ip_reason("ff02::1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (multicast).
- [ ] `deny_ip_reason("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (mapped → loopback IPv4).
- [ ] `deny_ip_reason("::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (mapped → RFC 1918).
- [ ] `deny_ip_reason("::10.0.0.1".parse::<Ipv6Addr>().unwrap().into())` returns `Some(_)` (IPv4-compatible → RFC 1918).
- [ ] `deny_ip_reason("::8.8.8.8".parse::<Ipv6Addr>().unwrap().into())` returns `None` (IPv4-compatible → public IPv4 allowed; or, if the architecture requires blanket-denying the IPv4-compatible form, document the deviation in the reason string).
- [ ] `deny_ip_reason("2001:db8::1".parse::<Ipv6Addr>().unwrap().into())` returns `None` or `Some(_)` depending on whether `2001:db8::/32` (documentation prefix) is included — the architecture does not require it; the implementation may include it as a future-proofing extension with a clear citation.
- [ ] `deny_ip_reason("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().into())` returns `None` (public Cloudflare IPv6 DNS — allowed).
- [ ] `cargo test -p rvc-net-policy --test deny_list_ipv6` green.

**Testing Notes:**

- Watch for the `::a.b.c.d` form not matching `to_ipv4_mapped`; this is the specific PRD URL-1 expansion vs the existing implementation.
- The `2001:db8::/32` doc prefix is not in the architecture's required list; treat it as out of scope for this issue.

---

### Issue 5.4: Implement `UrlPolicy` + `validate_url` (case-insensitive scheme; `ValidatedUrl` newtype)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 5.2 (IPv4 deny-list), **5.3** (IPv6 deny-list and the shared `deny_ip_reason(IpAddr)` entry point introduced in 5.3 that `validate_url` dispatches through for both `Host::Ipv4` and `Host::Ipv6` literals)
- **Blocks:** 5.5
- **Scope:** 1 day

> **Why 5.3 is a hard dependency, not just 5.2:** the acceptance criterion `validate_url("https://[::1]:9000", ...) → Err(_)` matches an IPv6 literal host. `validate_url` cannot route an `Ipv6Addr` through `deny_ipv4_reason` alone; it requires the `deny_ip_reason(IpAddr) -> Option<&'static str>` entry point that Issue 5.3 introduces (per 5.3's Implementation Notes: "share the `IpAddr` entry point `pub fn deny_ip_reason(IpAddr)`"). Without 5.3 landed, the IPv6-literal AC cannot pass.

**Description:**

Implement the static URL validation API:

```rust
pub struct UrlPolicy { pub allow_http: bool, pub allow_loopback: bool }
pub struct ValidatedUrl(url::Url);  // newtype that proves validation occurred
pub fn validate_url(s: &str, policy: &UrlPolicy) -> Result<ValidatedUrl, NetPolicyError>;
```

The function:

1. Parses with `url::Url::parse`.
2. Compares the scheme **case-insensitively** against `"https"` / `"http"` via the normalised `Url::scheme()` value (which `url` already lowercases). This is the L-1 substrate (the existing `crates/crypto/src/remote_signer.rs::check_remote_signer_url` uses `str::starts_with("https://")` which is case-sensitive; this fixes that).
3. If scheme is `http`, refuses unless `policy.allow_http` is true.
4. If scheme is neither, returns `NetPolicyError::InvalidScheme`.
5. Extracts the host. For `Host::Ipv4` / `Host::Ipv6`, runs `deny_ip_reason` against the literal IP and refuses on `Some(_)` — unless `policy.allow_loopback` is true AND the only reason is loopback (use a reason discriminator or a separate `is_loopback_only` helper).
6. For `Host::Domain`, accepts without further check (the DNS resolution + re-check is `validate_url_runtime`'s job in Issue 5.5).
7. Returns `Ok(ValidatedUrl(url))` on success.

`ValidatedUrl` exposes `pub fn as_url(&self) -> &url::Url` and `pub fn into_inner(self) -> url::Url`; deliberately does NOT implement `From<&str>` so the only path to construction is `validate_url`.

The case-insensitive test (L-1 substrate) is the unique fixture for `crates/net-policy/tests/mixed_case_scheme.rs`: `Https://signer.example.com:9000` and `HTTPS://signer.example.com:9000` must validate.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/src/url_policy.rs`.
  - `crates/net-policy/tests/mixed_case_scheme.rs`.
- Files to modify:
  - `crates/net-policy/src/lib.rs`: `pub mod url_policy;`, `pub use url_policy::{UrlPolicy, ValidatedUrl, validate_url};`.
- Approach:
  - Use `url::Url::parse(s)`. `Url::scheme()` returns lowercased per the `url` crate's own normalisation, so comparing against `"https"` literal is correct after parse.
  - For loopback handling: simplest implementation is a `pub(crate) fn deny_ip_reason_filtered(IpAddr, allow_loopback: bool)` that masks the loopback reason when the flag is set.
  - `policy.allow_loopback` is for test affordances and ops cases where loopback signing is intentional (e.g. local signer running on the same host). Default `false`.
  - `policy.allow_http` for compatibility with `--allow-insecure-remote-signer`.
- Key decisions:
  - `ValidatedUrl` is a newtype — does NOT derive `From<url::Url>` or `From<&str>`. The only construction path is through `validate_url` (or `validate_url_runtime` in Issue 5.5). This is the L-1/URL-1 type-level guard: anything downstream that takes `ValidatedUrl` cannot be handed an unvalidated URL.
  - `eth-types::canonical` edge: not added in Phase 5 (per phase-level assumption #1). `validate_url` operates only on `&str` and `url::Url`; no canonical pubkey/GVR parsing is required at this seam. The architecture's documented `net-policy → eth-types::canonical` edge lights up only when a future post-Phase-5 call site introduces it.
- Watch out for:
  - `Url::scheme()` already lowercases; the existing `crypto::remote_signer::check_remote_signer_url::starts_with("https://")` does NOT — the L-1 fix is to use `parsed.scheme()` not the raw input string.
  - `Host::Domain` returning `&str` — must compare lowercased if any host-name allow-list is wanted. None required by this issue.
  - The `url` crate parses `https://` and `Https://` identically (scheme is normalised). Confirm by direct test rather than assumption.
- The error message strings on `NetPolicyError::Denied { reason }` are surfaced into operator logs and Phase 6 consumer tests; keep them stable and include the offending CIDR + RFC citation where applicable.

**Acceptance Criteria:**

- [ ] `validate_url("https://signer.example.com:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Ok(_)`.
- [ ] `validate_url("Https://signer.example.com:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Ok(_)` (L-1: case-insensitive scheme).
- [ ] `validate_url("HTTPS://signer.example.com:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Ok(_)`.
- [ ] `validate_url("http://signer.example.com:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Err(NetPolicyError::InvalidScheme(_))`.
- [ ] `validate_url("http://signer.example.com:9000", &UrlPolicy { allow_http: true, allow_loopback: false })` returns `Ok(_)`.
- [ ] `validate_url("file:///etc/passwd", &UrlPolicy { allow_http: true, allow_loopback: false })` returns `Err(NetPolicyError::InvalidScheme(_))`.
- [ ] `validate_url("https://127.0.0.1:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Err(NetPolicyError::Denied { .. })`.
- [ ] `validate_url("https://127.0.0.1:9000", &UrlPolicy { allow_http: false, allow_loopback: true })` returns `Ok(_)`.
- [ ] `validate_url("https://10.0.0.1:9000", &UrlPolicy { allow_http: false, allow_loopback: true })` returns `Err(NetPolicyError::Denied { .. })` (allow_loopback does NOT relax RFC 1918).
- [ ] `validate_url("https://[::1]:9000", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Err(_)`.
- [ ] `validate_url("https://0.0.0.1:5052", &UrlPolicy { allow_http: false, allow_loopback: false })` returns `Err(_)` (PRD URL-1 explicit case).
- [ ] `ValidatedUrl` does NOT implement `From<url::Url>`, `From<&str>`, or any other trivial conversion — checked by attempting an `assert_no_impl!` style negative test, or by code review checklist.
- [ ] `cargo test -p rvc-net-policy --test mixed_case_scheme` green.

**Testing Notes:**

- The L-1 mixed-case test is the smallest possible regression: two `assert!(...is_ok())` lines that prove the case-insensitive scheme behavior the existing remote_signer code violates.

---

### Issue 5.5: Implement `validate_url_runtime` (DNS resolve + per-IP deny-list re-check)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 5.3 (IPv6 deny-list), 5.4 (`validate_url` + `ValidatedUrl`)
- **Blocks:** 5.6
- **Scope:** 1 day

**Description:**

Implement the async runtime DNS-rebinding-resistant validator:

```rust
pub async fn validate_url_runtime(s: &str, policy: &UrlPolicy)
    -> Result<(ValidatedUrl, Vec<SocketAddr>), NetPolicyError>;
```

Behavior:

1. Calls `validate_url(s, policy)` — static deny-list runs first; if the host literal is already a denied IP, no DNS lookup is attempted.
2. If the validated host is a domain, calls `tokio::net::lookup_host("{host}:{port}")` with a default port of 443 when none is in the URL. Returns `NetPolicyError::EmptyResolution(host)` on empty result; `NetPolicyError::DnsResolutionFailed` on resolver error.
3. Runs `deny_ip_reason` on **every** resolved `IpAddr`. ANY denied IP refuses the whole resolution (DNS-rebinding requires that no resolution lands in a denied range — the existing `validate_resolved_ips` in keymanager-api enforces the same invariant).
4. Returns the `ValidatedUrl` plus the `Vec<SocketAddr>` of resolved addresses; `PinnedResolver::pin` in Issue 5.6 consumes this list.

For IP-literal hosts (no DNS lookup needed) the returned `Vec<SocketAddr>` is `vec![SocketAddr::new(ip_literal, port)]` so callers see a uniform shape.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/tests/url_runtime_dns.rs`.
- Files to modify:
  - `crates/net-policy/Cargo.toml`: add `tokio = { workspace = true }` (already in workspace) with no default features beyond what's needed for `tokio::net::lookup_host` — typically the `"net"` feature.
  - `crates/net-policy/src/url_policy.rs`: add `validate_url_runtime` below `validate_url`.
- Approach:
  - `tokio::net::lookup_host(target).await` returns `std::io::Result<impl Iterator<Item=SocketAddr>>`. Iterate, collect into `Vec<SocketAddr>`.
  - For every `SocketAddr` extract `.ip()` and call `deny_ip_reason`; on `Some(reason)`, return `NetPolicyError::Denied { reason: format!("DNS resolution for {host} → {ip}: {reason}") }`.
  - For IP-literal hosts (`Host::Ipv4` / `Host::Ipv6`), construct `SocketAddr` directly with the URL's port.
  - The architecture's "DNS resolve + deny-list check on every resolved IP" is the literal contract; preserve the existing keymanager-api test (`test_validate_remote_signer_url_runtime_*`) substrate as a positive regression in `tests/url_runtime_dns.rs`.
- Key decisions:
  - The function returns `Vec<SocketAddr>` (not `Vec<IpAddr>`) because `PinnedResolver::pin` in Issue 5.6 consumes `SocketAddr` for reqwest's `resolve_to_addrs`. Avoiding a second `IpAddr` → `SocketAddr` conversion at the call site.
  - Default port `443` when the URL omits one (matches the existing `validate_remote_signer_url_runtime` behavior in keymanager-api).
- Watch out for:
  - `lookup_host` may return zero entries on success — treat as a hard error (`EmptyResolution`), not silently accept.
  - `tokio` feature flags: the workspace already pulls `tokio = { features = ["full"] }`; `net-policy/Cargo.toml` should declare `tokio = { workspace = true }` and rely on workspace-default features for simplicity, OR declare just `features = ["net", "rt"]` to keep the dependency surface tight. Pick the tighter option only if it doesn't break the workspace inheritance pattern.
  - For deterministic unit tests, factor the DNS resolver behind a trait or accept a `Vec<IpAddr>` override path in tests. Simplest pattern: a `pub(crate) async fn validate_url_runtime_with_resolver<R: Fn(&str) -> Pin<Box<dyn Future<...>>>>(...)` or simply test against `localhost`/IP literals.
- Tests use real DNS sparingly; rely on IP-literal cases and a single positive `localhost` resolution (which deny-list rejects, useful for the rebinding-protection assertion).

**Acceptance Criteria:**

- [ ] `validate_url_runtime("https://127.0.0.1:9000", &UrlPolicy { allow_http: false, allow_loopback: false }).await` returns `Err(NetPolicyError::Denied { .. })`.
- [ ] `validate_url_runtime("https://localhost:9000", &UrlPolicy { allow_http: false, allow_loopback: false }).await` returns `Err(_)` because `localhost` resolves to `127.0.0.1` / `::1`.
- [ ] `validate_url_runtime("https://9.9.9.9:443", &UrlPolicy { allow_http: false, allow_loopback: false }).await` returns `Ok((_, addrs))` with `addrs == [SocketAddr::new(Ipv4Addr::new(9,9,9,9), 443).into()]`.
- [ ] `validate_url_runtime("https://0.0.0.1:5052", &UrlPolicy { allow_http: false, allow_loopback: false }).await` returns `Err(NetPolicyError::Denied { .. })` (PRD URL-1 explicit case, runtime path).
- [ ] `validate_url_runtime("https://[::ffff:127.0.0.1]:9000", &UrlPolicy { allow_http: false, allow_loopback: false }).await` returns `Err(_)` (mapped IPv4 → loopback).
- [ ] If the input URL has no port and scheme is https, `Vec<SocketAddr>` uses port 443.
- [ ] `cargo test -p rvc-net-policy --test url_runtime_dns` green.

**Testing Notes:**

- Test against `localhost` for a deterministic deny path; against `9.9.9.9` (Quad9 DNS) or `1.1.1.1` for a deterministic allow path using IP literals (no DNS round-trip).
- Avoid tests that depend on live external DNS resolution — they make CI flaky. Use the IP-literal path for positive cases.

---

### Issue 5.6: Implement `PinnedResolver` (`reqwest::dns::Resolve` impl + per-connect `recheck()`)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 5.5 (`validate_url_runtime` returns the `Vec<SocketAddr>` that `PinnedResolver::pin` consumes)
- **Blocks:** 5.7
- **Scope:** 1 day

**Description:**

Implement the DNS-rebinding-resistant resolver that downstream consumers (Phase 6 Task 6.2 `crypto::remote_signer`) wire into `reqwest::Client::builder().dns_resolver(Arc::new(...))`:

```rust
pub struct PinnedResolver { /* stores ValidatedUrl + Vec<SocketAddr> */ }
impl PinnedResolver {
    pub fn pin(validated: ValidatedUrl, addrs: Vec<SocketAddr>) -> Self;
    pub fn recheck(&self) -> Result<(), NetPolicyError>;
}
impl reqwest::dns::Resolve for PinnedResolver { /* returns the pinned addrs */ }
```

Behavior:

- `pin` records the validated URL and the pinned `SocketAddr` set captured at validation time. Subsequent reqwest connections for that host MUST use only the pinned set.
- `reqwest::dns::Resolve::resolve` returns an `Addrs` iterator yielding the pinned `SocketAddr`s for the host in `ValidatedUrl`. For other hosts (if any reach this resolver — they should not, but defense-in-depth), returns an error or empty result.
- `recheck()` runs `deny_ip_reason` against the pinned IPs again at call time. The architecture's contract is "called inside `remote_signer.rs` before every sign." Its purpose is a final guard against an already-pinned set: it re-evaluates the pinned `SocketAddr`s against the (Phase 5: `const`) deny-list. The deny-list is **not** runtime-mutable in this phase (phase assumption #9), so the value `recheck()` adds is (a) idempotent re-assertion that the pinned set is still admissible against the same `const` table (catches accidental pin-after-validation-was-bypassed), and (b) the call-site shape Phase 6 Task 6.2 / 6.3 consumes when wiring rebinding-resistant re-validation (Phase 6 re-resolves DNS at connect time and re-pins; `recheck()` is the type-level handle for asserting the re-pinned set remains admissible). Rebinding resistance is delivered by re-resolution / re-validation at connect time, NOT by reloading the deny-list.

The `recheck()` shape is what Phase 6 Task 6.2 (URL-2) and Task 6.3 (GRPC-1/2/3+L-1) consume.

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/src/pinned_resolver.rs`.
  - `crates/net-policy/tests/rebinding_recheck.rs`.
- Files to modify:
  - `crates/net-policy/Cargo.toml`: add `reqwest = { workspace = true }` (already in workspace; `default-features = false` + `features = ["rustls-tls"]` is the workspace default per root `Cargo.toml`).
  - `crates/net-policy/src/lib.rs`: `pub mod pinned_resolver;`, `pub use pinned_resolver::PinnedResolver;`.
- Approach:
  - `reqwest::dns::Resolve` is a trait with one async method `resolve(&self, name: Name) -> Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>`. Implement it by ignoring the requested `Name` and returning an iterator over the pinned `SocketAddr`s (boxed). For safety, log a warning (via `tracing`) if `name.as_str()` doesn't match the pinned host; do not return foreign hosts' addresses.
  - The pinned set is `Vec<SocketAddr>`; the trait wants `Addrs = Box<dyn Iterator<Item = SocketAddr> + Send>`. Wrap with `Box::new(addrs.into_iter())`.
  - `recheck` walks the pinned `SocketAddr`s; for each, calls `deny_ip_reason(addr.ip())`; on any `Some(_)`, returns `NetPolicyError::Denied { reason }`.
- Key decisions:
  - The resolver does NOT re-do DNS resolution at connect time. The pinning is precisely the point: once `validate_url_runtime` captured a clean set, that set is the only set reqwest sees.
  - `tracing` is a workspace dependency already; the warn-on-foreign-host log uses `tracing::warn!`.
  - Provide a `Clone` impl on `PinnedResolver` (the resolver is wrapped in `Arc` by reqwest, but tests want easy clone for setup).
- Watch out for:
  - `reqwest::dns::Resolve` signature varies across reqwest versions; the workspace pins `0.12`. Confirm the signature against the docs; current `0.12` shape is `fn resolve(&self, name: Name) -> Resolving` where `Resolving = Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>`.
  - `Name` is `reqwest::dns::Name`, exposing `as_str()`.
  - The `tracing` warn must not log the full IP set at production levels — keep to `debug!` or a redacted form, since the IP set is operator-sensitive in some deployments.
- Phase 6 Task 6.2 (URL-2) wires this in `crypto::remote_signer` like:
  ```rust
  let (validated, addrs) = net_policy::validate_url_runtime(url, &policy).await?;
  let resolver = Arc::new(net_policy::PinnedResolver::pin(validated, addrs));
  let client = reqwest::Client::builder().dns_resolver(resolver.clone()).build()?;
  // per-sign: resolver.recheck()?;
  ```

**Acceptance Criteria:**

- [ ] `PinnedResolver` implements `reqwest::dns::Resolve` and `Clone`.
- [ ] `PinnedResolver::pin(validated, vec![SocketAddr::new(Ipv4Addr::new(9,9,9,9), 443).into()]).recheck()` returns `Ok(())`.
- [ ] `PinnedResolver::pin(validated, vec![SocketAddr::new(Ipv4Addr::new(127,0,0,1), 443).into()]).recheck()` returns `Err(NetPolicyError::Denied { .. })`.
- [ ] Calling `.resolve(name)` for the host stored in `ValidatedUrl` returns an iterator yielding the pinned `SocketAddr`s.
- [ ] Calling `.resolve(name)` for a different host logs a warning and returns an empty iterator (or an error) — confirms rebinding-evasion impossible.
- [ ] Integration test simulates a "rebound" scenario: construct a `PinnedResolver` with a clean IP set (e.g. `9.9.9.9`), confirm `recheck()` returns `Ok(())`; then construct a **separate** `PinnedResolver` with a denied IP in the pinned set (modelling the result of a fresh re-resolution at connect time landing on a now-denied IP — the rebinding case) and assert `recheck()` returns `Err(NetPolicyError::Denied { .. })`. The test does NOT mutate the deny-list (it is `const` per phase assumption #9) and does NOT mutate a constructed resolver's pinned set in place (owned by the resolver); the "rebound" is modelled as two distinct `pin` invocations with two distinct outcomes.
- [ ] `cargo test -p rvc-net-policy --test rebinding_recheck` green.
- [ ] `cargo clippy -p rvc-net-policy -- -D warnings` green.

**Testing Notes:**

- The resolver test does NOT spin up a real `reqwest::Client`; the trait method can be invoked directly with a `reqwest::dns::Name` constructed via `Name::from_str(...)?` (check the `reqwest 0.12` public API; if `Name` is not constructable in tests, use a wrapper trait that the production code routes through and assert against that).
- The architecture's "called inside `remote_signer.rs` before every sign" guidance is honored by exposing `recheck()` — Phase 6 Task 6.2 owns the actual call-site wiring.

---

### Issue 5.7: Reserved-ranges property test; update `tests/architecture_no_cycles.rs`; provenance README

- **Points:** 1
- **Type:** chore + test
- **Priority:** P1 (Phase exit gate)
- **Blocked by:** 5.6
- **Blocks:** Phase exit
- **Scope:** 0.5–1 day

**Description:**

Three small wrap-up items that make the phase shippable:

1. **Property test** `crates/net-policy/tests/reserved_ranges_property.rs`: iterate every CIDR in the deny-list table and assert (a) the network address itself is denied, (b) the broadcast address of the range is denied, (c) one IP just outside the range is allowed unless it lands in another denied range. Catches off-by-one mask bugs that the per-range positive tests might miss.
2. **`crates/net-policy/README.md`**: provenance + citation discipline per research R6:
   - RFC 6890 + IANA IPv4 Special-Purpose registry for IPv4 ranges (NOT obsolete RFC 5735).
   - IANA IPv6 Multicast Address Space / RFC 4291 §2.7 for `ff00::/8`.
   - IANA IPv6 Special-Purpose registry for the unicast reserved ranges.
   - RFC 6598 for `100.64.0.0/10` CGNAT.
   - PRD URL-1 acceptance criterion as the project-level justification.
   - "Zero new external dependencies" call-out per architecture P6.
3. **`tests/architecture_no_cycles.rs`** (repository-root path landed by Phase 1 Task 1.6, per phase assumption #8): add the assertion that `net-policy` sits at Level 2 with the following dependency-edge shape:
   - **Outbound internal-crate edges (Phase 5): none.** Phase 5 does *not* introduce a `net-policy → eth-types::canonical` edge (per phase assumption #1) — no issue 5.1–5.7 imports a canonical helper. The architecture's documented `net-policy → eth-types` Level-2 edge lights up only when a future post-Phase-5 call site needs it. The no-cycles assertion at Phase 5 exit therefore states: *"`net-policy` has no outbound edge to any internal workspace crate."*
   - **Outbound external-crate edges (acknowledged, allowed):** `thiserror` (5.1), `url` (5.1), `tokio` (5.5, `features = ["net", "rt"]` or workspace-default), `reqwest` (5.6, workspace `default-features = false`, `features = ["rustls-tls"]`), `tracing` (5.6). These are workspace dependencies and are not Level-graded by the architecture DAG; they are listed here so the "no outbound edge to a Level-3+ workspace crate" wording in the assertion is unambiguous about what *is* allowed.
   - **Inbound edges (Phase 5): none from production.** At Phase 5 exit no production crate consumes `net-policy`; the assertion is `assert!(graph.production_dependents("net-policy").is_empty())`. Dev-only dependents (test fixtures, doc examples) are tolerated.
   - **Forbidden edges (asserted absent):** any inbound from `eth-types`, `metrics`, `timing`, `telemetry` (Levels 0–1); any outbound from `net-policy` to a Level-3+ workspace crate (`crypto`, `secret-provider`, `slashing`, `signer`, `doppelganger`, `keymanager-api`, `grpc-signer`, `rvc`, `block-service`, `builder`, `bn-manager`, `propagator`, `sync-service`, `duty-tracker`, `validator-store`, `beacon`).

**Implementation Notes:**

- New files to create:
  - `crates/net-policy/tests/reserved_ranges_property.rs`.
  - `crates/net-policy/README.md`.
- Files to modify:
  - `tests/architecture_no_cycles.rs` (repository-root path landed by Phase 1 Task 1.6, per phase assumption #8 — no fallback location).
- Approach:
  - Property test:
    - Loop the `const` `(Ipv4Network, &'static str)` table from Issue 5.2 (expose `pub(crate) const DENY_TABLE_V4: &[(u32, u32, &'static str)]` or similar). For each tuple, compute the network address (`network`), the broadcast (`network | !mask`), and the next address outside (`broadcast + 1`).
    - Assert the network and broadcast are denied; the "next outside" is denied iff some other rule covers it (cheap check: re-run `deny_ipv4_reason` on it; expect `Some` or `None` based on the union of the table). The "and is allowed unless covered by another range" assertion catches `0.0.0.0/8` vs `127.0.0.0/8` adjacency-style off-by-one.
    - For IPv6, table the masked-prefix ranges (`fe80::/10`, `fc00::/7`, `ff00::/8`) and do the analogous check on representative addresses.
  - README:
    - One short paragraph per finding (URL-1, URL-2, L-1) explaining what this crate does for that finding.
    - One paragraph "Citations" listing each RFC/IANA registry with a URL.
    - One paragraph "Architecture" linking to `plan/remediation/architecture.md` section "Module: net-policy".
    - One paragraph "Consumers (Phase 6+)" listing `keymanager-api`, `crypto::remote_signer`, `grpc-signer` (potential).
  - `tests/architecture_no_cycles.rs` change: a single new assertion block. If the test infrastructure already lists "forbidden edges", append `("eth-types", "net-policy")`, `("metrics", "net-policy")`, `("timing", "net-policy")`, and `("telemetry", "net-policy")` as forbidden inbound edges. Assert that `net-policy` has **zero** outbound internal-crate edges at Phase 5 exit (NOT "`net-policy → eth-types` is the only outgoing edge" — that earlier wording was wrong; Phase 5 does not introduce the eth-types edge per phase assumption #1). External-crate edges (`thiserror`, `url`, `tokio`, `reqwest`, `tracing`) are not Level-graded and are explicitly excluded from the assertion's domain.
- Key decisions:
  - The property test only iterates the `const` tables — the deny-list is a closed set, so the property reduces to "every table entry is correctly translated into deny behavior", which is a strong but tractable assertion.
  - The README is operator-facing AND auditor-facing. Keep citations exact; research R6 is the source of truth for what to cite.

**Acceptance Criteria:**

- [ ] `crates/net-policy/tests/reserved_ranges_property.rs` exists and asserts the network address + broadcast address of every IPv4 CIDR entry is denied.
- [ ] The property test iterates every entry in the `const` IPv4 deny table (no entry skipped — would be a regression smell).
- [ ] `crates/net-policy/README.md` exists with sections: Purpose, Findings closed (URL-1, URL-2, L-1), Citations (RFC 6890, IANA IPv4 Special-Purpose, IANA IPv6 Special-Purpose, IANA IPv6 Multicast / RFC 4291 §2.7, RFC 6598), Architecture (link), Consumers.
- [ ] `tests/architecture_no_cycles.rs` (repository-root path) asserts `net-policy` sits at Level 2 with the following edge shape at Phase 5 exit:
  - **No outbound internal-crate edges** (Phase 5 does NOT introduce `net-policy → eth-types::canonical`; that edge is documented in the architecture for a future post-Phase-5 consumer).
  - No production-crate inbound edges (dev-only dependents are permitted).
  - No inbound from `eth-types`, `metrics`, `timing`, `telemetry`.
  - No outbound to any Level-3+ workspace crate.
  - External-crate edges to `thiserror`, `url`, `tokio`, `reqwest`, `tracing` are out of scope for the Level-grade assertion and are explicitly allow-listed in the test (or implicitly excluded by the `cargo metadata` filter to internal workspace members only).
- [ ] All four-gate CI checks (`cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`) green from workspace root.
- [ ] Existing `bin/rvc-signer/tests/signing_path_enumeration.rs` standing gate remains green.

**Testing Notes:**

- The property test is the "would a future re-citation drift catch a real bug" backstop; combined with the README's stable citation list, it provides the audit trail R6 calls for.
- The `tests/architecture_no_cycles.rs` path is fixed at the repository root by Phase 1 Task 1.6 (phase assumption #8). If Phase 1 deviated, that is a Phase 1 regression to resolve before Phase 5 starts — not a Phase 5 contingency.

---

## Phase Exit Summary

After Issue 5.7 merges:

- `crates/net-policy` is a Level 2 workspace crate with no production consumers (yet). All seven issues' acceptance criteria green.
- `prep/M3-shared` merged FF-only to `develop`; CI four-gate suite + standing `architecture_no_cycles` + `signing_path_enumeration` green.
- Phase 6 Tasks 6.1 (KM-3), 6.2 (URL-1+URL-2 cluster), 6.3 (GRPC-1/2/3+L-1), 6.4 (VS-1) are unblocked. The four remaining release-blocker P1 findings (URL-1, URL-2, KM-3, VS-1) can begin immediately.
- Standing gates: `tests/architecture_no_cycles.rs` now asserts the `net-policy` Level 2 slot; future PRs adding an unintended inbound edge fail CI.
- Tracker file updated with each issue's commit hash + test file reference.
