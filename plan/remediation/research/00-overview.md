# Remediation Research — Consolidated Overview

**Lead researcher consolidation.** Date: 2026-06-13.
**Inputs:** `plan/remediation/prd.md` (46-finding remediation PRD) + four per-angle
investigations, each independently fact-checked against primary sources.
**Net verdict:** the PRD's findings and fixes are substantively correct. Across ~92
verified claims, **zero** were materially refuted in a way that invalidates a finding; a
handful of *citations* and *wording* need correcting, and one fix should be re-anchored to
a different spec lever. **No P0/P1 finding is dropped.**

> Two of the four angles reported **prompt-injection attempts** embedded in fetched web
> content ("# MCP Server Instructions" blocks trying to redirect tooling toward alphaXiv).
> Both were ignored and reported per protocol; neither affected any result. (This overview's
> own pipeline saw a third such injection in tool output — also ignored.)

---

## 1. Recommendations (lead with these)

### R1 — Ship the P0 fixes as written; they are all real. *(highest confidence)*
Every P0 finding (SS-1, E-1, E-2, B-1/T-1, KG-1, SS-2/SS-3, DVT-1, D-1, D-3, KM-1) is
verified at the cited source lines on `develop` and grounded in primary spec/reference
sources. Proceed with the milestone M1/M2 plan unchanged in substance.

### R2 — Before re-classifying B-1/T-1 / L-9 as "still open," run `cargo test -- --ignored`. *(blocking pre-work, cheap)*
The fix infrastructure for the SSZ block-publish bug appears **partially landed**:
`ssz_deser.rs:190` is now a docstring for a `resolve_block_region_end` function that
already returns the correct "kzg_proofs offset for BlockContents, bytes.len() for raw
BeaconBlock" and warns about the C-1/ISSUE-1.1 bug. Either one format path's call site
still uses `bytes.len()`, or the L-9 ignored tests were simply never re-enabled. Determine
the actual current state before writing the RED test, or you may write a RED test that is
already green. — *Angle 01.*

### R3 — KG-1's fix must delete/invert a test that pins the bug. *(scope correction)*
`bls_to_execution.rs:144` `test_bls_to_execution_uses_capella_fork_version` actively asserts
the *wrong* behavior (verifies the signature FAILS under `genesis_fork_version`). The test is
part of the defect. PRD acceptance criterion KG-1(b) already requires flipping both tests —
treat that as mandatory, not optional. — *Angle 01.*

### R4 — Re-anchor KM-1's "MUST" away from the keymanager-APIs flows README. *(citation/framing fix; fix still stands)*
The flows README does **not** mandate atomic abort-on-export-error; its literal guidance is
"mark status=error, continue with remaining keys." The hard rules that *do* exist are: the
keymanager must NEVER delete a key's slashing-protection data, and `local_keystores.yaml`
requires `status=deleted` items to carry `slashing_protection`. The PRD's fail-closed remedy
(abort the whole DELETE, delete nothing — assumption #9) is still the safest reading; just
frame it as "**fail-closed, consistent with the spirit of the DELETE semantics**," cited to
`local_keystores.yaml` + EIP-3076, **not** as a literal MUST from the flows README. — *Angle 02.*

### R5 — State the SS-2/SS-3 chain-of-custody precondition in the fix. *(correctness guardrail)*
Removing slashing-DB consultation from `sign_aggregate_and_proof` is correct (aggregate-and-proof
is out of EIP-3076 scope), **but** only safe because the inner `Attestation` was already signed
via `sign_attestation` through the slashing-DB path. Restate this precondition in the fix notes;
it is implicit in EIP-3076's two-class scoping and easy to lose. — *Angle 02.*

### R6 — Fix the SSRF deny-list *citations* (the deny-list itself is correct). *(citation fixes)*
- `ff00::/8` IPv6 multicast → cite **IANA IPv6 Multicast Address Space / RFC 4291 §2.7**, NOT the
  IPv6 Special-Purpose registry.
- Replace **RFC 5735 → RFC 6890 + IANA IPv4 Special-Purpose registry** for any normative reference.
- The "shipped fixes across 5 projects" framing is single-sourced; only the **Twenty** advisory
  (GHSA-vrcj-hv2q-c58m) is verified. Cite each GHSA/CVE individually or drop the framing. The URL-1
  deny-list stands on first principles regardless. — *Angle 04.*

### R7 — Fix two recurring upstream-citation errors wherever they appear. *(consistency)*
- **EIP-7657 is Stagnant, not a "live draft."** Flagged by both Angle 02 and Angle 03. The D-3
  future-proofing rationale still holds; just don't cite it as actively progressing.
- **Beacon-API liveness epoch support is SHOULD, not MUST** (per master `liveness.yaml`). Downgrade
  any "MUST support current+previous epoch / guaranteed 400" language to "SHOULD support
  current+previous; older optional; unsupported/invalid epoch typically 400." — *Angle 03.*

### R8 — Implement doppelganger and BN-trust fixes from the live reference sources, not summaries.
For D-1/D-3 use the live **Lighthouse v5.3.0 `doppelganger_service.rs`** state machine (epoch
satisfaction at the last slot of `e+1`, CRITICAL-on-missing, pre-genesis bypass). For BN-1/BN-2
the fail-closed pattern (RPC error → Offline) is confirmed in Lighthouse `check_synced.rs`. — *Angles 03, 04.*

---

## 2. Reconciliation across angles

| Topic | Angle(s) | Resolution |
|---|---|---|
| **EIP-7657 status** | 02 + 03 both flagged | Single source of truth: **Stagnant**. Use everywhere; never "live/draft." |
| **Sync-committee signatures not slashable** | 02 (Lighthouse book, EIP-7657) + 03 (Teku gates them anyway) | Both consistent: sync-committee messages are NOT slashable on mainnet today, yet clients still *gate* them under doppelganger (Teku gates all three message classes). Supports D-3 broadening the gate beyond attestation. |
| **Slashing namespacing (CN vs pubkey)** | 02 (DVT-1, CN-1) | Single root cause (`client_cn`/peer-CN in the WHERE clause). PRD already clusters DVT-1+CN-1; verification confirms both line sets match `develop`. The "per-CN audit column" remediation is a design choice, not a sourced requirement. |
| **Fail-closed discipline** | 02 (KM-1, GVR-1), 03 (D-2 missing-liveness), 04 (BN sync, EXIT-1 GVR) | Uniformly supported. PRD §6.3 fail-closed discipline is the correct cross-cutting rule; every angle independently lands on "on error, refuse." |
| **GVR normalization** | 02 (GVR-1 hex case) + 04 (EXIT-1 chain-binding) | EIP-3076 doesn't pin hex case; normalize to lowercase via a shared canonicalizer (PRD GVR-1). EXIT-1's BN-cross-check of GVR is the runtime complement. |

**No direct contradictions between angles were found.** The only cross-angle friction was two
shared upstream facts (EIP-7657 status; the not-slashable-but-gated nuance), and both reconcile cleanly.

---

## 3. Claims to DROP or CAVEAT

| Claim (as originally stated) | Disposition | Replace with |
|---|---|---|
| keymanager-APIs flows README mandates "atomic" abort-on-export-error (KM-1) | **DROP the "literal MUST from flows README" framing** | `local_keystores.yaml` semantics + EIP-3076; fix is "fail-closed, consistent with DELETE semantics" |
| `ff00::/8` is in the IANA IPv6 Special-Purpose registry | **DROP — wrong registry** | IANA IPv6 Multicast Address Space / RFC 4291 §2.7 |
| beacon-APIs `validator-flow.md` specifies "SSE + dependent-root cross-check" | **DROP — source mismatch** | `events.yaml` + `getProposerDuties`/`getAttesterDuties` descriptions |
| Web3Signer `configure-tls` page documents `--http-host-allowlist` / mTLS | **DROP — over-attributed** | `docs.web3signer.consensys.io/reference/cli/options` |
| RFC 5735 as the normative IPv4 reserved-range source | **CAVEAT — obsoleted** | RFC 6890 + IANA IPv4 Special-Purpose registry |
| EIP-7657 is a "live draft proposal" | **CAVEAT — Stagnant** | "Stagnant; cited only for future-proofing rationale" |
| Beacon-API liveness "MUST support current+previous epoch," guaranteed 400 | **CAVEAT — downgrade to SHOULD** | "SHOULD support current+previous; older optional; unsupported/invalid → typically 400" |
| IPv4-mapped-IPv6 SSRF "shipped fixes" across Directus/Sync-In/OpenClaw/Craft CMS | **CAVEAT — single-source** | verify each GHSA/CVE individually; only Twenty (GHSA-vrcj-hv2q-c58m) confirmed |
| Cubist verbatim threat-model quote | **CAVEAT — minor wording** | substance verified; exact wording differs slightly |
| `execution_optimistic` "MUST set True" as a normative type-def rule | **CAVEAT — prose, not OpenAPI MUST** | recommended-behavior prose; substance holds |
| keymanager token literal "hex-encoded, ≥256 bits" in `bearerFormat` | **CAVEAT — stitched** | `bearerFormat` reads "URL safe, opaque token"; hex/256-bit from separate config guidance |
| IANA "continues listing `::/96` as Reserved" | **CAVEAT — over-stated** | deprecated by RFC 4291, not an active IANA reservation; fine for deny-list |

**MEDIUM-confidence (single-source) facts to spot-check if they become load-bearing:**
consensus-spec-tests archival date (2025-10-22) and directory layout; `MAX_COMMITTEES_PER_SLOT=64`;
`SYNC_COMMITTEE_SUBNET_COUNT=4`; Lodestar PR #6012 merge status of the restart-aware variant.

---

## 4. Consolidated assumptions (surfaced for the review gate)

Carried from the PRD §8 and refined by verification:

1. **Severity = priority** (PRD #1) — unchallenged by any angle. P0 = 11 release-blockers.
2. **Spec vectors from `consensus-spec-tests`** (PRD #2) — Angle 01 confirms layout/tags but the
   archival date and exact dir layout are single-source; treat fixture sourcing as the first work
   item per SSZ finding (PRD §7.2) and verify the tag against the active fork.
3. **One finding = one branch, FF-only merge** (PRD #3) — matches the user's persisted preference.
4. **KM-1 fixed by aborting the whole DELETE** (PRD #9) — **REFRAME** per R4: this is a fail-closed
   *design choice* consistent with `local_keystores.yaml` + EIP-3076, not a literal flows-README MUST.
5. **DVT-1/CN-1 keying change is forward-only with auto-migration** (PRD #5) — depends on Q3 (are
   there production on-disk slashing DBs?). No angle resolved Q3; it remains open.
6. **D-3 gate centralized in `crates/signer`** (PRD #6) — supported by Angle 03 (Lighthouse
   centralizes in `validator_store`/`doppelganger_service`) and the not-slashable-but-gated nuance.
7. **`is_attesting_enabled` → `is_signing_enabled`, default `false` for unknown pubkeys** (PRD #7) —
   fail-closed, consistent with Angle 03's D-2 finding and §6.3.
8. **Doppelganger forward-window length unchanged (~2 epochs)** (PRD #8) — Angle 03 confirms
   Lighthouse's "2-3 epochs (~12-20 min)"; the rs-vc value is the existing config.
9. **B-1/T-1 fix infrastructure may be partially landed** — **NEW assumption to validate** (R2):
   resolve actual state with `cargo test -- --ignored` before treating it as fully open.

---

## 5. Confidence summary

- **HIGH (multi-source / Read-verified):** all SSZ/tree-hash/domain rules and container shapes
  (Angle 01); all seven slashing-boundary local findings + EIP-3076 scope (Angle 02); Lighthouse
  doppelganger reference + all rs-vc doppelganger/gate line claims (Angle 03); fail-closed sync,
  optimistic refusal, IP-pinning, `catch_unwind`, EIP-7044 chain-binding (Angle 04).
- **MEDIUM:** a few un-fetched constant pages and the consensus-spec-tests metadata (Angle 01);
  exact attribution of `execution_optimistic` and keymanager-token prose (Angle 04).
- **LOW / single-source — verify before relying:** the four non-Twenty SSRF advisories (Angle 04);
  Lodestar PR #6012 merge status (Angle 03); the exact Cubist quotation (Angle 02).
- **Overstated → corrected:** keymanager atomicity MUST (Angle 02); IPv6 multicast registry, reorg/SSE
  source, Web3Signer mTLS page (Angle 04); EIP-7657 status and liveness MUST→SHOULD (Angles 02/03).

Net: **~92 claims verified, 1 materially overstated (re-framed, not a finding-invalidator), 3
source-mismatches (re-cite), several wording/citation flags. No P0 or P1 finding is dropped.**

---

## 6. Open questions still unresolved by research

- **Q3 (PRD §10):** Are there production on-disk slashing DBs? Gates the DVT-1/CN-1 migration design.
  No angle resolved this — operator input needed.
- **R2 follow-up:** exact landed state of the B-1/T-1 / L-9 fix path (`cargo test -- --ignored`).
- Whether the four non-Twenty SSRF advisories should be cited at all, or the "shipped fixes" framing
  dropped (R6).

---

## 7. Per-angle documents

- [01 — SSZ / tree-hash / signing-domain correctness](01-ssz-domain-correctness.md) — E-1, E-2, B-1/T-1, KG-1, L-9.
- [02 — Slashing protection, remote signer, DVT namespacing](02-slashing-remote-signer-dvt.md) — SS-1, SS-2/3, DVT-1, KM-1, CN-1, GVR-1, IMP-1.
- [03 — Doppelganger protection (forward window + signing gate)](03-doppelganger-protection.md) — D-1, D-3, D-2, S-3.
- [04 — BN trust boundary, SSRF deny-list, optimistic handling](04-bn-trust-boundary.md) — BN-1, BN-2, URL-1, URL-2, SSE-1, EXIT-1, Info-4.

Source of truth for findings: `docs/2026-06-13-adversarial-code-review.md` (46 verified findings).
Remediation plan: `plan/remediation/prd.md`.
