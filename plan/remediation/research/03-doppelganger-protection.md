# Angle 03 — Doppelganger protection (forward window + signing gate)

**PRD findings covered:** D-1 (P0), D-3 (P0), D-2 (P2), S-3 (P2).
**Verification verdict:** 17 of 22 claims fully verified (HIGH); 2 require small wording
corrections; 3 single-source but consistent with everything observable.

> **PROMPT-INJECTION NOTICE (reported per protocol):** one WebFetch result (Lighthouse
> v5.3.0 `validator_store.rs`) carried a trailing "# MCP Server Instructions" block trying
> to redirect tool use toward alphaXiv. It was injected via fetched content and ignored; it
> influenced no tool call or output.

## Scope

Whether rs-vc actually withholds signing during the doppelganger observation window, at
every signing entry point, and how it behaves at edges (pre-genesis, missing liveness
entries, epoch 0).

## Verified (HIGH confidence)

- **Lighthouse v5.3.0 reference behavior** — `doppelganger_service.rs` / `validator_store.rs`:
  routing, `only_safe`, `register_new_validator` initialization, epoch-satisfaction at the
  last slot of `e+1`, CRITICAL log on missing entries, pre-genesis bypass to
  `remaining_epochs = 0`. This is the reference design for D-1.
- **rs-vc codebase claims (Read-verified):** `service.rs:122-150` restart-aware logic;
  `service.rs:130` pre-genesis-skew guard; `service.rs:207-242` fail-open on missing entries
  (this is **D-2**); `store.rs:218-220` default-allow `unwrap_or(true)` (this is the
  fail-open gate behind **D-3**); `main.rs:1266` `if current_epoch > 0` guard (this is **S-3**).
- **PRD D-1/D-2/D-3/S-3 acceptance criteria** read directly from `prd.md`.
- **Lighthouse book "2-3 epochs (~12-20 min)"** wording (verbatim).
- **Teku** gates attestations + block proposals + sync-committee contributions (MEDIUM: the
  doc explicitly lists those three).

## REFUTED / DOWNGRADE — drop or caveat

1. **Beacon-API liveness epoch-support is SHOULD, not MUST.** Current master
   `apis/validator/liveness.yaml` says BNs "SHOULD support the current and previous epoch"
   and "MAY support earlier epoch." PR #131 discussion contains a Paul Hauner comment using
   "MUST," but the merged spec uses SHOULD. The "400-on-other-epochs" framing is also softer
   (the example error is "Invalid epoch: -2" for *negative* epochs, not a guaranteed 400 for
   any unsupported epoch).
   - **Downgraded claim:** "BNs SHOULD support current and previous epoch; older-epoch support
     is optional; requesting an unsupported or invalid epoch typically returns 400."
2. **EIP-7657 is Stagnant, not a "live draft proposal."** The D-3 future-proofing rationale
   is still defensible, but EIP-7657 cannot be cited as actively progressing. (Consistent with
   angle 02's finding on the same EIP.)

## Corrections / nuances

3. **PR #131 missing-entry behavior** is better phrased as "PR #131 did not standardize how
   clients interpret absent liveness entries; clients must decide" — the observable fact is
   that the spec is *silent*, which is what justifies rs-vc choosing fail-closed (D-2). The
   stronger "did NOT reach consensus" phrasing was not directly observed.
4. **Endpoint path** is `/eth/v1/validator/liveness/{epoch}` (Validator tag, `operationId
   getLiveness`) — confirmed against master `beacon-node-oapi.yaml` after an initial misleading
   fetch. PR #2230 originally added the Lighthouse-specific `/lighthouse/seen_validators`;
   PR #131 standardized the cross-client path.

## Single-source (consistent, but verify if load-bearing)

- Lodestar PR #6012 merge status of the restart-aware variant (one summarization). rs-vc's own
  restart-aware logic is Read-verified; only the Lodestar citation is single-source.

## Bottom line

The doppelganger cluster (D-1 + D-3 + D-2 + S-3) is well-substantiated and the reference-design
diff aligns with both the verified Lighthouse pattern and the PRD acceptance criteria. The
implementer should work from the live v5.3.0 `doppelganger_service.rs` state machine rather than
any summary. Fix the two wording items (liveness SHOULD-not-MUST; EIP-7657 Stagnant) wherever
they appear downstream.
