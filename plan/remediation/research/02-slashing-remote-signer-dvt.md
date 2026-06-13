# Angle 02 — Slashing protection, remote signer, DVT namespacing

**PRD findings covered:** SS-1 (P0/Critical), SS-2/SS-3 (P0), DVT-1 (P0), KM-1 (P0),
CN-1 (P1), GVR-1 (P1), IMP-1 (P1).
**Verification verdict:** 26 of 27 claims verified as substantively correct. **1 claim overstated** (keymanager-APIs atomicity wording).

## Scope

The slashing-protection boundary: the standalone signer's EIP-3076 consultation, the
per-CN/per-peer namespacing that governs cross-tenant double-sign detection, the DVT
threshold-partial flow, and the keymanager DELETE export-on-delete contract.

## Verified local-repo findings (HIGH confidence — line numbers match `develop`)

All seven local findings verified at the cited lines: **SS-1, SS-2/SS-3, CN-1, DVT-1,
KM-1, GVR-1, IMP-1**. CN-1 / DVT-1 / SS-2 line numbers in the PRD match the repository.

## Verified upstream claims (HIGH confidence)

- EIP-3076 scope and invariants (two message classes; aggregate-and-proof is NOT in scope).
- Web3Signer dispatch model, Teku / Lighthouse slashing-protection docs.
- Phase 0 spec, keymanager-APIs schema, Obol / SSV / Cubist threat-model sources.
- **EIP-3076 hex case-sensitivity:** the JSON Schema does not pin case; Web3Signer/Lighthouse/Teku
  interchange may emit either case and can fail to match a pinned GVR. Best practice is to
  normalize to lowercase. This is the spec basis for **GVR-1**.

## REFUTED / OVERSTATED — drop or caveat

- **Keymanager-APIs "atomicity requirement" (KM-1) is OVERSTATED.** The flows README does
  NOT use the words "in a single atomic sequential operation" and does NOT mandate aborting
  DELETE on export failure. Its literal guidance is closer to "any step failure should set
  status to error but allow processing to continue for remaining keys." The README's hard
  rules are: the keymanager must NEVER delete the slashing-protection data for a key, and
  must NEVER return slashing-protection data for a key with an error status.
  - **What this means for the PRD:** the KM-1 remediation (abort the whole DELETE on export
    error, delete nothing — PRD assumption #9) is still *defensible and safe*, but it must be
    framed as "**fail-closed remediation consistent with the spirit of the keymanager DELETE
    semantics**," NOT as a literal MUST from the flows README. The strongest spec lever is
    `local_keystores.yaml` status-value semantics (`status=deleted` MUST carry
    `slashing_protection`; the keymanager MUST NEVER delete the underlying records) plus
    EIP-3076 invariants — cite those, not the flows README atomicity wording.
  - The MUST framing appears only in the PRD itself, not in the cited source. **Low confidence
    on the exact language; the security argument remains valid.**

## Corrections / nuances

1. **EIP-7657 is Stagnant, not actively progressing.** This strengthens the underlying point
   ("sync-committee signatures are currently NOT slashable on mainnet") but "the EIP exists
   precisely because that hole is intentional and undefended today" is editorializing — the
   hole exists; whether it's "intentional" is debatable.
2. **Phase 0 spec URL fix.** `.../blob/dev/specs/phase0/validator.md` returns 404 on `dev`;
   point at `master` or a tagged version (v1.0.0–v1.3.0). Substance verified.
3. **Lighthouse Book direct fetch returned 403** (GitBook anti-bot). The "sync-committee
   contributions are not slashable and will continue to be produced even when doppelganger
   protection is suppressing other messages" wording was confirmed via search snippet faithful
   to multiple historical reproductions. High confidence on substance; note the fetch failure.
4. **Cubist quote** matches in substance; the exact verbatim wording I could verify differs
   slightly from the claim's formulation. The two are consistent; minor low-confidence on the
   exact quotation only.
5. **CN-1 "written-but-not-read schema column" remediation** is a design recommendation, not a
   verified claim — internally consistent with the columns currently in `stage.rs` but not
   externally sourced.
6. **SS-2/SS-3 chain-of-custody caveat (structural correctness).** Removing slashing-DB
   consultation from `sign_aggregate_and_proof` is correct per EIP-3076 scope, BUT the inner
   `Attestation` MUST have already been signed via `sign_attestation` through the slashing-DB
   path. Otherwise the chain of custody breaks. Restate this in the SS-2/SS-3 fix notes — it
   is implicit in EIP-3076's two-class scoping but easy to lose.

## Bottom line

The slashing-boundary findings are real and well-substantiated. Re-anchor KM-1's "MUST" to
`local_keystores.yaml` + EIP-3076 rather than the flows README; the fail-closed fix stands.
