# A-12 / E3 — `stage.rs` pin re-resolution (ARCH-5e)

**Status:** resolved, 2026-08-18.
**Decision:** proceed and **re-pin** to the post-redesign hash (stated default,
architecture phase-5 entry criterion **E3**).

## What A-12 was

The tracing initiative (TRC-1e / T19) prospectively pins
`crates/slashing/src/stage.rs` as **byte-identical to `0ae9a09`**:

```text
git diff 0ae9a09 -- crates/slashing/src/stage.rs
```

must be empty at every tracing merge. That pin is *prospective* (the tracing
tree is not landed as a CI step on `develop` today) and exists so tracing
instrumentation cannot creep into the slashing critical section.

## Why it is lifted here

**ARCH-5e** (ADR-005 / ARCH-P1-5) is the **authorized changer** of `stage.rs`.
It adds `reserve_block` / `reserve_attestation` + `CommittedReservation`
**alongside** `stage_*` (A-5.2: `stage_*` is retained, not replaced). This is
not instrumentation; it is the tentative-commit API.

Per `plan/architecture-2026-08-12/issues/05-phase-5.md` entry criterion **E3**:

> Default taken: proceed and re-pin to the post-redesign hash, recorded in
> `plan/tracing-2026-08-06/`. The resolution is written into ARCH-5e's
> description before its first commit.

This file **is** that resolution. The pin is not discovered by a red CI step.

## Re-pin procedure (TRC-1e / T19)

When the ADR-005 `stage.rs` work (ARCH-5e, then 5f at minimum) merges to
`develop`:

1. Take `git rev-parse` of the merge commit that contains the post-redesign
   `stage.rs`.
2. Replace the T19 baseline from `0ae9a09` to that commit:
   `git diff <new-pin> -- crates/slashing/src/stage.rs` must be empty.
3. Tracing work must still not instrument `stage.rs`; the pin's *purpose* is
   unchanged.

The exact post-redesign hash is filled in when this work is committed
(ARCH-5e is implemented uncommitted in the worktree). Until then the
tracing-only baseline remains `0ae9a09`, and **this file is the explicit
A-12 resolution**.

## What this does *not* authorize

- Deleting `stage_*` (deferred, A-5.2).
- Implementing `reconcile_unsigned` (that is **ARCH-5f**). Shipping `reserve_*`
  without 5f must not become a production caller — that re-opens M-1.
- Weakening C9's cancellation-proof `stage → sign → commit` core. `stage_*`
  and `stage_then_sign` stay.
