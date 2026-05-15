# Issue Estimates: Tier 1 — Standards Compliance

## Estimation Approach

- **Point scale:** 1 (half day) / 2 (one day) / 3 (one and a half days) / 5 (two+ days — must be justified)
- **Target scope:** Every issue completable in 1–2 days by a single code-writer
- Points reflect relative effort including coding, testing, review, and integration
- Two parallel workstreams: **Stream A** (API infrastructure + endpoints) and **Stream B** (testnet support + keygen)
- Stream B is fully independent of Stream A — zero shared files

## Phase Files

| File | Phase | Issue Count | Total Points |
|------|-------|-------------|-------------|
| [phase-1-foundation.md](./phase-1-foundation.md) | Phase 1: Foundation | 5 | 9 |
| [phase-2-config-endpoints.md](./phase-2-config-endpoints.md) | Phase 2: Config Endpoints | 7 | 14 |
| [phase-3-voluntary-exit.md](./phase-3-voluntary-exit.md) | Phase 3: Voluntary Exit | 4 | 7 |
| [phase-4-integration.md](./phase-4-integration.md) | Phase 4: Integration & Polish | 7 | 11 |
| **Total** | | **23** | **41** |

## Parallel Execution Plan

Two developers working simultaneously. Stream B (testnet) is fully independent and finishes early, so Dev B picks up Stream A overflow starting Day 2.

| Day | Stream A (Dev A) | Stream B (Dev B) | Notes |
|-----|-----------------|-----------------|-------|
| 1 | 1.1 Traits (2pts) | 1.4 Networks + 1.5 Keygen (3pts) | No deps, both start immediately |
| 2 | 1.2 NotFound (1pt) + 2.1 Types (2pts) | 1.3 save_config (3pts) | 1.2 quick, then 2.1 same day |
| 3 | 2.3 Fee handlers (2pts) | 1.3 cont. | 2.3 needs 2.1 (day 2) |
| 4 | 2.4 Gas handlers (2pts) | 2.2 Config adapter (3pts) | 2.2 needs 1.1 (day 1) + 1.3 (day 3) |
| 5 | 2.5 Graffiti handlers (2pts) | 2.2 cont. | |
| 6 | 2.6 Routes + AppState (2pts) | 3.1 Exit types (1pt) + 3.2 Exit adapter start (3pts) | 2.6 needs 2.3-2.5 (done day 5) |
| 7 | 2.7 Wire config (1pt) | 3.2 cont. | 2.7 needs 2.2 (day 5) + 2.6 (day 6) |
| 8 | 3.3 Exit handler (2pts) | 4.4 Persistence integ (2pts) | 3.3 needs 3.1 (day 6) |
| 9 | 3.4 Wire exit (1pt) + 4.1 Fee integ (2pts) | 4.5 Smoke (1pt) + 4.2 Gas/Graffiti integ (2pts) | |
| 10 | 4.3 Exit integ (2pts) | 4.7 Docs (1pt) | 4.3 needs 3.4 (day 9) |
| 11 | 4.6 Regression (1pt) | 4.6 Regression (1pt) | Both streams sync for final gate |

**Estimated duration:** ~11 working days with 2 parallel developers.

## Dependency Map

```text
Phase 1 (Foundation)              Phase 2 (Config)                  Phase 3 (Exit)           Phase 4 (Integration)
────────────────────              ──────────────────                ─────────────────         ─────────────────────

Stream A:

1.1 Traits ──────┬──────────────▶ 2.1 Types ──┬──▶ 2.3 Fee ──┐
  (2pts)         │                 (2pts)      ├──▶ 2.4 Gas ──┼──▶ 2.6 Routes ──▶ 2.7 Wire ──▶ 4.1 Fee IT
                 │                             └──▶ 2.5 Graf ─┘     (2pts)         (1pt)       (2pts)
                 │                                                     │                         │
                 ├──────────────▶ 2.2 Adapter ─────────────────────────┘───────────────┐       4.2 Gas/Graf IT
                 │                 (3pts)                                               │        (2pts)
                 │                   ▲                                                 │
                 │                   │                                                 ▼
                 ├──▶ 3.1 Types ──▶ 3.3 Handler ──┐                              4.4 Persist IT
                 │    (1pt)         (2pts)         │                               (2pts)
                 │                                 │
                 └──▶ 3.2 Adapter ─────────────────┴──▶ 3.4 Wire ──▶ 4.3 Exit IT
                      (3pts)                             (1pt)        (2pts)

1.2 NotFound ───────▶ 2.1 Types
  (1pt)                 (linked above)

1.3 save_config ────▶ 2.2 Adapter
  (3pts)               (linked above)

Stream B (independent):

1.4 Networks ──┐
  (2pts)       ├──────────────────────────────────────────────▶ 4.5 Smoke (1pt)
1.5 Keygen ────┘                                                4.7 Docs  (1pt)
  (1pt)

Final gate:
    All ──────────────────────────────────────────────────────▶ 4.6 Regression (1pt)
```

### Critical Path

The longest dependency chain determines the minimum duration:

```
1.1 (2) → 2.1 (2) → 2.3 (2) → 2.6 (2) → 2.7 (1) → 4.1 (2) → 4.6 (1) = 12 pts ≈ 6 dev-days
```

With two developers, the calendar critical path is **~11 days** (see schedule above).

### Sync Points

- **End of Phase 1** (Day 3): Both streams complete foundation. Verify `cargo test` passes.
- **End of Phase 2** (Day 7): All config endpoints implemented and wired. Verify 9 new endpoints respond.
- **End of Phase 3** (Day 9): Voluntary exit wired. All 10 new endpoints functional.
- **Phase 4 gate** (Day 11): Full integration tests, regression suite, docs. Ship.

## Risk Flags

| Issue | Risk | Mitigation |
|-------|------|------------|
| 1.3 `save_config()` | TOML serialization may not round-trip with `load_from_config()` — different key ordering, quoting, or missing fields could break reload | Write round-trip test first (RED). Block Phase 2 until this passes. |
| 3.2 Exit adapter | Porting signing logic from CLI involves beacon client calls, fork schedule, domain computation — more moving parts than config adapter | Size L (3pts). Mock beacon client in unit tests. Reference existing `voluntary_exit.rs` line-by-line. |
| 2.6 AppState extension | Adding fields to `AppState` and constructor changes the function signature — breaks the single call site in `main.rs` | Issue 2.7 immediately follows to fix the call site. These two should merge in sequence. |
| 1.4 Network tests | Existing tests explicitly assert Holesky/Sepolia are rejected — must be updated atomically with enum addition | Tests are in the same file. Update assertions in the same issue. `cargo test` must pass within the issue. |

## File Ownership Map

| Directory / Module | Owner Stream | Notes |
|--------------------|-------------|-------|
| `crates/keymanager-api/src/` | A | All API traits, handlers, types, error, server |
| `crates/keymanager-api/Cargo.toml` | A | Dependency additions for traits |
| `crates/rvc/src/keymanager_adapters.rs` | A | Both config and exit adapters |
| `crates/validator-store/src/` | A | `save_config()`, `has_validator()` additions |
| `crates/validator-store/Cargo.toml` | A | `tempfile` dependency |
| `bin/rvc/src/main.rs` | A | Adapter wiring |
| `crates/rvc/src/config/network.rs` | B | Network enum variants |
| `bin/rvc-keygen/src/network.rs` | B | Keygen network constants |
| `config.example.toml` | B | Documentation update |

## Merge Conflict Hotspots

All hotspots are within Stream A (no cross-stream file conflicts exist).

| File | Touched by | Strategy | Merge Order |
|------|-----------|----------|-------------|
| `crates/keymanager-api/src/handlers.rs` | 2.1 (helpers), 2.3, 2.4, 2.5, 2.6 (AppState), 3.3 | Strict ordering — each issue appends new handler functions in a dedicated section. Dev A owns this file exclusively. | 2.1 → 2.3 → 2.4 → 2.5 → 2.6 → 3.3 |
| `crates/keymanager-api/src/types.rs` | 2.1 (config types), 3.1 (exit types) | Append-only — 2.1 adds config request/response structs, 3.1 adds exit query/response structs in a new section below | 2.1 → 3.1 |
| `crates/rvc/src/keymanager_adapters.rs` | 2.2 (config adapter), 3.2 (exit adapter) | Append-only — each adapter is a new struct appended to the file. Dev B owns both issues sequentially. | 2.2 → 3.2 |
| `crates/keymanager-api/src/server.rs` | 2.6 (config routes), 3.4 (exit route) | Strict ordering — 2.6 extends constructor and adds config routes, 3.4 adds exit route and `exit_manager` param | 2.6 → 3.4 |
| `bin/rvc/src/main.rs` | 2.7 (config wiring), 3.4 (exit wiring) | Strict ordering — 2.7 adds config adapter construction, 3.4 adds exit adapter construction | 2.7 → 3.4 |
