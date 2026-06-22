# Research: Ethereum Validator-Client Logging Landscape (Lighthouse, Prysm, Teku, Nimbus, Lodestar)

## Overview

Every production Ethereum consensus client ships a validator client (VC) whose log stream is the
primary way operators confirm liveness and diagnose missed duties. Across the five major
implementations the conventions have converged hard on a few things and diverge on others:

- **Convergence:** all five default to **`info`** level, all five emit a **low-volume `info`
  heartbeat** keyed on "I published an attestation / block / sync message for slot N", all attach
  **`slot`** to essentially every duty line, all support **JSON output** for log aggregation while
  defaulting to **human-readable** for the console, and all **truncate the pubkey / block root** in
  log lines for readability.
- **Divergence:** the exact field *keys* (`committee_index` vs `CommitteeIndex` vs `index`), the
  pubkey **truncation format** (`0x82b2…` head-only vs `0x811a…ca6a` head+tail vs `0x5abb_ac30`
  underscore), whether correlation identifiers live as `key=value` pairs (Lighthouse/Prysm/Lodestar/
  Nimbus) or are routed by a structured backend, and how aggressively the VC narrates per-slot.

The space is mature (these conventions have been stable since the 2020-2021 mainnet/Altair era), so
the practical goal for rs-vc is **familiarity**: an operator migrating from Lighthouse or Prysm
should be able to read the rs-vc `info` stream and immediately recognise "attestation published for
slot N, here's the head it voted on" without a translation guide. The recommendation section maps
that onto rs-vc's already-decided `snake_case`, spans-first, `TruncatedPubkey` (`0x{first10}…{last8}`)
convention.

> Note on naming: the term **"validator client"** here means the duty-performing component. Some
> clients (Teku, Nimbus, Lodestar) historically embedded the VC in the beacon node and now also ship
> a standalone VC; the log conventions are the same in both modes. Beacon-node-only lines (sync
> status, peer count) are included where they shape what operators expect to see, but rs-vc is a VC
> and its heartbeat should mirror the *VC-side* milestones.

## Key Players

| Player | Logging stack / framework | Default level | Default console format | JSON output | Pubkey / root truncation in logs |
|--------|---------------------------|---------------|------------------------|-------------|----------------------------------|
| **Lighthouse** (Rust, Sigma Prime) | `slog`-style structured (`key: value`), `service: …` tag | `info` [1] | human-readable, colored | `--log-format JSON` (terminal), `--logfile-format JSON` (file) [2] | block root `0xa208…7fd5` (head+tail); full pubkey on the *enable* line, short elsewhere [3][4] |
| **Prysm** (Go, Offchain Labs) | logrus, `Field=Value`, `prefix=…` tag | `info` (`--verbosity`) | text | `--log-format` = `text`/`json`/`fluentd`/`journald` (default `text`) [5] | block root `0x2e1cf8ec…` (head); `pubKey` field on block line [6] |
| **Teku** (Java, Consensys) | Log4j2, `*** Field: Value` event lines | `INFO` (`--logging`) | human-readable, colored | `--log-destination`, `--log-color-enabled`; status-event lines (no first-class per-line JSON flag documented) [7] | block/root `acef76..c61b` (head+tail, double-dot) [7] |
| **Nimbus** (Nim, Status) | nim-chronicles, `key=value` "textlines" | `INFO` (`--log-level`) | textlines (colors/nocolors auto) | `--log-format json` (JSON Lines) [8] | validator `b93c290b` (8 hex, no `0x`); roots `"bbe7fc25"` (8 hex) [9][10] |
| **Lodestar** (TypeScript, ChainSafe) | Winston, `key=value`, leading `level:` | `info` (`--logLevel`) | human-readable, colored | terminal+file levels split; structured `key=value` (JSON via backend config) [11] | validator `0x811a…ca6a` / `0x91a4…f7e2` (head+tail); root `0x5abb_ac30` (underscore) [12][13] |

Log levels by client (decreasing verbosity, default in **bold**):

| Client | Level ladder |
|--------|--------------|
| Lighthouse | `trace` → `debug` → **`info`** → `warn` → `error` (terminal `--debug-level`; file `--logfile-debug-level` defaults to `debug`) [2] |
| Prysm | `trace` → `debug` → **`info`** → `warn` → `error` (logrus via `--verbosity`) |
| Teku | `ALL` → `TRACE` → `DEBUG` → **`INFO`** → `WARN` → `ERROR` → `FATAL` → `OFF` (`--logging`) [7] |
| Nimbus | `TRACE` → `DEBUG` → **`INFO`** → `NOTICE` → `WARN` → `ERROR` → `FATAL` → `NONE` (`--log-level`) [8] |
| Lodestar | `trace` → `debug` → `verbose` → **`info`** → `warn` → `error` (`--logLevel`; file `--logFileLevel` defaults to `debug`) [11] |

The semantics are uniform and match rs-vc's own taxonomy in the PRD: `info` = operator milestones
(low volume, production default), `warn` = degraded-but-progressing, `error` = an intended action did
not complete, `debug`/`trace` = developer internal state and wire detail (off in production). Nimbus
is the only one with an extra **`NOTICE`** rung between `info` and `warn`; Lodestar is the only one
with **`verbose`** between `debug` and `info`. rs-vc's 5-level `tracing` ladder
(`error/warn/info/debug/trace`) is the common denominator and needs no extension.

## Detailed Profiles

### Lighthouse (the convention most worth matching)

Lighthouse is the de-facto reference for "what a Rust VC log should look like," and since rs-vc is
Rust and targets operators migrating from Lighthouse, its conventions are the highest-priority match.

- **What it does:** Emits one `info` line per completed duty with a `key: value` body and a trailing
  **`service:`** tag identifying the subsystem (`attestation`, `block`, `slot_notifier`, `beacon`).
- **Info heartbeat (VC side):**
  - Startup / validator load:
    `INFO Initialized validators enabled: 2, disabled: 0` and per-key
    `INFO Enabled validator voting_pubkey: 0x82b225f6…c4ae8502b6d5337e3bf101ad72741dc69f0a7cf, signing_method: local_keystore` (the **enable** line carries the *full* pubkey; this is the one place Lighthouse does not truncate) [3].
  - BN connection:
    `INFO Connected to beacon node(s) synced: 1, available: 1, total: 1` (and a version line
    `Connected to beacon node version: Lighthouse/v…`) [3][4].
  - Attestation published:
    `INFO Successfully published attestations type: unaggregated, slot: 12422, committee_index: 3, head_block: 0xabc111…, validator_indices: [12345], count: 1, service: attestation` [3][1].
  - Block proposed:
    `INFO Successfully published block slot: 98, attestations: 2, deposits: 0, service: block` [4][14].
  - Builder/registration:
    `INFO Published validator registrations to the builder network` [4].
- **Per-slot status line (beacon side, `slot_notifier`):** the single most recognisable operator
  artifact in the ecosystem —
  `INFO Synced slot: 7342304, block: 0x43c2…e036, epoch: 229447, finalized_epoch: 229445, finalized_root: 0x313c…2695, exec_hash: 0x9a48…f10c (verified), peers: 88, service: slot_notifier` [15].
  Operators watch this line as a clock: one per slot (12s), and its absence/lag is the primary
  liveness signal. (This is a *beacon-node* line; a standalone VC like rs-vc would not emit the
  `Synced … peers` form, but operators expect a comparable once-per-slot "I'm alive and here's the
  head" cue.)
- **Field set:** `slot`, `epoch`, `committee_index`, `head_block` (truncated root, head+tail
  `0x….…`), `validator_indices` (array), `count`, `service`. Beacon lines add `finalized_epoch`,
  `finalized_root`, `exec_hash`, `peers`.
- **Levels / format:** `--debug-level {info,debug,trace,warn,error}` default `info` for the terminal;
  `--logfile-debug-level` defaults to **`debug`** (the file is more verbose than the console by
  default — a notable pattern); `--log-format JSON` for terminal JSON, `--logfile-format {DEFAULT,
  JSON}` for the file; `--log-color` default `true`; size-rotated files via `--logfile-max-size`
  (200 MB) / `--logfile-max-number` (10) [2].
- **Limitations:** field keys are not perfectly uniform across subsystems; the full pubkey on the
  enable line is a redaction consideration rs-vc explicitly avoids (PRD mandates truncation
  everywhere).

### Prysm

- **What it does:** logrus key-value lines with a **`prefix=`** tag (analogous to Lighthouse's
  `service:`). Uses **PascalCase** field keys.
- **Info heartbeat:**
  - Attestation:
    `Submitted new attestations AggregatorIndices=[454743] AttesterIndices=[454743] BeaconBlockRoot=0x2e1cf8ecf573 CommitteeIndex=61 Slot=5500683 SourceEpoch=171895 SourceRoot=0x4a44b3dba695 TargetEpoch=171896 TargetRoot=0x5bedf3d17c72 prefix=validator` [6].
  - Block proposal:
    `Submitted new block` with `blockRoot`, `numAttestations`, `numDeposits`, `pubKey`, `slot` [16].
  - Sync committee:
    `Submitted new sync message` and `Submitted new sync contribution and proof` with `blockRoot`,
    `slot`, `slotStartTime`, `timeSinceSlotStart`, `validatorIndex`, `subcommitteeIndex` [16].
  - Performance tracking (when validator monitoring is on): per-epoch summary lines for inclusion
    distance, balances, etc. [17].
- **Field set:** `Slot`, `CommitteeIndex`, `BeaconBlockRoot`, `SourceEpoch/SourceRoot`,
  `TargetEpoch/TargetRoot`, `AttesterIndices`, `pubKey`, `validatorIndex`, `subcommitteeIndex`.
  Notable: Prysm logs **source/target checkpoints explicitly** (more attestation detail at `info`
  than Lighthouse) and includes a **`timeSinceSlotStart`** timing field on sync messages.
- **Levels / format:** `--verbosity` (logrus levels, default `info`); `--log-format` =
  `text` (default) / `json` / `fluentd` / `journald` [5]. The `fluentd`/`journald` options are a
  Prysm-specific nicety for shipping to those backends directly.
- **Limitations:** PascalCase keys are inconsistent with the Rust ecosystem; rs-vc's `snake_case`
  registry is the right call, but operators coming from Prysm will look for the *concepts*
  (source/target, committee index) more than the exact casing.

### Teku

- **What it does:** Java/Log4j2 with a distinctive **status-event** style: `*** Event Type` followed
  by `Field: Value` pairs, designed to read as a console narrative rather than a field bag.
- **Info heartbeat:**
  - Per-slot:
    `Slot Event *** Slot: 716614, Block: acef76..c61b, Epoch: 22394` [7].
  - Per-epoch:
    `Epoch Event ***` (epoch boundary summary) [7].
  - Attestation (once per epoch per validator, deliberately rate-limited):
    `Validator *** Published attestation Count: 1, Slot: 48539, Root: 5e1bf5..cee8` [7].
  - Warn example (state-transition reject):
    `WARN - Rejecting invalid block at slot 2020474 with root 0x…` [18].
- **Field set:** `Slot`, `Block`/`Root` (truncated head+tail with `..` double-dot, *no* `0x`
  prefix), `Epoch`, `Count`. Teku deliberately summarises ("once each epoch") rather than logging
  every single attestation, to keep `info` volume low at high validator counts — a useful instinct.
- **Levels / format:** `--logging {OFF,FATAL,ERROR,WARN,INFO,DEBUG,TRACE,ALL}` default `INFO`;
  `--log-destination {BOTH,CONSOLE,DEFAULT_BOTH,FILE}` default `DEFAULT_BOTH` (console shows
  blockchain events, file gets errors+info — again the "file is the durable record, console is the
  narrative" split); `--log-color-enabled` default `true`;
  `--log-include-validator-duties-enabled` default `true` (a dedicated toggle for the duty
  heartbeat) [7]. No first-class per-line JSON flag is documented; structured shipping is via Log4j2
  config.
- **Limitations:** the `*** Event` style is idiosyncratic and not worth copying literally; the
  *behaviour* worth copying is the dedicated `--log-include-validator-duties` toggle and the
  per-epoch summarisation option.

### Nimbus

- **What it does:** nim-chronicles "textlines" (logfmt-compatible `key=value`), explicitly built on
  the philosophy that "log files shouldn't be based on formatted text strings, but on well-defined
  event records with arbitrary properties that are easy to read for both humans and machines" [10].
  Closest in spirit to rs-vc's spans-first structured goal.
- **Info heartbeat (validator monitor, detailed mode logs each step at INF):**
  - Attestation lifecycle: `Attestation seen` → `Attestation included in aggregate` →
    `Attestation included in block`, e.g.
    `INF 2021-11-22 11:32:44.228+01:00 Attestation seen topics="val_mon" attestation="(… slot: 2656363, index: 11, beacon_block_root: "bbe7fc25", source: "83010:a8a1b125", target: "83011:6db281cd" …)" src=api epoch=83011 validator=b93c290b` [9][19].
  - Sync committee:
    `Sync committee message sent message=(slot: 6329629, beacon_block_root: "fa7b0eca", validator_index: 394114, signature: "a400b7c2") delay=-3s117ms56us567ns` [19].
  - Activity metrics mirror the log events: `beacon_attestations_sent`, `beacon_aggregates_sent`,
    `beacon_attestation_sent_delay`, `beacon_blocks_sent`, `beacon_blocks_sent_delay`,
    `beacon_sync_committee_messages_sent`, `beacon_sync_committee_message_sent_delay` [19].
- **Field set:** `slot`, `index`, `beacon_block_root` (8-hex quoted, no `0x`), `source`/`target`
  (as `epoch:root`), `epoch`, `validator` (8 hex, no `0x`), `validator_index`, `delay`, `topics`,
  `src`. Notable: Nimbus is the most **timing-explicit** — a signed **`delay`** (how far into/before
  the slot the message went out) on sent messages, which is exactly the kind of duty-timing signal an
  SRE wants.
- **Levels / format:** `--log-level {TRACE,DEBUG,INFO,NOTICE,WARN,ERROR,FATAL,NONE}` default `INFO`;
  `--log-format {auto,colors,nocolors,json,none}`; JSON is JSON Lines (one object per line),
  recommended with a log rotator [8].
- **Limitations:** the nested `attestation="(…)"` tuple rendering is verbose; rs-vc's flat
  per-event fields are cleaner. The `delay`/timing field and the 8-hex short id are the takeaways.

### Lodestar

- **What it does:** Winston logger, leading `level:` then `key=value` pairs. TypeScript/Node.
- **Info heartbeat:**
  - Attestation: `info: Published attestations slot=2699, index=20, count=1` [12][13].
  - Aggregate: `info: Published aggregateAndProofs slot=2662, index=13, count=1` and
    `info: Published aggregateAndProof slot=140984, validator=0x811a…ca6a` [13][12].
  - Block: `Published block slot=131792, validator=0x91a4…f7e2, graffiti=chainsafe/lodestar-0.24.3` [13].
  - Signed (debug): `debug: Signed attestation slot=2976774, index=23, head=0xb4e289c9…, validatorIndex=258098` [12] — i.e. the *signed* step is `debug`, the *published* step is `info`, a clean level split rs-vc can mirror (build/sign = debug, publish = info milestone).
  - Per-clock/sync: `Synced - slot: …` with roots like `0x5abb_ac30` [13].
- **Field set:** `slot`, `index`, `count`, `validator` (truncated pubkey `0x811a…ca6a`, head+tail),
  `validatorIndex`, `head`, `graffiti`. Uses **camelCase** (`validatorIndex`, `aggregateAndProofs`).
- **Levels / format:** `--logLevel {error,warn,info,verbose,debug,trace}` default `info`;
  `--logFileLevel` default `debug`; `--logFile` (`none` to disable); `--logFileDailyRotate` default
  `5` [11]. Like Lighthouse/Teku, the **file defaults to a more verbose level (`debug`) than the
  console (`info`)**.
- **Limitations:** camelCase and the underscore-truncated root (`0x5abb_ac30`) are Lodestar-specific;
  not worth copying. The `Signed…`=debug / `Published…`=info split and the head+tail pubkey
  truncation are the takeaways.

## Cross-Client Patterns (what operators expect)

These are the conventions that recur across ≥3 clients and therefore define operator expectations:

1. **`info` = "I did my duty for slot N."** Every client's `info` heartbeat is anchored on
   published-duty milestones with `slot` attached. An operator's mental model is: *one attestation
   line per assigned slot per validator, one block line when it's your turn to propose.* [1][6][7][9][12]
2. **The published-duty milestone set is:** attestation published, aggregate published, block
   proposed/published, sync-committee message sent, sync contribution/aggregation, plus lifecycle
   bookends — startup/validator-set-loaded, BN connected, epoch boundary, builder/validator
   registration. (Voluntary exit is logged when it happens but isn't part of the steady heartbeat.)
   [3][4][6][16][19]
3. **`slot` is universal; `epoch` is common.** `slot` appears on essentially every duty line;
   `epoch` appears on attestation/per-slot/per-epoch lines (Lighthouse, Prysm source/target, Teku,
   Nimbus). [1][6][7][9]
4. **Block roots are always truncated**, typically **head+tail** (`0xa208…7fd5`, `acef76..c61b`,
   `0x811a…ca6a`); Prysm/Nimbus sometimes show head-only. Operators read these as opaque
   correlation handles, not full hashes. [3][6][7][12]
5. **Validators are identified by index OR truncated pubkey, often both.** Lighthouse uses
   `validator_indices: [12345]`; Nimbus uses an 8-hex short id `b93c290b`; Lodestar/Prysm carry a
   truncated `validator=0x811a…ca6a` / `pubKey`. The index is preferred when known (compact, stable);
   the truncated pubkey is the fallback and the human-recognisable handle. [3][9][12][16]
6. **`committee_index` (attestation) and `subcommittee_index` (sync) are standard.** Named
   `committee_index` (Lighthouse), `CommitteeIndex` (Prysm), `index` (Lodestar/Nimbus). [3][6][12]
7. **Default = human-readable; JSON is opt-in for aggregation.** All five default the console to a
   colored human-readable format and offer a `--log-format`/`--logfile-format` switch to JSON Lines
   for Loki/ELK/Fluentd ingestion. [2][5][8][11]
8. **The file log is often *more verbose* than the console** (Lighthouse `--logfile-debug-level`
   default `debug`; Lodestar `--logFileLevel` default `debug`; Teku `DEFAULT_BOTH` routes
   errors+info to file). The console is the live narrative; the file is the durable forensic record.
   [2][7][11]
9. **A subsystem/`service`/`prefix` tag** is attached so operators can filter by component
   (Lighthouse `service:`, Prysm `prefix=`). This is the human-log analog of rs-vc's per-crate
   targets / span names. [1][6]
10. **Timing/`delay` is surfaced by the better clients** (Nimbus `delay=…`, Prysm
    `timeSinceSlotStart`) because for a VC the *when* of a duty matters as much as the *whether* —
    a late attestation still loses rewards. [16][19]

## Trends

- **Standalone VCs and the keymanager/remote-signer split** (Web3Signer) have made
  `request_id`-style correlation across a VC↔signer boundary more important — directly relevant to
  rs-vc's :9000 Web3Signer path, where none of the five legacy clients offer a strong off-the-shelf
  pattern, so rs-vc's `request_id`-on-span design is a genuine improvement to lead with.
- **Structured/JSON-first for aggregation** is the clear direction (Loki, ELK, Datadog). Human
  textlines remain the console default, but operators increasingly run JSON to a collector. rs-vc's
  `tracing` + OTLP stack is ahead of the legacy clients here (spans → span attributes → traces),
  which the field-aggregation tools the others bolt on cannot match.
- **Per-epoch summarisation over per-attestation spam** (Teku's "once each epoch" attestation line,
  Prysm/Nimbus validator-monitor summaries) is the answer to `info` flooding at thousands of
  validators — a backstop rs-vc should keep in mind (PRD P2-1 sampling).
- **Timing-as-a-field** (Nimbus `delay`) is becoming an expected signal as MEV/timing-games sharpen
  attention on intra-slot duty timing.

## Gaps & Opportunities for rs-vc

- **Familiar `info` heartbeat is table stakes** — if rs-vc's steady `info` stream reads like
  Lighthouse's ("published attestation slot=… head=… index=… count=…"), migrating operators are
  instantly at home. This is the single highest-leverage familiarity decision.
- **One `request_id` across the Web3Signer :9000 boundary** is something none of the five do well;
  leading with it (PRD's spans-first `request_id`) is a differentiator, not just parity.
- **OTLP/traces** give rs-vc end-to-end duty correlation that the legacy clients approximate with
  grep-on-`slot`; lean into it rather than only matching their flat lines.
- **Timing field** (`delay`/`time_into_slot`) on published-duty milestones would match Nimbus's most
  useful operator signal and fits rs-vc's per-slot-deadline domain.

---

## Recommendation

**Adopt a Lighthouse-shaped `info` heartbeat, rendered in rs-vc's already-decided `snake_case`,
spans-first, `TruncatedPubkey` convention.** Concretely:

### 1. Info-level milestone set (the steady heartbeat)

Emit exactly these at `info` (one logical event per milestone, low volume, production-safe). Names
are the *event message*; structured fields follow the PRD registry.

| Milestone | Trigger | Carries (beyond span's `slot`/`epoch`/`pubkey`/`duty`) | Mirrors |
|-----------|---------|--------------------------------------------------------|---------|
| **Startup / config summary** | process start | network, version, validator counts | all |
| **Validators loaded** | key load complete | `enabled`/`disabled` counts | LH `Initialized validators` [3] |
| **Validator enabled** (per key, optional/once) | each key | truncated `pubkey`, `signing_method` | LH `Enabled validator` [3] |
| **BN connected** | BN handshake/sync ok | `synced`/`available`/`total`, redacted `bn_url`, BN version | LH `Connected to beacon node(s)` [3] |
| **BN failover** | active BN switch → **`warn`** | from/to redacted `bn_url`, reason | LH/Nimbus |
| **Epoch boundary processed** | new epoch duties ready | `epoch`, duty counts | Teku `Epoch Event` [7] |
| **Attestation published** | attestation broadcast | `committee_index`, `head` (trunc root), `validator_index`/`count` | LH/Prysm/Lodestar [1][6][12] |
| **Aggregate published** | aggregate broadcast | `committee_index`, `count` | Lodestar `Published aggregateAndProofs` [13] |
| **Block proposed/published** | block broadcast | `block_root` (trunc), `attestations`/`deposits` counts, proposer `validator_index` | LH `Successfully published block` [4] |
| **Sync-committee message sent** | sync msg broadcast | `subcommittee_index`, `head` (trunc) | Prysm/Nimbus [16][19] |
| **Sync contribution published** | contribution/aggregation broadcast | `subcommittee_index`, `count` | Prysm `sync contribution and proof` [16] |
| **Validator registration published** | builder registration | count | LH builder line [4] |
| **(optional) Per-slot tick** | once per slot | head `block_root`/`slot`, `finalized_epoch` | LH `slot_notifier` [15] |

Demote to **`debug`**: the *signed* step (Lodestar logs `Signed attestation`=debug,
`Published…`=info — adopt that split), duty cache hit/miss, BN endpoint selection, slashing-protection
inputs/decision. Demote wire/payload framing and per-item loops to **`trace`**. This keeps `info`
volume at roughly *one line per assigned duty per validator* — the operator mental model from §2.

### 2. Field conventions to match for familiarity

- **`slot` on every duty line; `epoch` on attestation/epoch/per-slot lines** — universal expectation
  [1][6][7][9]. (Already on spans per PRD; ensure they render onto the `info` events.)
- **`committee_index`** for attestations, **`subcommittee_index`** for sync — keep the PRD's
  `snake_case` (don't copy Prysm's `CommitteeIndex` or Lodestar's bare `index`; `committee_index`
  matches Lighthouse, the migration source rs-vc most cares about) [3].
- **Truncated head/root as a named field**, head+tail style. rs-vc has no head-block helper yet;
  add a `TruncatedRoot`/`TruncatedHash` `Display` wrapper analogous to `TruncatedPubkey`
  (`0x{first8}…{last6}` or similar) so block/head roots are short *and* zero-alloc when disabled.
  Use field name **`head`** (Lodestar/Nimbus) for the attested head and **`block_root`** for a
  proposed block — both head+tail truncated [3][12][13].
- **Prefer `validator_index` when known, truncated `pubkey` as the human handle** — log both on
  duty milestones where cheap; `validator_index: [..]` style (Lighthouse) or a single
  `validator_index` + `pubkey` pair. Keep the PRD's `0x{first10}…{last8}` `TruncatedPubkey`; it is
  the head+tail family operators already read, just slightly longer than Lighthouse's head-only
  enable-line key — and unlike Lighthouse it is *consistent* (never a full key), which is the right
  call given rs-vc's redaction mandate [3][12].
- **Add a timing field** (`time_into_slot` / `delay`) to published-duty milestones, matching
  Nimbus's most useful operator signal and rs-vc's per-slot-deadline domain [19].
- Keep the **`network`** resource attribute (already set), do not repeat per event.

### 3. Defaults and switching (P0-5 reconciliation)

- **Default level `info`**, **default console format human-readable** — matches all five clients and
  the PRD. JSON is **opt-in** for aggregation.
- **Make the file/aggregation level default to `debug`** if rs-vc keeps a file appender, matching
  Lighthouse (`--logfile-debug-level=debug`) and Lodestar (`--logFileLevel=debug`): console = live
  `info` narrative, file = `debug` forensic record. (Confirm against the existing `logroller`
  appender contract; this is a default choice, not a redesign.)
- **JSON profile** (PRD P2-3): document `RUST_LOG`-independent format selection so an operator can
  flip to JSON Lines for Loki/ELK exactly like `--log-format json` on the others. With `tracing`,
  this is the `fmt` layer's `.json()`; expose it via the same config/env knob in **both** binaries so
  they look identical (P0-5).
- Keep **`RUST_LOG`/`EnvFilter` env-overrides-config** precedence (the PRD decision); document
  per-module recipes the way the others document `--log-level`/`--verbosity`.

### 4. Operator-facing conventions worth copying

- **A once-per-slot "still alive, here's the head" cue** (Lighthouse `slot_notifier`) so operators
  can use rs-vc's stream as a clock and alert on its absence. As a VC (not a beacon node), make it a
  lightweight `info` tick (slot, head root, finalized epoch) rather than the full peers/sync line
  [15].
- **A dedicated toggle for the duty heartbeat** (Teku's `--log-include-validator-duties-enabled`) so
  operators at very high validator counts can quiet per-duty `info` without losing warnings/errors —
  or, equivalently, the PRD P2-1 sampling backstop [7].
- **A subsystem identifier** on each line — rs-vc gets this for free via per-crate `tracing` targets
  / span names (analogous to Lighthouse `service:` / Prysm `prefix=`); ensure it is rendered in both
  human and JSON output so operators can filter by component [1][6].
- **Truncate everything that's a key/root/url** (pubkeys, head/block roots, BN urls) — the universal
  readability+safety convention; rs-vc already mandates `TruncatedPubkey`/`RedactedUrl`, add the
  root wrapper to complete the set.

**Net:** rs-vc should look like "Lighthouse with consistent `snake_case` fields, always-truncated
secrets, a `request_id` that survives the Web3Signer hop, and OTLP traces underneath." That gives
migrating Lighthouse/Prysm/Teku/Nimbus/Lodestar operators an instantly familiar `info` heartbeat
while delivering correlation the legacy clients can't.

---

## Assumptions

- **rs-vc is a validator client, not a beacon node.** Beacon-node-only lines (peer count, sync
  distance, the full Lighthouse `Synced … peers` line) are treated as *context for operator
  expectations*, not as lines rs-vc must emit verbatim. The recommended per-slot tick is a
  lightweight VC version.
- **The PRD's settled decisions hold and are not re-opened by this research:** `snake_case`,
  spans-first, 5-level `tracing` taxonomy, `TruncatedPubkey` = `0x{first10}…{last8}`,
  `info`=production default, `RUST_LOG` env-overrides-config. This doc maps external conventions
  *onto* those, and only *adds* (e.g. a truncated-root wrapper, a timing field) rather than changing
  them.
- **Exact log strings are illustrative, not contractual.** The quoted lines are real but
  version-specific (client log wording changes between releases); they are cited to establish the
  *shape, fields, and level* of each milestone, which is stable, not to pin an exact string rs-vc
  must reproduce.
- **Several examples come from community guides (CoinCashew), client books, and GitHub issues**
  rather than a single canonical "log format spec" — because none of these clients publish a formal
  log-line schema. Where a field/level is corroborated across ≥2 sources or appears in
  official docs/source, confidence is high; single-source community examples (e.g. some exact Prysm
  block-line field names) are flagged inline as lower confidence.
- **Teku's lack of a documented per-line JSON flag** reflects the docs surveyed; Teku can ship
  structured logs via Log4j2 configuration, but it is not a simple `--log-format json` like the
  others. Treated as "JSON via backend config" rather than "no JSON."
- **The "file defaults more verbose than console" pattern** is assumed beneficial and recommended,
  contingent on the existing `logroller`/non-blocking-writer appender supporting an independent level
  — to be confirmed against the `telemetry` crate, not assumed to require a redesign.

## Sources

[1] [Missed Attestations — A technical guide to understanding and fine-tuning Lighthouse](https://blog.sigmaprime.io/attestation-analysis.html) — Sigma Prime (Lighthouse). Example `INFO Successfully published attestation slot/committee_index/head_block` and per-slot `Synced … service: slot_notifier` lines; default `info`.
[2] [Validator Client — Lighthouse Book (`help_vc`)](https://lighthouse-book.sigmaprime.io/help_vc.html) — Sigma Prime. `--debug-level` (default `info`), `--log-format JSON`, `--logfile-debug-level` (default `debug`), `--logfile-format {DEFAULT,JSON}`, `--log-color`, file rotation defaults.
[3] [Lighthouse — CoinCashew validator setup guide](https://www.coincashew.com/coins/overview-eth/guide-or-how-to-setup-a-validator-on-eth2-mainnet/part-i-installation/step-5-installing-validator/installing-validator/lighthouse) — CoinCashew. Example `Initialized validators`, `Enabled validator voting_pubkey` (full pubkey), `Connected to beacon node(s)`, `Successfully published attestations` lines and their fields.
[4] [Lighthouse validator log messages (block/builder/connection)](https://lighthouse-book.sigmaprime.io/mainnet-validator.html) — Sigma Prime, via search. `Successfully published block slot/attestations/deposits/service`, `Connected to beacon node version`, `Published validator registrations to the builder network`.
[5] [cmd package — prysm `--log-format` (text/json/fluentd/journald)](https://pkg.go.dev/github.com/prysmaticlabs/prysm/v4/cmd) — Offchain Labs / pkg.go.dev. `--log-format` values and `text` default; `--verbosity` (logrus levels).
[6] [Validator Performance Tracking](https://medium.com/offchainlabs/validator-performance-tracking-a2ea9ab44b3a) — Offchain Labs (Prysm). `Submitted new attestations` line with `AggregatorIndices/AttesterIndices/BeaconBlockRoot/CommitteeIndex/Slot/Source*/Target*/prefix=validator`.
[7] [validator-client, vc — Teku documentation / CLI reference](https://docs.teku.consensys.io/reference/cli) — Consensys (Teku). `--logging` levels (default `INFO`), `--log-destination` (default `DEFAULT_BOTH`), `--log-color-enabled`, `--log-include-validator-duties-enabled`; `Slot Event ***`, `Epoch Event ***`, `Validator *** Published attestation` example lines.
[8] [Logging — The Nimbus Guide](https://nimbus.guide/logging.html) — Status (Nimbus). Eight levels `TRACE…FATAL/NONE` (default `INFO`); `--log-format` {auto,colors,nocolors,json,none}; JSON Lines guidance.
[9] [Nimbus structured-logging example (Chronicles)](https://github.com/status-im/nim-chronicles) — Status. `INF … Attestation seen … epoch=83011 validator=b93c290b` textlines example; `key=value` philosophy.
[10] [Chronicles — Nimbus Libraries](https://libs.nimbus.team/lib/nim-chronicles/) — Status. textlines default, logfmt-compatible; "event records not formatted strings" philosophy; colors/nocolors/json formats.
[11] [validator CLI Command — Lodestar](https://chainsafe.github.io/lodestar/run/validator-management/validator-cli/) — ChainSafe. `--logLevel {error,warn,info,verbose,debug,trace}` default `info`; `--logFileLevel` default `debug`; `--logFile`, `--logFileDailyRotate` default 5.
[12] [Lodestar validator attestation/sign log examples (GitHub issues)](https://github.com/ChainSafe/lodestar/issues/2909) — ChainSafe. `info: Published attestations slot=…,index=…,count=…`, `debug: Signed attestation … validatorIndex=…`, `Published aggregateAndProof … validator=0x811a…ca6a`.
[13] [Lodestar — CoinCashew validator setup guide](https://www.coincashew.com/coins/overview-eth/guide-or-how-to-setup-a-validator-on-eth2-mainnet/part-i-installation/step-5-installing-validator/installing-validator/lodestar) — CoinCashew. `Published attestations/aggregateAndProofs slot/index/count`; `Published block … validator=0x91a4…f7e2, graffiti=…`; `Synced - slot:` with `0x5abb_ac30` root truncation.
[14] [Lighthouse validator-monitoring docs](https://lighthouse-book.sigmaprime.io/validator-monitoring.html) — Sigma Prime. Validator monitor log/metric naming and `service` tagging context.
[15] [Lighthouse `slot_notifier` per-slot status line (issue threads)](https://github.com/sigp/lighthouse/issues/4747) — Sigma Prime / GitHub. `INFO Synced slot/block/epoch/finalized_epoch/finalized_root/exec_hash/peers/service: slot_notifier`; `New block received root/slot`.
[16] [Prysm block/sync-committee submission log fields](https://hackmd.io/@potuz/HJGTPDz1n) — Offchain Labs (potuz). `Submitted new block` (`blockRoot/numAttestations/numDeposits/pubKey/slot`); `Submitted new sync message` / `sync contribution and proof` (`slot/slotStartTime/timeSinceSlotStart/validatorIndex/subcommitteeIndex`).
[17] [Track latest validator performance in Prysm](https://hackmd.io/@potuz/BknPgOOIF) — Offchain Labs (potuz). Per-epoch validator-performance summary logging.
[18] [Improve logging of invalid blocks — Teku issue #4329](https://github.com/ConsenSys/teku/issues/4329) — Consensys. `WARN - Rejecting invalid block at slot … with root 0x…` example; warn-level semantics.
[19] [Validator monitoring — The Nimbus Guide](https://nimbus.guide/validator-monitor.html) — Status (Nimbus). `Sync committee message sent … delay=…`; attestation lifecycle (`Attestation seen`/`included in aggregate`/`included in block`); `beacon_*_sent` / `*_sent_delay` metric+log naming; 8-hex `validator=` short id.
