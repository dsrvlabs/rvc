# prior-art
## Summary
Lighthouse is the closest peer (Rust + `tracing` + OpenTelemetry). Prysm uses OTel-Go + logrus. Teku/Lodestar are limited to what documentation surfaces (neither is Rust; deep code comparison is low ROI). Vouch advertises OTLP trace export but documentation doesn't describe span structure. Adopt from Lighthouse: dual attribute style (structured fields + message text). Ignore from everyone: none explicitly solved the test-capture "print tree on failure" problem the way our PRD P0-7 needs — it's our own design.

## Per-project takeaway

### Lighthouse (sigp/lighthouse) — Rust
- Logging library: **`tracing`** (migrated away from slog).
- OpenTelemetry: **built-in OTLP exporter**, configurable via `--telemetry-collector-url`; default service name `lighthouse-vc`.
- Span structure (from `validator_services/src/attestation_service.rs`): top-level span `"attestation_service"`, children `"handle_aggregates"` (`%slot`, `%committee_index`), `"publish_attestations"` (`count`), `"sign_aggregates"` (`count`), `"publish_aggregates"` (`count`). Fields include `slot`, `duty_slot`, `validator`, `validator_indices`, `pubkey`, `committee_index`, `beacon_block_root`.
- Remote signer propagation: not explicit in docs; Lighthouse routes Web3Signer via reqwest and likely injects `traceparent` via tower-http-style middleware, but unconfirmed.
- Test log capture: `common/logging` exposes `create_test_tracing_subscriber()` gated behind a `test_logger` feature — similar in spirit to our approach, but feature-gated instead of RAII-guarded. **Not as ergonomic** as our proposed `TestTracingGuard`.
- **Adopt:** structured fields with consistent names across duty types; OTel opt-in.
- **Ignore:** feature-gated test logger — too much friction per-test.

### Prysm (OffchainLabs/prysm) — Go
- Logging library: **logrus** for text logs; **OTel-Go** (`go.opentelemetry.io/otel/trace`) for distributed tracing.
- Span names follow `validator.{Verb}` pattern (e.g. `"validator.SubmitAttestation"`, `"validator.signAtt"`, `"validator.waitUntilAttestationDueOrValidBlock"`).
- Span attributes: `validator`, `slot`, `attestationHash`, `blockRoot`, `justifiedEpoch`, `targetEpoch`, `committeeIndex`, `attesterIndex`, `aggregationBitfield`.
- Log fields (logrus): `pubkey`, `slot`, `committeeIndex`, `blockRoot`, `sourceEpoch`, `sourceRoot`, `targetEpoch`, `targetRoot`.
- Remote signer propagation: `v.km.Sign(ctx, ...)` passes Go `context.Context` which carries trace context, but the SignRequest proto doesn't surface it — **implicit propagation** via context, unlike rs-vc's explicit metadata plan. Our explicit approach is more auditable.
- Test log capture: not visible in attest.go; Prysm relies on external runbook-style testing.
- **Adopt:** verb-style span naming (`{domain}.{Verb}`) — matches our `rvc.{domain}.{operation}`.
- **Ignore:** full-signature attribute dumps (`aggregationBitfield`) — verbose and we don't need it for debug.

### Teku (ConsenSys/teku) — Java
- Logging library: **log4j2** + Java-style structured logging.
- OpenTelemetry: present but documentation-sparse on what span names it emits. `--log-include-validator-duties-enabled` toggles per-duty logging.
- Test log capture: JUnit + log4j TestAppender (standard Java pattern).
- **Adopt:** the explicit `--log-include-validator-duties-enabled` flag idea — a runtime config to toggle per-duty info-level logs without recompile. (Not in rs-vc PRD today; could be a P2.)
- **Ignore:** log4j-specific patterns don't translate.

### Lodestar (ChainSafe/lodestar) — TypeScript
- Logging library: custom `LoggerVc` wrapper over an unknown base (likely Winston or Pino).
- Span structure: not traced; Lodestar logs at `debug`/`info`/`error` but doesn't expose a distributed-trace integration in `packages/validator/src/services/attestation.ts`.
- Fields per attestation: `slot`, `index`, `head` (root hex), `validatorIndex`, `count`, `participants`, `type` (`"aggregated"` / `"unaggregated"`).
- Remote signer: does not propagate trace context; signs via local `this.validatorStore.signAttestation()`.
- **Adopt:** explicit `type` field to distinguish aggregated vs unaggregated flows — matches our per-duty-root-span pattern.
- **Ignore:** lack of distributed tracing — our PRD is a step beyond.

### Vouch (attestantio/vouch) — Go
- Logging library: Go-standard + **OTLP trace export** (user-configurable endpoint).
- Span structure: documentation confirms OTLP trace export but doesn't surface specific span names publicly.
- Metrics: rich Prometheus metrics, but traces are a config-only feature.
- Remote signer: gRPC to Dirk/Web3Signer; trace propagation not documented.
- **Adopt:** per-duty metrics named `vouch_attestation_process_latest_slot` etc. — PRD P1-2 already plans to cross-reference metric names in log lines. Vouch's naming style (`{component}_{operation}_{metric}`) is a sensible model.
- **Ignore:** can't compare span structure without source deep-dive; low ROI.

## What to adopt / what to ignore for rs-vc

**Adopt:**
- Lighthouse's structured-field discipline on duty spans.
- Prysm's verb-form span naming — already matches our `rvc.{domain}.{operation}`.
- Lodestar's `type` field idea for distinguishing sub-shapes of a duty.
- Teku's "toggle per-duty logging" runtime flag (P2 candidate).

**Ignore:**
- Lighthouse's feature-gated test logger — our RAII guard is cleaner.
- Prysm's implicit context-based propagation — our explicit metadata injector is more auditable.
- Log4j/Winston/Pino patterns — language-specific, don't translate.
- Vouch's opaque span structure — no action item.

## Sources

- [Lighthouse validator_services attestation_service.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/validator_client/validator_services/src/attestation_service.rs) — sigp/lighthouse.
- [Lighthouse common/logging/src/lib.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/common/logging/src/lib.rs) — feature-gated test tracing.
- [Lighthouse Book — Validator Monitoring](https://lighthouse-book.sigmaprime.io/validator-monitoring.html) — sigp.
- [Prysm validator/client/attest.go](https://raw.githubusercontent.com/prysmaticlabs/prysm/develop/validator/client/attest.go) — OffchainLabs/prysm.
- [Teku docs — validator-client](https://docs.teku.consensys.io/reference/cli/subcommands/validator-client) — ConsenSys.
- [Lodestar validator attestation.ts](https://raw.githubusercontent.com/ChainSafe/lodestar/unstable/packages/validator/src/services/attestation.ts) — ChainSafe/lodestar.
- [Vouch configuration docs](https://github.com/attestantio/vouch/blob/master/docs/configuration.md) — attestantio.

---
