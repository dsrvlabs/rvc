# Unreleased

## Behavior changes

### rvc-signer CLI args that equal built-in defaults now win over the config file

`rvc-signer serve` previously treated a CLI flag as “unset” when its value matched
the clap built-in default (the `*_is_default` heuristic). That meant an operator who
explicitly passed e.g. `--listen-address 127.0.0.1:50052` or `--network mainnet`
could still have those values overwritten by `config.toml`.

CLI arguments that are present on the command line now always win over the file,
even when the value equals the built-in default. Unpassed flags still fall back to
the config file, then to the built-in default. Defaults live in one place
(`bin/rvc-signer` `config` constants / merge); clap no longer fills them via
`default_value` for the option-typed flags.

Affected flags include at least: `--listen-address`, `--backend`,
`--reload-interval`, `--http-listen-address`, `--http-tls-mode`, `--network`,
and (with the `dvt` feature) `--dvt-timeout`.

### rvc-signer builder registration uses network genesis on all transports

`VALIDATOR_REGISTRATION` / `sign_builder_registration` now derive the
application-builder domain from the server's configured network genesis fork
version (`--network` / `[signer].network`, default `mainnet`) on **both** gRPC
and HTTP. Previously HTTP always used mainnet `0x00000000` while gRPC accepted a
per-request override — identical non-mainnet registrations produced different
signatures across transports.

- Mainnet signatures are unchanged.
- On Hoodi / Holesky / Sepolia, configure `--network` to match the chain; the
  gRPC request field, when present, must equal the server network (empty still
  means "use server config").
- Cross-transport signature equality is enforced by integration tests.

### Proposer block production honors multi-node failover

When `proposer_nodes` is configured with more than one endpoint, block
production now routes through the proposer `BnManager` pool (best-of /
failover) instead of a single client built from `proposer_nodes[0]`.

- If the first proposer node is down, a healthy peer can still produce the
  block.
- With `proposer_nodes` empty, behavior is unchanged: the main beacon pool is
  used.
- Underlying pool clients use `max_retries = 0`; failover is the retry policy
  (see `BnManager` docs).

### rvc-keygen never silently overwrites signed outputs (all platforms)

`rvc-keygen` exit and BLS-to-execution commands now always create output files
with `create_new` semantics (shared `write_new_0600` helper). On non-unix
platforms they previously used plain `fs::write`, which could silently overwrite
an existing signed message at the same path. Writes to an existing path now fail
with a path-bearing error on every platform. Unix permission mode remains
`0o600` (owner read/write only).
