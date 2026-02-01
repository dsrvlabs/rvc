# rvc

> [!WARNING]
> This is an experimental project still under active development. DO NOT USE ON MAINNET.


## Overview

`rvc` is an Ethereum validator client that manages validator keys,
performs attestation duties, and submits signed attestations to the beacon chain.

The entire codebase is written by a customized AI agent and plugins, developed as part of a *Fully Automated Development* process while preserving development history and observability for humans.

One of the tools used in this project can be found [here](https://github.com/rootwarp/claude-plugin-dev-assistant.git).


## Prerequisites

- Rust 1.92+
- Protocol Buffers compiler (`protoc`)
- Access to an Ethereum beacon node (Prysm, Lighthouse, Teku, Nimbus, or Lodestar)

## Build

```bash
cargo build
cargo build --release
```

## Usage

```bash
rvc start \
  --config config.toml \
  --beacon-url http://localhost:5052 \
  --keystore-path ./keystores \
  --network hoodi
```

See `config.example.toml` for all configuration options.

### CLI Options

| Option | Description | Default |
|---|---|---|
| `--config` | Path to TOML config file | |
| `--beacon-url` | Beacon node HTTP endpoint | |
| `--keystore-path` | Directory containing EIP-2335 keystores | |
| `--password-file` | Keystore password file | |
| `--slashing-db-path` | Slashing protection SQLite database path | |
| `--metrics-port` | Prometheus metrics HTTP port | `8080` |
| `--grpc-port` | gRPC server port | `50051` |
| `--network` | Network preset (mainnet, goerli, sepolia, holesky, custom) | |
| `--log-level` | Log level (trace, debug, info, warn, error) | `info` |

### Endpoints

- `GET /metrics` - Prometheus metrics
- `GET /health` - Health status (JSON)
- `GET /livez` - Liveness probe
- `GET /readyz` - Readiness probe

## Development

```bash
cargo check
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Code Coverage

```bash
# Requires cargo-llvm-cov
cargo llvm-cov --workspace
cargo llvm-cov --workspace --html
```

## License

MIT OR Apache-2.0
