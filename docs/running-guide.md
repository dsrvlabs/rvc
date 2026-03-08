# Running rvc - Rust Validator Client

## Prerequisites

- Rust toolchain (edition 2021, MSRV 1.92)
- A running Ethereum beacon node (Lighthouse, Prysm, Teku, Nimbus, or Lodestar)
- EIP-2335 keystore files for your validators

## Building

```bash
# Debug build
cargo build

# Release build (recommended for production)
cargo build --release
```

Binary location:
- Debug: `target/debug/rvc`
- Release: `target/release/rvc`

## Quick Start

```bash
# Minimal invocation (uses defaults: mainnet, localhost:5052)
rvc start

# With a config file
rvc start -c config.toml

# With CLI overrides
rvc start --beacon-url http://localhost:5052 \
          --keystore-path ./keystores \
          --password-file ./passwords.txt \
          --network mainnet
```

## Commands

### `rvc start` - Run the Validator Client

```
rvc start [OPTIONS]
```

#### Core Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | none | TOML configuration file |
| `--beacon-url <URL>` | `http://localhost:5052` | Beacon node HTTP endpoint |
| `--beacon-nodes <URL,URL,...>` | none | Comma-separated beacon node URLs (multi-BN failover) |
| `--keystore-path <PATH>` | `./keystores` | Directory containing EIP-2335 keystore JSON files |
| `--password-file <PATH>` | none | Password file for keystore decryption |
| `--slashing-db-path <PATH>` | `./slashing_protection.sqlite` | Slashing protection SQLite database |
| `--network <NETWORK>` | `mainnet` | Network preset: `mainnet`, `sepolia`, `holesky`, `goerli`, `custom` |

#### Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-port <PORT>` | `8080` | Prometheus metrics HTTP port |
| `--grpc-port <PORT>` | `50051` | gRPC server port |
| `--grpc-address <ADDR>` | `127.0.0.1` | gRPC bind address |

#### Validator Options

| Flag | Default | Description |
|------|---------|-------------|
| `--graffiti <STRING>` | none | Block graffiti (max 32 bytes) |
| `--no-doppelganger-detection` | false | Disable doppelganger detection (enabled by default) |
| `--log-level <LEVEL>` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

#### Keymanager API Options

| Flag | Default | Description |
|------|---------|-------------|
| `--keymanager-enabled` | false | Enable the Keymanager API server |
| `--no-keymanager` | false | Disable Keymanager API (overrides config file) |
| `--keymanager-address <ADDR>` | `127.0.0.1:5062` | Keymanager API listen address |
| `--keymanager-token-file <PATH>` | `./keymanager-api-token.txt` | Bearer token file |
| `--remote-signer-url <URL>` | none | Web3Signer URL for remote signing |

#### Security Options

| Flag | Default | Description |
|------|---------|-------------|
| `--strict-permissions` | false | Exit if slashing DB has unsafe file permissions |
| `--strict-slashing-semantics` | false | Reject null-root re-signs (strict EIP-3076) |

#### Timeout Options (seconds)

| Flag | Default | Description |
|------|---------|-------------|
| `--block-production-timeout` | 3 | Block production deadline |
| `--attestation-timeout` | 4 | Attestation fetch deadline |
| `--aggregate-timeout` | 2 | Aggregate fetch/submit deadline |
| `--duty-fetch-timeout` | 10 | Duty resolution deadline |

#### Secret Provider Options

| Flag | Default | Description |
|------|---------|-------------|
| `--secret-provider <NAME>` | none | Secret provider to use for loading validator keys (e.g., `gcp`) |
| `--gcp-project-id <ID>` | none | GCP project ID (required when `--secret-provider` includes `gcp`) |
| `--gcp-secret-prefix <PREFIX>` | `validator-key-` | Prefix for GCP secret names |
| `--secret-refresh-interval <SECS>` | `0` | Interval in seconds to refresh keys from secret providers (0 = disabled) |

#### Tracing Options (OpenTelemetry)

| Flag | Default | Description |
|------|---------|-------------|
| `--tracing-endpoint <URL>` | none | OTLP endpoint (enables tracing when set) |
| `--tracing-exporter <KIND>` | `otlp` | Exporter: `otlp` or `gcp` |
| `--tracing-sample-rate <FLOAT>` | `0.01` | Head-based sampling ratio (0.0–1.0) |
| `--tracing-max-queue-size <N>` | `2048` | Max spans queued for export |
| `--tracing-max-export-batch-size <N>` | `512` | Max spans per export batch |

#### Genesis Overrides (for custom networks)

| Flag | Description |
|------|-------------|
| `--genesis-time <UNIX_TS>` | Genesis time as Unix timestamp |
| `--genesis-validators-root <HEX>` | Genesis validators root (0x-prefixed hex) |

---

### `rvc voluntary-exit` - Submit a Voluntary Exit

```
rvc voluntary-exit [OPTIONS]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--pubkey <HEX>` | yes | - | Validator public key (hex, 0x optional) |
| `--keystore-path <PATH>` | yes | - | Keystore directory |
| `--password-file <PATH>` | yes | - | Password file |
| `--epoch <N>` | no | current | Exit epoch |
| `--confirm` | no | false | Skip confirmation prompt |
| `--beacon-url <URL>` | no | `http://localhost:5052` | Beacon node URL |
| `--slashing-db-path <PATH>` | no | none | Slashing DB path |
| `--network <NETWORK>` | no | none | Network preset |
| `--genesis-validators-root <HEX>` | no | none | Override genesis root |
| `--log-level <LEVEL>` | no | `info` | Log level |

Example:
```bash
rvc voluntary-exit \
  --pubkey 0xabcd1234... \
  --keystore-path ./keystores \
  --password-file ./passwords.txt \
  --confirm
```

## Configuration File

Create a TOML file (see `config.example.toml`):

```toml
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing_protection.sqlite"
metrics_port = 8080
grpc_port = 50051
network = "mainnet"
log_level = "info"

# Optional
# password_file = "./passwords.txt"
# graffiti = "rvc"
# doppelganger_detection = true

# Multi-BN failover
# beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]

# Keymanager API
# keymanager_enabled = true
# keymanager_address = "127.0.0.1:5062"
# keymanager_token_file = "./keymanager-api-token.txt"
# remote_signer_url = "https://web3signer:9000"

# Secret provider
# [secret_provider]
# provider = "gcp"
# gcp_project_id = "my-project"
# gcp_secret_prefix = "validator-key-"
# refresh_interval = 3600
```

CLI flags override config file values.

## Password File Format

```
# Comments start with #
# Format: pubkey=password (one per line, 0x prefix stripped automatically)
abcd1234=mypassword
0x5678efgh=anotherpassword
```

Set restrictive permissions: `chmod 600 passwords.txt`

## Supported Networks

| Network | Genesis Time | Genesis Validators Root |
|---------|-------------|------------------------|
| mainnet | 1606824023 | `0x4b363db9...` |
| sepolia | 1655733600 | `0xd8ea171f...` |
| holesky | 1695902400 | `0x9143aa7c...` |
| goerli | 1616508000 | `0x043db0d9...` |
| custom | must specify | must specify |

## Endpoints

### Metrics (default port 8080)

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | Health check |
| `/livez` | Kubernetes liveness |
| `/readyz` | Kubernetes readiness |

### gRPC (default port 50051)

DutyTracker service.

### Keymanager API (default port 5062, when enabled)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/eth/v1/keystores` | List local keystores |
| POST | `/eth/v1/keystores` | Import keystores |
| DELETE | `/eth/v1/keystores` | Delete keystores |
| GET | `/eth/v1/remotekeys` | List remote keys |
| POST | `/eth/v1/remotekeys` | Import remote keys |
| DELETE | `/eth/v1/remotekeys` | Delete remote keys |

Requires bearer token authentication.

## Startup Sequence

1. Initialize logging and telemetry (if `--tracing-endpoint` set)
2. Validate CLI timeouts (must be > 0)
3. Load config file (or defaults) and merge CLI overrides
4. Open slashing protection database
5. Run integrity check on slashing DB
6. Apply strict slashing semantics (if `--strict-slashing-semantics`)
7. Check file permissions (if `--strict-permissions`)
8. Create beacon client and BnManager (multi-BN layer)
9. Validate genesis root against beacon node
10. Check beacon reachability and log beacon node version
11. Load validator keys from keystores
12. Load keys from secret providers (if `--secret-provider` configured)
13. Start periodic key refresh (if `--secret-refresh-interval` > 0)
14. Run doppelganger detection (if enabled, ~2 epochs)
15. Build services (signer, propagator, duty tracker, builder)
16. Start Keymanager API server (if enabled)
17. Start duty orchestrator (slot-by-slot validation)
18. Start gRPC and metrics servers

## Environment Variables

```bash
# Override log filter (takes precedence over --log-level)
RUST_LOG=debug rvc start

# Per-crate filtering
RUST_LOG=rvc=trace,bn_manager=debug rvc start
```

## Shutdown

Send `SIGINT` (Ctrl+C) or `SIGTERM` for graceful shutdown. The client will:
1. Stop the duty orchestrator
2. Close beacon node connections
3. Persist slashing DB state
4. Shut down metrics and gRPC servers

## Example Configurations

### Single Beacon Node (Testnet)

```bash
rvc start \
  --beacon-url http://localhost:5052 \
  --keystore-path ./keystores \
  --password-file ./passwords.txt \
  --network holesky \
  --log-level debug
```

### Multi-BN Production Setup

```bash
rvc start -c config.prod.toml \
  --beacon-nodes http://bn1:5052,http://bn2:5052,http://bn3:5052 \
  --strict-permissions \
  --strict-slashing-semantics \
  --log-level info
```

### With Remote Signer (Web3Signer)

```bash
rvc start \
  --keymanager-enabled \
  --remote-signer-url https://web3signer:9000 \
  --keymanager-address 127.0.0.1:5062
```

### With GCP Secret Manager

```bash
# Requires building with --features gcp-secret
rvc start -c config.toml \
  --secret-provider gcp \
  --gcp-project-id my-gcp-project \
  --gcp-secret-prefix validator-key- \
  --secret-refresh-interval 3600
```

### With OpenTelemetry Tracing

```bash
rvc start -c config.toml \
  --tracing-endpoint http://localhost:4318 \
  --tracing-sample-rate 0.1
```

For GCP Cloud Trace (requires `--features gcp-trace`):

```bash
rvc start -c config.toml \
  --tracing-exporter gcp \
  --tracing-sample-rate 0.01
```
