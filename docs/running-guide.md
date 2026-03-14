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

Binary locations:
- Debug: `target/debug/rvc`, `target/debug/rvc-signer`
- Release: `target/release/rvc`, `target/release/rvc-signer`

To build with DVT support for `rvc-signer`:

```bash
cargo build --release -p rvc-signer --features dvt
```

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

#### gRPC Remote Signer Options

| Flag | Default | Description |
|------|---------|-------------|
| `--grpc-signer-url <URL>` | none | gRPC remote signer URL (e.g., `https://signer.example.com:50052`) |
| `--grpc-signer-tls-cert <PATH>` | none | Client TLS certificate for mTLS (required if URL set) |
| `--grpc-signer-tls-key <PATH>` | none | Client TLS private key for mTLS (required if URL set) |
| `--grpc-signer-tls-ca-cert <PATH>` | none | CA certificate for mTLS verification (required if URL set) |

All three TLS flags are required when `--grpc-signer-url` is set.

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

# gRPC remote signer (rvc-signer)
# grpc_signer_url = "https://signer.example.com:50052"
# grpc_signer_tls_cert = "./certs/client.pem"
# grpc_signer_tls_key = "./certs/client-key.pem"
# grpc_signer_tls_ca_cert = "./certs/ca.pem"
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
14. Connect gRPC remote signer (if `--grpc-signer-url` configured, lazy, non-fatal)
15. Run doppelganger detection (if enabled, ~2 epochs)
16. Build services (signer, propagator, duty tracker, builder)
17. Start Keymanager API server (if enabled)
18. Start duty orchestrator (slot-by-slot validation)
19. Start gRPC and metrics servers

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

### With gRPC Remote Signer (rvc-signer)

```bash
# Start rvc-signer first
rvc-signer serve \
  --keystore-dir ./signer-keystores \
  --password-dir ./signer-passwords \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --tls-ca-cert ./certs/ca.pem \
  --listen-address 0.0.0.0:50052

# Then start rvc pointing to the signer
rvc start -c config.toml \
  --grpc-signer-url https://signer.example.com:50052 \
  --grpc-signer-tls-cert ./certs/client.pem \
  --grpc-signer-tls-key ./certs/client-key.pem \
  --grpc-signer-tls-ca-cert ./certs/ca.pem
```

---

## `rvc-signer` — Remote BLS Signing Server

Standalone gRPC signing server for key isolation. Keeps validator keys on a dedicated machine while `rvc` handles duty orchestration and slashing protection.

### `rvc-signer serve` — Start the Signing Server

```
rvc-signer serve [OPTIONS]
```

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | none | TOML configuration file |
| `--listen-address <ADDR>` | `127.0.0.1:50052` | gRPC listen address |
| `--keystore-dir <PATH>` | none | Directory containing EIP-2335 keystore files |
| `--password-dir <PATH>` | none | Directory with per-keystore password files |
| `--password-file <PATH>` | none | Single password file for all keystores |
| `--tls-cert <PATH>` | none | Server TLS certificate (PEM) |
| `--tls-key <PATH>` | none | Server TLS private key (PEM) |
| `--tls-ca-cert <PATH>` | none | CA certificate for client authentication (PEM) |
| `--backend <TYPE>` | `basic` | Signing backend: `basic` or `dvt` (requires `dvt` feature) |
| `--metrics-address <ADDR>` | `127.0.0.1:9101` | Prometheus metrics listen address |
| `--reload-interval <SECS>` | `30` | Keystore hot-reload interval (0 to disable) |
| `--dry-run` | false | Validate configuration and exit |

#### DVT Options (requires `--features dvt`)

| Flag | Default | Description |
|------|---------|-------------|
| `--dvt-peers <ADDR,ADDR,...>` | none | Comma-separated DVT peer addresses |
| `--dvt-threshold <N>` | none | Threshold for signature reconstruction |
| `--dvt-index <N>` | none | This node's share index |
| `--dvt-timeout <MS>` | `2000` | Per-peer RPC timeout in milliseconds |

### `rvc-signer split-key` — Split Key into Shares (requires `--features dvt`)

Splits a BLS secret key into Shamir shares stored as EIP-2335 keystores.

```
rvc-signer split-key [OPTIONS]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--keystore <PATH>` | yes | Source EIP-2335 keystore |
| `--password <STRING>` | no | Source keystore password |
| `--password-file <PATH>` | no | Source keystore password file |
| `--threshold <N>` | yes | Threshold (t) for Shamir secret sharing |
| `--shares <N>` | yes | Total number of shares (n) to generate |
| `--output-dir <PATH>` | yes | Output directory for share keystores |
| `--output-password <STRING>` | no | Password for output share keystores |
| `--output-password-file <PATH>` | no | Password file for output share keystores |

Example:

```bash
# Split a key into 3 shares with threshold of 2
rvc-signer split-key \
  --keystore ./validator.json \
  --password-file ./password.txt \
  --threshold 2 \
  --shares 3 \
  --output-dir ./shares \
  --output-password-file ./share-password.txt
```

### DVT Multi-Node Setup

```bash
# Node 1
rvc-signer serve \
  --backend dvt \
  --keystore-dir ./shares/node1 \
  --password-dir ./passwords \
  --tls-cert ./certs/node1.pem \
  --tls-key ./certs/node1-key.pem \
  --tls-ca-cert ./certs/ca.pem \
  --listen-address 0.0.0.0:50052 \
  --dvt-peers node2:50052,node3:50052 \
  --dvt-threshold 2 \
  --dvt-index 0

# Node 2 and Node 3 similar with their own shares and index
```

### gRPC Services

| Service | RPC | Description |
|---------|-----|-------------|
| `SignerService` | `Sign` | Produce BLS signature over a 32-byte signing root |
| `SignerService` | `ListPublicKeys` | List all available public keys |
| `SignerService` | `GetStatus` | Check readiness, backend type, key count |
| `PeerSignerService` | `PartialSign` | DVT partial signature for threshold signing |
