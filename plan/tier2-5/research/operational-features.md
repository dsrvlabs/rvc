# Operational Features Research

Research findings on operational features from other Ethereum validator client implementations, to inform rvc design decisions.

---

## 1. Lighthouse Proposer Nodes (`--proposer-nodes`)

### Overview

Lighthouse provides a dedicated proposer-node architecture that separates block proposal infrastructure from regular attestation duties. This is a security-focused design: by reducing the network footprint of block-producing nodes, it makes them harder for attackers to identify and target.

### Beacon Node Side: `--proposer-only`

The `--proposer-only` flag on a **beacon node** restricts its functionality:

- **Prevents** the node from subscribing to attestation subnets or sync committees
- **Reduces** resource consumption (CPU, bandwidth, memory)
- **Reduces** the attack surface -- subnet subscriptions are the primary way attackers de-anonymize validators
- The node can still produce blocks and propagate them to the network

**Critical constraint:** A proposer-only beacon node must NOT be connected to a validator client via the normal `--beacon-nodes` flag. Doing so causes the validator to fail duties (missed attestations, sync committee failures) because the node lacks subnet subscriptions.

### Validator Client Side: `--proposer-nodes`

The `--proposer-nodes` flag on the **validator client** accepts a comma-separated list of HTTP API endpoints:

```
lighthouse vc \
  --beacon-nodes http://bn1:5052,http://bn2:5052 \
  --proposer-nodes http://proposer-bn:5052
```

**Key behaviors:**

1. The VC still **requires** at least one normal beacon node in `--beacon-nodes` for attestation duties
2. Block proposal flow:
   - VC first requests a block from `--beacon-nodes` (higher chance of profitable block due to subnet subscriptions)
   - Then sends the signed block to `--proposer-nodes` for propagation
   - If `--proposer-nodes` fail, falls back to `--beacon-nodes`
3. Block builders (MEV) should be attached to `--beacon-nodes`, NOT `--proposer-nodes`

### Health Tracking

Proposer nodes share the same health-tracking infrastructure as regular beacon nodes:

- Every slot, the VC checks each connected beacon node to determine which is "Healthiest"
- Sync distance is classified into 4 tiers: **Synced**, **Small**, **Medium**, **Large**
- Nodes are sorted by tier, with user-specified ordering as a tiebreaker
- Health information is available via the `/lighthouse/beacon/health` API endpoint
- When a beacon node fails, it is flagged as offline and not retried for the rest of the slot (~12 seconds)

### Fallback Behavior

- If all `--proposer-nodes` fail during block publication, the VC reverts to standard `--beacon-nodes`
- The help text states: "A failure will revert back to the standard beacon nodes specified in --beacon-nodes"
- Proposer nodes do NOT replace regular beacon nodes; they supplement them

### Recommended Architecture

- Use **separate IP addresses** for proposer-only nodes vs. regular nodes
- **Rotate** proposer-only node IPs occasionally (ideally per block proposal) for enhanced anonymity
- Run proposer-only nodes on infrastructure distinct from your regular BNs

### Gotchas

- Connecting a proposer-only BN as a normal `--beacon-nodes` entry causes attestation failures and income loss
- Proposer-only nodes produce **less profitable blocks** (no subnet gossip = fewer transactions observed) -- this is why the VC fetches blocks from normal BNs first
- Block builders must go on `--beacon-nodes`, not `--proposer-nodes`
- Prior to v4.6.0, fallback BNs did not receive proposer preparation or validator registration messages, which could result in blocks with 0 transactions on failover

**Sources:**
- [Proposer Only Beacon Nodes - Lighthouse Book](https://lighthouse-book.sigmaprime.io/advanced_proposer_only.html)
- [Redundancy - Lighthouse Book](https://lighthouse-book.sigmaprime.io/advanced_redundancy.html)
- [Lighthouse VC CLI - cli.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/cli.rs)

---

## 2. Lighthouse Broadcast Flag (`--broadcast`)

### Overview

The `--broadcast` flag controls which beacon API message types are sent to **all** connected beacon nodes, versus the default "first available" strategy. Introduced as a replacement for the deprecated `--disable-run-on-all` flag.

### Valid Topics

| Topic | Description | Recommendation |
|-------|-------------|----------------|
| `subscriptions` | Subnet subscriptions and control messages that keep BNs primed and ready | **Keep enabled** (default) |
| `attestations` | Attestation messages | Improves propagation but increases BN load |
| `blocks` | Block proposals | Recommended first addition for multi-BN setups |
| `sync-committee` | Sync committee signatures and aggregates | Similar tradeoffs to attestations, less frequent |
| `none` | Disable all broadcasting | Only has effect when provided alone; not recommended |

### Default Behavior

```
--broadcast subscriptions
```

When the flag is **omitted**, only `subscriptions` are broadcast to all beacon nodes. All other message types use the "first available" (single-node) strategy.

### How It Works

**Without broadcast (single-node strategy):**
1. VC iterates through beacon nodes in order
2. Selects the first "healthy" node (based on sync distance tier + user ordering)
3. Sends the message to only that node
4. If it fails, tries the next node

**With broadcast (broadcast strategy):**
1. VC sends the message to **all** connected beacon nodes simultaneously
2. If some nodes fail, the message still reaches the network via other nodes
3. Increases redundancy at the cost of higher bandwidth and BN load

### Configuration Examples

```bash
# Default: broadcast only subscriptions
lighthouse vc --beacon-nodes http://bn1:5052,http://bn2:5052

# Broadcast subscriptions + blocks (recommended for multi-BN)
lighthouse vc --beacon-nodes http://bn1:5052,http://bn2:5052 \
  --broadcast subscriptions,blocks

# Broadcast everything
lighthouse vc --beacon-nodes http://bn1:5052,http://bn2:5052 \
  --broadcast subscriptions,attestations,blocks,sync-committee

# Expert mode: disable all broadcasting
lighthouse vc --beacon-nodes http://bn1:5052,http://bn2:5052 \
  --broadcast none
```

### Sync Tolerance Integration

The `--beacon-nodes-sync-tolerances` flag (default: `8,8,48`) configures the tier boundaries:

- **Synced**: sync distance 0-8 slots
- **Small**: sync distance 9-16 slots
- **Medium**: sync distance 17-64 slots
- **Large**: sync distance > 64 slots

Nodes in higher tiers are deprioritized. Within the same tier, user-specified ordering is used as a tiebreaker.

### Gotchas

- `none` is only effective when specified **alone**; if combined with other topics, it is ignored
- Broadcasting `attestations` can significantly increase BN load on large validator setups
- The flag value is parsed as a `Vec<ApiTopic>` with comma delimiter
- Broadcasting blocks is the most impactful improvement for multi-BN setups

**Sources:**
- [Validator Client CLI - Lighthouse Book](https://lighthouse-book.sigmaprime.io/help_vc.html)
- [Redundancy - Lighthouse Book](https://lighthouse-book.sigmaprime.io/advanced_redundancy.html)
- [Lighthouse v4.6.0 Release Notes](https://github.com/sigp/lighthouse/releases/tag/v4.6.0)

---

## 3. beaconcha.in Monitoring Endpoint Protocol

### Overview

beaconcha.in provides a push-based monitoring service where consensus clients periodically POST JSON metrics to a remote endpoint. The specification is maintained in the [gobitfly/eth2-client-metrics](https://github.com/gobitfly/eth2-client-metrics) repository.

### Endpoint URL

```
POST https://beaconcha.in/api/v1/client/metrics?apikey=<YOUR_API_KEY>&machine=<MACHINE_NAME>
```

- **Method:** POST
- **Content-Type:** application/json
- **API Key:** Found in beaconcha.in account settings at `https://beaconcha.in/user/settings#app`
- **Machine parameter:** Optional but recommended for multi-node setups

### Push Interval

- **Default:** Every **60 seconds** (once per minute)
- Configurable per client (e.g., Lodestar `--monitoring.interval` in milliseconds, Teku `--metrics-publish-interval` in seconds)

### Payload Format

The payload is a JSON object (or array of objects for batch submission). **Specification version:** 1

#### Universal Required Fields (all process types)

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Always `1` |
| `timestamp` | long | Unix timestamp in milliseconds |
| `process` | string | One of: `validator`, `beaconnode`, `system` |

#### Process-General Fields (for `beaconnode` and `validator` processes)

| Field | Type | Description |
|-------|------|-------------|
| `cpu_process_seconds_total` | long | Total CPU seconds consumed by process |
| `memory_process_bytes` | long | Memory usage in bytes |
| `client_name` | string | One of: `prysm`, `lighthouse`, `nimbus`, `teku`, `lodestar` |
| `client_version` | string | Version string (e.g., `"1.1.2"`) |
| `client_build` | int | Incrementing build number for comparison |
| `sync_eth2_fallback_configured` | bool | Whether a fallback BN is configured |
| `sync_eth2_fallback_connected` | bool | Whether currently connected to fallback |

#### Beacon Node-Specific Fields

| Field | Type | Description |
|-------|------|-------------|
| `disk_beaconchain_bytes_total` | long | Beacon chain disk usage |
| `network_libp2p_bytes_total_receive` | long | Total bytes received via libp2p |
| `network_libp2p_bytes_total_transmit` | long | Total bytes transmitted via libp2p |
| `network_peers_connected` | int | Number of connected peers |
| `sync_eth1_connected` | bool | Connected to execution layer |
| `sync_eth2_synced` | bool | Whether beacon node is synced |
| `sync_beacon_head_slot` | long | Current head slot |
| `sync_eth1_fallback_configured` | bool | EL fallback configured |
| `sync_eth1_fallback_connected` | bool | EL fallback connected |
| `slasher_active` | bool | Whether slasher is running |

#### Validator-Specific Fields

| Field | Type | Description |
|-------|------|-------------|
| `validator_total` | int | Total number of validators managed |
| `validator_active` | int | Number of active validators |

#### System-Specific Fields

| Field | Type | Description |
|-------|------|-------------|
| `cpu_cores` | int | Number of CPU cores |
| `cpu_threads` | int | Number of CPU threads |
| `cpu_node_system_seconds_total` | long | Total system CPU seconds |
| `cpu_node_user_seconds_total` | long | Total user CPU seconds |
| `cpu_node_iowait_seconds_total` | long | Total IO wait CPU seconds |
| `cpu_node_idle_seconds_total` | long | Total idle CPU seconds |
| `memory_node_bytes_total` | long | Total system memory |
| `memory_node_bytes_free` | long | Free system memory |
| `memory_node_bytes_cached` | long | Cached memory |
| `memory_node_bytes_buffered` | long | Buffered memory |
| `disk_node_bytes_total` | long | Total disk space |
| `disk_node_bytes_free` | long | Free disk space |
| `disk_node_io_seconds` | long | Disk IO seconds |
| `disk_node_reads_total` | long | Total disk reads |
| `disk_node_writes_total` | long | Total disk writes |
| `network_node_bytes_total_receive` | long | Total network bytes received |
| `network_node_bytes_total_transmit` | long | Total network bytes transmitted |
| `misc_node_boot_ts_seconds` | long | System boot timestamp |
| `misc_os` | string | Operating system identifier |

### Example Payloads

**Validator process:**
```json
{
  "version": 1,
  "timestamp": 1704067200000,
  "process": "validator",
  "cpu_process_seconds_total": 1234567,
  "memory_process_bytes": 654321,
  "client_name": "lighthouse",
  "client_version": "1.1.2",
  "client_build": 12,
  "sync_eth2_fallback_configured": false,
  "sync_eth2_fallback_connected": false,
  "validator_total": 3,
  "validator_active": 2
}
```

**Batch submission** (array of objects):
```json
[
  { "version": 1, "timestamp": 1704067200000, "process": "system", "..." : "..." },
  { "version": 1, "timestamp": 1704067200000, "process": "beaconnode", "..." : "..." },
  { "version": 1, "timestamp": 1704067200000, "process": "validator", "..." : "..." }
]
```

### Client Support

| Client | Version | Notes |
|--------|---------|-------|
| Lighthouse | v1.4.0+ | Best support; flag: `--monitoring-endpoint` |
| Lodestar | v1.6.0+ | Flag: `--monitoring.endpoint` |
| Teku | v22.3.0+ | Flag: `--metrics-publish-endpoint` |
| Nimbus | v1.4.1+ | Partial support (validator metrics unavailable) |
| Prysm | v1.3.10+ | Alpha; requires separate exporter binary |

### Security Considerations

- Always use **HTTPS** to prevent traffic interception
- The service can associate your validators, IP address, and other personal information
- beaconcha.in states IP addresses are never stored
- Only use monitoring services you trust

### Gotchas

- Prysm requires a separate `eth2-client-metrics-exporter` binary rather than native integration
- Nimbus does not expose all metrics (validator data is unavailable in the mobile app)
- Data may take a few minutes to appear in the mobile app after initial configuration
- Linux-only support (no Windows)

**Sources:**
- [gobitfly/eth2-client-metrics (specification)](https://github.com/gobitfly/eth2-client-metrics)
- [beaconcha.in Mobile App Monitoring](https://docs.beaconcha.in/notifications-monitoring/mobile-app-beacon-node)
- [gobitfly/eth2-client-metrics-exporter](https://github.com/gobitfly/eth2-client-metrics-exporter)

---

## 4. Lodestar Monitoring Endpoint Implementation

### Overview

Lodestar (TypeScript/Zig Ethereum consensus client by ChainSafe) implements the beaconcha.in client monitoring protocol natively in both its beacon node and validator client.

### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--monitoring.endpoint` | (none) | Remote service URL to push metrics to |
| `--monitoring.interval` | `60000` (ms) | Interval between metric pushes in milliseconds |

### Usage

```bash
# Beacon node
lodestar beacon \
  --monitoring.endpoint "https://beaconcha.in/api/v1/client/metrics?apikey={apikey}&machine={machineName}"

# Validator client
lodestar validator \
  --monitoring.endpoint "https://beaconcha.in/api/v1/client/metrics?apikey={apikey}&machine={machineName}"
```

### Implementation Details

1. **Collection:** Lodestar collects client statistics (CPU, memory, sync status, peer count, validator count, etc.) matching the eth2-client-metrics specification
2. **Push mechanism:** Periodically POSTs collected metrics as JSON to the configured endpoint
3. **Interval:** Default 60 seconds (60000ms); configurable via `--monitoring.interval`
4. **Machine name:** Optional `machine` query parameter for distinguishing multiple nodes
5. **Debugging:** Use `--logLevel debug` to inspect the exact data being transmitted
6. **Both processes:** The beacon node pushes `process: "beaconnode"` and `process: "system"` data, while the validator client pushes `process: "validator"` data

### Rate Limiting Consideration

When monitoring multiple nodes, increase the interval to avoid rate limiting. For example, `--monitoring.interval 300000` (5 minutes) is suggested in the documentation for multi-node setups.

### Implementation Architecture

- Both the beacon node and validator client have independent monitoring services
- Each pushes its own process-type data (`beaconnode` or `validator`)
- System metrics (`process: "system"`) can be sent by either process
- The monitoring service runs as a background task within the client
- Follows the [gobitfly/eth2-client-metrics](https://github.com/gobitfly/eth2-client-metrics) specification (version 1)

### Gotchas

- The `--monitoring.interval` accepts **milliseconds**, not seconds (unlike Teku which uses seconds)
- The `machine` query parameter is optional but strongly recommended for multi-node setups
- Available since Lodestar v1.6.0
- Security: the monitoring endpoint should use HTTPS and only be pointed at trusted services

**Sources:**
- [Lodestar Client Monitoring Documentation](https://chainsafe.github.io/lodestar/run/logging-and-metrics/client-monitoring/)
- [Lodestar Validator CLI](https://chainsafe.github.io/lodestar/run/validator-management/validator-cli/)
- [Lodestar Beacon CLI](https://chainsafe.github.io/lodestar/run/beacon-management/beacon-cli/)

---

## 5. `tracing-appender` and Log Rotation in Rust

### `tracing-appender` (Official, by tokio-rs)

**Crate:** [tracing-appender](https://crates.io/crates/tracing-appender)

#### Capabilities

| Feature | Supported | Notes |
|---------|-----------|-------|
| Time-based rotation | Yes | MINUTELY, HOURLY, DAILY, WEEKLY, NEVER |
| Size-based rotation | **No** | Open PR #2497, not yet merged |
| Max log files | Yes | Via `Builder::max_log_files(n)` |
| Gzip compression | **No** | Not planned |
| Non-blocking writes | Yes | Via `tracing_appender::non_blocking()` |

#### Builder API

```rust
use tracing_appender::rolling::{RollingFileAppender, Rotation};

let appender = RollingFileAppender::builder()
    .rotation(Rotation::DAILY)           // MINUTELY, HOURLY, DAILY, WEEKLY, NEVER
    .filename_prefix("myapp.log")        // Optional prefix before timestamp
    .filename_suffix("log")              // Optional suffix after timestamp
    .max_log_files(5)                    // Keep only 5 most recent files
    .build("/var/log/myapp")
    .expect("failed to initialize appender");

// Wrap with non-blocking for async performance
let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
```

#### File Naming

- With prefix `"app"` and daily rotation: `app.2024-01-15`
- With prefix `"app"` and suffix `"log"`: `app.2024-01-15.log`
- `max_log_files` deletes files matching the prefix/suffix pattern when count exceeds N

#### Defaults

- `rotation`: `Rotation::NEVER` (no rotation)
- `filename_prefix`: empty string
- `filename_suffix`: empty string
- `max_log_files`: None (no limit, files accumulate indefinitely)

#### Limitations

- **No size-based rotation** -- there is an open feature request ([Issue #1940](https://github.com/tokio-rs/tracing/issues/1940)) and an active but unmerged PR ([#2497](https://github.com/tokio-rs/tracing/pull/2497))
- **No compression** -- not in scope for the official crate
- **No retention by age** -- only retention by count (`max_log_files`)
- Weekly rotation always occurs on Sunday at midnight UTC
- Passing `max_log_files(0)` **prevents** automatic deletion (does NOT mean "keep zero files")

### Alternatives for Size-Based Rotation

#### `rolling-file` / `tracing-rolling-file`

**Crate:** [tracing-rolling-file](https://crates.io/crates/tracing-rolling-file) (v0.1.3)

| Feature | Supported |
|---------|-----------|
| Time-based rotation | Yes (daily, hourly, minutely) |
| Size-based rotation | **Yes** |
| Max log files | **Yes** (`max_filecount`) |
| Compression | No |

```rust
use tracing_rolling_file::RollingFileAppenderBase;
use tracing_rolling_file::RollingConditionBase;

let appender = tracing_rolling_file::RollingFileAppenderBase::new(
    "/var/log/myapp/app.log",
    RollingConditionBase::new()
        .daily()
        .max_size(100 * 1024 * 1024),  // 100 MB
    10,  // max_filecount: keep 10 files
)?;
```

File naming: Debian-style `basename`, `basename.1`, ..., `basename.N`.

#### `logroller`

**Crate:** [logroller](https://crates.io/crates/logroller) (v0.1.10)

| Feature | Supported |
|---------|-----------|
| Time-based rotation | Yes (minutely, hourly, daily) |
| Size-based rotation | **Yes** |
| Max log files | **Yes** (`max_keep_files`) |
| Gzip compression | **Yes** |
| XZ compression | **Yes** (feature-gated) |
| Timezone support | Yes (Local or Fixed) |

```rust
use logroller::LogRollerBuilder;

let roller = LogRollerBuilder::new()
    .directory("/var/log/myapp")
    .filename("app")
    .rotation_size(logroller::RotationSize::MB(100))
    .max_keep_files(10)
    .compression(logroller::Compression::Gzip)
    .build()?;

// Integrate with tracing
let (non_blocking, _guard) = tracing_appender::non_blocking(roller);
```

### Comparison Table

| Crate | Size Rotation | Time Rotation | Max Files | Compression | tracing Integration |
|-------|:---:|:---:|:---:|:---:|:---:|
| `tracing-appender` | No | Yes | Yes | No | Native |
| `tracing-rolling-file` | Yes | Yes | Yes | No | Via non_blocking |
| `logroller` | Yes | Yes | Yes | Gzip/XZ | Via non_blocking |

### Recommendation for rvc

- **If time-based rotation suffices:** Use `tracing-appender` (official, well-maintained, part of the tokio ecosystem)
- **If size-based rotation is needed:** Use `logroller` (most feature-complete: size rotation + gzip compression + tracing integration)
- **If size-based rotation without compression:** Use `tracing-rolling-file` (simpler, lighter dependency)

**Sources:**
- [tracing-appender docs](https://docs.rs/tracing-appender/latest/tracing_appender/)
- [tracing-appender Builder](https://docs.rs/tracing-appender/latest/tracing_appender/rolling/struct.Builder.html)
- [Issue #1940: Size-based rotation request](https://github.com/tokio-rs/tracing/issues/1940)
- [logroller docs](https://docs.rs/logroller/latest/logroller/)
- [tracing-rolling-file docs](https://docs.rs/tracing-rolling-file/)
- [rolling-file docs](https://docs.rs/rolling-file/)

---

## 6. Prysm/Teku Proposer Config from URL

### Prysm (`--proposer-settings-url`)

#### Configuration Flags

| Flag | Description |
|------|-------------|
| `--proposer-settings-file` | Local file path to JSON/YAML proposer config |
| `--proposer-settings-url` | Remote URL endpoint returning JSON proposer config |
| `--suggested-fee-recipient` | Default fee recipient (overridden by proposer settings) |
| `--enable-builder` | Enable MEV builder registration (overridden by proposer settings) |
| `--suggested-gas-limit` | Default gas limit (default: `30000000`) |

#### JSON Schema

```json
{
  "proposer_config": {
    "0x98765...": {
      "fee_recipient": "0xabcd...",
      "builder": {
        "enabled": true,
        "gas_limit": "30000000",
        "relays": ["https://relay1.example.com", "https://relay2.example.com"]
      }
    }
  },
  "default_config": {
    "fee_recipient": "0x1234...",
    "builder": {
      "enabled": true,
      "gas_limit": "30000000"
    }
  }
}
```

#### Internal Go Types

```go
type Settings struct {
    ProposeConfig map[[48]byte]*Option  // BLS pubkey -> per-validator config
    DefaultConfig *Option               // Fallback for unmapped validators
}

type Option struct {
    FeeRecipientConfig *FeeRecipientConfig
    BuilderConfig      *BuilderConfig
    GraffitiConfig     *GraffitiConfig
}

type BuilderConfig struct {
    Enabled  bool     `json:"enabled" yaml:"enabled"`
    GasLimit uint64   `json:"gas_limit,omitempty" yaml:"gas_limit,omitempty"`
    Relays   []string `json:"relays,omitempty" yaml:"relays,omitempty"`
}

type FeeRecipientConfig struct {
    FeeRecipient common.Address
}

type GraffitiConfig struct {
    Graffiti string
}
```

#### URL Fetch Behavior

- **HTTP Method:** GET
- **Expected Content-Type:** `application/json`
- **Refresh:** Settings are loaded **once at startup** only
- **No automatic periodic refresh** -- the `--proposer-settings-url` does NOT support hot-reloading
- This was explicitly discussed in [Issue #11378](https://github.com/prysmaticlabs/prysm/issues/11378) and closed as "COMPLETED" with the recommendation to use the **Keymanager API** for runtime updates instead of file/URL polling

#### Failure Handling

- If the URL fetch fails at startup, the validator client fails to start
- There is no retry mechanism for URL-based settings
- Runtime changes should go through the Keymanager API, which persists to the validator database

#### Loading Architecture

The `SettingsLoader` struct handles configuration loading:
1. Creates a `SettingsLoader` via `NewProposerSettingsLoader(cliCtx, db, opts...)`
2. Options pattern: `WithBuilderConfig()` and `WithGasLimit()` for CLI flag integration
3. The `Load()` method resolves settings and persists them to the validator database
4. Priority: proposer-settings-file/url > CLI flags (`--enable-builder`, `--suggested-fee-recipient`)

#### Gotchas

- Validator public keys must be full 98-character hex strings (with `0x` prefix), NOT wallet addresses
- `--proposer-settings-file` and `--proposer-settings-url` replaced the deprecated `--fee-recipient-config-file` and `--fee-recipient-config-url` as of v2.1.3
- JSON must be returned as a payload (not served as a file download)
- No periodic refresh -- use Keymanager API for runtime changes

---

### Teku (`--validators-proposer-config`)

#### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--validators-proposer-config` | (none) | URL or local file path to proposer config |
| `--validators-proposer-config-refresh-enabled` | `false` | Enable periodic reload of proposer config |

Environment variables: `TEKU_VALIDATORS_PROPOSER_CONFIG`, `TEKU_VALIDATORS_PROPOSER_CONFIG_REFRESH_ENABLED`

#### JSON Schema

```json
{
  "proposer_config": {
    "0x98765...": {
      "fee_recipient": "0xabcd...",
      "builder": {
        "enabled": true,
        "gas_limit": "36000000"
      }
    }
  },
  "default_config": {
    "fee_recipient": "0x1234...",
    "builder": {
      "enabled": true,
      "gas_limit": "36000000"
    }
  }
}
```

Note: Teku's default `gas_limit` is `36000000` (36M), whereas Prysm uses `30000000` (30M).

#### Builder Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fee_recipient` | string | Required in `default_config`, optional in `proposer_config` | Ethereum address for priority fees |
| `builder.enabled` | bool | Required in `default_config` | Whether to use builder endpoint |
| `builder.gas_limit` | string | Optional | Gas limit (default: `"36000000"`) |
| `builder.registration_overrides` | object | Optional | DVT/SSV overrides with `timestamp` and `public_key` |

#### Auto-Refresh Behavior

When `--validators-proposer-config-refresh-enabled=true`:

1. **Refresh interval:** Once per **epoch** (~6.4 minutes), triggered at the beginning of each epoch when the validator client calls `prepare_beacon_proposer`
2. **Refresh scope:** Reloads the entire proposer config from the URL or file
3. **On refresh failure:** The **last valid configuration** continues to be used (graceful degradation)
4. **Supports both:** Local file paths AND remote URLs

#### Priority Resolution

Configuration values are resolved in this order (highest to lowest):

1. Specific `proposer_config` entry for the validator public key
2. `default_config` values
3. CLI argument defaults (`builder.enabled` only)
4. Built-in defaults

#### Failure Handling

- If initial config load fails at startup, Teku fails to start
- If a refresh fails (with `--validators-proposer-config-refresh-enabled=true`), the last valid config is retained
- No exponential backoff or retry logic documented -- simply retries at next epoch

#### Gotchas

- `--validators-proposer-config-refresh-enabled` defaults to `false` -- must be explicitly enabled
- Refresh happens once per epoch (~6.4 minutes), not configurable to a different interval
- The `registration_overrides` field is specific to DVT/SSV setups

---

### Comparison: Prysm vs Teku Proposer Config

| Feature | Prysm | Teku |
|---------|-------|------|
| Local file | `--proposer-settings-file` | `--validators-proposer-config` |
| Remote URL | `--proposer-settings-url` | `--validators-proposer-config` (same flag) |
| Auto-refresh | **No** (one-time load at startup) | **Yes** (once per epoch, ~6.4 min) |
| Refresh toggle | N/A | `--validators-proposer-config-refresh-enabled` |
| Failure on refresh | N/A (no refresh) | Uses last valid config |
| Runtime updates | Keymanager API only | Config file/URL refresh or API |
| Default gas limit | 30,000,000 | 36,000,000 |
| Graffiti in config | Yes (`GraffitiConfig`) | No |
| Relay list in config | Yes (`relays` field) | No |
| Config format | JSON or YAML | JSON |

**Sources:**
- [Prysm Fee Recipient Docs](https://prysm.offchainlabs.com/docs/configure-prysm/fee-recipient/)
- [Prysm proposer package (Go docs)](https://pkg.go.dev/github.com/OffchainLabs/prysm/v7/config/proposer)
- [Prysm loader package (Go docs)](https://pkg.go.dev/github.com/OffchainLabs/prysm/v7/config/proposer/loader)
- [Prysm Issue #11378: Proposer settings refresh](https://github.com/prysmaticlabs/prysm/issues/11378)
- [Teku Proposer Config Docs](https://docs.teku.consensys.io/how-to/configure/use-proposer-config-file)
- [Teku CLI Reference](https://docs.teku.consensys.io/reference/cli)
