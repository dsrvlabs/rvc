# RVC Architecture (ASCII)

ASCII-only companion to [ARCHITECTURE.md](../ARCHITECTURE.md). Same system, rendered without Mermaid so it reads in any terminal or plain-text viewer.

RVC is a Rust-based Ethereum Validator Client organized as a Cargo workspace of **3 binaries + 20 library crates** in four layers: **Binary → Orchestrator → Domain → Foundation**. Dependencies flow downward only.

---

## 1. System Overview

```
                       +--------------------------------------+
                       |              External                |
                       +--------------------------------------+
                       | Beacon Nodes (N)    Web3Signer       |
                       | EIP-2335 Keystores  GCP Secret Mgr   |
                       | SQLite Slashing DB  Prometheus       |
                       | OTel Collector                       |
                       +------+-------+------+-------+---+----+
                              ^       ^      ^       ^   ^
                   HTTP REST  |       | HTTP |  load |   | OTLP
                   + SSE      |       | sign | keys  |   | /HTTP
                              |       |      |       |   |
+-----------------------------+-------+------+-------+---+-----------------+
|                        RVC Validator Client (bin/rvc)                    |
|                                                                          |
|  +--------------+     +---------------------+     +------------------+   |
|  | CLI/Bootstrap|====>|  DutyOrchestrator   |<===>|   BnManager      |   |
|  | main.rs      |     |  (3-phase slot loop)|     |  (multi-BN HA)   |   |
|  +------+-------+     +----+-----------+----+     +---------+--------+   |
|         |                  |           |                    |            |
|         v                  v           v                    v            |
|  +-------------+   +--------------+  +----------+   +-----------------+  |
|  | Keymanager  |   | Block / Sync |  | Signer   |   | DutyTracker     |  |
|  | API :5062   |   | Services     |  | Service  |   | Propagator      |  |
|  +-------------+   +--------------+  +----+-----+   +-----------------+  |
|                                           |                              |
|                                           v                              |
|                                 +-------------------+                    |
|                                 |  CompositeSigner  |                    |
|                                 | local|dyn|remote  |                    |
|                                 +----+--------+-----+                    |
|                                      |        |                          |
|                           local BLS  |        | gRPC mTLS                |
|                           (blst)     |        v                          |
|                                      |   +---------------------+         |
|                                      |   | bin/rvc-signer      |<=======>| (DVT peers)
|                                      |   | gRPC Signing Server |         |
|                                      |   +---------------------+         |
|  +---------------+   +----------------+   +---------------------+        |
|  | Metrics :8080 |   | Telemetry OTel |   |  Slashing DB (rusq) |        |
|  +---------------+   +----------------+   +---------------------+        |
+--------------------------------------------------------------------------+

+--------------------------------------+      +-------------------------+
|  bin/rvc-keygen  (offline tool)      |      |  Config (TOML + CLI)    |
|  mnemonic, keys, deposits, exits,    |      |  config.toml / flags    |
|  BLS-to-execution changes            |      +-------------------------+
+--------------------------------------+
```

Legend
- `==>` control/build dependency (startup wiring)
- `<=>` bidirectional runtime traffic
- `-->` unidirectional runtime traffic

---

## 2. Layered Crate View

```
+---------------------------------------------------------------------------+
|  Layer 1  BINARY  (entry points; parse args, bootstrap services)          |
+---------------------------------------------------------------------------+
|  bin/rvc          bin/rvc-keygen          bin/rvc-signer                  |
+---------------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------------+
|  Layer 2  ORCHESTRATOR  (the only crate that depends on every domain)     |
+---------------------------------------------------------------------------+
|              crates/rvc  (DutyOrchestrator, 3-phase slot loop)            |
+---------------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------------+
|  Layer 3  DOMAIN  (duty-specific logic; no I/O details)                   |
+---------------------------------------------------------------------------+
|  signer       duty-tracker    propagator    timing                        |
|  block-service   sync-service   builder     doppelganger                  |
+---------------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------------+
|  Layer 4  FOUNDATION  (infrastructure; no domain logic)                   |
+---------------------------------------------------------------------------+
|  crypto      slashing     bn-manager    beacon      metrics               |
|  eth-types   keymanager-api  telemetry  validator-store                   |
|  secret-provider   grpc-signer                                            |
+---------------------------------------------------------------------------+

Rule: edges only point downward. No layer imports upward.
```

---

## 3. Crate Dependency Graph

```
                             +------------+
                             |  bin/rvc   |
                             +-----+------+
           +-------+-------+-------+------+-------+----------+
           |       |       |       |      |       |          |
           v       v       v       v      v       v          v
        rvc*    bn-mgr  crypto  slashing metrics keymanager  telemetry
                  |       |        |                           ^
  (*) orchestrator        |        |                           |
                          |        |                           |
 bin/rvc-keygen ----------+        |                           |
 bin/rvc-signer ----------+        |                           |
                          |        |                           |
                          v        |                           |
                       eth-types <-+                           |
                          ^                                    |
   +----------------------+------------------------------------+
   |                                                           |
   |       +-----------+        +--------------+               |
   +-------+  rvc      +------->+  signer      +---+           |
           | (orch)    |        |  (safe sign) |   |           |
           +-----+-----+        +------+-------+   |           |
                 |                     |           v           |
                 | uses                |        slashing       |
                 v                     v                       |
           +-------------+      +-----------+                  |
           | duty-tracker|      |  crypto   |                  |
           +------+------+      +-----+-----+                  |
                  |                   |                        |
                  v                   v                        |
               bn-manager ----->  eth-types                    |
                  |                                            |
                  v                                            |
                beacon (HTTP client)                           |
                                                               |
           +-------------+    +--------------+                 |
           | block-svc   |    | sync-service |                 |
           +---+----+----+    +------+-------+                 |
               |    |                |                         |
               v    v                v                         |
            crypto signer        eth-types                     |
            vstore eth-types                                   |
                                                               |
           +-------------+    +--------------+                 |
           |  builder    |    | doppelganger |                 |
           +---+---+-----+    +------+-------+                 |
               |   |                 |                         |
               v   v                 v                         |
            bn-mgr signer         eth-types                    |
            crypto vstore                                      |
            eth-types                                          |
                                                               |
           +----------------+      +-----------------+         |
           | secret-provider|      | grpc-signer     |         |
           +--------+-------+      +--------+--------+         |
                    |                       |                  |
                    v                       v                  |
                 crypto                   crypto               |
                 metrics                                       |
                                                               |
           +------------+                                      |
           | propagator +------> bn-manager, metrics           |
           +------------+                                      |
                                                               |
           +------------+                                      |
           | timing     +------> eth-types                     |
           +------------+                                      |
                                                               |
           +-------------------+                               |
           |  telemetry  ----- (imported by bin/rvc; OTel layer)
           +-------------------+
```

---

## 4. 3-Phase Slot Processing

```
                           SLOT = 12 s
      0 s ........................ 4 s ........................ 8 s ........ 12 s
      |                              |                            |           |
      |  PHASE 1: PROPOSAL           |  PHASE 2: ATTEST + SYNC    |  PHASE 3  |
      |  t = 0                       |  t = slot/3                |  t = 2s/3 |
      |                              |                            |           |
      +------------------------------+----------------------------+-----------+

PHASE 1 (t=0)                 PHASE 2 (t=slot/3)            PHASE 3 (t=2*slot/3)
+-------------------------+   +--------------------------+  +-------------------------+
| if validator is proposer|   | sign attestations        |  | submit aggregate attest |
|  1. sign_randao_reveal  |   |  - slashing check first  |  | produce contributions   |
|  2. produce_block_v3    |   | submit_attestations      |  | submit contribution &   |
|  3. slashing check      |   | produce sync messages    |  |  proofs                 |
|  4. sign block          |   | submit sync committee    |  |                         |
|  5. record in DB        |   |  messages                |  |                         |
|  6. publish (blinded?)  |   |                          |  |                         |
+-------------------------+   +--------------------------+  +-------------------------+

EPOCH BOUNDARY (every 32 slots):
  - fetch attester/proposer/sync-committee duties (DutyTracker)
  - prepare_beacon_proposer (fee recipients)
  - submit committee subscriptions
  - register_validator (builder/MEV) with 0..30s jitter
```

---

## 5. Block Proposal Lifecycle

```
  [ slot start, I'm the proposer ]
              |
              v
     sign_randao_reveal           (DOMAIN_RANDAO)
              |
              v
     produce_block_v3              (graffiti, builder_boost_factor)
              |
              v
     SlashingDb.is_safe_to_propose
              |
       +------+------+
       |             |
    SLASHABLE       SAFE
       |             |
       v             v
    REJECT      sign block        (DOMAIN_BEACON_PROPOSER)
    (Double        |
     Proposal)     v
              record block in SlashingDb
                     |
              +------+------+
              |             |
           blinded?       full?
              |             |
              v             v
     publish_blinded   publish_block
     (broadcast to all BNs in both branches)
```

---

## 6. Signing Flow (CompositeSigner)

```
     [ signing request ]
              |
              v
    +----------------------+
    | Which message type?  |
    +----+-----+------+----+
         |     |      |    +------------+
         |     |      |                 |
   Attestation Block Sync          BuilderReg
         |     |   (no slashing)  (no slashing,
         v     v                   zero genesis)
   +----------+---------+              |
   | Slashing DB check  |              |
   | (check & record)   |              |
   +----+---------------+              |
        |                              |
   +----+----+                         |
   |         |                         |
 REJECT    SAFE <------------+---------+
(double     |
 vote /     v
 surround,  +--------------------+
 double-    |  CompositeSigner   |
 proposal)  +----+----+----+-----+
                 |    |    |
          remote |    |    | local
          HTTP   |    |    | key
        (Web3Sgn)|    |    |
                 v    |    v
         +---------+  |  +-------+
         | Web3Sgn |  |  | blst  |   <-- in-process BLS
         | /api/v1 |  |  | BLS12 |
         | /eth2/  |  |  | sign  |
         | sign    |  |  +-------+
         +---------+  |
                      | remote gRPC
                      v
              +-------------------+
              |  bin/rvc-signer   |   <-- mTLS; key never
              |  (gRPC over mTLS) |       leaves the signer
              +-------------------+
                      |
                      v
                SIGNATURE
```

---

## 7. Startup Sequence

```
   parse CLI + config.toml
           |
           v
   init telemetry (TracingGuard)
           |
           v
   open SlashingDb
           |
           v
   PRAGMA integrity_check ------+--> FAIL: refuse to start
           |                    |
           v                    |
   create BnManager             |
           |                    |
           v                    |
   validate genesis_validators_root against BN
           |                    |
           | mismatch ----------+--> FAIL: refuse to start
           v
   check BN sync status (el_offline, is_optimistic, sync_distance)
           |
           v
   load cloud keys (KeySourceManager / SecretProvider)
           |
           v
   load local validator keys -> CompositeSigner
           |
           v
   connect gRPC remote signer (mTLS) -> CompositeSigner
           |
           v
   Doppelganger detection (2 epochs) ---+--> DETECTED: exit code 2
           |                            |
           v  (if enabled)              |
   build domain services (BlockService, SyncService, Signer, ...)
           |
           v
   start DutyOrchestrator
           |
           +---> Metrics Server     :8080  (/metrics, /healthz)
           +---> Keymanager API     :5062  (Bearer token)
           +---> gRPC DutyTracker   :50051 (Healthz)
```

---

## 8. Service Construction Wiring

```
   Config / CLI
        |
        v
   +---------+
   | bin/rvc |
   +----+----+
        |
        +----> BnManager             (multi-BN failover)
        |         |
        |         +----> BeaconClient(s) (HTTP)
        |
        +----> CompositeSigner
        |         ^
        |         | add keys
        |         |
        |    KeySourceManager <----- SecretProvider (GCP, ...)
        |         ^
        |         | add remote signer
        |    GrpcRemoteSigner (mTLS) <-------> bin/rvc-signer
        |
        +----> SlashingDb            (SQLite, EIP-3076)
        |
        +----> SystemSlotClock
        |
        +----> ValidatorStore        (per-validator config, TOML)
        |
        v
   +------------------------+
   |    SignerService       |   (combines CompositeSigner + SlashingDb)
   +----+-------------------+
        |
        +----> BlockService          (uses Signer + BeaconBlockClient + VStore)
        +----> SyncService           (uses Signer + SyncBeaconClient)
        +----> BuilderService        (uses Signer + VStore + BnManager)
        +----> DutyTracker           (uses BnManager)
        +----> Propagator            (uses BnManager)
        |
        v
   +--------------------+
   | DutyOrchestrator   |   (generic: SlotClock, AttestationSubmitter, BeaconBlockClient)
   +--------------------+
        |
        +----> MetricsServer   :8080
        +----> KeymanagerAPI   :5062
        +----> gRPC Server     :50051
```

---

## 9. Data / Key Flow Summary

```
  EIP-2335 Keystores on disk
          |
          | password-decrypt (Scrypt / PBKDF2 -> AES-128-CTR)
          v
  KeyManager (HashMap<pubkey_hex, SecretKey>; Zeroize on drop)
          |
          | local route
          v
  CompositeSigner ----> local BLS (blst)
          |                  ^
          | dynamic route    |
          v                  |
  Keymanager API import -----+   (runtime key add/remove)
          |
          | remote routes
          v
  +----> Web3Signer (HTTP)
  +----> GrpcRemoteSigner (gRPC mTLS) ----> bin/rvc-signer
                                                |
                                                +----> BasicSigner (keystore)
                                                +----> DvtSigner    (Shamir shares,
                                                                     Lagrange combine)
```

---

## Related Documents

- [ARCHITECTURE.md](../ARCHITECTURE.md) — Mermaid diagrams + per-crate narrative
- [docs/keymanager-api.md](./keymanager-api.md) — Keymanager REST API
- [docs/keygen-guide.md](./keygen-guide.md) — Key generation walkthrough
- [docs/running-guide.md](./running-guide.md) — Operator guide
