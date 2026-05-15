# Research: Keymanager API Specification — Missing Endpoints

## Summary

The [Ethereum Keymanager API specification](https://github.com/ethereum/keymanager-APIs) [1] defines the exact request/response schemas, status codes, and authentication requirements for all 10 missing endpoints. This document captures the verified spec details and flags discrepancies with the PRD.

## Critical Discrepancy: Voluntary Exit `epoch` Parameter

**The PRD specifies `epoch` as a JSON request body field. The official spec defines it as an optional query parameter.**

Per the spec [1], the `POST /eth/v1/validator/{pubkey}/voluntary_exit` endpoint accepts `epoch` as:
```
Query Parameter: epoch (optional)
Schema: Uint64
Description: "Minimum epoch for processing exit. Defaults to the current epoch if not set."
```

The PRD (FR-7) states:
```json
Request Body: { "epoch": "300000" }
```

**Recommendation:** Follow the spec — implement `epoch` as a query parameter (`?epoch=300000`), not a request body field. Lighthouse confirms this approach (see reference-implementations.md).

## Authentication

All endpoints require Bearer token authentication [1]:
- Header: `Authorization: Bearer <token>`
- Token format: "hex-encoded token of at least 256 bits" (i.e., 64+ hex chars)
- Content-Type: `application/json` for request and response bodies

This is consistent with rvc's existing implementation in `auth.rs`.

## Schema Types

All schemas are defined in the `types/` directory of the spec repo [1].

### Pubkey
```yaml
type: string
pattern: "^0x[a-fA-F0-9]{96}$"
description: "The validator's BLS public key, uniquely identifying them. 48-bytes, hex encoded with 0x prefix, case insensitive."
example: "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
```

### EthAddress
```yaml
type: string
pattern: "^0x[a-fA-F0-9]{40}$"
description: "An address on the execution (Ethereum 1) network."
example: "0xAbcF8e0d4e9587369b2301D0790347320302cc09"
```

### Uint64
```yaml
type: string
pattern: "^(0|[1-9][0-9]{0,19})$"
example: "30000000"
```
**Important:** Uint64 is a **string**, not a JSON number. This applies to `gas_limit`, `epoch`, and `validator_index` fields.

### Graffiti
```yaml
type: string
description: "Arbitrary data to set in the graffiti field of BeaconBlockBody"
example: "plain text value"
```
Note: The spec does not explicitly enforce a max length in the schema, but the consensus layer limits graffiti to 32 bytes.

### Signature
```yaml
type: string
pattern: "^0x[a-fA-F0-9]{192}$"
```

### ErrorResponse
```yaml
type: object
required: [message]
properties:
  message:
    type: string
    description: "Detailed error message"
example: { "message": "description of the error that occurred" }
```

## Endpoint Specifications

### Fee Recipient Endpoints

#### GET `/eth/v1/validator/{pubkey}/feerecipient`

| Field | Value |
|-------|-------|
| operationId | `listFeeRecipient` |
| Description | Maps validator public key to eth address for fee recipient feature. Returns default if none configured. |
| Path param | `pubkey` — Pubkey schema (required) |
| Success response | 200 |
| Response body | `{ "data": { "pubkey": "<Pubkey>", "ethaddress": "<EthAddress>" } }` |
| Error codes | 400, 401, 403, 404, 500 |

**FeeRecipient schema:**
```yaml
type: object
required: [ethaddress]
properties:
  pubkey: Pubkey
  ethaddress: EthAddress
```

Note: `pubkey` is not listed as required in the FeeRecipient object schema, but is present in GET responses.

#### POST `/eth/v1/validator/{pubkey}/feerecipient`

| Field | Value |
|-------|-------|
| operationId | `setFeeRecipient` |
| Description | Sets validator client fee recipient mapping. Overwrites existing. Cannot specify 0x00 address. |
| Path param | `pubkey` — Pubkey (required) |
| Request body | `{ "ethaddress": "<EthAddress>" }` |
| Success response | **202 Accepted** (no body) |
| Error codes | 400, 401, 403, 404, 500 |

**Edge case:** The spec explicitly states "Cannot specify the 0x00 fee recipient address through the API."

#### DELETE `/eth/v1/validator/{pubkey}/feerecipient`

| Field | Value |
|-------|-------|
| operationId | `deleteFeeRecipient` |
| Description | Deletes configured fee recipient mapping. |
| Path param | `pubkey` — Pubkey (required) |
| Success response | **204 No Content** (mapping removed or no mapping existed) |
| Error codes | 400, 401, 404, 500 |
| Special: 403 | "Mapping found but cannot be removed" (e.g., set via config file) |

---

### Gas Limit Endpoints

#### GET `/eth/v1/validator/{pubkey}/gas_limit`

| Field | Value |
|-------|-------|
| operationId | `getGasLimit` |
| Description | Retrieves execution gas limit. Returns process-wide default if none set. |
| Path param | `pubkey` — Pubkey (required) |
| Success response | 200 |
| Response body | `{ "data": { "pubkey": "<Pubkey>", "gas_limit": "<Uint64>" } }` |
| Error codes | 400, 401, 403, 404, 500 |

**GasLimit schema:**
```yaml
type: object
required: [gas_limit]
properties:
  pubkey: Pubkey
  gas_limit: Uint64
```

**Important:** `gas_limit` is a **string** (Uint64), e.g., `"30000000"`, not a JSON number.

#### POST `/eth/v1/validator/{pubkey}/gas_limit`

| Field | Value |
|-------|-------|
| operationId | `setGasLimit` |
| Description | Establishes a gas limit for an individual validator. |
| Path param | `pubkey` — Pubkey (required) |
| Request body | `{ "gas_limit": "<Uint64>" }` |
| Success response | **202 Accepted** (no body) |
| Error codes | 400, 401, 403, 404, 500 |

#### DELETE `/eth/v1/validator/{pubkey}/gas_limit`

| Field | Value |
|-------|-------|
| operationId | `deleteGasLimit` |
| Description | Removes configured gas limit for specified pubkey. |
| Path param | `pubkey` — Pubkey (required) |
| Success response | **204 No Content** |
| Error codes | 400, 401, 404, 500 |
| Special: 403 | "A gas limit was found, but cannot be removed. This may be because the gas limit was in configuration files that cannot be updated." |

---

### Graffiti Endpoints

#### GET `/eth/v1/validator/{pubkey}/graffiti`

| Field | Value |
|-------|-------|
| operationId | `getGraffiti` |
| Description | Retrieves graffiti for a validator. Returns process-wide default if none set. |
| Path param | `pubkey` — Pubkey (required) |
| Success response | 200 |
| Response body | `{ "data": { "pubkey": "<Pubkey>", "graffiti": "<Graffiti>" } }` |
| Error codes | 400, 401, 403, 404, 500 |

#### POST `/eth/v1/validator/{pubkey}/graffiti`

| Field | Value |
|-------|-------|
| operationId | `setGraffiti` |
| Description | Assigns graffiti for an individual validator. |
| Path param | `pubkey` — Pubkey (required) |
| Request body | `{ "graffiti": "<Graffiti>" }` |
| Success response | **202 Accepted** (no body) |
| Error codes | 400, 401, 403, 404, 500 |

#### DELETE `/eth/v1/validator/{pubkey}/graffiti`

| Field | Value |
|-------|-------|
| operationId | `deleteGraffiti` |
| Description | Removes configured graffiti for specified pubkey. |
| Path param | `pubkey` — Pubkey (required) |
| Success response | **204 No Content** |
| Error codes | 400, 401, 404, 500 |
| Special: 403 | "Graffiti found but cannot be removed" (e.g., set via config files) |

---

### Voluntary Exit Endpoint

#### POST `/eth/v1/validator/{pubkey}/voluntary_exit`

| Field | Value |
|-------|-------|
| operationId | `signVoluntaryExit` |
| Description | Create and sign a voluntary exit message for an active validator identified by a public key known to the validator client. |
| Path param | `pubkey` — Pubkey of an active validator (required) |
| **Query param** | `epoch` — Uint64 (optional). Minimum epoch for processing exit. Defaults to current epoch. |
| Request body | **None** |
| Success response | 200 |
| Response body | `{ "data": { "message": { "epoch": "<Uint64>", "validator_index": "<Uint64>" }, "signature": "<Signature>" } }` |
| Error codes | 400, 401, 403, 404, 500 |

**SignedVoluntaryExit schema:**
```yaml
SignedVoluntaryExit:
  type: object
  properties:
    message:
      type: object  # VoluntaryExit
      properties:
        epoch:
          $ref: Uint64
          description: "Minimum epoch for processing exit."
        validator_index:
          $ref: Uint64
          description: "Index of the exiting validator."
    signature:
      $ref: Signature  # 0x-prefixed, 96-byte hex
```

---

## PRD Discrepancies Summary

| Item | PRD Says | Spec Says | Impact |
|------|----------|-----------|--------|
| **Voluntary exit epoch** | Request body `{ "epoch": "300000" }` | Query parameter `?epoch=300000`, no request body | **High** — API shape differs |
| **403 Forbidden** | Not mentioned in PRD | Defined for DELETE endpoints when config is file-based and cannot be removed | Low — rvc can skip 403 if all config is API-mutable |
| **Fee recipient 0x00** | Not mentioned | Cannot set 0x00 address via API | Low — validation rule to add |
| **Graffiti max length** | <=32 bytes (ASCII) | Spec schema has no explicit length limit | Low — enforce at implementation, consistent with CL limit |
| **Gas limit and voluntary exit spec says "not used on Phase0/Altair"** | Not mentioned | Spec notes these endpoints may return 400 if no external builder configured | Low — rvc can always serve these |

## Sources

[1] [ethereum/keymanager-APIs](https://github.com/ethereum/keymanager-APIs) — Official Ethereum Keymanager API OpenAPI specification repository. Individual endpoint specs at `apis/fee_recipient.yaml`, `apis/gas_limit.yaml`, `apis/graffiti.yaml`, `apis/voluntary_exit.yaml`. Type schemas at `types/`.
