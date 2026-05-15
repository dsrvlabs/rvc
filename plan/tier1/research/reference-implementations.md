# Research: Reference Implementations — Lighthouse & Lodestar

## Summary

Lighthouse (Rust, Warp-based) and Lodestar (TypeScript) both implement the full Keymanager API config endpoints. Their patterns are consistent with each other and the spec, confirming the PRD's design direction. Key takeaways: epoch is a query parameter for voluntary exit, all config endpoints follow a check-then-act pattern with 404 for unknown validators, and persistence is handled synchronously within the write lock.

## Lighthouse (Rust) [1][2]

### Architecture

- **Framework:** Warp (not Axum — rvc uses Axum, so route patterns differ)
- **Validator store:** `InitializedValidators` with `RwLock` for thread-safe access
- **Persistence:** `validator_definitions.yml` (YAML, not TOML like rvc)
- **Handler pattern:** `blocking_json_task` wrapper for sync operations on a blocking threadpool

### Route Registration Pattern

Lighthouse uses Warp's filter composition:

```rust
let get_fee_recipient = eth_v1
    .and(warp::path("validator"))
    .and(warp::path::param::<PublicKey>())
    .and(warp::path("feerecipient"))
    .and(warp::path::end())
    .and(validator_store_filter.clone())
    .then(|validator_pubkey: PublicKey, validator_store: Arc<...>| { ... });
```

### Pubkey Validation Pattern

Every handler follows the same check-first pattern:

```rust
if validator_store
    .initialized_validators()
    .read()
    .is_enabled(&validator_pubkey)
    .is_none()
{
    return Err(warp_utils::reject::custom_not_found(format!(
        "no validator found with pubkey {:?}", validator_pubkey
    )));
}
```

**Key insight:** Lighthouse checks `is_enabled()` which returns `None` if the validator is not found at all. This means disabled validators are still accessible — only truly unknown pubkeys get 404.

### Fee Recipient Handlers

**GET:** Calls `get_fee_recipient(&pubkey)` which returns effective value (override or default). Returns 500 if no fee recipient is set at all (neither override nor default) [3].

```rust
validator_store
    .get_fee_recipient(&PublicKeyBytes::from(&validator_pubkey))
    .map(|fee_recipient| {
        GenericResponse::from(GetFeeRecipientResponse {
            pubkey: PublicKeyBytes::from(validator_pubkey.clone()),
            ethaddress: fee_recipient,
        })
    })
    .ok_or_else(|| warp_utils::reject::custom_server_error("no fee recipient set".to_string()))
```

**POST:** Calls `set_validator_fee_recipient()` which writes to `validator_definitions.yml`. Returns 202.

**DELETE:** Calls `delete_validator_fee_recipient()` which removes the override. Returns 204.

### Gas Limit Handlers

Same pattern as fee recipient. `get_gas_limit(&pubkey)` always returns a value (falls back to default), so no 500 risk.

### Graffiti Handlers

**Notable difference:** Lighthouse checks for `--graffiti-file` flag before allowing POST/DELETE:

```rust
if graffiti_file.is_some() {
    return Err(warp_utils::reject::invalid_auth(
        "Unable to update graffiti as \"--graffiti-file\" flag is set".to_string(),
    ));
}
```

This returns **403 Forbidden** — matching the spec's 403 definition: "found but cannot be removed (configuration file-based)". rvc does not have a graffiti-file feature, so this 403 case does not apply.

### Voluntary Exit Handler

**Epoch as query parameter** (confirmed):

```rust
let post_validators_voluntary_exits = eth_v1
    .and(warp::path("validator"))
    .and(warp::path::param::<PublicKey>())
    .and(warp::path("voluntary_exit"))
    .and(warp::query::<api_types::VoluntaryExitQuery>())  // <-- query param
    ...
```

The handler delegates to `create_signed_voluntary_exit()`:
1. Resolves the validator index from the beacon node
2. Determines the exit epoch (from query param or current epoch via slot clock)
3. Signs the `VoluntaryExit` message using the validator's key
4. Returns `SignedVoluntaryExit` in the response (does **not** submit to beacon node)

**Important finding:** Lighthouse does **not** submit the signed exit to the beacon node in the API handler — it only returns the signed message. The PRD says "Submit the signed exit to the beacon node" (FR-7). This is a design choice: some clients submit, others don't. The spec does not mandate submission. rvc should decide which approach to take.

### Persistence

Lighthouse persists via methods on `InitializedValidators`:
- `set_validator_fee_recipient()` → updates in-memory + writes YAML
- `delete_validator_fee_recipient()` → removes override + writes YAML
- Same for gas_limit and graffiti

The write happens synchronously within the write lock, ensuring atomicity against concurrent requests.

### Error Handling

Four error types:
| Error | HTTP Status | Usage |
|-------|-------------|-------|
| `custom_not_found` | 404 | Unknown validator pubkey |
| `custom_bad_request` | 400 | Invalid input format |
| `custom_server_error` | 500 | Persistence failure, beacon node unreachable |
| `invalid_auth` | 403 | Config is file-based, cannot be modified via API |

---

## Lodestar (TypeScript) [4]

### Architecture

- **Validator store:** `ValidatorStore` class with `Map<PubkeyHex, ValidatorData>`
- **Config structure:** `ProposerConfig` type per validator
- **Persistence:** In-memory only in ValidatorStore; external persistence handled by caller

### Config Data Structure

```typescript
type ProposerConfig = {
  graffiti?: string;
  strictFeeRecipientCheck?: boolean;
  feeRecipient?: ExecutionAddress;
  builder?: {
    gasLimit?: number;
    selection?: BuilderSelection;
    boostFactor?: bigint;
  };
};
```

### Fee Recipient

```typescript
getFeeRecipient(pubkeyHex: PubkeyHex): ExecutionAddress {
  const validatorData = this.validators.get(pubkeyHex);
  if (validatorData === undefined) {
    throw Error(`Validator pubkey ${pubkeyHex} not known`);
  }
  return validatorData.feeRecipient ?? this.defaultProposerConfig.feeRecipient;
}
```

Pattern: throw on unknown pubkey (→ 404), return override or default.

### Gas Limit

```typescript
getGasLimit(pubkeyHex: PubkeyHex): number {
  const validatorData = this.validators.get(pubkeyHex);
  if (validatorData === undefined) {
    throw Error(`Validator pubkey ${pubkeyHex} not known`);
  }
  return validatorData?.builder?.gasLimit ?? this.defaultProposerConfig.builder.gasLimit;
}
```

Gas limit is nested under `builder` config. Falls back to default.

### Graffiti

```typescript
getGraffiti(pubkeyHex: PubkeyHex): string | undefined {
  // ... same unknown-pubkey check ...
  return validatorData.graffiti ?? this.defaultProposerConfig.graffiti;
}
```

Returns `undefined` if neither per-validator nor default graffiti is set.

### Voluntary Exit Signing

```typescript
async signVoluntaryExit(
  pubkey: BLSPubkeyMaybeHex,
  validatorIndex: number,
  exitEpoch: Epoch
): Promise<phase0.SignedVoluntaryExit> {
  const signingSlot = computeStartSlotAtEpoch(exitEpoch);
  const domain = this.config.getDomainForVoluntaryExit(signingSlot);
  const voluntaryExit = { epoch: exitEpoch, validatorIndex };
  const signingRoot = computeSigningRoot(ssz.phase0.VoluntaryExit, voluntaryExit, domain);
  return {
    message: voluntaryExit,
    signature: await this.getSignature(pubkey, signingRoot, signingSlot, signableMessage),
  };
}
```

**Domain computation:** Uses `DOMAIN_VOLUNTARY_EXIT` with the fork version at the exit epoch's slot. The domain includes `genesis_validators_root`. rvc's existing voluntary exit CLI already has this logic.

### DELETE Semantics

Both clients implement DELETE as "remove the override" — `delete validatorData.feeRecipient` / `delete validatorData.graffiti`. The validator continues operating with the default value. This is consistent with the spec: "DELETE removes the configured value, reverting to default."

---

## Patterns rvc Should Adopt

1. **Check-then-act with early 404:** Every handler should first verify the pubkey is known. Both reference implementations do this before any other logic.

2. **Effective value pattern:** GET returns the effective value (per-validator override OR default). Never return an error for "no override set" — always have a fallback. rvc's `ValidatorStore.effective_*()` methods already do this.

3. **Epoch as query parameter:** Follow the spec and Lighthouse. Use `axum::extract::Query` for the voluntary exit endpoint.

4. **Persistence within write lock:** Lighthouse persists synchronously while holding the write lock. This serializes writes and prevents races. rvc should do the same.

5. **Return SignedVoluntaryExit without submitting:** Consider whether rvc should submit to the beacon node (as the PRD suggests) or just return the signed message (as Lighthouse does). The spec does not mandate submission. Submitting is more convenient for operators but adds a beacon node dependency. **Recommendation:** Submit to beacon node (matching the PRD intent) and return the signed message, but handle beacon node failures gracefully.

## Pitfalls to Avoid

1. **Lighthouse bug [3]:** GET fee_recipient returned 500 when no default was configured. rvc should ensure a default always exists (the current `ValidatorDefaults` struct provides this).

2. **String-encoded gas_limit:** Both clients store gas_limit as a number internally but serialize to string in API responses. rvc must ensure `gas_limit` is `"30000000"` not `30000000` in JSON.

3. **Case sensitivity:** Pubkeys are case-insensitive per spec (`^0x[a-fA-F0-9]{96}$`). Normalize to lowercase for internal comparison.

4. **Graffiti encoding:** The spec says "plain text value" for graffiti. Lighthouse stores it as a 32-byte array padded with zeros. rvc already does this via `parse_graffiti()`. The API should accept UTF-8 strings and convert to the 32-byte representation.

## Sources

[1] [Lighthouse validator_client/http_api/src/lib.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/http_api/src/lib.rs) — Main HTTP API handler implementations.
[2] [Lighthouse common/account_utils/src/validator_definitions.rs](https://github.com/sigp/lighthouse/blob/stable/common/account_utils/src/validator_definitions.rs) — Validator definitions persistence.
[3] [Lighthouse Issue #3507: GET fee_recipient returns 500](https://github.com/sigp/lighthouse/issues/3507) — Bug where missing fee recipient default caused 500.
[4] [Lodestar packages/validator/src/services/validatorStore.ts](https://github.com/ChainSafe/lodestar/blob/unstable/packages/validator/src/services/validatorStore.ts) — ValidatorStore implementation with config management methods.
