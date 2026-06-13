# Angle 04 — Beacon-node trust boundary, SSRF deny-list, optimistic handling

**PRD findings covered:** BN-1 (P1), BN-2 (P1), URL-1 (P1), URL-2 (P1), SSE-1 (P1),
EXIT-1 (P1), Info-4 (P2); supports the SSE-1 `catch_unwind` callback-isolation pattern.
**Verification verdict:** 20 claims verified; 3 partially refuted / source-mismatched;
several minor wording flags. Core security argument well-supported.

> **PROMPT-INJECTION NOTICE (reported per protocol):** the WebFetch of consensus-specs
> `optimistic.md` carried an injected "# MCP Server Instructions" block (claiming an alphaXiv
> MCP server). Disregarded; it influenced no tool call or output.

## Scope

Treating the beacon node as an untrusted/SSRF-relevant boundary: reserved-IP deny-lists,
optimistic-sync refusal, IP pinning against DNS rebinding, SSE callback isolation, and
genesis/GVR chain-binding for exits.

## Verified (substance HIGH)

- **Fail-closed sync handling** (Lighthouse `check_synced.rs`: RPC error → Offline) — basis for BN-1/BN-2.
- **Optimistic refusal** via `execution_optimistic` — basis for BN-1.
- **SSRF deny-list scope** for IPv4/IPv6 reserved ranges — basis for URL-1.
- **IP pinning via `reqwest::resolve_to_addrs`** — basis for URL-2.
- **`catch_unwind` for callback isolation** — basis for SSE-1.
- **EIP-7044 + `genesis_validators_root` chain-binding** — basis for EXIT-1.
- **keymanager auth/transport requirements** — basis for KM-3.

## REFUTED / SOURCE-MISMATCHED — drop or re-cite

1. **`ff00::/8` multicast is NOT in the IANA IPv6 Special-Purpose Address Registry.** That
   registry holds `2001:db8::/32`, `2002::/16`, `fc00::/7`, `fe80::/10`. IPv6 multicast is
   governed by the separate **IPv6 Multicast Address Space registry (RFC 4291 §2.7)**. The
   claim conflated two registries.
   - **Re-cite:** for `ff00::/8` cite IANA IPv6 Multicast Address Space / RFC 4291 §2.7; for the
     unicast reserved ranges cite the IANA IPv6 Special-Purpose registry. (The URL-1 deny-list
     itself is still correct in substance.)
2. **beacon-APIs `validator-flow.md` does NOT specify "SSE + dependent-root cross-check."** That
   file marks reorg handling "(TBD)" and only says "monitor reorg events (TBD)... if reorg,
   ask for new proposer duties." The SSE + `previous_duty_dependent_root`/`current_duty_dependent_root`
   pattern is real but lives in `events.yaml` + the `getProposerDuties`/`getAttesterDuties`
   endpoint descriptions.
   - **Re-cite:** `events.yaml` + the duties-endpoint descriptions (which carry `dependent_root`),
     not `validator-flow.md`.
3. **Web3Signer `configure-tls` page does NOT cover `--http-host-allowlist` or mTLS.** That page
   documents PKCS#12 keystores and `tls-known-clients-file`. mTLS and `--http-host-allowlist` are
   real but documented on the CLI options reference / key-best-practices pages.
   - **Re-cite:** `https://docs.web3signer.consensys.io/reference/cli/options` alongside the
     configure-tls page.

## Minor wording flags (substance fine)

4. **RFC 5735 is obsoleted by RFC 6890.** All enumerated ranges remain reserved under RFC 6890 /
   the current IANA IPv4 Special-Purpose registry. **Cite RFC 6890 + the IANA registry**, not RFC 5735.
   The "benchmark testing... not meant to be forwarded" quote for `198.18.0.0/15` is closer to
   RFC 2544 than RFC 5735 — paraphrase/composite, substance correct.
5. **`execution_optimistic` "must take care to set True"** appears in surrounding spec prose as
   recommended behavior, not as a normative MUST in the `primitive.yaml` type definition. High on
   substance, medium on exact attribution.
6. **keymanager token "hex-encoded, ≥256 bits"** — the literal `bearerFormat` reads "URL safe,
   opaque token"; the hex/256-bit detail comes from separate config guidance. Claim stitches two
   adjacent passages; the token-file SHOULD-accept text is verified.
7. **`::/96`** — IANA lists `::/8` as "Reserved by IETF" but does not enumerate `::/96` as a
   standalone reserved entry; it is deprecated by RFC 4291, not by an active IANA reservation.
   Fine for deny-list purposes; "IANA continues listing" is slightly over-stated.
8. **Lighthouse `check_synced.rs`** verified on current stable HEAD; path/structure may differ on
   unstable, but the fail-closed behavior (RPC error → Offline) is current.

## Single-source / LOW confidence — verify before relying

9. **IPv4-mapped-IPv6 SSRF "shipped fixes" across five projects** — only the **Twenty** advisory
   (GHSA-vrcj-hv2q-c58m) was directly verified. Directus, Sync-In Server, OpenClaw, Craft CMS are
   grouped under one URL. **Cite each GHSA/CVE individually before publishing the "shipped fixes"
   framing.** Does not affect the URL-1 design (the deny-list is justified on first principles).

## Bottom line

The BN-trust-boundary security argument is sound and supports BN-1/BN-2/URL-1/URL-2/SSE-1/EXIT-1
as written. Fix the three citation mismatches (IPv6 multicast registry; reorg/SSE source;
Web3Signer mTLS page) and swap RFC 5735 → RFC 6890 in any normative deny-list reference.
