# Web3Signer-compatible HTTP Remote Signing API

`rvc-signer` can additionally serve the **Ethereum Remote Signing API** (the
community "Web3Signer" HTTP/JSON API, `ethereum/remote-signing-api` v1.3.0) so
third-party consensus-layer clients — **Lighthouse** and **Prysm** — can use it
as a remote signer. It is **additive**: the existing gRPC service stays
default-on and unchanged; the HTTP API is **opt-in**.

This page is the **security-critical operability floor**. The full worked
per-client recipes and the scripted SAN certificate generation are the operator
guide ([Phase 4 / FR-32]; see *Operator recipes* below) — this page is what you
must understand before turning the API on.

> ⚠️ **NEVER expose this API to the public internet.**
> The Remote Signing API has **no application-layer authentication** beyond TLS
> (and, in mTLS mode, the client certificate). It signs validator messages.
> Bind it to a private network / loopback and put it behind firewall rules that
> permit **only** your validator client(s) to reach it. Treat the listen address
> as you would the signing keys themselves.

---

## Enabling the HTTP API

The HTTP API is disabled by default. Enable it via the `[signer.http]` config
block **or** the matching CLI flags. The gRPC listener is unaffected — enabling
HTTP never disables gRPC.

### Config (`config.toml`)

```toml
[signer.http]
enabled        = true                 # opt-in; default false
listen_address = "127.0.0.1:9000"     # default 127.0.0.1:9000 (loopback)
tls_mode       = "mtls"               # "mtls" (default) | "server-tls-only"
tls_cert       = "/etc/rvc/http-server.pem"   # server cert chain (PEM)
tls_key        = "/etc/rvc/http-server.key"   # server private key (PEM)
tls_ca_cert    = "/etc/rvc/ca.pem"            # client CA (PEM) — required in BOTH modes
```

> **Bind address.** The default is **`127.0.0.1:9000` (loopback)** — it serves a
> validator client on the *same host* and fails safe (unreachable) for a remote
> one. If your VC runs on a different host, set `listen_address` to a routable
> **private-network** address that only the VC host can reach (behind a
> firewall). **Never bind a public interface** (e.g. `0.0.0.0` on a host with a
> public IP). The address is bound verbatim — there is no host normalization.

### CLI flags

| Flag | Meaning | Default |
| --- | --- | --- |
| `--http-enabled` | Turn the HTTP API on | off |
| `--http-listen-address <host:port>` | Listen address (bound verbatim — loopback default serves a same-host VC; set a private-network address for a remote one) | `127.0.0.1:9000` |
| `--http-tls-mode <mtls\|server-tls-only>` | Client-auth posture | `mtls` |
| `--http-tls-cert <PEM>` | Server certificate chain | — |
| `--http-tls-key <PEM>` | Server private key (PKCS#8 / PKCS#1 / SEC1; **unencrypted**) | — |
| `--http-tls-ca-cert <PEM>` | Client CA — **required in both modes** | — |

The HTTP TLS material is **independent of the gRPC TLS material**, so you can run
gRPC with mTLS and HTTP with server-TLS-only (or any combination).

**Fail-closed startup.** With `enabled = true`, the signer refuses to start if
any of `tls_cert` / `tls_key` / `tls_ca_cert` is missing or unreadable, if the
key is encrypted, or if the cert/key do not match — there is no plaintext
fallback. It also refuses to start the HTTP API if slashing protection is
disabled (the HTTP API requires the shared signing gate).

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/upcheck` | Liveness → `200 OK` |
| `GET` | `/api/v1/eth2/publicKeys` | List loaded BLS public keys |
| `POST` | `/api/v1/eth2/sign/{identifier}` | Sign (identifier = `0x`-prefixed pubkey) |

---

## TLS modes: mTLS vs server-TLS-only

Both modes **always** present a server certificate and **always** require the CA
(`tls_ca_cert`). The **only** difference is whether the client must present a
certificate:

| Mode | Client cert | Use with |
| --- | --- | --- |
| `mtls` (default, recommended) | **Required** and verified against `tls_ca_cert` | Lighthouse |
| `server-tls-only` | **Optional**; verified against `tls_ca_cert` *if presented* | Prysm |

> `server-tls-only` relaxes **only** the requirement that a client present a
> certificate. Server authentication is unchanged, the CA is still required, and
> any client certificate that *is* presented is still validated against the CA.
> It is not "no TLS" and not "skip verification".

### Server certificate SANs

Both clients perform real hostname/SAN verification and **neither exposes an
"insecure"/skip-verify flag**. The server certificate's **Subject Alternative
Names must cover every address a client dials** (DNS name and/or IP). A CN-only,
SAN-less certificate is rejected by both clients. One server certificate can
serve both clients if its SAN set covers every dialed address.

### Lighthouse (mTLS)

Lighthouse trusts the signer's server certificate via a PEM CA file and presents
a PKCS#12 client identity. Point its `validator_definitions.yml` web3signer
entry (or `POST /lighthouse/validators/web3signer`) at
`https://<signer-host>:9000` with the root certificate and client identity. The
client certificate's CA must be the one configured as `tls_ca_cert` here.

### Prysm (server-TLS-only)

Prysm connects over HTTPS with `--validators-external-signer-url` and presents
**no client certificate**, so the signer must run with `tls_mode =
"server-tls-only"`.

> **Prysm trusts the server certificate via the host OS trust store only** — it
> does **not** accept a per-validator CA file for the Web3Signer path. For a
> private CA you must install the CA root into the Prysm host's system trust
> anchors, or use a publicly-trusted (e.g. ACME) server certificate. The
> `--remote-signer-*` path flags are for the **legacy gRPC** signer, not this
> HTTP API — do not point operators at them.

---

## Audit CN under server-TLS-only

Each HTTP sign request records an audit Common Name derived from the client
certificate. In **server-TLS-only** mode a client (e.g. Prysm) presents no
certificate, so there is no CN to record and the audit entry falls back to the
default **`signing-gate`** (`AUDIT_CN_DEFAULT`). This is expected. A client that
*does* present a certificate (e.g. Lighthouse, even on a server-TLS-only
listener) still has its real CN recorded.

The CN is an **audit label only** — it never gates authorization and never
scopes slashing protection. A request with no CN still signs.

---

## Out of scope (for now)

- **Client-certificate revocation (CRL/OCSP).** Client certs are validated
  against the configured CA but revocation is not checked; rotate the CA or
  re-issue certs to revoke access.
- **Application-layer authentication / rate limiting.** None beyond TLS — rely on
  network isolation (see the warning above).
- **Encrypted (passphrase-protected) TLS private keys.** Not supported for the
  HTTP listener; provide an unencrypted key. Restrict its filesystem permissions
  to the signer user (e.g. `0600`, owned by the service account) — a
  world-readable server key lets an attacker impersonate the signer / MITM the
  validator client.

## Operator recipes

The full, worked Lighthouse-mTLS and Prysm-server-TLS-only setups, including a
scripted SAN certificate-generation recipe validated end-to-end on Holesky, are
the operator guide (Phase 4 / FR-32). This page is the safety floor those recipes
build on; the canonical cert/CA example there is the one validated by the Holesky
acceptance run.
