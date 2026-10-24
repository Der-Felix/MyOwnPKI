# Phase 2 – plan (v0.2: ACME server and domains)

> Written at the end of the night run 2026-10-21, after phase 1 (v0.1). The owner answered the open
> questions on 2026-10-22 (§4); the plan below follows those answers. Built from the night run of
> 2026-10-22 on (branch `night/v0.2`, docs/NIGHTLOG.md "Night log – v0.2").
>
> **Status: complete.** Released as v0.2.0 on 2026-10-23; v0.2.1 (installation as a systemd
> service, 2026-10-24) and v0.2.2 (own TLS, daily backup, trust page – amends Q1, 2026-10-24)
> followed. Phase 3: docs/PHASE3.md.

Goal (PLAN §10.1, v0.2): an **ACME server (RFC 8555) for the internal CAs with http-01 and
dns-01**, a **domain model** and **approval levels**, so that certbot, acme.sh, Traefik and Caddy
get certificates from the own CA – integration level 1 (PLAN §6.3a). The server only *reads*
dns-01 TXT records, through a **configurable DNS resolver** (internal DNS, split DNS); setting the
record is the client's job.

Rules that shape every step:

- **One issuance path (ADR-19).** ACME finalize calls the same policy engine and the same
  `ca.Engine` issuance as the UI and the API – no second signer, no shortcut. Presets give the
  extensions; the CSR only gives names and the key.
- **ACME payloads are attacker input** (security.md): JWS, CSRs, identifiers, account contact
  fields. Size limits on every body.
- **Validation is SSRF by design** (security.md "ACME validation"): only ports 80/53, resolve once
  and connect to that IP, short timeouts, an address policy per CA, never the admin listener.
- **Validity:** ACME issuances default to **90 days**, capped by the CA's maximum validity
  (owner decision 6, 2026-10-13).
- Same working rules as phase 1: step by step, `task check` green, commits after the owner's OK.

---

## 1. Data model

Everything ACME lives in `tenants/<t>/pki.db` – an order and the certificate it produces must be
in **one** transaction (ADR-06). Times UTC, IDs from `internal/ids`.

### 1.1 Domains and policy (`pki.db`, migration 0008)

```
domains                               -- a name space the tenant issues for
  id               TEXT PK
  name             TEXT UNIQUE        -- "homelab.example" (punycode, lower case, no trailing dot)
  ca_id            → cas.id           -- the intermediate that signs for it (its name constraints must permit it)
  include_subdomains INTEGER          -- 1: *.homelab.example and deeper; 0: only the name itself
  wildcards        INTEGER            -- 1: "*.x" may be requested (dns-01 only, RFC 8555 §7.1.3)
  challenge_types  TEXT               -- JSON ["http-01","dns-01"]; the allowed subset
  approval         TEXT               -- open | account | new_name (PLAN §6.3), see 1.3
  preset           TEXT               -- preset used for ACME orders (default "server")
  validity_days    INTEGER NULL       -- NULL = 90; capped by cas.max_validity_days
  address_policy   TEXT               -- internal | public: which IPs http-01 may connect to (1.4)
  created_at, updated_at

domain_ips                            -- IP identifiers (RFC 8738), optional
  domain_id → domains.id, cidr TEXT   -- e.g. 192.0.2.0/24
```

A name is served by the **most specific** domain that covers it; no domain → the order is refused
with `rejectedIdentifier`. Two domains with the same name are impossible (UNIQUE).

### 1.2 ACME objects (`pki.db`, migration 0009)

```
acme_accounts
  id TEXT PK, key_thumbprint TEXT UNIQUE   -- RFC 7638 JWK thumbprint (SHA-256)
  jwk TEXT                                  -- the public key (JSON), ES256/RS256/EdDSA only
  status TEXT                               -- pending_approval | valid | deactivated | revoked
  contact TEXT                              -- JSON ["mailto:…"], validated, shown escaped
  eab_key_id TEXT NULL → acme_eab_keys.id
  created_at, approved_at NULL, approved_by NULL

acme_eab_keys                         -- external account binding (RFC 8555 §7.3.4), created in the UI
  id TEXT PK, mac_key_hash TEXT       -- HMAC key shown once, stored hashed + encrypted (DEK) for verification
  label TEXT, domain_ids TEXT         -- which domains an account bound with it may order for
  expires_at, used_at NULL, created_by

acme_orders
  id TEXT PK, account_id → acme_accounts.id
  status TEXT                         -- pending | ready | processing | valid | invalid
  identifiers TEXT                    -- JSON [{"type":"dns","value":"…"}]
  not_before NULL, not_after NULL, expires_at
  certificate_id NULL → certificates.id
  error TEXT NULL                     -- RFC 8555 problem document
  created_at

acme_authzs                           -- one per identifier and account; reused while valid
  id TEXT PK, account_id, identifier_type, identifier_value, wildcard INTEGER
  status TEXT                         -- pending | valid | invalid | deactivated | expired | revoked
  expires_at                          -- pending: 1 hour; valid: 7 days (configurable, see §4)

acme_challenges
  id TEXT PK, authz_id → acme_authzs.id
  type TEXT                           -- http-01 | dns-01
  token TEXT                          -- 128 random bits, base64url
  status TEXT                         -- pending | processing | valid | invalid
  validated_at NULL, error TEXT NULL, attempts INTEGER

acme_order_authzs (order_id, authz_id)  -- many to many

acme_names                            -- names this tenant has issued for before (approval "new_name")
  name TEXT PK, first_order_id, approved_at, approved_by
```

**Nonces** live in memory (a bounded set with expiry, 1 hour); a restart invalidates them, which
RFC 8555 §6.5 allows (`badNonce`, the client retries). **Rate limits** are counters in memory per
account and per IP (§2 step 11).

### 1.3 Approval levels (PLAN §6.3)

| Level | New account | Order for a name never issued before | Renewal |
|---|---|---|---|
| `open` | valid at once | issued after the challenge | issued |
| `account` | `pending_approval` until an admin approves – or valid at once with an EAB key | issued | issued |
| `new_name` | as `open` (or EAB) | order stays `pending` with an authorization that waits for approval (`acme_names`); the client retries | issued |

The strictest level of all domains an order touches wins. Approval never happens per order (standard
clients time out after finalize, PLAN §6.3 note).

### 1.4 Configuration (`config.yaml`)

ACME is served **only behind a reverse proxy** that terminates TLS (owner Q1, 2026-10-22): the
server has no TLS listener of its own for ACME, but a separate plain-HTTP listener that is not
the public CRL port – so nobody can talk ACME in clear text past the proxy. (Amended in v0.2.2:
with `acme.tls_issuer` the ACME listener may speak TLS itself – PLAN §14 "v0.2.2", OPERATIONS 10.10.)

```yaml
acme:
  # The ACME listener (plain HTTP), only for the reverse proxy. Default 127.0.0.1:8081.
  listen: "127.0.0.1:8081"
  # The address clients use (the proxy's HTTPS URL); every URL the server hands out is built
  # from it – X-Forwarded-Host/-Proto are never trusted. Must be https://. Empty: ACME is off.
  base_url: "https://pki.homelab.lan/acme"
  # Only connections from these addresses/CIDRs may use acme.listen (others get 403), and only
  # their X-Forwarded-For is believed (rate limits, audit). Default: loopback.
  trusted_proxies: "127.0.0.1, ::1"
  # The DNS server that dns-01 asks (and http-01 uses to resolve names). Empty: the system resolver.
  resolver: "10.0.0.53:53"
public:
  listen: ":8080"          # CRL, AIA (HTTP, as in v0.1) – no ACME here
```

The proxy gets its own TLS certificate once, from the own CA through the UI or the API (a
server certificate for the proxy's host name) – no chicken-and-egg: ACME is not needed for it.
OPERATIONS.md shows Caddy, nginx and Traefik.

Address policy (`domains.address_policy`): `internal` allows RFC 1918, ULA and the configured
networks; `public` refuses private, loopback, link-local and CGNAT ranges. Both refuse the server's
own listener addresses and `0.0.0.0/::`.

---

## 2. Work plan

Each step ends with: summary for the owner (German), verification commands, a commit proposal.
"Approval" marks a step that needs a new dependency.

| # | Step | Approval needed | Verifies with |
|---|---|---|---|
| 1 | **Domain model**: migration 0008, `internal/domain` (create, change, delete when unused; lookup "most specific domain for a name"), checks against the CA's name constraints at creation, API `/domains` (spec first) and UI pages (list, form) | – | unit tests of the lookup (wildcards, sub-domains, IDN punycode, trailing dot); a domain outside the CA's name constraints is refused; contract tests |
| 2 | **Policy engine extension**: `policy.CheckOrder(domain, names, preset)` used by UI/API issuance **and** ACME; the existing name checks move behind it unchanged | – | the phase 1 issuance tests pass unchanged; new table tests per domain setting |
| 3 | **JOSE, own code** (owner Q3): parsing and the rules ourselves, cryptography only from the standard library. Flattened JSON with exactly one signature; protected header with `url`, `nonce` and exactly one of `jwk`/`kid` (RFC 8555 §6.2); duplicate header names refused. Fixed allowlist ES256 (P-256), ES384 (P-384), RS256 (≥ 2048 bits), EdDSA (Ed25519) – the algorithm follows from the key type, the header must match it; `none`, HS*, unknown `crit`, `b64: false` refused; ES signatures only as fixed-length R‖S (no DER). JWK thumbprint (RFC 7638); nonce store | – | RFC 7515 appendix A and RFC 7638 vectors; a negative test for every rule; a Go fuzz test of the parser (short run in CI); lego registers, orders and revokes against the server |
| 4 | **ACME listener and directory** (owner Q1): `acme.listen` (plain HTTP, default 127.0.0.1:8081) only for the reverse proxy; connections from outside `acme.trusted_proxies` get 403; X-Forwarded-For only from those; all URLs from `acme.base_url` (must be https://, `config check` refuses http). `GET /acme/directory`, `HEAD/GET newNonce`, `Replay-Nonce` on every answer, problem documents (`urn:ietf:params:acme:error:*`) | – | the directory through a proxy with `curl`; a request from an untrusted address gets 403; `config check` refuses an http base URL |
| 5 | **Accounts**: newAccount (incl. `onlyReturnExisting`), account update, deactivation, key change (RFC 8555 §7.3.5), EAB verification; approval queue in the UI; audit entries | – | certbot/lego register; EAB with a wrong MAC refused; a pending account can't order |
| 6 | **Orders and authorizations**: newOrder, authz reuse, order status machine, expiry job; identifiers checked against the domains (`rejectedIdentifier`, `unsupportedIdentifier`) | – | state-machine table tests; an order for a name without domain is refused before any challenge |
| 7 | **http-01 validator** (RFC 8555 §8.3): own `http.Client`, resolve once via the configured resolver and dial that IP, port 80 only, ≤ 10 redirects only to 80/443 on names of the same order, 10 s timeout, 1 KiB body limit, from two attempts with back-off; the address policy | – | tests with a local HTTP server; redirect to port 22 / to 169.254.169.254 / to the admin listener refused; DNS rebinding test (first answer public, second private) |
| 8 | **dns-01 validator** (RFC 8555 §8.4): TXT `_acme-challenge.<name>` through the configured resolver, CNAME chain followed (≤ 8, PLAN §6.3 "CNAME delegation"), no cache, wildcard authz only by dns-01 | – (owner Q4: `net.Resolver` with its own `Dial`) | tests with an in-process DNS server; split DNS (internal answer differs from public) documented with an example |
| 9 | **Finalize and certificate**: CSR checks (key ≥ policy, names = order identifiers exactly, no extensions copied), issuance through `ca.Engine` in the order's transaction, 90 days default, chain download (`application/pem-certificate-chain`), alternate chains none. **Sealed server:** newAccount, newOrder and challenges work; finalize stores the CSR and the order stays `processing` with `Retry-After`; the certificate is issued at the unseal (a job also retries every minute); the dashboard shows "N ACME orders wait for the unseal" | – (sealed server: owner 2026-10-22) | `openssl verify` of the result; a CSR with an extra name or `CA:TRUE` request gets exactly the preset's extensions; a CSR naming one name less is refused (`badCSR`) |
| 10 | **revokeCert** (by account key or by certificate key, RFC 8555 §7.6) through the phase 1 revocation, reasons as in the UI; CRL signed at once | – | revoke with each key type; a third account can't revoke; CRL check with OpenSSL |
| 11 | **Rate limits and abuse guards**: orders per account per hour, failed validations per name, new accounts per IP; `rateLimited` with `Retry-After`; limits in the tenant settings | – | tests with a fake clock |
| 12 | **ARI** (RFC 9773): `renewalInfo` with the window at 2/3 of the lifetime plus jitter (pki-rules.md §4) | – | lego (and other clients with ARI support) ask for it; the window lies inside the lifetime |
| 13 | **Approval levels in the UI**: account queue, new-name queue, EAB key creation (shown once), per-domain settings (default level `account`, owner Q2); dashboard counters "waiting for approval" | – | handler tests incl. no-inline-style; screenshots light/dark of the demo instance |
| 14 | **Conformance**: Pebble's client test suite and real clients in CI – certbot (`--server`, http-01 standalone, dns-01 via `certbot-dns-rfc2136` against a BIND test container), lego, acme.sh; Traefik and Caddy as a documented manual test | – (owner Q5: only in its own CI job, images pinned by digest) | the CI job green on Linux |
| 15 | **Docs and v0.2**: OPERATIONS.md chapter "ACME" (connecting certbot, Traefik, Caddy; trusting the root; split DNS), CHANGELOG 0.2.0, PLAN update, upgrade test from a v0.1 backup | – | the upgrade test: restore a v0.1 backup, migrate, issue by ACME |

### Notes

- **Order of work:** 1–2 make the domain the unit of policy; 3–6 are the protocol skeleton; 7–8 the
  validators; 9 issues; 10–15 complete it. A walking skeleton with certbot (http-01) is possible
  after step 9.
- **Not in v0.2** (PLAN §10.1 "After v1.0"): tls-alpn-01, ACME client for Let's Encrypt, OCSP.
- **The UI/API issuance stays** for manual cases; it uses the same policy engine (step 2).
- **Names in the audit log:** account IDs and thumbprints, never contact e-mail addresses (personal
  data, security.md "Audit log").

---

## 3. Dependencies

No new module in the release binary (owner 2026-10-22). Test tools only, pinned and at least two
weeks old, never in `go.mod`:

| Module / tool | License | For | Status |
|---|---|---|---|
| `github.com/go-jose/go-jose/v4` | Apache-2.0 | JWS | **not used** – own code (Q3) |
| `github.com/miekg/dns` | BSD-3 | dns-01 | **not used** – `net.Resolver` with its own `Dial` (Q4) |
| Pebble | MPL-2.0 | conformance tests (step 14) | **approved as a test tool**: `go run …@<version>` locally, in CI |
| lego | MIT | the walking skeleton and conformance (steps 3, 9, 14) | **approved as a test tool**: `go run …@<version>` locally, in CI |
| certbot with certbot-dns-rfc2136, BIND | Apache-2.0 / MPL-2.0 | conformance (step 14) | **approved** as containers, only in their own CI job, images pinned by digest |

---

## 4. Decisions of the owner (2026-10-22)

| # | Question | Decision |
|---|---|---|
| Q1 | HTTPS for ACME | **Only behind a reverse proxy**, no TLS listener of our own. A separate plain-HTTP `acme.listen` (default 127.0.0.1:8081), not the public CRL port. `acme.base_url` must be `https://` (`config check` refuses http). `acme.trusted_proxies`: only there X-Forwarded-For counts (rate limits, audit), other addresses get 403 on `acme.listen`. X-Forwarded-Host/-Proto are never trusted – every URL comes from `base_url`. OPERATIONS.md: Caddy, nginx, Traefik, and how the proxy gets its own certificate once from the own CA. **Amended 2026-10-24 (v0.2.2):** `acme.tls_issuer` adds a TLS listener of our own as an alternative; the proxy way stays the default – PLAN §14 "v0.2.2" |
| Q2 | Default approval level | **`account`**; EAB keys from the UI, shown once |
| Q3 | JOSE library or own code | **Own code**: parsing and rules ourselves, cryptography only from the standard library. Allowlist ES256 (P-256), ES384 (P-384), RS256 (≥ 2048), EdDSA (Ed25519); the algorithm follows from the key, the header must match; `none`, HS*, unknown `crit`, `b64: false` refused; ES signatures only as R‖S of the right length; flattened JSON with exactly one signature; `url`, `nonce` and exactly one of `jwk`/`kid`; duplicate header names refused. RFC 7515 appendix A and RFC 7638 vectors, a negative test per rule, a fuzz test, lego as the end-to-end check |
| Q4 | DNS library | **`net.Resolver` with its own `Dial`** to `acme.resolver` |
| Q5 | Conformance tests in CI | **Yes**, in their own CI job, container images pinned by digest |
| Q6 | Authorization lifetime | **7 days** |
| Q7 | IP identifiers | **http-01 only**, only within `domain_ips` |
| Q8 | Wildcards | **dns-01 only**, per domain, **default off** |
| Q9 | Which CA signs | **Per domain** |
| – | Sealed server | newAccount, newOrder and challenges work; **finalize while sealed: the order stays `processing` with `Retry-After`, the certificate is issued at the unseal**; the dashboard shows "N ACME orders wait for the unseal" |
