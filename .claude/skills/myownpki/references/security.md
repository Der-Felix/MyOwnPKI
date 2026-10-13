# Security rules

MyOwnPKI is a CA: whoever controls it can impersonate every host in the organisation.
Design every feature as if the admin UI were reachable from the internet (ADR-08 lets the
operator decide, so the product must be safe in the worst case).

## Listeners (ADR-08)

| Listener | Serves | Auth |
|---|---|---|
| Public (:80/:443) | ACME, CRL, OCSP, AIA (CA certs) | none by design – read-only or ACME-protocol only |
| Agent (:8443) | Connect-RPC for agents | mTLS with an `agent-ca` certificate |
| Admin (:9443) | Web UI + REST API | session (2FA) or API token; optional mTLS + IP allowlist |

Never mount admin routes on the public listener, not even "just for health checks".
Separate `http.ServeMux` per listener so a route can't leak across.

## Authentication

- Passwords: Argon2id with OWASP-recommended parameters or stronger; constant-time compare.
- Second factor mandatory: WebAuthn/passkeys (preferred) or TOTP. Recovery codes hashed.
- OIDC optional (Authentik, Keycloak, Entra ID): validate issuer, audience, nonce, PKCE.
- Sessions: server-side in `system.db`, random 256-bit IDs, cookie `HttpOnly; Secure; SameSite=Strict; Path=/`,
  `__Host-` prefix, idle + absolute timeout, rotate on login and privilege change.
- CSRF: synchronizer token for all state-changing requests (htmx sends it via a header set from a `<meta>` tag).
- Rate limiting and lockout on login, TOTP and API token endpoints.
- **Step-up auth** (fresh 2FA within N minutes) for: private key download, revocation, CA create/renew,
  unseal, role/permission changes, API token creation.
- API tokens: random, shown once, stored hashed, scoped (tenant, actions), expiring.

## Authorization (RBAC)

- Roles admin / operator / viewer, scoped by tenant, CA, domain, agent group.
- Check permissions in the **service layer**, not only in HTTP handlers – the API, UI, ACME and agent
  paths all call the same services.
- Tenant ID comes from the authenticated context, never from a request parameter alone.

## Key storage (ADR-09)

- Online-encrypted mode: envelope encryption in `internal/keys`. KEK derived from the unseal passphrase (Argon2id),
  wraps a random root key; one DEK per key, AES-256-GCM, purpose and key ID bound as additional data.
  A recovery key is a second wrap of the root key. Never log or print the passphrase or recovery key
  (`RecoveryKey` is redacted except `Reveal()`); use the private key only inside `WithKey`/`WithSigner`.
- The server starts **sealed**; no signing until unsealed. Unseal state is in memory only.
- Private key material: keep in memory as briefly as possible, zero buffers where Go allows (best effort),
  never log, never put in error messages, never send to the browser except an explicit, audited,
  step-up-authenticated download.
- HSM mode via PKCS#11 behind the `hsm` build tag (needs CGO).

## Untrusted input

- CSRs, uploaded certificates/archives, ACME JWS payloads, agent reports, OIDC claims: all untrusted.
- Size limits on every body (`http.MaxBytesReader`), on archive entries and total unpacked size.
- Archives: reject absolute paths, `..`, symlinks (zip-slip).
- Output escaping is automatic in templ – never use `templ.Raw` / unsafe HTML with data from users or certificates.
- PEM parsing: accept only expected block types; reject trailing garbage.

## ACME validation = outbound requests to attacker-chosen names (SSRF)

The http-01 and tls-alpn-01 validators connect to hostnames an ACME client chose.
- Only ports 80 (http-01) / 443 (tls-alpn-01); follow redirects only to 80/443 and only a few hops.
- Short timeouts, response size limit, no credentials, dedicated `http.Client`.
- Resolve once and connect to the resolved IP (no DNS rebinding between check and connect).
- Configurable address policy per CA: an internal CA must reach internal networks, a public-facing
  deployment may want to block RFC 1918/loopback/link-local. Never allow the server's own admin listener.
- The same rules apply to the agent enrollment check (ADR-18).

## Agent trust

- Enrollment modes `auto` / `verified` (default) / `manual` (PLAN §6.2). A passed challenge proves
  control of a name, not authorization – that's why `verified` needs token **and** challenge.
- Join tokens: single-use, short-lived, scoped to tenant + allowed name patterns, stored hashed.
- An agent may only request certificates for names bound to its identity (policy check server-side).
- **No remote command execution.** The server can only trigger hooks the agent's local config allowlists.
- Agent certificates are short-lived and renewed over the existing mTLS channel; revocation takes effect immediately.

## Audit log

- Append-only table in `audit.db`; each entry stores the hash of the previous entry (hash chain).
- Log who, what, when, from where, target object, result – never secrets or key material.
- Entries hold personal data (user name, source IP): store only what security needs, no user agent
  or request free text; single entries can't be deleted (hash chain) – see PLAN §5 for the GDPR note.
- Business changes reach the audit log through the outbox of their own database (same transaction);
  never write an audit entry and a business change "one after the other" across two databases.
- Export to syslog/SIEM (phase 5). `myownpki audit verify` walks every chain; `internal/audit` has
  `Enqueue` (in the business transaction), `Append` (direct events) and `Verify`.

## Transport and headers (admin listener)

- TLS 1.2+ (prefer 1.3), HSTS, `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`
  (relax only for documented needs, e.g. sandboxed plugin iframes later).
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Permissions-Policy` minimal.

## Supply chain

- Pin dependencies (`go.sum`), run `govulncheck` in CI, review new dependencies (license + maintenance).
- Releases: GoReleaser, cosign signatures, SBOM (syft). Containers: distroless, non-root, read-only rootfs.
