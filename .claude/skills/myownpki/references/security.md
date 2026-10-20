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
The admin listener takes `admin.allowed_networks` (checked against the direct peer before TLS, refusals
logged at most once a minute) and warns at start when it is reachable from other machines without one.
Separate `http.ServeMux` per listener so a route can't leak across.

## Authentication

Implemented in `internal/auth` (step 10); the numbers are PHASE1 decisions 39–48.

- Passwords: Argon2id (64 MiB, t=3, p=1, parameters in the hash); constant-time compare; at most 4
  hashes at once, the throttle is checked **before** a hash; unknown users cost a full hash too.
  12–256 characters, checked against the common password list, no composition rules, no expiry.
- Second factor mandatory: WebAuthn/passkeys (step 17) or TOTP (RFC 6238, 160-bit secret, a code
  works once). TOTP secrets are encrypted with the **auth key** (`auth.key_file`, outside the
  databases), bound to purpose and user ID. Recovery codes: ≥ 80 random bits (we use 100), single use,
  stored as HMAC keyed from the auth key.
- The second factor is fixed **at creation** (init on the console, reset-2fa): the first code only
  confirms it – never "enroll at first login", which would let whoever knows the password enroll.
- OIDC optional (Authentik, Keycloak, Entra ID): validate issuer, audience, nonce, PKCE.
- Sessions: server-side in `system.db` (only the SHA-256 of the ID), random 256-bit IDs, cookie
  `HttpOnly; Secure; SameSite=Strict; Path=/`, `__Host-` prefix, idle 30 min + absolute 12 h, new ID
  after the second factor; role changes, password change and disabling end sessions. Requests a page
  makes on its own (status, session polling) are passive by route and don't keep a session alive.
- CSRF: `http.CrossOriginProtection` (Sec-Fetch-Site/Origin) plus a synchronizer token for all
  state-changing requests (htmx sends it via a header set from a `<meta>` tag).
- Throttle (in memory, per IP+user and per user; unknown names one counter per IP; IPv6 per /64;
  pruning never drops a braking entry) and a time-limited lockout (never permanent: that would let
  anybody lock the admin out); `myownpki user unlock` ends it early. **Device cookies** (OWASP, step 13):
  a browser that completed a sign-in is judged by its own counter, not by the user lockout strangers
  cause; the cookie's HMAC covers a credentials epoch, so a new password, a new second factor or
  `user unlock` void it. Client IPs from `X-Forwarded-For` only behind `auth.trusted_proxies`.
- The last active instance admin and the last active admin of a tenant can't be disabled or lose
  the role.
- **Step-up auth** (fresh 2FA within 5 minutes) for: private key download, revocation, CA
  create/renew/retire/revoke, CRL upload, user/role changes, 2FA reset, API token creation (step 18).
- **Unseal = a signed-in instance admin + the passphrase** – the passphrase is the stronger proof,
  no extra step-up. Wrong passphrases are slowed down per instance and per client address. Changing your own password, authenticator or recovery codes needs the current
  password.
- Console emergencies (`user reset-2fa`) need the unseal passphrase or the recovery key: shell access
  to the server alone is not enough.
- Never log a typed user name of a failed login with an unknown user (it may be a password).
- The sign-in page shows nothing about the instance (version, seal state, demo mark) and one message
  for a wrong name, a wrong password and a lockout; a name that strangers locked costs a hash like
  an unknown one, so neither text nor answer time tells that it exists (step 14).
- Redirect targets from requests (`next=`) are local paths only; every POST of the UI ends in 303.
- API tokens: random, shown once, stored hashed, scoped (tenant, actions), expiring.

## Authorization (RBAC)

- Roles admin / operator / viewer, scoped by tenant, CA, domain, agent group (`internal/authz`;
  phase 1: tenant or one CA). Instance admins manage users and unseal – that gives no tenant rights.
  Viewers don't read the audit log (user names and IPs are personal data).
- Check permissions in the **service layer**, not only in HTTP handlers – the API, UI, ACME and agent
  paths all call the same services. `keys.Who.Principal` carries the caller; nil is denied; the
  console and system jobs have their own principals.
- Tenant ID comes from the authenticated context, never from a request parameter alone.
- Whoever may not read an object gets **404**, the same as for an unknown ID; whoever may read it but
  lacks the role for an action gets **403**. Nobody can probe which CAs or certificates exist.

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
- **Direct entries are fail-closed** (`internal/keys`, `internal/auth`): no unseal, sign-in or step-up whose
  entry can't be written – except actions that reduce power (seal, logout), which happen and report the error.
  **Outbox entries may pile up** while delivery fails; the server warns with count and age.
- Business changes reach the audit log through the outbox of their own database (same transaction);
  never write an audit entry and a business change "one after the other" across two databases.
- Export to syslog/SIEM (phase 5). `myownpki audit verify` walks every chain; `internal/audit` has
  `Enqueue` (in the business transaction), `Append` (direct events) and `Verify`.

## Transport and headers (admin listener)

- TLS 1.2+ (1.3 preferred, Go negotiates the hybrid post-quantum key exchange), HSTS `max-age=31536000` without includeSubDomains/preload, `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`
  (relax only for documented needs, e.g. sandboxed plugin iframes later).
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Permissions-Policy` minimal.

## Supply chain

- Pin dependencies (`go.sum`), run `govulncheck` in CI, review new dependencies (license + maintenance).
- Releases: GoReleaser, cosign signatures, SBOM (syft). Containers: distroless, non-root, read-only rootfs.
