# Changelog

All notable changes to MyOwnPKI are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
change the API, the configuration and the database schema; the release notes say how to upgrade.

## [Unreleased]

## [0.2.1] - 2026-10-24

Install and update MyOwnPKI as a hardened systemd service with one command: `install.sh`
(docs/OPERATIONS.md §2.1) – no Docker needed. The server itself is unchanged. **Docker
installations:** nothing changes – back up, pull the 0.2.1 image, start, as before. Upgrade from
0.2.0 without Docker: as before (backup, replace the binary, start); or run `install.sh` once – it
keeps an existing `/etc/myownpki/config.yaml` and `/var/lib/myownpki`.

### Added

- **`install.sh`** – installs or updates MyOwnPKI as a systemd service with one command, on Linux
  with systemd (amd64, arm64); a release asset of its own (listed in the signed `checksums.txt`)
  and in every archive. It checks the archive's SHA-256 and, when cosign is installed, the Sigstore
  signature before it installs anything; creates the user `myownpki`, `/var/lib/myownpki` and – only
  if there is none – `/etc/myownpki/config.yaml` (admin listener on the own /24s, the names from
  `hostname -f` and the own addresses, or `--tls-names`, `--admin-listen`, `--allowed-networks`);
  enables the service without starting it and prints the next commands. An update makes a backup
  and `backup verify` first and puts the old binary back – and ends with an error – unless the
  service comes back healthy and runs the new version.
  `--archive` installs from a local archive (machines without internet). docs/OPERATIONS.md §2.1.
- **systemd unit** `deploy/systemd/myownpki.service` with a strict sandbox (no capabilities,
  read-only system except the data directory, private users and devices, a system call filter;
  `systemd-analyze security` rates it 1.2, "OK"), and the drop-in `public-port-80.conf` for the public
  listener on port 80 without a reverse proxy (`--public-port-80`).

### Changed

- The release has 13 assets (`install.sh` added); the archives also hold the unit, the drop-in and
  `install.sh`.

## [0.2.0] - 2026-10-23

The ACME server (phase 2 of docs/PLAN.md). Upgrade: back up, replace the binary, start – the
migrations run at start; ACME stays off until `acme.base_url` is set, and it runs only behind a
reverse proxy that ends TLS. Read chapter 10 of docs/OPERATIONS.md before switching it on.

### Added

- **ACME server** (RFC 8555) for certbot, acme.sh, lego, Traefik, Caddy and other clients: accounts
  (with key change and deactivation), orders, http-01 and dns-01 challenges, finalize, certificate
  download with the chain, revocation (by the account, by an account that holds the names, or with
  the certificate's own key). Issuance goes through the same policy engine as the UI.
- **Domains** (*ACME → Domains*, `/api/v1/domains`): which names ACME issues for, the signing CA,
  the challenges, wildcards (dns-01 only), the preset and validity (default 90 days), which
  addresses http-01 may reach, and IP ranges for IP certificates.
- **Approvals**: per domain *open*, *approved accounts* (default) or *new names*; queues for
  accounts and names in the UI, EAB keys (external account binding) shown once, dashboard notices
  for what waits.
- **ARI** (RFC 9773): clients ask when to renew – the window opens at 2/3 of the lifetime; a revoked
  certificate is renewed at once; renewals name the certificate they replace.
- **Rate limits** as tenant settings: new orders per account, failed validations per name, new
  accounts per client address (IPv6 per /64); `429` with the real `Retry-After`.
- A sealed server keeps taking orders: certificates of finalized orders are issued at the unseal.
- Configuration `acme.base_url`, `acme.listen` (default `127.0.0.1:8081`), `acme.trusted_proxies`,
  `acme.resolver`; examples for Caddy, nginx and Traefik in docs/OPERATIONS.md.
- *ACME → Orders* lists the newest orders with their result.
- Tested in CI against real clients: lego, certbot (http-01, dns-01 with certbot-dns-rfc2136 against
  BIND, revocation) and acme.sh; Pebble as a control.

### Changed

- `PUT /api/v1/settings` takes an optional `acme_limits`; left out, the stored limits stay
  (clients of 0.1 keep working). The answer always contains it.
- Table cells in the UI can wrap long values (error details, contacts).

### Security

- ACME runs only behind a reverse proxy that ends TLS; the plain-HTTP listener answers only the
  addresses in `acme.trusted_proxies`, and no URL is built from `X-Forwarded-Host`/`-Proto`.
- JWS and JWK in own code with the standard library only: a fixed list of algorithms (ES256,
  ES384, RS256 with at least 2048 bits, EdDSA), strict parsing (duplicate members, `b64:false`,
  unknown `crit` and `none`/HS* refused); fuzz-tested.
- The validator resolves once and connects to exactly the checked address (no DNS rebinding),
  never to loopback or link-local, only to ports 80/443, follows redirects only within the order,
  and never tells the client what a target answered – it can't be used to read the inside network.
- EAB keys are stored encrypted with the key ring and overwritten when used.
- **Unseal refuses weak key derivation parameters:** a key ring whose stored Argon2id parameters
  are below t=4, 256 MiB, p=4 is refused (audited as `denied`, reason `weak_kdf`). Every release so
  far stored exactly these values, so existing installations are not affected; weaker values come
  only from test builds. Way out: unseal with the recovery key, or `myownpki passphrase reset`, and
  set a new passphrase – it is stored with the production values.

### Fixed

- Release notes on GitHub: the release draft had an empty text, because GoReleaser's changelog
  step – the one that reads the notes from CHANGELOG.md – was disabled. (The v0.1.0 notes were
  added by hand.)

## [0.1.0] - 2026-10-22

The first release: MyOwnPKI replaces the `pki.sh` Bash suite in the browser (phase 1 of
[docs/PLAN.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/PLAN.md)). Start with [docs/OPERATIONS.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/OPERATIONS.md).

### Added

- **CA engine**: root and intermediate CAs (online, or an offline root with the signing bundle for
  OpenSSL), CA renewal with a new key, retirement and revocation; leaf certificates from a CSR or
  with a server-generated key; built-in presets (server, client, server-client, S/MIME, code
  signing, timestamping, OCSP, custom) ported from `pki.sh`; name constraints, CA limits and the
  policy checks of PLAN §6 – extensions always come from the preset, never from the CSR.
- **Revocation and CRLs**: revocation with RFC 5280 reasons (keyCompromise blocks the key for later
  requests), CRLs signed at once and renewed in the background, the offline root's CRL uploaded;
  CRLs and CA certificates on the public listener, including the URLs of imported `pki.sh` CAs.
- **Key protection**: every CA and certificate key encrypted (AES-256-GCM under a root key wrapped
  with an Argon2id key from the unseal passphrase, plus a recovery key); the server starts sealed;
  seal and unseal audited; `myownpki passphrase change` and `passphrase reset` (with the recovery
  key).
- **Audit log**: hash-chained instance and tenant logs with signed checkpoints;
  `myownpki audit verify` and the audit pages.
- **Sign-in**: password (Argon2id, common-password check) plus TOTP and recovery codes, passkeys as
  second factor when `auth.passkey_origin` is set (through the API only, see below), step-up for dangerous actions, lockout and
  throttling, roles per tenant (viewer, operator, admin) and instance admins; API tokens.
- **REST API** `/api/v1` (OpenAPI 3.1 in `api/openapi.yaml`, 58 operations, RFC 9457 problems).
- **Web UI**: dashboard, certificates (issue wizard, detail, revoke, renew, download, export as
  PKCS#12 or PEM with "delete the key afterwards"), CAs including the offline signing flow, presets,
  users and roles, tenant settings, audit log, legacy import, own account; light and dark theme;
  no inline styles or scripts (strict CSP).
- **Legacy import** of a `pki.sh` directory (`myownpki import legacy`, or an archive upload in the
  UI): serial numbers, revocations (time and reason) and CRL numbers stay identical; dry run first.
- **Backup and restore**: `myownpki backup` while the server runs, `backup verify`, `restore` with
  hash, integrity, audit-chain and name-index checks.
- **Operations**: `myownpki init` (interactive, `--stdin` for automation, `--demo`),
  `myownpki healthcheck`, `config check`, `db status` / `db migrate`, `user unlock` / `reset-2fa`;
  a self-signed bootstrap certificate for the admin listener with its fingerprint in the log.
- **Release**: archives for linux/amd64, linux/arm64, darwin/arm64, windows/amd64 and
  freebsd/amd64 (pure Go, reproducible), SPDX SBOMs, a checksum file signed keyless with cosign,
  and the container image `ghcr.io/der-felix/myownpki` (distroless, non-root, signed);
  `deploy/docker-compose.yml` for a single server.

### Security

- Built with Go 1.27.3 (fixes GO-2026-6809 / CVE-2026-111943: `crypto/x509` now refuses known
  compromised intermediate certificates when verifying a chain).

### Known limitations

- No ACME server yet (v0.2), no agent and no monitoring yet (v0.3) – see the release plan in
  [docs/PLAN.md](https://github.com/Der-Felix/MyOwnPKI/blob/v0.1.0/docs/PLAN.md) §10.1.
- **Passkeys work only through the REST API in v0.1** – registering one, and using it to sign in
  or to confirm an action (`/api/v1/auth/webauthn/*`, `/api/v1/users/me/webauthn`). The web UI
  has no passkey button yet: it needs a small browser script that is not approved yet (ADR-04).
  The UI lists a user's passkeys and removes them; sign-in in the browser uses the authenticator
  app (TOTP).
- One tenant (`default`); the tenant UI comes later.

[Unreleased]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Der-Felix/MyOwnPKI/releases/tag/v0.1.0
