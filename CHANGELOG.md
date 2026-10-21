# Changelog

All notable changes to MyOwnPKI are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
change the API, the configuration and the database schema; the release notes say how to upgrade.

## [Unreleased]

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

[Unreleased]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Der-Felix/MyOwnPKI/releases/tag/v0.1.0
