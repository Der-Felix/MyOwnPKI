# Changelog

All notable changes to MyOwnPKI are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
change the API, the configuration and the database schema; the release notes say how to upgrade.

## [Unreleased]

### Fixed

- **Agent packages in the container image:** the image carries the agent packages under
  `/opt/myownpki/agent-dist`, but nothing pointed `agent.package_dir` there, so a container served
  none of them. The image now sets `MYOWNPKI_AGENT_PACKAGE_DIR=/opt/myownpki/agent-dist`.
  Installations with install.sh were not affected.

## [0.3.2] - 2026-10-29

A fix release: the server now serves the agent packages it installs.

### Fixed

- **Agent packages on the agent listener:** a v0.3.1 server answered every `/agent-packages/`
  download with 404, because it named the packages after its full version line instead of the
  release version. Guided agent installation therefore found no package, and the agent list did
  not mark older agents for update. No migrations; update the server, then the agents.

## [0.3.1] - 2026-10-28

Guided agent installation and packages, independent Windows trust confirmation, configurable
step-up and protected-action continuation, and safe predecessor handling for UI, REST, ACME and
agent deployments.

### Added

- **Independent root trust verification:** the public trust page, authenticated CA details and guided
  agent installation show authoritative SHA-256 and display-only SHA-1 for Windows certificate dialog
  comparison. Root CA details expose an exact 64-hex SHA-256 automation value; pending CAs show no
  empty fingerprints. Windows helpers no longer embed an expected hash: they compute both values and
  import only after a matching independent `-ExpectedSha256` or explicit interactive SHA-256
  confirmation. Strict argument validation, changed/mismatched certificate refusal, quiet-mode fail
  closed behavior and elevated-child reauthorization prevent accidental or self-confirmed imports.
- **Guided Linux agent setup and packages:** GoReleaser nFPM builds `.deb` and `.rpm` for Linux
  amd64/arm64 with a `noreplace` conffile, example systemd files and no maintainer scripts or
  autostart. The shared `myownpki-agent setup` verifies the independent root SHA-256, securely reads
  optional join-token files, writes configuration/units atomically, preserves custom configuration,
  polls pending enrollments and enables or restarts only enrolled agents. Tarballs and packages use
  the same implementation. `install-agent.sh` is now a deprecated verified-download forwarding
  wrapper with default version 0.3.1.
- **Verified agent distribution and guided installation:** `install.sh` stages the exact release's
  `.deb`, `.rpm` and tarballs for both Linux architectures after checking every artifact against
  `checksums.txt`, and restores the previous complete distribution when a server update rolls back.
  Docker contains the same immutable files under `/opt/myownpki/agent-dist`; `agent.package_dir`
  selects the host/container directory. The agent listener allows anonymous `GET`/`HEAD` only for
  the manifest-listed artifacts and checksums, with exact-name, size, method, traversal and symlink
  protections; RPC authentication is unchanged. *Agents → Install agent* requires admin and fresh
  step-up and generates the full verified download/install/setup flow from independent UI root and
  package hashes. Its optional exact-host token is one-use, expires after 15 minutes, appears only
  in the one-time response and is consumed through a 0600 file, never argv, URLs or logs. Agent
  reports additively carry the installed format (pki.db migration 0015 and protobuf field 5), and
  strict SemVer update hints cover only older agents, including correct prerelease ordering and no
  suggested downgrade.
- **Configurable predecessor handling on renewal:** choose immediate, delayed (1–30 days) or no
  revocation, always with reason `superseded`. Tenant defaults are independent for agent deployments
  and other certificates, with agent-wide, per-deployment and one-operation overrides. Current
  migration defaults are owner-confirmed (agent: immediately after confirmed deployment; other
  certificates: after seven days), recorded in `docs/PHASE3.md` §8.4.
  Non-agent ACME renewals require the same account and exact normalized name set, with an optional
  admin-audited per-account override in UI and REST; shared accounts should use one per host or
  `never`. Agent actions
  start only at an accepted deployed report with exact proof: a served TLS fingerprint always wins,
  with the leaf fingerprint read back after the atomic write as the check-less fallback. A written
  fingerprint never replaces a missing TLS proof and legacy agents without either field cause no action. Exact
  account/order/name mapping and a real serial transition are required; failed, rolled-back,
  currently serving, foreign-account and ambiguous certificates are protected. Delayed agent plans
  start at server-recorded deployment time and repeated reports never duplicate or move plans.
- **Planned revocations:** certificate lists/details and agent deployments show `Revocation planned`,
  the certificate filter and dashboard cover plans due within seven days, and authorized users can
  plan, cancel or revoke now with step-up and audit. The scheduler executes due plans idempotently,
  including restart/unseal catch-up; CRL publication follows the committed transaction through the
  existing CRL jobs. Additive system.db migration 0013 and pki.db migration 0014 create no revocations
  or schedules on upgrade with unchanged serials. REST adds renewal policy fields, plan/cancel
  endpoints, planned timestamps and agent/deployment policy endpoints; legacy `revoke_previous`
  remains supported.
- **Web action continuation after step-up:** protected forms show a safe action summary and run once
  after the second factor, without asking for their inputs again. In-memory pending actions use
  256-bit IDs in POST fields only, are bound to the session, user and credentials epoch, expire after
  five minutes independently of the configured proof lifetime, and are consumed atomically before
  the existing authorized handler. Replay, concurrent clicks, restart and business failure cannot
  repeat the action; downloads, one-time secrets and multipart legacy imports keep their response
  behavior. A new confirmation replaces the session's previous one, global entry/archive budgets
  reject unbounded growth, and every store operation reclaims expired state. REST step-up responses
  and the OpenAPI contract are unchanged.
- **Tenant-configurable step-up lifetime:** tenant admins can choose 5, 10, 15, 30 or 60 minutes
  (default 5) in *Tenant settings* or through the additive `step_up_minutes` REST field. Changes
  are audited and apply only to new TOTP, recovery-code and passkey proofs; each session snapshots
  the lifetime, so existing proofs are unchanged. system.db migration 0012 adds the setting and
  per-session snapshots, with five minutes retained for existing sessions.

## [0.3.0] - 2026-10-25

The Linux agent: trusted enrollment, ACME issuance, atomic deployment with rollback, scheduled
renewals and operator-requested renewal through the web UI and REST API. Linux packages and a
hardened systemd installation complete the release.

### Added

- **ACME in the agent** with lego v4.35.2 as a library: a local account key registered by
  thumbprint over mTLS, host-generated certificate keys and http-01 in standalone/webroot mode.
  Its own HTTP client ignores environment proxy and lego trust settings. Linked accounts are
  restricted to the active agent's allowed names at order creation, finalization and issuance,
  including after an unseal; ordinary ACME clients keep their normal domain policy. Account key
  rotation preserves the binding. Existing accounts cannot be captured by a new thumbprint
  reservation; denials are audited. Re-enrollment with a new agent ID and the old ACME key stops
  with an operator-action message. pki.db migration 0012 enforces unique reservations and links.
- **nginx and file deployment profiles**: contained, atomic PEM writes with owner/group/mode,
  shared test/reload hooks and a local TLS fingerprint check. Failed activations roll back the
  whole reload group; first-install failures remove the new files. Mixed groups test the restored
  configuration and reload existing deployments back to their old leaf when safe. A durable journal recovers an
  interrupted pass before new work, and local status shows deployment results. A failed rollback
  reports both errors without a retry loop.

- **Agent listener** (`agent.base_url`, `agent.listen` default `:8444`, `agent.tls_issuer`,
  `agent.ca`): Connect-RPC over TLS 1.3. Its certificate comes from `agent.tls_issuer` like the admin
  and ACME listeners'. Client certificates are accepted from the agent CA only – an intermediate with
  the EKU limit clientAuth only, checked by `myownpki config check` and at the start. Without a
  certificate only the enrollment answers; everything else is checked per request (a revoked or
  disabled agent is cut off at its next call).
- **Enrollment with proof of control** (ADR-18): the agent makes its key and CSR on the host; the
  server fetches a check file bound to that key from `http://<host>/.well-known/acme-challenge/`
  (the agent's own port 80, or the webroot of the web server already there – written only through
  an `os.Root`, so a symlink can't redirect it) with the rules of the ACME validator. Modes per
  tenant (`auto`, `verified` – the default –, `manual`; *Tenant settings*, `agent_enrollment` in
  `PUT /api/v1/settings`, system.db migration 0011). Join tokens: single-use, expiring, for name
  patterns, stored hashed, shown once. The queue holds at most 100 enrollments without a valid
  token – one with a token is never refused – and junk expires after 24 hours.
- **Agent certificates**: 7 days, renewed by the agent at 2/3 with a new key (at most 6 renewals per
  agent and hour); an agent whose certificate expired enrolls again with the key of its last one.
  Revoking an agent puts its agent certificates on the CRL. pki.db migration 0011.
- **`myownpki-agent`** `enroll [--token-file FILE]`, `run`, `status`, `config check` with
  `/etc/myownpki-agent/agent.yaml`. It ignores `HTTPS_PROXY`/`HTTP_PROXY`; a proxy only when
  agent.yaml names one.
- **REST API** `/agents`, `/agent-enrollments`, `/agent-join-tokens` (permission `agent.manage`,
  admin with step-up), and the pages *Agents*, *Enrollment requests*, *Join tokens*.
- **Reports and renewal scheduling:** a heartbeat every five minutes with jitter and one combined
  report after each deployment pass; 2/3-lifetime scheduling with ARI support, persistent failure
  backoff and a silent-agent indicator after three missed reports.
- **Renew now and Withdraw:** operator/admin actions in the UI and REST API wake the agent through
  a bounded long-poll. Versioned acknowledgements prevent stale reports from clearing newer requests;
  CSRF, role checks and audit entries cover both actions. Agent pages show deployments, disallowed
  names and removed configurations. The certificate filter hides agent identity certificates by
  default, while deployment certificates stay visible.
- **Linux packaging:** `install-agent.sh`, a hardened root systemd unit with explicit writable-path
  drop-ins, and reproducible Linux amd64/arm64 agent archives. The script verifies the downloaded
  archive against the signed checksum file, never overwrites agent.yaml and updates without
  self-update magic. The `agent end-to-end` CI job runs real ACME/agent flows and nginx rollback,
  measures `systemd-analyze security`, and checks protobuf compatibility with `buf breaking`.
- New modules (owner 2026-10-24): `connectrpc.com/connect` v1.21.0, `google.golang.org/protobuf`
  v1.36.12; buf v1.73.0 as a pinned development tool (THIRD_PARTY.md).

### Changed

- Reports and desired-state watches have per-agent rate limits (60 and 120 per 10 minutes) to
  protect the SQLite writer and audit log from a compromised agent. The dashboard excludes agent
  identity certificates from ordinary 30-day expiry views and warns per active agent when its
  current certificate has less than 48 hours left.
- pki.db migration 0013 stores reported deployments and renewal requests. The release now has 18
  assets, including the two agent archives and `install-agent.sh`.

### Fixed

- Enrollment without a matching domain stores a clear failed check instead of panicking; the
  service and Connect-RPC both return the pending enrollment with that explanation.
- Handler panics are logged at error level with the RPC procedure and stack on the agent listener;
  HTTP server panics are also logged at error level on the admin and ACME listeners. Panic messages
  remain visible when the configured log level is info, while TLS handshake noise stays at debug.
- Domain creation and editing require a signing CA whose EKU limit allows serverAuth, in the form
  and in the service and REST API. New forms start with "Please select" instead of the first CA.
- `install-agent.sh` no longer claims that a token file was kept when enrollment ran without one.
- nginx test and reload hooks need `20-low-ports.conf` for listeners below 1024, including webroot
  mode. `install-agent.sh --low-ports` installs that capability explicitly.
- Failed hooks include sanitized, bounded stderr in the agent log and deployment `last_error`:
  valid UTF-8 at every boundary, the final diagnostic lines preserved, Unicode format characters
  removed and the complete error within the server limit, including rollback failures.
- Renewal requests appear as status badges with a separate Withdraw action, deployment tables wrap
  without horizontal overflow, and removable agent names have a per-row Remove action instead of a
  separate form.
- The Windows trust-page text requires comparing the root fingerprint with an independently obtained
  value from the admin UI or an administrator, not with the file that carries the root itself.
- Agent end-to-end CI runs `nginx -t` on port 443 under the real systemd unit, first proving the
  failure without the low-port drop-in and then success with it. The exported nginx rootfs has the
  package's temporary directories, and the negative-control log is written with `tee`.

## [0.2.2] - 2026-10-24

The server can issue the TLS certificates of its own listeners from one of its intermediates, so
ACME works without a reverse proxy; a daily backup timer for systemd installations; and a public
trust page that hands out the root certificates. Without `tls_issuer` the listeners keep their
bootstrap or configured certificate, and the proxy way for ACME stays the default. **Upgrade from 0.2.1 with install.sh:** run the 0.2.2 `install.sh` as
before – backup, new binary, migration (system.db 0010), health check; it now also installs the
daily backup timer and enables it once (`--no-backup-timer` keeps it off). An installed
`public-port-80.conf` stays. This `install.sh` installs 0.2.2 and later only; for an older release
use that release's `install.sh`. **Docker installations:** back up, pull the 0.2.2 image, start; the
backup timer is for systemd installations. The trust page appears at `/` of the public listener in
both cases – switch it off in *Tenant settings* if you don't want it.

### Added

- **The server issues its own TLS certificates** from a CA of the instance: `admin.tls_issuer` for
  the admin listener (the names of `admin.tls_names`), `acme.tls_issuer` for the ACME listener (the
  host of `acme.base_url`). Through the normal CA engine – preset *server*, ECDSA P-256, the CA's
  name constraints, an audit entry by *system* – for 90 days at most (never beyond the CA's maximum
  or end), renewed at 2/3 and at once after a revocation, a name change or a CA renewal. Issued
  only while unsealed; key and fullchain lie in `<data_dir>/tls/` (key 0600), so a sealed restart
  serves them. When one expires while sealed, the listener falls back to its bootstrap
  certificate with a warning in the log and on the dashboard; the switch needs no restart.
  A **root CA** as `tls_issuer` is refused with the fix ("CA root is a root – name the issuing
  intermediate …") at the start, on the dashboard and in `myownpki config check` (a warning when
  the CA database is readable); the listener then serves its bootstrap certificate.
  docs/OPERATIONS.md §2.4.
- **ACME without a reverse proxy:** with `acme.tls_issuer`, `acme.listen` speaks TLS itself (e.g.
  `":443"`); every client may connect, the peer is the client address for rate limits and audit,
  `acme.trusted_proxies` and `X-Forwarded-For` are ignored. The proxy way stays the default.
  docs/OPERATIONS.md 10.10.

- **Daily backups:** `myownpki-backup.service` and `.timer` (daily, random delay up to an hour,
  missed runs caught up), installed and enabled by install.sh (`--no-backup-timer`,
  `--backup-keep N`, default 14). Each run writes `/var/backups/myownpki/<UTC time>`, verifies it
  and prunes; the unit has the server's sandbox and no network. docs/OPERATIONS.md §6.1.
- **`myownpki backup scheduled DIR --keep N`** (the timer's run: backup, verify, prune) and
  **`myownpki backup prune DIR --keep N [--dry-run]`**. Prune deletes only complete scheduled
  backups (named like `20261025T003512Z`, a valid `manifest.json`, exactly the listed files) –
  never install.sh's update backups, a backup that failed its check (`…-unverified`) or anything
  else.
- **Backup warnings on the dashboard:** a `…-unverified` backup in `/var/backups/myownpki`, or a
  newest timer backup older than 48 hours (timer off or failing) – once the timer is installed or
  has written a backup. The server only reads the directory; its unit needs no new rights.
  docs/OPERATIONS.md §6.1.
- **Public trust page** at `/` of the public listener, without sign-in: every active CA (roots
  first) with name, common name, validity and SHA-256 fingerprint, DER and PEM downloads, guides
  for Windows, macOS, iPhone/iPad, Android, Linux and Firefox. No JavaScript, a strict CSP,
  cached. On by default; *Tenant settings* or `trust_page` in `PUT /api/v1/settings` switch it off
  (system.db migration 0010). docs/OPERATIONS.md chapter 11.
- **Windows helpers** per root on the trust page: a `.cmd` (Batch/PowerShell in one file, ASCII,
  CRLF) for *this computer* (asks for administrator rights) or *my user only*; it checks the
  SHA-256 of the embedded root before the import and stops if the file was changed; `/check`
  only checks, an unknown switch never imports.
- `/ca/<name>/<generation>.pem`: the CA certificate as PEM.
- **`install.sh --acme https://NAME/acme`** (with `--acme-ca`, default `issuing`) writes the ACME
  keys for its own TLS into a new config and installs the drop-in for port 443.

### Changed

- `myownpki healthcheck` accepts the bootstrap and the issued admin certificate (with
  `admin.tls_issuer`); `myownpki config check` shows `tls_issuer` and the ACME mode.
- The drop-in `public-port-80.conf` is now `low-ports.conf` – for every listener on a port below
  1024 (`--public-port-80`, `--acme`). An installed `public-port-80.conf` keeps working and stays;
  the archives still carry it.
- CI: the install job installs with `--acme`, unseals through the API and reads the ACME directory
  over TLS with the root as trust anchor; `systemd-analyze security` is measured with the drop-in
  and must stay below 2.0. The conformance job runs lego and certbot directly against the own TLS
  listener.

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

[Unreleased]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Der-Felix/MyOwnPKI/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Der-Felix/MyOwnPKI/releases/tag/v0.1.0
