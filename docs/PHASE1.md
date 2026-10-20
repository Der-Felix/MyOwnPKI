# Phase 1 – plan

> Written at the end of phase 0; the owner answered the open questions on 2026-10-13 (§4).
> §2 is the agreed work plan. The data model (§1) is still a proposal that each step refines.

Goal of phase 1 (PLAN §10): data model, CA engine, importer, REST API, login with 2FA, RBAC,
unseal, audit log, UI for issue / revoke / upload / download in layout B –
**"pki.sh replaced in the browser"** – released as **v0.1** (PLAN §10.1 release plan to v1.0).

---

## 1. Data model

Principles: one SQLite file per purpose and tenant (ADR-06), one transaction never spans two
files, cross-database effects go through an **outbox** table. Phase 1 runs a single tenant
(`tenants/default/`), but every path is already tenant-aware so phase 5 needs no migration.
All times are stored as UTC (`TEXT`, RFC 3339 with `Z`); serials and fingerprints as upper-case hex.

### 1.1 `tenants/<t>/pki.db`

```
cas                                   -- the CA as configured (migration 0004, step 7)
  id               TEXT PK            -- opaque ID (internal/ids: prefix + time-sortable Base32)
  name             TEXT UNIQUE        -- legacy directory name (root, issuing, …); never changes (in every AIA/CRL URL)
  kind             TEXT               -- root | intermediate
  parent_id        TEXT NULL → cas.id
  status           TEXT               -- active | pending_signature | retired
  key_mode         TEXT               -- offline | online_encrypted | hsm (ADR-09)
  current_generation INTEGER NULL     -- the generation that signs new certificates
  path_len         INTEGER NULL
  nc_critical      INTEGER            -- name constraints critical (compat switch)
  eku_limit        TEXT               -- JSON array of dotted EKU OIDs (legacy EKU_LIMIT); [] = no limit
  public_base_url  TEXT               -- no trailing slash; immutable once the CA has signed anything
  crl_days         INTEGER
  crl_number       INTEGER            -- strictly increasing across all generations; preserved by the importer
  max_validity_days INTEGER           -- caps every issuance (presets, API, ACME default 90 days)
  created_at, updated_at TEXT

ca_generations                        -- one row per CA key and its certificate (AD CS "CAName(1).crt")
  ca_id → cas.id, generation INTEGER  -- PK (ca_id, generation); 1, 2, … – a renewal with a new key adds one
  key_id           TEXT NULL → keys.id -- NULL for offline keys
  key_algorithm, subject_dn TEXT
  serial_hex, not_before, not_after, ski_hex TEXT NULL
  cert_der         BLOB NULL          -- NULL while pending_signature; set once, then immutable
  csr_der          BLOB NULL          -- offline-signing flow
  fingerprint_sha256 TEXT UNIQUE
  issuer_ca_id, issuer_generation → ca_generations  -- the parent generation that signed it; NULL for a root
  created_at       TEXT

ca_name_constraints
  ca_id → cas.id, kind (dns|ip|email|uri), value, permitted (1) / excluded (0)

certificates
  id               TEXT PK
  ca_id            TEXT NULL → cas.id  -- NULL for external certificates
  ca_generation    INTEGER NULL       -- (ca_id, ca_generation) → ca_generations: the key that signed it
  source           TEXT               -- issued | imported | external
  preset           TEXT NULL
  serial_hex       TEXT               -- UNIQUE (ca_id, serial_hex): per CA across all generations (same issuer name)
  subject_dn, common_name TEXT
  not_before, not_after TEXT
  key_algorithm    TEXT
  key_id           TEXT NULL → keys.id -- only for server-generated keys
  cert_der         BLOB
  fingerprint_sha256 TEXT UNIQUE
  renewal_of       TEXT NULL → certificates.id
  requested_by     TEXT               -- user/token ID (display only; truth is in the audit log)
  custom_ku, custom_eku TEXT NULL     -- customizable presets (legacy CUSTOM_KU/EKU)
  created_at       TEXT

certificate_sans
  certificate_id → certificates.id, type (dns|ip|email|uri), value   -- INDEX (type, value)

revocations                           -- migration 0005 (step 9); final: no update, no delete
  certificate_id   TEXT PK → certificates.id
  reason           TEXT               -- RFC 5280 names, final reasons only (no certificateHold)
  revoked_at       TEXT
  invalidity_date  TEXT NULL          -- keyCompromise/cACompromise
  revoked_by       TEXT

ca_revocations                        -- revoked CA generations; final
  ca_id, generation → ca_generations, reason (+ cACompromise), revoked_at, invalidity_date, revoked_by
  source           TEXT               -- server (online parent) | root_crl (found in an uploaded offline root CRL)

crls                                  -- every CRL ever published, kept as evidence; immutable
  ca_id, generation → ca_generations, number, this_update, next_update, crl_der   -- PK (ca_id, number): strictly increasing per CA
  source           TEXT               -- signed (by the server) | uploaded (offline root: signed offline, checked on upload)

blocked_keys                          -- keys reported compromised; immutable, per tenant
  spki_sha256 PK, reason (keyCompromise|cACompromise), source_type (certificate|ca), source_id, blocked_at, blocked_by

cas.legacy_urls  INTEGER              -- set by the importer: serve <base>/<name>.crt|.crl as aliases of generation 1

keys
  id               TEXT PK
  purpose          TEXT               -- ca | leaf
  algorithm        TEXT
  storage          TEXT               -- envelope | hsm
  wrapped_dek      BLOB NULL          -- DEK encrypted with the root key (AES-256-GCM)
  key_ciphertext   BLOB NULL          -- private key (PKCS#8) encrypted with the DEK
  root_key_version INTEGER NULL
  hsm_ref          TEXT NULL          -- PKCS#11 URI (hsm build only)
  created_at       TEXT

import_jobs
  id, status, dry_run, started_at, finished_at, summary_json, problems_json

outbox
  id INTEGER PK, created_at, topic (audit|notify), payload_json, delivered_at NULL
```

**URLs in certificates** (owner 2026-10-13): `<public_base_url>/ca/<ca-name>/<generation>.crt`
(AIA caIssuers) and `<public_base_url>/crl/<ca-name>/<generation>.crl` (CRL distribution point). A
renewed CA (new key, same name) gets the next generation, so the chains and CRLs of older
certificates keep working. No OCSP URL until phase 4. Triggers keep issued certificates, signed CA
generations, CA names and used base URLs from ever changing; issued certificates are never deleted,
so a serial stays taken forever.

Status (`valid` / `expired` / `revoked`) is **derived**, not stored: `revocations` + `not_after`
vs. the injected clock. Nothing can get out of sync, and "expired" needs no nightly job.

### 1.2 `system.db`

```
tenants(id, name, allow_server_keygen /*default 1, switchable per tenant*/, created_at)
-- step 10 (migration 0004):
users(id, username UNIQUE /*lower case a-z0-9._@-, refused otherwise*/, password_hash /*Argon2id PHC*/,
      password_changed_at, totp_secret /*AES-GCM with the auth key, AAD = purpose + user id*/,
      totp_confirmed_at NULL, totp_last_step /*a code works once*/, totp_pending NULL,
      instance_admin, disabled_at NULL, failed_logins, locked_until NULL, created_at, updated_at)
      -- never deleted (trigger): the id is in audit entries
recovery_codes(user_id, code_hash /*HMAC-SHA256, key from the auth key*/, used_at NULL, created_at)
role_bindings(user_id, tenant_id, ca /*'' = whole tenant*/, role /*viewer|operator|admin*/, created_at, created_by)
sessions(id_hash PK /*SHA-256 of the cookie*/, user_id, state /*password|full*/, csrf_token,
         created_at, last_seen_at, expires_at, stepup_at NULL)   -- no IP: that is in the audit entry
-- step 11 (migration 0005):
instance(id = 1, demo /*init --demo: secrets in one file*/, initialized_at)   -- written last by init; never changed or deleted (triggers)
-- later:
webauthn_credentials(id, user_id, credential_id UNIQUE, public_key, sign_count, aaguid, name, created_at)  -- step 17
api_tokens(id, user_id, name, token_hash UNIQUE, scopes_json, created_at, expires_at, last_used_at)         -- step 18
unseal(slot PK /*passphrase|recovery*/, root_key_version, kdf, kdf_params, salt, wrapped_root_key)  -- the GCM tag proves the secret
settings(key PK, value_json)
```

### 1.3 `tenants/<t>/audit.db`

```
audit_entries(seq INTEGER PK, outbox_id TEXT UNIQUE /*source DB + outbox row, dedup*/, time, actor_type, actor_id, actor_name, action,
              target_type, target_id, result, source_ip, details_json,
              prev_hash, hash)   -- hash = SHA-256(prev_hash || canonical JSON of the entry)
```
Append-only (no UPDATE/DELETE statements exist in the code), verified by `POST /audit/verify`.
Entries arrive via the `outbox` of `pki.db`/`system.db`, so an issuance and its audit entry can't
be lost or duplicated even though they live in different files.

### 1.4 Mapping from legacy (importer)

| Legacy | New |
|---|---|
| `pki/root`, `pki/intermediate/<name>` + `ca.meta` (NAME TYPE CN SUBJECT KEY KEY_PASS DAYS PATHLEN PERMIT_DNS PERMIT_IP EKU_LIMIT OCSP_URL CREATED) | `cas`, `ca_name_constraints`, `keys` |
| `index.txt` (V/R/E, expiry, revocation[,reason], serial, subject) | `certificates` (serial preserved), `revocations` (time + reason preserved) |
| `crlnumber` | `cas.crl_number` (preserved, next CRL = +1) |
| `pki/issued/<name>/cert.meta` (PRESET NAME CN DNS IP EMAIL URI KEY DAYS CA …) + `cert.pem` / `key.pem` | `certificates`, `certificate_sans`, `keys` (if `key.pem` exists) |
| `pki.conf` (AIA_BASE_URL, CRL_DAYS, DEFAULT_*) | `cas.public_base_url`, `cas.crl_days`, settings |

---

## 2. Work plan

Each step ends with: summary for the owner (German), verification commands, a commit proposal;
commit only after the owner's OK, never push. `task check` must be green after every step.
"Approval" marks a step that needs a new dependency – it is asked for at that step, not earlier.

| # | Step | Approval needed | Verifies with |
|---|---|---|---|
| 0 | Fix the ShellCheck warnings in `legacy/` (own commit, behaviour unchanged), then CI ShellCheck at severity `warning` | – | `shellcheck --severity=warning …` clean; `legacy/build.sh` + a smoke run of `pki.sh` in a temp dir |
| 1 | actionlint (workflows) and vacuum (OpenAPI) as pinned CI tools, `task lint:ci` / `task lint:api`, fix their findings | – (approved) | both tools clean locally and in CI |
| 2 | `internal/clock` (injectable clock) and `internal/config` (YAML, strict, `MYOWNPKI_*` env overrides); `myownpki config check` | – | unit tests; `myownpki config check --config example.yaml` |
| 3 | ~~ogen trial~~ **done 2026-10-13:** hand-written handlers chosen, no generator (`docs/trials/ogen.md`) | – | – |
| 4 | **done 2026-10-13** – Store foundation: SQLite (pure Go), WAL pragmas, one writer + read pool, own migration runner (forward only, checksums) per DB type (`system`, `pki`, `audit`), sqlc; tenant directory layout | modernc.org/sqlite (approved 2026-10-13); owner installs sqlc 1.31.1 | migration tests in a temp dir; `myownpki db status` |
| 5 | **done 2026-10-13** (server wiring of the deliverer with step 12) – **Audit log** (instance `<data>/audit.db` + `tenants/<t>/audit.db`, hash chain, append-only triggers, no secrets in details) + **outbox** worker (exactly once via `outbox_id`; delivered rows deleted after 30 days, undelivered never) + `myownpki audit verify [--expect-head]`; chain heads to the process log at start and daily – before any CA code, so steps 7–11 audit from the start | – | tampering test breaks verification at the right `seq`; outbox delivers exactly once after a crash between commit and delivery |
| 6 | **done 2026-10-13** (API/UI wiring with steps 12–14) – Keys + unseal **+ recovery key**: Argon2id KEK, AES-256-GCM envelope encryption into `pki.db`, seal/unseal in memory, passphrase verifier; seal/unseal audited | golang.org/x/crypto | round trip; wrong passphrase rejected; test proves no plaintext key bytes in the DB file |
| 6a | **done 2026-10-13** – **Signed audit checkpoints** (Ed25519 from the root key, checkpoints are chain entries; made at unseal, before seal, daily, every 1000 entries; `audit verify --checkpoint-key`): at start, daily and every N entries a checkpoint (scope, seq, hash, time) is signed with a key derived from the unseal key and stored; `audit verify` checks the chain against the checkpoints – rewriting a chain then requires the passphrase (owner decision 2026-10-13) | – | recomputed chain without the key is detected; checkpoints survive restore |
| 7 | **done 2026-10-13** (`internal/ca`, pki.db migration 0004 with CA generations; API/UI wiring with steps 13–14 and 18–19) – CA engine – leaf issuance: 159-bit serials, extensions from the preset (critical EKU, ocsp-nocheck), CSR checks, name constraints **before** signing, per-CA max validity, AIA/CDP, ECDSA P-256 default, server-side key generation behind the tenant switch; every issuance audited | – | crypto/x509 + `openssl verify -purpose` per preset; NC and max-validity violations rejected (and audited as denied) |
| 8 | **done 2026-10-14** (`internal/ca`: lifecycle, offline flow; `myownpki ca list/show`; legacy `pki ca-sign`; API/UI with steps 18–19, `init` uses it in step 11) – CA lifecycle: create root/intermediate (ECDSA P-384 default), pathlen, name constraints, EKU limit; offline-signing flow (CSR out, certificate in); offline root import; renewal with a new key (next generation); retire; limits | – | chain verifies with OpenSSL; offline flow round trip with `legacy/pki.sh` as the offline root (CI on Linux; locally with `LEGACY_TEST_OPENSSL=/usr/bin/openssl` in Git Bash) and with the plain OpenSSL command of the instructions |
| 9 | **done 2026-10-14** (`internal/ca`: revoke, CRL, upload; `internal/publish`: serving, wired with step 12; CRL status in `db status` and `ca show`) – Revocation + CRL generation (number +1, AKI, nextUpdate) – **a sealed server can't renew CRLs: status/warning "sealed since …, CRL of <CA> expires on …"** in `db status`, API and process log (owner 2026-10-13), **from half of the CRL lifetime on** (owner 2026-10-14); **upload of the offline root's CRL** (signed by exactly that root generation, CRL number strictly increasing, thisUpdate not in the future, nextUpdate in the future; same half-lifetime warning); serving on the public listener, **including the legacy URLs `<base>/<name>.crt|.crl` as permanent aliases of generation 1 of imported CAs** | – | `openssl crl -text`; `openssl verify -crl_check` with a revoked leaf; uploaded root CRL with a wrong signer, an old number or a past nextUpdate is refused |
| 10 | **done 2026-10-15** (`internal/auth`, `internal/authz`, system.db migration 0004; `myownpki user unlock`/`reset-2fa`; HTTP wiring with steps 12–13) – **Auth core** (was 13): Argon2id passwords, TOTP (own RFC 6238 code), sessions, CSRF, step-up, rate limit/lockout, RBAC in the service layer. Comes **before `init`**, which creates the first admin with it. API tokens move to step 18 | – | one test per rule in security.md; RFC 6238 test vectors |
| 11 | **done 2026-10-15** (`internal/setup`, `myownpki init`, system.db migration 0005; `db status` shows the instance and the demo warning; serve wiring with step 12) – **`myownpki init`** (was 12): first admin (password + TOTP from step 10) + unseal passphrase + **recovery key** + **checkpoint key fingerprint to note down** (`Keyring.CheckpointKeyFingerprint` after a first unseal) (`keys.NewRecoveryKey` → show → confirm → `keys.Init`), **prominent warning to keep passphrase, recovery key and backups apart**. Recovery key only on an interactive terminal (`keys.RecoveryKeyOutput`); otherwise (Docker, systemd, pipe) init refuses and requires `--recovery-key-file <path>`, written with 0600 and never overwriting (`keys.WriteRecoveryKeyFile`), with the hint to store it safely and remove it from the server. Before init finishes the user re-types two random groups (`keys.ConfirmIndexes`/`CheckGroups`); the same for `recovery-key rotate` (owner 2026-10-13). Optionally init also creates an online root + intermediate with the step 8 functions (no second path, like legacy `pki init --intermediate`), so the browser test in step 14 has a CA; it must run without any input (Docker demo) and warns clearly "online root – for tests and homelab" (owner 2026-10-14). **From step 10 (owner 2026-10-15):** the first user gets **instance admin and `admin` in the default tenant**; init creates the auth key (`auth.CreateKeyFile`, path `auth.key_file`), the user (`auth.Service.CreateUser`) and confirms TOTP **on the console** (`ConfirmTOTP`); without a terminal it writes the otpauth link and the recovery codes to `--otpauth-file` (`auth.WriteEnrollmentFile`, 0600, never overwriting) and the first login confirms it – no window, the secret is fixed at init. Hidden input of passphrase and password with `golang.org/x/term` (approved 2026-10-15, two-week rule) | – | init on an empty data dir; refuses to run twice; non-terminal without file refused; wrong confirmation aborts without writing anything |
| 12 | **done 2026-10-16** (`internal/server`, `myownpki serve [--unseal]`; admin listener only `/healthz` until step 13) – **Server wiring + listeners with TLS** (was 15): admin listener with self-signed bootstrap certificate (fingerprint on the console) or operator certificate, later admin certificate from the own CA; HSTS; public listener for CRL/AIA (handlers from step 9); `serve` runs the audit deliverer, the checkpoint hooks (`OnUnseal`/`BeforeSeal`) and the daily heads | – | `openssl s_client`, `curl -v`; fingerprint matches the console; `audit verify` shows the checkpoints of unseal and seal |
| 13 | **done 2026-10-17** (`internal/httpapi` on `/api/v1`, read paths in `internal/ca`, device cookies with system.db migration 0006; private key download as PKCS#8 PEM) – **REST API, part 1** (from 16) – only what the browser test needs: login/logout/session with TOTP, unseal/seal/status, CAs list/show, certificates issue (CSR or server key)/list/show/download (certificate, chain), presets list. Hand-written (`net/http` ServeMux, `encoding/json`, no generator – step 3), RFC 9457 errors; **contract tests** read the spec and check each of these operations: route + method, role (`x-required-role`), step-up, problem responses, response schema | JSON Schema validator for the tests only (approved 2026-10-17) | contract tests; vacuum clean; `curl` examples in the summary |
| 14 | **done 2026-10-17** (`internal/web/app*.go` on the services, sign-in pages, PRG, flash cookie; screenshots of a neutral demo instance) – **UI, part 1** (shell B, from 17): login with TOTP, unseal, CA list, issue (CSR default, server key if allowed), certificates list/detail/download → **milestone M1: the owner tests a running server in the browser** | htmx (vendored, ask at this step) | handler tests incl. no-inline-style checks; screenshots light/dark; owner's browser test |
| 15 | **done 2026-10-21** (night run: `internal/ca/legacy` reader, `ca.ImportLegacy` in one transaction, `myownpki import legacy DIR [--dry-run]`, pki.db migration 0006 `ca_certificate_history`; decisions in docs/NIGHTLOG.md) – Legacy importer (was 10); CI builds a fixture PKI with `legacy/pki.sh` and imports it | – | serials, revocations (time + reason) and CRL numbers identical before/after |
| 16 | (was 11) **`myownpki backup` / `myownpki restore`**: consistent online backup of `system.db` and all databases of a tenant (`VACUUM INTO` / SQLite online backup), **audit databases (instance + tenants) last**, with a SHA-256 manifest that records every audit chain head, the newest checkpoint and the checkpoint key fingerprint; restore only into a stopped/empty data dir, with `PRAGMA integrity_check`, migration version check, manifest check and verification of every audit chain (instance + tenants) against the heads in the manifest; prominent warning to keep the unseal passphrase separate | – | backup during concurrent writes; restore round trip identical; corrupted/tampered backup rejected |
| 17 | Passkeys / WebAuthn (was 14) | go-webauthn/webauthn | registration + login with a virtual authenticator in tests |
| 18 | **REST API, part 2**: revoke, renew, export formats (PKCS#12, DER, bundles), CAs create/import/offline flow/renew/retire, import jobs, audit, users and roles, API tokens, tenant settings; contract tests now cover **every** operation of the spec | – | contract tests for the whole spec; vacuum clean |
| 19 | **UI, part 2**: revoke / renew / export, CAs (create, import, offline flow, renew), legacy import, audit, presets, users, tenant settings (subject defaults) | – | handler tests incl. no-inline-style checks; screenshots light/dark |
| 20 | Phase 1 wrap-up → **v0.1** (was 18): end-to-end test "pki.sh replaced" (import legacy PKI → issue → revoke → CRL check with OpenSSL → backup → restore), operations guide (incl. backup/passphrase warning), PLAN.md | – | the end-to-end test; `task check`; CI green |

**Order (owner 2026-10-14):** steps 8–9 finish the CA core. Steps 10–14 are the shortest way to a
running server the owner can test in the browser (milestone M1). Steps 15–19 complete phase 1, and
step 20 is release v0.1 (PLAN §10.1).
Dependencies that shaped the order:
- the auth core comes before `init`, because `init` creates the first admin with its password and
  TOTP code;
- the public listener (step 12) serves the CRL handlers of step 9;
- the browser test needs a CA – `init` can create root + intermediate (owner 2026-10-14).

**Until backup/restore (step 16) exists, an M1 test instance is disposable:** no backup of the
root key and the databases exists yet, so it must not hold a CA that anything relies on. Migrations
are forward-only, so its data does survive updates.

**Backup consistency (step 16):** each database file is copied as one consistent snapshot, but
the snapshots of different files are taken one after another. This is safe because no transaction
spans two databases and cross-database effects go through the outbox – **provided the order is
right**: first the producing databases (`system.db`, `pki.db`, …), **last** the consuming
audit databases (instance `audit.db` and every tenant's `audit.db`). Then the audit copies contain at least every entry the other copies mark as delivered;
entries delivered in between are delivered again after a restore and deduplicated by their outbox
ID (unique in `audit.db`). The reverse order could silently lose audit entries.

---

### Notes for later steps

- **Public base URL is independent of the listener port (steps 7/8, owner 2026-10-13).** The CRL
  distribution point and AIA URLs in every certificate are built from the CA's `public_base_url`,
  never from `public.listen`. They are baked into each certificate for its whole lifetime (and, for
  a CA, into every certificate it issues), so a port that changes later breaks revocation checking.
  - Docs: run the public listener on its default `:8080` behind a reverse proxy or port forwarding
    and publish it as `http://<name>/` on **port 80**.
  - CA creation (API/UI) and – once a default base URL exists in the config – `myownpki config check`
    **warn when the base URL contains a non-standard port** (anything but 80 for `http`, 443 for
    `https`), and name the consequence: the URL stays in every certificate until it expires.
  - Decided (owner 2026-10-13), implement at step 8: also warn on `https://` base URLs – RFC 5280 recommends HTTP for
    CRL and AIA, and a client that needs a CRL to check the TLS certificate of the CRL server is stuck.

- **CRLs (step 9) per generation:** each generation signs the CRL for the certificates it issued and
  publishes it at its own URL (`/crl/<name>/<generation>.crl`); the CRL number stays one strictly
  increasing counter per CA (`cas.crl_number`) across all generations.
- **The offline root's CRL (step 9, owner 2026-10-14):** intermediates below an offline root point
  their CDP to `<base>/crl/<root>/<generation>.crl`, which only the offline root can sign. The
  imported root has a name and base URL like every CA; its CRL is uploaded (`crls.source = uploaded`)
  and checked:
  - signed by exactly that root generation;
  - CRL number strictly increasing;
  - thisUpdate not in the future, nextUpdate in the future.

  Warnings start at half of the lifetime up to nextUpdate. The offline bundle of step 8 already
  shows how to create it (legacy `pki crl --ca root`, or `openssl ca -gencrl`).
- **Legacy import (step 15):** CAs that legacy renewed with the *same* key (`renew-ca`) keep their
  newest certificate in the generation; older certificates of the same key go into a history table
  created then (phase 1 renews only with a new key, owner 2026-10-14). Imported CAs are generation 1,
  so the legacy URL aliases of step 9 point there forever – also after later renewals.
- **issuingDistributionPoint – later, not now (step 9 finding, 2026-10-14):** a critical IDP with the
  generation's URL would bind each CRL to its URL. Tested and dropped: OpenSSL then refuses the CRL
  for certificates **without** a CRL distribution point ("different CRL scope", even without
  `-extended_crl`) – legacy certificates issued without `AIA_BASE_URL` have none. Revisit after the
  importer (step 15) knows which certificates lack a CDP; uploaded CRLs with an IDP are accepted.
- **Done in step 12 (from steps 9–11):** `serve` refuses to start before init and without the auth
  key; logs the demo warning at every start; runs `RenewCRLs` every 15 minutes and at unseal, and
  while sealed names every CRL that needs attention with "sealed since"; mounts `publish.New` on the
  public listener; prunes sessions hourly. **Done in step 14:** the demo warning as a banner on every page after sign-in.
- **Done in step 13 (from steps 10–12):** the API checks the CSRF token (header `X-CSRF-Token`)
  and the cross-origin headers itself, so its refusals are RFC 9457 problems; client addresses come
  from `auth.ClientIP` with `auth.trusted_proxies`; the session cookie is `auth.SessionCookie`. Unseal
  through the API (a signed-in instance admin + passphrase) works next to `serve --unseal`. Device
  cookies (OWASP) let a known browser in while strangers keep the account locked (decision 66).
  Lists and details check `authz.ReadPKI` in the engine (`internal/ca/read.go`).
- **Later (with htmx or an island):** a page that polls `GET /system/status` or `GET /auth/session`
  (seal state, idle countdown) – both are passive and don't keep the session alive.
- **Step 18 (owner 2026-10-17):** key download as PKCS#12 with a password (the dependency is asked
  then) and an option "delete the key from the server after the download"; until then the key stays
  encrypted on the server after every download. The spec documents this at the export operation.
- **vacuum (lint:api)** is not installed on the dev machine: the spec of step 13 is linted in CI only.
- **Container healthcheck (owner 2026-10-16, Docker demo):** distroless images have no curl, so a
  later `myownpki healthcheck` asks `/healthz` of the admin listener (accepting the bootstrap
  certificate by its pinned fingerprint) and exits 0/1 for `HEALTHCHECK`.
- **Docs (owner 2026-10-15):** recommend not to expose the admin listener to the internet at all,
  and to restrict it with `admin.allowed_networks` (ADR-08).
- **Backup (step 16) and the auth key:** `myownpki backup` copies `auth.key` when it is inside the
  data directory and says so; when `auth.key_file` points elsewhere (Docker secret, systemd
  credential) it prints that the key is **not** in the backup. Restoring without the key works, but
  every user then needs `myownpki user reset-2fa` (TOTP secrets and recovery codes are unreadable).
- **User names are never deleted (owner 2026-10-15):** for GDPR erasure requests a later
  "anonymize" replaces the name with `deleted-<id>`, drops password hash, TOTP secret and recovery
  codes, and the audit log keeps only the ID (PLAN §5).
- **ACME (phase 2) is stricter than the CSR wish list of step 7** (owner 2026-10-13): at finalize the
  CSR must name exactly the identifiers of the order – nothing missing, nothing extra – otherwise the
  order fails with `badCSR` (RFC 8555 §7.4). Names are never dropped or added there; the ACME path
  calls the engine with the order's identifiers and `IgnoreCSRNames` only after this exact match.
- **Subject defaults per tenant (step 19):** organization, country etc. as defaults for requests
  (like legacy `pki.conf`); the engine already takes them from the request (`ca.Subject`).

### Planned for the end of phase 1

- **Live demo on GitHub Pages**: a static export of the UI prototype on sample data (no server,
  no keys). Not built yet; planned once the phase 1 pages are complete.

## 3. Dependencies and their approval status

| Module / tool | License | For | Status |
|---|---|---|---|
| actionlint, vacuum (CI tools, pinned binaries) | MIT | lint workflows / OpenAPI | **approved** 2026-10-13 |
| ogen | Apache-2.0 | OpenAPI code generation | **not used** – decided after the trial (2026-10-13) |
| `modernc.org/sqlite` | BSD-3 | pure-Go SQLite (ADR-06) | **approved** 2026-10-13: v1.60.1 (SQLite 3.53.4), 8 runtime modules, ~7 MB |
| `github.com/pressly/goose/v3` | MIT | migrations | **not used** – own runner with checksums instead (2026-10-13) |
| sqlc binary 1.31.1 | MIT | query code generation (tool, not linked) | approved in phase 0; owner installs at step 4 |
| `golang.org/x/crypto` | BSD-3 | `argon2` (step 6), later `cryptobyte`, `ocsp` | **approved** 2026-10-13; v0.58.0 – already selected in the module graph via x/net (govulncheck); `argon2`/`blake2b` identical to the approved v0.57.0 on our platforms (diff checked: only LoongArch additions) |
| `github.com/go-webauthn/webauthn` | BSD-3 | passkeys | ask at step 17 |
| `golang.org/x/term` | BSD-3 | hidden input of passphrase and password on the console (`init`, `user reset-2fa`) | **approved** 2026-10-15 for step 11. **v0.47.0** (2026-10-09): already selected by the module graph – the approved `x/crypto` v0.58.0 and `x/net` v0.61.0 require it, and v0.46.0 would downgrade `x/crypto`, `x/net`, `x/tools` and `x/vuln` (tried 2026-10-15); **owner 2026-10-16: taken as selected by the graph** (exception in PLAN §13/§14) |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | JSON Schema 2020-12 validation of API answers in the contract tests – **tests only**, not in the binaries | **approved** 2026-10-17 for step 13: **v6.0.3** (2026-06-28); it brings `golang.org/x/text` (BSD-3) **v0.43.0** (2026-10-09), the version x/crypto v0.58.0 and x/net v0.61.0 already require – two-week rule exception as for x/term (PLAN §13) |
| htmx (vendored JS file) | 0BSD | UI interactions | **not in step 14** (owner 2026-10-17: plain forms are enough for M1) – ask when live updates need it |
| goversioninfo (or similar, build tool) | MIT | embed `assets/brand/app.ico` and version info in the Windows binaries | noted 2026-10-13 – ask before release packaging |

TOTP (RFC 6238) is ~60 lines with `crypto/hmac` – own code with the RFC test vectors, no dependency.
The common password list (step 10) is data, not a module: origin and license in `THIRD_PARTY.md`.

---

## 4. Decisions of the owner (2026-10-13)

| # | Question | Decision |
|---|---|---|
| 1 | Server-side key generation | **Yes**, switchable off per tenant; CSR stays the default |
| 2 | Key storage | **Encrypted in `pki.db`**; `keys/` only for HSM references (PLAN §4 updated). Setup and docs must warn clearly: **keep the unseal passphrase separate from the backups** |
| 3 | First admin | **`myownpki init`** |
| 4 | Admin TLS at first start | **Both**: self-signed bootstrap certificate with fingerprint on the console, or an operator certificate; after setup an admin certificate from the own CA |
| 5 | OpenAPI generator | **Trial of ogen on two endpoints**, result shown to the owner, then decide → **hand-written, no generator** (2026-10-13) |
| 6 | Lifetimes | **Keep presets + maximum validity per CA**; ACME issuances default to **90 days** (phase 2) |
| 7 | Algorithms | **ECDSA P-256 for leaves, P-384 for CAs** |
| 8 | Legacy ShellCheck warnings | **Fix in a separate commit**, then CI at severity `warning` |
| 9 | First push | Repository **stays public**; owner pushes |
| 10 | Problem types | **Keep `urn:myownpki:problem:*`** |
| 11 | AIA/CDP URL layout (step 7) | **With key generation**: `<base>/ca/<ca-name>/<generation>.crt` and `<base>/crl/<ca-name>/<generation>.crl` (like AD CS `CAName(1).crt`); CA names immutable; no OCSP URL until phase 4 |
| 12 | Validity (step 7) | **An explicit request is never changed silently** (beyond the CA maximum or the CA's end → denied); a preset default adapts to both, with a note |
| 13 | Key policy for CSRs (step 7) | ECDSA P-256/P-384/P-521, RSA 2048–8192 **with exponent 65537 only** (2048 flagged "compatibility only"), Ed25519; **warning** for Ed25519 and P-521 on TLS server presets (browsers/Chrome reject them); DSA, P-224 and anything else denied |
| 14 | Subject DN (step 7) | CN + optional O/OU/L/ST/C from the request (the CSR's subject as fallback); **CN at most 64 characters** – a derived CN that is longer is **left out, not cut**; an explicit one is denied; **control characters denied** in every DN field (also invisible formatting characters such as bidi overrides); tenant defaults at step 17 |
| 15 | Internationalized domain names (step 7) | **Punycode (`xn--…`) only**; Unicode in DNS names denied (look-alike names) |
| 16 | CSR names (step 7) | **Wish list**: names of a type the preset doesn't take are dropped and listed **in the response and in the audit entry** (also when the request is denied for another reason); explicit names of such a type are denied. **Not for ACME** (phase 2): there the CSR must match the order exactly (`badCSR`) |
| 17 | CN that looks like a host name (step 7) | Checked against the DNS name constraints when the certificate has no DNS SAN (then clients fall back to the CN – RFC 6125); the denial names the fix: a display name without dots ("Max Mustermann" instead of "max.mustermann") or a DNS SAN within the permitted names |
| 18 | Wildcards, single-label names, custom usages (step 7) | Wildcards only with preset flag `wildcard: true` (base domain added, as in legacy); single-label names like `nas` allowed (legacy); CN of DNS presets also becomes the first SAN (legacy `CN_AUTO`); at most 100 SANs; e-mail addresses ASCII only; a CA with an EKU limit issues no certificate without EKU |
| 19 | Offline signing (step 8) | The server creates key + CSR and an **OpenSSL extension file**; the offline root signs with exactly that file, **never with the CSR's extensions** (`copy_extensions none`), digest matching the root key (P-384 → sha384). Legacy `pki ca-sign` and a plain OpenSSL command (**needs OpenSSL 3.0 or newer** – macOS ships LibreSSL, there `brew install openssl@3`). On upload also checked: no SHA-1 (only SHA-2/Ed25519 accepted), **AKI = SKI of the root**, serial not taken, notBefore not before the root's, plus everything ordered (key, subject, CA:TRUE, KU, pathlen, name constraints, EKU). The subject is compared by content (OpenSSL may re-encode it); leaves carry the exact subject bytes of the uploaded certificate as issuer, and `subject_dn` comes from it. AIA/CDP URLs other than the ones MyOwnPKI serves are accepted with a warning that **stays visible**: audit entry, `ca show`, later API and UI |
| 20 | CA renewal (step 8) | Phase 1: **only with a new key** (next generation); an offline root is renewed by importing its new certificate under the same name |
| 21 | Legacy URLs (step 8/9) | Served permanently as **aliases of generation 1**, also after later renewals |
| 22 | CA keys (step 8) | New CAs: P-384 (default), P-256, RSA 3072/4096. **Import**: RSA 2048 and P-521 only with a warning; Ed25519 as CA always refused |
| 23 | CA defaults (step 8) | Root 7300 days, intermediate 3650 days (never beyond the parent), pathlen 0; CRL lifetime: offline root 180, online root 30, intermediate 7 days; maximum leaf validity 397 days. **CRL expiry warning (also while sealed) from half of the CRL lifetime on** |
| 24 | CLI for CAs (step 8) | Only `ca list` / `ca show`; creating and renewing via API/UI (steps 18–19) and `init` (step 11) |
| 25 | CA at `init` (step 11) | Optional online root + intermediate with the step 8 functions (no second path), **non-interactive possible** (Docker demo), warning "online root – for tests and homelab" |
| 26 | Revocation while sealed (step 9) | Allowed: stored and audited at once, the CRL is signed at unseal. Until then `db status` and `ca show` show "N revocation(s) not yet published in a CRL" – a revocation takes effect only with the CRL |
| 27 | CRL timing (step 9) | Renewed after a third of the lifetime; warning from half of it (also while sealed, also for the uploaded offline root CRL); "expired" after nextUpdate |
| 28 | Expired certificates in CRLs (step 9) | RFC 5280 §3.3: an entry stays until it was on a regular CRL after the certificate expired – removed only from notAfter + crl_days on |
| 29 | Revocation reasons (step 9) | Final reasons only (no certificateHold); "unspecified" without reasonCode extension; optional invalidity date for keyCompromise/cACompromise. **keyCompromise / cACompromise put the SHA-256 of the SubjectPublicKeyInfo into `blocked_keys`** (per tenant, immutable); the engine denies CSRs, server-generated keys, new and imported CA keys with a blocked key |
| 30 | CRL history (step 9) | Every CRL is kept (evidence); clean-up later if ever needed |
| 31 | Legacy aliases (step 9) | Only for CAs with `legacy_urls` (set by the importer) |
| 32 | CLI (step 9) | No revocation or upload by CLI; API/UI in steps 18/19; status read-only in `db status` and `ca show` |
| 33 | Serving CRLs and CA certificates (step 9) | `Cache-Control: public, max-age=900` (15 minutes) plus ETag and Last-Modified with 304 answers and HEAD – not until nextUpdate, so a new CRL after a revocation gets through proxies quickly |
| 34 | issuingDistributionPoint (step 9) | Not written for now – see the note "issuingDistributionPoint – later" (breaks certificates without a CRL distribution point in OpenSSL) |
| 35 | How long a generation needs CRLs (step 9) | Until its own notAfter **and** until the latest notAfter of everything it signed plus crl_days (RFC 5280 §3.3) – imported legacy certificates may outlive their CA |
| 36 | Unsupported reasons on the offline root's CRL (step 9) | certificateHold, removeFromCRL and unknown codes mark our intermediate as revoked (recorded as unspecified) with the warning "certificateHold is not supported – for MyOwnPKI this CA is revoked for good"; lifting the hold later changes nothing |
| 37 | Revocation edge cases (step 9) | An expired certificate can be revoked (with a warning; keyCompromise still blocks the key). If the CRL can't be signed after a revocation, the revocation stays stored, with a warning and `crl.sign/failure` in the audit log; `RenewCRLs` signs it later. A root can't be revoked (remove it from the trust stores); a CA below an offline root is revoked on the root's CRL and recognized at upload |
| 38 | CRL limits (step 9) | Upload at most 4 MiB, CRL number at most 63 bits; CRL warnings don't change the exit code of `db status` (alerting in phase 4) |
| 39 | Passwords (step 10) | Argon2id 64 MiB, t=3, p=1 (parameters in the hash, upgraded at the next login); **at most 4 hashes at once** – the throttle answers **before** a hash slot is taken, a caller who gets no slot waits up to 2 s and gets "busy"; 12–256 characters, no composition rules, no expiry (NIST SP 800-63B); refused: the user name inside, the product name, one repeated character or a plain sequence, and the **common password list** (Xato 1 million via SecLists, filtered to 12–256 characters, compared without case – `THIRD_PARTY.md`, built by `internal/tools/commonpasswords`); unknown users cost a full hash run too |
| 40 | TOTP (step 10) | RFC 6238: SHA-1, 6 digits, 30 s, ±1 step; **160-bit secret**; a code works once (last step stored, checked in Go **and** in the SQL update); secret encrypted with the auth key, AAD = purpose + user ID |
| 41 | Auth key (step 10) | `auth.key_file` (default `<data>/auth.key`), may live outside the data directory (Docker secret, systemd credential); created by init with 0600, never overwritten; readable by others → warning (Docker secrets are 0444), **writable by others → refused**. Limits stated openly: whoever has the databases **and** the key file has the TOTP secrets. **Losing the key = every user needs `user reset-2fa`** |
| 42 | Recovery codes (step 10) | 10 per user, 100 random bits each (20 Crockford characters), usable once, stored as **HMAC with a key from the auth key**; use is audited with the number left (warning at ≤ 3); failures count for throttle and lockout |
| 43 | Throttle and lockout (step 10) | In memory: per (IP, user) 5 free failures, per user 20, then 1 s doubling to 15 min; checked before any hash. **Unknown user names share one counter per address** – invented names never get entries of their own; **IPv6 counts per /64**, IPv4-mapped IPv6 as IPv4 (owner 2026-10-15). At most 100,000 entries: pruning drops forgotten entries first, then those with the fewest failures, **never one that is braking**. In the database: 10 failures in a row lock the account for 15 min, **never for good**; `myownpki user unlock <name>` ends it early (audited). Client IP: the direct peer, `X-Forwarded-For` only from `auth.trusted_proxies` (read from the right) |
| 44 | Sessions and CSRF (step 10) | Cookie `__Host-myownpki_session` (`HttpOnly; Secure; SameSite=Strict; Path=/`), only the SHA-256 stored; after the password a 5-minute pending session, after the second factor a **new** session ID; idle 30 min, absolute 12 h, activity written at most once a minute; no IP in the session table. CSRF: Go's `http.CrossOriginProtection` (Sec-Fetch-Site/Origin) plus the session token (header or form field) |
| 45 | Step-up and own changes (step 10) | Fresh second factor within 5 min for key download, revocation, CA management, CRL upload and user management (the second factor at login counts). **Unseal = signed-in instance admin + passphrase** (no step-up). Own password, authenticator and recovery codes need the **current password**; other sessions end. API token creation gets step-up in step 18 |
| 46 | Roles (step 10) | Instance admin (users, unseal) separate from tenant roles: viewer (read, **no audit log** – personal data), operator (issue, revoke, download keys), admin (+ CAs, CRL upload, tenant settings); a role for the whole tenant or one CA. A CA is revoked by whoever manages its **issuer**; a revocation is published with the revoker's right, without `ca.manage`. The engine and the keyring check permissions themselves; refusals are audited as denied. Role changes and disabling end the user's sessions. **The last active instance admin and the last active (tenant-wide) admin of a tenant can't be disabled or lose that role** – also not by another admin; nobody disables themselves (owner 2026-10-15) |
| 47 | User names and audit (step 10) | Lower case `a-z 0-9 . _ @ -`, 1–64 characters, anything else **refused, not converted**; users are disabled, never deleted. Failed logins with an unknown name are logged as "unknown user" **without the typed name** (it may be a password) |
| 48 | Console emergencies (step 10) | `myownpki user reset-2fa <name>` needs the **unseal passphrase or the recovery key** (shell access alone is not enough), reads it from a pipe, gives a new TOTP secret and new recovery codes (terminal or `--otpauth-file`), ends all sessions; the next login confirms exactly that secret. `--new-auth-key` creates a lost key file anew (never over an existing one) |
| 49 | init flow (step 11) | **Ask everything first, then write in one go** – an abort before (wrong confirmation, three wrong TOTP codes, Ctrl+C) leaves nothing behind, not even the data directory. Secret files are written before the database refers to their secrets. init runs the migrations itself (data directory 0700). The instance row and `system.init` are written while unsealed, so the checkpoint before the seal signs them at once – only `system.seal` comes after it (owner 2026-10-16) |
| 50 | Three ways (step 11) | **Interactive** (terminal: passphrase and password twice without echo, recovery key shown and two groups typed again, TOTP shown and the first code confirmed – three tries, recovery codes at the end); **`--stdin`** (automation: passphrase and password as two lines, only `\n`/`\r\n` removed – spaces stay, also at the end; `--admin-user`, `--recovery-key-file`, `--otpauth-file` required; TOTP confirmed at the first login); **`--demo`** (everything generated into `<data_dir>/init-demo-secrets.txt`) |
| 51 | Demo mark (step 11) | `--demo` writes `instance.demo = 1`, which can't be changed or removed (triggers); the `system.init` audit entry says `demo`; `db status` warns now, `serve` logs the warning at every start (step 12), the UI shows a banner (step 14). For production: a new instance |
| 52 | Test CA (step 11) | Online root `root` + intermediate `issuing`, CN "MyOwnPKI Test Root/Issuing CA <4 random Crockford characters>" (the same tag for both), O = host name – two test instances never make roots of the same name; the base URL is required, no default (it is in every certificate) |
| 53 | Resume (step 11) | A run that broke off while writing is finished by running init again: it proves the **unseal passphrase** (`--demo`: from its file) and creates only the missing parts – never a second root key, user, auth key or CA; files of a run that never reached the database must be moved away (the message says so). One test per abort point |
| 54 | First user (step 11) | Instance admin **and** `admin` of the default tenant; the name is typed (no default – a predictable name is half a login; `--demo`: `demo`); the password must differ from the unseal passphrase, **also ignoring case** – refused with the reason |
| 55 | Admin TLS (step 12) | Operator certificate (`admin.tls_cert_file`/`tls_key_file`) or a **bootstrap certificate** in `<data>/tls`: self-signed **end-entity** certificate (CA:FALSE, KU digitalSignature, EKU serverAuth – Firefox refuses a CA certificate as server certificate), ECDSA P-256, 397 days, renewed 30 days before the end or when the names change (host name, listen IP, loopback, `admin.tls_names`); key unencrypted (0600) – the listener must work while sealed. SHA-256 fingerprint in the log at every start and in a console box; a new certificate is a warning with the reason. TLS 1.2 minimum (1.3 with hybrid post-quantum key exchange negotiated), HTTP/2, HSTS `max-age=31536000` without includeSubDomains/preload |
| 56 | Admin allowlist (step 12) | `admin.allowed_networks` (IPs/CIDRs), checked against the direct peer **before** TLS – a refused client gets no answer at all; IPv4-mapped IPv6 as IPv4. Refusals are summed up and logged at most once a minute. A warning at start when `admin.listen` is not loopback and the list is empty |
| 57 | What listens (step 12) | Admin: only `GET /healthz` ("ok", nothing about the seal state) until API and login in step 13; the prototype UI stays `--dev`. Public: CRLs and CA certificates (step 9), no health check – nothing of the admin side |
| 58 | Start and unseal (step 12) | Migrations, init and auth key checked, then both listeners start **sealed**; `serve --unseal` asks for the passphrase on the terminal only after the listeners run (CRLs are served meanwhile); a wrong passphrase leaves the server running sealed, the lockout of step 6 applies; three tries |
| 59 | Shutdown (step 12) | Within **8 s** (Docker/Podman send SIGKILL after 10 s): no new connections, in-flight requests get half of it, then the seal with its last checkpoint, then the databases close |
| 60 | Jobs (step 12) | Outbox delivery on wake and every 5 s (with checkpoints every 1000 entries), checkpoints and audit heads in the process log daily (heads also at start), CRL renewal every 15 min and at unseal – while sealed a `crl attention` warning per CRL – sessions hourly, delivered outbox rows daily; a failing job is logged and runs again, it never stops the server |
| 61 | Audit failure (step 12) | **Direct audit entries are fail-closed**: no unseal, sign-in or step-up whose entry can't be written. A seal still happens (refusing it would keep the key in memory) and reports the error; logout likewise. **Outbox entries may pile up** while delivery fails – business changes go on, the server warns loudly with count and age of the oldest per outbox |
| 62 | First CRL (fix after step 12) | A CA (generation) whose key is on the server signs **its first CRL in the transaction that creates it** (number 1 for a new CA, the next number for a new generation) – online root, intermediate, renewal, install of an offline-signed intermediate (audit `crl.sign`, trigger = the CA action). Before, a new CA had no CRL until the first unseal, and strict relying parties refused every certificate below. Installing an offline-signed intermediate therefore needs an unsealed server, like every other CA change with an online key (owner finding 2026-10-16) |
| 63 | API structure (step 13) | `internal/httpapi` on `/api/v1` of the admin listener: a route table, one row per spec operation; chain per request: request ID (`X-Request-ID`, also in every problem) and `Cache-Control: no-store`, cross-origin protection, session, CSRF token for changes, JSON body rules. One access log line per request with the **route pattern** (no IDs, no query) and the **user ID**. Contract tests compare route table and spec and validate every answer against the spec's JSON Schema; fields outside the spec fail too (`santhosh-tekuri/jsonschema/v6` v6.0.3, tests only) |
| 64 | Answers (step 13) | No read access → **404** like an unknown ID; read access but a too low role → **403** `forbidden`; no fresh second factor → 403 `step-up-required`; policy → 422 `policy-violation` with every reason; wrong passphrase or code with a valid session or pending sign-in → 422 `wrong-secret` (401 only when the session or pending sign-in is missing or over – the UI tells "code wrong" from "sign in again"); lockout → 429 with Retry-After; too many hashes at once → 503 `busy`; sealed → 503 `sealed`; anything else → 500 with only the request ID. Bodies: `application/json` only (**415** otherwise; a POST without a body may omit it), unknown fields and trailing data → 400, more than 128 KiB → 413 |
| 65 | Sign-in over the API (step 13) | `POST /auth/login` → a pending session (5 minutes, good only for `/auth/totp`); `/auth/totp` takes a TOTP or a recovery code, a wrong one is 422 and counts with wrong passwords; then a **new session ID**. Works while sealed. `GET /system/status` and `GET /auth/session` are **passive** – they don't move the idle timeout; the route decides, not a header |
| 66 | Device cookies (step 13) | `__Host-myownpki_device`, issued and renewed only after a **complete** sign-in, valid one year; HMAC with a key derived from `auth.key` (HKDF label `myownpki auth device-cookie v1`) over user ID, random value, end and the **credentials epoch** (system.db 0006: +1 at a new password, reset-2fa, a new authenticator and `user unlock`). With a valid cookie only the (IP, user) brake applies, failures count against the cookie (10 in 15 minutes lock it for 15 minutes, list in memory), never against the user; a lock that strangers caused stays when the known device signs in. Logout keeps the cookie |
| 67 | Unseal over the API (step 13) | A signed-in **instance admin** + the passphrase, no step-up. Wrong passphrases are slowed down per instance (step 6 rule) **and per client address** (same rule, IPv6 by /64, IPv4-mapped as IPv4); every attempt is audited; a success resets the instance and that address – an address that guessed keeps its brake |
| 68 | Key download (step 13) | `POST /certificates/{id}/export` with `{"format":"pkcs8-pem"}`: **operator on the issuing CA** and a fresh second factor (a viewer never gets a key), unsealed, audited in the tenant log as `key.download` **before** the key leaves (fail-closed); attachment `<cn>.key.pem`, `application/x-pem-file`, `no-store`. The key stays encrypted on the server; PKCS#12 and "delete after download" follow in step 18 |
| 69 | Lists (step 13) | Newest first, cursor = the last ID of the page (IDs sort by time), at most **100** per page (more → 400). The search `q` is a plain substring of CN, SAN or serial with `instr()` – `%` and `_` are ordinary characters (sqlc doesn't parse `LIKE … ESCAPE`, and without wildcards there is nothing to escape) |
| 70 | Step-up in seconds (live finding 2026-10-17) | The engine works in whole seconds (like certificates), sessions in milliseconds: a key export in the same second as its step-up was refused. The step-up time is compared rounded down to the second; the API tests run on a clock off the whole second |
| 71 | Chains (step 13 review) | `chain` = the intermediates up to just below the root, `fullchain` = certificate + intermediates (certbot, legacy). The root is never part of a chain a server sends (RFC 8446 §4.4.2, SSL Labs "chain contains anchor"); it comes from `GET /cas/{id}/certificate`, whose `chain` format (for trust stores) keeps it |
| 72 | Review details (step 13) | A refused name drops the echo "preset … needs at least one name of type …" (and "needs a wildcard name") – the requester fixes the name; without any name the message stays. Unclean paths under `/api/v1/` (`//`, `/./`) answer 404 as a problem instead of the mux's 307 redirect in text/html |
| 73 | Real UI (step 14) | `internal/web/app*.go` serve the pages of the prototype on the services – the same ones the REST API calls, with the same checks; no read access = 404, a command the role doesn't allow is not offered and refused anyway. The prototype stays with `serve --dev`. Shell B, navigation only with built pages, the demo warning and "signing is off" (with "Unseal" for instance admins) above every page after sign-in |
| 74 | Post/Redirect/Get (step 14) | Every POST form ends with **303 See Other** on a GET page; issuing answers 303 on `/certificates/{id}`. Exceptions: the private key download (the file itself) and wizard steps that only move between steps. Messages for the next page in the cookie `__Host-myownpki_flash` (60 s, read once), never in the URL. No htmx in step 14 |
| 75 | `next=` (step 14) | A local path only: exactly one leading `/`, no `//` anywhere, no `\`, no `.`/`..` segments, no control characters – also percent-encoded (`/%2F%2Fevil`, `/%5Cevil`, `%0d%0a`); not `/login…`. Anything else goes to the dashboard |
| 76 | Sign-in page (step 14) | Shows nothing about the instance (`layout.Plain`: no version, seal state, demo mark). One message for a wrong name, a wrong password and a lockout, without a wait time; a name that strangers locked costs a hash like an unknown one (answer time). The code page takes a TOTP or a recovery code in one field; after a complete sign-in a sealed server sends instance admins to `/unseal` |
| 77 | Unseal page (step 14) | Instance admins only; shows "sealed since" and the CRLs that age meanwhile; the form has `autocomplete="off"` and no user name field (no stored "second password"); a wrong passphrase and the lockout are messages on the page; afterwards 303 on `next` or the dashboard. Sign out and seal are POST forms with the CSRF token |
| 78 | Issue wizard (step 14) | Preset → Key → Names → Review. The CSR as text or upload (PEM or DER, at most 64 KiB); a broken CSR or a bad signature is a message at the field. The CSR's names fill the name fields once (per CSR); issued is what the form says (`IgnoreCSRNames`) – the final "issue" checks every step again but never fills from the CSR again (found by a test: a missing prefill mark replaced the form's names). Refusals of the engine stay on the review step (422) with every reason |
| 79 | Key download in the UI (step 14) | A POST button on the detail page for operators of the CA when the key is stored; without a fresh second factor to `/step-up` and back to the detail page – the download is started again by hand, never on its own |
| 80 | Overview and logs (step 14) | Dashboard with real numbers (only of readable CAs; red/amber only when not 0) and "Needs attention": CRLs that age, CA certificates that end within 90 days, CAs that wait for a signature. The UI access log names the route pattern (no IDs, no client address) like the API – the audit log has the address of every sign-in (both factors, success and failure, also for unknown names), step-up and unseal (checked by a test). Screenshots from a throwaway demo instance with neutral names (O=Homelab, names under homelab.example) – no TOTP QR, recovery codes or passphrases in the pictures |
| 81 | A root issues no end-entity certificates (owner 2026-10-18) | A root signs intermediate CAs and CRLs only (CA/B BR §6.1.7): the CA engine refuses a leaf from a root as policy ("a root CA only signs intermediate CAs and CRLs – issue from an intermediate"; API 422 `policy-violation`, audited as denied). Why: a misissued leaf is revoked by its intermediate instead of touching the trust anchor, and the root key isn't in memory for every issuance. The wizard offers no root. Imported existing certificates (step 15) are not issuance. OCSP responder certificates from a root (allowed by BR §6.1.7) are a question for phase 4 |
| 82 | Commands only where they work (step 14 review) | "Issue certificate" appears in the menu and on the dashboard only for users who may issue at one CA at least (no dead links); the pages refuse on the server anyway |
| 83 | CA list (step 14 review) | Column "Signed": end-entity certificates and the intermediate CAs a CA signed (a root shows "1 intermediate CA", not 0); "Max. validity" of a root is "–" (it issues no leaves); key storage with readable labels ("Encrypted on this server", "Offline", "HSM") |
