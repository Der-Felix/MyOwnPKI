# Phase 1 – plan

> Written at the end of phase 0; the owner answered the open questions on 2026-10-13 (§4).
> §2 is the agreed work plan. The data model (§1) is still a proposal that each step refines.

Goal of phase 1 (PLAN §10): data model, CA engine, importer, REST API, login with 2FA, RBAC,
unseal, audit log, UI for issue / revoke / upload / download in layout B –
**"pki.sh replaced in the browser"**.

---

## 1. Data model

Principles: one SQLite file per purpose and tenant (ADR-06), one transaction never spans two
files, cross-database effects go through an **outbox** table. Phase 1 runs a single tenant
(`tenants/default/`), but every path is already tenant-aware so phase 5 needs no migration.
All times are stored as UTC (`TEXT`, RFC 3339 with `Z`); serials and fingerprints as upper-case hex.

### 1.1 `tenants/<t>/pki.db`

```
cas
  id               TEXT PK            -- ULID-like opaque ID
  name             TEXT UNIQUE        -- legacy directory name (root, issuing, …)
  kind             TEXT               -- root | intermediate
  parent_id        TEXT NULL → cas.id
  status           TEXT               -- active | pending_signature | retired
  key_mode         TEXT               -- offline | online_encrypted | hsm (ADR-09)
  key_id           TEXT NULL → keys.id
  key_algorithm    TEXT
  subject_dn       TEXT
  serial_hex       TEXT
  not_before, not_after TEXT
  cert_der         BLOB NULL          -- NULL while pending_signature
  csr_der          BLOB NULL          -- offline-signing flow
  fingerprint_sha256 TEXT UNIQUE
  ski_hex          TEXT
  path_len         INTEGER NULL
  nc_critical      INTEGER            -- name constraints critical (compat switch)
  eku_limit        TEXT               -- JSON array of EKU names/OIDs (legacy EKU_LIMIT)
  public_base_url  TEXT               -- immutable once the first certificate is issued
  crl_days         INTEGER
  crl_number       INTEGER            -- strictly increasing; preserved by the importer
  max_validity_days INTEGER           -- caps every issuance (presets, API, ACME default 90 days)
  created_at, updated_at TEXT

ca_name_constraints
  ca_id → cas.id, kind (dns|ip|email|uri), value, permitted (1) / excluded (0)

certificates
  id               TEXT PK
  ca_id            TEXT NULL → cas.id  -- NULL for external certificates
  source           TEXT               -- issued | imported | external
  preset           TEXT NULL
  serial_hex       TEXT               -- UNIQUE (ca_id, serial_hex)
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

revocations
  certificate_id   TEXT PK → certificates.id
  reason           TEXT               -- RFC 5280 names
  revoked_at       TEXT
  invalidity_date  TEXT NULL
  revoked_by       TEXT

crls
  ca_id → cas.id, number, this_update, next_update, crl_der   -- PK (ca_id, number); keep last N

keys
  id               TEXT PK
  purpose          TEXT               -- ca | leaf
  algorithm        TEXT
  storage          TEXT               -- envelope | hsm
  dek_wrapped      BLOB NULL          -- DEK encrypted with the KEK (AES-256-GCM)
  key_ciphertext   BLOB NULL          -- private key (PKCS#8) encrypted with the DEK
  kek_version      INTEGER
  hsm_ref          TEXT NULL          -- PKCS#11 URI (hsm build only)
  created_at       TEXT

import_jobs
  id, status, dry_run, started_at, finished_at, summary_json, problems_json

outbox
  id INTEGER PK, created_at, topic (audit|notify), payload_json, delivered_at NULL
```

Status (`valid` / `expired` / `revoked`) is **derived**, not stored: `revocations` + `not_after`
vs. the injected clock. Nothing can get out of sync, and "expired" needs no nightly job.

### 1.2 `system.db`

```
tenants(id, name, allow_server_keygen /*default 1, switchable per tenant*/, created_at)
users(id, username UNIQUE, display_name, email, password_hash /*Argon2id PHC string*/,
      must_change_password, disabled, created_at, last_login_at)
user_roles(user_id, tenant_id, role, scope_type /*tenant|ca*/, scope_id NULL)
totp_secrets(user_id PK, secret_ciphertext, confirmed_at)       -- encrypted like keys
recovery_codes(user_id, code_hash, used_at NULL)
webauthn_credentials(id, user_id, credential_id UNIQUE, public_key, sign_count, aaguid, name, created_at)
sessions(id_hash PK, user_id, created_at, last_seen_at, expires_at, step_up_until NULL,
         csrf_token_hash, ip, user_agent)
api_tokens(id, user_id, name, token_hash UNIQUE, scopes_json, created_at, expires_at, last_used_at)
unseal(kek_version PK, argon2_params, salt, verifier_ciphertext)  -- proves the passphrase, holds no key
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
| 5 | **done 2026-10-13** (server wiring of the deliverer with step 15) – **Audit log** (instance `<data>/audit.db` + `tenants/<t>/audit.db`, hash chain, append-only triggers, no secrets in details) + **outbox** worker (exactly once via `outbox_id`; delivered rows deleted after 30 days, undelivered never) + `myownpki audit verify [--expect-head]`; chain heads to the process log at start and daily – before any CA code, so steps 7–11 audit from the start | – | tampering test breaks verification at the right `seq`; outbox delivers exactly once after a crash between commit and delivery |
| 6 | Keys + unseal: Argon2id KEK, AES-256-GCM envelope encryption into `pki.db`, seal/unseal in memory, passphrase verifier; seal/unseal audited | golang.org/x/crypto | round trip; wrong passphrase rejected; test proves no plaintext key bytes in the DB file |
| 6a | **Signed audit checkpoints**: at start, daily and every N entries a checkpoint (scope, seq, hash, time) is signed with a key derived from the unseal key and stored; `audit verify` checks the chain against the checkpoints – rewriting a chain then requires the passphrase (owner decision 2026-10-13) | – | recomputed chain without the key is detected; checkpoints survive restore |
| 7 | CA engine – leaf issuance: 159-bit serials, extensions from the preset (critical EKU, ocsp-nocheck), CSR checks, name constraints **before** signing, per-CA max validity, AIA/CDP, ECDSA P-256 default, server-side key generation behind the tenant switch; every issuance audited | – | crypto/x509 + `openssl verify -purpose` per preset; NC and max-validity violations rejected (and audited as denied) |
| 8 | CA lifecycle: create root/intermediate (ECDSA P-384 default), pathlen, name constraints, EKU limit; offline-signing flow (CSR out, certificate in); CA import | – | chain verifies with OpenSSL; offline flow round trip with `legacy/pki.sh` as the offline root |
| 9 | Revocation + CRL generation (number +1, AKI, nextUpdate), serving on the public listener | – | `openssl crl -text`; `openssl verify -crl_check` with a revoked leaf |
| 10 | Legacy importer; CI builds a fixture PKI with `legacy/pki.sh` and imports it | – | serials, revocations (time + reason) and CRL numbers identical before/after |
| 11 | **`myownpki backup` / `myownpki restore`**: consistent online backup of `system.db` and all databases of a tenant (`VACUUM INTO` / SQLite online backup), **audit databases (instance + tenants) last**, with a SHA-256 manifest that records every audit chain head; restore only into a stopped/empty data dir, with `PRAGMA integrity_check`, migration version check, manifest check and verification of every audit chain (instance + tenants) against the heads in the manifest; prominent warning to keep the unseal passphrase separate | – | backup during concurrent writes; restore round trip identical; corrupted/tampered backup rejected |
| 12 | `myownpki init`: first admin + unseal passphrase, **prominent warning to keep the passphrase separate from backups** | – | init on an empty data dir; refuses to run twice |
| 13 | Auth core: Argon2id passwords, TOTP (own RFC 6238 code), sessions, CSRF, step-up, rate limit/lockout, RBAC in the service layer, API tokens | – | one test per rule in security.md; RFC 6238 test vectors |
| 14 | Passkeys / WebAuthn | go-webauthn/webauthn | registration + login with a virtual authenticator in tests |
| 15 | Listeners with TLS: admin listener with self-signed bootstrap certificate (fingerprint on the console) or operator certificate, later admin certificate from the own CA; HSTS; public listener for CRL/AIA | – | `openssl s_client`, `curl -v`; fingerprint matches the console |
| 16 | REST API per `api/openapi.yaml`, **hand-written** (`net/http` ServeMux, `encoding/json`, no generator – step 3), RFC 9457 errors; **contract tests** read the spec and check every operation: route + method, role (`x-required-role`), step-up, problem responses, response schema | JSON Schema validator for the tests only (ask at this step) | contract tests; vacuum clean; `curl` examples in the summary |
| 17 | UI (shell B), in sub-steps: a) login/2FA/unseal, b) certificates list/detail/download, c) issue (CSR default, server key if allowed) / revoke / renew / export, d) CAs (create, import, offline flow), e) import, audit, presets, tenant settings | htmx (vendored, at 17a) | handler tests incl. no-inline-style checks; screenshots light/dark |
| 18 | Phase 1 wrap-up: end-to-end test "pki.sh replaced" (import legacy PKI → issue → revoke → CRL check with OpenSSL → backup → restore), operations guide (incl. backup/passphrase warning), PLAN.md | – | the end-to-end test; `task check`; CI green |

Steps 0–12 need no web login and no UI: the CA core, its audit trail and its backup are finished
and verified first.

**Backup consistency (step 11):** each database file is copied as one consistent snapshot, but
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
| `golang.org/x/crypto` | BSD-3 | `argon2`, `cryptobyte`, later `ocsp` | ask at step 6 |
| `github.com/go-webauthn/webauthn` | BSD-3 | passkeys | ask at step 14 |
| htmx (vendored JS file) | 0BSD | UI interactions | ask at step 17a |
| goversioninfo (or similar, build tool) | MIT | embed `assets/brand/app.ico` and version info in the Windows binaries | noted 2026-10-13 – ask before release packaging |

TOTP (RFC 6238) is ~60 lines with `crypto/hmac` – own code with the RFC test vectors, no dependency.

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
