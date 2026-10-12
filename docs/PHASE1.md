# Phase 1 – proposal (draft for discussion)

> Written at the end of phase 0 (2026-10-13). Nothing here is implemented or decided yet –
> it is a basis for the kickoff of phase 1. Open questions to the owner are in §4.

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
tenants(id, name, created_at)
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
audit_entries(seq INTEGER PK, time, actor_type, actor_id, actor_name, action,
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

## 2. Order of steps (each one small, testable, committable)

| # | Step | Verifies with |
|---|---|---|
| 1 | `internal/clock` (injectable clock) and `internal/config` (YAML, strict, `MYOWNPKI_*` env) | unit tests; `myownpki serve --config …` prints the validated config |
| 2 | Store foundation: SQLite open with pragmas, one writer + read pool, goose migrations per DB type, sqlc setup | migration tests on a temp dir; `sqlite3`-free inspection via `myownpki-ctl --offline db status` |
| 3 | Keys + unseal: Argon2id KEK, envelope encryption, seal/unseal in memory | round-trip tests; wrong passphrase rejected; no plaintext in DB (test greps the file) |
| 4 | CA engine: serials (159-bit), leaf template from preset (incl. critical EKU, ocsp-nocheck – see NIGHTLOG step 5), CSR checks, name constraints **before** signing, AIA/CDP, validity capped by CA `notAfter` | crypto/x509 + `openssl verify -purpose` per preset; NC violation tests |
| 5 | Root/intermediate creation and the offline-signing flow (CSR out, certificate in) | chain verifies with OpenSSL; pathlen/NC present |
| 6 | CRL generation (number +1, AKI, nextUpdate) | `openssl crl -text`, `openssl verify -crl_check` |
| 7 | Audit log with hash chain + outbox worker | tampering test breaks verification at the right `seq` |
| 8 | Legacy importer, CI builds a fixture PKI with `legacy/pki.sh` | serials, revocations and CRL numbers identical before/after |
| 9 | Auth: users (Argon2id), TOTP, WebAuthn, sessions, CSRF, step-up, RBAC in the service layer, first-admin bootstrap | tests per rule in security.md; rate limit/lockout tests |
| 10 | Admin listener with TLS (bootstrap certificate, then one from the own CA) | `curl -v`, `openssl s_client`; headers incl. HSTS |
| 11 | REST API from `api/openapi.yaml` | contract tests generated from the spec |
| 12 | UI (layout B): login, unseal, certificates (list, detail, issue, revoke, download/export), CAs, presets, audit, import | htmx flows without JS fallback broken; screenshot tests light/dark |

Steps 1–8 need no UI and no login – the CA core can be finished and verified first.

---

## 3. Dependencies phase 1 will need (all need owner approval)

| Module | License | For |
|---|---|---|
| `modernc.org/sqlite` | BSD-3 | pure-Go SQLite (ADR-06) |
| `github.com/pressly/goose/v3` | MIT | migrations |
| `golang.org/x/crypto` | BSD-3 | `argon2`, `ocsp` (phase 4), `cryptobyte` |
| `github.com/go-webauthn/webauthn` | BSD-3 | passkeys |
| OpenAPI generator (`ogen` or `oapi-codegen`) | Apache-2.0 | handlers from the spec |
| htmx (vendored JS file) | 0BSD | UI interactions |
| sqlc binary 1.31.1 | MIT | query code generation (tool, not linked) |

TOTP (RFC 6238) is ~60 lines with `crypto/hmac` – proposed as own code with RFC test vectors
instead of a dependency.

---

## 4. Open questions to the owner

1. **Server-side key generation** (legacy workflow, key stored encrypted, download with step-up)
   in addition to CSR signing? *Recommendation: yes, but switchable off per tenant; CSR is the default in the UI.*
2. **Where do CA/leaf keys live?** PLAN §4 says `keys/` directory; the proposal above puts the
   encrypted blobs into `pki.db` (one backup, Litestream replicates it, atomic with issuance).
   *Recommendation: DB; `keys/` only for HSM references.*
3. **First admin:** `myownpki init` on the console (asks for username + password, forces 2FA
   enrollment at first login) or a one-time setup token printed at first start?
   *Recommendation: `myownpki init`.*
4. **TLS for the admin listener at first start:** self-signed bootstrap certificate (fingerprint
   printed on the console, like Proxmox), user-provided certificate, or both?
   *Recommendation: both; after setup, issue the admin certificate from the own CA.*
5. **OpenAPI generator:** ogen (full 3.1 support, generates its own router) or oapi-codegen
   (3.0-focused, plain net/http)? *Recommendation: try ogen on two endpoints first, decide after.*
6. **Default lifetimes:** keep the legacy 397/730 days in the presets, or move towards CA/B SC-081
   (200 days from 2026, 100 from 2027) now? *Recommendation: keep presets; add a per-CA maximum.*
7. **Default key algorithm** for server-generated keys and new CAs: ECDSA P-256 (leaves) / P-384
   (CAs) as in pki-rules.md, or RSA 3072 like many legacy setups? *Recommendation: ECDSA.*
8. **Legacy ShellCheck warnings** (25, mostly unused variables): fix them so CI can use severity
   `warning`? *Recommendation: yes, in a small separate commit.*
9. **When is the first push?** The CI has never run. *Recommendation: create the GitHub repository
   private, push, let CI run once before phase 1 starts.*
10. **Problem-type URIs:** keep `urn:myownpki:problem:*`, or decide the project domain now (PLAN §12)?
