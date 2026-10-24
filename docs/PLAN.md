# MyOwnPKI – Project Plan

> Status: phases 1 and 2 complete – v0.1.0 released 2026-10-22, v0.2.0 (phase 2, ACME server) released 2026-10-23, v0.2.1-rc.1 (installation as a systemd service) tagged and in production since 2026-10-24, v0.2.2 (own TLS, daily backup, trust page) built in the night run 2026-10-24, not released; next: phase 3 · Last updated: 2026-10-24 · License: Apache-2.0
>
> Goal: turn the existing Bash PKI script into a self-hosted, enterprise-grade
> PKI platform with a web UI, REST API, ACME and an agent system –
> "like step-ca, but better".

---

## 1. Vision

MyOwnPKI is your own, fully controlled PKI – from homelab to enterprise:

- **Secure web UI** with dashboards, upload/download and role-based access
- **Agents** deploy certificates to target servers and monitor them (similar to SaltStack)
- **ACME in both directions:** an ACME server for the internal CA *and* an ACME
  client for Let's Encrypt / ZeroSSL (http-01, dns-01, tls-alpn-01)
- **Multiple domains** as first-class objects with policies and ownership
- **Multi-tenant** (optional), scales to thousands of servers
- **Runs anywhere:** Docker, Podman, LXC, Linux, macOS, Windows, FreeBSD

### How it differs from step-ca

| step-ca | MyOwnPKI |
|---|---|
| Web UI only in the commercial edition | Secure web UI included |
| No deployment/monitoring agent | Agent with deploy profiles, inventory and served-certificate checks |
| Templates hand-written in JSON | Ready-made presets (802.1X, LDAPS, S/MIME, VPN, …) and deployment recipes |
| No Let's Encrypt client | Internal and public certificates in one UI |
| Multi-tenancy only in the cloud edition | Self-hosted multi-tenancy |

---

## 2. Decisions (ADR overview)

| # | Decision | Rationale |
|---|---|---|
| ADR-01 | **Go** for server, agent and CLI | One static binary per platform, native `crypto/x509`, `lego` for ACME, cross-compiling without toolchains |
| ADR-02 | **Built in-house**, not on top of step-ca | Full control over data model, presets and name constraints |
| ADR-03 | **Server-side rendering**: `templ` + htmx | Minimal attack surface, strict CSP, UI embedded in the binary |
| ADR-04 | **Islands** for interactivity: Web Components + ECharts, bundled with esbuild-as-a-Go-library | Rich dashboards without an SPA and **without Node.js/Bun** |
| ADR-05 | **API first**: REST, OpenAPI 3.1, spec before code | UI, CLI, Ansible/Terraform share the same API |
| ADR-06 | **Multiple SQLite databases** (pure Go, no CGO) | Per-tenant isolation, no cross-blocking writes, no Postgres needed |
| ADR-07 | **Litestream** for replication/backup | Sufficient high availability for now |
| ADR-08 | **Three separate listeners** (public / agent / admin) | CRL/OCSP/ACME public, administration secured separately |
| ADR-09 | **Key mode selectable per CA** (offline / online-encrypted / HSM) | The operator decides |
| ADR-10 | **Agent connects outbound** (pull), mTLS, Connect-RPC | No open ports on targets, NAT-friendly |
| ADR-11 | **Keys are generated on the target host** (agent sends only a CSR) | Private keys never leave the host |
| ADR-12 | **Fixed global CSS classes**, themes change tokens only | Less code, no style drift, maintainable |
| ADR-13 | **Layout selectable per user** (A Compact / B Standard / C Focus) | Different ways of working, one set of pages |
| ADR-14 | **License Apache-2.0**, no GPL/AGPL dependencies | Free, patent grant, enterprise-friendly |
| ADR-15 | **Plugins deferred** | Keep extension points in mind, build later |
| ADR-16 | **Bash script stays** as an offline tool (root CA, air-gap), in `legacy/` | Proven; the root does not have to live on a web server |
| ADR-17 | **English only** (UI, API, docs, repo) | Focus, no i18n effort early on; keep UI strings centralised anyway |
| ADR-18 | **Agent enrollment via proof of control** (http-01/dns-01), otherwise manual approval | Automatic where provable; stricter modes per tenant/domain |
| ADR-19 | **One issuance path: ACME** – the agent uses ACME internally as well | One policy engine for agent, certbot, Traefik & co.; the agent is optional |
| ADR-20 | **New repository** `Der-Felix/MyOwnPKI`, Bash script under `legacy/` | Clean history; old project and its docs stay intact |

---

## 3. Architecture

```
                    ┌──────────────────────────────────────────────────┐
  Browser ─────────▶│ Admin listener  :9443  UI + REST API (2FA, opt. mTLS)
  certbot/Traefik ─▶│ Public listener :80/443 ACME, CRL, OCSP, AIA      │
  Agents ──────────▶│ Agent listener  :8443  Connect-RPC over mTLS      │
                    │                                                  │
                    │  myownpki (single binary)                        │
                    │  ├─ CA engine        signing, CRL, OCSP           │
                    │  ├─ ACME server      RFC 8555 for internal CAs    │
                    │  ├─ ACME client      lego → Let's Encrypt/ZeroSSL │
                    │  ├─ Scheduler        renewal, expiry, alerts      │
                    │  ├─ Agent gateway    jobs, inventory, status      │
                    │  ├─ Policy engine    who may do what for which domain
                    │  ├─ Notify           mail, ntfy, webhook, Matrix… │
                    │  └─ Store            SQLite + encrypted keys      │
                    └──────────────────────▲───────────────────────────┘
                                           │ outbound, mTLS
              ┌────────────────────────────┼────────────────────────────┐
     myownpki-agent (Linux)     myownpki-agent (Windows)     myownpki-agent (FreeBSD)

  Offline: legacy/pki.sh / myownpki-ctl --offline  →  root CA on an air-gapped machine
```

### Binaries

| Binary | Purpose |
|---|---|
| `myownpki` | Server (UI, API, ACME, CA engine, scheduler) |
| `myownpki-agent` | Agent on target systems (Linux/systemd, Windows service, FreeBSD rc.d) |
| `myownpki-ctl` | CLI against the REST API, plus an offline mode for root ceremonies |

---

## 4. Data storage

```
/var/lib/myownpki/
├─ system.db                     tenants, global admins, settings, sessions, outbox
├─ audit.db                      instance audit log: logins, users, unseal (append-only, hash chain)
└─ tenants/<tenant>/
   ├─ pki.db                     CAs, certificates, encrypted private keys, domains, agents, policies, deploy profiles, outbox
   ├─ acme.db                    ACME accounts, orders, authorizations, challenges, nonces
   ├─ audit.db                   tenant audit log (append-only, hash chain, tamper-evident)
   ├─ metrics.db                 time series for dashboards, retention + downsampling
   └─ keys/                      HSM references only (PKCS#11 URIs) – no key material
```

- **Private keys (CA and server-generated leaf keys) are stored encrypted in `pki.db`**
  (envelope encryption, see §5): one backup and one Litestream replica contain everything, and a
  key is written in the same transaction as its certificate. *(Decided 2026-10-13.)*
- **The unseal passphrase must be kept separate from the backups.** A backup of `pki.db`
  plus the passphrase is a complete CA; a backup alone is useless to a thief. Setup (`myownpki init`)
  and the operations docs say this prominently.

- SQLite in **WAL mode**, one writer per file → the split prevents cross-blocking.
- Type-safe queries with `sqlc`; migrations with an own small runner per database type – forward
  only, one transaction each, and the SHA-256 of every applied migration is stored, so a changed
  migration file stops the server instead of silently diverging *(decided 2026-10-13, instead of goose)*.
- Backup/export/delete of a tenant = one directory.
- **`myownpki backup` / `myownpki restore`** *(phase 1)*: consistent online backup of `system.db`
  and all tenant databases (`VACUUM INTO` / SQLite online backup; the audit databases – instance and
  tenants – **last**) with a SHA-256
  manifest that also records the head (seq + hash) of every audit chain; restore with integrity,
  migration-version and manifest checks and a full verification of every audit chain against those heads.
  Litestream (ADR-07) adds continuous replication later.
- No transactions across database boundaries → design flows so each transaction stays in one DB (outbox pattern where needed).

### Scaling targets (enterprise)

| Scenario | Design consequence |
|---|---|
| 5,000 servers, one certificate each | ~85 issuances/day at 90-day validity – trivial |
| Short-lived certificates (7 days) | ~1,000/day – trivial |
| 5,000 agent heartbeats every 30 s | Status kept **in memory**, only state changes are written; history downsampled in `metrics.db` |
| Reverse proxy with 200 certificates | Agent **batches** deploys: write all files → `nginx -t` → one reload → rollback on failure |
| Many certificates expiring at once | Random jitter on renewal; ACME Renewal Information (ARI, RFC 9773) |
| High OCSP load | Pre-signed OCSP responses cached, rebuilt on revocation |

---

## 5. Security

### Web UI
- Login: local users (Argon2id) with **passkey/WebAuthn or TOTP mandatory**; optional **OIDC** (Authentik, Keycloak, Entra ID)
- Optional **mTLS client certificate** for the admin listener (issued by the own CA)
- **Step-up auth** (fresh 2FA) for: key download, revocation, CA operations, permission changes
- **RBAC**: roles admin / operator / viewer, scoped per tenant, CA, domain, agent group
- Strict **CSP** without inline JS, HSTS, cookies `HttpOnly; Secure; SameSite=Strict`, CSRF tokens
- Rate limits, account lockout, IP allowlist per listener
- Context-aware auto-escaping (`templ`) – **CSR contents are attacker input**

### Keys
| Mode | Description |
|---|---|
| Offline | CA key not on the server; signing via CSR export → offline signature → import |
| Online, encrypted | Key encrypted in `pki.db`; server starts **sealed**, unlocked with a passphrase (unseal), key afterwards only in RAM |
| HSM / KMS | PKCS#11 (YubiHSM, Nitrokey, SoftHSM), later cloud KMS/TPM – separate build with CGO; only a reference in `keys/` |

- The UI clearly warns about "root online" (root certificates are practically impossible to revoke).
- Minimum key standards configurable (e.g. per BSI TR-02102).
- **Default algorithms:** ECDSA P-256 for leaf keys, ECDSA P-384 for CA keys *(decided 2026-10-13)*.
- **Server-side key generation** for leaves is available but **switchable off per tenant**; CSR
  signing is the default in UI and API *(decided 2026-10-13)*.
- **Key hierarchy** *(phase 1 step 6, decided 2026-10-13)*: passphrase →Argon2id (t=4, 256 MiB,
  p=4; parameters stored; unseal refuses less – *minimum, decided 2026-10-23*)→ KEK → **root key** (random, wrapped in `system.db`) → one DEK per private
  key → private key (PKCS#8), all AES-256-GCM with additional data that binds each ciphertext to its
  purpose and key ID. Changing the passphrase rewraps only the root key (one row, atomic); the root
  key's GCM tag proves the passphrase, no separate verifier. Sealed after every start; when
  unsealed only the root key is in memory, DEKs and private keys are decrypted per signing
  operation. Passphrase ≥ 16 characters.
- **Recovery key** *(decided 2026-10-13)*: 256 random bits, created at init, shown **once** (Crockford
  Base32 in groups of six with two check characters), stored only as a second wrap of the root key.
  Unseal and passphrase reset with the recovery key, each with its own audit entry. **Keep the
  recovery key apart from the passphrase and from the backups** – backup + recovery key = the CA.
  Old backups still open with the passphrase or recovery key that was valid when they were taken.
- **A sealed server can't sign – also no CRL renewal.** Step 9 shows "sealed since …, CRL of <CA>
  expires on …"; phase 4 alarms when the sealed state outlasts the CRL lifetimes.
- **Later option: auto-unseal** via TPM, cloud KMS or a key file – the key file only with a clear
  warning (whoever takes file and database together has the CA). Not in phase 1.

### Setup and admin access
- First administrator via **`myownpki init`** on the console (username, password and the **TOTP
  second factor, set up and confirmed right there**) – also sets the unseal passphrase, with the
  backup warning from §4. Without a terminal (Docker demo) init writes the otpauth link to a file
  (0600, never overwritten) and the first login confirms exactly that secret – there is no window in
  which somebody else could enroll *(owner 2026-10-15)*. The first user is instance admin and
  `admin` of the default tenant.
- **Users are never deleted** (their ID is in the audit log), only disabled. For GDPR erasure
  requests a later "anonymize" replaces the name with `deleted-<id>`, removes password hash, TOTP
  secret and recovery codes; the audit log then keeps only the ID *(owner 2026-10-15)*.
- The **auth key** (`auth.key_file`) encrypts the TOTP secrets; it may live outside the data
  directory. Losing it means every user's second factor must be reset (`myownpki user reset-2fa`,
  which needs the unseal passphrase or the recovery key).
- Admin listener TLS: at first start a **self-signed bootstrap certificate**, its SHA-256
  fingerprint printed on the console for verification; alternatively an operator-provided
  certificate. After setup the admin certificate is issued by the own CA. The bootstrap
  certificate is an end-entity certificate (CA:FALSE, serverAuth), renewed 30 days before its end
  or when its names change *(step 12)*.
- The admin listener should never face the internet; `admin.allowed_networks` limits it to the
  admin networks before any TLS handshake (ADR-08, step 12).

### Audit & supply chain
- Audit log as a hash chain: `<data>/audit.db` for instance events (logins, users, unseal),
  `tenants/<t>/audit.db` per tenant. Entries of a business change arrive via the outbox of the same
  database (exactly once, deduplicated by `outbox_id`); events without a business change (failed
  login, denied request) are appended directly. `myownpki audit verify` walks every chain.
- **Anchors** – a hash chain alone can't detect a cut-off end or a fully recomputed chain by someone
  with write access to the file, so its head (seq + hash) is also kept elsewhere:
  - phase 1: written to the process log at start and daily, recorded in the backup manifest, and
    checked with `myownpki audit verify --expect-head`;
  - step 6a: **signed checkpoints** – Ed25519, key derived from the root key (exists only while
    unsealed); a checkpoint is a normal chain entry signing the entry before it, made at unseal,
    before seal, daily and every 1000 entries; its public key fingerprint is shown at init, logged at
    unseal and pinned with `audit verify --checkpoint-key` –
    rewriting the chain then needs the passphrase;
  - phase 5: **SIEM/syslog export** of every entry – the strongest anchor, because the copy lives
    outside the CA's control.
- **Personal data (GDPR):** audit entries contain personal data – user names and source IP
  addresses. Only what security needs is stored (who, what, when, from where, target, result; no
  user agent, no free text from requests). Operators document the retention period and the legal
  basis in their records of processing (Art. 30 GDPR) – typically the security of the PKI and the
  ability to prove who issued or revoked a certificate for as long as certificates of the CA can be
  relied upon. **Single entries can't be deleted or changed**: that is what makes the chain
  tamper-evident. Erasure requests are therefore handled at the level of whole logs (e.g. archiving
  and starting a new chain after the retention period) and must be assessed by the operator's data
  protection officer. *(Owner request 2026-10-13; not legal advice.)*
- Export to SIEM/syslog (phase 5)
- Signed releases (cosign), SBOM (syft), reproducible builds (GoReleaser)
- Container: distroless, non-root, read-only filesystem, works with rootless Podman

---

## 6. Features

### 6.1 Upload / download
**Upload:** sign CSR · intermediate CSR for offline signing · external certificates for monitoring ·
batch (existing `.conf` templates, CSV, YAML) · backup restore · import of an existing `pki/` directory

**Download:** PEM, chain, fullchain, combined · PKCS#12 (password chosen at download, optional legacy) · DER ·
ZIP including deployment guide · CRL · CA bundle · encrypted backup

**Rules:** strict parsing, size limits, zip-slip protection · key downloads only with step-up auth and an audit entry.

### 6.2 Agent system
- **Enrollment:** agent generates key + CSR → proves control of its hostname → identity from a dedicated `agent-ca`

  | Mode (per tenant/domain) | Flow |
  |---|---|
  | `auto` | Join token **or** passed http-01/dns-01 check → approved immediately |
  | `verified` (default) | Join token **and** passed check → approved; only one of them → waits for approval |
  | `manual` | Always manual approval in the web UI (like `salt-key -A`) |

  - If no check is possible (no DNS record, port 80 closed) → agent goes to the approval queue
  - The server performs the check itself (fetches from the agent via HTTP or checks the TXT record)
- **Deploy profiles:** path, owner, mode, format (PEM, P12, JKS, Windows certificate store) + reload hook; the existing `GUIDE.txt` recipes (nginx, Apache, Traefik, Caddy, HAProxy, Proxmox, TrueNAS, UniFi, Docker, OpenVPN, strongSwan, IIS) become built-in profiles
- **Monitoring:** heartbeat, inventory, fingerprint comparison, **local TLS check** (is the service really serving the new certificate?)
- **Renewal:** automatic at ~2/3 of lifetime, with jitter, batched reload and rollback
- **Targeting:** tags/grains (e.g. `role=webserver`, `site=fra`)
- **Trust store distribution:** root CA into system trust stores (Linux, Windows, Java, Firefox NSS)
- **Security boundaries:** no arbitrary remote execution – hooks are allowlisted locally in the agent config; an agent may only request certificates for its own names (policy)
- **Platforms:** Linux (systemd), Windows (service), FreeBSD (TrueNAS, pfSense, OPNsense)

### 6.3 ACME
- **ACME server** (RFC 8555) for internal CAs: http-01, dns-01, tls-alpn-01; EAB; per-CA/provisioner policies; ARI (RFC 9773); conformance tests with certbot, acme.sh, Traefik, Caddy, Pebble
- **ACME client** via `lego`: Let's Encrypt, ZeroSSL, any ACME CA; 150+ DNS providers (Cloudflare, Hetzner, INWX, deSEC, RFC2136/BIND, Technitium, PowerDNS …)
- **http-01 via the agent** directly on the target host
- **CNAME delegation** for `_acme-challenge` (no full DNS API token needed)
- Staging toggle, rate-limit monitoring, account key management
- **Validity:** ACME issuances default to **90 days**; presets keep their own defaults for UI/API
  issuance; every CA has a **maximum validity** that caps both *(decided 2026-10-13)*.

**Approvals in the ACME server (optional, for more security):**

| Level | Effect |
|---|---|
| Open | Any ACME client passing the challenge gets certificates (within the domain policy) |
| Account approval | New ACME accounts wait for admin approval or need an EAB key from the UI |
| New-name approval | First issuance for a **new hostname** needs approval; renewals run automatically |

> Note: approval *per order* is impractical with standard clients – certbot & co. only wait
> briefly after finalize. Approval therefore happens at account or name level; the client
> simply retries after approval.

### 6.3a Integration levels per host

| Level | Tool on the host | What the server knows |
|---|---|---|
| 1 – ACME only | certbot, acme.sh, win-acme, Traefik, Caddy, cert-manager | Issuances and renewals |
| 2 – ACME + scan | as level 1 | plus: server-side TLS scan checks the certificate is actually served |
| 3 – Agent | `myownpki-agent` (uses ACME internally) | everything: inventory, deploy, reload, rollback, trust store, local TLS check |

The agent is therefore **optional** – level 1 is enough for hosts that already run an ACME client.

### 6.4 Domains
- Domain as a first-class object: internal or public CA · DNS provider + credentials · authorised roles/agents · name constraints of the matching intermediate CA
- SAN, multi-domain and wildcard certificates (existing feature)
- UI recommendation: individual certificates over large SAN certificates (handshake size, CT log exposure, Let's Encrypt limit of 100 SANs)

### 6.5 Further features
- OCSP and CRL served straight from the database (no restart after revocation)
- Notifications: e-mail, ntfy, Gotify, Matrix, Telegram, Teams, Slack, webhook
- Prometheus `/metrics`, Grafana dashboard
- Certificate Transparency monitoring for public domains
- Network scan for unmanaged TLS endpoints
- API tokens with scopes; later Ansible module, Terraform provider
- Later: SSH CA, SCEP/EST for network devices

---

## 7. Frontend & design

### Technology
| Layer | Choice |
|---|---|
| Pages, forms, tables | `templ` + htmx |
| Interactive islands | Web Components (TypeScript, bundled with esbuild as a Go library) |
| Charts | Apache ECharts (theme derived from CSS tokens) |
| Dashboard grid | gridstack.js |
| Live data | Server-Sent Events |
| Assets | `embed.FS` – everything inside the binary |

### CSS structure (fixed global classes)
```
web/styles/
├─ tokens.css       colours, spacing, radii, fonts (the only file themes change)
├─ base.css         reset, typography, base layout
├─ components.css   .card .btn .btn-primary .tb .bd-ok/-wa/-cr .st .stat .form-row .chart-box …
└─ layouts.css      shells A / B / C
```
- No inline styles (CI check)
- Component gallery at `/design`
- **Status colours (ok/warn/critical) are fixed** and cannot be themed

### Layouts (selectable per user)
| Layout | For whom | Structure |
|---|---|---|
| **A Compact** | Admins in daily operations | tree navigation, toolbar, dense tables, task bar |
| **B Standard** | Operators, audit, search | top navigation, page title + filters, info column |
| **C Focus** | On-call, management, mobile | slim text navigation, big KPIs, "needs attention" list |

- Three shells, **one set of pages/components**
- Default per role, changeable by the user, lockable by the tenant admin
- Mobile automatically uses layout C
- Additional switches: density (compact/comfortable), light/dark
- Screenshot tests per layout

### Themes (three levels)
```
Global (instance admin)     logo, product name, base colour, font, login page
 └─ Tenant / team           accent colour, logo, default dashboard layout
     └─ User                layout A/B/C, density, light/dark, own widgets
```
- Designed in the UI (colour pickers, logo upload, live preview) – no CSS knowledge needed
- Higher levels decide what lower levels may change
- Automatic contrast check (WCAG)
- Themes contain **no JavaScript and no templates**

### Dashboards (initial scope)
KPIs (certificates, expiring soon, agents online, ACME success) · expiry timeline ·
renewal heatmap · certificates per CA/domain · agent status · key algorithm distribution ·
compliance hints · recent activity

---

## 8. Repository layout (target)

```
MyOwnPKI/
├─ cmd/
│  ├─ myownpki/            server
│  ├─ myownpki-agent/      agent
│  └─ myownpki-ctl/        CLI
├─ internal/
│  ├─ ca/                  CA engine, presets, name constraints, CRL, OCSP
│  ├─ acme/server/         ACME server
│  ├─ acme/client/         lego integration
│  ├─ agent/               agent protocol, gateway, deploy profiles
│  ├─ api/                 REST handlers (hand-written, checked against the spec by contract tests)
│  ├─ auth/                login, WebAuthn, TOTP, OIDC, RBAC
│  ├─ store/               SQLite, migration runner + schema/<kind>, sqlc queries, <kind>db packages
│  ├─ keys/                unseal, encryption, PKCS#11
│  ├─ policy/              policies
│  ├─ notify/              notifications
│  ├─ config/              config file + MYOWNPKI_* overrides (myownpki config check)
│  ├─ clock/               injectable clock (UTC)
│  ├─ web/                 templ components, layouts A/B/C
│  └─ tools/screenshots/   dev tool: README screenshots (task screenshots)
├─ assets/brand/           logo, favicons, app.ico (source of truth: SVGs); assets.go embeds what the UI serves
├─ web/
│  ├─ styles/              tokens, base, components, layouts
│  └─ islands/             Web Components (TypeScript)
├─ api/openapi.yaml        spec first (ADR-05); api.Spec embeds it
├─ presets/*.yaml          ported from legacy/lib/presets.sh (+ README.md: file format)
├─ guides/*.tmpl           ported from legacy/lib/export.sh (GUIDE.txt)
├─ deploy/                 config.example.yaml; later Dockerfile, Compose, LXC, systemd, Homebrew, Windows
├─ legacy/                 pki.sh + lib/ (offline root tool)
├─ .github/                CI workflow, shared setup action, Dependabot
├─ Taskfile.yml            build, test, lint, dev, cross, vuln
└─ docs/                   PLAN.md, NIGHTLOG.md (phase 0 log), PHASE1.md, screenshots/
```

---

## 9. Migration from the Bash script

1. **Presets → YAML:** KU/EKU/SAN rules from `legacy/lib/presets.sh` as data
2. **Deployment guides → templates:** from `legacy/lib/export.sh` (`write_howto`)
3. **Importer:** reads `pki/root`, `pki/intermediate/*`, `pki/issued/*` (`index.txt`, `cert.meta`, `ca.meta`) into `pki.db` – serial numbers and revocations must be preserved so existing CRLs stay correct
4. **Bash script stays** in `legacy/`: add `--json` output, document it for offline root ceremonies

---

## 10. Roadmap

| Phase | Scope | Outcome |
|---|---|---|
| **0 – Foundation** ✅ 2026-10-13 | Go skeleton, CI, presets → YAML, OpenAPI draft, design tokens + component gallery | Runnable empty binary, design system visible (`task dev` → `/design`) |
| **1 – Core** ✅ 2026-10-21 | Data model, CA engine, importer, REST API, login (2FA), RBAC, unseal, audit log, UI: issue / revoke / upload / download, layout B | Bash script replaced in the browser |
| **2 – ACME server & domains** | ACME server (http-01, dns-01, tls-alpn-01), domain model, policies, approval levels, EAB | certbot/Traefik/Caddy against the own CA (integration level 1) |
| **3 – Agent** | Enrollment with proof of control, issuance via ACME, deploy profiles (Linux first), heartbeat/inventory, batched reload + rollback; then Windows, FreeBSD; ACME client (lego) for Let's Encrypt | Deploy and monitor certificates (level 3), public certificates |
| **4 – Operations** | Dashboards, layouts A + C, themes (3 levels), notifications, OCSP/CRL, Prometheus, Litestream, trust store distribution, **alarm when the server stays sealed** (measured against the remaining CRL lifetimes) | Production-ready |
| **5 – Enterprise** | Tenant UI, OIDC, HSM build, SIEM export, CT monitoring, network scan, **Shamir split of the recovery key (m of n, four-eyes principle)** | Enterprise feature set |
| **Later** | Plugins (WASM sandbox), SSH CA, SCEP/EST, Terraform provider | – |

The phases describe the architecture's building blocks; **what ships when** is decided by the
release plan below – v1.0 takes parts of phases 2–4 and leaves others for later.

### 10.1 Release plan to a stable v1.0 (owner decision 2026-10-14)

| Version | Content | Outcome |
|---|---|---|
| **v0.1** | Phase 1 complete, as planned in `docs/PHASE1.md` | Bash script replaced in the browser |
| **v0.2** | ACME server with **http-01 and dns-01** (the server only *reads* the TXT record, through a **configurable DNS resolver** – internal DNS, split DNS); domain model and approval levels | certbot/Traefik/Caddy against the own CA |
| **v0.3** | **Linux agent** (with the DNS provider integration for dns-01) and **monitoring** (details below) | Certificates deployed and watched |
| **Beta** | Feature freeze; release pipeline, demo, guides, upgrade tests; only fixes | Tested by others before 1.0 |
| **v1.0** | Everything above, stable | – |

**v1.0 contains:**

- **Phase 1 complete.**
- **ACME server:** http-01 and dns-01; domain model and approval levels (§6.3, §6.4).
  - With dns-01 the *client* sets the TXT record; the server only reads it. So the server needs no
    DNS provider, but a **configurable DNS resolver** (e.g. the internal DNS, also for split DNS).
  - Until the agent brings provider support (v0.3), the docs show `certbot-dns-rfc2136` and
    `certbot-dns-cloudflare`.
- **Linux agent:** enrollment with proof of control (ADR-18), issuance via ACME (ADR-19), deploy
  profiles **nginx, Apache, HAProxy, file + hook**, reload with rollback, heartbeat/inventory.
  - DNS providers for dns-01 through the lego providers: **RFC 2136 and Cloudflare** first.
  - The ACME directory URL is configurable from the start, so Let's Encrypt later is only configuration.
  - It can optionally add the root to the system trust store.
- **Monitoring:**
  - dashboard: expiry, agent status, sealed warning;
  - TLS scan of the endpoints (integration level 2, §6.3a);
  - notifications by **e-mail and webhook**, including the alarm when the server stays sealed.
- **Trust store, small form:**
  - root download as PEM, DER and `.mobileconfig` (Apple);
  - a guide per system in the web guide: Windows, macOS, iOS, Android, Linux, Firefox;
  - the Linux agent can add the root to the system trust store (optional).
- **Guide in the web UI:**
  - a "first steps" assistant after `init`;
  - embedded guides: building a CA, offline root, connecting certbot, installing the agent,
    backup/restore.
- **Live test:**
  - `deploy/demo/docker-compose.yml` with MyOwnPKI, nginx with the agent, and a certbot container –
    one command shows http-01 end to end;
  - additionally, the static UI demo on GitHub Pages.
- **Release:**
  - GoReleaser, cosign signatures, SBOM;
  - Docker image (distroless, non-root);
  - an upgrade test between versions;
  - a beta phase before 1.0.

  The tools are asked for when the release step comes up, and every publication needs the owner's
  go (CLAUDE.md).

**After v1.0:**
- layouts A and C, themes;
- OCSP, Prometheus, Litestream;
- tls-alpn-01 and EAB;
- Windows and FreeBSD agent;
- ACME client for Let's Encrypt in the agent (only configuration then, see above);
- trust-store distribution by GPO, MDM and into Java trust stores;
- phase 5 (enterprise).

---

## 11. Backlog: plugins (deferred)

Planned extension points so the architecture stays open:
DNS providers · notification channels · deploy targets · policy checks · auth providers ·
inventory imports · export formats · dashboard data sources.
Planned technology: WebAssembly (wazero/Extism) with a permission manifest, declarative UI widgets,
plugin pages only inside `<iframe sandbox>` on a separate origin.

---

## 12. Open points

- [x] Language: English only (ADR-17)
- [x] Agent approval: proof of control, otherwise manual (ADR-18)
- [x] Repository: new repo `Der-Felix/MyOwnPKI` (ADR-20)
- [ ] Check name availability: domains (`.io`, `.de`, `.dev`), trademark registers (DPMA/EUIPO)
- [x] DNS providers first: RFC 2136 and Cloudflare, in the agent (v0.3); the ACME server only needs a configurable resolver. Deploy profiles first: nginx, Apache, HAProxy, file + hook (v1.0, §10.1)
- [x] Notification channels first: e-mail and webhook (v1.0, §10.1)
- [x] Task runner: Taskfile (phase 0, see §13)
- [x] Configuration format: YAML (phase 0, see §13)
- [x] OpenAPI code generator: none – hand-written handlers + contract tests (trial of ogen, 2026-10-13, §14 "API draft")
- [x] Server-side key generation: yes, switchable per tenant, CSR is the default (§5)
- [x] Key storage: encrypted in `pki.db`, `keys/` only for HSM references (§4)
- [x] Repository visibility: public (2026-10-13)

### Backlog from the production use of v0.2.1-rc.1 (owner 2026-10-24) – noted, not built

- Issue form: the name fields (DNS names, IPs, e-mails, URIs) also accept commas and spaces as
  separators, not only one name per line.
- CA form: hide the *Path length* field when creating a root instead of ignoring it silently.
- install.sh docs: `sudo` drops `https_proxy` – behind a proxy use
  `sudo --preserve-env=https_proxy,http_proxy,no_proxy bash install.sh …` or a root shell.

---

## 13. Tooling and conventions (decided in phase 0)

Not ADRs – operational choices that can be revisited without touching the architecture.
Rationale and alternatives: docs/NIGHTLOG.md.

| Topic | Decision |
|---|---|
| Go version | `go 1.27.3` in `go.mod` – the minimum and the toolchain at once (no separate `toolchain` line while both are equal); `GOTOOLCHAIN=auto` downloads it, CI and the release workflow use `GOTOOLCHAIN=local` with the same version (`GO_VERSION`) |
| Task runner | Taskfile (`task check` before every commit; `task dev`, `task cross`, `task vuln`) |
| Configuration | One YAML file, strict decoding (unknown keys are errors) + `MYOWNPKI_*` env overrides; library `go.yaml.in/yaml/v3`. Phase 1 step 2: `internal/config`, example `deploy/config.example.yaml`, `myownpki config check`; unknown `MYOWNPKI_*` variables are errors; listeners take IP literals only (no host names); admin listener defaults to `127.0.0.1:9443` (remote access is opted into); no secrets in the file (the unseal passphrase is entered at runtime) |
| Clock | `internal/clock`: `Clock` interface, `System` (UTC) – the only code allowed to call `time.Now` (lint rule) – and `Fake` for tests |
| Dev mode | `myownpki serve --dev` – CLI flag only, never in the config file; binds only to the IP literals `127.0.0.1`/`::1`; "DEV MODE – no TLS, no auth" on start and on every page |
| Tools in `go.mod` (`go tool`) | templ (generator = runtime version), govulncheck |
| Tools as pinned binaries | golangci-lint 2.14.0 (GPL – must not enter `go.mod`), sqlc 1.31.1 (from phase 1), ShellCheck 0.11.0 (CI) |
| CI | GitHub Actions; actions pinned to commit SHAs; downloads verified by SHA-256; read-only token; daily govulncheck; Dependabot weekly |
| Lint | golangci-lint v2 with security and project rules (`.golangci.yml`): e.g. no `math/rand`, no `time.Now` outside tests, no `//nolint` without reason |
| Presets | `presets/*.yaml`, embedded; strict validation; parity test against `legacy/lib/presets.sh` |
| UI | System fonts, no JavaScript in phase 0, status colors fixed per light/dark, US English spelling |
| API errors | RFC 9457 with problem types `urn:myownpki:problem:<name>` (kept, confirmed 2026-10-13) |
| CI lint tools | actionlint (workflows) and vacuum (OpenAPI) approved as pinned CI tools (2026-10-13); added in phase 1 step 1: actionlint 1.7.12, vacuum 0.30.6 (newest release older than two weeks), rules in `api/vacuum.yaml` – snake_case and per-property examples switched off with reasons, every other warning fails CI |
| Passkeys | `github.com/go-webauthn/webauthn` v0.18.2 (approved for step 17; its modules in THIRD_PARTY.md); a virtual authenticator for tests in `internal/auth/passkeytest` (own minimal CBOR encoder) |
| Two-week rule, exceptions | A module version already selected by the graph through approved modules is taken as it is, never forced down by downgrading those (§14 "CI and build"): `golang.org/x/crypto` v0.58.0 (2026-10-13), `golang.org/x/term` v0.47.0 (released 2026-10-09, required by x/crypto v0.58.0 and x/net v0.61.0; owner 2026-10-16), `golang.org/x/text` v0.43.0 (released 2026-10-09, required by x/crypto v0.58.0 and x/net v0.61.0; pulled in by the test-only JSON Schema validator; owner 2026-10-17). **Security point releases of Go** are taken at once: go1.27.3 (released 2026-10-19, owner 2026-10-21) for GO-2026-6809 / CVE-2026-111943 – `crypto/x509` `Certificate.Verify` gained a denylist of compromised intermediates; MyOwnPKI calls it when it checks CA chains (`ca.verifyCAChain`) |
| Legacy ShellCheck | warnings fixed in a separate commit, then CI runs ShellCheck at severity `warning` (done in phase 1 step 0: entry scripts with followed sources, the standalone script in full, `lib/*.sh` without SC2034 because modules share globals – the standalone script covers it) |
| Release tools | GoReleaser 2.18.2, cosign 3.1.3, syft 1.54.1 as pinned CI tools (SHA-256, approved 2026-10-21 for v0.1), base image `gcr.io/distroless/static-debian12:nonroot` by digest; `.goreleaser.yaml`, `.github/workflows/release.yml` (only on `v*` tags, draft release), `deploy/docker/Dockerfile`; owner checklist `docs/RELEASING.md` |

---

## 14. Phase 0 decision record

Detailed choices made while building phase 0 (most of them during the autonomous run documented
in docs/NIGHTLOG.md, which also lists how to reverse each one). §13 has the summary; this section
keeps the reasons. None of them changes an ADR.

### CI and build
| Decision | Why |
|---|---|
| Third-party actions pinned to a full commit SHA, not a tag | A tag can be moved to other code later; a SHA can't. The CI builds a CA |
| Only GitHub's own actions; golangci-lint, ShellCheck, sqlc, actionlint and vacuum downloaded directly with a pinned SHA-256 | Fewer third parties with code execution in CI; a swapped release file is detected |
| Two-week rule: dependencies and tools are only updated to releases that have been public for at least 14 days – Dependabot `cooldown: 14` days, the same rule by hand for pinned binaries; security updates are not delayed | A broken or hijacked release usually surfaces within days; a CA should not be among the first to run it |
| Two-week rule, exception: if an approved tool already pulls a newer version of a module into the graph (Go picks the highest), we don't downgrade the tool – the diff of the packages we actually use is checked against the approved version and the exception recorded (cases: x/crypto v0.58.0 via govulncheck, 2026-10-13; x/term v0.47.0, required by x/crypto v0.58.0 and x/net v0.61.0 – v0.46.0 would downgrade x/crypto, x/net, x/tools and x/vuln, 2026-10-16; x/text v0.43.0 for the same reason, 2026-10-17) | Downgrading the vulnerability scanner would cost more safety than it buys |
| Two-week rule, exception for **Go security point releases** (owner 2026-10-21): go1.27.3 two days after its release, because govulncheck found GO-2026-6809 (CVE-2026-111943) on a path we use – `ca.verifyCAChain` → `x509.Certificate.Verify`. The `go` line of `go.mod` is raised to 1.27.3 as well, so no older toolchain builds the project, not even with `GOTOOLCHAIN=local` | A point release changes only fixes; the risk of waiting (a CA trusting a distrusted intermediate) is larger than that of a two-day-old Go release from the Go team |
| `permissions: contents: read`, `persist-credentials: false` | Least privilege – a compromised step can't push or read a token from `.git/config` |
| Runner images pinned (`ubuntu-24.04`, `windows-2025`, `macos-15`) | `*-latest` changes underneath; failures should come from our changes |
| sqlc is installed in CI only when `sqlc.yaml` exists | Not used before phase 1 |
| `CGO_ENABLED` written directly in front of every Go command in `Taskfile.yml`; only the `race` job enables CGO; `task build:verify` checks the build info of every binary | Task doesn't override variables already set in the environment, so a top-level `env:` could be silently overruled (first CI run: `-race requires cgo`; locally `CGO_ENABLED=1` produced CGO binaries). Release binaries must stay pure Go (ADR-01) |

### Presets
| Decision | Why |
|---|---|
| Key usages split into `key_usage.rsa` and `key_usage.other` (ECDSA, Ed25519) | Legacy only knew RSA and Ed25519; non-RSA keys can't encrypt, so `keyEncipherment` is RSA-only |
| `subject_alt_names.required_any_of` as a list (legacy: `"dns\|ip"`) | Unambiguous and validated per element |
| EKUs by name; a dotted OID only for EKUs without a name (e.g. `1.3.6.1.5.5.8.2.2`); `ipsecIKE` names 1.3.6.1.5.5.7.3.17 | One spelling per usage, so duplicates are detectable |
| `keyAgreement`, `encipherOnly`, `decipherOnly` rejected | `other` also covers Ed25519, which can't do key agreement; no legacy preset uses them |
| Cross-field rules: serverAuth ⇒ DNS/IP SAN required; emailProtection ⇒ e-mail SAN required; timeStamping only and critical (RFC 3161); `ocsp_no_check` ⇒ OCSPSigning; `openssl_purpose` matches the EKUs; `customizable` only for family `custom` | Each encodes an RFC / CA-B Forum requirement; all 12 legacy presets already satisfy them |
| `validity_days` 1–3650, files ≤ 64 KiB, one YAML document per file, names sorted alphabetically | Sanity bounds and cheap hardening for later uploads; display order is a UI decision |

**Finding for the CA engine:** `crypto/x509` always writes extendedKeyUsage as non-critical, so the
`timestamp` preset's critical EKU (and `id-pkix-ocsp-nocheck`) must be built as extra extensions –
`internal/ca/preset/x509_test.go` shows how. keyUsage and basicConstraints are always critical, as required.

### API draft
| Decision | Why |
|---|---|
| `x-required-role` and `x-step-up` on every operation | RBAC and step-up become reviewable and testable in the spec |
| `/health` unauthenticated and returns only "ok"; version and seal state only via `/system/status` – since step 13 the listener's own `GET /healthz` is the only health check, `/api/v1/health` is gone (owner 2026-10-17) | Load balancers need a check; anonymous endpoints must not reveal versions; one check is enough |
| Key export is `POST /certificates/{id}/export` with the password in the body (step 18; step 13 has only `pkcs8-pem` without a password) | Secrets in URLs end up in proxy logs and browser history |
| `certificateHold` not offered | Temporary revocation is poorly supported; CA/B Baseline Requirements forbid it |
| Role scopes `tenant` and `ca` only; no tenant in any path | Domain/agent-group scopes come with phases 2/3; the tenant comes from the authenticated context |
| Not in the draft: batch upload, encrypted backup download, ACME, domains, agents | Not in the phase 1 row or belong to later phases |
| **No code generator: API handlers are written by hand** with `net/http` (ServeMux patterns) and `encoding/json`; the spec stays the source of truth through **contract tests** (steps 13 and 18) that check every operation for route, method, role (`x-required-role`), RFC 9457 errors and response schema (owner decision 2026-10-13, trial in `docs/trials/ogen.md`) | ogen would add 27 runtime modules (+18 % binary for 3 endpoints), can't generate `issueCertificate` and the legacy import, gives handlers no access to cookies/headers and leaks internal error text by default; its strength – schema-driven input validation – is covered by the contract tests |

### Storage foundation (phase 1 step 4)
| Decision | Why |
|---|---|
| `modernc.org/sqlite` v1.60.1 (SQLite 3.53.4, BSD-3, 8 runtime modules, ~7 MB) – approved 2026-10-13 | Pure Go (ADR-01/06); builds for all five targets without CGO |
| Per file one **writer connection** (`_txlock=immediate`) and a **read pool** with `PRAGMA query_only` | Writes queue inside the process instead of failing with SQLITE_BUSY; WAL keeps readers going; a read path can't write by mistake |
| Pragmas on every connection: WAL (writer), `busy_timeout` 5 s, `foreign_keys`, `synchronous=NORMAL` | NORMAL is safe with WAL: a power cut can lose the last commits, never corrupt the file |
| **Own migration runner** instead of goose (owner decision 2026-10-13): forward only, one transaction per migration, SHA-256 of each applied file (line endings normalized) stored; a changed file or a database from a newer binary stops everything | No dependency; the schema history of a CA can't diverge silently; going back = `myownpki restore` |
| Every database starts with `db_info.db_type`; a file of the wrong type is refused before anything is migrated | Catches swapped files after a manual restore |
| Tenant IDs are directory names: `^[a-z0-9][a-z0-9-]{0,62}$`; directories created with mode 0700 | No path traversal, no case collisions on Windows/macOS |
| `myownpki db status` (read-only; exit 0 = up to date, 1 = problem, 3 = missing/pending) and `myownpki db migrate` | Scriptable check for monitoring; a problem outranks "pending" because migrating would not fix it |
| sqlc: one block and one Go package per database type (`systemdb`, later `pkidb`, `auditdb` …); schema = the migration files | A package only knows the tables of its own file – a query across databases doesn't compile |
| SQL files (schema and queries) are ASCII only, enforced by a test | sqlc 1.31.1 miscounts positions after multi-byte characters in SQLite files and cuts statements short (found in step 4) |

### Audit log (phase 1 step 5, design approved 2026-10-13)
| Decision | Why |
|---|---|
| Two kinds of log: `<data>/audit.db` (instance: logins, users, unseal) and `tenants/<t>/audit.db`; each file records its scope in `db_info`, a file in the wrong place is refused | A global admin's login doesn't belong in a tenant's log; swapped files are caught |
| `hash = SHA-256("MYOWNPKI-AUDIT-V1", prev_hash, seq, outbox_id, time, actor…, details_json)`, every field length-prefixed; first `prev_hash` = SHA-256 of a genesis tag and the scope | No ambiguity between fields (unlike concatenation or JSON); a log can't be passed off as another scope's |
| Append-only enforced twice: no UPDATE/DELETE in the code, and triggers in the schema; tampering is detected by `Verify` at the exact `seq` (modified, missing, link broken) | Triggers stop bugs, the chain catches file edits |
| Outbox per producing database (`AUTOINCREMENT` ids), delivered exactly once: append (dedup by `outbox_id`, also `UNIQUE` in the schema), then mark delivered; delivered rows deleted after 30 days, undelivered never | A crash between the two steps leads to a recognized duplicate, never to a lost or double entry |
| Details are validated: no secret-looking keys (password, passphrase, secret, private, credential, token …), IP addresses only, ≤ 8 KiB | Second line of defense against logging secrets; data minimization (GDPR note in §5) |
| `myownpki audit verify [--scope] [--expect-head SEQ:HASH]` (read-only; exit 0/1/3); the deliverer logs every chain head at start and daily | The head in the process log is the anchor until signed checkpoints (step 6a) and SIEM export (phase 5) |
| Signed checkpoints (step 6a): Ed25519 instead of HMAC, key derived from the root key via HKDF; checkpoints are chain entries (`audit.checkpoint`); `verify` checks signature, coverage and one key per log, and pins the key with `--checkpoint-key` | Verification needs only the public key – offline, without unseal; pinning stops an attacker who re-signs everything with an own key |

### Keys and unseal (phase 1 step 6, design approved 2026-10-13)
| Decision | Why |
|---|---|
| Hierarchy passphrase → KEK (Argon2id t=4, 256 MiB, p=4) → root key → DEK per key → private key; recovery key (HKDF) as second wrap of the root key; AES-256-GCM everywhere with additional data binding purpose, slot or key ID | Passphrase change and reset rewrite one row; a ciphertext moved to another row or purpose doesn't decrypt |
| Root key only in memory while unsealed; DEK and private key decrypted per operation (`WithKey`/`WithSigner`), buffers cleared afterwards; seal waits for running signatures | Shortest possible lifetime of key material; Go can't clear parsed key objects – docs recommend no core dumps and no unencrypted swap |
| One secret check at a time; 3 free failures, then 1 min doubling to 1 h; every attempt audited (success, failure, denied) in the instance log; nothing about the secret is logged | Each attempt costs 256 MiB – no memory exhaustion by parallel guesses; guessing is slowed and visible |
| Stored Argon2id parameters are bounds-checked before use | A tampered row can't turn an unseal attempt into a denial of service |
| *(2026-10-23)* The production values are also the **minimum at unseal**: a passphrase slot with less (t, memory or lanes) is refused and audited (`denied`, `weak_kdf`); the way out is the recovery key and a new passphrase. Weaker values exist only for tests (`keys.TestKDF`, `auth.TestParams` – one place, `keys.TestArgon2`) and only in test binaries (`testing.Testing()`): no flag, configuration key or environment variable; outside a test binary the option panics. Every v0.1.0 key ring has exactly t=4, 256 MiB, p=4 (checked by the upgrade test) | A key ring made by a test build must never protect real keys; tests need 8 MiB instead of 256 MiB per derivation (the race job ran out of memory) |
| Recovery key: Crockford Base32, 9 groups of 6, 2 check characters (typos are caught before a real attempt); redacted in `%v`, JSON and slog – only `Reveal()` prints it | It can't reach a log by accident |
| Recovery key output and confirmation are prepared for `myownpki init` (step 11): terminal only if interactive, otherwise `--recovery-key-file` (0600, never overwritten); two random groups re-typed before anything is stored | Owner decision 2026-10-13 |
| `golang.org/x/crypto/openpgp` is blocked by depguard | GO-2026-5932: unmaintained and unsafe by design; it ships in the same module as argon2 |

### CA engine (phase 1 step 7, design approved 2026-10-13)
| Decision | Why |
|---|---|
| A CA has generations (`ca_generations`): each key and its certificate is one generation; AIA/CDP URLs contain it (`<base>/ca/<name>/<n>.crt`, `<base>/crl/<name>/<n>.crl`); CA names are immutable | A renewal with a new key would otherwise break the chains and CRLs of every older certificate (AD CS uses `CAName(1).crt` for the same reason) |
| Every check runs before signing: CSR signature, key policy, names (strict LDH/IP/e-mail/URI, punycode only, wildcards only in the wildcard preset), preset SAN rules, name constraints and EKU limits of every CA up to the root, validity | Clients are not relied on to reject; a refused request never reaches the key |
| The CSR's names and subject are a wish list; its extensions are never read | Copying `CA:TRUE` or `keyCertSign` from a CSR would mint a rogue CA (tested) |
| After signing, the certificate is parsed and verified against the chain with `crypto/x509` (name constraints, EKU nesting) before it is stored | Second, independent layer – a gap in the first check becomes a failure, not a certificate (tested by removing each layer) |
| Certificate, names, server-generated key (encrypted) and the `certificate.issue` audit event in one pki.db transaction; refusals go to the tenant audit log as `denied` (policy) or `failure` (sealed, internal) | Nothing is stored without its audit entry; every refusal is visible |
| 159-bit random serials, unique per CA across generations; issued certificates can't be updated or deleted (triggers) | RFC 5280: issuer name + serial identify one certificate, forever – a reused serial would make CRLs ambiguous |
| SKI per RFC 7093 (SHA-256, 160 bits); lifetime counts both ends (notAfter = notBefore + days − 1 s); notBefore 5 minutes in the past, never before the CA's start | Modern SKI method; exact lifetimes for validity limits; clients with a slow clock |

### CA lifecycle (phase 1 step 8, design approved 2026-10-14)
| Decision | Why |
|---|---|
| Online root (key encrypted in pki.db, with a warning) or **imported offline root** (certificate only, fingerprint shown to compare) | Homelab convenience and best practice side by side; the import is the moment trust is decided |
| Intermediate below an offline root: server creates key + CSR + an OpenSSL extension file; the root signs with exactly that file (`copy_extensions none`, digest matching the root key) – legacy `pki ca-sign` or plain OpenSSL; the upload is checked against the order (key, subject, CA:TRUE, KU, pathlen, name constraints, EKU, AKI = root SKI, serial unused, validity inside the root, SHA-2/Ed25519 only) | A CSR is attacker input even from our own server: what the CA certificate may do is decided by the server's order, and anything else signed offline is refused before it becomes trusted |
| Renewal only with a new key → next generation; the old generation keeps its URL and its CRL; an offline root is renewed by importing its new certificate under the same name | Older chains and CRLs keep working (step 7 URL layout); same-key renewal would need a certificate history – only the importer needs that (step 10) |
| Parent checks: pathlen of the parent allows the new level, EKU limit is a subset, DNS name constraints outside the parent's are warned about; subject DNs unique among CAs; CA names immutable | Mistakes are caught where they are made, not by clients months later |
| New CA keys P-384/P-256/RSA 3072/4096; imported RSA 2048 and P-521 with a warning; Ed25519 never as CA | Browsers and Windows don't verify Ed25519 chains; Chrome rejects P-521 in TLS chains |
| Every lifecycle action audited in the pki.db transaction (`ca.create`, `ca.import_root`, `ca.csr_create`, `ca.certificate_install`, `ca.renew`, `ca.retire`, `ca.update`); refusals as denied/failure in the tenant log | Same rule as issuance: nothing changes without its audit entry |

### Revocation and CRLs (phase 1 step 9, design approved 2026-10-14)
| Decision | Why |
|---|---|
| Revocations are final and stored at once (also while sealed); the CRL of the issuing generation is signed right after – or at unseal; until then "N revocation(s) not yet published" | An urgent revocation must not wait for a passphrase, but nobody should believe it is effective before a CRL lists it |
| One CRL per CA generation, number strictly increasing per CA across generations, AKI = SKI of the generation, renewed after ⅓ of the lifetime, warning from ½, entries kept until notAfter + crl_days (RFC 5280 §3.3) | Older chains keep a working CRL; caches always prefer the newest number; a warning means a renewal was missed, with half the lifetime left to act |
| keyCompromise/cACompromise block the key (SHA-256 of the SubjectPublicKeyInfo) for every new certificate and CA of the tenant | A key reported stolen must never come back in a new CSR |
| The offline root's CRL is uploaded and checked (signer generation, number, times, no delta, no unknown critical extension); intermediates it lists are marked revoked and stop issuing | The server can't sign it, but must neither serve a stale or foreign CRL nor keep using a CA its root has revoked |
| Serving: DER over plain HTTP, `max-age=900` with ETag/Last-Modified/304 and HEAD; legacy aliases only for imported CAs | A new CRL gets through proxies within minutes; unchanged files cost nothing |
| No issuingDistributionPoint for now | OpenSSL refuses a CRL with IDP for certificates without a CDP ("different CRL scope") – legacy certificates without AIA_BASE_URL have none (tested) |

### Auth core (phase 1 step 10, design approved 2026-10-15)
| Decision | Why |
|---|---|
| Argon2id 64 MiB/t=3, at most 4 at once, throttle before the hash, "busy" after 2 s | A login flood can't take the memory; guessing is slowed before it costs anything |
| Passwords 12–256 characters, no composition rules or expiry, checked against 46,145 common passwords (Xato 1M, filtered to ≥ 12) | NIST SP 800-63B; a 10k list would hold only 10 entries of that length |
| TOTP secret fixed at creation, encrypted with a separate auth key (AAD = purpose + user); codes work once; recovery codes 100 bits, HMAC-keyed | A copy of `system.db` alone holds no usable second factor; no window to enroll a foreign authenticator |
| Sessions: SHA-256 of the ID stored, `__Host-` cookie, new ID after the second factor, idle 30 min / absolute 12 h; CSRF = `http.CrossOriginProtection` + token | A stolen database holds no session; standard browser protections first, the token for older browsers |
| Lockout time-limited (10 failures → 15 min), `user unlock` on the console | A permanent lockout is a switch for attackers to turn the admin off |
| Roles checked in the CA engine and the keyring (`internal/authz`); instance admin separate from tenant roles; viewers don't read the audit log; the last active instance admin and tenant admin always stay | No handler can forget a check; managing users is not the same as running the PKI; audit entries are personal data |
| `user reset-2fa` needs the unseal passphrase or the recovery key | Losing the auth key or a phone must be recoverable – but not by shell access alone |

### Setup – `myownpki init` (phase 1 step 11, design approved 2026-10-15)
| Decision | Why |
|---|---|
| Ask and confirm everything first, then write; secret files before the database; a broken-off run is finished by running init again with the passphrase as proof | A half-done init (root key, no user) must neither leave the operator locked out nor be repeatable by anybody without the passphrase |
| Interactive, `--stdin` (two lines, only the line end removed) and `--demo` (all secrets generated into one file) | People, automation and a quick try-out need different things; spaces belong to a passphrase |
| A demo instance is marked for good; the warning in `db status`, the server log and the UI | All secrets in one file is the opposite of keeping them apart – nobody should drift into production with it |
| Test CA names carry a random tag and the host name | Two test instances never produce roots with the same name in a trust store |
| Admin password ≠ unseal passphrase (also ignoring case) | They protect different things and must not fall together |

### Server (phase 1 step 12, design approved 2026-10-16)
| Decision | Why |
|---|---|
| Bootstrap certificate as a self-signed end-entity certificate, key unencrypted, fingerprint at every start | Browsers accept an exception only for a non-CA certificate; the admin listener must work while sealed, and the fingerprint is the check |
| Allowlist before the TLS handshake, refusals summed up once a minute | A scanner sees nothing and can't flood the log |
| Listeners start sealed; `--unseal` asks only afterwards; a wrong passphrase keeps the server running | CRLs and CA certificates are served from the first second, whatever the operator types |
| Shutdown within 8 s, seal with the last checkpoint at the end | Container runtimes kill after 10 s; the audit log must be signed up to the end |
| Direct audit entries fail-closed, outbox entries may pile up (warned with count and age) | No unseal or sign-in without a trace; business changes are never lost, only delayed |

### REST API part 1 (phase 1 step 13, design approved 2026-10-17)
| Decision | Why |
|---|---|
| A route table in `internal/httpapi`, each row an operation of the spec; contract tests compare both and validate every answer against the JSON Schema of the spec, plus a check that no field outside the spec is sent | The spec stays the source of truth without a generator; a renamed field fails a test instead of a client |
| No read access = 404 (as for an unknown ID); read access but a too low role = 403 | Nobody can probe which CAs or certificates exist; whoever may see an object learns why an action fails |
| Sign-in works sealed; reading works sealed, signing answers 503 `sealed` | The browser must be able to sign in to unseal; the TOTP secrets are under the auth key, not the unseal key |
| Device cookies (OWASP) with a credentials epoch (system 0006) | A stranger who knows a user name can't lock the real admin out; a new password, a new second factor or `user unlock` void every old device |
| Status and session polling are passive (decided by the route) | An open tab must not keep a session alive forever |
| Private key download in step 13 as unencrypted PKCS#8 PEM over TLS, with step-up, audited before the key leaves; PKCS#12 with a password in step 18 | The browser test needs server-generated keys; PKCS#12 needs another dependency, decided at step 18 |
| JSON bodies only (415 otherwise), unknown fields refused | A form post or a typo can't slip through |

### Web UI part 1 (phase 1 step 14, design approved 2026-10-17)
| Decision | Why |
|---|---|
| The real UI calls the services directly, not the REST API over HTTP; pages of the prototype are reused | One permission check in the service layer for both; no second client to secure |
| Plain forms, Post/Redirect/Get with 303, messages in a short-lived cookie; no htmx yet | A reload never issues twice; no text from a URL reaches a page; nothing JavaScript needs to do for M1 |
| The sign-in page shows nothing about the instance and one message for every failure | Version, seal state and the demo mark help strangers; the message must not tell real names from invented ones |
| `next=` only as a strictly checked local path | An open redirect after sign-in is a classic phishing aid |
| The CSR's names fill the form; issued is what the form says | The requester sees and confirms the names; extensions and names never come from the CSR unchecked (ADR-19, pki-rules) |

### Night run 2026-10-21 (phase 1 steps 15–20, release) – for the owner to confirm
Taken alone during the autonomous run, each the reversible variant; docs/NIGHTLOG.md has the full
tables with "how to reverse".

| Decision | Why |
|---|---|
| Legacy import: reader `internal/ca/legacy` (parses, never executes) + `ca.ImportLegacy` in one transaction + `myownpki import legacy DIR [--dry-run]`; the root becomes an **offline root** by default (`--root-key online` imports its key) | pki.sh stays the offline root tool; all or nothing; the dry run shows every problem first |
| Import keeps serials, revocation time and reason and the CRL numbering: `crlnumber` (hex) − 1 becomes the last number, pki.sh's CRL is kept as evidence, every online CA signs its next CRL in the import transaction; certificateHold → unspecified, CACompromise on a leaf → keyCompromise, both with a warning | RFC 5280 §5.2.3 (numbers never go back); what relying parties see stays the same |
| Older certificates of a key pki.sh renewed (`renew-ca`) go into `ca_certificate_history` (pki.db 0006) | They verify the same leaves and are evidence |
| Backup = a new directory with `VACUUM INTO` copies (audit logs last) and `manifest.json` (SHA-256, migration versions, audit heads, checkpoint key); `backup verify` and `restore` run the same checks on a work copy, incl. integrity, chains ending at the heads and the SAN index; restore only into an empty data directory | Works while the server runs; a manipulated or damaged backup never becomes the PKI |
| Passkeys (go-webauthn v0.18.2) as **second factor and step-up**, only with `auth.passkey_origin`; adding one needs step-up + current password, raises the credentials epoch and ends other sessions; UV required, no attestation; reset-2fa removes passkeys | Same rules as TOTP (decision 45); WebAuthn binds passkeys to the host name users type |
| No passkey button in the UI until esbuild (ADR-04) or one plain script is approved | A browser needs `navigator.credentials`; no ADR change at night |
| PKCS#12 export written by our own code (`internal/pkcs12`: PBES2 AES-256-CBC, PBKDF2-SHA256 600,000 iterations, MAC HMAC-SHA256, password ≥ 12 characters); "delete the key after the download" overwrites DEK and ciphertext, the row stays (pki.db 0007) | No PKCS#12 module approved; what OpenSSL 3 writes and current Windows/macOS/Java import |
| API tokens (`mop_…`, only SHA-256 stored, expiry ≤ 1 year, roles ≤ the owner's) **never satisfy step-up** | Step-up means a human with a second factor; no revoke, key download or CA management by token |
| `DELETE /users/{id}` disables the user; a refused legacy import over the API answers 201 with a job of status `failed`; removing a passkey is `POST …/remove` | Users are never deleted (decision 47); the spec rules want shared problem responses; no request body on DELETE |
| UI part 2 with three generic templates (form, table, detail), still no JavaScript; pages that show a secret once (new user's authenticator, token, recovery codes, export file) answer the POST itself with `no-store` instead of PRG | A secret never travels in a cookie or URL and is shown once |
| `myownpki healthcheck` pins the exact certificate file the admin listener serves (no CA check); `127.0.0.1` must be in `admin.allowed_networks` when that is set | Distroless has no curl; an unchecked TLS connection would talk to anything on the port |
| `myownpki passphrase change` / `reset` (console): the key ring could since step 6, no command used it – the recovery key was a dead end | A lost passphrase must be recoverable with the recovery key (§5) |
| Release v0.1: only the server binary; archives and image reproducible (commit time stamps, `-trimpath`, symbols kept); `checksums.txt` and the image signed keyless; image without `latest` tag and without buildx SBOM; multi-platform build through Docker's containerd image store instead of an extra BuildKit image; GoReleaser makes a draft, the GHCR package starts private | Nothing becomes public before the owner checks it; no tool or image beyond the approved ones |

### Web UI and dev mode
| Decision | Why |
|---|---|
| `serve` refuses to start without `--dev` until TLS and login exist; dev mode rejects host names, IPv6 zones and port 0 | Nothing unauthenticated may reach the network |
| Dev default `127.0.0.1:9443` (the future admin port), plain HTTP; banner on stderr and sticky on every page | Same URL habit as later, unmistakable mode |
| CSP from security.md plus `img-src 'self'; form-action 'self'`; COOP/CORP, X-Frame-Options, Permissions-Policy; HSTS only with TLS (phase 1) | Strict defaults from the first page |
| Static assets: explicit Content-Type for `.css`/`.svg`, `Cache-Control: no-cache`, no directory listings | On Windows Go takes MIME types from the registry, and with `nosniff` a wrong type breaks the page; asset URLs aren't fingerprinted yet |
| No htmx and no JavaScript yet; dark mode demonstrated with `data-theme="dark"` on a preview block | Not needed for a static gallery; htmx is vendored with approval in phase 1 |
| Status colors fixed per light/dark mode | Themes can't change them (ADR-12), but dark mode needs other shades for contrast |
| Log timestamps converted to UTC | "UTC everywhere" – the first dev run logged local time |
| Demo data without real names (`it-admin@homelab.lan`) | Public repository |

### UI direction (after review of the phase 0 gallery, 2026-10-13)
The first gallery was rated "about 40 % AI-looking" (layout, tiles/boxes, icons). New direction:
**classic enterprise admin tool** (Windows Admin Center, vCenter). ADR-12 and ADR-13 stay unchanged –
this only changes tokens, component classes and the shell.

| Decision | Why |
|---|---|
| Shell: fixed text-only sidebar grouped by area (Overview, Certificates, Authorities, ACME, Agents, Administration); dark header with product, tenant switch, search, user menu; breadcrumb; title left, commands right; content at full width | Familiar from Windows/VMware admin tools; no centered column, no table of contents |
| Light by default, dark and "follow the OS" optional; 2 px radii; few borders; sections separated by spacing and headings | Calm, dense, professional |
| No KPI cards – overview figures as a plain number row; no pastel notices – messages as a line with a text label ("Warning:", "Error:") | Removes the "dashboard template" look |
| No icons in status, messages, buttons or navigation; status as text with an optional small dot | Text is unambiguous and accessible; the icon sprite was removed |
| Logo (assets/brand, owner's design) as the only image: small on-dark variant in the header, favicons (SVG with light/dark, ICO, Apple touch icon) served same-origin; brand gold only in the logo, not a CSS token | Recognizable without breaking the "no icons" rule; gold would be confused with the warning color |
| System fonts (Segoe UI + Consolas on Windows, platform fonts elsewhere); IBM Plex Sans/Mono was compared in screenshots and not adopted (owner decision) | No download, no license file; switching later only touches two tokens |
| Appearance (layout variant, light/dark/system, density) stored per browser in a cookie, values checked against an allow-list, switched server-side without JavaScript | Works under the strict CSP; no client code |
| Layout variants for now: A narrow sidebar, B standard sidebar (default), C no sidebar; small screens use the C navigation | The final split of A/B/C (PLAN §7) is decided after the prototype |
| UI prototype in dev mode on fixture data with the real templ components (dashboard, certificate list and detail with tabs, issue wizard, CA list and detail, appearance) | Phase 1 reuses pages and components and only replaces the fixture with the store |
| Wizard checks (presets, name constraints, CSR signature, per-CA max validity) run server-side and are repeated on the final submit | Hidden form fields are client input; the CA engine checks everything again in phase 1 |
| State-changing requests are rejected when cross-origin (`http.CrossOriginProtection`, Sec-Fetch-Site/Origin) | Baseline CSRF defence from the first form on; session-bound CSRF tokens follow with login (phase 1) |

### UI precision pass (2026-10-13)
| Decision | Why |
|---|---|
| Microsoft Fluent 2 as the metric yardstick (values only, no dependency) rather than VMware Clarity | Fluent 2 is built around Segoe UI (our font) and Windows Admin Center; its spacing ramp is in 4 px steps |
| Strict 4 px grid: every size is a token; outside `tokens.css` only 1px/2px lines are allowed – enforced by `TestStrictGrid` | Precision that can't erode over time |
| Type ramp caption 12/16, body 14/20 (also tables), subtitle 16/24, title 20/28, figures 28/36; 32 px controls, 36 px table rows (28 px compact) | One fixed hierarchy; line heights on the 4 px grid |
| Common left edge for breadcrumb, title, description, filters, command text, table text; table row lines end flush with the text edge (like the line under the tabs), command bars "bleed" by their inner padding | Edges line up; table lines and tab line form one edge (owner decision) |
| One page header for all pages, rendered by the shell from `view.Page` (breadcrumb except on the dashboard, title, status, description, actions) | Pages can't drift apart |
| Command bars grouped create \| edit/transfer \| dangerous (always last), separated by a line | Same order everywhere; destructive commands never in the middle |
| Number row as equal grid columns, semibold tabular figures | Figures line up like a table |
| Serials truncated with "…" in tables (full value in `title` and on the detail page); SHA-256 fingerprints as `78:3D:…` in two lines of 16 bytes | Readable lists; fingerprints comparable with `openssl x509 -fingerprint -sha256` |
| Consolas before Cascadia Mono | Optically closer to Segoe UI at the same size |

### v0.2.2 – own TLS, daily backup, trust page (owner decisions 2026-10-24)
From the production use of v0.2.1-rc.1 (Debian 13 LXC, install.sh through Salt). Built in the night
run of 2026-10-24 (docs/NIGHTLOG.md); rows marked *(night)* were decided alone, as the cautious
variant, for the owner to confirm.

| Decision | Why |
|---|---|
| **Amends PHASE2 Q1 ("ACME only behind a reverse proxy")**: `acme.tls_issuer` is an alternative – the ACME listener speaks TLS itself. Without it nothing changes: plain HTTP behind the proxy stays the default and stays supported | A homelab without a proxy can run ACME; the proxy way keeps working for everybody who has one |
| `admin.tls_issuer` / `acme.tls_issuer` name a CA of the instance; the server issues the listener's certificate through `ca.Engine.Issue` (preset *server*, a new ECDSA P-256 key per certificate, a CSR, `IgnoreCSRNames` with exactly the configured names), audited as *system / server* | One policy engine (ADR-19): name constraints, CA limits and the audit log apply to the server's own certificate too |
| 90 days at most, capped by the CA's maximum and its end; renewed at 2/3, at once after a revocation, a name change or a CA renewal (the leaf no longer verifies against the CA's current certificate) | Short-lived like ACME certificates; nothing to renew by hand |
| Key unencrypted in `<data_dir>/tls/<listener>.key` (0600), fullchain without the root in `<listener>.crt`; issuance only while unsealed; an expired certificate falls back to the bootstrap certificate per handshake (`GetCertificate`), with a warning every 15 minutes and on the dashboard | The listeners must work while sealed, like the bootstrap certificate (§5); no restart for a switch |
| *(night)* Config keys `tls_issuer` (the owner's proposal) – not `tls_ca` | `tls_ca` reads like "the CA to verify clients against" (nginx, Traefik) – a dangerous misreading |
| *(night)* `admin.tls_issuer` needs `admin.tls_names` and excludes `admin.tls_cert_file`; the issued certificate has exactly `admin.tls_names` – no host name, `localhost` or loopback added | Name constraints of a real intermediate (e.g. `u.lab`) would refuse `localhost`; the health check pins the file, it needs no name |
| *(night)* A refused issuance is retried after 6 hours (other errors after 15 minutes), not at every check | Each refusal is an audit entry; a configuration error must not fill the log |
| `tls_issuer` must name an intermediate: a root is named at the start (log), as an error on the dashboard and as a warning in `config check` (when the CA database is readable) with the fix and the intermediates under that root; nothing is issued or tried, the listener serves the bootstrap certificate – also instead of a still valid certificate from an earlier intermediate | A root usually has no name constraints – a listener certificate straight from it would bypass the intermediate's. The engine refuses it anyway (CA/B BR §6.1.7); this names the fix before the first refusal and keeps refusals out of the audit log |
| A root in `tls_issuer` is a **warning** in `config check` (stderr, exit 0), not an invalid config | The server starts with it (bootstrap certificate), and install.sh aborts an update on a failed `config check` – a warning must not block an update; install.sh shows stderr |
| *(night)* With `acme.tls_issuer` the ACME listener serves its own self-signed bootstrap certificate (`acme-bootstrap.crt`) until the first issuance, instead of refusing the handshake | The same behaviour as the admin listener; clients refuse it with a clear "unknown authority" |
| With `acme.tls_issuer`: `acme.listen` is its own listener (never the admin one), every peer may connect, `acme.trusted_proxies` and `X-Forwarded-For` are ignored, the peer is the client address for rate limits and audit | No header is believed when no proxy wrote it |
| Daily backup: `myownpki-backup.timer` (daily, `RandomizedDelaySec=1h`, `Persistent=true`) starts `myownpki-backup.service` (oneshot), which runs `myownpki backup scheduled /var/backups/myownpki --keep ${BACKUP_KEEP}` – backup, verify, prune in one Go command, prune only after a passed check | One exit code per run for systemd (`systemctl --failed`); no shell in the unit to build the time stamp |
| `backup prune` deletes only complete scheduled backups: name `YYYYMMDDTHHMMSSZ`, a real directory, a readable manifest, exactly the listed files with the listed sizes; keep ≥ 1 | Never anything an admin put there, never a half-written or tampered directory |
| *(night)* install.sh's update backups (`<time>-<version>`) are **spared** – they don't count against `--keep` and prune never deletes them | They are the way back before a migration; one per update, few; daily backups must not push them out (nor they the daily ones) |
| *(night)* A scheduled backup that fails its check is renamed `<time>-unverified`: never pruned, not counted, the run fails | A bad backup must not count as one of the 14 good ones, and must stay for a look |
| *(night)* The backup unit may also write `/var/lib/myownpki` (not only the backup target, as asked) | SQLite writes its `-shm` lock file even to read a database in WAL mode, and every backup is an entry in the instance audit log – read-only would break both |
| *(night)* The backup unit adds `PrivateNetwork=yes`, `IPAddressDeny=any`, `RestrictAddressFamilies=AF_UNIX` to the server's sandbox | A backup needs no network; a test checks that it keeps every other setting of the main unit |
| *(night)* `BACKUP_KEEP` as `Environment=` in the unit, overridden by the drop-in `keep.conf` (`install.sh --backup-keep N`) – not a config key | `config.yaml` is never changed by install.sh, and an unknown `MYOWNPKI_*` variable is an error by design |
| *(night)* install.sh enables the timer only when it installs it the first time; `--no-backup-timer` disables it; a later run without the option leaves it off | An admin who switched it off keeps it off (Salt runs install.sh again and again) |
| *(night)* `backup prune` writes no audit entry (it reads only the backup directory, needs no config); the journal names every deleted and every skipped directory | The deletions are of copies, not of PKI state; creation is audited |
| Trust page at `/` of the public listener (internal/publish, templ page `internal/web/pages/trust` in the `Plain` layout, the app's stylesheets and logo served there too); CSP `default-src 'none'` plus own styles and images, no script; page 5 minutes, files 15 minutes cache with ETag | The same design language without the admin listener; nothing a stranger could make run |
| Tenant setting `trust_page` (system.db 0010, default on), asked per request; in `PUT /api/v1/settings` optional (absent keeps it), always in the answer – like `acme_limits` in v0.2 | v0.2 clients keep working; switching off applies at once |
| *(night)* Off switches only the page and the Windows helpers off; `/ca/…crt`, the new `/ca/…pem` and the CRLs stay | Certificates point to them (AIA, CDP) – they must never disappear |
| *(night)* Shown: active CAs, every generation that is valid now and not revoked (an older root generation stays while valid), roots first | After a root renewal, clients still need the older root for older certificates |
| Windows helper: one `.cmd` per root generation and store (LocalMachine with self-elevation, CurrentUser), Batch/PowerShell polyglot (`<# :` … `#>`), the root as PEM inside, its SHA-256 compared before the import, ASCII and CRLF; `/check` without import (the Windows CI job runs it), `/quiet` | The owner's existing approach; a changed file stops before it changes a trust store |
| *(night)* Any unknown argument stops the helper with exit code 64 before anything is imported | Found while testing: Git Bash turned `/check` into a path, and the helper went on to the import – a typo must never become a trust decision |
| *(night)* No `.mobileconfig` for Apple yet (PLAN §10.1 "trust store, small form" names it) | Not asked for in this run; the DER file works on iOS and macOS, the guide says how |
