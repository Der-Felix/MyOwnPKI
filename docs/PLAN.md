# MyOwnPKI – Project Plan

> Status: phase 0 complete, phase 1 next · Last updated: 2026-10-13 · License: Apache-2.0
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

### Setup and admin access
- First administrator via **`myownpki init`** on the console (username, password; second factor
  enrolled at first login) – also sets the unseal passphrase, with the backup warning from §4.
- Admin listener TLS: at first start a **self-signed bootstrap certificate**, its SHA-256
  fingerprint printed on the console for verification; alternatively an operator-provided
  certificate. After setup the admin certificate is issued by the own CA.

### Audit & supply chain
- Audit log as a hash chain: `<data>/audit.db` for instance events (logins, users, unseal),
  `tenants/<t>/audit.db` per tenant. Entries of a business change arrive via the outbox of the same
  database (exactly once, deduplicated by `outbox_id`); events without a business change (failed
  login, denied request) are appended directly. `myownpki audit verify` walks every chain.
- **Anchors** – a hash chain alone can't detect a cut-off end or a fully recomputed chain by someone
  with write access to the file, so its head (seq + hash) is also kept elsewhere:
  - phase 1: written to the process log at start and daily, recorded in the backup manifest, and
    checked with `myownpki audit verify --expect-head`;
  - after step 6: **signed checkpoints** with a key bound to the unseal passphrase (PHASE1 step 6a) –
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
| **1 – Core** | Data model, CA engine, importer, REST API, login (2FA), RBAC, unseal, audit log, UI: issue / revoke / upload / download, layout B | Bash script replaced in the browser |
| **2 – ACME server & domains** | ACME server (http-01, dns-01, tls-alpn-01), domain model, policies, approval levels, EAB | certbot/Traefik/Caddy against the own CA (integration level 1) |
| **3 – Agent** | Enrollment with proof of control, issuance via ACME, deploy profiles (Linux first), heartbeat/inventory, batched reload + rollback; then Windows, FreeBSD; ACME client (lego) for Let's Encrypt | Deploy and monitor certificates (level 3), public certificates |
| **4 – Operations** | Dashboards, layouts A + C, themes (3 levels), notifications, OCSP/CRL, Prometheus, Litestream, trust store distribution | Production-ready |
| **5 – Enterprise** | Tenant UI, OIDC, HSM build, SIEM export, CT monitoring, network scan | Enterprise feature set |
| **Later** | Plugins (WASM sandbox), SSH CA, SCEP/EST, Terraform provider | – |

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
- [ ] Which DNS providers and deploy profiles have priority for phases 2/3?
- [ ] Which notification channels first?
- [x] Task runner: Taskfile (phase 0, see §13)
- [x] Configuration format: YAML (phase 0, see §13)
- [x] OpenAPI code generator: none – hand-written handlers + contract tests (trial of ogen, 2026-10-13, §14 "API draft")
- [x] Server-side key generation: yes, switchable per tenant, CSR is the default (§5)
- [x] Key storage: encrypted in `pki.db`, `keys/` only for HSM references (§4)
- [x] Repository visibility: public (2026-10-13)

---

## 13. Tooling and conventions (decided in phase 0)

Not ADRs – operational choices that can be revisited without touching the architecture.
Rationale and alternatives: docs/NIGHTLOG.md.

| Topic | Decision |
|---|---|
| Go version | Toolchain pinned in `go.mod` (`toolchain go1.27.2`); `GOTOOLCHAIN=auto` downloads it, CI uses `GOTOOLCHAIN=local` |
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
| Legacy ShellCheck | warnings fixed in a separate commit, then CI runs ShellCheck at severity `warning` (done in phase 1 step 0: entry scripts with followed sources, the standalone script in full, `lib/*.sh` without SC2034 because modules share globals – the standalone script covers it) |

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
| `/health` unauthenticated and returns only `{"status":"ok"}`; version and seal state only via `/system/status` | Load balancers need a check; anonymous endpoints must not reveal versions |
| Key export is `POST /certificates/{id}/export` with the password in the body | Secrets in URLs end up in proxy logs and browser history |
| `certificateHold` not offered | Temporary revocation is poorly supported; CA/B Baseline Requirements forbid it |
| Role scopes `tenant` and `ca` only; no tenant in any path | Domain/agent-group scopes come with phases 2/3; the tenant comes from the authenticated context |
| Not in the draft: batch upload, encrypted backup download, ACME, domains, agents | Not in the phase 1 row or belong to later phases |
| **No code generator: API handlers are written by hand** with `net/http` (ServeMux patterns) and `encoding/json`; the spec stays the source of truth through **contract tests** (step 16) that check every operation for route, method, role (`x-required-role`), RFC 9457 errors and response schema (owner decision 2026-10-13, trial in `docs/trials/ogen.md`) | ogen would add 27 runtime modules (+18 % binary for 3 endpoints), can't generate `issueCertificate` and the legacy import, gives handlers no access to cookies/headers and leaks internal error text by default; its strength – schema-driven input validation – is covered by the contract tests |

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
