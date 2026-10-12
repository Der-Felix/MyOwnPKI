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
├─ system.db                     tenants, global admins, settings, sessions
└─ tenants/<tenant>/
   ├─ pki.db                     CAs, certificates, domains, agents, policies, deploy profiles
   ├─ acme.db                    ACME accounts, orders, authorizations, challenges, nonces
   ├─ audit.db                   append-only, hash chain (tamper-evident)
   ├─ metrics.db                 time series for dashboards, retention + downsampling
   └─ keys/                      encrypted CA keys (or HSM references)
```

- SQLite in **WAL mode**, one writer per file → the split prevents cross-blocking.
- Type-safe queries with `sqlc`, migrations with `goose` (per database type).
- Backup/export/delete of a tenant = one directory.
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
| Online, encrypted | Server starts **sealed**, unlocked with a passphrase (unseal), key afterwards only in RAM |
| HSM / KMS | PKCS#11 (YubiHSM, Nitrokey, SoftHSM), later cloud KMS/TPM – separate build with CGO |

- The UI clearly warns about "root online" (root certificates are practically impossible to revoke).
- Minimum key standards configurable (e.g. per BSI TR-02102).

### Audit & supply chain
- Audit log as a hash chain, export to SIEM/syslog
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
│  ├─ api/                 REST handlers (generated from OpenAPI)
│  ├─ auth/                login, WebAuthn, TOTP, OIDC, RBAC
│  ├─ store/               SQLite, migrations, sqlc queries
│  ├─ keys/                unseal, encryption, PKCS#11
│  ├─ policy/              policies
│  ├─ notify/              notifications
│  └─ web/                 templ components, layouts A/B/C
├─ web/
│  ├─ styles/              tokens, base, components, layouts
│  └─ islands/             Web Components (TypeScript)
├─ api/openapi.yaml        spec first (ADR-05); api.Spec embeds it
├─ presets/*.yaml          ported from legacy/lib/presets.sh (+ README.md: file format)
├─ guides/*.tmpl           ported from legacy/lib/export.sh (GUIDE.txt)
├─ deploy/                 Dockerfile, Compose, LXC, systemd, Homebrew, Windows
├─ legacy/                 pki.sh + lib/ (offline root tool)
├─ .github/                CI workflow, shared setup action, Dependabot
├─ Taskfile.yml            build, test, lint, dev, cross, vuln
└─ docs/                   PLAN.md, NIGHTLOG.md (phase 0 log), PHASE1.md (proposal)
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
- [ ] OpenAPI code generator for phase 1 (oapi-codegen has partial 3.1 support, ogen full) – see docs/PHASE1.md
- [ ] Server-side key generation in the UI/API, or CSR signing only? – see docs/PHASE1.md

---

## 13. Tooling and conventions (decided in phase 0)

Not ADRs – operational choices that can be revisited without touching the architecture.
Rationale and alternatives: docs/NIGHTLOG.md.

| Topic | Decision |
|---|---|
| Go version | Toolchain pinned in `go.mod` (`toolchain go1.27.2`); `GOTOOLCHAIN=auto` downloads it, CI uses `GOTOOLCHAIN=local` |
| Task runner | Taskfile (`task check` before every commit; `task dev`, `task cross`, `task vuln`) |
| Configuration | One YAML file, strict decoding (unknown keys are errors) + `MYOWNPKI_*` env overrides; library `go.yaml.in/yaml/v3` |
| Dev mode | `myownpki serve --dev` – CLI flag only, never in the config file; binds only to the IP literals `127.0.0.1`/`::1`; "DEV MODE – no TLS, no auth" on start and on every page |
| Tools in `go.mod` (`go tool`) | templ (generator = runtime version), govulncheck |
| Tools as pinned binaries | golangci-lint 2.14.0 (GPL – must not enter `go.mod`), sqlc 1.31.1 (from phase 1), ShellCheck 0.11.0 (CI) |
| CI | GitHub Actions; actions pinned to commit SHAs; downloads verified by SHA-256; read-only token; daily govulncheck; Dependabot weekly |
| Lint | golangci-lint v2 with security and project rules (`.golangci.yml`): e.g. no `math/rand`, no `time.Now` outside tests, no `//nolint` without reason |
| Presets | `presets/*.yaml`, embedded; strict validation; parity test against `legacy/lib/presets.sh` |
| UI | System fonts, no JavaScript in phase 0, status colors fixed per light/dark, US English spelling |
| API errors | RFC 9457 with problem types `urn:myownpki:problem:<name>` (no domain chosen yet) |
