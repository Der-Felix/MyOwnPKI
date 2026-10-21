# Phase 3 – plan (v0.3: Linux agent and monitoring)

> Written at the end of the night run 2026-10-21. A **proposal** that builds on PHASE2.md (the ACME
> server must exist first). Nothing in it is decided until the owner has answered §4.

Goal (PLAN §10.1, v0.3): the **Linux agent** – enrollment with proof of control (ADR-18),
certificates through ACME (ADR-19), deploy profiles **nginx, Apache, HAProxy, file + hook** with
reload and **rollback**, heartbeat and inventory – and **monitoring**: expiry dashboard, a TLS scan
of the endpoints (integration level 2), notifications by **e-mail and webhook**, including the
**alarm when the server stays sealed**.

Rules that shape every step:

- **The agent is just another ACME client (ADR-19).** It gets certificates through the ACME server
  of phase 2 with the same policy as certbot. Its extra powers – inventory, deploy, reload – come
  from its own mTLS channel (ADR-10), never from a privileged issuance path.
- **Keys are generated on the host (ADR-11)**; the private key never leaves it.
- **No remote command execution** (security.md "Agent trust"): the server can only ask for hooks the
  agent's local config allows. The server never sends a command line.
- **Outbound only (ADR-10):** the agent connects to the server; no open port on the host – except
  port 80 for an http-01 challenge, and only while one runs (or dns-01).
- Agent reports are attacker input on the server side (a compromised host must not reach beyond
  its own names).

---

## 1. Data model

### 1.1 Agents (`tenants/<t>/pki.db`, migration 0010)

```
agents
  id TEXT PK
  hostname TEXT                       -- as proven at enrollment (FQDN)
  status TEXT                         -- pending_approval | active | disabled | revoked
  enrollment_mode TEXT                -- auto | verified | manual (PLAN §6.2), the mode that admitted it
  proof TEXT                          -- JSON: which checks passed (token, http-01, dns-01) and when
  cert_serial TEXT NULL               -- its current mTLS certificate (from the agent-ca)
  acme_account_id NULL → acme_accounts.id
  tags TEXT                           -- JSON {"role":"webserver","site":"fra"}
  os, arch, agent_version TEXT
  last_seen_at NULL, created_at, approved_at NULL, approved_by NULL

agent_names                           -- names the agent may order for (policy, security.md)
  agent_id → agents.id, name TEXT     -- the hostname plus names an admin adds

join_tokens                           -- single-use, short-lived, scoped (security.md)
  id TEXT PK, token_hash TEXT, name_patterns TEXT (JSON), expires_at, used_at NULL, created_by

agent_deployments                     -- what the agent should keep in place, and what it reports
  id TEXT PK, agent_id, profile TEXT  -- nginx | apache | haproxy | file
  names TEXT (JSON), preset TEXT
  target TEXT (JSON)                  -- paths, owner, mode, format – validated server-side and again by the agent
  state TEXT                          -- pending | deployed | failed | rolled_back
  certificate_id NULL, deployed_at NULL, last_error NULL, served_fingerprint NULL

agent_heartbeats                      -- the last N per agent (ring), for the dashboard
  agent_id, at, report TEXT (JSON: certificates found on disk, versions, TLS self-check)
```

The **agent CA** is a dedicated intermediate (`agent-ca`, client-auth EKU only, short lifetimes –
7 days, renewed over the existing channel). It is created by `init` or the first enrollment and
never issues for other purposes.

### 1.2 Monitoring (`pki.db`, migration 0011; `system.db` for channels)

```
endpoints                             -- what the TLS scan checks (level 2)
  id TEXT PK, host TEXT, port INTEGER, sni TEXT NULL
  source TEXT                         -- manual | agent | certificate (SANs of issued certificates)
  last_scan_at NULL, last_fingerprint NULL, last_error NULL, expires_at NULL

alerts
  id TEXT PK, kind TEXT               -- expiry | sealed | crl_stale | deploy_failed | agent_silent | scan_mismatch
  subject TEXT, severity TEXT, first_seen_at, last_seen_at, resolved_at NULL, notified_at NULL

notification_channels (system.db)     -- e-mail (SMTP) and webhook first (PLAN §12)
  id, kind, config TEXT               -- secrets (SMTP password, webhook HMAC key) encrypted with a DEK
  enabled, created_at
```

### 1.3 Agent configuration (`/etc/myownpki-agent/agent.yaml`)

```yaml
server: https://pki.homelab.lan:8444     # the agent listener (ADR-08), see Q1
acme_directory: https://pki.homelab.lan:8443/acme/directory   # any ACME CA – Let's Encrypt later is only this line
ca_bundle: /etc/myownpki-agent/root.pem  # trust anchor for both
hooks:                                   # the ONLY commands the agent ever runs (allowlist)
  nginx: ["/usr/sbin/nginx", "-t"]       # test first …
  nginx-reload: ["/usr/bin/systemctl", "reload", "nginx"]
paths:                                   # where deploy profiles may write
  - /etc/ssl/myownpki/
dns01:                                   # optional, for hosts without port 80
  provider: rfc2136                      # rfc2136 | cloudflare (lego providers, PLAN §12)
```

---

## 2. Work plan

| # | Step | Approval needed | Verifies with |
|---|---|---|---|
| 1 | **Agent listener** (ADR-08, its own port) with mTLS against the agent CA only; the agent CA (client-auth only); the protocol: Connect-RPC (ADR-10) with a small protobuf service – enroll, heartbeat, fetch desired state, report | Q2 (connect-go + protobuf, or JSON over HTTPS) | a client without an agent certificate can't even finish the handshake; an agent certificate is refused on the admin listener |
| 2 | **Enrollment** (ADR-18): the agent makes its key and CSR, sends the join token (if any); the server checks control of the hostname by http-01 (fetches from the agent, SSRF rules of PHASE2 step 7) or dns-01; mode `auto` / `verified` (default) / `manual`; the approval queue in the UI (like `salt-key -A`) | – | each mode × (token, check passed, check failed) gives the table of PLAN §6.2; a token is single-use and expires; audit entries |
| 3 | **Agent certificate renewal** over the channel (7 days, renewed at 2/3), revocation takes effect at the next handshake | – | fake-clock test; a revoked agent is cut off |
| 4 | **ACME in the agent**: an ACME client (lego as a library, PLAN §6.3) with its own account, http-01 on port 80 (short-lived listener) or dns-01 via RFC 2136 / Cloudflare; names limited to `agent_names` server-side | Q3 (lego) | the agent gets a certificate from the phase 2 server; a name outside its list is refused by the server, not just the agent |
| 5 | **Deploy profiles** nginx, Apache, HAProxy (combined PEM), file: write to a temp file in the target directory, `fsync`, rename; owner and mode from the profile; formats PEM / combined PEM; key file 0600 | – | tests in a temp root; a path outside `paths` is refused by the agent even if the server asks |
| 6 | **Reload with rollback**: test hook (`nginx -t`), reload hook, then a **local TLS check** (connect to the service, compare the served fingerprint); on any failure restore the previous files and reload again; report the result | – | nginx in a container: a broken certificate rolls back, the old one is served again; batched reload for several certificates of one service |
| 7 | **Heartbeat and inventory**: every 5 minutes (jitter), certificates found in the configured paths, agent version; `agent_silent` alert after 3 missed beats | – | dashboard shows last seen; fake-clock test for the alert |
| 8 | **Renewal scheduling** at 2/3 of the lifetime with jitter, or the ARI window (PHASE2 step 12) | – | fake-clock test; ARI window followed |
| 9 | **Linux packaging**: systemd unit (hardened: `ProtectSystem=strict`, `ReadWritePaths` = the profile paths, `NoNewPrivileges`), install script, the agent in the release archives (`.goreleaser.yaml` gets the agent build) | Q4 (packages: .deb/.rpm via nFPM?) | install on a clean Debian/Ubuntu VM; `systemd-analyze security` score documented |
| 10 | **Trust store, small form** (PLAN §10.1): root download as PEM, DER, `.mobileconfig`; the agent can add the root to the system trust store (`update-ca-certificates`), off by default | – | Debian and Fedora layouts tested in containers |
| 11 | **Expiry dashboard**: certificates by expiry, agent status, sealed warning, CRL freshness | – | handler tests, screenshots light/dark |
| 12 | **TLS scan** (integration level 2): scheduled scan of `endpoints` (manual, from agents, from SANs), served certificate vs. the issued one, expiry, chain; SSRF rules as for http-01, ports from the endpoint list only | – | test servers serving the right / an old / a foreign certificate |
| 13 | **Notifications**: e-mail (SMTP with STARTTLS/TLS, no plain auth over plain text) and webhook (JSON, HMAC-SHA256 signature header, retries with back-off); alert rules: expiry (30/14/7/1 days), deploy failed, agent silent, scan mismatch, **sealed** – the alarm when the server stays sealed, measured against the remaining CRL lifetime (PLAN §10 phase 4 item, pulled into v1.0 by §10.1) | – | a local SMTP and webhook receiver in tests; secrets never in logs; a sealed server alerts before its CRLs expire |
| 14 | **Demo and docs**: `deploy/demo/docker-compose.yml` (MyOwnPKI, nginx with the agent, a certbot container – http-01 end to end, PLAN §10.1 "Live test"), OPERATIONS.md chapters "Agent" and "Monitoring", CHANGELOG 0.3.0 | Q5 (demo images) | one command brings the demo up; the guide followed on a clean VM |

### Notes

- **Order of work:** 1–3 give a trusted channel, 4–6 the useful part (a certificate deployed and
  checked), 7–10 operations, 11–13 monitoring, 14 shows it. Monitoring steps 11–13 need no agent
  and could start in parallel with step 1.
- **Not in v0.3** (PLAN §10.1 "After v1.0"): Windows and FreeBSD agents, Let's Encrypt in the agent
  (only configuration then), GPO/MDM/Java trust stores, more deploy profiles from the `GUIDE.txt`
  recipes.
- **The webhook signature** lets the receiver check the sender; the HMAC key is shown once.

---

## 3. Dependencies

| Module / tool | License | For | Status |
|---|---|---|---|
| `connectrpc.com/connect` + `google.golang.org/protobuf` | Apache-2.0 / BSD-3 | agent protocol (ADR-10, step 1) | **to ask** (Q2); code generation with `buf` or `protoc` as a tool |
| `github.com/go-acme/lego/v4` | MIT | ACME client and DNS providers in the agent (step 4) | **to ask** (Q3) – brings many provider modules; only RFC 2136 and Cloudflare are linked if built with the provider sub-packages directly |
| nFPM (via GoReleaser) | MIT | .deb / .rpm of the agent (step 9) | **to ask** (Q4) |
| nginx, certbot, Debian/Fedora images | BSD-2 / Apache-2.0 / various | tests and the demo only | **to ask** (Q5), pinned by digest |
| SMTP | – | `net/smtp` from the standard library (frozen but sufficient) – no module | – |

---

## 4. Open questions to the owner

| # | Question | Proposal |
|---|---|---|
| Q1 | **Agent listener port** – ADR-08 says a separate listener; `:8443` is taken by ACME (PHASE2 Q1) | `:8444` |
| Q2 | **Agent protocol**: Connect-RPC as ADR-10 says (two modules + a generator), or JSON over HTTPS with mTLS (no new module)? | Connect-RPC as decided in ADR-10 – typed, versioned messages; JSON stays possible through Connect's JSON codec for debugging |
| Q3 | **lego** in the agent (large module tree) – or an own minimal ACME client for http-01 plus RFC 2136? | lego: the DNS providers are the reason it was chosen (PLAN §6.3), and it is the most used Go ACME client |
| Q4 | **Packages**: .deb/.rpm with nFPM, or a tarball with an install script first? | Tarball + install script in v0.3, packages in the beta |
| Q5 | **Demo** with external images (nginx, certbot) pinned by digest | Yes |
| Q6 | **Default enrollment mode** | `verified` (token **and** check, PLAN §6.2 default) |
| Q7 | **Notification defaults**: which alerts are on after install, and to whom? | expiry 14/7/1 days, deploy failed, sealed – to the instance admins' e-mail once a channel exists |
| Q8 | **TLS scan of SANs from issued certificates** automatically, or only listed endpoints? | Only listed endpoints plus what agents report – scanning every SAN surprises networks |
| Q9 | **Agent self-update** – out of scope for v0.3? | Out of scope; the package manager or the install script updates it |
