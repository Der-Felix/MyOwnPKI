# Phase 3 – plan (v0.3: Linux agent, then monitoring)

> Written at the end of the night run 2026-10-21 as a proposal. The owner answered the open
> questions on 2026-10-24 (§5) and split the phase: **v0.3.0 is the Linux agent** (steps 1–9 plus
> 2a and 8a below); **monitoring (steps 11–13) follows in v0.3.x**. Branch `release/v0.3.0`, built
> in blocks A–E (§3). §5 has the decisions, §7 what is still open.
>
> **Progress:** block A done (`9eacb4f`); **block B built** 2026-10-24 – steps 1–3 and the enrollment part
> of 2a, see "Built in block B" at the end of §6. **Block C reviewed and implemented** –
> steps 4–6, with the owner's clarifications below. Blocks D–E follow.
> **v0.3.1–v0.3.2** released (§8). **Monitoring** is planned in §9: v0.3.3 alerts and notifications,
> v0.3.4 the TLS scan.

Goal of v0.3.0, measured on a real host: on an **nginx reverse proxy** the agent gets its
certificate by ACME from the own server, puts it in place for nginx, reloads nginx and **rolls back**
when anything fails. The web UI shows the agent and its deployments; **"Renew now"** on a deployment
makes the agent renew within seconds.

Later in v0.3.x (PLAN §10.1): monitoring – expiry dashboard, a TLS scan of the endpoints
(integration level 2), notifications by **e-mail and webhook**, including the **alarm when the server
stays sealed** – plus dns-01 in the agent, the Apache and HAProxy profiles and the demo.

Rules that shape every step:

- **The agent is just another ACME client (ADR-19).** It gets certificates through the ACME server
  of phase 2 with the same policy as certbot. Its extra powers – inventory, deploy, reload – come
  from its own mTLS channel (ADR-10), never from a privileged issuance path.
- **Keys are generated on the host (ADR-11)**, a new one for every certificate; the private key
  never leaves the host.
- **No remote command execution** (security.md "Agent trust"): the server never sends a command
  line, a path or a hook name. What the agent deploys, where, and which hooks it runs come from
  its local `agent.yaml` only; the server can only ask "renew deployment X now".
- **Outbound only (ADR-10):** the agent connects to the server; no open port on the host – except
  port 80 for an http-01 challenge in standalone mode, and only while one runs. In webroot mode the
  web server that is there anyway answers.
- **Agent reports are attacker input** on the server side: a compromised host must not reach
  beyond its own names, and nothing it reports is ever used as a path or a command on the server.
- **No proxy from the environment:** the agent ignores `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`.
  It uses a proxy only when `agent.yaml` names one (owner 2026-10-24) – hosts reach the PKI
  directly, and a proxy from `/etc/environment` would get in the way.

---

## 1. Data model and configuration

### 1.1 Agents (`tenants/<t>/pki.db`, migration 0011)

```
agents
  id TEXT PK
  hostname TEXT                       -- the FQDN proven at enrollment
  status TEXT                         -- pending_approval | active | disabled | revoked
  enrollment_mode TEXT                -- auto | verified | manual: the mode that admitted it
  proof TEXT                          -- JSON: token (id, valid?), http-01 (method, passed?, when)
  cert_serial TEXT NULL               -- its current agent certificate (agent CA)
  prev_cert_serial TEXT NULL          -- the one before, accepted until it expires (renewal overlap)
  acme_key_thumbprint TEXT NULL       -- RFC 7638 thumbprint of its ACME account key (step 4)
  os, arch, agent_version TEXT        -- as reported
  desired_version INTEGER             -- +1 on every change of its desired state (step 8a)
  last_seen_at NULL, created_at, approved_at NULL, approved_by NULL

agent_enrollments                     -- one per enrollment attempt, until decided or expired
  id TEXT PK, agent_id → agents.id
  handle_hash TEXT                    -- the agent polls with the handle; only its hash is stored
  csr_der BLOB                        -- the agent's CSR; the certificate is built from the profile
  check_token TEXT, check_method TEXT -- http-01 for enrollment: standalone | webroot
  token_id NULL → join_tokens.id
  expires_at, decided_at NULL, decided_by NULL

agent_names                           -- the names this agent may order (security.md "Agent trust")
  agent_id → agents.id
  pattern TEXT                        -- an exact name or *.suffix
  source TEXT                         -- hostname | token | admin
  added_by, added_at

join_tokens                           -- single-use, short-lived, scoped, stored hashed
  id TEXT PK, token_hash TEXT
  name_patterns TEXT (JSON)           -- the hostname must match one; they become agent_names
  expires_at, used_at NULL, used_by NULL → agents.id, created_by, created_at

agent_deployments                     -- what the agent reports from its agent.yaml, plus requests
  agent_id → agents.id, name TEXT     -- the deployment name in agent.yaml; PK (agent_id, name)
  profile TEXT                        -- nginx | file
  names TEXT (JSON), challenge TEXT   -- as reported (display only, never used as a path)
  state TEXT                          -- pending | deployed | failed | rolled_back
  certificate_serial NULL, not_after NULL, served_fingerprint NULL
  deployed_at NULL, last_error NULL, last_report_at
  renew_requested_at NULL, renew_requested_by NULL   -- "Renew now" (step 8a)
```

Plus `acme_accounts.agent_id` (NULL for every other ACME client): the account an agent registered
over its channel (step 4). The tenant setting **`agent_enrollment`** (`auto` | `verified` |
`manual`, default `verified`) lives in `system.db` (migration 0011), like `trust_page`.

Everything an agent reports has length limits, is stored as data and is escaped in the UI. There
is no heartbeat table in v0.3.0: the latest report per deployment and `last_seen_at` are enough;
the history comes with monitoring.

**The agent CA** is an intermediate with the **EKU limit `clientAuth` only** (the existing CA
setting), created like any intermediate – online, or signed by the offline root. `agent.ca` names
it (§1.4). It signs only agent certificates: ECDSA P-256 key from the host, **7 days**, EKU
`clientAuth`, subject CN and DNS SAN = hostname (preset *client*); extensions from the
profile, never from the CSR (pki-rules).

**The agent's identity** (owner 2026-10-24): the agent certificate has **no SAN URI**. The server
maps a client certificate to its agent by the serial and then compares the **whole certificate**,
byte for byte, with the agent's current or previous one in `pki.db` – any other certificate,
even one with a known serial, identifies nobody. At most 6 renewals per agent and hour.

### 1.2 Monitoring (v0.3.x – `pki.db` and `system.db`, migration numbers when built)

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

### 1.3 Agent configuration (`/etc/myownpki-agent/agent.yaml`, root, 0600)

The agent's only source for what it deploys, where it writes and what it runs. `myownpki-agent
config check` validates it; the agent refuses to start with an invalid one.

```yaml
server: https://pki.homelab.lan:8444            # agent.base_url of the server
ca_bundle: /etc/myownpki-agent/root.pem         # trust anchor for the agent listener and for ACME
hostname: proxy1.homelab.lan                    # optional; default: the host's FQDN – proven at enrollment
acme_directory: https://pki.homelab.lan/acme/directory   # any ACME CA – Let's Encrypt later is only this line
# proxy: http://proxy.homelab.lan:3128          # optional, for both connections; environment variables are ignored

enrollment:                                     # how the enrollment check (ADR-18) is answered
  challenge: webroot                            # standalone | webroot (default standalone)
  webroot: /var/www/acme

hooks:                                          # the ONLY commands the agent ever runs: absolute path, no shell
  nginx-test:   ["/usr/sbin/nginx", "-t", "-q"]
  nginx-reload: ["/usr/bin/systemctl", "reload", "nginx"]

paths:                                          # where the agent may write – deployments and webroots
  - /etc/ssl/myownpki/
  - /etc/nginx/ssl/
  - /var/www/acme/

deployments:
  - name: proxy                                 # unique per agent; the UI shows it
    profile: nginx                              # fullchain.pem + privkey.pem (0600) in dir
    names: [proxy1.homelab.lan, app.homelab.lan, wiki.homelab.lan]
    challenge: webroot                          # standalone | webroot
    webroot: /var/www/acme                      # token in <webroot>/.well-known/acme-challenge/
    dir: /etc/ssl/myownpki/proxy
    test_hook: nginx-test                       # before the reload; a failure restores the old files
    reload_hook: nginx-reload
    check: 127.0.0.1:443                        # local TLS check: SNI = first name, fingerprint compared

  - name: legacy                                # an existing nginx host: its paths and config stay
    profile: file                               # each file exactly where it is today
    names: [www.homelab.lan]
    challenge: standalone                       # the agent listens on :80 while the challenge runs
    files:
      fullchain: /etc/nginx/ssl/www.homelab.lan.crt
      key: /etc/nginx/ssl/www.homelab.lan.key
    owner: root
    group: root
    key_mode: "0600"                            # the default; certificates 0644
    test_hook: nginx-test                       # the same test, reload, check and rollback as nginx
    reload_hook: nginx-reload
    check: 127.0.0.1:443
```

The two profiles differ only in where the files go: `nginx` writes `fullchain.pem` and
`privkey.pem` into `dir`; `file` writes each of `certificate`, `chain`, `fullchain` and `key` to
the path given (at least `key` and `certificate` or `fullchain`). Test hook, reload hook, TLS check and
rollback (step 6) work the same in both.

Rules the config check enforces:

- Every file, directory and webroot of a deployment lies under one of `paths` (after cleaning the
  path and resolving symlinks); `..` and relative paths are refused.
- Target files are distinct and cannot overlap the agent's state directory or `ca_bundle`.
- A hook is referenced by name only and must exist under `hooks`; its first element is an absolute
  path to an executable; arguments are fixed – nothing from the server or from a certificate is
  ever added.
- `names` are exact DNS names (no IPs or wildcard identifiers in v0.3.0: http-01 cannot prove a
  wildcard); `challenge: webroot` needs `webroot`.
- `test_hook`, `reload_hook` and `check` are optional in **both** profiles. `check` is
  `host:port`; without it there is no TLS check (and a rollback only follows a failed hook).
- The join token is **not** in `agent.yaml`: `myownpki-agent enroll --token-file FILE` reads it
  once, and the install script deletes the file after a successful enrollment.
- The agent's own key, certificate and ACME account key live in `/var/lib/myownpki-agent` (0700,
  files 0600).

### 1.4 Server configuration (new section `agent`)

```yaml
agent:
  base_url: https://pki.homelab.lan:8444   # what agents connect to; its host is the name in the
                                           # listener certificate. Empty: no agent listener
  listen: ":8444"                          # default when base_url is set
  tls_issuer: issuing                      # the CA that issues the listener certificate (required)
  ca: agent-ca                             # the agent CA: EKU limit clientAuth only (§1.1)
```

Environment: `MYOWNPKI_AGENT_BASE_URL`, `…_LISTEN`, `…_TLS_ISSUER`, `…_CA`. `tls_issuer` works as for
the admin and ACME listeners (`internal/server/issuedtls.go`, OPERATIONS §2.4): issued while
unsealed, 90 days at most, renewed at 2/3, a root is refused, a bootstrap certificate until the
first issuance – agents refuse that one and retry. `config check` refuses an agent section without
`tls_issuer` or `ca`, and warns (as for a root in `tls_issuer`) when the CA named by `ca` has
another EKU limit than `clientAuth` only.

---

## 2. Protocol: Connect-RPC over mTLS (ADR-10, Q2)

`proto/myownpki/agent/v1/agent.proto`, package `myownpki.agent.v1`, one service `AgentService`.
Generated Go code in `internal/gen/myownpki/agent/v1` (messages and the Connect client and handler),
checked in and covered by `task generate:check`. All procedures are unary.

| Procedure | Client certificate | What it does |
|---|---|---|
| `Enroll` | **none** | hostname, CSR, optional join token, check method → enrollment ID, handle, check token |
| `EnrollStatus` | **none** (the handle) | starts the check when asked, then pending / approved (with the certificate and chain) / denied |
| `RenewCertificate` | agent | a new CSR (new key) → a new 7-day certificate (step 3) |
| `RegisterACMEAccount` | agent | the thumbprint of the agent's ACME account key (step 4) |
| `Report` | agent | heartbeat: version, OS, deployments with state, certificate, last error (step 7) |
| `WatchDesiredState` | agent | long-poll with `known_version` (step 8a) |

- **TLS:** TLS 1.3 only on the agent listener. `ClientAuth: VerifyClientCertIfGiven` with the agent
  CA as the only `ClientCAs`: a certificate from any other CA fails the handshake. `Enroll` and
  `EnrollStatus` are the only procedures that work without a certificate – rate-limited per
  address, size-limited, nothing but a pending entry comes from them.
- **Per request, not per handshake:** for every other procedure the server maps the certificate
  (serial) to the agent and checks that it is `active` and that the serial is its current or
  previous one and not revoked – so a revocation or a "disable" takes effect at the next call,
  even on a resumed TLS session.
- **The other listeners:** the admin and the ACME listener never accept an agent certificate as an
  identity. Neither asks for client certificates today; when the admin listener gets mTLS (PLAN §5)
  its `ClientCAs` exclude the agent CA. A test pins this: a client with an agent certificate gets
  no session and no ACME account from it (§5).
- **Versions:** fields are only added; `buf breaking` against `main` in CI keeps an older agent
  working with a newer server.

---

## 3. Work plan

"In" is the release. Blocks: **A** this plan · **B** steps 1–3 and 2a's enrollment part · **C** steps
4–6 · **D** steps 7, 8, 8a · **E** step 9 and the docs.

| # | In | Step | Approval needed | Verifies with |
|---|---|---|---|---|
| 1 | 0.3.0 | **Agent listener** (ADR-08, `agent.listen`, default `:8444`), its certificate through `agent.tls_issuer` (the `issuedtls` mechanism); client auth against the agent CA only; the Connect-RPC service (§2) | Q2 – approved | a client with a certificate from another CA fails the handshake; without a certificate only `Enroll`/`EnrollStatus` answer; an agent certificate gives nothing on the admin and ACME listener |
| 2 | 0.3.0 | **Enrollment** (ADR-18): key and CSR on the host; join token (single-use, expiring, name patterns, hashed); the server checks control of the hostname by http-01 with the SSRF rules of PHASE2 step 7 (the hostname must be covered by a domain; its address policy and `acme.resolver` apply); modes `auto` / `verified` (default) / `manual` (§6.1); approval queue and join tokens in the UI; queue limits and enrolling again (§6.1) | – | each mode × (token, check passed, check failed) gives the table of §6.1; a token works once and expires; a pending agent is admitted by an admin; 100 junk enrollments don't block an agent with a token; an expired agent comes back with the key of its last certificate, a disabled one doesn't; audit entries |
| 2a | 0.3.0 | **Challenge responder: standalone and webroot** (owner 2026-10-24), shared by enrollment (step 2) and ACME (step 4): standalone listens on `:80` only while a check runs; webroot writes `<webroot>/.well-known/acme-challenge/<token>` (0644) and deletes it afterwards, also after a crash (the agent notes what it wrote); the webroot must lie under `paths` | – | both modes answer the server's check; the token file is gone afterwards; a webroot outside `paths` is refused by the config check; port 80 in use → clear error naming `challenge: webroot` |
| 3 | 0.3.0 | **Agent certificate renewal** over the channel (7 days, renewed at 2/3 with jitter, new key), revocation and "disable" take effect at the next call; the previous certificate stays valid until it expires | – | fake-clock test; a revoked agent is cut off on its next call; a renewal survives a server restart in between |
| 4 | 0.3.0 | **ACME in the agent** with lego as a library (only `lego`, `certificate`, `registration`, `challenge/http01` and `providers/http/webroot`; no DNS providers): its own account key on the host, registered by thumbprint over the channel; the ACME server limits orders of that account to the agent's `agent_names` (at `newOrder` and again at `finalize`), on top of the normal domain policy | Q3 – approved | the agent gets a certificate from the phase 2 server; a name outside its list is refused **by the server** (`rejectedIdentifier`), not just by the agent; a revoked agent's account can't order |
| 5 | 0.3.0 | **Deploy profiles nginx and file** (Apache and HAProxy in v0.3.x): nginx writes `fullchain.pem` and `privkey.pem` into a directory, file writes each part to the path given – for a host that keeps its existing paths and nginx config; temp file in the target directory, `fsync`, rename, `fsync` of the directory; owner, group and mode from the deployment; PEM; key 0600 by default | – | tests in a temp root for both profiles; a path outside `paths` is refused by the agent; files never half-written |
| 6 | 0.3.0 | **Reload with rollback, for both profiles**: keep the previous files and a durable journal, replace the files, test, reload once per shared reload hook, then check TLS (SNI = first name, SHA-256 of the expected leaf, bounded retries over ~10 s). On failure restore previous files, remove first-installation files and test the restored group. If it passes and a reload was attempted, attempt one rollback reload/check for existing deployments. An open journal is recovered before another pass (§6.3) | – | both profiles against nginx in the Linux container: a mismatched certificate/key staged after validation fails `nginx -t`, restores the old files and leaves the old certificate served without a reload. A mixed group's TLS failure after reload restores and reloads existing deployments and verifies their old leaf; first installations stay `failed`. Failed restored tests prevent a reload and mark the whole group `failed`, explaining that the service still has the pre-rollback state. A stop between replacement and reload recovers from the journal |
| 7 | 0.3.0 | **Heartbeat and report** every 5 minutes (±30 s jitter): agent version, OS, every deployment with state, certificate, expiry and last error; `last_seen_at`; the UI shows "silent" after 3 missed beats (the `agent_silent` alert comes with monitoring) | – | fake-clock test; the agent list shows last seen and version |
| 8 | 0.3.0 | **Renewal scheduling** at 2/3 of the lifetime with jitter (a random point in the last 10 % before 2/3), or earlier when the server's ARI window (PHASE2 step 12) says so | – | fake-clock test; ARI window followed |
| 8a | 0.3.0 | **"Renew now" without remote commands** (owner 2026-10-24, §6.4): the button sets `renew_requested_at/by` and raises the agent's `desired_version`, with an audit entry; `WatchDesiredState` long-poll (answer at once when newer, else "unchanged" after at most 50 s); the agent renews through its normal ACME path (new key, deploy, rollback) and reports; the server clears the request. operator and admin may, viewer may not; the button is locked while a request is open. UI: agent list, agent detail with deployments | – | the API call reaches the agent within seconds; viewer gets 403; a second request while one is open is refused; a server restart during a long-poll: the agents come back within the backoff, no burst (test with many fake agents) |
| 9 | 0.3.0 | **Linux packaging**: hardened systemd unit (§6.6), `deploy/install-agent.sh` modelled on `install.sh`, the agent in `.goreleaser.yaml` (released for linux/amd64 and linux/arm64; it must still build for Windows, macOS and FreeBSD in the CI cross-build); CI job **agent end-to-end**; OPERATIONS chapter "Agent"; CHANGELOG 0.3.0 | Q4 – tarball and script | the CI job (§6.7) must run `TestNginxDeployProfiles` with nginx available in Linux CI from this step onward (no skip); `systemd-analyze security` measured in CI and documented |
| 10 | later | **Trust store, small form** (PLAN §10.1): root download as PEM, DER, `.mobileconfig`; the agent can add the root to the system trust store (`update-ca-certificates`), off by default | – | Debian and Fedora layouts tested in containers |
| 11 | 0.3.x | **Expiry dashboard**: certificates by expiry, agent status, sealed warning, CRL freshness. Expiry alerts must exclude agent identity certificates from end-entity lists and warn per active agent when its current certificate has less than 48 hours left. | – | handler tests, screenshots light/dark |
| 12 | 0.3.x | **TLS scan** (integration level 2): scheduled scan of `endpoints` (manual, from agents, from SANs), served certificate vs. the issued one, expiry, chain; SSRF rules as for http-01, ports from the endpoint list only | – | test servers serving the right / an old / a foreign certificate |
| 13 | 0.3.x | **Notifications**: e-mail (SMTP with STARTTLS/TLS, no plain auth over plain text) and webhook (JSON, HMAC-SHA256 signature header, retries with back-off); alert rules: expiry (30/14/7/1 days), deploy failed, agent silent, scan mismatch, **sealed** – measured against the remaining CRL lifetime | – | a local SMTP and webhook receiver in tests; secrets never in logs; a sealed server alerts before its CRLs expire |
| 14 | 0.3.x | **Demo**: `deploy/demo/docker-compose.yml` (MyOwnPKI, nginx with the agent, a certbot container – PLAN §10.1 "Live test") | Q5 – later | one command brings the demo up |

### Notes

- **API first (ADR-05):** the agent pages of the UI use REST operations that are in
  `api/openapi.yaml` first – agents, enrollments, join tokens, agent names, deployments, renew
  request – with `x-required-role` and contract tests, as in phase 1.
- **Not in v0.3.0:** steps 10–14, Windows and FreeBSD agents (they only have to compile),
  dns-01 in the agent, Let's Encrypt in the agent (only configuration later), agent self-update
  (Q9), `.deb`/`.rpm` (Q4).
- **Not in v0.3** (PLAN §10.1 "After v1.0"): GPO/MDM/Java trust stores, more deploy profiles from
  the `GUIDE.txt` recipes.
- **The webhook signature** (step 13) lets the receiver check the sender; the HMAC key is shown once.

---

## 4. Dependencies

New modules follow the two-week rule (a version at least two weeks old), go into THIRD_PARTY.md
with what they bring, and `task vuln` (govulncheck) stays green. Exact versions are chosen in block
B and C.

| Module / tool | License | For | Status |
|---|---|---|---|
| `connectrpc.com/connect` + `google.golang.org/protobuf` | Apache-2.0 / BSD-3 | agent protocol (step 1) | **approved** 2026-10-24 (Q2) |
| `protoc-gen-go` and `protoc-gen-connect-go` | as their modules | code generators | from the two approved modules themselves, as `go tool` entries in `go.mod` – the same versions as the runtime, so generated code and library always match |
| [buf](https://github.com/bufbuild/buf) CLI | Apache-2.0 | runs the generators, `buf lint`, `buf breaking` | **chosen** (Q2 left the choice open): a pinned release binary with its SHA-256 per OS, fetched by the Taskfile into `.tools/` like the other pinned tools; never in `go.mod`, not in any binary |
| `github.com/go-acme/lego/v4` | MIT | ACME client in the agent (step 4) | **approved** 2026-10-24 (Q3); only the packages named in step 4 are imported. Its core still brings `go-jose` (Apache-2.0) and `miekg/dns` (BSD-3, used by lego's own checks) – listed in THIRD_PARTY.md. lego's HTTP client is replaced by the agent's own, so it reads no proxy from the environment |
| nginx image | BSD-2 | the CI job "agent end-to-end" only | pinned by digest; not shipped |
| nFPM (.deb/.rpm) | MIT | – | **not now** (Q4: archive and install script) |
| SMTP | – | `net/smtp` from the standard library (v0.3.x) – no module | – |

**Why buf and not protoc:** protoc is a C++ program – one more native binary per platform, and
the Windows build differs from the Linux one. buf is a single Go-built binary for Windows, Linux
and macOS, parses the `.proto` files itself, runs the two generators as local plugins (offline, no
Buf Schema Registry) and adds `buf lint` and **`buf breaking`**, which checks that a change to the
protocol stays compatible with agents already in the field. The generators themselves come from the
approved modules, so buf adds no code to any binary.

---

## 5. Owner decisions (2026-10-24, the questions of the first draft)

| # | Question | Decision |
|---|---|---|
| Q1 | Agent listener port | **Own port, default `:8444`.** Its server certificate through `agent.tls_issuer` (the mechanism of the admin and ACME listeners). Client auth against the agent CA only; an agent certificate is refused on the admin and the ACME listener |
| Q2 | Agent protocol | **Connect-RPC + protobuf** (`connectrpc.com/connect`, `google.golang.org/protobuf`). The generator is a pinned tool in the Taskfile – buf (§4); generated code is checked in and checked by the "generated code" job in CI |
| Q3 | ACME client | **lego as a library** (`github.com/go-acme/lego/v4`), only the needed packages (http-01 standalone and webroot); no DNS providers – dns-01 is not part of v0.3.0 |
| Q4 | Packages | **Archive with an install script**, no `.deb`/`.rpm` yet |
| Q5 | Demo with external images | **Moved to v0.3.x** |
| Q6 | Default enrollment mode | **`verified`** – join token **and** a passed check |
| Q7 | Notification defaults | decided 2026-10-29 (§9.2): end-entity 14 / 3 days, CA 90 / 30 days, sealed after 10 minutes, agent silent after 1 hour, reminder every 24 hours, one digest per run |
| Q8 | TLS scan of SANs | decided 2026-10-29 (§9.2): no automatic scan of SANs – only endpoints entered by an admin or reported by an agent (v0.3.4) |
| Q9 | Agent self-update | **No** – the install script updates it |
| – | Proxy | The agent ignores `HTTPS_PROXY`/`HTTP_PROXY`; a proxy only when `agent.yaml` names one |
| – | Webroot mode | Per deployment `challenge: standalone \| webroot` and `webroot: <path>`, for enrollment **and** ACME; the webroot must be under `paths` (step 2a) |
| – | "Renew now" | A desired state, no remote command: request on the deployment, long-poll, the normal ACME path (step 8a, §6.4) |
| – | Profiles | Test hook, reload hook, TLS check and rollback for **both** profiles: a host that keeps its paths and nginx config uses the file profile with `nginx -t` and the check (§1.3) |
| – | Enrollment queue | A valid join token is never refused because of the limit of 100; pending without token and check expire after 24 h, the others after 7 days (§6.1) |
| – | Hooks with `sudo` | Don't work under `NoNewPrivileges=yes` – documented as a limitation of v0.3.0; a hook field `user` (the agent switches itself before `exec`) is planned for v0.3.x (§6.6) |

The second round of decisions (2026-10-24, the open points of the first version of this plan):

| # | Topic | Decision |
|---|---|---|
| 1 | `agent.ca` | A fourth server key names the agent CA explicitly; `config check` checks its EKU limit (§1.4) |
| 2 | Expired agent certificate | The agent enrolls again with the key of its **last agent certificate** – the server compares exactly that public key. Without a new token only a known agent that is neither revoked nor disabled comes back, with a passed check (§6.1) |
| 3 | Renew request while the agent is offline | Stays open; the UI says "waiting for the agent (last seen …)"; operator or admin can withdraw it |
| 4 | Agent user | Root in the sandbox of §6.6 – `systemctl reload` and the profiles' file owners need root; an own user would need a polkit rule per service |
| 5 | Agent certificate on the admin and ACME listener | Neither listener asks for client certificates (that would make browsers show a certificate picker); a test pins that an agent certificate gains nothing there; the agent CA never goes into the admin listener's `ClientCAs` when admin mTLS comes (§2) |
| 6 | Revoking an agent | Its deployed certificates stay valid; the revoke dialog offers to revoke them as a second step (§6.2) |
| 7 | ACME approval levels | The linked account counts as approved; all `agent_names` sources (`hostname`, `token`, `admin`) count as approved names for `new_name` – nothing is approved twice (§6.3, clarified by the owner for block C) |
| – | Later releases | Apache and HAProxy profiles and dns-01 in the agent come in v0.3.x |

---

## 6. Design details

### 6.1 Enrollment (steps 2 and 2a)

1. `myownpki-agent enroll` makes an ECDSA P-256 key and a CSR on the host and calls `Enroll` with
   the hostname, the CSR, the join token (if given) and the check method of `enrollment:`.
2. The server stores a pending agent and answers with an enrollment ID, a handle (random, only its
   hash is kept) and a **check token**. The agent places `<token>.<base64url(SHA-256 of its public
   key)>` at `http://<hostname>/.well-known/acme-challenge/<token>` – in its webroot, or on its own
   `:80` listener – and calls `EnrollStatus` to start the check. The content binds the check to the
   agent's key, like an ACME key authorization binds it to the account.
3. The server fetches the file with the ACME validator (port 80, the domain's address policy,
   `acme.resolver`, the redirect rules of PHASE2 step 7). The hostname must be covered by a domain
   of the tenant – otherwise the check fails and the agent goes to the queue.
4. The decision (the tenant's `agent_enrollment`):

   | Mode | Valid token | Check passed | Result |
   |---|---|---|---|
   | `auto` | yes | any | admitted |
   | `auto` | no | yes | admitted |
   | `auto` | no | no | approval queue |
   | `verified` (default) | yes | yes | admitted |
   | `verified` | only one of them | | approval queue |
   | `verified` | no | no | approval queue (the queue shows both failed) |
   | `manual` | any | any | approval queue |

   A token is valid when it is unused, not expired, of this tenant and the hostname matches one of
   its name patterns; using it marks it used, even when the agent then waits in the queue.
5. Admitted → the server issues the 7-day agent certificate (needs an unsealed server; sealed: the
   agent waits as "approved, waiting for the unseal"). The agent polls `EnrollStatus` every 30 s
   (jitter) until it has its certificate, then deletes the check token file and starts `run`.
6. `agent_names` start with the hostname (source `hostname`) and the token's patterns (source
   `token`); an admin adds or removes names in the UI.

**Queue limits** (owner 2026-10-24) – `Enroll` needs no certificate, so the queue must not fill up
from outside, and junk must never lock out a real agent:

- At most **100 pending enrollments without a valid token** per tenant; a further one without a
  token is refused with a clear error. An enrollment **with a valid join token is never refused**
  because of this limit and doesn't count against it.
- Pending enrollments with neither a valid token nor a passed check expire after **24 hours**, all
  others after **7 days**.
- Test: 100 junk enrollments fill the limit; an agent with a token is still admitted (and in
  `verified` with a passed check, at once).

**Enrolling again** (owner 2026-10-24): an agent whose certificate expired (off for more than 7
days, or the server sealed for more than ~2.3 days) calls `Enroll` with the key of its last agent
certificate. The server compares exactly that public key with the one of the agent's last
certificate. Only a known agent that is neither `revoked` nor `disabled` is admitted again with a
passed check and without a new token; everybody else goes through the table above. Deployed
certificates and ACME keep working meanwhile.

### 6.2 The agent certificate (step 3)

- 7 days, renewed at 2/3 (about day 4.7) with jitter over `RenewCertificate`, a new key each time.
  The server accepts the current and the previous serial; older ones are refused.
- **Revoke** (admin): status `revoked`, its agent certificates on the agent CA's CRL, its ACME
  account can no longer order; the agent is cut off at its next call. Certificates it deployed stay
  valid – revoking them would take services down; the UI offers it separately (§5).
- **Disable** (admin): the same without the CRL entry, reversible.

### 6.3 ACME in the agent (steps 4–6)

- The agent has one ACME account per server; its key (ECDSA P-256) lives in the state directory.
  Before `newAccount` the agent sends the key's thumbprint over the channel
  (`RegisterACMEAccount`); when that key registers, the account is linked to the agent
  (`acme_accounts.agent_id`) and counts as approved – the agent was admitted at enrollment.
- Orders of a linked account: every identifier must match the agent's `agent_names`, at `newOrder`
  and again at `finalize` and immediately before `Engine.Issue`, including `ProcessPending` after
  an unseal. The agent must still be active at each point. A refusal has a clear problem
  (`rejectedIdentifier` for a removed/disallowed name, `unauthorized` for an inactive agent).
  An existing order becomes invalid on refusal; newOrder rejects before creating one. The storing
  transaction checks again against concurrent names/status changes.
  The domain policy applies as for every client (ADR-19).
- `RegisterACMEAccount` is idempotent for the same agent and thumbprint; a reservation belonging
  to another agent is `FailedPrecondition`. A new reservation is also refused with
  `FailedPrecondition` and a `denied` audit entry if any account already uses that thumbprint,
  even an unlinked account: http-01 responses expose thumbprints, so they are not proof of ownership.
  Only verified `newAccount` requests bind accounts, both when creating one and when returning
  an existing one after an interrupted registration; ordinary ACME reads never bind or take a
  binding write transaction. `keyChange` preserves the account's agent ID and changes the agent's
  thumbprint atomically. One account per agent; subsequent key rotation uses ACME keyChange.
  After revocation and enrollment with a new agent ID, the previous account key is refused with a
  terminal operator-action error, never retried or automatically replaced. OPERATIONS describes
  removing that directory's `acme-*.key` and matching `acme-*.json` while the agent is stopped.
- Every source of `agent_names` (`hostname`, `token`, `admin`) counts as approved at `new_name`:
  enrollment proved the hostname, an admin created the token patterns or added the name.
  This approval is local to the linked account, never a global approval for other clients.
- **Accepted boundary (owner 2026-10-24):** `agent_names` restricts the linked account only.
  A compromised host can create an unlinked account and obtain anything the normal domain policy
  permits and whose http-01 challenge it can answer. This is normal ACME behavior; domain approval
  levels control that access. Unlinked clients keep their existing behavior.
- lego **v4.35.2** (2026-04-24), core packages only. Its configuration is constructed directly,
  not through `lego.NewConfig`, which reads `LEGO_CA_*` environment variables. A dedicated HTTP
  client trusts `ca_bundle`, honors only the configured proxy, has bounded HTTPS requests and
  propagates cancellation. An account key/registration is stored separately per directory URL.
- The http-01 challenge is answered by the responder of step 2a, the same way as at enrollment.
- One pass: renew what is due (or requested), deploy each, reload once per reload hook, check,
  roll back what failed, report.

**Deployment and recovery (owner clarifications 2026-10-24):**

- Both profiles use the same pipeline. A shared nonempty `reload_hook` is one group; without one,
  each deployment is its own group. All members are staged before tests, and duplicate test hooks
  run once. All targets must be distinct, remain under `paths`, and use a temporary file in the
  target directory, file fsync, rename and directory fsync. The allowed parent directories must
  exist; deployment subdirectories are created inside them. New certificates/fullchains never
  contain the trust anchor; keys default to 0600, certificates to 0644.
- Before replacing any file, save root-only backup copies and `deployment-journal.json` in the
  state directory. The journal records the group, targets, previous presence, mode/owner, old
  certificate metadata and phase. Backups and journal are durable before the first replacement;
  phases are `prepared`, `replaced`, `reloading`, `checking`, `rollback`.
- Test-hook failure: restore every file in the group and test the restored configuration, no reload.
  Reload/TLS-check failure: restore, test the restored files, attempt one reload and verify the old
  leaf of every existing deployment. A rollback failure reports
  `failed` with the original and rollback errors. No retry loop. Hook arguments come only from
  local configuration; on failure, the last stderr lines are bounded to 1 KiB of valid UTF-8
  without control characters and logged as `output`. Hooks must not write secrets to stderr.
  Each invocation has a 30-second timeout.
- Without a previous certificate/key, remove newly created files and keep that deployment `failed`.
  For a mixed group restore existing files, remove first-installation files and always run the
  test hooks. If they pass and a reload was attempted, reload once and verify the old fingerprint
  of each existing deployment; those deployments become `rolled_back`. If restored tests fail
  (for example, a configuration still references a removed file), do not reload: all group members
  become `failed`, with a message that the service still has the state from before the rollback.
  Incomplete previous certificate/key pairs are refused before replacing files.
- At startup, an open journal restores the backups, tests and reloads the group, verifies the old
  certificate and stores `rolled_back`. Recovery validates the recorded targets/group against the
  current local configuration; a changed configuration that no longer matches stops recovery.
  A file-restoration failure keeps the journal for operator-assisted recovery. A completed restore
  with a failed reload/check stores `failed` and removes the journal, preventing an automatic loop.
- Local results live in `deployments.json` and appear in `status`; the `Report` RPC and renewal/ARI
  scheduling are block D. `run` recovers first and makes an initial pass for deployments without
  a local result. A failed deployment is not retried in the agent-certificate maintenance loop;
  an account-registration `FailedPrecondition` stops `run` immediately for operator action.
- Linux provides directory fsync and an advisory state lock to exclude overlapping agent processes.
  Windows remains a compilation/test target only; it is not a supported deployment platform yet.
- Tests use the real agent/mTLS/ACME server in both challenge modes, normal-client regression,
  real local TLS endpoints for success and rollback, and an interrupted pass reopened by a fresh
  agent. `TestNginxDeployProfiles` runs both profiles against a private nginx process on Linux
  (inside the pinned nginx container in step 9); it is skipped when nginx is unavailable.

### 6.4 "Renew now" and the long-poll (step 8a)

- **Click** (operator, admin): REST `POST …/agents/{id}/deployments/{name}/renew` sets
  `renew_requested_at/by`, raises `agents.desired_version`, writes an audit entry (outbox of
  `pki.db`, same transaction). Refused while a request is open (409) – the button shows "requested
  by … at …" and is locked.
- **Desired state** (the answer of `WatchDesiredState`): `version` and per deployment name
  `renew_requested_at`, plus the agent's allowed names – so it can say "name not allowed" before
  it orders. Never a path, a command or a hook name.
- **Long-poll:** `WatchDesiredState(known_version)` answers at once when the version is newer,
  otherwise holds the call and answers "unchanged" after 45–50 s (random, so the agents don't fall
  into step). The server keeps one waiting call per agent (a new one replaces the old) and wakes it
  from memory when the version changes; the agent listener's timeouts allow the 50 s.
- **The agent** calls again at once after an answer. On an error it backs off: 1 s, doubling, at
  most 60 s, with full jitter (a random wait between 0 and the step), reset after a success. A
  server restart breaks every waiting call; the jitter spreads the reconnects, and the agents pick
  up the state that was saved in `pki.db` – nothing is lost, no burst, no agent hangs (each call has
  a client-side deadline of 60 s).
- **Done:** the agent renews through its normal ACME path – new key on the host (ADR-11), deploy,
  test, reload, check, rollback – and reports the result with `Report`; the server clears the
  request when the report is newer than the request, whatever the result, and shows the result.

### 6.5 Rights and audit

| Action | viewer | operator | admin |
|---|---|---|---|
| See agents, deployments, enrollments | yes | yes | yes |
| "Renew now" | – | yes | yes |
| Join tokens, approve or deny enrollments, agent names, disable, revoke | – | – | yes |

Audit entries: enrollment requested / admitted / queued / approved / denied, join token created /
used, agent certificate issued (actor *system*), names changed, disabled, revoked, renew requested,
deployment result when the state changes (not every heartbeat). ACME issuances are audited as
before.

### 6.6 The agent on the host (step 9)

- Runs as **root** in a strict sandbox (§5): `ProtectSystem=strict`,
  `ReadWritePaths=` the `paths` of `agent.yaml` (webroots are inside them), `StateDirectory=
  myownpki-agent`, `NoNewPrivileges=yes`, `ProtectHome=yes`, `PrivateTmp=yes`, only IPv4, IPv6 and
  Unix sockets, `@system-service` system calls. Hooks run inside this sandbox too – an allowlisted
  command can't write outside the allowed paths either. This contains filesystem mistakes in the
  agent. It is **not a security boundary against code running as root in the agent process**:
  `systemctl reload` needs access to systemd over D-Bus, and the same access permits `systemd-run`.
  The actual protection is that the server sends no commands and hooks come only from root-owned
  `agent.yaml`.
- `CAP_NET_BIND_SERVICE` only through a drop-in when a deployment or the enrollment uses
  standalone, or a hook binds a port below 1024 (for example `nginx -t`, also in webroot mode).
- `nginx -t` opens nginx's log files: the install script adds nginx's log directory to
  `ReadWritePaths` when a hook runs nginx – the CI job proves it.
- **Known limitation in v0.3.0** (owner 2026-10-24): with `NoNewPrivileges=yes` hooks that use
  `sudo` or otherwise switch users don't work – for example `podman exec` as another user. Hooks
  run as root inside the sandbox. *Planned for v0.3.x:* a hook field `user`; the agent itself
  switches to that user (setuid/setgid) right before `exec`, without sudo.
- `install-agent.sh --server URL --ca-bundle FILE [--token-file FILE] [--webroot DIR]`: user-less
  install (root service), directories, an `agent.yaml` from a template (never overwritten), the
  unit and drop-ins, `myownpki-agent enroll`, then `systemctl enable --now`. Running it again with a
  newer release updates the binary and restarts – no self-update (Q9).
- Commands: `myownpki-agent run` (the service), `enroll`, `status`, `config check`, `--version`.

### 6.7 CI job "agent end-to-end" (step 9)

On the Linux runner: the server with ACME and the agent listener, nginx in a container (pinned by
digest) with a webroot, the agent in **webroot mode** for enrollment and ACME:

1. enroll with a join token (`verified`), the agent appears in the API;
2. first certificate deployed, nginx serves it (`openssl s_client` against the root);
3. "Renew now" through the REST API → a new certificate is served within seconds;
4. a broken certificate → `nginx -t` fails, the old certificate is still served, the deployment
   reports `rolled_back`. The fault (a key that doesn't match the certificate) comes from an agent
   built with the build tag `e2etest` for this job only – release binaries can't do it;
5. `systemd-analyze security myownpki-agent.service` shown in the job summary.

### 6.8 Firewall

| From | To | Port | Why |
|---|---|---|---|
| host (agent) | server | 8444/tcp | agent channel (mTLS) |
| host (agent) | server | the ACME port (443 with `acme.tls_issuer`, or the proxy) | certificates |
| server | host | 80/tcp | http-01 check – enrollment and every ACME order |

Nothing else is opened on the host; in standalone mode port 80 is open only while a check runs.


### 6.9 Built in block B (2026-10-24) – what differs from the text above

- **Identity:** the agent certificate has no SAN URI. The server maps a client certificate to its
  agent by serial **and** by comparing the whole certificate with the stored one; only the current and
  the previous certificate count. The certificates use the preset *client* (CN and DNS SAN = hostname).
- **Protocol so far:** `Enroll`, `EnrollStatus`, `RenewCertificate`. `RegisterACMEAccount` (block C),
  `Report` and `WatchDesiredState` (block D) are added then – adding procedures keeps older agents working.
- **Enrolling again** uses a CSR with the key of the last certificate (that key is the proof); the
  next renewal at 2/3 brings a new key again.
- **`myownpki-agent enroll`** returns when the enrollment waits for approval; `run` (the service) polls
  every 30 s and installs the certificate once admitted. A pending agent asks the sealed server
  without causing an audit entry per poll.
- **Permission `agent.manage`** (admin only, with step-up): join tokens, approvals, names, disable,
  revoke. Reading agents, the queue and the tokens needs the viewer role.
- **REST API:** `/agents`, `/agents/{id}` with `disable`, `enable`, `revoke`, `names`;
  `/agent-enrollments` with `approve` and `deny`; `/agent-join-tokens`; `agent_enrollment` in
  `/settings`. UI: Agents, Enrollment requests, Join tokens; the mode in Tenant settings.
- **The enrollment check** uses the ACME validator's http-01 fetch (`acme.HTTP01Checker`) – same
  rules, also when the ACME server is off.
- **Webroot writes** go through an `os.Root` opened on the webroot (owner 2026-10-24): the webroot
  itself is checked against `paths`, and nothing below it – also a directory swapped for a symlink
  after the check – can lead a write or a delete out of it. The webroot must exist.
- **Renewals** of the agent certificate: at most 6 per agent and hour (`ResourceExhausted`).

---

## 7. Open points

Nothing is open for v0.3.0. Q7 and Q8 were decided with the monitoring plan (§9.2).

---

## 8. v0.3.1 (owner decisions, 2026-10-25)

v0.3.1 makes agent installation a guided, verifiable operation, lets operators choose whether a
proven replacement revokes its predecessor immediately, after a grace period or never, makes the
step-up lifetime configurable and continues a web action after its second factor. **Steps 15–19 are
v0.3.1. Step 20 (the knowledge base) is only reserved for v0.3.2.**
Monitoring (steps 11–13) comes after that; it is not pulled into v0.3.1.

### 8.1 Work plan and evidence

| # | In | Step | Verifies with |
|---|---|---|---|
| 15 | 0.3.1 | **Agent packages and one setup path.** GoReleaser's nFPM integration (no Go dependency) builds `myownpki-agent` as `.deb` and `.rpm` for linux/amd64 and linux/arm64: binary, unit and drop-ins as examples, `agent.yaml` as a conffile, no service start before enrollment. The logic of `install-agent.sh` moves to `myownpki-agent setup`: server URL, root SHA-256, webroot or standalone, optional `--token-file`, optional `--low-ports`. Tarball and packages use the same setup code. | Inspect both package formats on both architectures. Fresh installation never starts or enables the service. `setup` is idempotent, preserves an existing `agent.yaml`, checks the root fingerprint, writes token files 0600 and starts only after admission; a pending approval prints the later start command. Tarball and package runs produce the same effective configuration. Shell/Go tests and real systemd installation in Linux CI. |
| 16 | 0.3.1 | **Distribution and guided installation.** `install.sh` installs and updates the matching agent `.deb`, `.rpm` and tarball beside the server, always checked against `checksums.txt`; never mixed versions. The server image already contains the same immutable artifacts (§8.2). The agent listener offers only the manifest-listed artifacts and their checksums for unauthenticated read. *Agents → Install agent* builds the complete root/fingerprint, package/checksum, install and `setup` commands; optional host-scoped, one-time join token. Agent list marks older agents and shows the update command. | Wrong root fingerprint, changed artifact, changed checksum, wrong version and path traversal all stop before installation. No client certificate is needed only for those reads; enrollment and every other RPC still requires its existing authentication. No arbitrary filesystem path, redirect or command is accepted. Web tests cover roles, CSRF, one token shown once and absent from argv, URL and logs. Linux E2E installs the served package, verifies and enrolls, and updates an older agent. |
| 17 | 0.3.1 | **Configurable predecessor handling.** On renewal, choose `revoke now`, `revoke after N days` (1–30, proposed 7), or `never revoke`, always with reason `superseded`. Agent revocation or scheduling starts only after an accepted `deployed` report with its TLS check; other certificates use the completed renewal issuance. Tenant defaults are separate for agent deployments and other certificates, with agent/deployment and one-operation overrides. The existing scheduler executes planned revocations idempotently. See "Predecessor handling" below. | Test all three choices, defaults and every override, UI/step-up summaries, ACME exact-name-set renewal, N bounds and additive REST. For agents cover previous and never-deployed/discarded certificates, exact set equality, current-serving exclusions, `failed`/`rolled_back`, other accounts, the delay starting at `deployed`, and no duplicate schedule. Fake-clock tests cover execution, cancellation, revoke-now, restart/unseal catch-up, audit, filters/dashboard and CRLs; ambiguous mappings still revoke and schedule nothing. |
| 18 | 0.3.1 | **Step-up lifetime per tenant.** Tenant setting `step_up_minutes`: 5, 10, 15, 30 or 60 minutes, default remains today's 5. Admin only, with audit; applies to new step-up proofs, not retroactively to existing timestamps. | Every allowed value works; another number, zero, negative and values above 60 are refused. Viewer/operator get 403, admin change is audited. Fake-clock tests cover exact expiry at the selected duration and the unchanged default. |
| 19 | 0.3.1 | **Continue the web action after step-up.** A required second factor creates a server-side pending action, bound to the session, valid at most 5 minutes, single-use and protected by the existing CSRF check. The challenge page states the action. Correct proof executes the original normalized action once instead of asking for its inputs again. Nothing sensitive goes into a URL. | Fake-clock and handler tests: action executes exactly once; replay, other session, expired entry and wrong CSRF fail. Action summary is visible. No pending ID appears in URL, access log, redirect or HTML attribute other than the POST field. Server restart discards it safely. Injected action names/fields are refused. A business failure cannot cause a replay. Step 19 does not change the REST contract. |
| 20 | **0.3.2 only** | **Knowledge Base as GitHub Wiki.** Sources under `docs/wiki/`; CI checks links. A command copies them into a separate Wiki checkout; the owner commits and pushes. Then monitoring. | `task wiki:check` finds a missing local target and a broken relative anchor; no network-dependent link test. `task wiki:sync` copies only the documented source set and prints the resulting `git status`; it never commits or pushes and never touches the main checkout. |
| 21 | 0.3.1 | **Trust without self-confirmation.** Trust page and admin UI show SHA-256 and SHA-1, the latter only for comparison with the Windows certificate dialog. SHA-256 remains authoritative and tools verify only SHA-256. The Windows helper has no embedded expected fingerprint: it shows both and imports only after the user confirms an independent comparison, or automatically with `-ExpectedSha256 <value>` from the admin UI. The same rule applies to generated agent-install commands. | UI tests for both labels and SHA-256 authority. Helper tests prove no embedded expectation, SHA-256/SHA-1 display, mismatch aborts without import, match or explicit user confirmation imports. `-ExpectedSha256` uses only the authenticated-UI value. Agent-install tests show that no expected value is derived from the downloaded certificate or artifact. |

Once `fix/ci-local` is merged, the Linux evidence for steps 15 and 16 runs through `task ci:local`
and the corresponding `scripts/ci/` entries. The same script is the single source for local and
GitHub Actions execution; new or changed checks are registered there rather than duplicated inline.

### 8.2 Design decisions

**Package contents and setup.**

- Packages install files only. There are no package-script hooks, service enablement or enrollment at
  package installation time. `agent.yaml` is a conffile and is never silently replaced. The unit and
  drop-ins are examples until `setup` installs/enables them.
- `setup` owns the behavior that was in `install-agent.sh`: validate server URL and root fingerprint,
  create state/config/drop-ins, honor webroot/standalone and `--low-ports`, enroll, and only then
  enable/start. A pending enrollment leaves the service disabled and prints the command for after
  approval. Update mode keeps local configuration and restarts an already enrolled service.
- `install-agent.sh` becomes, if retained for one release, a thin compatibility wrapper around the
  binary from the verified tarball. It contains no second setup implementation. The documented
  default is the package or tarball plus `setup`.
- The server-side `install.sh` stores the agent artifacts in a new, explicitly configured
  `agent.package_dir` (host default `/var/lib/myownpki/agent-dist`). It downloads both package
  formats and the tarball of its **own exact version**, verifies every file against the release
  `checksums.txt`, and stops on a missing/changed file. It never installs or enrolls an agent on the
  PKI server itself.
- **Docker solution:** GoReleaser puts those same files and `checksums.txt` into the server image
  under `/opt/myownpki/agent-dist`; `agent.package_dir` points there in the container. No runtime
  download is needed. The directory is read-only to the server process and is the only source of
  the download manifest. Development without these files returns 404, not an empty manifest.
- The artifact manifest maps a small allowlist of version, format and architecture to exact files.
  There is no user-provided filesystem path, symlink following, directory listing, upload, delete,
  redirect or proxy fetch. Package and checksum downloads are immutable and bounded in size. The
  agent listener's other procedures are unchanged.
- The UI flow is admin-only with fresh step-up because it can create a join token. A token has the
  exact hostname, one use and a 15-minute expiry. It is displayed once, written by the operator to a
  root-only file (0600) and passed only through `--token-file`; it never appears in an argument,
  URL, report, access log or page after the first display.

**The guided commands and their trust chain.**

1. Download the root as PEM from the existing public trust-page endpoint over HTTP and compare its
   SHA-256 fingerprint with the value shown by the admin UI. HTTP alone is not trusted; the
   comparison with the value seen in the authenticated UI is the trust decision.
2. Download the selected package and `checksums.txt` from the agent listener over HTTPS using that
   verified root, then check the package against the displayed/listed SHA-256. A checksum fetched
   over HTTP can never authorize an installation.
3. Install the package with the OS package manager (or unpack the tarball).
4. Run `myownpki-agent setup` with the server URL, expected root fingerprint and local mode. Use a
   token file when a token was requested. The generated commands are copyable; downloaded content
   is never piped into a shell, and no token appears in the command line.

The agent list compares its reported agent version with the server version. An older agent gets an
informational hint and the same verified package/update command for its installed format and
architecture. There is no automatic update or remote command. A newer agent remains compatible via
the additive protobuf rules; no downgrade is suggested.

**Predecessor handling (owner addition, 2026-10-25).**

- Every renewal offers three choices for its predecessor: **revoke now**, **revoke after N days**
  (N = 1–30, proposed default 7), or **never revoke**. The eventual revocation reason is always
  `superseded`. For an agent, "now" still means only after its accepted `deployed` report with the
  passed TLS check; for UI, REST and non-agent ACME renewal it means after the completed issuance.
- The tenant has separate defaults for **agent deployments** and **other certificates** (UI, REST
  and ACME without an agent). An agent-wide default overrides the tenant's agent setting; an
  optional deployment override supports services with different replacement cadences. *Renew now*
  on an agent and *Renew* on an owned certificate show a confirmation with that effective default
  preselected. A choice and, for a delayed revocation, the day count apply to exactly that operation.
  The step-up summary repeats both. REST renewal accepts the same optional choice; omission keeps
  the effective default. Changing tenant, agent or deployment defaults is admin-only and audited.
- For non-agent ACME clients such as certbot, acme.sh and Caddy, a new order by the same account for
  the identical normalized name set is a renewal and applies the tenant default for other
  certificates. ACME gains no nonstandard negotiation field. A delayed period for these certificates
  starts at issuance; the agent-specific `deployed` rule below does not apply to them.
- Compare the previously stored serial before applying an accepted agent report. Act only on a real
  serial transition to `deployed`, which already means the TLS check passed. The previous
  certificate's issuance record must be linked to the same `acme_accounts.agent_id`; otherwise it is
  left valid and the mismatch is logged for diagnosis, without granting a cross-account revocation.
- Extend `pki.db` with `agent_deployment_certificates(agent_id, deployment, certificate_id,
  first_deployed_at, last_deployed_at)`, unique over all three IDs. An accepted `deployed` report
  inserts or updates this history. **Never deployed** means no accepted row in this history, not
  merely a different current state. Older issued but never-deployed/discarded certificates from
  failed or aborted orders of the same deployment are handled by the selected choice too. Every
  serial currently reported as `deployed` by any deployment of this agent is excluded in every case.
- The mapping is three-way and exact: the account is the authenticated agent's linked ACME account;
  the normalized, sorted, duplicate-free identifier set of the ACME order must equal the report's
  deployment-name set; and the candidate certificate's `created_at` must be before the `created_at`
  of the newly confirmed certificate. No agent-provided timestamp decides age. The newly confirmed
  certificate itself and anything newer is excluded. For every candidate require its own exact
  record. If the mapping is not unique, an order is missing, names differ or timestamps tie, **revoke
  and schedule nothing in that ambiguous group and log the ambiguity**. Never guess by hostname
  alone or act across accounts. An already revoked, unrelated duplicate does not block a clear
  candidate.
- For agents, a delay starts at the server-recorded accepted `deployed` time, never at issuance or
  an agent-provided time. `failed` and `rolled_back` neither revoke nor create a schedule. `never
  revoke` does neither. Repeated reports and later matching replacements never create a second
  schedule or silently move an existing one.
- A pending entry appears as **Revocation planned · \<date\>** in certificate lists and details and
  beside the deployment on the agent page. The certificate filter gains `planned`; the dashboard
  shows **N revocations due in the next 7 days**. An authorized user can **revoke now** or **cancel
  the planned revocation** at any time before execution. Both are audited and require step-up like
  revocation; cancellation leaves the certificate otherwise unchanged.
- The existing scheduler executes due entries idempotently, rechecking that the certificate is still
  planned and not already revoked. It catches up overdue entries after restart and unseal. Immediate
  revocation or schedule creation, report/history update, certificate linkage and audit enqueue
  happen in one `pki.db` transaction. Execution writes the final `superseded` revocation and audit
  idempotently. **CRL production stays outside these transactions and follows the existing CRL
  scheduler.** A report fails only for a real database error, never because a CRL has not been
  produced yet or because mapping was ambiguous; ordinary report backoff continues to apply.
- Authorization is checked again for every explicit plan, cancellation and revoke-now action:
  whoever may revoke the certificate may plan it. An explicit predecessor from another ACME account
  requires admin; an agent report or ordinary ACME order can never select another account's
  certificate. The scheduler executes only a persisted, already authorized plan and accepts no
  account or serial supplied by an agent report, so scheduling cannot expand the caller's rights.
- The migration is additive: nullable per-certificate plan metadata and the new default/override
  settings leave existing certificates and revocation states untouched. REST is additive too:
  certificate responses expose the planned timestamp, plan/cancel endpoints use the same permission
  and step-up rules, and renewal accepts the optional choice plus days. Existing clients that omit
  the fields retain the configured behavior. Upgrade with unchanged serials creates no revocation or
  schedule.

**Step-up continuation.**

- Pending actions live in **server memory**, not in the browser or a URL. A 256-bit random ID is the
  lookup key in a POST field; a restart discards the entry and tells the user to start the action
  again. There is no persistent payload to leak through a database export and no new database schema.
- Each entry contains session ID, user ID, credentials epoch, creation/expiry time and an
  **allowlisted action type with normalized target/parameters**, never a callback or arbitrary raw
  request. Summary text is built by the server and contains no secret values. Existing role and
  object checks run again at execution.
- The existing step-up form remains POST+CSRF. Session, credentials epoch and absolute/idle expiry
  are checked again. The pending entry expires independently after at most 5 minutes, even when the
  configured step-up lifetime is longer.
- Consumption is atomic under a mutex: the entry is marked consumed before the business handler can
  run, so double-click, concurrent tabs and retry cannot execute it twice. A crash or business error
  does not silently replay it; the operator starts over deliberately. The business audit entry is
  written once by the original action, not once for the challenge and once for the continuation.
- **REST stays as it is.** Its `step-up-required` response is an explicit, stateless contract for
  API clients; each request already carries its action and CSRF/auth proof. Introducing a stored
  one-time continuation would change retry semantics and require clients to keep UI state. API
  clients repeat the original operation with a fresh proof instead.

**Trust without self-confirmation.**

- The trust page and the authenticated CA/agent pages show SHA-256 and SHA-1. SHA-1 is labeled
  explicitly **only for comparison with the Windows certificate dialog**, never as the authoritative
  integrity check. SHA-256 remains the value every tool checks; SHA-1 is display-only.
- The Windows helper contains no expected fingerprint. It computes and shows both values. Import
  requires the user's confirmation that the values were compared with an independently obtained
  SHA-256, or the explicit `-ExpectedSha256 <value>` parameter. Automation accepts that parameter
  only as an exact 64-hex-character value shown by the authenticated admin UI. A mismatch, malformed
  value or unattended missing comparison stops before any store change.
- Every generated command follows the same rule: expected roots, certificate fingerprints and
  package checksums come from the authenticated UI, never from the certificate, artifact, download
  page or checksum file being verified. Agent installation therefore cannot confirm a malicious
  root or package with its own data.

**Knowledge base reserved for 0.3.2.**

`task wiki:check` validates local Markdown targets and relative anchors deterministically; external
URLs do not require network access in CI. `task wiki:sync -- /path/to/wiki-checkout` copies the
reviewed source set and prints `git status`, including deletions for the owner to review. It never
commits, pushes, switches the main checkout or deletes the Wiki checkout.

### 8.3 Security and operational risks

- **Unauthenticated artifact reads:** artifacts contain no tenant data or secrets and are generic,
  but their integrity is not taken from transport or a checksum alone. The out-of-band root
  fingerprint, HTTPS and package SHA-256 form the complete chain. A wrong root or package fails
  closed. Only manifest-listed immutable files are public.
- **Package and update execution:** package files and the guided commands are executed by the
  administrator, never by the server on itself. No autostart, no remote update command and no second
  implementation in shell reduce the risk of executing unexpected content. Checksums are verified
  before any binary is installed.
- **Predecessor revocation and scheduling:** account ownership and, for agents, a proven TLS-serving
  state are mandatory. This avoids a compromised report revoking another account's certificate or a
  failed rollback revoking the still-serving old certificate. `never revoke` supports migration
  review. Explicit scheduling repeats the revocation permission and step-up checks; the scheduler
  cannot turn an untrusted report into a cross-account revocation.
- **Pending-action replay and tampering:** session and credentials binding, short expiry, CSRF,
  action allowlisting and atomic single consumption are all required. Raw form actions, arbitrary
  callbacks and URL state are refused. A pending entry never changes who may perform the action.
- **Sensitive data:** pending actions stay in memory and are not logged. Join tokens are shown once
  and accepted only through a 0600 file. `setup` and package scripts never print them. There is no
  sensitive value in generated URLs, redirects, action summaries or REST responses.

### 8.4 Owner decisions (2026-10-25)

1. Package CI uses pinned containers for **Debian 12 and 13, Ubuntu 24.04, and Rocky/Alma 9 and 10**.
   There is no apt/yum repository metadata in this release.
2. `agent.package_dir` is accepted: `/var/lib/myownpki/agent-dist` on hosts and
   `/opt/myownpki/agent-dist` in Docker.
3. `install-agent.sh` stays for one release as a thin wrapper with a deprecation notice and is
   removed in v0.3.2. The shared implementation is `myownpki-agent setup`.
4. An agent downgrade is allowed only when the administrator explicitly invokes the package manager.
   The UI never suggests a downgrade; protobuf compatibility checks remain mandatory.
5. Pending-action summaries show only the action and non-secret target. Sensitive parameters stay
   in memory and are never logged, as inventoried below.
6. **Decided – factory defaults for predecessor handling.** Agent deployments use `revoke now`
   after the confirmed deployment; other certificates use `revoke after 7 days`. The owner confirmed
   both defaults on 2026-10-26.

| Action | Parameters held in the pending entry | What the summary shows |
|---|---|---|
| Revoke certificate | certificate ID, reason | Common name, serial and reason; no key material |
| Plan/cancel certificate revocation | certificate ID, planned time or cancellation | Common name, serial, `superseded`, planned date or cancellation |
| Renew certificate | certificate ID, predecessor choice, optional days | Common name, serial, predecessor choice and days when applicable |
| Download private key | certificate ID | Common name and serial; never the private key |
| Export certificate / PKCS#12 | certificate ID, format, password, delete-key flag | Common name, serial, format and deletion choice; never password, key or bundle |
| Create/import CA; offline flow | parent, CA name, subject, algorithm, validity, path length, constraints, EKU limit, base URL, public CSR/certificate PEM | CA name, parent and operation; public policy only, never private keys or full PEM |
| Change CA limits, sign/upload CRL | CA ID, limits, CRL PEM | CA name and operation or limits; no full CRL |
| Renew, retire or revoke CA | CA ID, reason | CA name, generation when applicable and reason |
| Create join token | label, hostname/patterns, TTL | Label, exact hostname/patterns and expiry; never token or token hash |
| Approve/deny enrollment | enrollment ID | Hostname and approve/deny, no CSR or handle |
| Add/remove agent name | agent ID, add/remove, name/pattern | Hostname, operation and name/pattern |
| Disable/enable/revoke agent | agent ID | Hostname and operation |
| Renew/withdraw deployment | agent ID, deployment name, predecessor choice and optional days when renewing | Hostname, deployment, renew/withdraw, and predecessor choice with days when applicable |
| Create user | username, initial password, role, scope, instance-admin flag | Username, role, scope and instance-admin choice; never password, TOTP secret or recovery codes |
| Change user roles, unlock, disable/enable | user ID, role, scope | Username and role/scope or account operation |
| Change own password | current and new password values | "Change your password"; no values |
| Change authenticator or make recovery codes | current password, confirmation code | Operation only; no password, secret or recovery code |
| Create API token | name, role, scope, days | Name, role, scope and expiry; never token secret |
| Revoke API token | token ID | Token name only, never token secret |
| Remove passkey | passkey ID, current password | Passkey name only; no password or credential data |

The table is exhaustive for the existing step-up-protected web forms. New actions must be added to it
with their allowlisted parameter shape before continuation is enabled. A pending action never uses a
raw request body or a caller-provided callback.

---

## 9. Monitoring: v0.3.3 and v0.3.4 (owner 2026-10-29)

The owner asked for monitoring next and left the defaults to this plan ("as you think"). It replaces
steps 11–13 of §3. **v0.3.3** has alerts and notifications (steps 22–25); **v0.3.4** adds the TLS
scan (step 26). Branch `release/v0.3.3`; the Docker fix of PR #18 ships with it.

Goal of v0.3.3, measured on the live installation: a server left sealed after an update, a
certificate that nobody renews, an agent that stops reporting and a failed deployment each produce
**one** e-mail and webhook call – without anyone opening the dashboard – and a second message when
the problem is gone.

### 9.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 22 | 0.3.3 | **Alert evaluation.** A job every minute evaluates the rules of §9.2 against `pki.db` and the keyring and keeps the result in `alerts` (`system.db`, migration 0014): one row per condition with a stable key (kind + subject), severity, `first_seen_at`, `last_seen_at`, `resolved_at`. Reading works while sealed; nothing is decrypted. The dashboard's "Needs attention" stays, and its new first block lists the open alerts. | Fake-clock tests per rule: opens at the threshold, raises warning → critical, resolves when fixed (renewed, unsealed, agent back), never duplicates; a superseded certificate and an agent identity certificate never alert; a sealed server opens `sealed` after 10 minutes and `critical` when a CRL's next update is less than 24 hours away. |
| 23 | 0.3.3 | **Notifications.** Channels come from the configuration (`notify.email`, `notify.webhook`; §9.3), never from the database, so they work while sealed. After each evaluation one **digest** per channel lists what opened, rose, was reminded (every 24 hours while open) or resolved. Queue `notifications` (`system.db`, same migration) with retries 1 min, 5 min, 30 min, 2 h, then dropped and logged. `myownpki notify test` sends a test message from the command line with the server's configuration. | A local SMTP server and webhook receiver in tests: STARTTLS and implicit TLS, no authentication over plain text, HMAC header matches the body, retry schedule with a fake clock, one digest for many alerts, no message when nothing changed. Password and secret never appear in logs, errors, the queue or `config check`. |
| 24 | 0.3.3 | **Alerts in UI and REST.** Page *Alerts* (open and resolved in the last 7 days), dashboard block, `GET /api/v1/alerts` (viewer and up, `api/openapi.yaml` first), `POST /api/v1/notifications/test` (admin, audited). `config check` shows the channels and the thresholds. | Handler and contract tests, roles (viewer reads, only admin sends the test), audit entry for the test; `config check` names a missing secret file and an unreadable one. |
| 25 | 0.3.3 | **Docs and release.** OPERATIONS chapter "Monitoring and notifications" (setup, a test, what each alert means and what to do), CHANGELOG 0.3.3, version bump. | `task check`, Linux CI including the image job, live test on the owner's installation: seal → message after 10 minutes, unseal → resolved. |
| 26 | 0.3.4 | **TLS scan** (§3 step 12, Q8): endpoints entered by an admin and the deployments agents report; served leaf vs. the newest issued certificate for that name, expiry, chain; alert `scan_mismatch`. SSRF rules as for http-01, ports from the endpoint list only; **no automatic scan of every SAN**. | Test servers serving the right, an old and a foreign certificate; a private address outside the domain policy is refused. |

### 9.2 Rules and defaults (Q7, Q8)

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `cert_expiry` | a valid end-entity certificate expires and is **not superseded** – no valid, unrevoked certificate with the same normalized name set ends later. Agent identity certificates never count | ≤ 14 days left | ≤ 3 days left |
| `ca_expiry` | the current certificate of an active CA expires (the dashboard's existing 90 days) | ≤ 90 days | ≤ 30 days or expired |
| `crl` | a CRL is not current (the dashboard's existing CRL states) | stale | expired |
| `sealed` | the server is sealed (since start or the last seal) | after 10 minutes | when a CRL's next update is less than 24 hours away – a sealed server can't sign a new one |
| `agent_silent` | an active agent has not reported | after 1 hour | after 24 hours |
| `agent_certificate` | an active agent's own certificate was not renewed | – | < 48 hours left (as on the dashboard today) |
| `deploy_failed` | the last report of a deployment is `failed` or `rolled_back` | always | – |

- **Thresholds** are configuration (`monitor:`), so an operator can change them without a release.
  Allowed: expiry days 1–90 with critical below warning, `sealed_after` 1–60 minutes,
  `agent_silent_after` 10 minutes–24 hours, `repeat_every` 1–168 hours.
- **Digest instead of one message per alert:** a CA with 40 expiring certificates produces one
  message, not 40. A message is sent only when something opened, rose, resolved or is due for its
  reminder.
- **Q8:** no automatic scan of names from issued certificates – the server would connect to hosts
  nobody asked it to check. Only endpoints an admin enters or an agent reports (v0.3.4).

### 9.3 Notification channels

```yaml
notify:
  email:
    smtp: mail.homelab.lan:587       # host:port
    security: starttls               # starttls | tls | none (none: only without username)
    username: pki@homelab.lan        # optional
    password_file: /etc/myownpki/smtp-password   # optional, read at each send
    from: pki@homelab.lan
    to: [ops@homelab.lan]
  webhook:
    url: https://hooks.homelab.lan/myownpki
    secret_file: /etc/myownpki/webhook-secret    # HMAC-SHA256 key, required
    ca_file: /etc/myownpki/hooks-ca.pem          # optional extra roots
```

- **Why the configuration and not the database** (a change to the §1.2 draft): the most important
  alert is "sealed", and a sealed server can't decrypt a DEK-encrypted SMTP password. Secrets live in
  files next to `tls_key_file` and `auth.key_file`, readable by the service user only; the
  configuration holds the path. Environment variables `MYOWNPKI_NOTIFY_*` as for every other key.
- **Webhook:** `POST` JSON (`{"server": …, "events": [{kind, subject, severity, state, since, link}]}`),
  header `X-MyOwnPKI-Signature: sha256=<hex HMAC of the body>`, 10 s timeout, no redirects, TLS
  against the system roots plus `ca_file`. The URL is the operator's, so the http-01 SSRF rules do
  not apply; it must be `https`, except `http` to a loopback address.
- **E-mail:** plain-text, one message per digest, subject `[MyOwnPKI] 2 new, 1 resolved`; links
  point to the first name of `admin.tls_names` and the port of `admin.listen` (no link without
  `tls_names`). Standard library `net/smtp` – no new dependency.
- **Neither channel configured:** alerts still open and show in the UI; `config check` and the
  dashboard say that nobody is notified.

### 9.4 Not in v0.3.3

The TLS scan (v0.3.4), notification settings in the UI, per-user subscriptions, more channels
(Slack, Teams, ntfy – the webhook covers them through a relay), and silencing single alerts.
