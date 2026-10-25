# Phase 3 – plan (v0.3: Linux agent, then monitoring)

> Written at the end of the night run 2026-10-21 as a proposal. The owner answered the open
> questions on 2026-10-24 (§5) and split the phase: **v0.3.0 is the Linux agent** (steps 1–9 plus
> 2a and 8a below); **monitoring (steps 11–13) follows in v0.3.x**. Branch `release/v0.3.0`, built
> in blocks A–E (§3). §5 has the decisions, §7 what is still open.
>
> **Progress:** block A done (`9eacb4f`); **block B built** 2026-10-24 – steps 1–3 and the enrollment part
> of 2a, see "Built in block B" at the end of §6. **Block C reviewed and implemented** –
> steps 4–6, with the owner's clarifications below. Blocks D–E follow.

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
| Q7 | Notification defaults | open – with monitoring (v0.3.x) |
| Q8 | TLS scan of SANs | open – with monitoring (v0.3.x) |
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
  local configuration and output is discarded; each invocation has a 30-second timeout.
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
  standalone (like `low-ports.conf` on the server).
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

Nothing is open for v0.3.0. With monitoring (v0.3.x): Q7 (notification defaults) and Q8 (TLS scan
of SANs).
