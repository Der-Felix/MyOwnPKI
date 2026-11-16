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
| 5 | 0.3.0 | **Deploy profiles nginx and file** (Apache and HAProxy in v0.3.11, PLAN §10.1): nginx writes `fullchain.pem` and `privkey.pem` into a directory, file writes each part to the path given – for a host that keeps its existing paths and nginx config; temp file in the target directory, `fsync`, rename, `fsync` of the directory; owner, group and mode from the deployment; PEM; key 0600 by default | – | tests in a temp root for both profiles; a path outside `paths` is refused by the agent; files never half-written |
| 6 | 0.3.0 | **Reload with rollback, for both profiles**: keep the previous files and a durable journal, replace the files, test, reload once per shared reload hook, then check TLS (SNI = first name, SHA-256 of the expected leaf, bounded retries over ~10 s). On failure restore previous files, remove first-installation files and test the restored group. If it passes and a reload was attempted, attempt one rollback reload/check for existing deployments. An open journal is recovered before another pass (§6.3) | – | both profiles against nginx in the Linux container: a mismatched certificate/key staged after validation fails `nginx -t`, restores the old files and leaves the old certificate served without a reload. A mixed group's TLS failure after reload restores and reloads existing deployments and verifies their old leaf; first installations stay `failed`. Failed restored tests prevent a reload and mark the whole group `failed`, explaining that the service still has the pre-rollback state. A stop between replacement and reload recovers from the journal |
| 7 | 0.3.0 | **Heartbeat and report** every 5 minutes (±30 s jitter): agent version, OS, every deployment with state, certificate, expiry and last error; `last_seen_at`; the UI shows "silent" after 3 missed beats (the `agent_silent` alert comes with monitoring) | – | fake-clock test; the agent list shows last seen and version |
| 8 | 0.3.0 | **Renewal scheduling** at 2/3 of the lifetime with jitter (a random point in the last 10 % before 2/3), or earlier when the server's ARI window (PHASE2 step 12) says so | – | fake-clock test; ARI window followed |
| 8a | 0.3.0 | **"Renew now" without remote commands** (owner 2026-10-24, §6.4): the button sets `renew_requested_at/by` and raises the agent's `desired_version`, with an audit entry; `WatchDesiredState` long-poll (answer at once when newer, else "unchanged" after at most 50 s); the agent renews through its normal ACME path (new key, deploy, rollback) and reports; the server clears the request. operator and admin may, viewer may not; the button is locked while a request is open. UI: agent list, agent detail with deployments | – | the API call reaches the agent within seconds; viewer gets 403; a second request while one is open is refused; a server restart during a long-poll: the agents come back within the backoff, no burst (test with many fake agents) |
| 9 | 0.3.0 | **Linux packaging**: hardened systemd unit (§6.6), `deploy/install-agent.sh` modelled on `install.sh`, the agent in `.goreleaser.yaml` (released for linux/amd64 and linux/arm64; it must still build for Windows, macOS and FreeBSD in the CI cross-build); CI job **agent end-to-end**; OPERATIONS chapter "Agent"; CHANGELOG 0.3.0 | Q4 – tarball and script | the CI job (§6.7) must run `TestNginxDeployProfiles` with nginx available in Linux CI from this step onward (no skip); `systemd-analyze security` measured in CI and documented |
| 10 | 0.3.9 | **Trust store, small form** (PLAN §10.1, part of the public trust portal): root download as PEM, DER, `.mobileconfig`; the agent can add the root to the system trust store (`update-ca-certificates`), off by default | – | Debian and Fedora layouts tested in containers |
| 11 | 0.3.3 | **Expiry dashboard** (replaced by §9 step 22): certificates by expiry, agent status, sealed warning, CRL freshness. Expiry alerts must exclude agent identity certificates from end-entity lists and warn per active agent when its current certificate has less than 48 hours left. | – | handler tests, screenshots light/dark |
| 12 | 0.3.4 | **TLS scan** (integration level 2; replaced by §9 step 26): scheduled scan of `endpoints` (manual, from agents, from SANs), served certificate vs. the issued one, expiry, chain; SSRF rules as for http-01, ports from the endpoint list only | – | test servers serving the right / an old / a foreign certificate |
| 13 | 0.3.3 | **Notifications** (replaced by §9 steps 22–24): e-mail (SMTP with STARTTLS/TLS, no plain auth over plain text) and webhook (JSON, HMAC-SHA256 signature header, retries with back-off); alert rules: expiry (30/14/7/1 days), deploy failed, agent silent, scan mismatch, **sealed** – measured against the remaining CRL lifetime | – | a local SMTP and webhook receiver in tests; secrets never in logs; a sealed server alerts before its CRLs expire |
| 14 | 0.3.11 | **Demo** (PLAN §10.1): `deploy/demo/docker-compose.yml` (MyOwnPKI, nginx with the agent, a certbot container – PLAN §10.1 "Live test") | Q5 – later | one command brings the demo up |

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
| 24 | 0.3.3 | **Alerts in UI and REST.** Page *Alerts* (open and resolved in the last 7 days), dashboard block, `GET /api/v1/alerts` (viewer and up, `api/openapi.yaml` first), `POST /api/v1/notifications/test` (admin, audited). `config check` shows the channels and the thresholds. *Built:* tenant-wide role needed to read (a role limited to one CA gets 403, the alerts name the whole tenant); the test needs the tenant role admin (permission `notification.test`), no step-up because it changes nothing, at most one every 10 seconds, audit action `notification.test` with the result per channel (never a secret; error texts may name hosts, file paths and recipient addresses); the page's button is a plain POST form that ends in 303 on the page, like every action of the UI (htmx is not shipped yet); a missing, unreadable or empty secret or CA file fails `config check` (exit 1), no channel only warns. | Handler and contract tests, roles (viewer reads, only admin sends the test), audit entry for the test; `config check` names a missing secret file and an unreadable one. |
| 25 | 0.3.3 | **Docs and release.** OPERATIONS chapter "Monitoring and notifications" (setup, a test, what each alert means and what to do), CHANGELOG 0.3.3, version bump. *Built:* OPERATIONS chapter 13 (setup for e-mail, webhook and the container image, the test, every alert with what to do, retries and the log lines to watch, troubleshooting, an end-to-end check), the 0.3.3 CHANGELOG section with upgrade notes, and the version bump as in v0.3.2 (`DEFAULT_VERSION` of both install scripts, the install, cosign and Compose examples in README, OPERATIONS and RELEASING, the version test of the agent installer); live test by the owner pending. | `task check`, Linux CI including the image job, live test on the owner's installation: seal → message after 10 minutes, unseal → resolved. |
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
    to: ops@homelab.lan, lead@homelab.lan   # comma-separated
    ca_file: /etc/myownpki/mail-ca.pem          # optional extra roots, e.g. this PKI's root
  webhook:
    url: https://hooks.homelab.lan/myownpki
    secret_file: /etc/myownpki/webhook-secret    # HMAC-SHA256 key, required
    ca_file: /etc/myownpki/hooks-ca.pem          # optional extra roots
```

- **Why the configuration and not the database** (a change to the §1.2 draft): the most important
  alert is "sealed", and a sealed server can't decrypt a DEK-encrypted SMTP password. Secrets live in
  files next to `tls_key_file` and `auth.key_file`, readable by the service user only; the
  configuration holds the path. Environment variables `MYOWNPKI_NOTIFY_*` as for every other key.
- **Webhook:** `POST` JSON (`{"server": …, "created": …, "events": [{kind, subject, severity, state, since, detail, link}]}`,
  state `opened`, `raised`, `reminder`, `resolved` or `test`), header `X-MyOwnPKI-Signature: sha256=<hex HMAC of the body>`, 10 s timeout, no redirects, TLS
  against the system roots plus `ca_file`. The URL is the operator's, so the http-01 SSRF rules do
  not apply; it must be `https`, except `http` to a loopback address. The standard proxy variables
  (`HTTPS_PROXY`, `NO_PROXY`) apply.
- **E-mail:** plain-text, one message per digest, subject `[MyOwnPKI] pki01: 2 new, 1 resolved`; links
  point to the first name of `admin.tls_names` and the port of `admin.listen` (no link without
  `tls_names`). Standard library `net/smtp` – no new dependency.
- **Neither channel configured:** alerts still open and show in the UI; `config check` and the
  dashboard say that nobody is notified.

### 9.4 Not in v0.3.3

The TLS scan (v0.3.4), notification settings in the UI, per-user subscriptions, more channels
(Slack, Teams, ntfy – the webhook covers them through a relay), and silencing single alerts.

---

## 10. TLS scan: v0.3.4

v0.3.3 tells you when a certificate is about to expire *in the database*. It cannot tell you that
the certificate renewed last night never reached the web server. The TLS scan closes that gap
(integration level 2, PLAN §6.3a): the server connects to the TLS endpoints an admin entered,
reads the certificate each one **serves**, and compares it with what this PKI issued for that name.
This section replaces the step 26 row of §9.1 and the draft `endpoints` table of §1.2.

Goal of v0.3.4, measured on the live installation: an endpoint that serves a certificate of this PKI
shows as *OK* with the right fingerprint; when it is pointed at an **older** certificate, one
`scan_mismatch` alert and one notification follow within one scan interval (plus the confirmation
and grace times of §10.2); when the right certificate is back, the alert resolves with a second
message. A host that is only rebooting produces nothing.

Where this plan differs from the text above it (the code decides):

- **Agents do not report an address.** The protocol carries `check_configured`, a boolean
  (`proto/myownpki/agent/v1/agent.proto`, `DeploymentReport.CheckConfigured` in
  `internal/agents/report.go`). The `check` address in `agent.yaml` is `host:port` as seen *from the
  host* (validated in `internal/agent/config.go`, typically `127.0.0.1:443`), which means nothing to
  the server. So §9.1 step 26 ("the deployments agents report") and `source = agent` of §1.2 are
  **not built** in v0.3.4 (§10.3). The protocol stays as it is.
- **Migration numbers are per database kind** (`internal/store/schema/<kind>/`). `system.db` is at
  0014 (the alerts), `pki.db` is at 0017. The endpoints live in `pki.db`, so the file is
  `internal/store/schema/pki/0018_endpoints.sql`, not 0015.
- **No automatic scan of SANs** (Q8) stays; `source = certificate` of §1.2 is dropped.

### 10.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 26 | 0.3.4 | **Endpoints and scanner**, in three commits. (a) `internal/netguard`: the address policy and the resolve-once dial of `internal/acme/validate.go` (`allowedAddr`, `policyDial`, `cgnat`) move into a shared package that http-01, the agent enrollment check (`acme.HTTP01Checker`) and the scan all call; the port rule (80/443) stays in `acme`, the scan has its own. (b) `pki.db` migration 0018 `endpoints` (§10.2), `internal/tlsscan`: store, `Service` (create, list, delete, scan now, with `authz`, audit through the `pki.db` outbox and the limits), sqlc queries. (c) `Scanner` and its job: a dispatcher every 30 seconds hands due endpoints to a pool of 4 workers and returns at once; per scan: resolve once through `acme.resolver`, the address policy of the covering domain, one TCP connection, a TLS handshake with `InsecureSkipVerify` only to *collect* the chain, close. The chain is then verified **separately** against this PKI's CAs (`ca.Engine.TrustAnchors`, new, read-only) and stored as `trusted`, `incomplete` or `untrusted`. The `monitor:` keys `scan_interval`, `scan_timeout`, `scan_ports`, `scan_max_endpoints` go into `internal/config` (`Monitor`, `envFields` in `env.go`, validation), `deploy/config.example.yaml`, tests and `cmd/myownpki/config.go` (`printMonitoring`). *Built (3 commits):* (a) `netguard.Dialer` takes the port rule as `CheckPort` (nil refuses every port) and the cap and timeout per address, `Allowed` also refuses an address with a zone, `NewResolver`, `NetProblem` and `DNSProblem` moved too; `acme.policyDial` is a thin wrapper that keeps the 80/443 rule and the old texts. (b) Migration 0018 as in §10.2; the permissions `endpoint.manage` (admin) and `endpoint.scan` (operator, admin) are added here and not in step 28 because the service checks them; `agents.CheckDNSName` is the shared name check, plus a punycode check for `xn--` labels; `Engine.TrustAnchors` leaves out revoked CA generations. (c) `monitor.scan_unreachable_after` and `scan_mismatch_after` are built here with the other keys (`config.Monitor.Scan()`, kept apart from `Values()`); the job `tls-scan` is registered only when `scan_interval` is not `off`; a finished worker looks for more due endpoints itself, so a backlog does not wait for the 30-second tick; a scan keeps the last good data when it fails; one more error kind, `could not connect`, and the refusals are `refused by the address policy`, `no domain covers the host` and `port is not in monitor.scan_ports`; a TLS 1.2 server that rejects the missing client certificate after its chain (`handshake failure`, `bad certificate`) is `client certificate required`; `go test -race` was not run on the Windows machine (no C compiler), CI does. 
 | `netguard` table tests (loopback, link-local, multicast, unspecified, reserved incl. broadcast, private under `public`, CGNAT, IPv4-mapped IPv6, IPv6 zone; each embedding and translated range with its edges: `::/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, Teredo, `::ffff:0:0:0/96`; each non-global range with its edges; the documentation ranges stay allowed) and the **unchanged** `internal/acme` validation tests still green; a rebinding test (a second lookup would answer 127.0.0.1, the connection still goes to the first, checked address); scanner tests against a local TLS server (right, older, foreign, expired, wrong name, leaf-only chain, client certificate required, plain HTTP on the port, accepts TCP and never answers, closed port) with the network edges injected; `go test -race`; a scan runs while the keyring is sealed; closing the server stops running scans |
| 27 | 0.3.4 | **Evaluation.** `internal/tlsscan` holds the pure function `Assess` (endpoint, what the PKI issued for the name, now: state); `internal/monitor/scan.go` feeds it from the certificates the evaluator already loads (valid ones, the superseded rule of `nameSet` in `certificates()`, `evaluate.go`) plus a fingerprint lookup for a served certificate that is not in the expected set (`ca.Engine.CertificateByFingerprint`, new, read-only, same 404 rule as `Certificate`, over the existing sqlc query `GetCertificateByFingerprint`). The kinds `scan_mismatch`, `scan_expiry`, `scan_unreachable`, `scan_chain` (§10.2) become findings of `Evaluator.Evaluate`; `alerts` (system.db) needs no migration (`kind` has no CHECK). Thresholds are `monitor:` keys with ranges. Resolve on recovery; digests and channels are unchanged (`notify` is not touched; the kinds travel as free text). The dashboard figure *Open alerts* counts them with no change (`alertNumber` counts every open alert); the dashboard's message list (`alertMessages`) keeps its allowlist and does not show them. *Built (2 commits):* `tlsscan.Assess(endpoint, Input{Current, Known}, Params, now)` returns the state and the alarms already past confirmation (2 successful scans of one fingerprint) and grace; `monitor/scan.go` builds the expected set and the `Known` lookup and writes the texts. Decisions where §10.2 was silent: failed scans below `scan_unreachable_after` keep the state of the last good scan; once the streak is reached the state is `unreachable` for every failure kind but only the kinds that count (§10.2) open the alert; `older`, `foreign` and `wrong_name` open `scan_mismatch` only when the expected set is not empty (the grace time needs the newest certificate); `revoked` wins over the IP-without-SNI rule; `scan_expiry` is left out when the served certificate has its `cert_expiry` finding; with `scan_interval: off` the scan findings are not produced and the alerts resolve. `Evaluator.EndpointStates` (and `Server.EndpointStates`) give the page and the API the same assessment per endpoint that the alerts use. 
 | Fake-clock tests per kind: nothing before the confirmation scan; `scan_mismatch` opens only after the grace time and a second scan of the same fingerprint and resolves with the next good scan; `scan_unreachable` opens at the Nth consecutive failure and not for a reboot; no duplicates across runs; an unmanaged name gives state `unmanaged` and no `scan_mismatch`; wildcard and IP endpoints; a deleted endpoint resolves its alerts; one digest with a mismatch opened and another alert resolved in the same run |
| 28 | 0.3.4 | **REST and UI.** `api/openapi.yaml` first: `listEndpoints`, `createEndpoint`, `deleteEndpoint`, `scanEndpoint` (tag `monitoring`; `x-required-role` viewer, admin, admin, operator), the `Endpoint` schema, the new `Alert.kind` values. Handlers in `internal/httpapi/endpoints.go`, routes in `routes.go` (`signedIn`), a `WaitError`-style 429 with `Retry-After` for scan now (as `notify.WaitError` in `problem.go`). Page *Endpoints* (`internal/web/app_endpoints.go`, built from `admin.DetailPage`, `TableData` and `FormData` like *Alerts*; nav entry under Overview in `layout/app.templ`, `Real: true`, hidden without `pki.read` or when monitoring is off, as *Alerts*): add form, table with state, served fingerprint, expiry, issuer, last scan and error, a *Scan now* and a *Remove* button per row (plain POST forms that end in 303). New permissions `endpoint.manage` (admin) and `endpoint.scan` (operator, admin) in `internal/authz`; audit actions `endpoint.create`, `endpoint.delete`, `endpoint.scan`; labels for the four kinds in `alertKinds` (`internal/web/app_alerts.go`). *Built (2 commits, after a netguard fix that closed the IPv6 forms embedding an IPv4 address):* the API commit holds the spec and the handlers together, so that every commit passes `TestEverySpecOperationIsServed`; `monitor.Endpoints` joins the endpoint service (role check, audit) with `Evaluator.EndpointStates`, so the page, the API and the alerts show one state (`listEndpoints` first asks the service whether the caller may read, then assesses only what it returned). The responses: `Endpoint` with `state` (the `tlsscan.State*`), `expiry_severity` (the `scan_expiry` alarm), the error kind and a `served` object (fingerprint, `certificate_id` when this PKI issued it, serial, clipped subject and issuer, dates, chain state, TLS version, how long it has been served); `created_by` only for roles with `endpoint.manage`, in the API and on the page. Refusals of the service are **422** `policy-violation` with `errors[0].field` as a JSON pointer (`/host`, `/port`, `/sni`) and the rule; a malformed body is 400, a body over 4 KiB is 413 (and the 413 text now names the limit of the route), duplicate, limit and scanning off are 409, scan now twice is 429 with `Retry-After`; `scanEndpoint` answers **202** without a body. The handlers do not audit: the service does, refusals included. The page (`internal/web/app_endpoints.go`) uses `admin.DetailPage` and `TableData`; `admin.Cell` got a `Title` (hover text), the only change to a shared template. Plain POST forms (`/endpoints`, `/endpoints/scan`, `/endpoints/delete`) end in 303 and a flash message; the UI ships no htmx script and none was added. Decisions where §10.2 was silent: the states `pending` and `refused` are shown as *Pending* and *Refused*; the four wrong-certificate states share the word *Wrong certificate* with a short qualifier (older certificate of this PKI, not issued by this PKI, not valid for this name, revoked); *Expiring* replaces *OK* only while the served certificate is fine otherwise (any other state keeps its word and the *Expires* cell takes the status color); with `scan_interval: off` the page shows one sentence and no *Scan now*, but add and remove still work; the dashboard's message list stays as step 27 left it and does not show the scan alerts (the *Open alerts* figure counts them). The suite runs on the real engine; the served-certificate rows are written with SQL, as the scanner would.
 | Contract tests (every operation of the spec has a route and the reverse); `task lint:api`; role tests (viewer reads, operator scans but cannot add, admin adds, a role limited to one CA gets 403); the validation table below; audit entries incl. denied ones; scan now answers 429 inside 60 seconds; a hostile served subject (`<script>`) renders as text; the page renders with and without monitoring; no inline styles or undefined classes (the UI tests) |
| 29 | 0.3.4 | **Docs and release.** OPERATIONS chapter 14 "TLS scan" (set-up, each state and alert with what to do, ports and limits, troubleshooting, the end-to-end check below), a pointer row in §13.6, an upgrade paragraph in OPERATIONS §9 ("From v0.3.3 to v0.3.4: pki.db migration 0018, additive"); CHANGELOG 0.3.4; version bump to 0.3.4 in the files of commit `6a8016d` ("docs: prepare v0.3.3 release": `CHANGELOG.md`, `README.md`, `deploy/docker-compose.yml`, `deploy/install-agent.sh`, `deploy/install.sh`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`) and the `v=0.3.3` examples in `docs/OPERATIONS.md`; PLAN §10.1 and this file marked as built. *Built (6 commits, no product code):* OPERATIONS chapter 14 (14.1–14.11: what a scan does, requirements, set-up in the UI and with curl, the page and every state, the alerts, settings, limits and storage, the never-scanned ranges, roles and audit, troubleshooting per error kind, the end-to-end check above), a pointer row in §13.6, a pointer in §13.7 and the introduction of chapter 13, the upgrade paragraph in §9, and notes in §10.5 and §10.9 that the address guard is shared. CHANGELOG 0.3.4 dated 2026-11-12 with the compare links; **the two agent bullets of commit `3b755ba` ("Agent commands with an absolute path" and "Join token page runs setup") moved from 0.3.3 to 0.3.4 Fixed**, because they were merged into the 0.3.3 section after the tag and v0.3.3's published release notes never had them. The version bump is the file list of `6a8016d` plus the `v=` and package file name examples in OPERATIONS, the version in the heading of `site/hosts/salt.md` (the join-token limit still holds) and `info.version` of `api/openapi.yaml` (0.2.0 to 0.3.4; no test pins it). The public site has the page `site/tls-scan.md`, an entry in the navigation, index (level 2 is *Available*), monitoring, troubleshooting, upgrade, best practices, hosts and API pointers; the version on the home page comes from the changelog data. Stale statements fixed: OPERATIONS §12.6 (`sudo sh -c 'cd … && rm …'`), CONTRIBUTING (PHASE3 is the current plan), the PLAN status line (v0.3.4 is **not** marked as released). Where the text follows the code and not the plan: a mismatch is confirmed by two scans of one fingerprint *counted from before the renewal*, so an endpoint that served the old certificate for weeks alerts at the first evaluation after `scan_mismatch_after`; the error vocabulary and the counted kinds include `could not connect`; *Unreachable* is also the state of a `client certificate required` endpoint after the threshold, with no alert; the message of the `422` for an IP in a never-scanned range still lists only unspecified, loopback, link-local, multicast and reserved addresses and does not name the NAT64, 6to4, Teredo and IPv4-compatible ranges (a text to fix in code, not changed here). *Live test by the owner pending.* | `task check`, `task ci:local` (every SKIP line reported), Linux CI incl. the image job, the live test below |

**Live test for the owner** (names are examples; set `monitor.scan_interval: 5m` for the test):

1. `myownpki config check` shows the *TLS scan* rows. Restart the service.
2. *Endpoints*: add `proxy.homelab.lan`, port 443, a host that serves a certificate of this PKI. Within
   a minute the state is **OK**; compare the shown fingerprint with
   `openssl s_client -connect proxy.homelab.lan:443 -servername proxy.homelab.lan </dev/null | openssl x509 -noout -fingerprint -sha256`.
3. **Older certificate:** on that host switch the service to a previous certificate of the same name
   (the agent's backup, or one issued earlier) and reload. The newer certificate must be older than
   `scan_mismatch_after` (default 1 hour). After two scans: `scan_mismatch` (warning) on *Alerts*
   and one e-mail or webhook message.
4. **Fix:** put the current certificate back and reload. The next scan resolves the alert; the
   second message says *resolved*.
5. **Unreachable:** stop the service. After 3 failed scans: `scan_unreachable`. A restart within two
   scans (a reboot) produces nothing. Start it again: resolved.
6. **Unmanaged:** add an endpoint that serves a certificate of another CA for a name this PKI never
   issued: state *Not issued by this PKI*, no `scan_mismatch`.
7. **Guard:** adding `127.0.0.1` port 443 and `proxy.homelab.lan` port 22 is refused; both attempts
   are in the audit log. Seal the server: the *Last scan* column keeps moving.
8. Remove the test endpoints; their alerts resolve within a minute.

### 10.2 Rules and defaults

**How a scan works.** One TCP connection per endpoint and scan, one TLS handshake, then close. The
server sends the ClientHello and what the handshake requires, **no application data and no HTTP
request** – so there are no redirects to follow, no request to forge and no body to limit. The
connection uses `InsecureSkipVerify` only because its purpose is to *collect* whatever the endpoint
serves (`#nosec G402` with the reason, as in `http01`). Trust is decided afterwards: the leaf and the
served intermediates are verified with `x509.Verify` against the root CAs of this PKI at the injected
time, key usage server authentication. If that fails, a second run adds this PKI's own
intermediates: success means the endpoint forgets to send them (`incomplete`), failure means the
chain does not lead to this PKI (`untrusted`). A leaf that has expired is verified at its last valid
second so that expiry does not hide a chain problem (expiry has its own alert). The hostname is not
part of `Verify`; the name comparison is `Assess`' job.

**Decisions** (the owner is asleep: the cautious variant; `(owner may change)` marks real choices):

| Question | Default | Why |
|---|---|---|
| Who may add or remove endpoints | tenant **admin**, permission `endpoint.manage`, no step-up, audited; an API token may | It makes the server connect to chosen hosts, so it sits at the level of domains and agents. It grants no trust and changes no certificate, so no step-up (like `notification.test`), and a script that registers endpoints is wanted for v0.3.5/6. The check uses a tenant-wide resource, so a role limited to one CA cannot. `(owner may change)` |
| Who may read | tenant-wide `pki.read` (viewer and up) | Endpoints name the hosts of the whole tenant, like alerts (`monitor.Store.List`) |
| Who may scan now | operator and admin, permission `endpoint.scan`; once per endpoint and 60 seconds, kept in the row so it survives a restart | Scanning an endpoint that is already entered adds no new target. `(owner may change)` |
| Which hosts | the host must be covered by a **domain** (`ca.Engine.DomainFor`: DNS names by name, IPs by the domain's IP ranges), and the **address policy of that domain** applies at every scan, not only when the endpoint is added | The rule the agent enrollment already follows (§3 step 2). Creating a domain needs `ca.manage` with step-up (`Engine.CreateDomain`), so an API token or an admin without a fresh second factor cannot widen the set of reachable hosts. `(owner may change)` |
| What the guard always refuses | under every policy: unspecified, loopback, link-local (incl. 169.254.0.0/16, fe80::/10), multicast, an IPv6 address with a zone, 0.0.0.0/8 and 240.0.0.0/4 (incl. the broadcast address); the IPv6 ranges that embed an IPv4 address or translate to one, **as whole ranges** – `::/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32` and the IPv4-translated `::ffff:0:0:0/96` (IPv4-mapped `::ffff:a.b.c.d` is the exception: it is unmapped and judged as its IPv4 address); and the non-global ranges 192.0.0.0/24, 198.18.0.0/15, 192.88.99.0/24, fec0::/10, 100::/64 and 5f00::/16. The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) stay allowed. Under policy `public` also RFC 1918, fc00::/7 and 100.64.0.0/10. Private ranges are allowed under `internal` (the default) | One implementation (`internal/netguard`), one set of tests. A translated address could reach 127.0.0.1 (`64:ff9b::7f00:1`, `::ffff:0:7f00:1`) although it looks global, and no TLS endpoint of anybody lives in these ranges, so they are refused whole instead of parsed one by one. The documentation ranges stay open because tests and examples use them as stand-ins for public addresses. The server cannot scan its own 127.0.0.1, but its LAN address is allowed: a bare handshake gives nothing a client does not get anyway |
| Ports | only those in `monitor.scan_ports`; default `443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443` (TLS from the first byte); 1–65535, at most 32 entries; an endpoint's own port only, nothing derived or followed | A tenant admin cannot turn the server into a port scanner; widening the list is a decision of whoever edits the configuration on the server. STARTTLS ports (25, 143, 587) need protocol bytes and are out (§10.3) |
| Number of endpoints | `monitor.scan_max_endpoints`, default **100** (1–500); beyond it adding is refused with 409 | Bounds work and memory; the order of `agents.MaxDeployments` |
| Host syntax | a fully qualified DNS name by the rules of `agents.CheckHostname`/`checkDNSName` (lower case, at least two labels, letters, digits, hyphen, no wildcard, a trailing dot is trimmed; the check is shared, not copied) or an IP literal (IPv6 without brackets, no zone, IPv4-mapped is unmapped) | Attacker-style input is rejected at the door, with a table test; the guard is the second wall (`localhost` falls out by syntax, `127.0.0.1` by the guard) |
| SNI | optional per endpoint. Empty: a DNS host is sent as SNI; an IP host sends **no** SNI (RFC 6066 forbids IP literals). Set: that name is sent, and it is the name the certificate is expected for | An IP endpoint with virtual hosts needs a name. The SNI is a validated DNS name and never a connect target |
| IPv6 | supported. The resolver's A and AAAA answers are checked one by one in its order; at most **4** addresses are tried per scan, 3 seconds each, inside the endpoint timeout; no Happy Eyeballs | The guard tries every address today; the cap is new for the scan (a `MaxTries` field) so a name with 50 records cannot hold a worker |
| Timeout | `monitor.scan_timeout`, default **10 s** (2–30 s), for resolve, connect and handshake together. The work after the handshake (reading the trust anchors from `pki.db` and verifying the chain) has its **own budget of 5 s** (`ChainTimeout`), derived from the scanner's context so that `Close()` still cancels it | As `validateTimeout`. A handshake that ends with the deadline in sight must not leave the chain check without time: that would end every scan in an error and store no result |
| Interval and jitter | `monitor.scan_interval`, default **15 m** (5 m–24 h, or `off`); the next scan of an endpoint is the interval plus a random 0–10 % (injectable source); a new endpoint is scanned at the next dispatch | 15 minutes finds a stuck deployment the same morning for one handshake per endpoint; jitter keeps 100 endpoints from firing together after a restart. `off` is for operators who forbid outbound connections; the page then says so |
| Concurrency and memory | dispatcher every 30 s; **4** workers; an endpoint in flight is skipped; its `next_scan_at` moves forward when it is claimed, so a crash cannot rescan at once; an endpoint whose `next_scan_at` lies beyond now + 2 × interval counts as due too (the clock stepped back, for example a VM that booted with a wrong time), so it never stays silent; `Close()` cancels and waits (as `acme.Server.Close`); a handshake message is bounded by `crypto/tls` (64 KiB); only the leaf and 8 intermediates are looked at | The scheduler (`scheduler.runDue`, `internal/server/jobs.go`) is **one goroutine** that runs the jobs one after the other: a scan inside `runDue` would stall the CRL, ACME and alert jobs. So the job only dispatches |
| Sealed server | scans, evaluation and alerts run while sealed | Nothing is decrypted: the scan needs no key, and the certificates and CA certificates it compares are public data in `pki.db` (as in §9.1 step 22). A sealed server that still reports a lapsed deployment is the point |
| What is stored | per endpoint: host, port, SNI, source, created by and at, next and last scan, last success, failure streak, error **kind** with a fixed short message, and of the served leaf: SHA-256 fingerprint, serial, subject, issuer (each clipped to 256 bytes, valid UTF-8, control characters replaced), not before and after, chain length, chain state, TLS version, and how many consecutive scans saw this fingerprint. **Never** the DER, a public key, a SAN list or the resolved address (the address goes to the log) | Metadata is enough to compare and show; nothing private is on the wire anyway |
| Error text | a fixed vocabulary (`dns`, `refused by the address policy`, `timed out`, `connection refused`, `TLS handshake failed`, `no certificate`, `client certificate required`), reusing the idea of `netProblem`/`dnsProblem` in `acme`; what the remote end said is never stored, quoted or logged; anything unmapped is clipped to 200 bytes; templ escapes on output. **Subject and issuer of a served certificate go to the page and the API only, never into an alert's `detail`**, which travels to e-mail and webhook | A remote host chooses its own certificate text and error bytes: attacker input (security.md "Untrusted input") |
| Names never issued by this PKI | state **`unmanaged`**: the page says *Not issued by this PKI*, **no `scan_mismatch`**; `scan_unreachable` and `scan_expiry` still apply. An IP endpoint without SNI is `unmanaged` too (this PKI's certificates rarely carry IP SANs); the page hints to set an SNI | Alerting about a certificate nobody here manages is noise; but the admin entered the endpoint, so a dead or expiring certificate on it is still worth a message. `(owner may change)` |
| Wildcards | a certificate matches an endpoint name by RFC 6125 rules: one leftmost label, so `*.homelab.lan` covers `proxy.homelab.lan`, not `a.b.homelab.lan` or `homelab.lan`; an endpoint host is never itself a wildcard | A wildcard certificate is a normal answer for a name |
| Clock | `Scanner`, `Service` and `Assess` take a `clock.Clock` or `now`; `tls.Config.Time` and `x509.VerifyOptions.CurrentTime` come from it; real timeouts are `context` deadlines as in `validate.go` | Project rule: injectable clock, `time.Now` is a lint error |
| Logs | one `scan` line at `Info` when an endpoint's state changes (ok to unreachable, …) with host, port and kind; each scan at `Debug`; never a subject or a remote message | A scan every 15 minutes per endpoint must not fill the log |

**What "the issued one" means.** For an endpoint name N (the SNI, else the host), the *expected set* is
every certificate of the PKI that is valid now (not revoked, not expired, `not_before` ≤ now), is not
an agent identity certificate (`HideAgentCertificates`), covers N and is **not superseded**: no other
valid certificate with the same normalized name set ends later (`nameSet` in `evaluate.go`). Two
certificates with different name sets (an exact one and a wildcard one) are both current. The served
leaf's SHA-256 fingerprint is compared with the set (`CertificateInfo.Fingerprint`, upper-case hex).

**States** (computed by `tlsscan.Assess`; the page, the API and the alerts show the same one):

| State | Meaning | Alert |
|---|---|---|
| `pending` | no scan yet | – |
| `ok` | the served leaf is in the expected set and the chain is `trusted` | – |
| `unmanaged` | the expected set is empty and the served leaf is not a certificate of this PKI | – (page only) |
| `older` | the served leaf is a certificate of this PKI that is superseded – or that has ended with nothing newer. The page words the second case **Expired** ("no newer certificate was issued", in the color of the expiry alert); the state stays `older`, so the API vocabulary has no new value | `scan_mismatch` for a superseded one (it needs a newer certificate to wait for); an ended one is `scan_expiry` |
| `foreign` | the expected set is not empty and the served leaf is not from this PKI | `scan_mismatch` |
| `wrong_name` | the served leaf is from this PKI but does not cover N | `scan_mismatch` |
| `revoked` | the served leaf is a revoked certificate of this PKI | `scan_mismatch`, critical |
| `chain` | the leaf is right but the chain is `incomplete` or `untrusted` | `scan_chain` |
| `unreachable` | the last scans failed | `scan_unreachable` |
| `refused` | no domain covers the host any more, or the guard refuses the address | – (the page says why; not an outage) |

**Alerts** (key `kind:endpoint id`, subject `host:port`, `href` `/endpoints`; they follow the rules of
§9.2: one row per condition, severity may rise, resolves when the cause is gone):

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `scan_mismatch` | state `older`, `foreign` or `wrong_name` seen by **2 consecutive scans** (same fingerprint) and the newest certificate of the expected set is older than `scan_mismatch_after` (measured from its `created_at`, so the minutes between a renewal and its deployment stay silent); state `revoked` needs only the 2 scans, no grace | `older`, `foreign`, `wrong_name` | `revoked` |
| `scan_expiry` | the served leaf ends within the `monitor.expiry_days` thresholds, or has ended, and it is not a certificate whose `cert_expiry:<id>` finding exists in the same run (that alert already says it) | ≤ 14 days | ≤ 3 days or expired |
| `scan_unreachable` | `scan_unreachable_after` consecutive failed scans (kinds `dns`, `timed out`, `connection refused`, `TLS handshake failed`, `no certificate`) | from the Nth failure | down for 24 hours |
| `scan_chain` | state `chain` seen by 2 consecutive scans, only when the served leaf is a certificate of this PKI | always | – |

`scan_expiry` reuses the pair `monitor.expiry_days` rather than adding keys: the question is the same
("how long until clients refuse it") and a second pair of numbers would drift. It is a separate kind
from `cert_expiry` because it is about what is *served*: it is the only expiry alert for a foreign or
superseded certificate that is still in use, and the served certificate is the one that causes the
outage.

**Configuration** (`monitor:`, strings like every key; `MYOWNPKI_MONITOR_SCAN_*`; all shown by
`config check`; out-of-range values fail `config check` and the start, as today):

| Key | Default | Allowed |
|---|---|---|
| `scan_interval` | `15m` | `5m`–`24h`, or `off` |
| `scan_timeout` | `10s` | `2s`–`30s` |
| `scan_ports` | `443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443` | 1–32 ports, 1–65535 |
| `scan_max_endpoints` | `100` | 1–500 |
| `scan_unreachable_after` | `3` | 1–10 failed scans |
| `scan_mismatch_after` | `1h` | `5m`–`24h` |

**Data** (`pki.db` 0018, additive). The table is per tenant like the agents' tables. The scanner writes
results there in one transaction; the evaluator reads them and writes alerts to `system.db` in
another – no transaction spans two databases (ADR-06), and audit entries for add and remove go
through the outbox of `pki.db` in the same transaction.

```
endpoints
  id TEXT PK (prefix ep)
  host TEXT, port INTEGER, sni TEXT NULL            -- UNIQUE (host, port, COALESCE(sni, ''))
  source TEXT CHECK (source IN ('manual', 'agent')) -- 'agent' is a seam: nothing writes it yet
  created_at, created_by
  next_scan_at, scan_requested_at NULL
  last_scan_at NULL, last_ok_at NULL, fail_streak INTEGER, last_error_kind NULL, last_error NULL
  fingerprint NULL, serial NULL, subject NULL, issuer NULL, not_before NULL, not_after NULL,
  chain_len NULL, chain_state NULL CHECK (chain_state IN ('trusted', 'incomplete', 'untrusted')),
  tls_version NULL, same_count INTEGER, fingerprint_since NULL
```

The SQL file and the queries (`internal/store/queries/pki/endpoints.sql`) are ASCII only; `sqlc`
regenerates `pkidb`.

**Validation table for `createEndpoint`** (attacker-style input, one test row each): `localhost`,
`127.0.0.1`, `[::1]`, `0.0.0.0`, `169.254.169.254`, `fe80::1%eth0`, `::ffff:127.0.0.1`,
`::ffff:0:7f00:1`, `64:ff9b::7f00:1`, `198.18.0.1`, `a b`,
`*.homelab.lan`, `-x.homelab.lan`, a 254-character name, an empty host, `xn--` garbage,
`http://proxy.homelab.lan`, port `0`, `22`, `80`, `65536`, `-1`, a duplicate, the 101st endpoint, a host
no domain covers, a body larger than 4 KiB; `proxy.homelab.lan.` is accepted and stored without the dot.
Every refusal names the field and the rule, never an address that was resolved.

**Endpoint IDs in requests.** The ID of the scan and remove calls (path of the REST API, field of the UI
forms) is attacker input. It must match `^[0-9A-Za-z_-]{1,64}$`; anything else is "not found", but only
**after** the role check, so a caller without the role gets 403 and never learns anything from the
order. A denied or failed request with such an ID is audited with the target type `endpoint` alone; the
ID that was asked for goes into `details.id`, cleaned (control and format characters replaced) and
clipped to 64 bytes. The audit log shows target IDs to admins and ships them to a SIEM, so an ID that is
not well-formed never becomes one. A "not found" itself is not audited.

**Test strategy.** No real hosts and no real DNS: names are `homelab.lan`, addresses `192.0.2.x`. A
local TLS server (`net.Listen("tcp", "127.0.0.1:0")` with `crypto/tls`) serves a certificate; the
network edges are replaced the way `acme.Server.SetNetwork` does it – `dial` connects to that
listener and `lookupIP` answers `192.0.2.10` – while the address policy, the port rule and
everything around them run unchanged. Certificates come from the real engine of
`internal/testinstance` (`Engine.Issue`; a renewal for the *older* case; revocation; a second
throw-away CA generated in the test for *foreign*; `clock.Fake` advanced for *expired*, which the page words *Expired*), so the
comparison runs on real rows. The failure servers are small goroutines: leaf only, wrong name,
requires a client certificate, plain HTTP, accepts and stays silent, closed port. Two more cases: a
connection whose close after a finished handshake is held back past the deadline still stores a result
and logs no error (the chain check has its own budget), and an endpoint whose next scan lies beyond
twice the interval is scanned at the next dispatch (fake clock stepped back). The ID cases of the
validation table run through the service, the REST API and the UI forms: a viewer gets 403 and a clean
audit entry, an admin gets "not found". Everything runs
under `-race` and the fake clock, without `time.Sleep`.

### 10.3 Not in v0.3.4

- **Endpoints reported by agents.** The agent reports no host:port (top of this section), and
  extending the Connect-RPC protocol (a field in `agent.proto`, agent and server in step) changes a
  released protocol. A later candidate: a button on a deployment that pre-fills the add form with the
  deployment's first name and port 443, still an admin's decision. `source = 'agent'` exists in the
  table so that this needs no table rebuild.
- **Automatic scan of the names in issued certificates** (Q8): the server would connect to hosts
  nobody asked it to check.
- **STARTTLS protocols** (SMTP, IMAP, POP3, LDAP): they need protocol bytes before the handshake,
  against "nothing beyond the ClientHello". A different feature.
- **A network or port scan to discover unmanaged endpoints** (PLAN §6.5): this release scans what an
  admin entered.
- **mTLS endpoints** are read only as far as the handshake gives the certificate (TLS 1.3 shows it
  before the server rejects us); no client certificate is ever presented.
- **Scan history, charts, per-endpoint settings** (interval, thresholds), silencing one endpoint, an
  import of endpoints from a file and a CSV export. The *Analysis* page of v0.3.8 (orphaned
  certificates "not served anywhere") can read the stored last result.
- **OCSP stapling, protocol versions, cipher suites and key sizes of the endpoint.** The handshake
  accepts TLS 1.2 and 1.3 only; a server that speaks TLS 1.0/1.1 only is reported as `TLS handshake
  failed`.
- **No ADR changes.** The plan fits ADR-06 (one transaction, one database), ADR-10/18/19 and ADR-12;
  it adds one package (`internal/netguard`), no dependency and no protocol change.

---

## 11. Agent and host onboarding: v0.3.5

Today a new host takes a dozen manual steps: install the package, run `setup`, wait for an approval,
then hand-edit `agent.yaml` (hooks, `paths`, deployments, `acme_directory`) and hand-edit the systemd
drop-in `10-paths.conf` so that the sandbox lets the agent write what `agent.yaml` allows – and a
mistake in either shows up only as `Read-only file system` after the first failed renewal. v0.3.5
removes the hand work (PLAN §10.1, owner 2026-11-08): `myownpki-agent deployment add` writes both
files in one step, an *Add host* assistant in the UI walks an admin from "new FQDN" to "certificate
deployed", Salt, Ansible, scripts and CI get a path that needs no browser on the host side, and the
docs carry recipes for Postfix, Dovecot and Proxmox VE.

Goal of v0.3.5, measured on the live installation: **(a)** a fresh VM (`minion-01.homelab.lan`) goes
from "nothing installed" to "agent enrolled, first certificate deployed and served" through the
assistant with two pasted command blocks and one approval; **(b)** the same VM, rolled
out from the Salt master with an enrollment pass in the pillar, is enrolled and has its certificate
**without anyone opening the UI for that host**; **(c)** a host with an agent of an older release keeps
working and its hand-made `/var/log/nginx` entry in `10-paths.conf` survives an update.

Where this plan differs from the text above it (the code decides – every line was read, none run):

- **API tokens cannot create join tokens.** PLAN §10.1 (rows v0.3.5 and "v1.0 contains") and §14
  "Release sequence" say the automation path uses "the existing API tokens: create join tokens, read
  agents and deployments". That is wrong. `agent.manage` is in the `stepUp` list of
  `internal/authz/authz.go`, and `Principal.Check` returns `TokenStepUpError` for a token **before** it
  looks at roles, so even a token with the admin role gets `403` on `createAgentJoinToken`,
  `approveAgentEnrollment`, `changeAgentNames`, `disableAgent` and `revokeAgent` (PLAN §14 decision on
  tokens; `api/openapi.yaml` header, `x-step-up`). §11.2 designs the automation path from that fact.
- **API tokens have roles, not scopes.** The skill's `security.md` says "scoped (tenant, actions)";
  PLAN §14 correctly says "roles ≤ the owner's" and §6.5 lists scopes as backlog. `api_tokens`
  (system.db 0008) stores `roles_json`; `auth.AuthenticateToken` builds a `Principal` from role
  bindings only. So there is no existing "narrow" permission to hand to a script, and a token with the
  admin role also holds
  `tenant.manage` – which has no step-up and can set the enrollment mode (§11.3).
- **A join token's patterns become the agent's allowed names.** `agents.initialNames`
  (`internal/agents/enroll.go`) copies every pattern of the admitting token into `agent_names` with
  source `token`. For a single-use token for one host that is the point; for a token or pass with
  `*.homelab.lan` it would give every admitted host the right to order any name below the domain. The
  pass of §11.2 therefore grants the host name only.
- **`setup` owns the drop-ins and rewrites them.** `agent.Setup` (`internal/agent/setup.go`) writes
  `10-paths.conf` as `state_dir` plus `paths` on **every** run, so the `/var/log/nginx` entry that
  OPERATIONS §12.3 tells an admin to add by hand is lost at the next `setup` run (the *Update agent*
  commands run `setup`). It also **removes** `20-low-ports.conf` whenever `--low-ports` is not given
  and enrollment is not standalone (`needLowPort`), although OPERATIONS §12.3 says nginx hooks need it
  in webroot mode. And `needLowPort` ignores the `challenge` of deployments. PHASE3 §6.6 says "the
  install script adds nginx's log directory"; `setup` does not. Step 30 pins this with failing tests
  first and fixes it.
- **A fresh `agent.yaml` cannot hold a deployment.** `renderSetupConfig` writes no `acme_directory`,
  and `Config.Validate` requires one as soon as there is a deployment. Today the admin adds it by hand.
- **The UI ships no htmx script.** `web/web.go` embeds only `styles/*.css`; CSP is `script-src 'self'`
  with no script. The `hx-get`/`hx-trigger="every 3s"` attributes in `pages/admin/generic.templ`
  (`DetailData.RefreshURL`, used by the agent page) are inert. PHASE3 §9.1 step 24 already says "htmx is
  not shipped yet". The assistant therefore uses plain forms and a `<meta http-equiv="refresh">`.
- **`agent.yaml` is written 0644, not 0600** (PHASE3 §1.3 says 0600): `renderSetupConfig` writes no
  secret, the token file is the secret. Unchanged; noted so nobody "fixes" it by accident.
- **Migration numbers.** `pki.db` is at 0017 here; v0.3.4 (§10) reserves 0018 for `endpoints`. This
  release needs 0019, `internal/store/schema/pki/0019_enrollment_pass.sql`.
- **`site/` is not in this branch.** It arrived with PR #28 on `main`, after `release/v0.3.4` forked.
  Step 33 starts by merging `origin/main` into `release/v0.3.5`.
- **Unmerged fix.** `fix/agent-absolute-path` (`3b755ba`) makes every generated command call
  `/usr/local/bin/myownpki-agent` (root's `PATH` often lacks `/usr/local/bin`). Step 32 builds on it; it
  must be merged first, or the assistant generates the bare name the fix removes.

### 11.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 30 | 0.3.5 | **`myownpki-agent deployment add`, `list`, `remove` and `sandbox sync`**, in three commits. (a) *One model of the sandbox.* `agent.Config` gains the optional block `sandbox: {write: [dirs], low_ports: bool}` (§11.2); `RenderDropins(cfg, existing)` in `internal/agent` derives `10-paths.conf` (`state_dir`, `paths`, `sandbox.write`) and decides `20-low-ports.conf`; `Setup` calls it instead of its own string. The three bugs of the list above are pinned by failing tests first: a manual `/var/log/nginx` entry survives, `20-low-ports.conf` survives, a standalone *deployment* makes the capability needed. `setup` gets `--acme-directory URL` (written into a new `agent.yaml`). `sandbox sync [--dry-run] [--adopt\|--prune]` recomputes both drop-ins from `agent.yaml` (what a Salt run calls after it rendered the file). (b) *The editor and the commands.* `internal/agent/edit.go` changes `agent.yaml` through the `yaml.Node` API of the existing `go.yaml.in/yaml/v3` (no new dependency): comments and key order stay, `deployments: []` becomes a block, new hooks and `paths` entries are appended; the result is parsed with `ParseConfig` (the same `Validate` as `run` and `config check`) **before** anything is written. `deployment add NAME` takes the flags of §11.2; it writes the drop-ins first and `agent.yaml` second (a crash in between leaves a wider sandbox, never a missing one), restores the drop-in bytes when the second write fails, keeps the previous file as `agent.yaml.bak`, runs `systemctl daemon-reload` when a drop-in changed and prints the one restart command (or does it with `--restart`). `--dry-run` prints a unified diff of all three files and writes nothing. `list` prints name, profile, names, targets, hooks and check; `remove NAME` removes the deployment and recomputes the drop-ins (it keeps `paths` unless `--prune-paths`, and never touches deployed files or state). (c) *Recipes.* `internal/recipe` (data only, no imports, so the server can use it without linking lego) holds nginx, Postfix, Dovecot and Proxmox VE (§11.2); `deployment add --recipe NAME` fills defaults, explicit flags win, `--dry-run` shows the expansion and prints "example recipe, test on a non-production host" for the three non-nginx ones. *Built:* three commits as planned. (a) `internal/agent/dropin.go`: `RenderDropins` **merges** instead of rewriting: an entry found in `10-paths.conf` that `agent.yaml` does not explain is kept and reported (`Kept in 10-paths.conf …`), missing entries are appended to the last `ReadWritePaths=` line, nothing is removed except by `--prune` or by the paths `deployment remove --prune-paths` has just taken out of `agent.yaml`; a file that already holds everything is not rewritten (byte for byte, comments and other directives included); `20-low-ports.conf` is written for `sandbox.low_ports: true`, any standalone challenge (enrollment **or** deployment) or `--low-ports`, removed only by an explicit `false`, otherwise left as found – a file that differs from the packaged one is **not overwritten** (a note says so); a path with white space, quotes or `%` is refused before anything is written (systemd would split or expand it); `setup --acme-directory`, and `config check` prints the effective sandbox, whether the drop-ins match and warnings for system directories. The three bugs have failing tests that were written first (`setup_sandbox_test.go`). (b) `edit.go` (the `yaml.Node` editor), `deployment.go`, `diff.go`, `paths_policy.go`, `cmd/myownpki-agent/deployment.go`. (c) `internal/recipe` and `--recipe`. **Deviations and choices:** `sandbox sync --adopt|--prune` and `list` come with (b); `--sandbox-write` and `--low-ports` are recorded in the `sandbox:` block of `agent.yaml` so that `setup` and `sandbox sync` keep them; `deployment remove` writes `agent.yaml` first and the drop-ins second (the opposite of `add`: a crash must never leave a deployment without its sandbox); blank lines: yaml.v3 drops them, the ones between top-level blocks are put back, the ones inside a block are not; new scalars follow the quoting of the file (plain names and profiles when `hostname:` is plain, paths and command lines always quoted); a directory that becomes writable may not have a symbolic link on its way (the loader's own check follows links, ReadWritePaths would too); a recipe hook is defined only when the deployment refers to it; sandbox directories of a recipe are added to those of the operator; all commands except `list` need root, also with `--dry-run`; `sandbox sync` has no `--restart`. **Not built here:** the Linux CI extension (agent end-to-end job running `deployment add --recipe nginx`, `systemd-analyze verify`, restart under real systemd) and `go test -race` (no C compiler on the development machine); the recipes remain unverified examples until step 33 | Table tests with a temp root and a fake `systemctl` (the `setupSystemd` seam of `setup.go`); **golden files** for the YAML round trip (comments, flow lists, an empty `deployments: []`, hooks and `paths` already present, a file with anchors/aliases/merge keys or two documents is refused with "edit it by hand"); `Validate` problems are reported before a byte is written; a second `add` of the same name is refused; `--dry-run` writes nothing (file tree compared before and after); failure injection on the second write restores the drop-in; every recipe passes `deployment add --recipe X --dry-run` followed by `config check` in a temp root; paths refused: `/`, `/etc`, `/usr`, `/var`, `/root`, `/home`, `..`, relative, a symlink out of the root; non-root run changes nothing; **setup regression**: a pre-v0.3.5 host whose `10-paths.conf` has `/var/log/nginx` and whose `20-low-ports.conf` exists keeps both through `setup`, `sandbox sync` and `deployment add`; `go test -race`; Linux CI: the agent end-to-end job runs `deployment add --recipe nginx` on the real nginx container, `systemd-analyze verify`, restarts the unit under real systemd and sees the certificate served |
| 31 | 0.3.5 | **The automation path: the enrollment pass** (§11.2 decides it), in four commits. (a) *Schema and service.* `pki.db` migration 0019 adds `kind`, `max_uses`, `use_count`, `revoked_at`, `revoked_by` to `join_tokens` (additive; existing rows become `kind = 'token'`, `max_uses = 1`, `use_count` 1 where `used_at` is set). `agents.CreateJoinToken` takes a kind; one conditional `UPDATE` consumes a use atomically (`UseJoinToken` in `queries/pki/agents.sql`); `checkToken`, `admits` and `initialNames` in `enroll.go` follow the pass rules; `DeleteJoinToken` deletes only `use_count = 0`; new `RevokeJoinToken`. sqlc regenerates `pkidb`. (b) *REST, spec first.* `createAgentJoinToken` accepts `kind`, `max_uses`; `listAgentJoinTokens` and the schemas gain the new fields; new `revokeAgentJoinToken` (`POST /agent-join-tokens/{joinTokenId}/revoke`, admin, `x-step-up`); `hostname` filter on `listAgents` and `listAgentEnrollments`; **install facts** `getAgentInstall` (`GET /agent-install`, viewer): server URL, ACME directory, root SHA-256 and URL, and the manifest of package files with SHA-256, built by the code that builds the guided commands today (`agentTLSTrust`, `agentdist`) moved into a shared function. (c) *UI.* *Agents → Join tokens* gets the pass form (label, names, uses, hours), a state column (`active 3 of 10`, `used up`, `expired`, `revoked`), a *Revoke* button, and per pass the list of hosts it admitted; the step-up summary in `app_stepup_summaries.go`. (d) *Pinning tests of the contract:* an API token with the admin role gets `403` on creating a pass. *Built:* the pinning tests first (`internal/httpapi/agent_pass_test.go`: a token of every role gets `403` on creating, withdrawing and revoking a token or pass and on deciding an enrollment; a session without a fresh second factor gets `step-up-required`), then (a) `0019_enrollment_pass.sql` and `internal/agents`: `CreateToken(NewToken)` with `CreateEnrollmentPass` and the unchanged `CreateJoinToken` as wrappers, `UseJoinToken` as one conditional `UPDATE … RETURNING use_count, max_uses` inside the transaction of the enrollment and its audit entry, `RevokeJoinToken`, `ListJoinTokens` with the hosts of each pass, the rules in `checkToken`/`admits`/`admitBy`/`initialNames`, audit action `agent.token.revoke`; (b) REST as specified plus `agents.TLSTrust` (moved out of the web package) and `agents.InstallSource`/`Service.InstallFacts` behind `getAgentInstall`; (c) the *Enrollment passes* section on *Join tokens* with the routes `POST /agents/tokens/pass` and `POST /agents/tokens/revoke`; (d) an end-to-end test with the real agent (`TestEnrollmentPassEndToEnd`, `internal/server`). **Deviations and choices:** `CreateJoinToken` keeps its signature (many call sites); the kind goes in through `CreateToken`. A pass is also refused for a host whose agent is *disabled* (the plan says active): somebody switched it off on purpose, and a pass must not bring the host back under a new identity; a revoked agent does not count. The same check runs again inside the transaction that creates the agent, so two enrollments for one new name cannot both be admitted (the second is queued with the reason, its use stays spent). The audit has no extra actions for use, exhaustion or a late attempt: `agent.enroll` carries `token_id`, `token_kind`, `use` (“3 of 10”) and `token_problem`, as the plan's audit row says. The refusal reasons are told to whoever holds the secret, as the single-use token does today (an unknown secret only says “unknown join token”). `revokeAgentJoinToken` answers `200` with the token and `409` for one that cannot admit anybody any more. `valid_hours` above 168 and `max_uses` outside 2–25 are `400` (schema); a pattern no domain covers, a missing label or more than five names are `422`. `getAgentInstall` is served by the agent service (`Service.Install`, set by the server next to the checker) and hashes the package files at most once a minute. The end-to-end test calls `Agent.Enroll(token)` instead of `agent.Setup` (the token-file handling has its own tests in `internal/agent`). `stepUpActions` lost its `RenewAgent` entry. **Not built here:** `go test -race` (no C compiler on the development machine) | Fake-clock and `-race` tests in `internal/agents` with real SQLite: 20 concurrent enrollments on a pass of 5 uses give exactly 5 valid and 15 "no uses left", none lost on a restart in between; expiry to the second; revoke ends use at once; pattern match exact and wildcard (one label or more below the suffix, never the bare suffix); a host with an active agent is refused by a pass (goes to the queue naming why); a pass admits only after a passed check in every mode (`auto`, `verified`), never in `manual`; the admitted agent has `agent_names` = its host name only; a single-use token behaves exactly as before (existing tests unchanged); the audit entry of an enrollment names the pass and the use number, never the secret (grep over the whole audit and log output); `createAgentJoinToken` via a token with the admin role is `403`, via a session without a fresh second factor is `step-up-required`, via a session with one is `201`; viewer token lists passes (no secret) and reads agents and enrollments; contract test (every spec operation has a route and the reverse); `task lint:api`; migration test from the 0018 database; **an end-to-end test**: pass created, two `agent.Setup` runs with `--token-file` in temp roots admitted with the fake checker, third refused, pass revoked, fourth refused |
| 32 | 0.3.5 | **The *Add host* assistant.** *Agents → Install agent* becomes *Add host* (same route `/agents/install`, the button on the agent list is renamed) with four steps shown by the existing `.steps` component. (1) *Form:* host FQDN, architecture, package format, enrollment http-01 mode and webroot (as today), **service** (`nginx`, `postfix`, `dovecot`, `proxmox`, or "agent only"), certificate names (the host name by default), admission (one-use token or "none: I approve it in the UI"). (2) *Commands, shown once* (the POST result, as today): the independent values, the token file, install + `setup` (with `--acme-directory`), then `deployment add --recipe …` with the names, then the restart. (3) *Progress page* `GET /agents/add/{hostname}`: whether an enrollment is waiting (host, source address, check result, token valid; *Approve* and *Refuse* for an admin), the agent once admitted (status, last seen, version), each deployment with state, serial, expiry and last error; refreshes every 5 seconds through `<meta http-equiv="refresh">` on the passive route `/agents/add/{hostname}/status` (new `view.Page.Refresh`, `layout/app.templ`); the first view counts as activity, the refreshes do not. (4) *Done:* the certificate is deployed. Step-up is the existing machinery: `a.protected` routes with allowlisted fields and entries in `actionSummary` (`app_stepup_summaries.go`) *Built:* the assistant is a new set of pages under `/hosts/add` plus the entry *Add host* in the *Agents* group of the navigation (hidden when agents are off or the role cannot read them) and an *Add host* command on the agent list. *Install agent* (`/agents/install`) is **unchanged**: the plan above says to turn it into the assistant under the same route and a progress page at `/agents/add/{hostname}`, but `GET /agents/add/{host}` collides with `GET /agents/{id}/update` and `GET /agents/{id}/deployments` in the mux (neither pattern is more specific, registration panics), so the routes are `GET /hosts/add` (step 1), `POST /hosts/add` (step 2, no side effect, answers with the page like the certificate wizard), `POST /hosts/add/commands` (`a.protected`, fields `hostname service challenge webroot names format arch admission`), `GET /hosts/add/{host}` (progress, active route) and `GET /hosts/add/{host}/status` (the same page on a passive route, so the reloads do not keep the session alive), and `POST /hosts/add/{host}/approve|deny` (`a.protected`, field `id`, back to the progress page); step 33 decides whether *Install agent* goes. Step 1 asks host name, service (nginx, Postfix, Dovecot, Proxmox VE, *certificate files only*), challenge (standalone or webroot, with the port-80 explanation), webroot, more certificate names (up to four, default none) and the agent package (deb, rpm, tarball or already installed). Step 2 shows the domain check in words for every name (no domain, or a domain without http-01, is refused), the tenant's enrollment mode, and a table of the ways to be admitted with the approval each needs; the choice (a select) is *single-use token* (admins only, 15 minutes, names = host plus extras, second factor), *an existing enrollment pass* that covers the host (shown by label and uses, never its secret: the commands ask for it on the host with `read -s`; not offered for extra names or a host that has an agent) or *no secret* (one approval). The commands page is the answer to `POST /hosts/add/commands`, `no-store`: the token file block, the verified root plus optional package lines plus `setup` (the block of `joinTokenHostSection`, now built by `hostSetupCommands`, byte-identical for the existing pages; `--webroot` is added for the webroot challenge), the `deployment add` block, and `/usr/local/bin/myownpki-agent deployment list`. The progress page walks *Host enrolled* (nothing yet, checking, waiting for your approval with the facts and the Approve and Refuse buttons for `agent.manage`, refused, expired, admitted), *Agent online* (first report, online with last seen, silent, disabled) and one row per deployment (`pending`, `deployed` with serial, expiry and a link, `failed`, `rolled back` with the agent's last error clipped to 300 characters and escaped), and reloads every **10 seconds** (not 5) through `view.Page.RefreshSeconds/RefreshURL` and a `<meta http-equiv="refresh">` in the shell until the agent is online and every deployment is deployed. `admin.DetailData` and `admin.FormData` gained `Steps`. **Shared code and checks:** `internal/agentpath` (standard library only) holds the system-directory list and `agent` delegates to it, so the server refuses the same directories without linking the agent; `agent.ParseDeploymentAdd` is the one place that defines the flags of `deployment add` (the command calls it); `agent.DryRunDeploymentAdd(cmd, DryRunHost)` runs a parsed command through `AddDeployment` as a dry run without root, with absolute paths mapped below a temporary root (a `..` stays visible; the system-root rule works on the path text and is therefore covered by `internal/agentpath`'s own test). The central test runs **every generated line** (each service, both challenges, with and without extra names, and every hostile form value that survives validation) under bash with a mock agent, reads the arguments with `ParseDeploymentAdd` into what the plan says, and dry-runs them on a host set up for the plan. **Choices where the plan was silent:** the cautious variant for viewers and operators: they see all pages, but token and pass creation is not offered and the POST answers `403`; `install -d -m 0755` for the parent of the certificate directory instead of `--create-dirs` (which would also create a mistyped webroot); `--restart` on the line, and `systemctl enable myownpki-agent` named in the text for a host that stayed pending (setup leaves the unit disabled); extra names only with the token (a pass or no secret grants the host name only); `--acme-directory` on the line, not on `setup`; no `style`, script or htmx anywhere. **Not built here:** screenshots (milestone only), a run on the Linux CI, `go test -race`. | Handler tests: only `agent.manage` reaches the form and the POST, viewers and operators get 403, the progress page needs the tenant-wide `pki.read` and shows no button without `agent.manage`; **the token appears exactly once** (the POST response, `Cache-Control: no-store`), never in a URL, a redirect, the progress page, a log line or an action summary; hostile input (`$(reboot)`, quotes, newlines, `<script>` in the host, names, webroot) is refused by validation or `shellQuote`d, and a pending enrollment with a hostile hostname renders as text; every generated `deployment add` line is executed against `agent.AddDeployment` with `--dry-run` in a temp root (the recipe table cannot drift from the CLI); the approve button works through the step-up continuation of v0.3.1 exactly once; the progress page walks through "nothing yet", "waiting", "admitted", "deployment failed" and "deployed" with the fake clock; the refresh meta is present only on the progress pages; no inline style, no undefined CSS class (the UI tests); screenshots of step 1 and 3, light and dark, with `task screenshots` at the milestone only |
| 33 | 0.3.5 | **Docs, recipes and release.** (a) Merge `origin/main` (brings `site/`) and `fix/agent-absolute-path`. (b) OPERATIONS: §12.2 (join token text: tokens, pass, who may create what), §12.3 (the sandbox paragraphs now describe `deployment add`, `sandbox sync` and the `sandbox:` block; hand-editing the drop-in becomes the exception), new §12.7 *Adding a host* (assistant, `deployment add`, the pass, a Salt or CI roll-out, what to do when a pass leaks), new §12.8 pointing to the recipes, an upgrade paragraph in §9 ("From v0.3.4 to v0.3.5: `pki.db` migration 0019, additive; agents need no update; a v0.3.5 agent is needed for `deployment add`"). (c) The public site: `site/hosts.md` (guided installation becomes *Add host*, `agent.yaml` and sandbox sections use `deployment add`), **new `site/hosts/recipes.md`** (nginx, Postfix, Dovecot, Proxmox VE: the exact commands of §11.2, marked as examples) with a child entry in `site/_data/nav.yml`, `site/hosts/salt.md` (the section "The limit of v0.3.3" is replaced by the pass; the hand-written `10-paths.conf` state is replaced by `sandbox sync`), `site/cli.md`, `site/api.md`, `site/security.md` and `site/best-practices.md` (automation tokens are viewer tokens; why a pass and not a token), `site/troubleshooting.md`, `site/upgrade.md`; prose that names a version (`grep -n "0\.3\." site`). (d) CHANGELOG 0.3.5; version bump to 0.3.5 in the files of commit `6a8016d` ("docs: prepare v0.3.3 release": `CHANGELOG.md`, `README.md`, `deploy/docker-compose.yml`, `deploy/install-agent.sh`, `deploy/install.sh`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`) plus the `v=0.3.x` and `_0.3.x_` examples in `docs/OPERATIONS.md` (§2.1 and §12.2; `site/` reads the version from `CHANGELOG.md` through `scripts/ci/site-prepare.sh`); PLAN §10.1 and this file marked as built. (e) The live test below *Built:* five commits on `release/v0.3.5`, **not released** (the owner decides about merge and tag; the live test below is pending, so the changelog says so). (a) `origin/main` merged first (v0.3.4, the enrollment-mode fix of PR #32, `fix/agent-absolute-path`). (b) OPERATIONS: §12.7 *Adding a host* (the assistant, `deployment add|list|remove`, `sandbox sync`, what existing hosts see), §12.8 *Enrollment passes* and §12.9 *Recipes* are new instead of one §12.7 and a pointer; §12.2 names *Add host* and the three enrollment modes (the second factor for changing the mode is said there and in §4), §12.3 describes the sandbox model, §12.5 points at `sandbox sync`, §9 has "From v0.3.4 to v0.3.5". (c) The site: `site/hosts.md` (assistant, pass, `deployment add`, `setup --acme-directory`, the sandbox section rewritten), `site/hosts/salt.md` (the section "The limit of v0.3.4" is replaced by the pass, the state file uses `--token-file` and `sandbox sync`, still "an example to adapt" and the formula still v0.3.6), **`site/recipes.md`** with a top-level navigation entry (the plan said `site/hosts/recipes.md` as a child of *Adding hosts*; a page of its own is easier to find and to link from the assistant), `troubleshooting.md`, `upgrade.md`, `best-practices.md`, `cli.md`, `api.md`, `security.md`, `index.md`. (d) CHANGELOG 0.3.5 **without a date** and with the compare links, as `4f5f7fc` had them; the Security entry of PR #32 moved from Unreleased into it; the version bump in the files of `5b43551` (README, compose, both install scripts, RELEASING, the agent installer test, the version examples of OPERATIONS, `api/openapi.yaml`); `site/` takes the version from the dated changelog sections, so it shows 0.3.4 until the dating commit. PLAN and CLAUDE.md still say "in progress". **Docs against code:** the pass forms and the API take whole hours, 1 to 168, so the service floor of 5 minutes cannot be asked for; *Withdraw* on the Join tokens page lists tokens only, a pass nobody used is withdrawn through the API (`DELETE`); the progress page reloads every 10 seconds, not the 5 of the first draft; the assistant lives under `/hosts/add`, not `/agents/add`; viewers and operators get the commands for *no secret* or a pass (no second factor is asked for those, nothing secret is created); the nginx recipe's directory is `/etc/ssl/myownpki/<deployment name>`. **Not done and not verifiable here:** none of the commands was run in a throw-away container or VM, so the recipes stay unverified examples (the pages say so, with what to verify); the Salt sketch was not run against Salt; Jekyll was not built, only `site-check.sh`; `go test -race` and the Linux CI jobs (agent end-to-end, image, install) did not run on this machine. | `task check`, `task ci:local` (every SKIP line reported), `scripts/ci/site-check.sh` (nav, links), Linux CI incl. the agent end-to-end and image jobs, the live test below; every command in the recipes is run once in a throw-away container or VM and the result (worked, needed a change) is written into the recipe page |

**Live test for the owner** (names are examples; use a test host for the service steps):

1. Update the server to v0.3.5 (`myownpki db status`: `pki.db` at 0019). An agent of v0.3.4 keeps
   reporting; nothing changes on it.
2. Update one agent with *Agents → Update*. On a host whose `10-paths.conf` has `/var/log/nginx` and
   whose `20-low-ports.conf` exists, both survive: `cat /etc/systemd/system/myownpki-agent.service.d/10-paths.conf`.
3. On that host: `myownpki-agent deployment add test --recipe nginx --name proxy.homelab.lan --dry-run`
   shows the diff of `agent.yaml` and both drop-ins; run it without `--dry-run`, then
   `systemctl restart myownpki-agent`. The agent page shows the deployment and a deployed certificate;
   `myownpki-agent config check` is valid. `myownpki-agent deployment remove test` undoes it.
4. **Assistant:** *Agents → Add host* for a fresh VM (`minion-01.homelab.lan`), service nginx, token.
   Paste the two blocks as root on the VM; the progress page shows the agent, then the certificate
   (compare the serial with `openssl s_client -connect minion-01.homelab.lan:443`). Repeat without a
   token: the progress page shows the waiting enrollment, one click and the second factor admit it.
5. **Pass:** *Join tokens → New enrollment pass*: `*.homelab.lan`, 3 uses, 1 hour. With a *viewer* API
   token `POST /api/v1/agent-join-tokens` answers `403`. Put the pass in a file on two minions and run
   `setup --token-file` from the Salt master (`salt -t 180 … cmd.run`): both are admitted without a
   click (mode `verified`). A third minion outside the pattern waits in the queue; a fourth minion after
   the pass is used up is told "no uses left". The pass page lists the two hosts. Revoke the pass; the
   audit log shows create, three uses and revoke, never the secret.
6. **Recipes:** run the Postfix, Dovecot and Proxmox recipes on test hosts and write down every
   difference from the page (a different path, a missing group, a hook that needs another directory in
   `sandbox.write`).
7. **Negative:** `deployment add` with `--dir /etc`, a name twice, a hook with a relative path and
   without root: each is refused with the message of §11.2 and `agent.yaml` is unchanged
   (`diff agent.yaml agent.yaml.bak`).

### 11.2 Rules and defaults

**Decisions** (the owner is asleep: the cautious variant; `(owner may change)` marks real choices):

| Question | Default | Why |
|---|---|---|
| How does automation get hosts admitted | **Two paths.** Baseline **A**: enrollment without a token plus one approval per host (works today, needs no secret in Salt). Automation path **B**: an admin creates a bounded **enrollment pass** with the second factor; Salt, Ansible, scripts and CI only consume it. `(owner may change)` | See the options table below. A needs a person per host, B a person per roll-out |
| Narrower API-token permission (**C**) | **Rejected** | See the options table |
| Is the pass a new object | **No: a kind of join token** (`kind = 'pass'`), same table, same hash lookup, same `Enroll` field. No change to the agent, the protocol or `agent.proto` | Five columns and one `UPDATE` instead of a second table with the same lookup, expiry, audit and list. The differences are four rules in `enroll.go`, written down below |
| Pass limits | label required; 1–5 name patterns (exact or `*.suffix`, at least two labels below the TLD as `CheckPattern` enforces); **2–25 uses, default 10**; validity **5 minutes to 7 days, default 24 hours**; constants in `internal/agents`, no configuration key. `(owner may change)` | A roll-out needs a few hours; 7 days is the longest a forgotten pass can live. A larger fleet takes two passes |
| Every pattern must be covered by a domain | Yes: creation is refused (`422`, naming the pattern) when `ca.Engine.DomainFor` finds no domain for the exact name, or for `x.<suffix>` of a wildcard. `(owner may change)` | The enrollment check needs a domain (`agents.check`); a pass for names no domain covers could never admit anyone |
| What a pass grants the host | **The host name only** (source `hostname`). The patterns decide who may enroll, not what the host may order | Otherwise one leaked pass for `*.homelab.lan` would give N hosts the right to order everything below the domain (`initialNames`). Extra names: the single-use token of the assistant (its names become `agent_names`) or an admin on the agent page. `(owner may change)` |
| Does a pass replace the proof of control | **No.** A pass admits only together with a **passed http-01 check, in every mode** (in `auto` a passed check admits anyway; in `manual` everything waits for an admin) | `admits` lets a plain token admit in `auto`. A pass is multi-use and lives in a pillar; it must not be enough on its own |
| A pass for a host that already has an active agent | **Refused** (the enrollment waits in the queue, the reason is in `token_problem`): "an agent for this host exists – a pass admits new hosts only; ask an admin for a single-use token" | `agents_hostname` is a plain index (`0011_agents.sql`), so nothing else stops a second identity for the same name. Replacing a host stays a human act. `(owner may change)` |
| What counts as a use | One enrollment that presented a valid pass, including one that then waits in the queue (as a join token today). A host that enrolls again uses another one | Simple, atomic, auditable |
| Secret | `mjp_` plus 256 random bits (`mjt_` stays for tokens), shown once in the create response, only the SHA-256 is stored | A scanner and a person can tell a pass from a token; `Enroll` does not check the prefix |
| Who creates and revokes | tenant **admin with a fresh second factor** (`agent.manage`, unchanged). **No new permission, no change in `authz`**: a token still never satisfies it | This is the design: a person with the second factor admits a new kind of actor, the automation uses what it was handed |
| Who reads | `pki.read` (viewer and up, tokens included): kind, patterns, uses, state, hosts admitted. Never the secret | As the join token list today |
| Revoke | Ends use at once. It does **not** touch enrollments or agents the pass already produced: the pass page lists them with their state so an admin can refuse or disable them. A pass with `use_count = 0` can also be deleted; a used one stays as a record. `(owner may change)` | Revoking must be safe to do in a hurry; disabling hosts is a separate, visible decision |
| Audit | `agent.token.create` (kind, max uses, patterns, expiry), `agent.token.revoke` (new action), and the existing `agent.enroll` entry of every enrollment gains `token_id`, `token_kind` and `use` ("3 of 10"), with the source address it already has. Refusals name the reason (`expired`, `no uses left`, `revoked`, `not for this host`, `active agent exists`). The secret is in no entry and no log line | "Every use audited and counted" |
| API for status | A **viewer** API token reads `GET /agents?hostname=…`, `GET /agent-enrollments?hostname=…`, `GET /agent-join-tokens`, `GET /agent-install`. The docs say: give automation a viewer token and nothing more. `(owner may change)` | A token with the admin role also holds `tenant.manage` (§11.3) |
| The assistant | Admin only (`agent.manage`), as today's install page; the progress page for `pki.read`, its buttons for `agent.manage` with step-up; no state is stored for it | The page that shows a token must be as strict as the page that creates one |
| `deployment add` and the sandbox | Explicit flags; a recipe is a convenience that `--dry-run` expands. Existing `10-paths.conf` entries that `agent.yaml` does not explain are **kept** and reported (`sandbox sync --adopt` writes them into `sandbox.write`, `--prune` drops them). Missing directories are an error unless `--create-dirs`. Daemon reload is automatic, **restart is not** (`--restart`). `agent.yaml.bak` keeps the previous file. `(owner may change)` | Nothing the operator wrote is lost silently, nothing is widened silently, a running agent is not restarted by surprise |
| One owner of `agent.yaml` | Either the admin and `deployment add`, or Salt rendering the whole file and then `sandbox sync`. Never both | A rendered file overwrites what `add` wrote |

**The options for the automation path** (the question of the owner, with what the code shows):

| | What | Verdict and trade-off |
|---|---|---|
| **A** | No secret: `setup` without a token, the host proves its name by http-01 and lands in *Enrollment requests*; an admin approves it once (`approveAgentEnrollment`, step-up). Works today in the default mode `verified` (`admits`: no token and a passed check is not enough). The assistant's progress page makes the approval one click | **Baseline.** Nothing secret in Salt and nothing to leak, but a person per host. Right for a handful of hosts and for replacing a host. Tenant mode `auto` removes the person (a passed check alone admits), at the price that anyone who can answer port 80 for a name below a domain is admitted – documented, not recommended |
| **B** | **Enrollment pass** (above). The admin creates it once with the second factor; Salt holds it for the roll-out | **Automation path.** A leaked pass admits at most N more hosts, only for names matching the pattern, only if the server can fetch the check file from that name (an attacker needs DNS or port 80 for it), never replaces an existing agent, grants the host name only, and dies in at most 7 days or on revoke. Still an actor admitted without a person looking at it – that is the trade-off, bounded by N, the pattern and the lifetime |
| B′ | A batch of single-use tokens, one exact host name each, created by an admin in one step | Tighter (each secret names its host) and needs no migration, but the host list must be known when the admin has the second factor at hand, which does not fit "a CI job creates a VM". Can be added later as a UI form on top of the existing tokens |
| **C** | A narrower API-token permission that creates join tokens without step-up | **Rejected.** The code shows nothing that bounds it: `createJoinToken` takes 1–20 arbitrary patterns and up to 30 days, checks no domain, and the patterns become `agent_names`. A token with that right on a Salt master would let a compromised master mint actors with names of its choice. Tokens have roles, not scopes (list above), so it would also be a new permission model |

**The pass in a roll-out** (what the docs show):

1. *Join tokens → New enrollment pass*: label `salt rollout 2026-11`, names `*.homelab.lan`, 10 uses,
   24 hours. Copy the secret.
2. Put it in the encrypted pillar. The state writes `/root/myownpki-join-token` (mode 0600) only
   `unless` `/var/lib/myownpki-agent/agent.crt` exists, and runs
   `myownpki-agent setup … --token-file /root/myownpki-join-token` (`setup` deletes the file when it
   newly obtains admission; a pending host keeps it).
3. Salt then renders `agent.yaml` (or runs `deployment add`) and `sandbox sync`.
4. Check with a viewer token: `GET /api/v1/agents?hostname=minion-01.homelab.lan`.
5. Afterwards remove the pass from the pillar. If it ever leaked: revoke it (admin, second factor),
   read the list of hosts it admitted, disable or revoke any you do not know.

**What changes where** (the checklist for review):

| Area | Change |
|---|---|
| `internal/authz` | **Nothing new.** `ManageAgents` stays in `stepUp`; a test pins that a token cannot create or revoke a pass. Housekeeping: `stepUpActions` has an entry for `RenewAgent`, which is not a step-up permission; remove it |
| Schema | `pki.db` 0019 `0019_enrollment_pass.sql`: `ALTER TABLE join_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'token' CHECK (kind IN ('token', 'pass'))`, `max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 25)`, `use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0)`, `revoked_at TEXT`, `revoked_by TEXT`; then `UPDATE join_tokens SET use_count = 1 WHERE used_at IS NOT NULL`. `used_at` and `used_by` stay as they are and are set when the **last** use is taken, so the existing `CHECK ((used_at IS NULL) = (used_by IS NULL))` and every reader of a single-use token keep working. No other database. ASCII only |
| `internal/agents` | `CreateJoinToken(kind, maxUses)`, `RevokeJoinToken`, the rules in `checkToken`/`admits`/`initialNames`, `UseJoinToken` as one conditional update (`use_count < max_uses AND revoked_at IS NULL AND expires_at > ?`) |
| OpenAPI | Additive, `x-required-role` and `x-step-up` as listed in step 31; secret pattern `^mj[tp]_[A-Za-z0-9_-]{43}$`; new problems `422` for a pattern no domain covers |
| Audit actions | new `agent.token.revoke`; `agent.token.create` and `agent.enroll` carry more detail; nothing else |
| UI | Join tokens page (pass form, state, revoke, hosts); *Add host* (steps and progress page); `view.Page.Refresh`; no new navigation entry (v0.3.4 adds *Endpoints*; this release adds none) |
| Agent | `deployment`, `sandbox sync`, `setup --acme-directory`, the `sandbox:` key. **No protocol change.** An older agent binary refuses an `agent.yaml` with `sandbox:` (`KnownFields`), which matters only when someone downgrades; the OPERATIONS upgrade paragraph says so |
| Alerts, config, permissions elsewhere | none |

**`myownpki-agent deployment add NAME`** (Linux, root, systemd; `list` also runs elsewhere):

| Flag | Meaning |
|---|---|
| `--recipe nginx\|postfix\|dovecot\|proxmox` | defaults from `internal/recipe`; every other flag overrides |
| `--profile nginx\|file` | as in `agent.yaml` |
| `--name FQDN` (repeat) | certificate names, validated like `names:`; the first one is the SNI of the local check |
| `--challenge webroot\|standalone`, `--webroot DIR` | default: what `enrollment:` uses |
| `--dir DIR` (nginx profile) | `fullchain.pem` and `privkey.pem` go here |
| `--certificate`, `--chain`, `--fullchain`, `--key` FILE (file profile) | as `files:` |
| `--owner`, `--group`, `--key-mode` | as in `agent.yaml`; the key mode may not give rights to others |
| `--hook NAME='CMD ARGS'` (repeat), `--test-hook NAME`, `--reload-hook NAME` | defines hooks (split on spaces and quotes, **no shell**, first element absolute) and references them; an identical command line that already exists is reused under its name, so deployments of one service share one reload and one rollback group |
| `--check HOST:PORT` | local TLS check; it is an **implicit-TLS** handshake (`checkServed` uses `tls.Dialer`), so STARTTLS ports (25, 143, 587) cannot be checked |
| `--sandbox-write DIR` (repeat), `--low-ports` | extra directories hooks may write; `CAP_NET_BIND_SERVICE` |
| `--acme-directory URL` | required when `agent.yaml` has none |
| `--create-dirs`, `--dry-run`, `--restart`, `--config FILE` | as described in the decisions table |

What it validates **before writing**: root; `agent.yaml` parses and is valid now; the name is new;
everything `Config.Validate` checks (names are FQDNs, targets lie under `paths`, distinct, outside
`state_dir` and `ca_bundle`, hooks exist, the key mode); every directory it adds to `paths` is the
**parent** of a target (for the nginx profile the parent of `dir`, which the agent creates) or a
webroot, exists (or `--create-dirs`) and is not one of the system roots `/`, `/etc`, `/usr`, `/var`,
`/boot`, `/dev`, `/proc`, `/sys`, `/run`, `/root`, `/home`, `/tmp`, `/bin`, `/sbin`, `/lib*`, `/opt`,
`/srv`, `/mnt` or below `/proc`, `/sys`, `/dev` (a wide but legitimate directory such as `/etc/nginx` is
accepted with a warning that names a narrower one). The same list becomes a **warning** of
`config check`, not an error, so no existing configuration stops working. A hook whose executable is
`nginx`, `apachectl`, `apache2ctl` or `haproxy` prints a hint when `--sandbox-write` (its log
directory) or `--low-ports` is missing, because those hooks fail without them (OPERATIONS §12.3). It
writes only `agent.yaml`, `agent.yaml.bak` and the two drop-ins in the unit's `.service.d` directory,
atomically (temp file in the same directory, `fsync`, rename, as `atomicSetupFile`).

**The `sandbox:` block** (optional, additive):

```yaml
sandbox:
  write: [/var/log/nginx]   # directories that hooks (not the agent) write; only ReadWritePaths gets them
  low_ports: true           # 20-low-ports.conf; unset: derived (standalone anywhere) or left as found
```

`10-paths.conf` is then exactly `state_dir`, `paths`, `sandbox.write` and the entries kept from the
file as found. `20-low-ports.conf` is written when `low_ports` is true or any challenge is standalone,
removed only when `low_ports: false` is set explicitly. `config check` prints the effective result and
whether the drop-ins on disk match it.

**The recipes** (`internal/recipe`; the site page carries the full text; **all are examples written
from the documentation of each service and not yet run on a live host – step 33 verifies them**):

| Recipe | Profile and files | Owner, mode | Hooks | Check | Sandbox | To verify |
|---|---|---|---|---|---|---|
| nginx | nginx, `dir` below `/etc/ssl/myownpki` | root, key 0600 | test `/usr/sbin/nginx -t`, reload `/usr/bin/systemctl reload nginx` | `127.0.0.1:443` | write `/var/log/nginx`, low ports | known from OPERATIONS §12.3 and the CI job |
| postfix | file: `/etc/ssl/myownpki/postfix/fullchain.pem`, `…/privkey.pem`; `main.cf`: `smtpd_tls_chain_files = /etc/ssl/myownpki/postfix/privkey.pem, /etc/ssl/myownpki/postfix/fullchain.pem` (Postfix 3.4 and later; older: `smtpd_tls_cert_file`, `smtpd_tls_key_file`) | root:root, key 0600 | test `/usr/sbin/postfix check`, reload `/usr/bin/systemctl reload postfix` | only with an implicit-TLS listener (`submissions` on 465 in `master.cf`); none otherwise | none expected | that `postfix check` runs inside the sandbox without writing; that no group is needed (the key is read before Postfix drops privileges) |
| dovecot | file: `/etc/ssl/myownpki/dovecot/fullchain.pem`, `…/privkey.pem`; config 2.3: `ssl_cert = </…/fullchain.pem`, `ssl_key = </…/privkey.pem`; 2.4: `ssl_server_cert_file`, `ssl_server_key_file` (no `<`) | root:root, key 0600 | test `/usr/bin/doveconf -n`, reload `/usr/bin/systemctl reload dovecot` | `127.0.0.1:993` (implicit TLS) | none expected | that a reload makes new connections use the new certificate; the exact `doveconf` option for a syntax-only test |
| proxmox | file: `/etc/ssl/myownpki/pve/fullchain.pem`, `…/privkey.pem` (the agent does **not** write into `/etc/pve`, a FUSE file system that takes neither `chown` nor `chmod`) | root:root, key 0600 | reload `/usr/bin/pvenode cert set /etc/ssl/myownpki/pve/fullchain.pem /etc/ssl/myownpki/pve/privkey.pem --force 1 --restart 1` (it validates, installs and restarts `pveproxy`; a rollback re-runs it on the restored files) | `127.0.0.1:8006` | write `/etc/pve` | the `pvenode` syntax of the installed version; that `pvenode` works under the sandbox; one agent per node |

Names: the recipe's certificate name is the host name unless `--name` says more (more names need the
token of the assistant, as above). Group memberships: none of the three needs one **as far as the
documentation says** because the daemons read their keys as root; a service that reads its key as an
unprivileged user takes `--group` and `--key-mode 0640` (for example `ssl-cert` on Debian). That is a
claim to verify on each host, and the recipe page says so.

**Error messages** (one line each, with the next step; tested):

| Case | Message |
|---|---|
| not root | `deployment add must run as root; nothing was changed` |
| invalid file | `agent.yaml is not valid yet – run "myownpki-agent config check" and fix it first; nothing was changed` |
| name exists | `deployment "proxy" exists – pick another name or run "deployment remove proxy" first` |
| too broad | `--dir /etc: too broad – the agent may write only where "paths" allows; use a subdirectory such as /etc/ssl/myownpki` |
| directory missing | `/etc/ssl/myownpki does not exist – create it, or pass --create-dirs` |
| no ACME directory | `agent.yaml has no acme_directory – pass --acme-directory https://pki.homelab.lan/acme/directory` |
| YAML features | `agent.yaml uses anchors, aliases or several documents – edit it by hand and run config check` |
| hook | `hook "nginx-test": the first element must be an absolute path` |
| no unit yet | `the unit is not installed (run setup first) – files written, systemctl skipped` |
| pass: used up | `the enrollment pass has no uses left (10 of 10) – ask an admin for a new one` |
| pass: other | `the pass expired`, `the pass was revoked`, `the pass is not for <host>`, `an agent for <host> exists – a pass admits new hosts only` |

**Test strategy.** No real hosts, no real DNS: names are `homelab.lan`, addresses `192.0.2.x`
(`minion-01.homelab.lan`, `pki.homelab.lan`). The agent commands run against a temp root with the
unit directory, `agent.yaml` and `paths` inside it and the `setupSystemd` seam replaced by a recorder,
as the `setup` tests do; the real `systemctl` appears only in the Linux CI job that already boots
systemd (`scripts/ci/agent-package-systemd.sh`, `agent-e2e-*`). The server side uses
`internal/testinstance` with the fake checker and `clock.Fake`, no `time.Sleep`, everything under
`-race`. The pass is exercised through the same `Service` the API and the UI call. The UI tests are
the existing ones (inline styles, undefined classes, hostile text). Docs are checked by
`site-check.sh` and by running each documented command once.

### 11.3 Not in v0.3.5

- **Server-assigned deployments** (the server tells the agent what to deploy inside local limits). This
  **needs an ADR change** (ADR-10: the agent takes no commands from the server; PLAN §6.2, "After
  v1.0"). Nothing here designs it: the assistant and the pass only produce commands and secrets for a
  **person or a script on the host** to run, and every path, hook and name still comes from the local,
  root-owned `agent.yaml`.
- **Windows and FreeBSD agent**, and `deployment add` on them (they only compile).
- **The Salt formula** (v0.3.6): it will call `deployment add`, `sandbox sync` and `setup --token-file`
  with the pass of this release; `site/hosts/salt.md` stays "an example to adapt" until then.
- **dns-01 in the agent** (v0.3.7), the Apache and HAProxy profiles (v0.3.11).
- **Step-up for loosening `agent_enrollment`.** `tenant.Store.Set` needs only `tenant.manage`, which
  has no step-up, so an API token with the admin role can switch the tenant to `auto` or set
  `step_up_minutes` to 60. This plan keeps automation at the viewer role, but the hole is real and
  independent of onboarding: propose it as its own `fix/enrollment-mode-step-up` (the settings form
  would become an `a.protected` route with the continuation of v0.3.1). Not built here.
- **Granting extra names through a pass**, **pass per hostname list (B′)**, **a bulk "Add hosts"
  form**, **pass usage alerts** and **a revoke that also refuses the pass's open enrollments**.
- **Automatic refresh of the agent page.** Its inert `hx-get` stays; a `Page.Refresh` for it is a
  one-line follow-up once step 32 has added the field.
- **`--recipe` for services other than the four**, and any recipe as a built-in profile (PLAN §6.2's
  list stays a roadmap).
- **No ADR changes.** The plan fits ADR-05 (spec first), ADR-06 (the pass is in `pki.db`, one
  transaction per database), ADR-10 and ADR-11 (no change to the channel or the keys), ADR-12, ADR-17,
  ADR-18 (the pass is a join token; the proof of control stays required) and ADR-19 (issuance is still
  ACME); it adds one tiny package (`internal/recipe`), no dependency and no protocol change.

## 12. Salt formula: v0.3.6

v0.3.5 gave a script the pieces it needs (`setup --token-file`, `deployment add`, `sandbox sync`, the
enrollment pass). v0.3.6 puts them into a **Salt formula** in `deploy/salt/myownpki/`, so that a
fleet is rolled out by `state.apply myownpki` instead of a hand-copied state file. The sketch in
`site/hosts/salt.md` (written in v0.3.5, never run) becomes the starting point; the formula is the
tested version of it.

Goal of v0.3.6, measured on the live installation: a minion whose pillar names the server, the root
fingerprint, the package hash and one deployment is, after `salt 'minion-01.homelab.lan' state.apply
myownpki`, enrolled (with an enrollment pass: without a click) and has its certificate; a second
`state.apply` changes nothing; a minion without a pass waits for one approval and the next highstate
finishes the job.

### 12.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 34 | 0.3.6 | **The formula.** `deploy/salt/myownpki/` with `init.sls`, `agent.sls`, `map.jinja`, `defaults.yaml`, `pillar.example` and `README.md`. States: verified package (`file.managed` with `source_hash`, then `pkg.installed` through the file, never an unverified URL), the root PEM, the pass (only while the host has no agent certificate), `setup` (`creates:` the agent certificate), the deployments (§12.2) and the sandbox. No `service.running` (a not enrolled agent stays disabled) *Built:* in one commit (`aa599b9`), as planned in states and files; the differences are in §12.4. The staged package is checked by the state `myownpki-agent-package-verified` (an explicit `sha256sum` that fails the run), because Salt ignores `source_hash` for `salt://` sources; `pkg.installed` uses `sources` with the staged file. The README of the formula carries the pillar table, the states, the rules and what is not tested. | `salt-call --local state.show_highstate` renders for the test pillars; `shellcheck` on any helper script |
| 35 | 0.3.6 | **Test and CI.** `deploy/salt/test/` (minion config with grains, pillars for Debian amd64 with a pass, RedHat arm64 without a pass, own-file mode, and the refusals of §12.2; dummy package, root and `agent.yaml` fixtures with their real hashes) and `scripts/ci/salt-test.sh`. A new CI job `salt formula` downloads the **Salt onedir tarball with a pinned SHA-256** (same pattern as cosign in `release.yml`), renders every test pillar with `state.show_highstate`, runs `state.apply test=True` and checks the expected states and absent states (§12.2). The job runs for code changes like the other heavy jobs *Built:* in two commits (`49e5476` test, `91c5972` CI). 13 cases in `deploy/salt/test/cases` (Debian amd64 with a pass, two deployments and one removal; Debian minimal; RedHat arm64 with `config_source`; Suse aarch64 with an `https://` source; nine refusals), one dummy package per format with its real SHA-256. Cases marked `mode: render` are only rendered (the runner has no `rpm`, and an `https://` source would download). The CI job `salt formula` pins Salt 3008.5 (onedir, SHA-256 in the job and in `THIRD_PARTY.md`), runs `salt-test.sh --self-test`, then `salt-test.sh` as root, and is **not** a required check. `scripts/ci/local.sh` has the two lines for `task ci:local`. | The job is green on the PR; `bash scripts/ci/salt-test.sh --self-test` runs the part that needs no Salt |
| 36 | 0.3.6 | **Docs.** `site/hosts/salt.md` is rewritten around the formula (the sketch stays as "what the formula does, step by step"); `deploy/salt/myownpki/README.md`; `site/hosts.md`, `site/upgrade.md` (updating agents with the formula), `site/troubleshooting.md` and OPERATIONS get the formula where they now say "plain Salt"; PHASE3 live-test checklist *Built:* the Salt page is rewritten around the formula (the old state-file sketch is gone, because the formula is what it described; the page lists what the formula does step by step); `site/hosts.md`, `site/upgrade.md` (the update path and a 0.3.5 to 0.3.6 row), `site/troubleshooting.md` (a Salt formula section), `site/index.md`, the README line, and OPERATIONS (new 12.10, pointers in 12.3 and 12.8, an upgrade paragraph). The README of the formula is part of step 34. `site-check.sh` passes; Jekyll was not built here, and no documented `salt` command was run against a Salt master (the commands are checked against the formula and the agent code). | `scripts/ci/site-check.sh` |
| 37 | 0.3.6 | **Release.** CHANGELOG `[0.3.6]`, version bump (`DEFAULT_VERSION` in both install scripts, `api/openapi.yaml`), PLAN §10.1 and `CLAUDE.md` after the tag | RELEASING.md |

**Live test for the owner** (names are examples; use two test minions, one for the pass and one without). Status after the run of 2026-11-12 (§12.4): the upgrade of enrolled hosts (steps 4 and 8) and `low_ports` are done on five enrolled Debian amd64 hosts; the steps that enroll a new host (3, 5 and 9) are open; steps 6 and 7 were not reported:

1. Update the server and one agent to v0.3.6 (`myownpki --version`; the agent through *Agents → Update*).
   v0.3.6 has no migration; `myownpki db status` stays at `pki.db` 0019.
2. On the Salt master, copy `deploy/salt/myownpki` from the tag into `/srv/salt/`, put the root and the
   packages (`deb` and, if you have a Red Hat or SUSE minion, `rpm`) into `/srv/salt/myownpki/files/`, and
   take the root's SHA-256 and the package hashes from the admin UI (*Agents → Add host*, or
   `GET /api/v1/agent-install`). Write the pillar `myownpki:agent` for `minion-01.homelab.lan` (version,
   server, ACME directory, root, hashes, a webroot, one `nginx` deployment) and check
   `salt 'minion-01.homelab.lan' state.show_highstate`: no `myownpki-agent-refused`.
3. **With a pass:** (*open*) create a pass (`*.homelab.lan`, 3 uses, 1 hour) and put it into the pillar of
   `minion-01.homelab.lan`. `salt -t 300 'minion-01.homelab.lan' state.apply myownpki`. The output ends
   with `Agent … is enrolled; myownpki-agent is enabled and running.`; the agent page shows the
   deployment and a deployed certificate (compare the serial with
   `openssl s_client -connect minion-01.homelab.lan:443`). **Without a pass:** the same for
   `minion-02.homelab.lan` with no `enrollment_pass`: `setup` prints `Enrollment is pending`.
4. **The second apply is a no-op:** (*done*) run the same `state.apply` on `minion-01.homelab.lan` again with
   `--state-output=changes`. No state reports a change, and the summary has no `changed=` count.
5. **Pending approval:** (*open*) on `minion-02.homelab.lan` approve the request (*Agents → Enrollment requests*,
   second factor), then `state.apply myownpki` again (or the next highstate): the host is enrolled, the
   service is enabled and running, the deployment is deployed. Check that the deployments were already
   in `agent.yaml` after the first apply (§12.4), and that `/root/myownpki-join-token` is gone from the host
   that waited with a pass after the second apply (`myownpki-agent-pass-absent`, §12.4).
6. **Refusals:** break the pillar one way at a time and read the reason with `state.show_highstate`: a
   missing `server`, a typo in a key, a wrong hash length, `config_source` together with `deployments`,
   an unknown deployment option. Each gives only `myownpki-agent-refused`, and nothing is installed.
   Then give the pillar a wrong package hash for the architecture: `state.apply` fails in
   `myownpki-agent-package-verified` and does not install.
7. **`absent`:** put the deployment name into `absent`, apply (`deployment remove`; deployed files stay),
   then remove it from `absent`, restore it in `deployments` and apply again (it is added back). Change
   an option of an existing deployment in the pillar without `absent`: nothing happens, as documented.
8. **Update to a new release:** (*done*, 0.3.2 to 0.3.5 on five hosts) when the next release exists, change `version` and the hashes, stage the
   package and apply to one minion: the package is installed from the verified file and the state
   `myownpki-agent-setup-update` runs `setup` again; `myownpki-agent --version` shows the new release
   and the deployment still works.
9. **Remove the pass:** (*open*) delete `enrollment_pass` from the pillar, apply, and check
   `salt 'minion-*' cmd.run 'test -e /root/myownpki-join-token && echo present || echo absent'`; revoke
   the pass if it has uses left and read its host list. The audit log shows create, the uses and revoke,
   never the secret.

If something differs from `site/hosts/salt.md`, write the difference into the page before the release is
published.

### 12.2 Rules and defaults

**Pillar (`myownpki:agent`).** Defaults in `defaults.yaml`, merged with the pillar in `map.jinja`.

| Key | Meaning |
|---|---|
| `version` (required) | The release to install, for example `0.3.6`. Part of the package file name |
| `server` (required) | Agent listener, `https://pki.homelab.lan:8444` |
| `acme_directory` (required) | ACME directory the agent uses; goes into `agent.yaml` through `setup --acme-directory` |
| `root_source` + `root_sha256` (required) | `salt://` source of the root PEM and its SHA-256 from the admin UI |
| `package.sha256` (required) | Map `amd64` / `arm64` to the SHA-256 of the package from the admin UI |
| `package.source` | Default `salt://myownpki/files/{name}`, `{name}` is `myownpki-agent_<version>_linux_<arch>.<deb\|rpm>`; an `https://` URL is allowed because the hash is checked |
| `package.format` | `auto` (deb for `os_family` Debian, rpm for RedHat and Suse), or `deb` / `rpm` |
| `webroot` | Existing webroot for the enrollment check; unset means standalone on port 80 |
| `low_ports` | `true` passes `--low-ports` to `setup` |
| `enrollment_pass` | Optional secret, read from the pillar; written to `/root/myownpki-join-token` (0600, `show_changes: False`) only while `/var/lib/myownpki-agent/agent.crt` does not exist. Never on a command line |
| `config_source` | Optional `salt://` full `agent.yaml` (the file mode of v0.3.5). `sandbox sync` runs when it changes |
| `deployments` | Optional map name -> options, applied with `deployment add` unless `deployment list` already shows the name. Allowed options are exactly those `deployment add` has (`recipe`, `name`, `webroot`, `create_dirs`, `restart`, ...); an unknown option fails the render |
| `absent` | Optional list of deployment names to `deployment remove` |

**One owner of `agent.yaml`.** `config_source` and `deployments` are mutually exclusive; the render
fails with a message that says so. A changed option of an existing deployment is not applied (the
state sees the name and stops): remove it first through `absent`, or use `config_source`.

**Failing closed.** A missing required key, a missing hash for the minion's architecture, an
`enrollment_pass` that is not a string, or an unknown `package.format` fails the state (a
`test.fail_without_changes` state with the reason), never a partial install. The package is installed
only from the hash-checked local file. The formula never runs `service.running` or enables the unit.

**Secrets.** The pass is the only secret. It comes from the pillar (documented as encrypted pillar,
targeted at the hosts of the roll-out), is written with `show_changes: False` and removed from the
pillar by the admin afterwards. Any `cmd.run` that uses it passes the **file**, never the value.

**Tested versions.** The CI job pins one Salt release; the README names it and says what is not tested
(other Salt versions, a real apply against a server).

### 12.3 Not in v0.3.6

- **A real `state.apply` against a server in CI** (needs a PKI server and port 80 on the runner; the
  `agent end-to-end` job covers the agent side). The owner's live test covers it.
- **Managing the server** (`install.sh`, backup timer) with Salt.
- **Ansible or Puppet roles** (a later release may reuse the pillar names).
- **Windows minions** (the agent only compiles there).
- **Shipping the formula as a release asset.** It is copied or fetched with gitfs; a tarball asset
  would change the 22-file release layout and the checklist.
- **No ADR changes, no change to the product code** unless step 34 shows that `deployment list` has no
  output the state can test for the name; then a machine-readable form is a separate, small commit.

### 12.4 Built (differences from the plan)

Steps 34 to 36 were built on `release/v0.3.6`: the formula, its tests and the pages are in the repository,
the live test above was run by the maintainer on 2026-11-12 (result below), so the changelog says what was tested. Where the build differs
from §12.1 and §12.2 (the code decides):

- **The pillar path is `myownpki:agent:*`.** The sketch in `site/hosts/salt.md` read
  `myownpki:enrollment_pass`. The keys are `version`, `server`, `acme_directory`, `root_source`,
  `root_sha256`, `package.{sha256, source, format}`, `webroot`, `low_ports`, `enrollment_pass`,
  `config_source`, `deployments` and `absent`. An unknown key anywhere is refused.
- **Salt ignores `source_hash` for `salt://` sources.** The plan said `file.managed` with `source_hash`.
  The formula verifies the staged package itself (`myownpki-agent-package-verified`, an explicit
  `sha256sum`; a mismatch fails the run on every apply) and installs only from that local, verified file in
  `/var/cache/myownpki-agent` (root-owned, mode 0755). `source_hash` is passed only for an `https://`
  source, where Salt does check it.
- **A new package on an enrolled host runs `setup` again** (`myownpki-agent-setup-update`). This is the
  documented update path (it refreshes the unit and the drop-ins and restarts the agent); the plan did not
  list it. It belongs into `site/upgrade.md`, "Update the agents", and is there.
- **The unit is never enabled or started by the formula.** The restart is `systemctl try-restart` only,
  after a changed `agent.yaml` or deployment. `restart: true` as a deployment option would start an agent
  that waits for approval; the docs say to leave it unset.
- **Deployments.** `deployment add` runs only when `deployment list` does not show the name, so a changed
  option of an existing deployment is **not** applied (remove it through `absent` first, or use
  `config_source`). `config_source` and `deployments`/`absent` are mutually exclusive. The allowed options
  are the flags of `deployment add` except `dry_run` and `config`. `acme_directory` is required in the
  pillar even with `config_source`, because `setup` takes it.
- **Fails closed, with many refusals:** missing required keys, no hash for the minion's architecture, an
  unsupported architecture, an `os_family` that `auto` cannot map, an unknown key, option, architecture or
  format, a pass that is not a string, a value of the wrong type, a name in both `deployments` and
  `absent`. The one failing state is `myownpki-agent-refused`; the reason is in its **name**, because
  `test=True` hides the comment, so the docs say to read it with `state.show_highstate`.
- **`state_dir` other than `/var/lib/myownpki-agent` breaks the `agent.crt` checks** of the pass state and
  of `setup` (`creates`). The docs say to keep the default.
- **A pending host is not an error for Salt.** `setup` exits 0 with `Enrollment is pending`, so the state
  succeeds, the deployments are added (the file does not depend on the approval) and the unit stays
  disabled. The next apply polls the request, because `agent.crt` still does not exist. This is read from
  the code (`internal/agent/setup.go`, the state requisites) and part of the live test.
- **A leftover pass file (found while writing the docs; fixed afterwards).** `setup` deletes the token
  file only when it admits the host in that run (`newlyAdmitted`). A host that waited and was approved
  later, and a host whose pass was removed from the pillar while it waited, would keep
  `/root/myownpki-join-token`. The state `myownpki-agent-pass-absent` (`file.absent`, `onlyif: test -e` the
  agent certificate, after `setup`) deletes it, with or without `enrollment_pass` in the pillar, and never
  before the host has its certificate (a host that still waits needs the file for the next `setup`).
  CI asserts the state in every case that renders the formula and not in the refusals.
- **Tested** (CI job `salt formula`, Salt 3008.5, not a required check): every pillar of
  `deploy/salt/test/cases` rendered with `state.show_highstate`, expected and forbidden states, that the
  pass appears in no output, and `state.apply test=True` for the cases a Debian runner can apply.
  **Not tested:** a real apply against a server, other Salt versions, `pkg.installed` for `rpm`, and the
  `https://` source. The README and `site/hosts/salt.md` say so.
- **Live test by the maintainer (2026-11-12).** Five enrolled Debian amd64 hosts; Salt master and minions on
  a current Salt version; the package came from the Salt file server (`salt://myownpki/files/<deb>`). One
  real `state.apply myownpki` upgraded the agent from 0.3.2 (installed by `install-agent.sh`, not by `dpkg`)
  to 0.3.5 on all five: package staged, the hash check passed (the verify state was skipped), `pkg.installed`
  from the local file, `myownpki-agent-setup-update` ran once, `myownpki-agent-setup` was skipped
  (`agent.crt` exists), `myownpki-agent-pass-absent` did nothing. The `agent.yaml` hash, the certificate
  serial and the existing deployments were unchanged, and the service restarted and was active. A second
  apply changed nothing (`setup-update`: none of the onchanges reqs changed). Four hosts had
  `20-low-ports.conf` and needed `low_ports: true`; `setup` printed `Kept in 10-paths.conf …` for a
  hand-added `/var/log/nginx` and kept it. The pass is not needed for enrolled hosts.
- **Found by the live test:**
  - The pillar top file (`/srv/pillar/top.sls`) and the state top file (`/srv/salt/top.sls`) are different
    files; the formula reads only the pillar.
  - A host already listed in the pillar top under its own id needs a second entry with another matcher
    (`'L@minion-01.homelab.lan'` with `- match: compound`); a duplicate YAML key silently drops the first.
  - A scheduled highstate (for example every 60 minutes) applies the formula for real as soon as it is in
    the state top file: apply by hand with `state.apply` first, add the state top entry afterwards.
  - `low_ports: true` is needed on enrolled hosts that already have the low-ports drop-in; a small overlay
    pillar file with only that key, listed after the base file in the pillar top, was enough.
- **Still not live tested:** the enrollment of a new host with an enrollment pass (`setup --token-file`,
  `pass-absent` after the enrollment, a pending host), `rpm` hosts, `arm64`, `config_source`, the gitfs
  install and other Salt versions.

---

## 13. dns-01 in the agent: v0.3.7

Until now the agent proves a name with http-01 only: port 80 of the host, standalone or through a webroot.
That fails for **wildcards** (`*.homelab.lan` can only be proven with dns-01, RFC 8555 §7.1.3), for hosts
**without port 80** (a service on 8443 behind a firewall) and for hosts **behind NAT**. v0.3.7 gives a
deployment the challenge `dns-01`: the agent writes the TXT record `_acme-challenge.<name>` through **RFC 2136**
(BIND, Knot, PowerDNS with TSIG) or the **Cloudflare API**, waits until it is visible, lets the ACME
server read it, and removes it again. The server only *reads* the TXT record (PLAN §10.1), so it stays
unchanged unless step 41 finds a gap. The two secrets involved, a TSIG key and a Cloudflare token, decide
the design: they live in a separate root-only file, never in `agent.yaml`, a log, a command line or a report.

Goal of v0.3.7, measured on the live installation: a deployment `*.homelab.lan` plus `homelab.lan` gets
its certificate through RFC 2136 against the internal DNS server, on a host whose port 80 is closed; the
TXT records are gone afterwards; a wrong key fails with a message that contains no secret; a second
deployment through Cloudflare works the same way (if the maintainer has a zone there).

Where this plan differs from the task text and from PLAN §10.1 (read from the code and from `go list`; nothing was run):

- **RFC 2136 does not come from lego.** lego's `providers/dns/rfc2136` imports `bodgit/tsig`, whose GSS-TSIG
  part brings a Kerberos stack: **12 new modules** in the Linux build (`gokrb5` and five more `jcmturner/*`,
  `hashicorp/go-multierror`, `go-uuid`, `errwrap`, `go-logr`, `jinzhu/copier`; Windows adds `alexbrainman/sspi`),
  mostly last released between 2018 and 2023, for a feature (GSS-TSIG) this release does not offer. The plan
  writes a small provider on `miekg/dns`, which is already in `go.mod` (indirect, through lego). **Cloudflare comes
  from lego** and adds **no module** (its package imports only lego itself and `miekg/dns`). §13.3 and §13.7 have
  the details and the way back.
- **No proxy from the environment.** The task text says `HTTPS_PROXY`; the agent never reads it (the rules at the
  top of this file, `site/cli.md`). The Cloudflare calls use `proxy:` of `agent.yaml`, like the ACME calls.
- **Enrollment stays http-01.** ADR-18 names dns-01 as a proof of control, but `internal/agents/enroll.go` has
  only the http-01 check. A host without port 80 enrolls with a join token and one approval; its certificates
  then use dns-01. Enrollment by dns-01 is not part of this release (§13.6).
- **The pages `site/learn/acme.md`, `site/guides/split-dns.md`, `choose.md`, an FAQ and a glossary do not exist** in
  this repository. The pages to change are in step 43; the split-DNS text is `docs/OPERATIONS.md` §10.7.
- **The server already does what the agent needs** (read from `internal/acme`): `challengeTypes` offers only dns-01 for
  `*.` identifiers, a domain with `wildcards` must allow dns-01 (`internal/ca/domains.go`), the validator reads
  `_acme-challenge.<name>` through `acme.resolver` and follows CNAMEs, and `acme_test.go` issues a wildcard.
  One rule surprises: a **linked agent account may order `*.x` only if its names hold the identical pattern
  `*.x`** (`agents.Matches`), and an enrollment pass grants the host name only (`initialNames`).

### 13.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 38 | 0.3.7 | **Schema, validation, seam.** `internal/agent/config.go`: `ChallengeDNS01 = "dns-01"`, `Config.DNSProviders` (`dns_providers`, a map from name to `DNSProvider`), `Deployment.DNSProvider` (`dns_provider`) and `Deployment.CheckName` (`check_name`), strict keys, the rules of §13.2 (wildcard names only with dns-01, the provider exists, no `webroot` with dns-01, path rules for `credentials_file`, bounds for `ttl` and the propagation values, a provider no deployment uses is a warning). A new `dns_seam.go`: the interface `dnsProvider` (lego's `challenge.Provider` plus `Timeout`), a factory field on `Agent` that tests replace, a default that fails with "not built" until step 40. `deploy_reload.go`: the TLS check uses a concrete SNI name (`serverName(d)`: `check_name`, else the first name without `*`; a deployment with only wildcard names and a `check` needs `check_name`). `acme.go`: no responder for dns-01. `edit.go`: `dns_providers` in `topLevelOrder` after `enrollment`. `dropin.go` needs nothing, dns-01 binds no port. **Guard for the dependency (§13.3):** a depguard rule in `.golangci.yml` and `cmd/myownpki/deps_test.go` (`go list -deps` of `./cmd/myownpki` and `./cmd/myownpki-ctl` contains neither `go-acme/lego` nor `miekg/dns`) | Table tests for every rule and refusal; an `agent.yaml` of 0.3.6 parses to the same `Config`; `task check`; `go list -deps ./cmd/myownpki` unchanged |
| 39 | 0.3.7 | **Credentials files.** `dns_creds.go` with `dns_creds_unix.go` and `dns_creds_other.go`: `loadDNSCredentials(path, type)` opens with `O_NOFOLLOW`, then checks the *open* file: regular, mode 0600 or 0400, owner root or the agent's effective user, at most 4 KiB, parent directory not writable by group or others and owned by root or the agent's user (Windows: no mode check, like the token file). The format is YAML with strict keys (§13.2). Values are a `secret` type that prints as `[redacted]` in `%v`, `%+v`, `%#v`, slog, JSON and errors (like `Material`); a `redact()` helper removes them from any error text; buffers are cleared after the run. `agent config check` gets a block "DNS providers": type, state of the credentials file (ok, missing, wrong mode, wrong owner), exit 1 when a deployment uses a bad file; it never prints contents | Unit tests (mode 0644 and 0660, symlink, directory, foreign owner through an injected `stat`, too large, unknown key, empty value, a sentinel secret never appears in any formatted output or log line); `config check` output tests; `task check` on Linux and Windows |
| 40 | 0.3.7 | **Providers, propagation, cleanup.** `dns_cloudflare.go` (lego `providers/dns/cloudflare`, its `Config` filled field by field: token and optional zone token from the file, TTL, timeouts, an own `http.Client` with the agent's `proxy`, the **system** trust store and TLS 1.2; no `BaseURL` key in production). `dns_rfc2136.go` (own, §13.2: UPDATE over TCP, TSIG hmac-sha256/384/512, response MAC verified, zone from `zone` or the SOA lookup). `dns_wrap.go` (the wrapper every provider runs in: refuses a domain that is not one of the deployment's names, checks the context before `Present` and in every propagation poll, runs `CleanUp` with `context.WithoutCancel` and 30 s, records cleanup errors, which lego only logs). *Built after the independent review (see the status paragraph below):* once the issuance is canceled all `CleanUp`s share one deadline of 12 s (`shutdownCleanupBudget`, below `TimeoutStopSec` of 30 s) and a record without time left is not sent but recorded; `dnsGuard.Notice` names the `_acme-challenge.<name>` records that may remain, `obtain` puts it into `Material.Notice` (in front of the error on failure) and `runPass` into the deployment's *Last error*; the build error of a provider is redacted before its secrets are wiped; the TSIG secret is signed from a copy so the wipe cannot race a late `CleanUp`; the Cloudflare provider reports a record that may exist although lego holds no ID. `acme.go`: `SetDNS01Provider` with `dns01.AddRecursiveNameservers` from `resolver` or `/etc/resolv.conf` and never lego's public fallback, `DisableAuthoritativeNssPropagationRequirement` and `PropagationWait` per `propagation`. `agent run` unsets every `LEGO_*`, `CLOUDFLARE_*`, `CF_*` and `RFC2136_*` variable and, after the review, `SSL_CERT_FILE` and `SSL_CERT_DIR` (hooks inherit the cleaned environment). The ARI lookup of a tick uses `TryLock` on `passMu` and is skipped while an issuance runs. `internal/testutil/dnsserver`: an in-process `miekg/dns` server (UDP and TCP on 127.0.0.1, zone store, UPDATE with TSIG, SOA, TXT and CNAME queries, a log of every message). `go.mod` (`miekg/dns` direct), `THIRD_PARTY.md` | Unit tests with a fake provider (order of `Present` and `CleanUp`, cleanup after failure and after cancel, wrong domain, `*.x` plus `x` give two records and two removals); the RFC 2136 provider against `dnsserver` (add, remove, idempotent, wrong secret, REFUSED, forged response MAC, zone mismatch, CNAME delegation); the Cloudflare provider against an `httptest` stub (zone lookup, create, delete by ID, token header, no token in any error); after the review also: a lost Cloudflare answer (warning, notice, no token or body in any text) and a refused create, two hanging records within the shared budget, the notice merged into the results, signing while the secret is wiped, the provider build error without a secret, both `SSL_CERT_*` variables removed, no ARI request while the lock is held, a CNAME target outside `zone` refused; `task check`, `task vuln`, `task ci:local` |
| 41 | 0.3.7 | **End to end with the real server.** `internal/server/agent_dns01_test.go` on `newAgentEnv`: `cfg.ACME.Resolver` is the `dnsserver`, the domain has `Wildcards: true`, the agent's names hold `*.homelab.lan` and `homelab.lan`. The agent obtains both names through RFC 2136 and through the Cloudflare stub (its handler writes into the same zone store). Refusals: name missing in the agent's names, domain without wildcards, record never appears (timeout), wrong key. After every case the zone store holds no `_acme-challenge` record. A conformance test `TestConformanceAgentDNS01` (tag `conformance`) runs the same against the BIND of `test/conformance` (TSIG key in a 0600 file, `propagation: resolver`, `resolver` = `$CONF_DNS`), inside the existing job `ACME conformance` (`run.sh` already runs every `TestConformance*` of `internal/server`). **Server gaps:** none found by reading; this step proves it, and a gap found here is fixed here | `go test ./internal/server -run DNS01`, also on Windows and macOS (the matrix); the conformance job is green; `task ci:local` |
| 42 | 0.3.7 | **`deployment add` and the Salt formula.** Flags `--dns-provider`, `--dns-type`, `--dns-credentials`, `--dns-nameserver`, `--dns-zone`, `--dns-resolver`, `--check-name` in `deployment_cli.go` and `DeploymentSpec`; `--challenge dns-01` then needs no webroot, no `paths` entry and no low-ports drop-in. A provider entry is written when `--dns-type` is given for a new name; a different definition for an existing name is refused ("edit agent.yaml by hand"). A missing or wrongly protected credentials file is a **warning** (Salt runs `deployment add` before the secret file may exist). `--dry-run` shows the diff. Salt: the seven options in `opts_string` of `deploy/salt/myownpki/map.jinja`, the README table, one test case `debian-dns01` and one refusal | Editor tests (comments kept, dry run, conflicting definition, `'*.homelab.lan'` quoting); the CI job `salt formula`; the users of `ParseDeploymentAdd` (`internal/web/hostadd_test.go`) stay green |
| 43 | 0.3.7 | **Docs.** New `site/dns-01.md` (when to use it, the two providers, credentials file and permissions, DNS server settings with a BIND `update-policy` example, Cloudflare token scope, wildcards and the agent's names, propagation options, firewall, troubleshooting); `site/hosts.md` (flags, the wildcard line), `site/cli.md`, `site/recipes.md` (one note: any recipe works with `--challenge dns-01`), `site/troubleshooting.md` (errors of dns-01), `site/best-practices.md` (token scope, one file per provider), `site/hosts/salt.md` (the credentials file with `file.managed`, `mode: 0600`, `show_changes: False`), `site/upgrade.md` (agents first: an older agent refuses the new keys), `site/index.md`, `site/_data/nav.yml`, the README line; `docs/OPERATIONS.md` §10.7 (pointer: the agent now does it), §12.3 (schema), §12.4 (firewall rows) and a new §12.11; CHANGELOG `[0.3.7]` (undated); the live-test status in this section | `scripts/ci/site-check.sh`; every documented command checked against the code |
| 44 | 0.3.7 | **Release.** Version bump as in `d30bf6f`: `DEFAULT_VERSION` in `deploy/install.sh` and `deploy/install-agent.sh`, `test/install/agent_functions_test.sh`, `api/openapi.yaml`, `deploy/docker-compose.yml`, README, `docs/OPERATIONS.md`, `docs/RELEASING.md`; CHANGELOG dated by the maintainer; PLAN §10.1, `CLAUDE.md` and the site after the tag | `docs/RELEASING.md` |

**Live test for the maintainer** (names are examples; use a test host, not production):

1. Update the server and one agent to v0.3.7. The server has no migration (`myownpki db status` unchanged). An agent of 0.3.6 or older refuses an `agent.yaml` with `dns_providers`: update the agent first.
2. *ACME → Domains*: `homelab.lan` with wildcards and dns-01 on. *Agents → the host → Names it may order*: add `*.homelab.lan` and `homelab.lan` (a pass or the host name alone does not grant the wildcard).
3. On the DNS server: a TSIG key (hmac-sha256) that may update only `_acme-challenge.homelab.lan` (BIND: `update-policy { grant acme-agent name _acme-challenge.homelab.lan. TXT; };`). On the host: `/etc/myownpki-agent/dns/homelab.yaml`, root, mode 0600. `myownpki-agent config check` is green; set the mode to 0640 and it fails with the mode, not the content; set it back.
4. `deployment add wild --recipe nginx --name '*.homelab.lan' --name homelab.lan --challenge dns-01 --dns-provider homelab-dns --dns-type rfc2136 --dns-nameserver 192.0.2.53 --dns-credentials /etc/myownpki-agent/dns/homelab.yaml --check-name www.homelab.lan --dry-run`, then without `--dry-run`, restart, *Renew now*. The deployment turns *deployed*; `openssl s_client -connect host:443 -servername x.homelab.lan` shows both SANs; `dig +short TXT _acme-challenge.homelab.lan @192.0.2.53` is empty afterwards. Block port 80 from the PKI host and repeat: it still works.
5. **Failure:** put a wrong secret in the file. The renewal fails with a message that names the provider and the problem; `journalctl -u myownpki-agent` and *Last error* on the agent page contain no part of the secret; no TXT record is left; the other deployments of the host keep renewing.
6. **Rotation:** correct the file; the next attempt works without a restart.
7. **Cloudflare** (only with a zone there): a token with *Zone:Read* and *DNS:Edit* for that one zone, a deployment with `--dns-type cloudflare`, with `proxy:` if the host needs one. Afterwards the zone holds no `_acme-challenge` TXT.
8. **A wrong name:** a deployment for a name that is not in the agent's names fails with `rejectedIdentifier`, and the agent page already says "not covered by Names it may order".

**Status of the live test (step 43):** pending. The documentation says so in three places: the status note of
`site/dns-01.md`, the operations guide §12.11 (*What is tested*) and the CHANGELOG `[0.3.7]` (*Known
limitations*). Not tested against the real thing: the Cloudflare code against the real API (CI uses a stub), a
BIND `update-policy` on the maintainer's server (the conformance test uses `allow-update`), the default
`propagation: authoritative` against name servers on port 53 (CI uses `propagation: resolver`), the Salt
formula's dns-01 deployments on live minions, and macOS. **Docs against code, step 43:** when the pages were
written, a failed cleanup was only logged (`dnsGuard.warn`; `Warnings()` was read by tests only) although the
plan said "a warning in the status". The release branch then gained `dnsGuard.Notice` (`1c37850`), which puts
`dns-01 cleanup failed: a TXT record may remain at _acme-challenge.<name>; ...` into the deployment's *Last
error*, and the pages describe that; they must be read again if it changes. Step 43 also fixed the sentences
"the agent does not do dns-01 yet" in `site/learn/acme.md`, `site/faq.md` and the guides for certbot, acme.sh,
lego, Traefik and Caddy, split DNS and domains.

**Independent security review (§13.4) and its fixes.** An independent reviewer read the diff and found no
blocker; its six findings were fixed on the release branch before the release, with tests (seven fix commits:
`d45f0d8`, `be331bf`, `1c37850`, `bef1989`, `95e68fb`, `ac29e88`, `2b03a3c`; `12b8e42` adds a test only).
The fixes: the build error of a DNS provider is redacted before its secrets are wiped; the TSIG secret is
signed from a copy, so the guard's wipe cannot race a `CleanUp` that timed out and still runs; a failed
cleanup is reported as a notice in the deployment's *Last error*; a Cloudflare record that may exist although
lego holds no ID is reported (network error, a non-JSON answer, 5xx or 2xx, not a refused 4xx); the cleanups
share one 12 s budget while the agent stops; `SSL_CERT_FILE` and `SSL_CERT_DIR` are removed from the
environment; the ARI lookup uses `TryLock` and is skipped while an issuance runs. The pages and the
operations guide were aligned with this (`site/dns-01.md`, `site/troubleshooting.md`, §12.11, CHANGELOG).

**Deviations from the plan text above, as built:**

- **§13.2 decision 3, "30 s, not cancellable":** 30 s per `CleanUp` holds while the issuance runs; once it is
  canceled all `CleanUp`s of the issuance share 12 s (below `TimeoutStopSec` of 30 s, the risk in §13.5), and a
  record without time left is recorded as a failure instead of being sent.
- **§13.2 decision 3, "a warning in the status":** built as `dnsGuard.Notice` in the deployment's *Last error*,
  without a change of the report schema. The deployment stays `deployed`; on failure the notice stands in
  front of the error; the next clean pass clears it. It names the records, never provider text.
- **§13.4 "Resolver and environment":** besides `LEGO_*`, `CLOUDFLARE_*`, `CF_*` and `RFC2136_*` the agent
  removes `SSL_CERT_FILE` and `SSL_CERT_DIR`, because the Cloudflare client trusts the system roots; the
  hooks inherit the cleaned environment.
- **§13.4 "Cloudflare":** a create that may have worked while lego holds no record ID is reported as a leftover
  record; the plan only had the failed delete.
- **Renewal tick:** the optional ARI lookup does not wait for `passMu` any more; the plan did not mention it.
- **RFC 2136 `zone`:** with `zone` set, a CNAME target outside it was already refused by `zoneFor`; the test is new.

### 13.2 Decisions

The maintainer was not available; each row takes the cautious option. Review them together with §13.7.

| Topic | Decision | Why |
|---|---|---|
| **1. Selecting dns-01** | A deployment gets `challenge: dns-01` and `dns_provider: <name>`. The name refers to an entry of the new top-level map `dns_providers`: `type` (`rfc2136` or `cloudflare`), `credentials_file` (absolute, required), `nameserver` (`host` or `host:port`, rfc2136 only, required), `zone` (rfc2136, optional), `ttl` (default 120; 120 to 3600 for Cloudflare, 30 to 3600 for rfc2136), `resolver` (`IP` or `IP:port` for SOA, CNAME and propagation queries, optional), `propagation` (`authoritative` default, `resolver`, `wait`), `propagation_wait` (seconds, default 0, at most 300), `propagation_timeout` (seconds, default 120, at most 600). Unknown keys are errors; `config check` reports every problem at once. `enrollment.challenge` stays standalone or webroot | Settings are shared by deployments, a deployment line stays short, two DNS servers are possible, and the secret is only *referenced* |
| **1b. Wildcards** | `names` may hold `*.` plus a name of at least two labels (the rule of `agents.CheckPattern`) **only** with dns-01. `*.x` and `x` may be in one deployment (two authorizations, one TXT name, two values). The agent never asks the server about policy: the ACME server decides (domain `wildcards` on, dns-01 allowed, the agent's names hold the identical `*.x`). The refusal reaches the user as the server's `rejectedIdentifier`, and the agent page already marks names the agent may not order | One source of truth for policy (ADR-19); an agent-side copy of the server's rules would drift |
| **2. Credentials** | `credentials_file` is read when an issuance starts, so a changed file works at the next renewal without a restart, and is cleared from memory afterwards. Checks as in step 39. Format: YAML, strict keys. `cloudflare`: `api_token` (required), `zone_token` (optional, only if you split Zone:Read from DNS:Edit). `rfc2136`: `tsig_key_name`, `tsig_algorithm` (`hmac-sha256` default, `hmac-sha384`, `hmac-sha512`; `hmac-md5` and `hmac-sha1` are refused), `tsig_secret` (base64, as in BIND's `key` statement). The path may not be under `/home`, `/root` or `/run/user` (`ProtectHome=yes` hides them from the agent), `state_dir`, `paths` or a deployment target. **No sandbox change:** `/etc` is readable under `ProtectSystem=strict` and the file is only read, so `10-paths.conf` and `sandbox sync` stay as they are. The legacy Cloudflare global API key is not supported | The token file check of `setup` is the model (regular file, 0600), plus owner and open-file checks because this secret is read at every renewal. A file beats an environment variable (visible in `/proc`) and `agent.yaml` (shared, often versioned). Salt places the file with `file.managed` in the host's own state (step 43) |
| **3. Propagation, cleanup** | After `Present` the agent polls (every 2 s, until `propagation_timeout`) with lego's pre-check. `authoritative`: the TXT must be on every authoritative server of the zone (port 53; the lego default, robust against negative caching). `resolver`: only the configured resolver (hosts that cannot query authoritative servers). `wait`: no query, sleep `propagation_wait`. `propagation_wait` is added before the first check in every mode. `CleanUp` runs on success, failure, cancellation and timeout (30 s, not cancellable) and removes only this run's record. `Present` is idempotent (RFC 2136 adds an identical RR once; for Cloudflare a new record is made and removed by ID). A cleanup error becomes a log line and a warning in the status; the issuance keeps its result. **CNAME delegation is supported** (lego follows `_acme-challenge` CNAMEs; the update goes to the target zone, so the credentials must be valid there), tested once with `dnsserver` | A premature "ready" costs a failed authorization; a stuck record costs only tidiness. lego only logs cleanup errors (`prober.go`), so the wrapper has to record them |
| **4. Network** | RFC 2136 needs outbound **TCP 53** to `nameserver` (updates are TCP only: signed, no size limit) and, for `authoritative`, UDP and TCP 53 to the zone's name servers. Cloudflare needs outbound **HTTPS** to `api.cloudflare.com`, through `proxy:` when set (never `HTTPS_PROXY`), with the **system** trust store (`ca_bundle` is the private root); a host without `ca-certificates` gets a hint. **No SSRF guard in the agent:** the guard protects the *server*, whose targets come from ACME clients. The agent's targets (nameserver, resolver, API) come from the root-owned `agent.yaml`, and the TXT name is built from the deployment's names, which the wrapper checks against what the ACME server returns | The agent is the client; its network inputs are as trusted as its hooks. The wrapper closes the one remote input, an authorization for a name nobody asked for |
| **5. Tests** | A seam (`dnsProvider` factory on `Agent`) and a fake for unit tests. For integration without real providers, `miekg/dns` is already in `go.mod`: `internal/testutil/dnsserver` (imported by tests only) is both the RFC 2136 server and the zone store the ACME server reads (`acme.resolver`); the Cloudflare stub is an `httptest` server writing into that store. All of it runs on Windows, macOS and Linux. lego's authoritative check uses port 53 only, so the tests set `propagation: resolver`. CI: no new job; unit and e2e tests run in the matrix, the BIND test inside `ACME conformance` | Reuses what exists, adds no test dependency and no job |
| **6. Server** | No change planned. Step 41 re-checks wildcard orders for a linked account, `validReport` with `challenge = "dns-01"` (bounded string, accepted today) and the UI | A protocol or schema change would break mixed fleets |
| **7. UI, docs, Salt** | The *Add host* assistant is **not** extended: it ends in a pasted command and cannot place a secret file safely, its enrollment check is http-01, and it takes exact names only. Admins run `deployment add` by hand after the assistant (the page says so). The formula passes the new options as flags and does **not** manage secrets | Secrets belong to the host's own state or to the admin, not into a generated command |
| **8. lego's resolver state** | lego keeps the resolver list and the DNS timeout in package variables. The agent sets them before every issuance (`resolver`, else `/etc/resolv.conf`, else an error) and never uses lego's built-in fallback to public resolvers, which would send internal names to the internet. Issuances are serialized by `passMu` | A silent fallback leaks internal names; state left by another provider would query the wrong server |

### 13.3 Dependencies

Measured on this branch with a probe module (the same `go.mod`, a program using the packages; `-s -w`, linux/amd64): the agent is 11.9 MB today. lego `dns01` alone: 7,676,064 bytes; plus lego Cloudflare **+77,824**; plus lego RFC 2136 **+118,784** more. The sizes are small; the module count is the real cost.

| Module / package | Version (date) | License | Decision |
|---|---|---|---|
| `github.com/go-acme/lego/v4`: `challenge/dns01`, `providers/dns/cloudflare` | v4.35.2 (2026-04-24, pinned already) | MIT | **use**; no new module, no version change; the `THIRD_PARTY.md` row changes (its text "No DNS provider ... is built in") |
| `github.com/miekg/dns` | v1.1.72 (2026-01-22, pinned already) | BSD-3-Clause | indirect becomes direct (own RFC 2136 provider, test server); no new module |
| lego `providers/dns/rfc2136` | v4.35.2 | MIT | **not used.** It brings `bodgit/tsig` v1.2.2 (2023-02, BSD-3), `jcmturner/gokrb5/v8` v8.4.4 (2023-02), `aescts`, `dnsutils`, `goidentity`, `rpc` (2020 to 2022, Apache-2.0), `gofork` (BSD-3), `hashicorp/go-uuid`, `go-multierror`, `errwrap` (MPL-2.0), `go-logr/logr` v1.4.3 (Apache-2.0), `jinzhu/copier` v0.4.0 (MIT) and, on Windows, `alexbrainman/sspi` (2018, BSD-3). All permissive and older than two weeks, but a Kerberos stack the release would not use, and the provider defaults to `hmac-sha1` |

**Keeping it out of the server binary.** Today `go list -deps ./cmd/myownpki` shows no lego and no `miekg/dns`; only `internal/recipe` is shared with the agent. The new code lives in `internal/agent` (imported by `cmd/myownpki-agent`); server tests import it, which does not reach the server binary. Two guards in step 38: a depguard rule and a test that runs `go list -deps` on the server and on `myownpki-ctl`. `task vuln` must stay green.

### 13.4 Security review (an independent reviewer checks, with the diff only)

- **Credentials:** opened without following symlinks and checked on the open descriptor (mode, owner, parent directory, size); a failing check names the problem, never the content; no secret in `agent.yaml`, `agent status`, the report to the server (`LastError`, `Challenge`), slog, lego's log, panics or a `%v` of any struct; `credentials_file` never inside `paths` or `state_dir`.
- **TXT cleanup:** on every path (success, error, cancel, timeout, a panic in a provider, SIGTERM during the wait); only this run's value is removed; the e2e tests assert an empty zone; SIGKILL leaves a record (§13.5).
- **Logging and errors:** provider errors go through `redact()`; no Cloudflare response body in logs; no `LEGO_DEBUG_*` (the agent unsets `LEGO_*`).
- **The wrapper:** refuses a domain that is not a deployment name (a compromised ACME server cannot make the agent write another name's record); `*.x` maps to `_acme-challenge.x`.
- **RFC 2136:** the TSIG MAC of the response is verified, algorithm list, TCP only, zone check, no UPDATE outside the computed zone; the docs' `update-policy` is as narrow as the product allows.
- **Cloudflare:** token scope documented as one zone; the HTTP client uses system roots, TLS 1.2, a 30 s timeout and `proxy:` only; no `BaseURL` key.
- **Resolver and environment:** no fallback to public resolvers; the environment never feeds a provider.
- **Dependency tree:** the `go list -m all` diff is empty except `miekg/dns` becoming direct; `govulncheck -mode=binary` on the agent; the server binary has neither package.
- **Config and sandbox:** unknown keys refused; paths hidden by `ProtectHome` refused; no new writable path; the `systemd-analyze security` result is unchanged.

### 13.5 Risks

| Risk | Handling |
|---|---|
| A wrong default resolver, or a firewall that blocks port 53 to the authoritative servers, hides the record from the check | `propagation: resolver` or `wait` come first in troubleshooting; the error names the failed check and the server |
| SIGKILL, a power cut or `TimeoutStopSec` (30 s) during the wait leaves a TXT record | Harmless to validation (the server accepts any matching value) but untidy; the Cloudflare record IDs live in memory only, so no later run removes it. Documented; a sweep is a later idea (§13.6) |
| lego's package variables bleed between providers | Set before every issuance under `passMu` (decision 8); a test issues with two providers in a row |
| Our own RFC 2136 code has a bug a mature library would not | One UPDATE message; tested against `miekg`'s server and against BIND in CI; lego's package remains the way back (§13.7) |
| An agent of 0.3.6 reads an `agent.yaml` with the new keys and refuses to start | `KnownFields(true)` is deliberate (typos are errors). `site/upgrade.md`: update the agents first |
| The wildcard certificate exists but nobody may order it | The agent page says "not covered by Names it may order"; docs and live-test step 2 |
| Windows DNS (Active Directory) accepts only GSS-TSIG updates | Not supported; the docs say so and name the options (BIND or Knot for the ACME zone, or a CNAME delegation of `_acme-challenge`) |

### 13.6 Not in v0.3.7

- **GSS-TSIG (Kerberos, Active Directory DNS)**, other lego providers, **the legacy Cloudflare global API key**, DNS updates over HTTPS or TLS.
- **Enrollment by dns-01** (the ADR-18 text): the enrollment check stays http-01.
- **Extending the Add host assistant** (secrets, wildcards, a dns-01 choice) and a server-side view of the DNS provider per deployment.
- **A sweep of stale `_acme-challenge` records**, hooks around the DNS step, and one provider per name inside a deployment.
- **A new CI job.** No ADR change; PLAN §10.1 gets a note after the tag (RFC 2136 is an own provider on `miekg/dns`).

### 13.7 Open points for the maintainer

1. **Own RFC 2136 provider instead of lego's** (§13.3): fewer modules and no Kerberos, but our code. The way back is one file (`dns_rfc2136.go` returns lego's provider) plus the 12 modules in `go.mod`; say so before step 40 if you prefer lego's.
2. **Active Directory DNS** is common in homelabs (`homelab.lan` may be one). If yours is, RFC 2136 needs another DNS server for the ACME zone, or a CNAME delegation, or GSS-TSIG in a later release.
3. **Default `propagation: authoritative`** needs port 53 to the zone's name servers. Say if your network blocks that.
4. **Credentials file rules** (mode 0600 or 0400, owner root or the agent's user, outside `/home`, `/root` and `/run/user`, not under `paths` or `state_dir`) are stricter than the token file. Confirm.
5. **`check_name`** is a key I added for the local TLS check, because the SNI `*.homelab.lan` is not a host name; the alternative (no check for wildcard-only deployments) loses the rollback guard.
6. **Not verified:** the shape of the Cloudflare API calls for the stub (read from `providers/dns/cloudflare/internal` in step 40), whether the BIND `update-policy` line works on your server (live test 3), and the `graphify` graph was absent in this worktree (`graphify-out/` does not exist), so every reference above comes from direct file reads.

---

## 14. Charts, reports and analysis: v0.3.8

v0.3.8 answers "what is the state of the PKI, and why?" in the web UI: **charts** on the dashboard, a calm
**Reports** page, and an **Analysis** page with rule-based findings that each say what was seen, why it
matters and what to do. Everything is computed on the server from data it already holds; nothing is sent to
an external service. The UI inventory (a screenshot walk through every page) ends in a gap list for the
maintainer. Written on 2026-11-13 while the maintainer was away: the decisions in §14.2 are cautious
defaults for review, not agreements.

Goal, measured on the live installation: *Reports* shows the expiry forecast, issuances by source, the
certificates per CA and status, the alert history and the agent fleet, and every number matches the
certificate list and the agent page; *Analysis* names the real oddities of the homelab with reasons and says
"unknown" where it has no data; both pages work with the strict CSP, without a single console violation.

**Facts found in the repository (2026-11-13, `origin/main` 7b9d687)** that shape the plan:

- **There is no JavaScript pipeline.** `go.mod` has no esbuild, `web/islands/` does not exist, `web/web.go`
  embeds `styles/*.css` only, `staticFiles` knows no `.js` type, no template may contain `<script>`
  (`TestNoInlineStylesOrScripts` and the `.templ` scan forbid it), and htmx is **not** loaded (the `hx-*`
  attributes in `admin/generic.templ` are inert; the host progress page uses `<meta http-equiv=refresh>`).
  v0.3.8 would be the first script the product ever served. The passkey button waits for the same
  mechanism (PLAN: "No passkey button in the UI until esbuild (ADR-04) or one plain script is approved").
- **ADR-04** reads "Islands for interactivity: Web Components + ECharts, bundled with esbuild-as-a-Go-library".
  esbuild is a separate, **not approved** dependency; `frontend.md` repeats the plan.
- **Strict CSP** (`internal/web/server.go`): `default-src 'self'; script-src 'self'; style-src 'self'; img-src
  'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. No `unsafe-*`.
- **No source column.** `certificates.source` is `issued | imported | external`. ACME, agent and UI/API
  issuance are told apart only by joins: `acme_orders.certificate_id` and `acme_accounts.agent_id`.
- Alerts are pruned after 30 days (`monitorKeep`); `monitor.Rules` holds every threshold; `Evaluator` already
  builds the certificate set, the endpoint states and the agent findings; `Engine.CertificateCounts`
  already gives the counts per CA and status, scoped by the caller's roles.
- The screenshot tool (`internal/tools/screenshots`) already runs the real UI on a throwaway demo instance and
  captures with a headless Edge/Chrome in light and dark. The demo instance has no agents, alerts or endpoints.

### 14.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 45 | 0.3.8 | **Data layer for reports.** New package `internal/report`. Migration `pki.db` **0020** (next free number; additive, indexes only): `certificates (created_at)` and `acme_orders (certificate_id) WHERE certificate_id IS NOT NULL`. sqlc queries in `internal/store/queries/pki/reports.sql` (`ExpiryTimes`: `not_after` of non-revoked certificates in a window; `IssuanceSources`: `created_at` plus the class of every `source='issued'` certificate of a window, D6) and two read methods on `ca.Engine` that keep the CA scoping of `CertificateCounts`. `report.Build(ctx, Deps, now)` returns the five datasets of §14.2 (ISO weeks in UTC, Monday start; buckets are filled in Go, empty weeks included). A 60-second cache per tenant with a mutex (one build at a time). Deps are interfaces (engine, agents, alerts store, rules, clock). Tests: fake clock, week borders (Sunday 23:59:59 and Monday 00:00:00), a 53-week year, empty tenant, revoked and agent identity certificates excluded, source classes against a real engine with an ACME order, an agent-linked account and a UI issuance, the cache (second call does not query, the next minute does), a CA-scoped role gets `authz.ErrDenied` before any query | `task generate`, `go test ./internal/report/... ./internal/ca/... ./internal/store/...`, `task check` |
| 46 | 0.3.8 | **Analysis rules.** New package `internal/analysis`: `Snapshot` (plain structs, §14.2), `Load` (reads through the engine, agents, ACME, domains and scan services with the system principal and builds the snapshot), ten rule functions `func(Snapshot) Result` with the ids, thresholds and texts of §14.2, `Run(snapshot) []Result` sorted by severity, rule and subject (at most 200 findings per rule, the rest only counted). One engine method `ca.Engine.CertificateTraits` returns signature algorithm and key size parsed from `cert_der` for the valid certificates (not a field of `CertificateInfo`, so list pages do not parse DER). The package imports no network package (a test checks the import list). Tests: a table per rule with the cases "fires", "does not fire", "boundary" and "unknown"; fixtures are built in the test; the SHA-1 and RSA-1024 DER cases use two committed, clearly marked fixture PEMs (Go refuses to sign them; the generation command is in the test comment); texts are asserted so a rule cannot claim more than its input shows | `go test -race ./internal/analysis/...`, `task check` |
| 47 | 0.3.8 | **REST and OpenAPI first.** `api/openapi.yaml`: `GET /reports` and `GET /analysis` (tag `monitoring`, `x-required-role: viewer`, 403 for a role limited to one CA, works while sealed, shapes in §14.2), schemas `Report`, `ReportWeek`, `Analysis`, `AnalysisRule`, `Finding`. Handlers in `internal/httpapi/reports.go` call `report.Build` and `analysis.Load/Run` after the permission check; `GET /analysis?rule=<id>` filters. Contract tests, a permission test per role (viewer ok, CA-scoped viewer 403, no session 401), a test that a finding with a hostile name (`<script>`, `"`, 4,000 characters) comes back as JSON data and clipped | `task check` (contract tests), `task lint:api` |
| 48 | 0.3.8 | **Chart rendering, server side.** New package `internal/web/chart`: `Spec` (kinds `columns`, `stacked`, `bars`; series with label, token class and pattern; categories; values; a one-sentence summary) and a templ component that writes a `<figure>` with `<figcaption>`, one `<svg class="chart-svg" role="img" aria-labelledby>` with `<title>` and `<desc>`, text labels and a legend (swatch plus text), and a `<details>` "Numbers" with the same data as a `.table`. Classes in `components.css` (`.chart .chart-svg .ch-bar .ch-axis .ch-grid .ch-label .ch-legend .ch-ok .ch-warn .ch-crit .ch-neutral .ch-s1 .ch-s2 .ch-s3`, hatch patterns for s2 and s3), tokens `--chart-s1..s3` and `--chart-grid` in `tokens.css` for light, dark and the OS-follow block (a test checks that every chart token has at least 3:1 contrast against `--bg` in both themes, WCAG 1.4.11). Status series use the fixed status tokens only. Test changes: `<svg>` is allowed only as `<svg class="chart-svg" …>` from this package, and inside it `<image>`, `<foreignObject>`, `<use>`, `href`, `style` and `on*` stay forbidden; the `.templ` scan exempts `internal/web/chart/` for `<svg` only. A gallery entry in `/design`. Tests: golden SVG per kind, label escaping (`<`, `&`, quotes; 5,000 characters clipped to 32 runes), zero values, one series, 13 and 26 categories, determinism (same input, same bytes) | `task generate`, `go test ./internal/web/...`, `task check` |
| 49 | 0.3.8 | **Pages.** `GET /reports` (`internal/web/app_reports.go`, `pages/reports`): five sections, each a `<details open>` with a heading, the chart, the summary sentence and the numbers table, plus "Computed at <time> UTC, refreshed every minute". `GET /analysis` (`app_analysis.go`, `pages/analysis`): a summary line ("3 findings: 1 critical, 1 warning, 1 info; 2 rules cannot be assessed"), the findings as a table (Severity, Rule, Subject, What was seen, Why it matters, What to do), then "Rules" with the state of every rule (ok, findings, unknown plus the reason) and a short "How this works" paragraph (rules in Go, nothing leaves the server). Dashboard: two charts (expiry timeline, certificates per CA and status) below the number row, each in a `<details open>`. The two sidebar entries and the dashboard charts appear only for a role that passes the tenant-wide `authz.ReadPKI` check (the test the alerts use). Tests: render for viewer, operator and admin and for a CA-scoped viewer (403 page, no nav entry), no inline style or script, every class defined, hostile CA, domain and certificate names escaped | `go test ./internal/web/...`, `task check` |
| 50 | 0.3.8 | **UI inventory.** `-inventory` mode for `internal/tools/screenshots`: shoots every parameterless GET page of the real UI (the route list is a Go slice next to `shots`; a test fails when `registerApp` gains a route that is neither in the list nor on an exclusion list) in light and dark at 1400 x 900 into `.tmp/ui-inventory/` (gitignored, never committed). The demo instance gets cheap seeds so the pages are not empty: alerts through the monitor store, endpoints through the scan store, back-dated issuances (a settable fake clock for the seeding only, then the real one); agent pages that need a live agent are read from their templ source and marked "not shot". The step then looks at each image and writes **`docs/UI-GAPS.md`**: one row per page (what was seen in light and dark, what is missing or odd, candidate fix, size S/M/L) and a ranked list of gaps; the roadmap candidates (global search, host view, chain view, CSV export, audit log filters, notification settings in the UI) are checked against what exists. No product code changes | `task screenshots -- -inventory` (browser path as for the normal run), `go test ./internal/tools/screenshots/...` |
| 51 | 0.3.8 | **Docs and release.** New `site/reports.md` (reading each chart and each finding, the rules table, "unknown" explained, what to do), `site/monitoring.md` and `site/tour.md` (pointers), `site/faq.md` and `site/glossary.md` (expiry wave, renewal loop, orphaned certificate, signature algorithm), `site/_data/nav.yml` (group Operate), a paragraph in `site/learn/lifetimes.md` on waves and jitter; OPERATIONS new §15 (pages, API, permission, cache, what is not stored, rules table); CHANGELOG `[0.3.8]` undated; the version bump in the files of `git show d30bf6f --stat`; PLAN §10.1 row v0.3.8, §7 "Technology: Charts" and the ECharts open point updated for D1; four new shots (`reports`, `analysis`, and their `-dark` variants) added to `shots`, `task screenshots` run once if a browser is there; this section gets "Built" notes | `scripts/ci/site-check.sh`, `task ci:local` (report every SKIP), `git diff --check` |

**Live test for the maintainer** (after the PR is merged to a test server; names are examples):

1. Update the server to v0.3.8. `myownpki db status` shows `pki.db` 0020; nothing else changed in the database.
2. Sign in as admin, open *Reports*. Compare "certificates per CA and status" with *Certificates* (`?status=valid`,
   `expired`, `revoked`) and the expiry timeline with *Certificates*, `?status=expiring`: the totals agree.
3. Issue one certificate in the UI and one with `certbot` or the agent, wait a minute, reload: the current
   week of "Issuances per week" shows one UI and one ACME or agent certificate; the table under the chart
   shows the same numbers. Tab through the page with the keyboard: every `<details>` opens, the focus is visible.
4. Switch to dark and to the OS theme; look at the legend and the hatching.
5. Open the browser console on both pages: **no CSP violation**, no failed request.
6. *Analysis*: read each finding and judge it. Expect the real oddities of the homelab (agents older than the
   server, domains nobody uses). Check one "orphaned certificate" finding by hand with `openssl s_client` on the
   host. With the TLS scan off, that rule must say "cannot be assessed", not "orphaned".
7. Issue the same name from two sources (UI and ACME): the duplicate rule fires and names both. Re-issue one
   name four times within a day with a script: the renewal loop fires.
8. As a viewer limited to one CA: no *Reports* or *Analysis* entry, and `GET /api/v1/reports` is 403.
9. `curl -s -H "Authorization: Bearer $TOKEN" https://pki.homelab.lan:9443/api/v1/analysis | jq '.rules[] | {id,state}'`.
10. Read `docs/UI-GAPS.md` and mark what to build next.

### 14.2 Rules and defaults

**Decisions** (D1 to D3 answer the hard questions of the brief; the maintainer reviews them later):

| # | Decision | Why |
|---|---|---|
| D1 | **Charts are server-rendered SVG in v0.3.8**: Go builds calm bars and columns, templ emits them as inline `<svg>` with global CSS classes, **no JavaScript**. The approved ECharts stays approved but unused; `THIRD_PARTY.md` gets no entry. The island path is §14.3, a separate step if the maintainer wants it | The six charts are bars and columns. ECharts has a documented, unresolved CSP problem (its HTML tooltip writes inline `style`: apache/echarts #19938, open, no maintainer answer; the fix PR #19717 was closed unmerged); whether 6.1.0 behaves is **not verified**. The product has no script pipeline, no `.js` content type and tests that forbid `<script>`, so an island adds a whole class of surface and about 1.1 MB for six simple charts. SVG works under the CSP today, follows dark mode through tokens, needs no JS and is testable as text |
| D2 | **No bundler, no esbuild.** Nothing in `go.mod` or the build changes; no Node anywhere | esbuild is a second dependency that is not approved (ADR-04, CLAUDE.md); D1 needs none |
| D3 | **The CSP is not loosened**, not for charts and not for a probe. If a later island cannot run under it, the island does not ship | A CA's admin UI with `unsafe-inline` is not acceptable for a chart |
| D4 | **Permission: the tenant-wide `authz.ReadPKI` check, like the alerts.** No new permission. A role limited to one CA gets 403 (API and UI) and no navigation entry | Reports and findings name CAs, hosts, accounts and domains of the whole tenant; a per-CA slice of alerts and agents does not exist. A new permission would add a role matrix for no gain |
| D5 | **Data is loaded through the existing services** with a system principal inside `report.Build` and `analysis.Load`, after the caller passed D4; the result is cached 60 seconds **per tenant** | Same reads as the monitor, no raw SQL in the web layer; everyone who passes D4 may see all of it, so a shared cache leaks nothing. A reload stays cheap with 10,000 certificates |
| D6 | **Source classes** (only `source = 'issued'`; imported and external certificates are not issuances): `acme` = an `acme_orders` row points at the certificate and its account has no `agent_id`; `agent` = same, the account has an `agent_id`; `ui` = no order (UI and API issuance, one class: same engine call). Agent identity certificates (`preset = 'client'`, `requested_by` an agent, as in `HideAgentCertificates`) are left out everywhere and the page says so | The only way the data tells them apart (§14 facts); documented so the numbers can be rebuilt by hand |
| D7 | **Weeks** are ISO weeks in UTC (Monday 00:00). Expiry timeline: the current week and 12 more (13 columns); the first counts only certificates that end after now. Issuances: 12 weeks ending with the current one. Alert history: what the store keeps, 30 days (5 weekly columns), and the caption says so; retention is not changed. A bar is `ch-crit` when its week starts inside the critical window, `ch-warn` inside the warning window (`monitor.Rules`), else neutral; the table repeats it as a "Window" column | Stable labels (2026-W47), testable borders, no clock in the SVG; color is never the only carrier |
| D8 | **Analysis is advice, not an alarm:** rules are pure functions over a snapshot, nothing is stored, **no dismiss or acknowledge** in v0.3.8, no new configuration keys (thresholds are constants in `internal/analysis/rules.go`, listed below), findings never produce alerts, e-mail or webhooks | A dismissal table needs a `system.db` migration and invites silencing; derived findings are recomputed. The monitor stays the one place that alarms (no duplicate of `cert_expiry`) |
| D9 | **Three states per rule: ok, findings, unknown.** A rule whose input is missing says `unknown` plus the reason ("the TLS scan is off") and produces no finding. Texts are fixed templates with numbers; a finding never states more than the snapshot shows ("no scanned endpoint served this certificate in 7 days", never "not used") | The brief's "no false claims"; an admin may revoke on the strength of a finding |
| D10 | **Severity is `info`, `warning` or `critical`**, shown as text and mapped to `--status-info`, `--status-warn`, `--status-crit`; an `info` finding is never a call to act | Fixed status colors (ADR-12); three levels are enough |
| D11 | **Nothing leaves the server.** `internal/analysis` and `internal/report` import no network package (tests); no external AI, no telemetry, no font or script from elsewhere | Findings contain internal names; PLAN says the page stays local |
| D12 | **Collapsing is `<details>`, the state is not remembered** (no JS, no storage). Reports: all sections open. Dashboard: two charts, both open | Native and keyboard-operable; remembering needs a cookie or a script (open point 6) |
| D13 | **UI inventory by the existing screenshot tool**, output untracked, the deliverable is `docs/UI-GAPS.md` | No browser-automation dependency, no committed images (every image stays in Git history); the maintainer reads one list |

**Data per chart** (all UTC; step 45 adds the queries named here):

| Chart | Source | Notes |
|---|---|---|
| Expiry timeline, 13 weeks | `ExpiryTimes`: `not_after` of non-revoked, non-agent certificates in (now, now + 13 weeks), via `certificates_not_after` | Bucketed in Go; contains the dashboard's "Expire in 30 days" |
| Issuances per week by source | `IssuanceSources` (D6), `created_at` from the start of the week 12 weeks ago, the new indexes of 0020 | At 85 issuances a day (PLAN scaling) about 7,000 rows; the cache absorbs reloads |
| Certificates per CA and status | `Engine.CertificateCounts(HideAgentCertificates)`: valid, expiring (30 days), expired, revoked per CA | Already scoped; status tokens ok, warn, crit, neutral, with text labels |
| Alert history | `monitor.Store.Since(now - 30 days)`: opened per week by severity, plus how many are still open | Tenant-wide `ReadPKI`, like the Alerts page |
| Agent fleet health | `agents.ListAgents` (plus the deployments; one extra sqlc query if the list does not carry them): active and seen within `AgentSilentWarn`, silent (warning, critical), disabled, revoked; version current, older, unknown; deployments by state | Hidden when the agent listener is off |

**Analysis rules.** The id is stable and appears in the API. `Snapshot` holds: now, the server version, the valid
end-entity certificates (name set, class, issuer key, CA, creation time, fingerprint, traits), the CA generations,
agents with deployments, endpoints with their last scan, ACME accounts with their last order, domains, `monitor.Rules`.

| Id | Fires when | Severity | Text (seen, why, what to do) | Unknown when |
|---|---|---|---|---|
| `orphaned_certificate` | a valid, current certificate is at least 14 days old, **no** agent deployment reports its serial as deployed, and at least one endpoint that covers one of its names was scanned successfully in the last 7 days and none of those scans saw its fingerprint | info | "No scanned endpoint and no agent served this certificate in 7 days. It may belong to a host that is gone. Check the host, then revoke it (second factor)." | scanning is off or no endpoint covers its names: then **one** summary line "N certificates are not covered by any scanned endpoint", never a per-certificate finding |
| `duplicate_certificates` | two or more valid certificates with the identical name set from at least two different issuer keys (ACME account, agent, UI), each with more than a third of its lifetime left; or three or more from one issuer key | warning (two sources) / info | "Two sources issue for the same names; the renewal overlap of one source is normal and ignored. One of them may be forgotten." Names the sources | the class of a certificate cannot be determined |
| `renewal_loop` | three or more certificates for the same name set created within 24 hours (critical at six), or eight within 7 days | warning / critical | "A client got N certificates for these names in a day. Usually a deploy hook that fails and rolls back, or a job that never stores the result. ACME servers rate-limit this." Names the source | never |
| `expiry_wave` | one calendar week holds at least 10 valid certificates **and** at least 30% of all valid end-entity certificates (the tenant has at least 20) | warning | "N of M certificates end in week W. Renewals that fail together become one big incident. Let ACME clients renew at two thirds of the lifetime and add jitter." | fewer than 20 valid certificates |
| `weak_key` | a valid certificate has an RSA key under 2048 bits (typically an import from `pki.sh` or an external certificate) | critical | "RSA N bits can be factored with moderate effort. Reissue with ECDSA P-256 or RSA 3072 and revoke the old one." RSA 2048 is **not** flagged | the key size cannot be parsed |
| `weak_signature` | a valid end-entity or intermediate CA certificate is signed with SHA-1, MD5 or MD2 (a root's own signature is irrelevant and ignored) | critical | "SHA-1 collisions are practical; the CA/B Forum Baseline Requirements ban SHA-1 for new certificates. Reissue from a CA that signs with SHA-256 or better." | the algorithm is unknown to Go |
| `ca_cliff` | the current generation of an issuing CA ends in less than the default validity new certificates get (the domain's `validity_days`, else 90): the engine shortens a default validity to the CA's end (`computeValidity`) and refuses a longer explicit request | warning; critical under 14 days | "This CA ends on D. Every certificate it issues from now on ends on D at the latest; K valid certificates already end that day. Renew the CA first (second factor)." The monitor's `ca_expiry` stays the alarm | the CA has no signed generation yet |
| `outdated_agent` | an active agent's version is older than the server's (`internal/version.Compare`): a minor or more behind is a warning, a patch only info | warning / info | "Agent X runs 0.3.2, the server runs 0.3.8. Update it from *Agents*, Update, or with the Salt formula." | the server version is `dev` or a version is not strict semver |
| `unused_acme_account` | a valid account without agent link is at least 30 days old and has no order in 90 days (or never) | info | "No orders for N days. It may belong to a retired client. An ACME client deactivates an account (RFC 8555 section 7.3.6); the UI cannot yet." Contacts are not shown | never |
| `unused_domain` | a domain at least 30 days old for which no certificate (any status) of the tenant has a name that `Domain.Covers` | info | "Nothing was ever issued under this domain. An approved name space nobody uses is a standing permission. Remove it or issue a first certificate." | never |

**REST shapes** (step 47; times RFC 3339 UTC; both answer `Cache-Control: no-store`):

- `GET /api/v1/reports` returns `generated_at`, `expiry.weeks[{start, count, window}]` (`critical|warning|none`),
  `issuances.weeks[{start, acme, agent, ui}]`, `authorities[{id, name, valid, expiring, expired, revoked}]`,
  `alerts{retention_days, weeks[{start, warning, critical}], open}` and `agents` (null when the listener is off:
  `{active, silent_warning, silent_critical, disabled, revoked, version{current, older, unknown}, deployments{deployed, pending, failed, rolled_back}}`).
- `GET /api/v1/analysis[?rule=id]` returns `generated_at`, `summary{critical, warning, info, unknown}`,
  `rules[{id, title, state: ok|findings|unknown, count, unknown_reason}]`, `findings[{key, rule, severity, subject,
  seen, why, recommendation, href}]`. `key` is `rule:subject id`, stable between runs. No field holds HTML.

**Accessibility.** Every chart is a `<figure>` with a caption and a one-sentence summary; the SVG has `role="img"`
with `<title>` and `<desc>`; the exact numbers are a real table in a `<details>` (keyboard operable, readable by
screen readers); every series has a text label and a pattern, so color never carries information alone; nothing
animates, so `prefers-reduced-motion` needs no special case; text is at least 12 px (`--fs-caption`); the SVG scales
with its `viewBox`, so the C-layout width works.

### 14.3 Dependency note and the island path (not built in v0.3.8)

**v0.3.8 adds no dependency.** No Go module, no JavaScript, no tool: `go.mod`, `go.sum` and `THIRD_PARTY.md` stay
unchanged (check after step 51: `git diff origin/main -- go.mod go.sum THIRD_PARTY.md` is empty). The maintainer's
approval of ECharts is kept for a later step. What that step takes (so the choice is cheap):

- **Artifact.** `dist/echarts.min.js` from the npm tarball of `echarts@6.1.0` (published 2026-05-19, older than
  two weeks; `latest` on 2026-11-13; Apache-2.0 per the registry). Size 1,121,883 bytes (jsDelivr file listing).
  Prebuilt subsets exist: `echarts.common.min.js` 715,020 bytes and `echarts.simple.min.js` 500,315 bytes (their
  content is not checked). A smaller **custom build needs Node and a bundler**, so it is not possible under
  ADR-04's no-Node rule; with esbuild approved, a tree-shaken build (bar, line, SVG renderer, grid, legend,
  tooltip) would be a fraction of that (an estimate, not measured).
- **Where and how.** `web/vendor/echarts/echarts.min.js` plus `LICENSE` (11,990 bytes), `NOTICE` (168 bytes) and the
  license of the bundled **zrender** (BSD-3-Clause as far as known; read it in the tarball), embedded with `//go:embed`
  and served as `/static/vendor/echarts/echarts.min.js?v=<first 12 hex of its SHA-256>` with `text/javascript;
  charset=utf-8` (add `.js` to `staticTypes`; on Windows Go takes types from the registry) and `Cache-Control: public,
  max-age=31536000, immutable` for the hashed URL only. Only the Reports page and the dashboard load it
  (`view.Page.Scripts`). `THIRD_PARTY.md` records version, date, license, size, SHA-256 and the registry's
  `dist.integrity` (sha512); a test hashes the embedded file and fails on a difference. The maintainer fetches the
  tarball (`curl -O https://registry.npmjs.org/echarts/-/echarts-6.1.0.tgz`) and compares it with the registry's
  integrity value; no `npm` in the build.
- **Island without a bundler.** `web/islands/pki-chart.js`, hand-written ES2020, one `customElements.define`, reads
  its data from a `data-spec` attribute the server fills (JSON, escaped by templ) and builds the option from the CSS
  tokens (`getComputedStyle`); the server-rendered SVG and table stay inside the element as the fallback. The test
  rules relax to "`<script src="/static/…">` without a body". If esbuild is approved later, the island becomes
  TypeScript in `web/islands/*.ts`, bundled during `go generate`, and the vendored file gives way to tree-shaken imports.
- **CSP, facts and gaps.** Known: the HTML tooltip of 5.5.0 writes inline `style` through `innerHTML` and violates
  `style-src 'self'` (issue #19938); `renderMode: 'richText'` was suggested there, with no reported result. `style`
  set through the CSSOM (`el.style.x = …`, `cssText`) is allowed by CSP; `setAttribute('style', …)` and markup are
  not. The `unsafe-eval` error reported for "ECharts" in a Grafana forum thread came from a plugin that evaluates
  user strings, not from the core, as far as the thread shows. **Not verified:** the behavior of 6.1.0, which style
  writes zrender's SVG renderer makes, and any `eval` in the core. The probe (first sub-step of the later island
  step): a test page served with the product's exact CSP, a `securitypolicyviolation` listener that writes into the
  DOM, ECharts with `renderer: 'svg'`, `animation: false`, `tooltip.renderMode: 'richText'`, and `msedge --headless=new
  --dump-dom`. Zero events: the island may ship. Any event: it does not (D3).

### 14.4 Security review list (for an independent reviewer)

1. **Permission before data:** `/reports`, `/analysis`, both API routes and the dashboard charts check the tenant-wide
   `authz.ReadPKI` first; the cache is read only after that. A viewer limited to one CA gets 403 and no nav entry;
   check that no parameter (`?rule=`) skips the check.
2. **Tenant isolation:** every query runs on the tenant's own `pki.db` handle; the alert read filters on `tenant`.
   Check that no cache key comes from request input and that two tenants cannot share an entry.
3. **Attacker text in output:** CA, domain, agent and certificate names come from CSRs, ACME and agents. Check that
   chart labels and findings go only through templ (no `templ.Raw`, no string-built SVG), that labels are clipped,
   that JSON fields hold no HTML, and that finding texts are fixed templates plus escaped values.
4. **CSP and markup:** no `style` attribute, no `<style>`, no script, no `href` or `<image>` inside the SVG; the test
   relaxation allows exactly one tag shape. Look at the console of a real browser for violations.
5. **No false claims:** the `unknown` path of each rule (no scan, no endpoint, a `dev` server version); an orphaned
   finding needs a successful scan within 7 days; texts say "not seen", never "unused".
6. **Read-only:** the routes are GET, change nothing and write no audit entry (reads are not audited today); the
   builder uses the system principal only after item 1 and never returns data to a caller who failed it.
7. **Resource use:** at most one build per tenant per minute, bounded loops (200 findings per rule, group sizes), no
   DER parsing of the certificate table outside the cache; a reload storm cannot hammer SQLite.
8. **Nothing leaves the server:** no outbound call in the two packages; no new dependency (§14.3).
9. **Migration 0020:** indexes only, no data change; a failed migration leaves 0019 intact (forward-only runner).
10. **Fixtures:** the two committed PEM fixtures are marked, contain no real name and no private key.

### 14.5 Risks

| Risk | Handling |
|---|---|
| ECharts is what the roadmap and ADR-04 name; D1 deviates | Flagged in §14.7 and, by step 51, in PLAN §10.1; the approval stays; §14.3 keeps the later step cheap |
| Inline `<svg>` needs a relaxed test and a new CSS family | The relaxation allows one tag shape from one package and forbids the dangerous children; the gallery shows every class (ADR-12) |
| Findings that cry wolf (duplicates during renewal overlap, a wave in a small tenant) | Overlap ignored, minimum counts, `info` for soft rules, `unknown` for missing data; the live test judges each finding |
| An orphan finding makes someone revoke a certificate that is in use (a host the scan cannot reach) | Needs a scan of a covering endpoint; the text says "not seen" and says to check first; revocation needs a second factor anyway |
| Migration number 0020 collides with `release/v0.3.7` or another branch | Take the next free number when the step starts; the live test names the number actually used |
| Seeding back-dated issuances in the demo instance (step 50) disturbs session or key timing | Fake clock only around the seed, restored before the first sign-in; if it proves fragile, seed by direct inserts in the tool and say so |
| No headless Edge or Chrome on the build machine | Steps 50 and 51 report "screenshots not taken" and finish the rest; `-browser PATH` as before |
| The cache hides a change for up to a minute | The page says when it was computed; a minute is the monitor's period |

### 14.6 Not in v0.3.8

- **ECharts, the `<pki-chart>` island, esbuild, any script** (§14.3); gridstack and a movable dashboard grid.
- **Dismiss, acknowledge or snooze** of findings, notifications or alerts from the analysis, thresholds in the configuration.
- **A longer alert history** (retention stays 30 days), per-CA or per-domain report slices, CSV or image export, a date picker, saved views.
- **The renewal heatmap and the key algorithm distribution** of PLAN §7 "Dashboards (initial scope)".
- **UI work from the gap list** (global search, host view, chain view, CSV export, audit filters, notification
  settings): only the list is delivered.
- **No ADR change** (ADR-04 stays; open point 1 asks), no change to the agent, ACME, CA signing or the agent protocol.

### 14.7 Open points (for the maintainer)

1. **D1:** server-side SVG instead of the ECharts island. Say yes (PLAN §10.1 and §7 follow), or ask for the island: then it
   becomes a step 48b with the CSP probe first (§14.3), and the script mechanism could serve the passkey button too.
2. **ADR-04** still says esbuild; D1 does not need it. Decide later whether to approve it (passkey button, TypeScript islands).
3. Are `ui` (UI and API together) and the exclusion of agent identity certificates the right source classes (D6)?
4. The thresholds of §14.2 (14 and 7 days, 20 certificates, 30%, 3 per 24 hours, 30 and 90 days) are defaults to try;
   configuration keys only if one proves wrong.
5. Dismiss or acknowledge for findings (needs a `system.db` migration) and a longer alert retention.
6. Should the open or closed state of the report sections be remembered per user (cookie, like the appearance)?
7. Not verifiable here, to check in the steps: the zrender license text, the content of the ECharts subsets, whether a role
   limited to one CA should get a reduced Reports page instead of 403, whether the deployments come with `ListAgents`,
   and whether a browser is available for steps 50 and 51.

### 14.8 Built notes

**Steps 45 and 46 (data layer and analysis rules).** What differs from the plan text, and why:

- **Migration `pki.db` 0020** is `0020_report_indexes.sql`: `certificates_created_at` and the partial
  `acme_orders_certificate`, nothing else (a test compares the schema before and after). `created_at` is stored with
  milliseconds (`audit.TimeFormat`) while `not_after` has whole seconds, so `IssuanceSources` takes its bounds in the
  millisecond format; compared as text, the two formats do not sort the same at a whole second.
- **`report.Service`** is the way in for the API and the pages (`Get(ctx, who)`: the tenant-wide `ReadPKI` check, then
  the one-minute cache); `report.Build` does no permission check. `analysis.Service` is the same for the analysis
  (`analysis.Analyze` = `Load` + `Run`). Both caches are fields of the tenant's service, not keyed by anything.
- **Deployments** come with `agents.GetAgent` per agent, like the monitor (open point 7): `ListAgents` carries none, so
  no extra sqlc query. The agent fleet counts an active agent that never reported as active (the monitor does not call
  it silent either); version and deployment counts cover the agents that are neither disabled nor revoked.
- **`Valid` of an authority includes `Expiring`** (the same as the Certificates page with `status=valid`); the stacked
  chart draws `Valid - Expiring`, `Expiring`, `Expired`, `Revoked`.
- **Extra engine reads** beyond `CertificateTraits`, because the rules need them: `CertificateOrigins` (issuer key and
  class by certificate), `CertificateNames` (every DNS name and IP, for `unused_domain`), `ACMEAccountActivity` (account,
  agent link, last order, for `unused_acme_account`), and the signature algorithm of a CA generation
  (`GenerationInfo.SignatureAlgorithm`, for `weak_signature` of intermediates). All keep the CA scoping.
- **`Snapshot` has `Recent`**: the certificates created in the last 7 days whatever their status. `renewal_loop` counts
  certificates, not valid certificates, so a loop whose predecessors are revoked or expired is still seen. It has no
  `monitor.Rules` field: no rule uses one, the thresholds are the constants of `rules.go`.
- **`orphaned_certificate`** needs more than "a scan did not see it": the endpoint stores only the fingerprint of its
  last good scan, so a witness is a covering endpoint that was scanned successfully in the last 7 days **and has served
  another certificate for at least 7 days** (`FingerprintSince`). Without such an endpoint the certificate is counted in
  the one summary line, never judged. A covering endpoint that serves the certificate, or an agent deployment in state
  `deployed` (matched by serial, ID or fingerprint), ends the check.
- **`Run` returns one `Result` per rule** in the order of the table; `Findings(results)` flattens them sorted by
  severity, rule and subject; `Summarize` counts every finding, also those beyond the 200 kept per rule.
- **A rule can be `unknown` for part of its input**: `Result.Unassessed` and `UnknownReason` also qualify a result with
  findings ("and N could not be assessed"). `duplicate_certificates` and `ca_cliff` use this for a certificate of unknown
  origin and a CA without a signed generation. `ca_cliff` also reports a CA that already ended (critical, own text).
- **`internal/analysis` imports `tlsscan`** for the endpoint type and the name matching; it reads the stored result of
  the last scan and never starts one. The import test bans `net`, `net/http`, `net/url`, `crypto/tls` and the other
  network packages in both new packages; `net/netip` only parses addresses.
- **Fixtures:** `internal/analysis/testdata/weak-key-rsa1024.pem` and `weak-signature-sha1.pem` (self-signed, names under
  `.invalid`, no private key; the OpenSSL command is in the header of each file).
- Not run on this machine: `go test -race` (no C compiler here; the packages are pure Go and the build is `CGO_ENABLED=0`).

**Step 47 (REST and OpenAPI).** What differs from the plan text, and why:

- **The handlers call `report.Service.Get` and `analysis.Service.Get`**, not `Build` and `Load`/`Run`: the services do the
  tenant-wide `authz.ReadPKI` check and the one-minute cache. The server builds both once (`Server.Reports()`,
  `Server.Analysis()`, in `internal/server/monitor.go`) with the monitor's `Rules` and `Release` as server version;
  `httpapi.Deps` has `Reports` and `Analysis`. The pages of step 49 take the same two services.
- **An unknown `?rule=` is 400** (`bad-request`, field `rule`, the valid ids named, the input never echoed), like a bad
  `?state=` of `GET /alerts`. The id is checked against the fixed rule list before anything is read, so a refused
  caller with a bad id sees 400 instead of 403; the list of ids is not a secret. An empty `?rule=` means no filter.
- **Schemas:** besides `Report`, `ReportWeek`, `Analysis`, `AnalysisRule` and `Finding` the spec has `ReportIssuanceWeek`,
  `ReportAuthority`, `ReportAlertWeek` and `ReportFleet`, so every week row has a named shape. `AnalysisRule.id` is an
  enum of the ten ids. There is no `external` flag on an authority: the certificates without a CA are the entry with an
  empty `id` and an empty `name`, last in the list.
- **`generated_at` is cut to whole seconds** in the JSON. `agents` is `null` while the agent listener is off (the key stays).
  An active agent that never reported counts as `active`. `Report.authorities[].valid` includes `expiring`.
- **`AnalysisRule.unknown_reason`** is a string, empty when there is none (an `ok` rule, or `findings` without a gap);
  `count` is every finding of the rule, `findings` holds at most 200 per rule. With `?rule=` the summary covers that rule only.
- **Tests:** the contract run covers both operations (viewer 200, a role limited to one CA 403, no role 403, no session 401,
  the 400); `internal/httpapi/reports_test.go` covers shapes, the cache by content, roles, API tokens (tenant-wide 200,
  limited to one CA 403), the refusal of a user of another tenant on the service the API uses, and a CA named with
  `<script>`, quotes and 4,000 characters (the finding clips it, the body holds no literal `<`). The API is bound to one
  tenant and takes none from the request, so "another tenant" is tested on the service, not over HTTP; the separate cache per
  tenant is tested in `internal/report`. `internal/server/monitor_test.go` checks the wiring.
- No CLI help or docs change: the plan names none; the API reference page of the site is step 51.

**Step 48 (chart rendering).** What differs from the plan text, and why:

- **No `internal/web/chart` package.** The chart is a templ component in the existing `components` package
  (`components.Chart(view.Chart)`, `chart.templ` and `chart.go` for the geometry), the plain description is
  `view.Chart` (the `view` and `components` packages import nothing else of the product), and the texts and the
  mapping from `report.Report` live in the new Go-only package `internal/web/charts` (`Expiry`, `Issuances`,
  `Authorities`, `Alerts`, `Fleet`). The step 49 pages call `components.Chart(charts.Expiry(rep.Expiry))` and so on;
  `charts.Fleet` returns three bar charts (states, versions, deployments) or nil while the listener is off.
- **Kinds:** `columns` and `bars` (one value per category, the color comes from the category's series: expiry windows,
  agent states) and `stacked` and `stackedbars` (one value per series). The CA chart is horizontal (`stackedbars`)
  because names are long; the other stacked charts and the expiry timeline are vertical.
- **The legend is drawn inside the SVG** (swatch plus text, wrapped in Go), not as HTML, so the hatch patterns
  (`pattern` per chart id: `s2` diagonal, `s3` horizontal lines) are the same in the plot and the legend. Chart ids are
  page constants (`chart-expiry` ...) and must be unique on a page: the patterns are found by id (the gallery's dark
  preview uses its own id for that reason).
- **Tokens:** `--chart-s1..s3` (light, dark, OS-follow) and `--chart-w` (480 px, the widest chart; the SVG scales below
  it, the viewBox is 360 units wide so a phone shows 12 px text at about 1:1). No `--chart-grid`: grid lines use
  `--border`, the axis `--border-strong`, text `--text-muted`. `TestChartColorsHaveContrast` checks 3:1 against `--bg`
  for the three series and the five status tokens in all three blocks.
- **Text safety:** every string from data is stripped of control and format characters (line breaks, bidi overrides),
  clipped (18 runes on an axis, 48 in the table and tooltip, 24 for series, 200 for title and summary; the plan said 32)
  and written by templ; attributes are plain decimals or constants; class names come from a fixed list.
- **Empty and extreme data:** all zero (or no category) renders the empty-state sentence and the caption, no SVG and no
  table; a zero value draws no bar; a non-zero value is at least 2 units; values are clamped to 0 .. 2^50.
- **Test rule:** `svg_rules_test.go` holds `svgViolations`: an `<svg` must be exactly
  `<svg class="chart-svg" role="img" aria-labelledby="..." viewBox="0 0 W H">`, not nested, closed, and with no
  `<script>`, `<foreignObject>`, `<image>`, `<use>`, `<style>`, `<a>`, `<animate*>`, `<set>`, `href`, `src`, `style=`, `on*=`
  or `javascript:` inside. The render tests use it on every page; the `.templ` scan allows `<svg` only in
  `components/chart.templ`, in the template form of the same shape.
- The gallery has a "Charts" section with sample data (fixed dates), the empty state, and one chart in the dark preview.

**Step 49 (pages).** What differs from the plan text, and why:

- **Routes and names:** `GET /reports` (nav key `reports`, label "Reports") and `GET /analysis` (`analysis`, "Analysis"), both in
  the navigation group Overview between Alerts and Endpoints and both `Primary`, so layout C and the top navigation of a
  small screen show them like Alerts. The code is `internal/web/app_reports.go`, `app_analysis.go` and the page packages
  `pages/reports` and `pages/analysis`. `AppDeps` has `Reports` and `Analysis` (interfaces `ReportSource` and
  `AnalysisSource`, one `Get(ctx, who)` each); `Server` hands the monitor's services over as `reportSource()` and
  `analysisSource()` (nil, not a typed nil, without monitoring: then the pages answer 404 "Monitoring is off." and the
  navigation has no entry). The permission is the services' own tenant-wide `authz.ReadPKI` check: a role limited to one
  CA gets the 403 page; the navigation entry is hidden by the same check as the Alerts entry.
- **New component `components.Fold(id, title, open)`:** a native `<details class="fold">` whose `<summary>` holds the `<h2>`
  (so each section has a heading for a screen reader, and the page has one `<h1>`). Classes `fold` and `fold-body` in
  `components.css`, a "Folds" entry in the gallery, `TestFoldStylesAreCalm`. The state is not remembered (D12).
- **Reports:** sections Expiry and Authorities open, Issuances, Alerts and Agents closed (the task for step 49 differs from D12's
  "all open"). The Agents section is left out when `rep.Agents` is nil (agent listener off). A plain
  sentence under each heading says what is counted and left out (revoked and agent identity certificates, the D6 source
  classes, 30 days of alerts). "Computed at <time> UTC. The numbers are refreshed at most once a minute." is the page
  description. A chart without data shows its empty-state sentence and, by the component's design (step 48), no numbers table.
- **Analysis:** the order is the summary line, Findings (a table: Severity as the status dot plus text, Rule, Subject as a link
  to the affected page when the finding has a path inside the UI, What was seen, Why it matters, What to do), Rules (rule,
  state, count) and "How this works". The rules table links a rule that has findings to `?rule=<id>`; `?rule=` limits the
  findings table and says so with a "Show all findings" link; an unknown id is a 400 page that does not echo it. A rule in
  state `unknown` shows as `unknown: <reason>` in the neutral status and never as a finding; a rule with findings and a gap
  says "findings; N not assessed: <reason>". The tables scroll sideways on a phone (not the adaptive layout: six wrapped
  columns were unreadable at 375 px). A finding link that is not a path starting with one `/` is dropped, the row stays.
- **Dashboard:** the two charts (expiry, authorities) sit below the "Expiring in the next 30 days" table, each in an open fold,
  with an "All reports" link, only for a caller who passes `ReadPKI`. A failed build costs the charts (a warning line, the
  cause in the server log), not the dashboard.
- **Tests:** `app_reports_page_test.go` covers the roles (viewer, operator and admin 200, a CA-limited role 403 with no entry and
  no dashboard charts, anonymous redirect to the sign-in page), the sealed server (both pages render with the sealed notice),
  no monitoring, hostile CA, subject, reason and link text, empty states, the unknown rule, the filter, unique ids, one h1
  and the h2 list per page. `reportPages` feeds the new pages into the HTML rules of `server_test.go` (no inline style or
  script, every class defined, tokens only, SVG shape).
- **Browser check** on the pages with canned data (light, dark, 375 px): no horizontal page scroll, legend and hatching
  readable in both themes. `serve --dev` is the prototype and has no real pages (Reports and Analysis are real-UI entries, shown
  disabled there), so the check used the real handler of the test instance.

---

## 15. Public trust portal: v0.3.9

Since v0.2.2 the public listener serves a trust page at `/` (OPERATIONS chapter 11): every active CA with its fingerprints, DER and PEM downloads, two Windows helpers and one guide per platform, all for the *first* root only. v0.3.9 turns it into a **trust portal**: the server picks the platform from the `User-Agent` (no script, the CSP stays strict), a manual list overrides it, the steps and commands are generated per root with the fingerprint in the text, iPhone, iPad and Mac get a `.mobileconfig`, and the agent can add its root to the system trust store on request. It also absorbs the `.mobileconfig` item of the backlog (PLAN §12). The release adds **no dependency and no migration**.

Goal of v0.3.9, measured on the live installation: a Windows, a macOS, an iPhone, an Android and a Linux device each end up trusting the root from `http://<server>/` with the shown steps, and a tampered download is refused by the commands that check it; an agent host with `system_trust` has the root in its system store and `curl https://<own-host>/` works without `--cacert`; with the trust page switched off every new URL answers 404.

Where this plan differs from the task text (read from the code, nothing was run; the graph in the main checkout located the files, the facts are from direct reads):

- **The portal is plain HTTP, not the server's own TLS.** `internal/server/server.go` serves the public listener with `http.Server.Serve` on a plain listener (default `:8080`, `:80` with `--public-port-80`); only the ACME listener can speak TLS (`acme.tls_issuer`). The chicken and egg is therefore worse than the task says: nothing protects the first download, and the page never says otherwise (decision 2). A reverse proxy in front may add TLS, from this PKI (same problem) or from a public CA (then the page is authentic; the plan does not depend on it).
- **The Windows helper deliberately has no expected fingerprint** (OPERATIONS §11.1: "never copy an expectation from the download page or helper itself"). The task wants a fingerprint inside the script text shown on the page. Both stand: the helper files stay as they are, and the *shown commands* embed the page's value with an honest label (decision 1b, open point 1).
- **There is no `myownpki ... fingerprint` command.** Out-of-band sources that exist: the admin UI (*Authorities*, root: SHA-256 and "Root SHA-256 for automation"), `myownpki ca show NAME` (prints `SHA-256` per generation, `cmd/myownpki/ca.go`) and `openssl` on the downloaded file.
- **The public handler has no rate limit, no access log, no counters and no audit entries**, and the repository has no metrics endpoint (Prometheus is phase 4). Decision 3 keeps it that way.
- **The agent has no separate pin.** `setup` verifies the root file against `--root-sha256` once and writes it as `ca_bundle` (root-owned, 0600, in the configuration directory, which the unit cannot write); the unit is sandboxed (`ProtectSystem=strict`, only `state_dir`, `paths` and `sandbox.write` writable), so it cannot write `/etc/ssl` or `/etc/pki`. Decision 4 puts the install into a root-run command, not into `run`.
- **The existing page names one root** (`Data.Example`, the first one) in all commands; with a renewed root both generations are listed but the guides ignore the second. The portal generates blocks per shown root.

### 15.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 52 | 0.3.9 | **Artifacts as pure functions.** New package `internal/trustkit` (standard library only, no HTTP, no database): `Root` (name, generation, DER, public base URL, common name), `Platform` (`windows`, `macos`, `ios`, `android`, `debian`, `fedora`, `firefox`, `java`), `SHA256Hex(der)`, `MobileConfig(Root) ([]byte, error)` (decision 1), `Guide(Platform, Root) []Block` (title, note, lines: the commands of decision 1; `Block` is data, templ escapes it). Refusal rule: the base URL must match a conservative pattern (`http` or `https`, host of letters, digits, dots and hyphens, optional port, optional path of `[A-Za-z0-9._~/-]`); otherwise no command is generated and the page says "download the file and compare by hand" (never a half-escaped command). Golden files `testdata/*.golden` from one **fixture root** (a throwaway self-signed certificate, committed, named and commented as never real; regenerated with `-update`) | Tests: the `.mobileconfig` parses with `encoding/xml` (DOCTYPE, `dict` pairs), carries the exact DER (base64 decodes to the fixture; with OpenSSL on the PATH `openssl x509 -inform DER -noout -fingerprint -sha256` agrees, else skip), `PayloadRemovalDisallowed` is `<false/>`, no date, no host name, no serial, no private data; the same root gives byte-identical output twice, another root gives other UUIDs and identifier; UUID version nibble 8 and variant bits; every checking command contains the root's 64 hex digits and the base URL and nothing else variable; hostile common names (`'; rm -rf / #`, `<`, quotes, newline, bidi controls, 10 000 characters) and hostile base URLs (quote, backtick, `$(...)`, newline, `%0a`, space, unicode, `user:pw@`) give either no command or text without those characters; `shellcheck` on the Linux blocks and a PowerShell parse of the Windows block when the tools exist (skip otherwise); `go test ./internal/trustkit`, `go vet`, `git diff go.mod go.sum` empty, `task check` |
| 53 | 0.3.9 | **Detection, routes, portal page.** `internal/trustkit/detect.go`: `Detect(ua) Detection` (decision 3: the first 512 bytes, ASCII fold, an ordered `strings.Contains` table, no regular expression). `internal/publish/trust.go`: `/` takes one optional query value `os` from an allow-list (`windows`, `macos`, `ios`, `android`, `debian`, `fedora`, `firefox`, `java`, `all`); anything else (unknown, empty, repeated, longer than 16 bytes) counts as not given; `Vary: User-Agent` always; the file route `/trust/{name}/{gen}/{file}` gains `profile.mobileconfig` (roots only, same checks and the same switch as the Windows helpers; `Content-Type: application/x-apple-aspen-config`, `Content-Disposition: attachment; filename="<name>[-<gen>].mobileconfig"` built from the validated CA name, 15 minute cache like the helpers). `internal/web/pages/trust/trust.templ` (then `task generate`): the warning and the out-of-band text first (decision 2); a table of the shown **roots** (name, common name, valid, SHA-256, DER, PEM); "Your system" with the detected platform and all platforms as links `?os=…`; the steps and commands of every shown root for the selected platform (no detection and no `os`: the chooser plus `?os=all`, which is today's all-in-one guide); the Firefox note when the agent string says Firefox; a short table of the intermediates (downloads only: "servers send them, install nothing"). Existing CSS classes only. The Windows helpers stay with their text. The setting `trust_page` keeps its name and meaning | Tests: a table of at least 30 user agents (Chrome on Windows, macOS, Linux and Android; Edge; Safari on an iPhone and on an iPad that claims to be a Mac; Firefox on Windows, Ubuntu and Fedora; curl; empty; NUL bytes; 10 KB; `<script>`; "Windows" repeated 5000 times; Cyrillic; "like Mac OS X" must give `ios`, "Linux" inside an Android string must give `android`); the page never contains a part of the user agent or of the query (a canary in both, absent from the body); `?os=<script>`, repeated and 2 KB values give the page without `os`; with `trust_page` off `/`, `/?os=windows`, `/trust/root/1/profile.mobileconfig` and both `.cmd` answer 404 while `/ca/root/1.crt`, `.pem` and `/crl/…` answer 200; CSP equals `TrustCSP` (no `script-src`), no `<script`, no `style=`, every class defined in `web/styles`, every link served; HEAD and `If-None-Match` work; a renewed root gives two blocks, an intermediate never gets commands or a profile; a benchmark of one request (reported, see risks). Manual: `curl -s -A 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)' http://127.0.0.1:8080/` and `curl -sI http://127.0.0.1:8080/trust/root/1/profile.mobileconfig`; `go test ./internal/publish ./internal/trustkit ./internal/web/...`; `task generate` leaves no diff; `task check` |
| 54 | 0.3.9 | **Admin UI.** The root's detail page (`internal/web/app_pki.go`, next to "Public base URL") gets "Trust portal" (the root's base URL plus `/`, or "switched off in Administration → Tenant settings") and a plain text block "Message for your users" (the URL, the SHA-256, one sentence that the value must match this page, one sentence about the second step on iPhone), shown as `<pre>` to copy by hand (no script, no clipboard button). The label of the `trust_page` setting in `app_admin.go` says "portal" and lists what it covers; `prototype.go` follows so `task dev` shows the same; `api/openapi.yaml` changes only the description of `trust_page` (same field, no schema change) *Built:* `internal/web/portal.go` (pure `portal` and `userMessage`, the address only through `trustkit.ValidBaseURL`), a "Trust portal" row and a `<pre class="pem">` block "Message for your users" on a root's page only (an intermediate shows neither; no new class, `/design` unchanged); the row says "Switched off in Administration → Tenant settings." while `trust_page` is off, and a hint without an address for an empty or odd base URL; the fingerprint comes from the generation's SHA-256 (the web layer has no DER), formatted with `trustkit.ColonHex`. Label of the setting: "Trust portal at / of the public listener (CA certificates, fingerprints, install steps per platform)" with a help text naming `/`, `?os=`, the profile and the Windows helpers and saying `/ca/` and `/crl/` stay served. `api/openapi.yaml` is left to step 57. | Web tests: URL and fingerprint in the block, absent when the setting is off, base URL escaped in the page; the setting label; `task check`; by hand in `task dev` |
| 55 | 0.3.9 | **Agent: root in the system trust store** (decision 4). `internal/agent/trust_store.go` and `trust_cli.go`, `config.go` (`system_trust` with `root_sha256`; `edit.go` `topLevelOrder`), `setup.go` (`--system-trust`), `cmd/myownpki-agent/main.go` (`trust install\|remove\|status`, a block in `config check`), `deploy/agent.example.yaml`. A seam `trustEnv` (os-release path, directories, runner, effective user) so tests use a fake runner and temp directories | Tests with the fake runner for both families (Debian and RedHat from `ID` and `ID_LIKE`; anything else refused): install writes the file and runs exactly one fixed argv; a second run is a no-op without a runner call; changed content is replaced; a failing hook restores the old state (file removed or previous content back) and reports bounded output; a pin mismatch, two certificates in `ca_bundle`, a non-CA, a not self-signed certificate, a symlinked `ca_bundle`, target or directory, and a non-root user are refused before any write; `remove` deletes only the fixed file and only when it holds the pinned root; `run` with the key set makes no runner call; `status` exit codes; `config check` output for off, installed, missing and pin mismatch (exit 1); an `agent.yaml` of 0.3.8 parses to the same `Config`, an older agent refuses the new key; the unit file and the drop-ins are unchanged (golden); `GOOS=windows` and `GOOS=darwin` build; `go list -deps ./cmd/myownpki ./cmd/myownpki-ctl` unchanged (`cmd/myownpki/deps_test.go`); `task check`, `task vuln`. One `trust install` and a TLS check inside the container of `scripts/ci/agent-e2e-systemd.sh` if that is cheap (open point 5) *Built:* `trust_store.go` (the seam `trustEnv`: file system root, runner, effective user; family from `os-release`; fixed targets and argv; hook with a fixed `PATH` and 60 s; rollback of a failed hook, for `remove` too), `trust_cli.go` (`TrustInstall`, `TrustRemove`, `TrustStatus`, the `config check` block), `cmd/myownpki-agent/trust.go`. Differences from the text: `install --no-record` (for a file Salt renders, so the key is not written and reverted each run) and `status --root-sha256` (the guard of the formula asks for the pin of the pillar, so a new `root_sha256` runs `install` again); `install` with another pin than the recorded one replaces the key (a renewal) after the new pin matched `ca_bundle`; `remove` needs a valid `agent.yaml` and a pin (the key or `--root-sha256`). `config check` exits 1 only when the pin does not match `ca_bundle`; "not installed" and "differs" are information (exit 0) while `trust status` exits 1 for both. `deploy/agent.example.yaml` is not changed (it is compared with the installed file by `setup`; the key is documented in the docs step). No test inside the container of `agent-e2e-systemd.sh`. |
| 56 | 0.3.9 | **Salt formula.** Pillar `myownpki:agent:system_trust` (boolean, default false, any other type refused like the other keys): the state `myownpki-agent-system-trust` runs `myownpki-agent trust install --root-sha256 <root_sha256>` with `unless: myownpki-agent trust status --quiet`, after `setup`, with no change to the service states; `false` and absent create no state (the docs say `trust remove` by hand: a formula that removes would surprise). `map.jinja`, `defaults.yaml`, `pillar.example`, the README table; test cases `debian-system-trust` and one refusal in `deploy/salt/test/cases`; the expectations in `scripts/ci/salt-test.sh` | The CI job `salt formula` (every pillar renders, the pass and the pin appear nowhere they should not); `bash scripts/ci/salt-test.sh --self-test`; `task ci:local` *Built:* the state `myownpki-agent-system-trust` after `setup` (`trust install --root-sha256 <pin>`, `unless` `trust status --quiet --root-sha256 <pin>`, `--no-record` when `config_source` is set), `system_trust` in `defaults.yaml`, `map.jinja` (a non-boolean is refused; `true` on an `os_family` other than Debian and RedHat is refused, because the agent would fail there on every highstate), the README, `pillar.example`; cases `debian-system-trust`, `refuse-system-trust-not-boolean`, `refuse-system-trust-suse`, and `system_trust: true` added to `redhat-arm64-config`. `scripts/ci/salt-test.sh` needed no change (cases are found by file name; its self-test already demands the key in `pillar.example` and the README). The render has not run on a machine with Salt: the CI job `salt formula` is its first run. |
| 57 | 0.3.9 | **Docs, screenshots, release.** Pages and OPERATIONS as in decision 7; CHANGELOG `[0.3.9]` (undated); the version bump of `d30bf6f` (README, `api/openapi.yaml`, `deploy/docker-compose.yml`, `deploy/install-agent.sh`, `deploy/install.sh`, `docs/OPERATIONS.md`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`); `internal/tools/screenshots` gets a `public` view kind (a second server with `publish.New(...).WithTrustPage(...)` on the tool's instance, which already has CAs) and two shots, `trust-portal` (`?os=windows`, because the headless browser's own agent string would decide otherwise) and `trust-portal-ios`; the live-test status below; PLAN §10.1, §12 and `CLAUDE.md` after the tag | `scripts/ci/site-check.sh`; every documented command checked against the code; `task screenshots` (at a milestone only; the maintainer decides whether the PNGs are committed, they stay in the history); `docs/RELEASING.md` |

**Live test for the maintainer** (a test server, one device per line; nothing touches production names):

1. Update the server to v0.3.9; `myownpki db status` is unchanged (no migration). Open `http://<server>/` in a desktop browser: the roots table, the fingerprint, the chooser. Compare the SHA-256 with *Authorities → the root* and with `myownpki ca show <root>` on the server.
2. **Windows:** `?os=windows` or detection. Run the PowerShell command for *my user*: Windows asks for confirmation (expected) and the root appears in `certmgr.msc`; then the same in an administrator window for *this computer*; then the helper `.cmd` with `/check`. **Tamper test:** point the host name at a stand-in that serves another file; the command prints a mismatch and imports nothing.
3. **macOS:** open the `.mobileconfig`, finish in *System Settings → Privacy & Security → Profiles*; Safari opens `https://` pages of the PKI without a warning; note how *Not Signed* looks and that removal works. Then the Terminal command on a second Mac, or after removing the profile.
4. **iPhone and iPad:** Safari, the profile with *Not Signed* shown, install, then *Settings → General → About → Certificate Trust Settings* (without it the page still warns). On an iPad that asks for the desktop site the page shows macOS: the chooser leads to the right steps.
5. **Android:** the user store steps; Chrome trusts the host, an app that targets API 24 or higher does not (as the page says).
6. **Debian or Ubuntu, then Fedora, Rocky or Alma:** the command block; `curl https://<pki host>/` works without `--cacert`; a block with a changed hash stops before `update-ca-certificates`.
7. **Firefox** (import dialog; `security.enterprise_roots.enabled` on Windows or macOS) and **Java** (`keytool` prints the fingerprint and asks before it trusts).
8. **Agent:** update one agent to v0.3.9 (agents first: an older agent refuses the new key). As root `myownpki-agent trust install --root-sha256 <hex>` prints the file and the hook; `trust status` exits 0; `config check` shows "system trust"; a second `install` changes nothing; a wrong hash is refused; `systemctl show myownpki-agent -p ReadWritePaths` is unchanged. `trust remove`, then `trust status` exits 1.
9. **Salt:** a minion with `system_trust: true`: `state.apply myownpki` installs it, the second apply changes nothing.
10. **Switch off:** untick the setting in *Tenant settings*: `/`, `/?os=windows`, the profile and both helpers answer 404; `/ca/…` and `/crl/…` still answer 200.

If a real device behaves differently from the page text (menu names, iOS and Android versions), the text is corrected before the release is published.

### 15.2 Decisions

The maintainer was not available; each row takes the cautious option. Review them together with §15.7.

| Topic | Decision | Why |
|---|---|---|
| **1a. `.mobileconfig`** | Route `/trust/<root>/<gen>/profile.mobileconfig`, roots only, generated per request from the certificate in `pki.db`, byte-identical for the same root (no date, no host name). Top-level dict: `PayloadType` `Configuration`, `PayloadVersion` 1, `PayloadDisplayName` (the common name, control characters removed, at most 64 characters, XML-escaped), `PayloadDescription` (fixed text), `PayloadIdentifier` `local.myownpki.root.<first 32 hex digits of the SHA-256>`, `PayloadUUID`, `PayloadRemovalDisallowed` **false**, `PayloadContent` with one dict: `PayloadType` `com.apple.security.root`, `PayloadVersion` 1, its own identifier (`...<fp32>.cert`) and UUID, `PayloadCertificateFileName`, `PayloadContent` the DER as `<data>`. UUIDs are the first 16 bytes of SHA-256 over a fixed label, a second label per UUID and the 32 raw fingerprint bytes, with version nibble 8 (RFC 9562 custom) and the variant bits set, in upper case. No `PayloadScope` (open point 2). The profile is **unsigned**: iOS and macOS show it as *Not Signed*; the page says so and why: a signature would need a certificate the device already trusts, which is what is missing. A renewed root has another fingerprint, so another identifier: both profiles can be installed side by side | Deterministic output can be tested by golden file and lets a profile be replaced instead of duplicated. Nothing private exists in a root, so nothing private can leak. Removable, because an admin who wants a locked profile uses MDM. The iOS second step (*Settings → General → About → Certificate Trust Settings*) is in the page text for iPhone and iPad, in the admin message and in the docs: without it iOS installs the root but does not trust it for websites |
| **1b. Commands per platform** | Generated by `trustkit.Guide` from the DB and the root's base URL (the one in every certificate), **never from the request**. **Windows:** the DER saved as `<name>.cer` (double-click, *Install Certificate*); the helpers of §11.1 stay the checked path (they elevate, show both fingerprints and ask for an independent value); new: a short PowerShell block that downloads the `.crt`, compares `Get-FileHash -Algorithm SHA256` with the 64 hex digits in the text and only then runs `Import-Certificate` into `Cert:\CurrentUser\Root` (Windows adds its own confirmation) or, in a PowerShell started as administrator, `Cert:\LocalMachine\Root`; on a mismatch it deletes the file and throws. **Debian and Ubuntu:** one chain `curl -fsS -o root.crt '<url>' && echo '<hex>  root.crt' \| sha256sum -c - && openssl x509 -inform DER ... && sudo install -m 0644 ... /usr/local/share/ca-certificates/myownpki-<name>.crt && sudo update-ca-certificates`, every line joined with `&&`, so a failed check stops the rest. **Fedora, RHEL, Rocky, Alma:** the same with `/etc/pki/ca-trust/source/anchors/` and `sudo update-ca-trust`. **macOS** (second path next to the profile): `shasum -a 256 -c`, then `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`. **Android:** the user store steps and the sentence that apps targeting API 24 or higher ignore user CAs unless their network security configuration opts in (Chrome and most browsers accept them), that a screen lock may be required and that menu names differ. **Firefox:** the import dialog; `security.enterprise_roots.enabled` for Windows and macOS only. **Java:** `keytool -importcert` **without** `-noprompt`, so keytool shows the fingerprint and asks. Each block says in one line that the embedded value only checks the download against *this page* | The task asks for a fingerprint in the shown text, and a failed hash must stop the chain. It proves the file is the one the page describes, not that the page is genuine (decision 2), so the label says exactly that and the real check stays the comparison with the admin UI. Windows `Import-Certificate` is used instead of `certutil` because it fails with an error object. Commands are text to read and paste: nothing is hidden behind a pipe. Quoting is safe because every variable part is either a hash or passed the pattern of step 52 |
| **1c. Scripts as files** | No new script is served. The Windows helpers stay as they are (generated from the DB, no request data). **No `curl ... \| sh`, no generated installer**, and the optional "script that prints what it does" is not built: the commands above are the readable form, and a Linux host that needs automation gets the agent option (decision 4) or Salt | A script built from request data is an injection point, a downloaded script is run without being read, and a second path to the same effect needs the same review twice |
| **2. Trust of the page itself** | The first block of the page is the warning, rewritten: the page comes over plain HTTP, so **nothing on it proves itself, not even the fingerprints**; compare the SHA-256 with a value obtained another way before anything is installed. Then "Where to get the value": the admin UI (*Authorities → the root*), `myownpki ca show <root>` on the PKI server, the administrator, a printout or the message of step 54. Text only, no QR code. The page never says "secure", never links an `https://` variant and never claims that a proxy's TLS helps; with a public CA in front of it the page is authentic, but the text does not depend on that. The Windows helper text of §11.1 stays | Server and page are served by whoever controls the path; saying less would be wrong. A fingerprint copied from the page and compared with the same page is no check |
| **3. A public, unauthenticated endpoint** | **Input:** only the `User-Agent` (first 512 bytes, ASCII case fold, ordered `strings.Contains` table, no regular expression, so no backtracking and linear time) and the optional query `os` (allow-list, one value, at most 16 bytes, otherwise ignored). **Output:** the platform name comes from a fixed table, never from the input; nothing of the request is written into HTML, a header, a file name or a command (templ escapes anyway). **Roots:** install blocks and profiles only for roots; intermediates appear in a downloads table; every valid, unrevoked generation of an active root, as today. There is no per-CA switch (open point 6). **Switch:** the existing tenant setting `trust_page`, asked per request, covers `/`, `?os=`, the profile and the helpers; `/ca/...` and `/crl/...` stay (certificates point to them). **Caching:** `Vary: User-Agent` always; `Cache-Control: private, max-age=300` when the page depends on the detected platform, `public, max-age=300` otherwise (explicit `os`, or no platform found); the profile 15 minutes with ETag like the helpers. **Headers:** `TrustCSP` unchanged (`default-src 'none'`, own styles and images, no script), `nosniff`, the existing page headers; `.mobileconfig` as `application/x-apple-aspen-config`, `Content-Disposition` only from the validated CA name. **No redirect** anywhere and no `Location` header. **Rate limit:** none (the public listener has none today, its timeouts and the 8 KiB header limit stay); the docs tell internet-facing installations to limit in the proxy. **Audit and counters:** none, no IP, no log line per request | A stranger can send any bytes as agent string: so the string selects a row of a table and nothing else. A hash-chained audit log must never be written by anonymous requests (security.md), and counts without a metrics endpoint would be state with no reader. A limiter needs a client address, which behind a proxy needs `trusted_proxies` logic the public listener does not have; the cost of a request (a list of CAs and a render) equals today's page |
| **4. Agent: root in the system trust store** | **Opt-in, off by default, a root-run command, never part of `run`.** `agent.yaml` key `system_trust: {root_sha256: "<64 hex>"}`: absent means off; the value is the pin. `setup --system-trust` (needs the `--root-sha256` it already requires) writes the key and installs after enrollment; for an existing host `myownpki-agent trust install --root-sha256 <hex>` does the same and records the key; `trust remove` deletes the file and the key; `trust status [--quiet]` is read-only (exit 0 only when the installed file is the pinned root). **Checks before any write:** `ca_bundle` is read with the checks of `setup` (regular file, at most 1 MiB, no symlink), holds exactly one PEM certificate, is a self-signed CA, and its SHA-256 equals the pin and the `--root-sha256` argument; the caller is root; `os-release` `ID` or `ID_LIKE` names `debian` or one of `rhel`, `fedora`, `centos`, anything else is refused. **Targets, fixed:** Debian `/usr/local/share/ca-certificates/myownpki-agent-root.crt` and `update-ca-certificates` (`--fresh` on remove); RedHat `/etc/pki/ca-trust/source/anchors/myownpki-agent-root.pem` and `update-ca-trust`. The file is written through a temp file in the same directory (0644), renamed, and the hook runs with a fixed argv, no shell, a fixed `PATH`, no proxy or `SSL_CERT_*` variables, 60 s, output bounded like hook output; a failed hook rolls the file back, so "file present" means "hook succeeded". Idempotent: identical content means no write and no hook. `remove` deletes only that file and only when it holds the pinned root. `config check` prints a block "system trust" (off; installed; not installed, with the command; pin differs from `ca_bundle`, exit 1). **Sandbox: no change**, because the confined process never writes the store; the install runs where `setup` and `sandbox sync` already run. **Salt:** pillar `system_trust` (step 56). **Ships in v0.3.9** as steps 55 and 56, independent of 52 to 54: if the review is not through, they move to the next release and the CHANGELOG and docs lose two paragraphs. Pure standard library, in `internal/agent`, so nothing reaches the server binary | The root is the one the host already pinned at enrollment, so the option adds no new trust decision, only a wider scope of the same one, and the docs say so: "the agent can add the CA that issues its own certificates; it never touches anything else". It also says what that scope is: every program on the host then trusts that root for every name, limited only by name constraints on the intermediates. Widening the unit's `ReadWritePaths` to `/etc/ssl`, `/etc/pki`, `/usr/local/share` and the keystore hooks of `update-ca-certificates` would give the always-running, network-facing process write access to the host's trust anchors; a root-run command in the admin's hands or in Salt needs none of it |
| **5. UI** | Portal: the layout and classes of the current page (`layout.Plain`, `.section`, `.table`, `.btn-row`, `.pem`/`.fingerprint` blocks, `.muted`, messages with a text label); tables for roots, platforms and intermediates, no cards, no icons, no new class unless one is unavoidable (then in `components.css` and the `/design` gallery). The chooser is a plain list of links; the selected one is marked in words. Admin: the root's detail page shows the portal URL (the base URL plus `/`) and the "Message for your users" block; the Authorities list is unchanged | `references/frontend.md`: calm and plain; the admin page is the out-of-band source the portal points to, so the URL and the value sit together |
| **6. Tests** | As in the steps: a Go test per artifact with golden files from one fixture root; the user-agent table with hostile rows; route tests with the page switched off; a CSP test; canary tests for reflection; the agent with a fake runner and temp directories (nothing touches `/etc`); a PowerShell and `shellcheck` check where the tools exist. No network, no real device in CI | Parsing the output (`encoding/xml`, `x509`, OpenSSL) is the project's rule; the golden files make every change of a command visible in review |
| **7. Docs** | `site/guides/trust-the-root.md` (the portal first, then per platform; its text about "the trust page" becomes the portal; no new page, so `nav.yml` stays), `site/learn/trust.md` (the first-download problem), `site/faq.md` (the trust page answers and the line that lists v0.3.9 as planned), `site/glossary.md` (trust portal, configuration profile, public listener), `site/tour.md`, `site/hosts.md` (`--system-trust`), `site/hosts/salt.md`, `site/cli.md` (`trust`), `site/upgrade.md` (agents first), `site/troubleshooting.md` (iOS, Android, `Not Signed`), `site/index.md`, the README line; `docs/OPERATIONS.md` chapter 11 (11.2 the portal and its routes, 11.3 the `.mobileconfig`; §11.1 gets one sentence on the commands) and a new §12.12 (the agent and the system trust store), §10.4 pointer; CHANGELOG `[0.3.9]` (undated; *Known limitations* names the live-test status); screenshots as in step 57 | The pages carry `sources:` front matter, so each lists the files it was checked against |
| **8. Review** | §15.4 is the checklist for an independent reviewer who reads only the diff | Same as v0.3.4 and v0.3.7 |

**Artifact reference (what step 52 generates and the golden files pin).** `<url>` is the root's `.crt` URL built from the CA's public base URL, `<hex64>` the lower-case SHA-256 of the DER (upper case in PowerShell), `<file>` the name the page already uses (`<name>`, or `<name>-<generation>` for an older generation), `<fp32>` the first 32 hex digits.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><array><dict>
    <key>PayloadCertificateFileName</key><string><file>.crt</string>
    <key>PayloadContent</key><data>BASE64 OF THE DER</data>
    <key>PayloadIdentifier</key><string>local.myownpki.root.<fp32>.cert</string>
    <key>PayloadType</key><string>com.apple.security.root</string>
    <key>PayloadUUID</key><string>UUID-2</string>
    <key>PayloadVersion</key><integer>1</integer>
  </dict></array>
  <key>PayloadDisplayName</key><string>common name, cleaned</string>
  <key>PayloadIdentifier</key><string>local.myownpki.root.<fp32></string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>UUID-1</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict></plist>
```

(The inner dict also carries `PayloadDisplayName` and `PayloadDescription`, the outer one `PayloadDescription`; fixed texts, left out above.) The Windows block is one `if`/`else` statement, so pasting it line by line cannot import after a failed check:

```powershell
$f = Join-Path $env:TEMP 'myownpki-root.cer'
Invoke-WebRequest -UseBasicParsing -Uri '<url>' -OutFile $f
if ((Get-FileHash -Algorithm SHA256 -Path $f).Hash -eq '<HEX64>') { Import-Certificate -FilePath $f -CertStoreLocation Cert:\CurrentUser\Root } else { Remove-Item $f; Write-Error 'SHA-256 mismatch: nothing was installed' }
```

```bash
# Debian, Ubuntu (Fedora, RHEL, Rocky, Alma: -out myownpki-<file>.pem, anchors/ directory, update-ca-trust)
curl -fsS -o root.crt '<url>' \
  && echo '<hex64>  root.crt' | sha256sum -c - \
  && openssl x509 -inform DER -in root.crt -out myownpki-<file>.crt \
  && sudo install -m 0644 myownpki-<file>.crt /usr/local/share/ca-certificates/myownpki-<file>.crt \
  && sudo update-ca-certificates
```

macOS replaces the last two lines of the chain with `shasum -a 256 -c -` and `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt`; Java ends with `sudo keytool -importcert -trustcacerts -alias myownpki-<file> -file root.crt -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit` (`changeit` is the public default, no `-noprompt`). Detection table, first match wins, on the first 512 bytes in lower case: `iphone`, `ipad`, `ipod` give `ios`; `android` gives `android`; `windows` gives `windows`; `macintosh` or `mac os x` gives `macos`; `cros` (ChromeOS, checked before `x11`) gives nothing; `ubuntu` or `debian` gives `debian`; `fedora`, `red hat` or `centos` gives `fedora`; `linux` or `x11` gives `linux` (both families shown). Firefox is a flag (`firefox/` and not iOS), not a platform.

### 15.3 Dependencies

**None.** `go.mod` and `go.sum` stay as they are; the guard in `cmd/myownpki/deps_test.go` stays green. `trustkit` uses `crypto/sha256`, `encoding/base64`, `encoding/xml` and `net/url`, with plain string building (no `text/template`); the agent part uses `os`, `os/exec`, `crypto/x509`. A plist library (`howett.net/plist`) would be one more module in the **server** binary for a file `encoding/xml` can write and read in this fixed shape; a QR library is excluded by the task. `trustkit` is imported by `internal/publish` (server); the agent does not import it and keeps its own root checks (`verifiedRoot`).

### 15.4 Security review (an independent reviewer checks, with the diff only)

- **Request data:** trace every byte of the `User-Agent` and of `?os=`: they reach only a table lookup and an allow-list comparison; no path of them into HTML, headers, file names, commands, logs or errors (the canary tests); no regular expression on them; caps (512 and 16 bytes) enforced before any work.
- **Generated text:** every variable in a command or in the profile is a hash, a validated CA name, a number, a base URL that passed the pattern, or XML-escaped certificate text; no `templ.Raw`, no `text/template` with unescaped fields; hostile CA, common-name and base-URL cases are in the tests; a failed pattern removes the command instead of escaping it.
- **Profile:** nothing but the public root; deterministic; no `PayloadRemovalDisallowed: true`; no payload type beyond `com.apple.security.root`; no scope, URL or webhook payload; the UUID rule is as stated.
- **Honesty of the page:** no sentence suggests that HTTP, the page or its fingerprints are verified; the *Not Signed* and iOS second-step texts are present; Android's API 24 limit is stated.
- **Exposure:** the new routes are unreachable with the setting off; `/ca/...` and `/crl/...` are not newly gated; nothing new on the admin or agent listener; no redirect; no state written by an anonymous request; `Vary` and `Cache-Control` as decided; CSP identical to the constant.
- **Agent:** the pin is checked on the file that is copied (read once, hashed, written from the same bytes, not re-read by path); no symlink at `ca_bundle`, the directory or the target; the temp file is created in the target directory with 0644 and removed on every error; the hook argv is fixed, the environment is cleaned, no shell; rollback on a failed hook; `remove` and `install` never touch another file in the directory; root is required; `run` has no code path to the trust code; the unit and the drop-ins are byte-identical; no secret exists in this feature (a root is public).
- **Dependencies and build:** an empty `go.mod` diff; `govulncheck` clean; neither `trustkit` nor the agent trust code adds a package to the other binary (`go list -deps`).
- **Docs:** the statement of what the agent option can do and what it implies (every program trusts the root; name constraints still apply) is in `site/hosts.md` and OPERATIONS §12.12.

### 15.5 Risks

| Risk | Handling |
|---|---|
| Someone alters the page in the network path, and the hash in a command is then the attacker's | Said on the page and in the docs (decision 2); the admin UI block and `myownpki ca show` are the reference; nothing in v0.3.9 can fix an HTTP page, only a public CA in front of it can |
| The embedded hash teaches people to skip the comparison | Order of the page: warning and sources first, commands after; each block names its limit; the helpers keep the stricter independent check; open point 1 offers a stricter alternative |
| Wrong guess of the platform (iPadOS sends a Mac string, Linux has no family in the string, Android in desktop mode) | The chooser is on every page; the macOS text names the iPad case; unknown Linux shows both families |
| A real device behaves differently (iOS and Android menus, macOS profile scope, `Not Signed` text) | I could not test any device; the live test and open point 2 cover it, and the page text is corrected before the release |
| Unauthenticated load: a render per request without a limiter | Same cost as the page today; the step 53 benchmark gives a figure, and a 30-second cache of the CA list is the first measure if it is high (not built now, because the switch must stay immediate and stale CA data is worse than load) |
| `update-ca-certificates` runs other hooks (Java keystores) and an old file may linger after a root renewal | Documented; `remove` uses `--fresh` on Debian; a renewal means a new `install` with the new hash, and the old file name is the same, so it is replaced |
| An older agent reads an `agent.yaml` with `system_trust` and refuses to start (`KnownFields`) | Same rule as dns-01: update the agents first (`site/upgrade.md`); the key appears only on request |
| The profile cannot be signed, so devices warn | Expected and documented; MDM or signing is a later idea |

### 15.6 Not in v0.3.9

- **A signed profile**, MDM payloads (Wi-Fi, VPN, ACME), Windows Group Policy, Intune or Jamf recipes, an Android `network_security_config` generator.
- **Installer scripts served as files**, `curl | sh`, a QR code, a clipboard button or any script on the page.
- **A trust page per tenant or per CA**, a "hide this root" switch, a setting that offers intermediates, a counter, a log or an audit entry for downloads, a rate limiter on the public listener.
- **The agent installing anything but its own pinned root**, other families (SUSE, Arch, Alpine), macOS and Windows agents, Java and NSS stores through the agent, automatic removal by Salt, a hook of the agent's `hooks:` allowlist for it.
- **Extending the Add host assistant** with the option (admins add `--system-trust` by hand; the page says so). No ADR change, no schema change, no API change except one description.

### 15.7 Open points for the maintainer

1. **The embedded fingerprint** (decision 1b) contradicts the sentence in §11.1 that no expectation may be copied from the page. I kept both, with the label; the stricter alternative is a command with `<paste the value from the admin UI>` the user must replace before it runs. Say which you prefer; §11.1 is edited to match.
2. **Nothing here was tested on a device.** Unverified: how iOS shows a profile-installed root and whether it still needs the *Certificate Trust Settings* step (the page says yes), the macOS result of a profile without `PayloadScope` (user or system) and its *Profiles* menu path, the Android menu names and the screen-lock requirement, whether `ImportEnterpriseRoots` works for Firefox on Linux (the page says Windows and macOS only), and `update-ca-certificates --fresh` on removal.
3. **No rate limit and no cache** on the public listener (decision 3); confirm, or ask for the 30-second cache of the CA list.
4. **Detection is approximate:** an iPad that asks for the desktop site and every Linux without a distribution token are guessed; the chooser covers them.
5. **CI cost:** a `trust install` check in the systemd container job and a PowerShell run of the Windows block on the Windows job are possible but add minutes; the plan has unit tests with a fake runner and a parse only unless you want more.
6. **No way to hide a root** from the portal (a CA of another purpose, say an agent CA that is a root): there is no such setting today and one would be a schema change. Say if you need it.
7. **Agent option:** only Debian and RedHat families; applied by command and Salt, not by `run` (to keep the sandbox); a root renewal needs a new `install`. Confirm, or accept that this part moves to the next release.
8. **Screenshots:** two PNGs enter the Git history for good; commit them or only use them in the docs build.
9. **Not verified here:** no Go build, test or `task` ran (documentation only); the page text, the Android and iOS facts and the PowerShell commands are written from knowledge, not tried; `graphify query` was available and truncated, so every reference comes from a direct read of the file named.

---

## 16. Preview and versioned settings: v0.3.10

v0.3.10 gives two "undo" building blocks (PLAN §10.1). A **preview** shows, before anything is signed, what an
issuance would produce: names, validity, extensions, the preset and the policy checks with the exact reason of
every refusal, the CA that would sign, its chain and the URLs baked into the certificate. **Versioned settings**
record every change to the rules (domains, ACME rate limits, the tenant settings) with who, when and an optional
reason, show a structured diff between versions and restore an old version as a *new* one. Undoing an issuance
stays what it is: revoke (RFC 5280 §5.2.3). Written on 2026-11-13 while the maintainer was away: the decisions in
§16.2 are cautious defaults for review, not agreements.

Goal, measured on the live installation: in the issue wizard the review step shows the policy result and the
chain, a request the policy refuses shows every reason and cannot be submitted, and the preview leaves no trace
(no certificate, key, outbox row or audit entry); a domain changed on purpose is restored from its *History* page
in two clicks, with the second factor, and the restore is a new version and an audit entry; two admins editing the
same domain never overwrite each other silently.

**Facts found in the repository (2026-11-13, `release/v0.3.10` = `origin/main` fc046f0; nothing was run):**

- **One funnel.** `ca.Engine.Issue` is called by the wizard (`internal/web/app_issue.go`), the REST API (`httpapi/pki.go`),
  ACME finalize (`acme/finalize.go`), agent enrollment, `RenewCertificate` and the server's own TLS certificate
  (`server/issuedtls.go`). `Engine.issue` is a straight pipeline: authorize, preset, `loadIssuer`, root check, sealed
  check, key (CSR parsed by `parseCSR`: 64 KiB, one PEM block, signature verified; or "the server may generate"),
  `customize`, `subjectAndNames`, `checkConstraints`, `checkEKULimit`, `computeValidity`, then one `reasons` list. Only
  after it come randomness (`generateKey`, `newSerial` inside `buildTemplate`), signing and `store`. The refusal audit
  entry is written by `Issue`, not by `issue`. That order makes a pure "plan" cheap, but nothing names it yet.
- **`POST /csr/inspect` exists** (`InspectCSR`, `renewcert.go`): it parses a CSR and lists what it asks for. It knows
  neither CA nor preset nor policy. The wizard's review step (`reviewRows`) is built from the form fields only and
  shows no policy result.
- **Surface drift found:** the REST path fills the tenant's subject defaults (`Request.SubjectDefaults`,
  `httpapi/pki.go:436`), the wizard does not (`app_issue.go` never sets them), although the setting says it fills fields
  "that neither the request nor the CSR gives". A preview built apart from the issue request would show one thing and
  sign another; this is why the request is built in one place (step 60).
- **Where the rules live.** Domains: `pki.db` table `domains` (per tenant), written only by `createDomain`,
  `updateDomain`, `deleteDomain` in `internal/ca/domains.go`, each in one `inTx` with `audit.Enqueue`. Tenant
  settings: one row of `tenants` in the shared `system.db` (17 columns, query `GetTenantSettings`), written only by
  `tenant.Store.Set`, again in one transaction with the outbox. **Presets are not data:** they are embedded files
  (`presets/*.yaml`, `preset.Builtin()`), no UI or API edits them. **Notification channels and their secrets are in the
  configuration file**, not in a database (the comment of `system/0014` says so). EAB keys, join tokens and API
  tokens have their own tables and are secrets or runtime state.
- **Permissions (`internal/authz`).** Domains need `ManageCA` (step-up, never with an API token); tenant settings need
  `ManageTenant` (no step-up), the enrollment mode additionally `EnrollMode` (step-up); `ReadAudit` is admin only (user
  names are personal data). CAs are retired, never deleted, and a CA's name never changes (trigger
  `cas_name_immutable`), so a stored CA name stays resolvable.
- **Numbers.** `pki.db` is at 0019 here and 0020 on `origin/release/v0.3.8` (`report_indexes`, indexes only);
  `system.db` is at 0014 on both branches; `audit.db` needs no change (an audit action is a string). v0.3.9 adds none.

### 16.1 Work plan

| # | In | Step | Verifies with |
|---|---|---|---|
| 58 | 0.3.10 | **The plan seam in the engine.** Split `Engine.issue` into `plan(ctx, req, now, commit bool)` and `commit(ctx, planned, now)`: `plan` is today's pipeline up to the `reasons` check (including `acmeRequest`, authorize, key checks, names, constraints, validity, `RenewalOf`) and returns a `*planned` (issuer, leaf, checked CSR, notes, dropped names) plus, as before, a `*DeniedError` with the reasons; `commit` generates the key if needed, builds the template, signs, runs `checkIssued` and `store`. `commit=false` differs in one place only: a sealed keyring is recorded (`Plan.Sealed`) instead of returning `keys.ErrSealed`. The checks become an ordered list `{name, problems}` (names and preset rules, name constraints, EKU limits, validity, key policy, renewal reference) whose concatenation **is** `reasons`, so the preview's refusal reasons are the real ones by construction. New file `internal/ca/plan.go`: `Plan` (allowed, reasons, sealed, checks, CA name, generation and maximum validity, preset name and description, subject, names, dropped CSR names, key algorithm and source, notBefore, notAfter, days, key usage, extended key usage, extension list, AIA and CDP URLs from `CertURL`/`CRLURL`, chain links with subject, SHA-256 and notAfter, notes, warnings) and `Engine.Plan`, which never writes, never audits and never reads `e.rand()`. `buildTemplate` loses the serial (set by `commit`) and tolerates "no key yet" (no SKI; the plan says "derived from the new key, RFC 7093"); `describeExtensions(tmpl, issuer)` lists basicConstraints (critical, CA:FALSE), keyUsage (critical), extendedKeyUsage (critical only where the preset says so), SKI, AKI, subjectAltName, AIA, CDP and `id-pkix-ocsp-nocheck`. Tests in `internal/ca/plan_test.go` (table, fake clock): **equivalence**, for every row `Plan` then `Issue` with the same request: `Allowed` equals "no error"; on refusal `Plan.Reasons` equals `DeniedError.Reasons` in order; on success the parsed certificate matches the plan (subject, SANs, notBefore, notAfter, key usage, EKU and criticality, the OID set of the extensions, AIA, CDP, chain fingerprints, notes, warnings). Rows: server, wildcard (base domain added), CN-derived SAN, custom key usage, validity capped and explicit, SAN types dropped from the CSR, name constraint and EKU-limit refusals, root CA refusal, expired CA certificate, blocked key, server-side key (SKI excluded), sealed (`Plan.Sealed` against `ErrSealed`), an ACME order. **Silence:** after `Plan` the row counts of `certificates`, `keys`, `outbox` and the audit log are unchanged, and an engine whose `Rand` fails the test when read proves that no serial, key or signature was drawn. A new extension in `buildTemplate` that `describeExtensions` misses fails the OID-set comparison | `go test ./internal/ca -run 'Plan|Equivalence'`; the existing `internal/ca`, `internal/acme` and `internal/agents` tests unchanged and green; `task check` |
| 59 | 0.3.10 | **Preview in the REST API, OpenAPI first.** `POST /api/v1/certificates/preview` (`previewCertificate`, tag `certificates`, `x-required-role: operator`, no step-up) with exactly the request body of `POST /certificates` (`$ref` to the same schema, same validation, same 64 KiB CSR limit, same `MaxBody`, unknown fields refused) and the response `CertificatePreview` (200; schemas `PolicyCheck`, `ChainLink`, `ExtensionInfo`). The handler shares one `issueRequest` builder with `issueCertificate` (extracted from `httpapi/pki.go`, including the tenant subject defaults). A refusal is a **200 with `allowed: false` and `reasons`** where issuance answers 422; 400 (malformed body), 401, 403/404 (role, unknown CA: exactly as issuance, via `Engine.CAName` and `authorize`), 413 and 415 stay. No serial field exists in the schema. `CertificatePreview.generated_at` and the description say the preview is not a promise: issuance checks again. `POST /csr/inspect` stays (parse only). Tests: contract test against the spec; a behavior table run against both endpoints (`allowed` equals 201 against 422, the reasons equal the 422 field messages, same status for the 403 and 404 cases); no audit entry and no row after a preview; a viewer gets 403; a CA-scoped operator gets 404 for another CA; an API token works (preview needs no step-up) *Built:* as planned, in `api/openapi.yaml`, `httpapi/pki.go` (`API.certificateRequest`: decode, validation, CA lookup, the request and the tenant subject defaults, used by `issueCertificate` and `previewCertificate`), `httpapi/preview.go` (the mapping of `ca.Plan`) and `routes.go`. Schemas `CertificatePreview`, `PolicyCheck`, `ChainLink`, `ExtensionInfo`; the descriptions say that `collected` means the check reports every problem it finds and all collected checks run before the refusal, and that `stopped_at` names the gate that ended the plan early (a gate hides the problems of the checks after it until it is fixed). The response lists objects that the plan did not reach as `null` (`ca`, `preset`, `subject`, `key`, `validity`, `aia_url`, `cdp_url`) and lists as `[]`; it has no `ca_id`, no serial and no CSR; a refused plan gives no validity, usages, extensions or URLs. `422` and `503` are not documented for the preview (a refusal is a 200; a sealed server previews and says `sealed: true`). The tests are in `preview_test.go` (agreement with issuance over 14 bodies, the same answers for the permission, format and size cases, a token, nothing written, sealed, every reason, hostile names, the equality of the two engine requests through the unexported `API.onRequest` test hook) and in the contract run. No new problem type, so `api/vacuum.yaml` is unchanged (`vacuum lint` passes with infos only). | `go test ./internal/httpapi`; `task lint:api`; `task check` |
| 60 | 0.3.10 | **Preview in the wizard.** `internal/web/app_issue.go`: one `a.issueRequest(c, st, cas)` builds the `ca.Request` for the preview **and** for `a.issue`, so the wizard now also applies the tenant subject defaults, as the REST path does (a test pins it). `renderIssue` calls `Engine.Plan` on the review step (after "Next" and after a refused issue) and replaces `reviewRows` with tables from the plan: *What will be issued* (subject, names, preset, key, validity in dates and days, key usage, extended key usage, the other extensions), *Policy* (one row per check: passed, refused or note, with its text), *Who signs* (CA, generation, chain with fingerprints, the AIA and CRL URLs) and the notes and warnings. A refused plan shows each reason as a message line, hides the "Issue certificate" button (Back stays) and says what to change; a sealed server keeps its warning; a plan that fails for an internal reason shows "The preview could not be computed" and leaves issuing possible (the engine decides again). "Prepared at hh:mm UTC; the checks run again when you issue." Files: `pages/certificates/issue.templ` and `IssueData` (`Plan *PlanView`; `CanIssue` = unsealed and allowed), `task generate`. Plain POST forms, no JavaScript; the CSR text is never echoed, only what the engine derived from it, escaped by templ *Built:* as planned, with one deliberate difference: **the wizard does not apply the tenant subject defaults and still sends `IgnoreCSRNames` for a CSR**, because the task for this step said the preview must show what the wizard really issues and the wizard's signing must not change. Decision 7 (the wizard starts applying the defaults) is therefore **not** implemented; the CHANGELOG must not list it as Changed, and the drift stays open for a decision of the maintainer. `app.issueRequest` (`internal/web/app_issue.go`) is the one builder: `app.reviewPlan` plans its request on the review step (`Engine.Plan`, after "Next" and after a refused or sealed submit) and `app.issue` issues exactly the same one. The unexported `AppDeps.onRequest` test hook records both; `TestReviewAndIssueSendTheSameRequest` proves they are equal in server-key mode, CSR mode and CSR mode with an IP and a custom validity, and that `SubjectDefaults` stays empty. The page is `pages/certificates/plan.templ` (`PlanView`, `IssueData.Plan`) filled by `internal/web/app_issue_plan.go`, which copies the plan and decides nothing. Sections: *Review* (verdict "Allowed" or "Refused" with the status dot, one message line per reason, "Prepared at hh:mm UTC", the forecast-not-a-promise line), *Policy checks* (Check, Result "Passed", "Refused" or "Refused, stopped here", Problems; a note names the check where it stopped and says the later checks were not run), *What would be issued* (preset, subject DN, names, key and its source, not before, not after, days, key usage, extended key usage, names left out of a CSR, and the line "Not before is this moment minus 5 minutes (a clock-skew allowance), not the time you submit; the CA state may change before you submit, and issuing checks everything again."), *Extensions* (Extension, OID, Critical, Detail), *Who signs* (CA, key generation and maximum validity, the AIA and CDP URLs), *Chain* (issuing CA first, root last, SHA-256 in two lines of 16 bytes, expiry) and *Notes and warnings*. A refused plan shows only what it reached (no validity, usages, extensions or URLs), switches "Issue certificate" off (`CanIssue` = unsealed and allowed) and says "Use Back to change the preset, the names, the key or the validity."; Back stays. A sealed server shows "The server is sealed – issuing is possible after an unseal." inside the plan. If no plan can be made (an invalid state, an engine error) the page says "The preview could not be computed. The checks run when you issue." and keeps the old summary rows, so issuing stays possible. A refused submit keeps "Nothing was issued – the policy refused the request." and shows each reason once (the plan lists them; the duplicate message lines are dropped). Everything is templ-escaped; the CSR text is never echoed. The only CSS change is `.form { grid-template-columns: minmax(0, 1fr) }`: without it the widest table made the whole form 986 px wide at 375 px; no new class, so `/design` is unchanged. Tests are in `app_issue_plan_test.go` (allowed, refused, stopped at a gate with a 1024-bit RSA CSR, sealed, hostile text, request equality, nothing written: row counts of certificates, names, keys, outbox, blocked keys and both audit logs, permission), and `realPages` gained the refused, hostile and sealed review pages for the inline-style, class, token and SVG scans. Checked in a browser at 375 px and in light and dark: no page overflow, the tables scroll inside their wrapper. | `go test ./internal/web ./internal/web/pages/...` (page tests: refused plan, allowed plan, sealed, a CSR with a hostile CN such as `<script>` and a SAN outside the domain, the review request equal to the submitted one, no subject defaults); the inline-style and script scan; a screenshot walk of the review step in light and dark |
| 61 | 0.3.10 | **Version store and diff.** Migrations `pki.db` **0021** and `system.db` **0015**, both `settings_versions` (`id AUTOINCREMENT`, `kind`, `object_id`, `version`, `change` in create/update/delete/restore/baseline, `schema`, `snapshot_json` with `json_valid`, `snapshot_sha256`, `actor_type`, `actor_id`, `actor_name`, `reason` (at most 200 characters), `restored_from`, `created_at`; `UNIQUE (kind, object_id, version)`; triggers that abort `UPDATE` and `DELETE`, as `audit_entries` has). No `kind` CHECK, so later kinds need no table rebuild; Go allows `domain` and `tenant`. sqlc queries per database (`queries/pki/settings_versions.sql`, `queries/system/settings_versions.sql`), `task generate`. New package `internal/settingsver` without imports of `ca` or `tenant`: `DomainSnapshot` and `TenantSnapshot` (explicit structs, closed field lists, `schema` 1, canonical JSON), `Fields()` as an ordered list `{key, label, values []string}`, `Diff(a, b) []FieldChange` (key, label, before, after, kind changed/added/removed; lists compare as sets, never a text diff), `Backend` (insert, latest, get, list), `Append` (next number, expected-version check returning `ErrConflict`, reason check without control characters, SHA-256 of the canonical snapshot) and `List` (newest first, cursor). Adapters over the sqlc packages in `internal/ca/versions.go` and `internal/tenant/versions.go`. **Secret guard:** `TestSnapshotsHaveNoSecrets` (reflection: every snapshot field is on a reviewed allow-list and none matches `password`, `secret`, `token`, `key`, `credential`, `passphrase`) and `TestEveryColumnIsClassified` (`PRAGMA table_info` of `tenants` and `domains`: each column is either in the snapshot or on an explicit "not a setting" list), so a future column fails the test until someone decides | Unit tests: golden diffs for both kinds, set semantics of lists, schema 1 round trip; the append-only triggers (update and delete abort); the `UNIQUE` backstop; migration forward on an empty and on a populated 0020 database; `go test ./internal/store/... ./internal/settingsver`; `task generate` leaves no diff *Built:* migrations `pki.db` 0021 and `system.db` 0015 (`0020` of `pki.db` is v0.3.8's), the table as planned (`kind` has a length check but no list of kinds; `reason NOT NULL`, at most 200 characters; `CHECK ((change = 'restore') = (restored_from IS NOT NULL))`; `json_type = 'object'`) plus a **third trigger**, `settings_versions_no_replace` (`BEFORE INSERT` when the version or the `id` exists): `INSERT OR REPLACE` removes the row it replaces **without firing the `DELETE` trigger** (SQLite does that only with `recursive_triggers` on), so the two planned triggers alone are no wall; the `UNIQUE` stays behind it as the second layer (the test drops the trigger to prove it). Queries `settings_versions.sql` per database (insert, latest, get, list newest first with cursor, latest of every object of a kind, which is how a deleted domain is found). `internal/settingsver`: `DomainSnapshot` (the domain's own settings; the CA by ID only, so a CA rename is no change) and `TenantSnapshot` (nested `acme`, `agent_predecessor`, `other_predecessor`), `Fields()` (keys like `acme.orders_per_account`; an unset value has no entries, which is what makes `added` and `removed` happen), `Diff(a, b)` (every field compares as a set; `nil` means nothing), `Canonical` (struct order, no HTML escaping, hash of the bytes; at most 64 KiB), `Decode` (closed: unknown fields and trailing data are `ErrCorrupt`, unknown schema `ErrUnknownSchema`), `Version.Decoded` (checks the hash first). Writers call `Current` (the ETag number), `CheckExpected` (a `*ConflictError`, `errors.Is(ErrConflict)`, carrying the newest version: number, actor, time), then `Append(ctx, backend, Entry)`, which does the check again, writes the baseline if the object has no history and the change is an update or delete (it then needs `Entry.Before`), and the version; a restore needs `RestoredFrom` (must exist) and an object with history, a create needs none. Readers use `Get`, `List` (page with `Next` cursor), `DiffVersions(from, to)` (`from = 0` = nothing before) and `Backend.LatestOfKind`. `PKIBackend(pkidb.New(tx))` and `SystemBackend(systemdb.New(tx))` live in `settingsver` itself, **not** in `internal/ca/versions.go` and `internal/tenant/versions.go` as the plan said: the package already imports only the sqlc packages, so both backends are tested against the real databases and step 62 adds no import. **Guards:** `PRAGMA table_info` lists every column of the `STRICT` tables `tenants` and `domains` (the test also compares it with `pragma_table_list.ncol` and asserts `strict = 1`), so the open question of §16.5 is answered; `TestEveryColumnIsClassified` and `TestSnapshotsHaveNoSecrets` (closed kinds only: bool, string, int, `[]string`, nested structs of the package; secret words are matched per word, `keygen` is not `key`) are tested themselves with a deliberately bad struct. Not classified as versioned: `domains.id`, `created_at`, `updated_at`, `tenants.id`, `name`, `created_at`, each with its reason in the test. `go test -race` could not run (it needs cgo, which is off here); the concurrency test runs eight writers in one process and is exact because the writer connection is single. |
| 62 | 0.3.10 | **Wire the writers: record, baseline, conflict.** `createDomain`, `updateDomain`, `deleteDomain` and `tenant.Store.Set` append a version **in the same transaction** as the change and its audit entry (a failed audit or version write rolls everything back; nothing is half recorded). The first change of an object without versions first appends a `baseline` version of the state *before* the change (actor "system, before history"), so the very first mistake can be undone; a delete stores the deleted state. New optional `ChangeOptions{ExpectedVersion *int64, Reason string}` on `DomainSettings`, `DomainRequest` and a `Store.SetWith` (`Set` keeps its signature and calls it with none): a given `ExpectedVersion` that is not the latest number (0 = none yet) returns `ErrConflict` before anything is written, inside the writer transaction, so two writers cannot both pass. Audit details of `domain.create`, `domain.update`, `domain.delete` and `tenant.settings` gain `version` and `snapshot_sha256`; the reason stays out of the audit log (free text, security.md). `Engine.DomainVersion` and `Store.Version` give the ETag number. Tests: baseline then change gives versions 1 and 2; two concurrent updates with the same expected version: exactly one wins, the other gets `ErrConflict`, numbers stay contiguous; a forced audit failure leaves neither row change nor version; a delete is recorded; the audit `snapshot_sha256` equals the stored hash; every existing domain and settings test stays unchanged | `go test ./internal/ca ./internal/tenant ./internal/audit`; `go test -race` on the concurrency tests; `task check` *Built:* all four writers record a version in their own transaction (`createDomain`, `updateDomain`, `deleteDomain` in `pki.db`, `tenant.Store.SetWith` in `system.db`); a grep for every writer of `domains` and `tenants` (sqlc queries, REST, UI, tools) found no other path: the import and the backup restore replace whole databases (the history travels with them), the tools only call the engine, and the raw SQL that remains touches `created_at` in a screenshot seed and `step_up_minutes` in tests. `ChangeOptions{ExpectedVersion, Reason}` exists **twice**, in `ca` (field `DomainSettings.Options`, so also `DomainRequest.Options`; `Engine.DeleteDomainWith`) and in `tenant` (`Store.SetWith`, which returns the version it wrote): `tenant` must not import `ca`, and `settingsver` was left as step 61 built it. `Domain.Version` (set by create, update and `GetDomain`) and `Settings.Version` (set by `Get`) carry the ETag number; both read the version **before** the row, so a change in between gives an older number than the body and a later `If-Match` fails instead of overwriting it; `ListDomains` and `DomainFor` leave it 0. Inside the writer transaction the order is: conflict check, re-read of the row (the baseline, and `ErrNotFound` when the domain was deleted meanwhile, which used to be a silent no-op update), change, `Append`, audit entry. `tenant.SetWith` checks the expected version **before** the second-factor check, so an out-of-date form says so before it asks for a confirmation that would be wasted; a refused mode change writes nothing. A domain conflict is audited like another refused domain change (`failure`, with the error text); the reason is checked early (422 `policy-violation` / `ErrInvalid`) and never reaches the audit log. **REST:** the ETag is the quoted decimal version (`"7"`, `"0"` = no history yet) on `GET /domains/{id}`, `GET /settings` and on the answers of `POST`/`PATCH` `/domains` and `PUT /settings` (pulled forward from step 63, otherwise nobody could know the number); `If-Match` accepts exactly one such value (weak ETags, `*`, lists and non-numbers are 400 `bad-request`); a mismatch is 412 `precondition-failed` with the extra members `current_version`, `changed_by`, `changed_at`; `precondition-required` (428) is in the problem list but no response component yet (vacuum fails on an unused one), step 63 adds it with the restore. The optional write-only `reason` is in the `PATCH`, `PUT` and `POST` bodies now (not in `DELETE`, which has no body). **UI:** the domain change form, the domain delete form and the settings form carry the hidden `base_version`, which joins the `a.protected` lists (so it survives the second-factor detour); a stale save redirects to the page with the flash "Changed by *name* at *time* UTC while you were editing – your change was not saved"; a form without the field is not checked, a malformed one is refused. The 409 page that keeps the typed values and the reason field are step 64. Tests: `internal/ca/domains_versions_test.go`, `internal/tenant/versions_test.go` (versions 1, 2, 3 and the baseline, contiguous numbers, conflict and its audit entry, six concurrent writers with one winner, a trigger-injected failure in the outbox and in `settings_versions` rolls everything back including the baseline, audit `version` and `snapshot_sha256` equal the stored row, reason absent from the audit log), `internal/httpapi/versions_test.go`, `internal/web/app_versions_test.go`; all earlier tests are unchanged. `go test -race` could not run (no cgo). |
| 63 | 0.3.10 | **History and restore: engine and REST, OpenAPI first.** Engine: `ListDomainVersions`, `GetDomainVersion`, `RestoreDomain(ctx, id, version, opts, who)` and `ListDeletedDomains`; `Store.Versions`, `Store.Version`, `Store.Restore`. **One code path:** a restore turns the stored snapshot into a `DomainSettings` (or `Settings`) and runs the ordinary `createDomain`/`updateDomain` (or `Set`) logic with `change = restore`, so `checkDomain` (CA active, online key, name constraints, EKU limit, maximum validity, preset exists, challenge rules) and the tenant validation refuse everything a normal change would refuse, with the same reasons. A version that points at a CA that is retired or a preset that is gone is refused with those reasons (422 `policy-violation`); so is a domain name taken by another domain. Restoring the state that is already current is refused (409 `conflict`, "identical"). Permissions: `ManageCA` (step-up, not for tokens) on the current CA and on the version's CA; `ManageTenant`, and `EnrollMode` when the mode differs, because `Set` checks them. Reading history needs `ReadAudit` (and `ReadPKI` on the domain's CA, 404 otherwise). A detail read answers `restorable` and `restore_problems` from the same checks without writing. Audit actions `domain.restore` and `tenant.settings_restore` (version, restored_from, the changed keys, snapshot hash; refusals are audited like other domain changes). OpenAPI: `GET /domains/{domainId}/versions`, `GET /domains/{domainId}/versions/{version}` (`against=previous` by default, `current` or a number: the diff), `POST /domains/{domainId}/versions/{version}/restore` (body `reason`), `GET /domains/deleted`, and the same three under `/settings/versions`; `ETag` on `GET /domains/{id}` and `GET /settings`; optional `If-Match` on `PATCH`, `DELETE` and `PUT`, **required** on a restore (428 without, 412 on a mismatch; new problem types `precondition-failed` and `precondition-required`); optional `reason` in the `PATCH`, `PUT` and `POST` bodies. Tests: restore of an update, of a delete (same ID, name free), a retired CA, a missing preset, a taken name; no fresh step-up gives `step-up-required`, an API token gives `forbidden`, a viewer and an operator get 403 (history: 404 for an unreadable CA); an enrollment-mode restore needs step-up, a restore that leaves the mode alone does not; 412 and 428; restoring twice in a row; the restore creates version n+1 and an audit entry and never edits version k; contract and behavior tests *Built:* as planned; the spec came first (`e5e9f21`), with the operations `listDomainVersions`, `getDomainVersion`, `restoreDomainVersion`, `listDeletedDomains`, `listSettingsVersions`, `getSettingsVersion`, `restoreSettingsVersion`, the response component `PreconditionRequired` (the one step 62 left for this step), the parameters `IfMatchRequired`, `VersionNumber` and `Against`, and paging as in `/audit` (`before`, `limit` 1 to 100, `next_before`). `internal/settingsver/read.go` adds `Compare` (one version and its diff against `previous`, `current` or a number, 0 = nothing), `PageChanges` (the keys each version of a page changed; nil when a snapshot is unreadable, so a damaged row never breaks the list), `Same`, `Keys`, `ErrIdentical` and `ErrPreconditionRequired`. Engine: `internal/ca/restore.go` (`ListDomainVersions`, `GetDomainVersion`, `DomainRestoreCheck`, `RestoreDomain`, `ListDeletedDomains`) and `internal/tenant/restore.go` (`Versions`, `VersionDetail`, `RestoreCheck`, `Restore`; `Store.Version` is step 62's). **One path:** `RestoreDomain` sets the unexported `ChangeOptions.restore` and calls the existing `updateDomain` (the domain exists) or `createDomain` (it is deleted: same ID, name checked again), which then record `restore` and audit `domain.restore`; the tenant side moved the body of `SetWith` into `Store.set`, which `SetWith` and `Restore` share, and `validate` was extracted. The dry run (`restore.dry`) goes through the same functions up to the write. Decisions and details: reading a history needs `ReadAudit` **tenant-wide**, so an admin of one CA gets 403 (the audit log is tenant-wide too) and a viewer of another CA gets 404 for a domain and 403 for the settings; a restore needs what the same change needs, so restoring a *deleted* domain is a create and needs a tenant-wide admin, while restoring an existing domain needs `ManageCA` on its CA, and moving it back to another CA needs that CA as well; the engine answers 428 only **after** the permission checks (a token gets `forbidden` before it hears about `If-Match`, which is why the contract run can replay the restore with a token); a stale `If-Match` is 412 before a list of reasons (checked early and again inside the writer's transaction); `restorable` and `restore_problems` leave out a missing second factor but name an API token's refusal; `against=current` compares with the live state, and with nothing for a deleted domain (`from: 0`); a snapshot of an unknown schema or one that does not match its hash is 409 `conflict` with a clear detail on detail and restore, and `changed_keys: null` in the list; a restore body is required (`{}` for no reason) because every body route needs JSON; the `ETag` of the list and of a version is the newest version number of the object, and the answer of a restore carries the new one. `tenant.Store` has no audit database, so a refused tenant restore is audited with its own outbox transaction (`tenant.settings_restore`, denied or failure, with `restored_from` and the error text, never the reason); a missing version is not audited, as for domains. Tests: `internal/ca/restore_test.go`, `internal/tenant/restore_test.go`, `internal/settingsver/read_test.go`, `internal/httpapi/history_test.go` and `history_more_test.go` (the permission matrix for viewer, operator, tenant admin, admin of one CA, viewer of another CA, token and nobody, list paging, the diffs including `from = 0` and a deleted domain, restore of an update, of a delete, retired CA, missing CA, missing preset, taken name, 428, 412, 409, concurrent restores with one winner, audit entries, no secrets in any answer, hostile reasons as data) and the contract run, which now covers the seven operations. `go test -race` could not run (no cgo). | `go test ./internal/ca ./internal/tenant ./internal/httpapi`; `task lint:api`; `task check` |
| 64 | 0.3.10 | **History in the UI.** A tab row "Settings / History" (`components.Tabs`; `DetailData.Tabs` and `FormData.Tabs` are new fields) on the domain page and on *Administration → Tenant settings*. Routes `GET /domains/{id}/history`, `GET /domains/{id}/history/{version}`, `GET /domains/deleted` (a link under the domain list) and `GET /admin/settings/history[/{version}]`. The list is a table (Version, When UTC with a relative hint, Who, Change, Reason, changed settings); the version page shows *What this version changed* and *What restoring it would change now* as a two-column plain-text table (Setting, Before, After; lists one value per line; no color beyond the fixed status tokens), then a form (reason, the current version as `base_version`, "Restore this version", disabled with the `restore_problems` when it cannot be restored). The edit forms get the hidden `base_version` and a "Reason (optional)" field; a mismatch re-renders the form with "Changed by *name* at *time* while you were editing – see History" (409) and keeps the typed values. Restores and edits go through `a.protected` (the new fields join its list), so step-up works as for every other action; every POST ends in 303 with a flash message. No JavaScript, no cards, no icons. `task generate`; `/design` gets the diff table | Page tests (history table, diff, restore form states, conflict page, a hostile reason and a hostile domain name escaped, a viewer sees no tab); the inline-style and script scan; the walk of the pages in light and dark; the step-up replay of a restore |
| 65 | 0.3.10 | **Docs and release.** New `site/preview-and-history.md` (preview in the wizard and the API, what it cannot promise, what is versioned and what is not and why, reading a diff, restoring, the second factor, conflicts), `site/api.md`, `site/reference.md`, `site/guides/domains-and-approvals.md` (History), `site/security.md` (what versions hold: rules, never secrets), `site/troubleshooting.md` (412, 428, "cannot be restored"), `site/upgrade.md` (migrations 0021 and 0015, no downgrade past them), `site/_data/nav.yml`; `docs/OPERATIONS.md` (a section on size, retention, that backups carry the history, restoring a domain after a CA change); CHANGELOG `[0.3.10]` (undated; Added, Changed: the wizard applies the tenant subject defaults; Upgrading); the live-test status in this section; PLAN §10.1 row and the "Safe changes" bullet after the tag (presets are not versioned: they are embedded). Version bump as in `d30bf6f`: `DEFAULT_VERSION` in `deploy/install.sh` and `deploy/install-agent.sh`, `test/install/agent_functions_test.sh`, `api/openapi.yaml`, `deploy/docker-compose.yml`, README, `docs/OPERATIONS.md`, `docs/RELEASING.md`; CHANGELOG dated by the maintainer | `scripts/ci/site-check.sh`; every documented command and URL checked against the code; `task ci:local` with every SKIP line reported; `docs/RELEASING.md` |

**Live test for the maintainer** (a test domain such as `scratch.homelab.lan`, not a production one):

1. Update the server to v0.3.10; `myownpki db status` shows `pki.db` 0021 (or later, if another branch adds one first) and `system.db` 0015.
2. *Certificates → New*: server preset, a CSR of a real host, up to the review. It lists names, validity dates, key usage, extended key usage, the extensions, the policy checks, the chain and both URLs. Compare with `openssl req -in host.csr -noout -text`, then issue and compare with `openssl x509 -in host.pem -noout -text`: the same names, validity (minutes apart), extensions and URLs; only serial and key identifier are new.
3. Provoke a refusal: a name outside the CA's name constraints, a validity above the CA maximum, a CSR with a SAN type the preset does not take. The review names each reason and offers no issue button; *Certificates* shows no new row, *Administration → Audit* no `certificate.issue` entry, not even a denied one.
4. `curl -X POST .../api/v1/certificates/preview` with the body of step 3: a viewer token gives 403; an operator token gives 200, `allowed: false` and the reasons the wizard showed.
5. *Domains → scratch → History*: "no changes recorded". Change the validity and save: the History shows version 1 (before history) and 2 with your name. Change the approval, save, open version 2 and *Restore*: the page shows the diff, asks for the second factor, and the domain is back, as version 4 (restore of 2). Version 2 is unchanged; the audit log has `domain.restore`.
6. Two browser windows on the same domain: save in the first, then in the second: the second says who changed it and when and keeps what you typed; nothing is overwritten.
7. Retire a test CA that a test domain uses, then restore an older version of that domain: refused, with the CA's name in the reason. Delete the scratch domain: *Domains → Deleted domains* lists it, and its last version restores it with the same ID.
8. *Tenant settings → History*: change the ACME limits and restore: works with the admin role and no extra confirmation. Change the agent enrollment mode and restore the old one: it asks for the second factor. An API token cannot restore a domain (`forbidden`).
9. Look through the History pages and `GET .../versions` for any password, token or the SMTP and webhook secrets of the configuration: there is none (they are not in a database).

### 16.2 Decisions

The maintainer was not available; each row takes the cautious option. Review them together with §16.5.

| Topic | Decision | Why |
|---|---|---|
| **1. The seam** | `Engine.plan(…, commit bool)` is the first half of today's `issue`, `commit` the second; `Issue` = plan + commit, `Plan` = plan with `commit=false` and a result type. No second implementation of any check | The preview must never drift from issuance (ADR-19: one policy engine). The checks are collected into one list, so the reasons of both are the same slice by construction, and an equivalence test over every case guards the rest |
| **2. What a preview may touch** | Reads only: no row, no audit entry (not even denied), no key, no serial, no randomness (an engine whose `Rand` fails on use is the test). Nothing is stored between preview and issue, and no preview ID exists | "Nothing is signed" must be checkable. A stored preview would be a second source of truth and an extra attack surface. Reads are not audited elsewhere either (viewing a certificate) |
| **3. Refusal semantics** | A policy refusal is 200 `allowed:false` with all reasons; malformed input, permission and an unknown CA keep their 4xx exactly as for issuance; a sealed server is `allowed` by policy plus `sealed: true` | "Would it be refused?" has a legitimate answer; 422 would look like a broken request to a client. The sealed state is a fact about the server, not the request, and an admin can fix it |
| **4. REST shape** | A separate operation `POST /certificates/preview` with the issue request schema, not a `dry_run` flag on `POST /certificates` | A mistyped or dropped flag must never sign something. A separate path has its own response (200 against 201), its own role entry and a clear audit story. The parse-only `POST /csr/inspect` stays for tools |
| **5. CSR in the preview** | The same `parseCSR` (64 KiB, one block, no headers, signature checked) and the same `maxSANs`, name and subject rules, because it is the same code; the response never echoes the CSR, only what the engine derived, as JSON data; the UI escapes via templ; a CSR's extension request is listed as ignored, never applied | CSR contents are attacker input (security.md). A lenient preview parser would be a parser oracle and a way to render hostile strings unescaped |
| **6. ACME** | No preview in the ACME protocol (RFC 8555 has no dry run). `Plan` already works for an ACME order inside the engine, because the order goes through the same `plan`; an admin page "what would ACME do for these names" is not built | Trivial in the engine, not in the UI (it needs a CSR-less path in `acmeRequest` and a page); the task said out of scope unless trivial |
| **7. Subject defaults in the wizard** | The wizard starts applying the tenant subject defaults, like the REST path and like the setting's own text says; one request builder serves preview and issue; a test pins it; the CHANGELOG names it | Fixing the drift is required for an honest preview. It changes what the wizard signs (O, OU, L, ST, C from the tenant, only where empty), so it is called out; the alternative, two behaviors, is not acceptable for a preview |
| **8. What is versioned** | **Domains** (every field) and the **tenant settings** (every column of `GetTenantSettings`: server key generation, subject defaults, the three ACME rate limits, trust page, agent enrollment mode, step-up minutes, the two predecessor defaults). "ACME policies" in the task = the domains plus the ACME rate limits. **Not versioned:** presets (embedded in the binary, nobody edits them; the preview shows the preset applied and a certificate stores its preset name and custom usages), CA limits (`crl_days`, `max_validity_days`; a CA's identity and name constraints are baked into certificates and can never be restored), per-account and per-agent predecessor overrides and agent names (state of one object), EAB keys, join tokens and passes, API tokens, the configuration file | Selective on purpose: rules an admin edits as a whole and that decide what gets issued. Runtime state and everything secret stay out. CA limits are the first candidate for the next release (§16.5) |
| **9. Where versions live** | A table `settings_versions` in **each database that owns the setting**: `pki.db` (domains, per tenant) and `system.db` (tenant settings, keyed by tenant ID). The version row is written in the same transaction as the change and its audit entry. Append-only by trigger (like `audit_entries`) | ADR-06: one transaction, one database; a version in another file could disagree with its data after a crash. The triggers make "history can't be edited" a database fact, not a convention |
| **10. Snapshot and secrets** | Typed snapshot structs with a closed field list and a `schema` number, never a copy of a row or a map; the full state after the change (for a delete: the deleted state). **Secrets cannot enter:** no model carries one today (notification channels are configuration, EAB keys and tokens have own tables), and two tests make it structural: reflection over the snapshots against a reviewed allow-list and name patterns, and a check that every column of `tenants` and `domains` is in a snapshot or on a "not a setting" list. A future secret column fails both until someone decides | A deny-list by hand gets forgotten; a closed type and a failing test do not. A full state per version makes a restore independent of its neighbors and a diff a pure function of two snapshots |
| **11. Baseline** | The first change to an object without versions first writes version 1 `baseline` (the state before the change, actor "system, before history"); an untouched object has no row (ETag 0). No data migration | The first mistake after the upgrade is exactly the one that must be undoable; building the snapshot in Go avoids a second serializer in SQL that could differ |
| **12. Diff** | A structured field diff (`Diff(a, b)`: setting, before, after; lists compare as sets), computed on demand, never stored, never a text diff | A text diff of JSON means nothing to an admin; fields have labels, so the UI can say "challenge types: http-01, dns-01 → dns-01" |
| **13. Restore** | Restoring version k means "make the setting look like snapshot k": it runs the **normal** create/update/set path, so every validation applies, and appends version n+1 `restore` with `restored_from = k`; versions are never edited. Refused: a version that references a retired CA or a missing preset (the reasons name them), a taken domain name, the identical state. A deleted domain is re-created with its old ID | One code path again: a restore can never create what a normal change would refuse. Refusing with reasons is safer than silently dropping the part that no longer fits |
| **14. Concurrency** | Optimistic, whole object: the latest version number is the ETag; `If-Match` (REST) and the hidden `base_version` (UI) must equal it, checked inside the writer transaction; 412 or a 409 page says who changed it and when. `If-Match` is optional on the old `PATCH`, `PUT` and `DELETE` (the released API stays compatible) and required on a restore | Silent last-writer-wins on rules is how mistakes happen; SQLite's single writer makes the check exact. A required header on a new operation costs nobody anything |
| **15. Permissions, step-up** | A restore needs what the same change needs: `ManageCA` with step-up for domains (never an API token), `ManageTenant` plus `EnrollMode` (step-up) when the enrollment mode changes, because the restore calls the normal writer. Reading history needs `ReadAudit` (it shows user names) and, for a domain, `ReadPKI` on its CA (404 otherwise). No new permission | The maintainer's rule: restoring policy is not easier than changing it. A new permission would be a second place to forget |
| **16. Audit** | Existing entries gain `version` and `snapshot_sha256`; a restore writes `domain.restore` or `tenant.settings_restore` with `restored_from`, the changed keys and the hash, in the business transaction; the free-text reason stays only in the version row | The hash ties a table a DBA could edit to the tamper-evident chain (a later verify command can use it); free text does not belong in the audit log (security.md) |
| **17. Retention** | Keep everything, no pruning in v0.3.10. A snapshot is about 0.5 KiB, so 1,000 changes are about 0.5 MB. Backups carry the history | Deleting history needs a decision about what is lost, and the append-only triggers say no; the cost of keeping is negligible at homelab scale |
| **18. Migration numbers** | `pki.db` **0021** (0020 is v0.3.8's report indexes), `system.db` **0015**, `audit.db` none. If v0.3.8 is not merged first, 0021 still works: the runner applies in order and 0020 is independent | Checked with `git ls-tree` on both release branches (see the facts above); the numbers are re-checked when the step starts |
| **19. UI** | Tabs on the two existing pages, tables and a plain-text diff, no JavaScript, 303 after every POST, step-up through `a.protected` | `references/frontend.md`; htmx is not loaded in the product today (checked: no script is served) |

### 16.3 Dependencies

None. `encoding/json`, `crypto/sha256`, `reflect` (tests) and the existing `modernc.org/sqlite`, `sqlc` and `templ` tooling. The diff is about 100 lines of own code over two closed structs, which beats a diff library here (those diff text or arbitrary trees, and a new module in a CA needs a reason). `go.mod` and `THIRD_PARTY.md` do not change.

### 16.4 Security review (an independent reviewer checks, with the diff only)

- **The preview signs nothing:** `plan` has no call to `generateKey`, `newSerial`, `e.sign`, `store`, `audit.*` or any write; the silence test (row counts, failing `Rand`) runs for every equivalence row, including a refused one and a sealed one. No private key or CSR is stored, echoed or logged.
- **No second implementation:** the checks run once, in `plan`; `describeExtensions` only formats the template that `commit` signs, and the OID-set test fails when the two disagree. Compare the new `engine.go` with the old `issue` line by line: only the sealed handling differs under `commit=false`.
- **Attacker input:** the CSR limits, PEM rules, signature check, `maxSANs`, name rules and subject rules are the issuance ones; a CSR with a hostile CN or SAN (`<script>`, bidi controls, 100 SANs of 253 characters) renders escaped on the page and as data in the API; the response size is bounded by `maxSANs` and `short()`.
- **Oracle:** the preview needs `IssueCert` on the CA; the chain it lists (subject, fingerprint) is public (AIA and the trust page serve the same certificates); refusal reasons are the ones issuance gives the same caller; a CA the caller may not read answers 404 as for issuance.
- **Versions hold no secrets:** closed snapshot types, the two guard tests, a review of the sqlc queries (no `SELECT *` into a snapshot), nothing from the configuration file reaches a version; a reason is length-limited, free of control characters, escaped on output and not copied into the audit log.
- **Append-only:** the triggers abort update and delete; the only write path is `Append` inside the business transaction; a rolled-back change leaves no version; `UNIQUE (kind, object_id, version)` backs the conflict check.
- **Restore equals change:** it calls the normal writers; permission, step-up and token rules are the writer's (a test each: no step-up, token, wrong role, other CA); the confirm page shows the diff against the *current* state, so an admin sees what a restore changes before the second factor.
- **Tenant boundaries:** the tenant ID of `system.db` versions comes from the authenticated context, never from a parameter; a domain version is read through its CA's permission; `GET /domains/deleted` lists only domains whose CA the caller may read.
- **Concurrency:** two restores, or a restore against an edit, serialize on the writer; the loser gets 412 and nothing changes.

### 16.5 Risks and open points

| Risk | Handling |
|---|---|
| The preview shows a `notBefore` of "now" and the real one is minutes later; the CA state may change between preview and issue | Dates are labeled "as of hh:mm UTC"; issuance checks everything again and its refusals show on the review step as today |
| Splitting `issue` into plan and commit changes behavior for ACME, agents or the TLS issuer | The whole existing suites of `internal/ca`, `acme`, `agents` and `server` run unchanged; the equivalence test has an ACME order; the sealed rule is the only branch |
| A hostile, huge CSR makes previews expensive (signature check, chain parse) | The same limits as issuance (64 KiB, 100 SANs); the cost is below one wizard step of today; no extra rate limit in this release (open point 5) |
| A restore re-applies an old policy that is unsafe now (an open approval, enrollment `auto`) | The diff is shown first, the second factor is required, the audit log records it; for the enrollment mode the existing step-up applies |
| History grows without limit | 0.5 KiB per change; decision 17; a prune with a keep-N rule would be a later, deliberate migration |
| The baseline hides what happened before the upgrade | By design and stated on the page ("no changes recorded before v0.3.10"); the audit log keeps older changes as text |
| `If-Match` is optional on the old calls, so scripts keep last-writer-wins | Documented; the UI and the new restore never skip it |

**Not in v0.3.10:** a preview for ACME orders, renewals (`/certificates/{id}/renew`) and agent issuance (the engine supports it, no surface); a dry run for domain or settings *edits* (the diff after the fact plus restore covers it); versions of CA limits, presets, per-account policies and agent names; pruning, export and import of history; a `myownpki settings verify` command that compares versions with the audit hashes; undoing issuances (revoke) or "change sets"; any change to an ADR.

**Open points for the maintainer:**

1. **The wizard starts applying the tenant subject defaults** (decision 7): certificates from the UI gain O, OU, L, ST and C where the form leaves them empty. Confirm, or say that the REST path should stop doing it instead.
2. **Reading history is admin only** (`ReadAudit`), because it names users. An operator cannot see who changed a domain; say if operators should see history without names.
3. **Whole-object conflicts:** two admins changing different fields of one domain still conflict. A field-wise merge is possible later.
4. **Retention:** keep everything (decision 17). Say if you want a cap, a time limit or an export.
5. **No rate limit on the preview.** It is cheaper than a wizard page, but an API token could call it in a loop; the login throttle does not cover tokens.
6. **Candidates for the next release:** versions for CA limits, an ACME "what would happen for these names" page, a `settings verify` command, a preview on the renewal page.
7. **Not verified:** nothing was built or run; every statement comes from reading the code (a `graphify` query located the files). Open: the exact extension set `crypto/x509` writes for the template (the OID-set test finds out), whether `PRAGMA table_info` on `STRICT` tables behaves as the guard test assumes, whether the `vacuum` rules accept the two new problem types without changes to `api/vacuum.yaml`, and the final migration numbers if v0.3.9 or another branch adds one before this merge.

---

## 17. Apache, HAProxy, guides and demo: v0.3.11

v0.3.11 completes the feature set of v1.0 (PLAN §10.1) with four independent workstreams. **A: Apache and HAProxy for the agent**,
as two Apache recipes (Debian family, Red Hat family) and one HAProxy recipe, plus the one thing the agent cannot do today, a
single PEM with the key inside (HAProxy's usual form). **B: guides in the web UI**: a read-only *First steps* page that derives
its checklist from what the instance already knows, and five embedded guides in a small closed content format, with no
Markdown library. **C: a demo** in `deploy/demo/docker-compose.yml` that shows http-01 with certbot end to end and, as a second act,
an agent next to nginx. **D: the container base** moves from `distroless/static-debian12` to `static-debian13`, pinned by digest.
The release adds **no migration, no change to the REST API and no dependency** (the one possible exception, a Markdown library,
is not planned; see decision 9). Written on 2026-11-16 while the maintainer was away: the decisions in §17.2 are cautious
defaults for review, not agreements.

Goal, measured on the live installation: a host with Apache (Debian) or HAProxy gets a certificate from the agent, the service
serves it after the reload, and a deliberately broken staged file is refused by the test hook and rolled back; a new instance shows
*First steps* after the first sign-in, each open item links to the page or guide that finishes it, and nothing on those pages
writes anything; the documented demo ends with a certificate from certbot for a name of the demo domain and an nginx served by the
agent; the released image runs on the Debian 13 base with the same user, the same healthcheck and working outbound TLS.

**Facts found in the repository (2026-11-16, `release/v0.3.11` = `origin/main` 65ee465; nothing was built or run; `graphify-out/` does not exist in this worktree, so every reference is a direct read of the file named):**

*A. Recipes and the agent*

- **Recipes are data.** `internal/recipe/recipe.go` holds four entries (`nginx`, `postfix`, `dovecot`, `proxmox`) with profile, paths, owner, key mode,
  hooks (argv, absolute first element), test and reload hook, local check, `SandboxWrite`, `LowPorts`, and an `Example` flag with `Notes`. It imports
  nothing from the module, so the server's Add host assistant (`internal/web/hostadd.go`, `app_hostadd.go`) reads the same table. `internal/agent/deployment_recipe.go`
  (`applyRecipe`) fills only empty fields, adds the sandbox directories, and defines a hook only when the deployment references it. `{name}` is replaced **in `Dir` only**.
- **Two profiles exist:** `nginx` (a directory with `fullchain.pem` and `privkey.pem`) and `file` (`certificate`, `chain`, `fullchain`, `key`; `internal/agent/config.go:134`). Both go through one pipeline
  (`deploy_files.go: deploymentPaths`, `targets`; stage with journal, test hook, reload hook, TLS check against the expected leaf, rollback, `deploy_reload.go`). The name "nginx" is historical:
  the profile is simply "a directory with two files", which is what Apache needs. HAProxy's single PEM with the key inside is **not** expressible: `Material` has `Certificate`, `Chain`, `Fullchain`, `Key`
  (`acme.go:38`) and no combined part. The legacy suite already knows the form (`legacy/lib/export.sh`: "combined.pem: private key + fullchain in a single file (for HAProxy)"; `internal/ca/export.go` `ExportCombinedPEM`, offered as a download in the UI).
- **The four file fields are listed by hand in about fifteen places:** `config.go` (validation and the overlap check), `deploy.go:308`, `deploy_journal.go:82` and `:216`, `deploy_reload.go:115`, `runtime.go:207`, `deployment.go` (validation, `neededDirs`, `footprint`, `ListDeployments`), `deployment_cli.go` (flags), `deployment_dryrun.go`, `deployment_recipe.go`,
  `dns_config.go:184`, `edit.go:353`, `writable.go:98`, and in `internal/web` `hostadd.go:240` and `app_hostadd.go:424`. A new field must touch all of them; a helper removes the lists first.
- **Existing tests name "apache" as the *unknown* recipe:** `internal/agent/deployment_recipe_test.go:171`, `cmd/myownpki-agent/main_test.go:113` (the exact "known: dovecot, nginx, postfix, proxmox" text), `internal/web/hostadd_test.go:148` and `hostadd_page_test.go:234`. They change with step 66.
  `internal/recipe/recipe_test.go` pins the name list, requires `Example` for every recipe except nginx and a `/etc/ssl/myownpki/` prefix, and `TestEveryRecipeRendersAValidDeployment` (agent) iterates `recipe.Names()`, so every new recipe is validated, dry-run, written and checked against the drop-ins automatically.
- **Hooks:** one fixed argv, no shell, 30 s, stdout discarded, stderr kept and sanitized (`deploy_reload.go: runHook`); hooks with the same name and command are shared, so all deployments of one service form **one reload group** (one reload, one rollback). The agent runs as root under `ProtectSystem=strict` with the capability set `CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER` (`deploy/systemd/myownpki-agent.service`); only `state_dir`, `paths` and `sandbox.write` are writable. A `systemctl reload` works from inside (nginx is live-tested); a hook that writes a log file needs that directory in `sandbox.write` (nginx: `/var/log/nginx`) and one that binds a low port needs `low_ports` (`nginx -t` does, which is why the nginx recipe has it).
- **A hint exists already** (`deployment.go:700`): for a hook whose command is `nginx`, `apachectl`, `apache2ctl` or `haproxy` it prints "writes its log files … add --sandbox-write" and a low-ports hint. For `haproxy -c` and `apache2ctl configtest` that text is probably wrong (check mode binds nothing); step 68 narrows it.
- **Who owns the key:** the recipes use `root:root`, key mode `0600`; `targets()` refuses a mode with rights for others; `CAP_CHOWN` lets the agent set another owner. Apache and HAProxy read key and certificate in their root-run master before they drop privileges (documentation, not tried here), so no group is needed; the existing docs make the same claim for Postfix and Dovecot and list it as unverified.
- **What each service wants (from the services' documentation, not tried):**
  - *HAProxy:* `bind … ssl crt <file or directory>`; the usual PEM holds the certificate chain **and** the key (`cat cert chain key`). HAProxy also reads a key from a sidecar file: the global option `ssl-load-extra-files` (default `all`, which includes `key`) makes it load `<basename>.key` when the PEM has no key (read on docs.haproxy.org/3.0, global section; the `crt` section itself could not be reached in the fetch, so what a *directory* `crt` skips and whether the order of key and certificates matters are **not verified**). Check: `haproxy -c -f /etc/haproxy/haproxy.cfg` (Debian and Red Hat both put the binary in `/usr/sbin`; Debian's unit may add `-f /etc/haproxy/conf.d`, to verify). Reload: `systemctl reload haproxy` (master-worker; a failed new configuration keeps the old workers). `-c` loads the certificate files, so a mismatched key should fail it (to verify). It binds no port.
  - *Apache:* `SSLCertificateFile` (the full chain is accepted there since 2.4.8, `SSLCertificateChainFile` is deprecated), `SSLCertificateKeyFile`, `mod_ssl` enabled. Debian and Ubuntu: unit `apache2`, `/usr/sbin/apache2ctl configtest`, logs `/var/log/apache2`. Red Hat family: unit `httpd`, `/usr/sbin/httpd -t` (or `apachectl configtest`), logs `/var/log/httpd`, SELinux enforcing by default. `reload` is a graceful restart. **Open and important:** I believe `-t` stops after parsing and before `post_config`, where `mod_ssl` loads the key; then `configtest` checks that the files exist and the directives parse, **not** that key and certificate match. The agent already checks the pair (`tls.X509KeyPair`) before it writes, so the realistic gap is a corrupted file after writing; CI step 69 turns the belief into a recorded fact.
  - Both services pick their certificate by SNI from what the admin wrote into their own configuration; the recipe never edits the service configuration (same rule as for Postfix).
- **Salt:** `deploy/salt/myownpki/map.jinja:229` passes `recipe` through as a free string to `deployment add`; there is **no list of recipe names** in the formula, so no state or pillar key has to learn `apache2`, `httpd` or `haproxy`. Examples and docs name recipes (`pillar.example:45`, `README.md:127`); the renderer test cases (`deploy/salt/test/cases/`) can gain one case per new recipe. A formula that uses `config_source` (a rendered `agent.yaml`) needs the new `files.combined` key spelled out in its README.
- **Site and docs that list the recipes:** `site/recipes.md`, `site/hosts.md` (lines 10, 65, 69, 282), `site/choose.md`, `site/index.md`, `site/best-practices.md`, `site/cli.md`, `site/faq.md`, `docs/OPERATIONS.md` §12.9 and the `--recipe` flag text in OPERATIONS and `internal/agent/deployment_cli.go:62`. None of them says "Planned (v0.3.11)"; only `site/faq.md:487` mentions the release ("What comes next", which also still lists v0.3.10 as planned).
- **CI today:** the job `agent end-to-end` (`.github/workflows/ci.yml`) runs a real server, agent and nginx in a pinned `nginx:1.29.2-trixie@sha256:…` container (`scripts/ci/agent-e2e-nginx.sh`, tests `TestNginxDeployProfiles` and `TestNginxStagedFaultRollsBack` under build tag `e2etest`: nginx is started by the test with its own config, pid and a free port), and runs `nginx -t` on port 443 under the real systemd unit by exporting the container's root file system (`agent-e2e-nginx-systemd.sh`). The pattern is reusable for the two new services. Official images are Debian-based but differ from the distribution packages (the `httpd` image builds Apache into `/usr/local/apache2`; the Debian layout with `apache2ctl` and `envvars` is not there); a Debian 13 image with `apt-get install apache2` tests the real packaging. **Docker is not installed on the development machine**; CI has it.

*B. Guides in the web UI*

- **`init` is a terminal command and creates no CA by default** (`internal/setup/setup.go`: unseal passphrase, recovery key, first admin with TOTP; optionally a *test* root and intermediate, `--with-ca` and `--ca-base-url`; `--demo` generates every secret into one file and marks the instance as a demo for good). After it the admin signs in and sees an empty dashboard (`app_pki.go: dashboard`: counts, "Nothing needs attention"). There is no place in the UI that tells a new admin what to do next, and `init` cannot open one; "assistant after `init`" therefore means a page in the UI that a new instance leads to.
- **The pattern to follow is the Add host assistant** (`app_hostadd.go`, §11): server-rendered plain forms and links, `components.Steps`, `admin.DetailPage` with `Section{Title, Text, KV, Pre, Table, Forms}`, a flash `view.Message`, step-up through `a.protected`. **The UI ships no script and loads no htmx** (§16.2 decision 19; the progress page refreshes with `<meta http-equiv="refresh">`). CSP is `default-src 'self'; script-src 'self'; style-src 'self'; … form-action 'self'` (`internal/web/server.go:27`); templates may use only the global classes of `web/styles/`.
- **The navigation is a Go table** (`internal/web/layout/app.templ`, `var nav`, groups Overview, Certificates, Authorities, ACME, Agents, Administration); routes are registered in `internal/web/app.go`. Every real route must also be in the screenshot inventory (`internal/tools/screenshots/inventory.go`, checked by `screenshots_test.go`), and `realPages` (`app_test.go:397`) feeds the scans for inline styles, scripts, undefined classes and SVG rules.
- **What exists to embed:** `site/` is a Jekyll site (about 60 pages; the guides `site/guides/*.md` are 6 to 17 KB each, e.g. `backup-and-restore.md`, `offline-root.md`, `certbot.md`, `ca-lifecycle.md`; `site/hosts.md` is 37 KB) written in **kramdown with Liquid** (`{{ '/hosts/' | relative_url }}`, `{:toc}`, `{: .warning}`, front matter with `sources:`). `scripts/ci/site-check.sh` checks them with Jekyll's rules. They cannot be shown by the UI as they are: Liquid and kramdown attributes would appear as text. The other embedded content in the binary is `go:embed` of small files only (`api/openapi.yaml`, `presets/*.yaml`, `web/styles/*.css`, `assets/brand`, `deploy/examples.go`); nothing renders Markdown. **`go.mod` has no Markdown library** (no goldmark, blackfriday or similar); `go.yaml.in/yaml/v3` is a direct dependency.
- **PLAN §10.1 names the five guides:** building a CA, offline root, connecting certbot, installing the agent, backup and restore. Site pages for four of them exist (`ca-lifecycle.md`, `offline-root.md`, `certbot.md`, `backup-and-restore.md`); "installing the agent" lives in `site/hosts.md` and OPERATIONS §12.
- **What a checklist can read without new queries:** the server's sealed state, the CA list (`Engine.CAs`), the domain list, the certificate counts (`Engine.CertificateCounts`, agent certificates hidden by `HideAgentCertificates`), the agents, alerts and settings through the same calls the dashboard, `/domains`, `/agents` and the tenant settings use, each under the signed-in user's own permissions (a CA-scoped role gets `authz.ErrDenied` for tenant-wide lists, as the dashboard handles it). The server does **not** know whether a backup ran (the daily timer is a systemd unit of the host) nor whether a reverse proxy exists; those stay "not detected, see the guide". `a.d.ACMEDirectory` (`app.go:74`) is set only when ACME is configured.
- **Per-user state exists only for appearance** (`view.Prefs`, theme, density, layout); a "dismissed" flag would be new state and a schema change (`system.db`).

*C. Demo*

- **`deploy/docker-compose.yml`** is the production example: one service, `ghcr.io/der-felix/myownpki:0.3.10`, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, a named volume, `./docker/config.yaml` mounted read-only, the admin UI published on `127.0.0.1:9443`, the public listener on `8080`; `init` is run by hand at a terminal. `deploy/docker/config.yaml` sets the data directory, listeners and `agent.package_dir: /opt/myownpki/agent-dist` (the image carries the exact release's agent packages). The version tag is one of the strings the release bump rewrites.
- **The unseal passphrase is never read from a file or variable** (`internal/config/config.go:9`): a server starts sealed, and an admin unseals in the UI, with `serve --unseal` at a terminal, or through `POST /api/v1/system/unseal` (the CI job `install` does this with a password and a TOTP code computed in Bash, `test/install/systemd_test.sh`, helpers `api` and `totp`). `init --demo` writes passphrase, password, recovery key and the TOTP secret into one `0600` file (`<data_dir>/init-demo-secrets.txt`) and marks the instance as a demo (UI banner, log warning at every start).
- **ACME needs more than a running server:** `acme.base_url` must be `https://…` (the proxy terminates TLS), or `acme.tls_issuer` makes the server serve its own TLS on the ACME port with a certificate issued by its own CA (v0.2.2: a bootstrap certificate while sealed, its own after the unseal). A **domain** must cover the name and allow http-01, and its address policy (`internal` or `public`, `internal/ca/domains.go:68`) decides whether a private Docker address may be validated. `init --with-ca` creates CAs but **no domain**; a domain is a `ManageCA` change that needs a fresh second factor and never an API token.
- **The conformance run already drives real clients** (`test/conformance/run.sh`: lego, certbot, acme.sh against the server and BIND), with images pinned by digest and a tag-date comment (two-week rule; `THIRD_PARTY.md`).
- **The agent has no container image.** Its distribution is `.deb`, `.rpm` and a tarball; the **server image carries all of them** under `/opt/myownpki/agent-dist` with `checksums.txt` (checked by `scripts/ci/image-snapshot.sh`). `myownpki-agent setup` is systemd-oriented (it writes the unit and drop-ins); `myownpki-agent run --config` works without systemd, but the recipe hooks (`systemctl reload nginx`) do not, so a container needs hooks of its own (`nginx -s reload`). Enrollment without a secret leaves the host in the approval queue (Add host: `admitNone`); a join token or pass is created with the second factor.
- **CI can run Docker** (`image` job: a GoReleaser snapshot with `dockers_v2`, local tags `ghcr.io/der-felix/myownpki:<version>-amd64|arm64`; the `conformance` and `agent-e2e` jobs). The released tag `0.3.11` does not exist until the maintainer publishes, so the demo must take its image from a variable that CI points at the snapshot. The static part of the demo (compose file structure, pins, hardening flags, scripts) can be tested **without Docker** with `go test` (the repository parses YAML with `go.yaml.in/yaml/v3`) and `shellcheck` (installed here).

*D. Container base*

- **Where:** `deploy/docker/Dockerfile` names `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872…7f7ab` **twice** (the `FROM` and `COPY --from=… /home/nonroot /var/lib/myownpki`, which takes the base image's own empty `0700` home owned by 65532 as the data directory because there is no shell for `mkdir`). `internal/config/config_test.go:351` hard-codes the string `gcr.io/distroless/static-debian12:nonroot@sha256:` and requires exactly two occurrences and no other `gcr.io/`; it fails the day the Dockerfile changes. `THIRD_PARTY.md` has the table row (index digest, "index uploaded 2026-08-21") and the command for a new digest; `docs/PLAN.md` line 611 names the base; `docs/NIGHTLOG.md` is history and stays. `.goreleaser.yaml` names no base (`dockers_v2` only points at the Dockerfile).
- **How the digest is read today** (`THIRD_PARTY.md`): `curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" https://gcr.io/v2/distroless/static-debian12/manifests/nonroot` and the header `Docker-Content-Digest` (the digest of the multi-platform *index*). **Tried on 2026-11-16 from this machine: for `static-debian12` it returns exactly the pinned digest, so the method works without Docker; for `static-debian13` the same call answers `200` with an OCI index** (`nonroot` exists). The registry's `…/tags/list` also lists every manifest with `timeUploadedMs` and its tags; on 2026-11-16 the current `static-debian13:nonroot` index was **uploaded 2026-11-12**, i.e. it is *younger than the two-week rule* of `THIRD_PARTY.md`; the newest index older than two weeks was uploaded 2026-10-31 and carries tags of the form `nonroot-<commit>`. No digest is written into this plan on purpose: it is read again, by the commands in step 70, on the day of the step.
- **What the binary needs from the image:** nothing but a root file system, a user and CA certificates. The build is pure Go (`CGO_ENABLED=0`, so no glibc and no libc version coupling to Debian 12 or 13); non-test code has no `time.LoadLocation` and no tzdata import (UTC everywhere, an injected clock), so time zone data is not used; outbound TLS (webhooks and SMTP with TLS in `internal/notify`) uses the system roots, which the distroless static image ships (`etc/ssl/certs/ca-certificates.crt`, from Debian's `ca-certificates`). `HEALTHCHECK` runs the binary itself (`myownpki healthcheck`), not a tool of the image.
- Debian 13 is already the platform of the CI nginx container (`nginx:1.29.2-trixie`) and of the maintainer's LXC hosts (PLAN line 840); PLAN §10.1 line 501 already says "Debian 13 base from v0.3.11".

*E. The roadmap row against the repository*

- **"deploy profiles"**: no new profile is needed for Apache (the `nginx` profile is "a directory with two files"); HAProxy needs a new *target* inside the `file` profile (`files.combined`), not a new profile name. They are recipes (decision 1).
- **"embedded guides"**: the Jekyll pages cannot be embedded as they are, and rendering Markdown needs either a new dependency or an own parser (decision 9).
- **"first steps assistant after `init`"**: `init` runs in a terminal; the assistant can only be a UI page (decision 11). A dismissible banner would need a stored flag (migration), which this plan avoids.
- **"demo … one command"**: the passphrase cannot be passed in, a domain needs the second factor, and the agent has no image; a single `docker compose up` cannot finish unattended. Decision 15 scopes the demo honestly. The roadmap row itself is not wrong enough to edit; it is not changed.
- **"pinned by digest"**: possible and tested as above, but the newest digest is younger than the two-week rule today (decision 18).

### 17.1 Work plan

Steps continue after step 65 of v0.3.10. Each step is a few commits; every commit builds and passes the tests of its package (`task check` as far as this machine allows: `internal/publish` tests are blocked locally by Windows Defender and run in CI). **Docs are written in step 77, not per step**, so the parallel lanes below never touch the same docs.

| # | In | Step | Verifies with |
|---|---|---|---|
| 66 | 0.3.11 | **Apache recipes.** `internal/recipe`: `apache2` (Debian, Ubuntu; profile `nginx`, `Dir` `/etc/ssl/myownpki/{name}`, root, `0600`, hooks `apache2-test` = `/usr/sbin/apache2ctl configtest` and `apache2-reload` = `/usr/bin/systemctl reload apache2`, check `127.0.0.1:443`, `SandboxWrite` `/var/log/apache2`, no low ports) and `httpd` (Red Hat family; hooks `httpd-test` = `/usr/sbin/httpd -t` and `httpd-reload` = `/usr/bin/systemctl reload httpd`, `SandboxWrite` `/var/log/httpd`). Both `Example: true` with notes: the `SSLCertificateFile` and `SSLCertificateKeyFile` lines with the exact paths, `mod_ssl` on, what `configtest` covers (existence and syntax, key match unknown), the SELinux label of `/etc/ssl/myownpki` (`restorecon`), a group such as `ssl-cert` only if a service reads the key unprivileged, one reload group for all vhosts. Commit 1: the table, `recipe_test.go` (name list; the `Example` rule becomes an explicit set of live-tested recipes, today `nginx`), golden files `recipe-apache2.out.yaml` and `recipe-httpd.out.yaml` next to `recipe-nginx.out.yaml`. Commit 2: the assistant (`hostServices` gets "Apache (Debian, Ubuntu; example recipe)" and "Apache httpd (Red Hat family; example recipe)"), the `--recipe` flag help, and the tests that used "apache" as the unknown name (they switch to a name that stays unknown, such as `lighttpd`) *Built:* as planned. `apache2` and `httpd` are recipes of the `nginx` profile with the hooks, log directories and notes of the plan, both `Example: true`; the notes say that `configtest` and `httpd -t` are not known to check the key pair. The golden files `recipe-apache2.out.yaml` and `recipe-httpd.out.yaml` sit next to `recipe-nginx.out.yaml`, the assistant lists "Apache (Debian, Ubuntu; example recipe)" and "Apache httpd (Red Hat family; example recipe)", the `--recipe` help names them, and the tests that used "apache" as the unknown service use `lighttpd`. The existing `TestEveryRecipeRendersAValidDeployment` covers both. | `go test ./internal/recipe ./internal/agent ./internal/web ./cmd/myownpki-agent`; the existing `TestEveryRecipeRendersAValidDeployment` now covers both recipes (dry run writes nothing, drop-ins match, a second run is refused) |
| 67 | 0.3.11 | **One-file target `files.combined`** (HAProxy's usual form). Commit 1, **no behavior change**: `Files` gets `Targets() []string`, `CertPath()` (fullchain, else certificate) and `KeyPath()`; the fifteen hand-written lists call them; every existing test stays unchanged and green. Commit 2: `Files.Combined` (`yaml:"combined"`, flag `--combined`): the certificate chain followed by the key in one PEM (certificate first, so the existing "first PEM block is the leaf" read-backs in `writtenLeafFingerprint`, `currentLeaf` and the journal keep working; Go's `tls.X509KeyPair` accepts the same blob for both arguments, which keeps the previous-pair check). Validation: `combined` excludes `certificate`, `chain`, `fullchain` and `key` and lies under `paths`; the file gets the **key mode** (`0600` default, never rights for others), owner and group of the deployment; the buffer is built in memory per write, cleared after it and never logged (`Material` already redacts itself); the journal backup of the old file is a `0600` state file like the old key file today. `deployment add --dry-run`, `list`, `remove` (footprint), `neededDirs`, `edit.go` (the written YAML), the dns-01 target check and `sandbox sync` know the key. **An older agent refuses the new key** (strict parsing, as with `dns_providers` and `system_trust`): update agents first, said in `site/upgrade.md`. Commit 3: the places that print files (`app_hostadd.go` explanation, `hostadd.go` certificate parents) learn `recipe.Recipe.Combined` *Built:* in the three commits of the plan. Commit 1 (`refactor(agent)`): `files.go` has `Files.Targets`, `CertPath`, `KeyPath`, `Map` and one field list, and the places that spelled out the four fields call them; no existing test was edited. Commit 2: `Files.Combined` (`yaml:"combined"`, `--combined`): the certificate chain, then the key, in one file with the key mode (`0600` by default, never rights for others), owner and group of the deployment, written through the same atomic write, journal, test hook, reload hook, TLS check and rollback; the buffer is a copy that the writer clears, and the journal backup is a `0600` state file. Validation refuses `combined` together with any other target, a path outside `paths` and an overlap with another deployment, `state_dir` or `ca_bundle`. `deployment add --dry-run`, `list`, `remove`, `edit.go`, the dns-01 target check and `sandbox sync` read the new field through the list. The tests are `deploy_combined_config_test.go`, `deploy_combined_test.go` and the additions to `files_test.go`. An older agent refuses the key (strict parsing). Commit 3: `recipe.Recipe.Combined` and the helper `recipeFiles` in `internal/web/hostadd.go` for the commands and the explanation. | Tests in `internal/agent`: config matrix (combined alone is valid; with key, fullchain, certificate or chain refused; relative, outside `paths`, overlapping another deployment, `state_dir` and `ca_bundle` refused; mode `0644` refused); the written file equals fullchain plus key byte for byte, parses with `tls.X509KeyPair(file, file)` and with `crypto/x509` per block, has the key mode and the owner; atomic write (temp file in the directory, no half file after a failing write); journal: stage, failed test hook, rollback restores the old combined file; first installation removes it; interrupted-journal recovery; `writtenLeafFingerprint` and `currentLeaf` find the leaf; `deployment list` and `remove` name and prune the right directory; an `agent.yaml` of 0.3.10 parses to the same `Config`; `GOOS=windows` and `GOOS=darwin` build; `go list -deps ./cmd/myownpki` unchanged |
| 68 | 0.3.11 | **HAProxy recipe.** `recipe.Recipe` gets `Combined`; `applyRecipe` replaces `{name}` in **every** path of a recipe (not only `Dir`: HAProxy usually serves many certificates, and one static path would collide at the second deployment, "target file is also used by"); recipe `haproxy`: profile `file`, `Combined` `/etc/ssl/myownpki/haproxy/{name}.pem`, root:root, `0600`, hooks `haproxy-test` = `/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg` and `haproxy-reload` = `/usr/bin/systemctl reload haproxy`, check `127.0.0.1:443`, no sandbox directory, no low ports; `Example: true`; notes: `bind :443 ssl crt /etc/ssl/myownpki/haproxy/<name>.pem` or the directory `crt /etc/ssl/myownpki/haproxy/`, `crt-list` is the admin's own file, the test command must name the configuration the service really uses (`-f` may need `conf.d`), `accept-proxy` or non-loopback binds break the local check (override with `--check`, or none), whether the directory form skips the agent's `.myownpki-*` temp file. The hint of `deployment add` stops saying "writes its log files" for `haproxy -c` and `apache2ctl configtest` (it names only hooks that really bind or log: `nginx -t`). The assistant gets "HAProxy (example recipe)". **Fallback if the owner declines the agent change (decision 3):** `file` profile with `fullchain` = `<name>.pem` and `key` = `<name>.pem.key`, relying on HAProxy's `ssl-load-extra-files key` default; then step 67 shrinks to commit 1 *Built:* as planned. `haproxy` is the `file` profile with `Combined` `/etc/ssl/myownpki/haproxy/{name}.pem`, root:root, `0600`, `haproxy-test` = `/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg`, no sandbox directory, no low ports, `Example: true`; `applyRecipe` replaces `{name}` in every path, after it checked the name against the agent's name rule (a slash, `..` or upper case is refused before a path is built). The assistant lists "HAProxy (example recipe)" and names the deployment `haproxy`, so its file is `/etc/ssl/myownpki/haproxy/haproxy.pem`. The hint of `deployment add` no longer names `haproxy -c`, `apache2ctl configtest` or `apachectl -t` as hooks that open sockets and log files (`opensSocketsAndLogs`); later, a custom Apache configuration check without `--sandbox-write` gets a separate hint at the log directory, because Apache opens its error log even for a check and fails with `AH00091` otherwise. The Salt formula passes `combined` through (`map.jinja`, `opts_string`); no formula test case was added for `apache2` or `haproxy` (see step 77). The sidecar-key fallback of decision 3 was not needed. | `go test ./internal/recipe ./internal/agent ./internal/web`; golden `recipe-haproxy.out.yaml`; two deployments from the recipe in one `agent.yaml` do not collide and share one reload group; a test that a `{name}` with `/` or `..` cannot reach a path (names are validated; the test pins it); hint tests (nginx still hinted, `haproxy -c` and `apache2ctl configtest` not) |
| 69 | 0.3.11 | **The real services in CI.** New e2e tests (`//go:build e2etest`, Linux) `TestApacheDeployProfile` and `TestHAProxyDeployProfile` modeled on `TestNginxDeployProfiles`: the test starts the service **itself** with its own configuration, pid file and a free port (Apache: a minimal config with `mod_ssl`, `Listen`, `SSLCertificateFile`, `SSLCertificateKeyFile`, reload by `-k graceful`; HAProxy: `-W` master-worker, reload by `SIGUSR2` to the master), writes the old certificate, runs a pass through the real pipeline with the recipe's real test-hook command pointed at that configuration, checks the served leaf, then stages a corrupted pair and **records what the test hook says** (HAProxy `-c` expected to fail; for Apache the result of `configtest` is **asserted either way and documented**: if it passes a mismatched key, the notes and `site/recipes.md` say so and the agent's own pair check is the guard). A staged-fault test as `TestNginxStagedFaultRollsBack`. Scripts `scripts/ci/agent-e2e-apache.sh` and `agent-e2e-haproxy.sh` (shared functions), images by digest with tag and date comments, `THIRD_PARTY.md` rows (license, "CI only; not shipped"), a step in the job `agent end-to-end` (or a separate job, so a failure in one service does not hide the nginx result); `shellcheck` on the scripts. A Debian 13 image with `apt-get install apache2` for the Debian layout; the official `haproxy` image for HAProxy. The Red Hat layout (`httpd`, SELinux) stays a live test (§17.7) *Built:* with two differences from the plan. The tests are `TestApacheDeployProfile`, `TestApacheConfigtestOnKeyMismatch`, `TestApacheStagedFaultRollsBack`, `TestHAProxyDeployProfile`, `TestHAProxyCheckOnKeyMismatch`, `TestHAProxyDirectoryAndTemporaryFile`, `TestHAProxyCombinedOrder` and `TestHAProxyStagedFaultRollsBack` (build tag `e2etest`, Linux; they run only with `MYOWNPKI_E2E_APACHE=1` or `MYOWNPKI_E2E_HAPROXY=1`). The test starts the service itself with a private configuration, pid file and free loopback port, as the user of the job. Instead of a Debian 13 image and the official `haproxy` image by digest, the job **`agent-e2e-services`** (named *agent end-to-end (Apache, HAProxy)*, a separate job so that a failure does not hide the nginx result) installs `apache2` and `haproxy` from the packages of the `ubuntu-24.04` runner and runs each test three times, so no `THIRD_PARTY.md` row was needed; the scripts are `agent-e2e-apache.sh`, `agent-e2e-haproxy.sh` and `agent-e2e-services-functions.sh`. Three results are recorded, not assumed: what `apache2ctl configtest` does with a mismatched key, whether the directory form of `crt` skips the agent's `.myownpki-*` temporary file, and whether the order of certificate and key in the combined file matters. Each is compared with the notes of the recipe: a contradiction fails the test, a note that is merely behind becomes a `NOTES-UPDATE` warning, and every `OBSERVED` line goes to the job summary. **The first CI run answered them** (Apache 2.4.58 and HAProxy 2.8.30 on Ubuntu 24.04): `configtest` does not detect a mismatched key; a failed graceful reload with a damaged key stopped Apache and the rollback did not bring it back; `haproxy -c` refuses a mismatched pair; the directory form of `crt` skips the temporary file; the order of certificate and key does not matter. The notes, `site/recipes.md` and the CHANGELOG say so, and the tests still fail if a later observation contradicts a note. The Red Hat layout, the real unit and SELinux are not covered. | The CI job; `bash scripts/ci/shellcheck-smoke.sh`; `task ci:local` with every SKIP line reported; the test names appear in the CI log with the recorded `configtest` behavior |
| 70 | 0.3.11 | **Container base `static-debian13`.** On the day of the step read the digest (decision 18): `curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" https://gcr.io/v2/distroless/static-debian13/manifests/nonroot` for the current tag, and `curl -s https://gcr.io/v2/distroless/static-debian13/tags/list` (field `manifest`: each entry has `timeUploadedMs`, `tag`, `mediaType`) to find the **newest index older than 14 days** that carries a `nonroot-<commit>` tag; `curl -sI … /manifests/nonroot-<commit>` gives its digest; `curl -s … /manifests/<digest>` lists the platforms (`linux/amd64` and `linux/arm64` must both be there) and, per platform, the config blob (`User`, `Env`, `WorkingDir`) to compare with the debian12 one. `crane digest` or `docker buildx imagetools inspect` do the same and are not installed on this machine; the curl form is the documented one. Commit 1: `deploy/docker/Dockerfile` (both `FROM` and `COPY --from=`, comment says Debian 13), `internal/config/config_test.go:351` (the string and the "exactly two" rule), `THIRD_PARTY.md` (row: tag, "index uploaded <date>", digest; the command block names `static-debian13`; the two-week sentence), PLAN line 611. Commit 2: the `image` CI job checks what the image really carries, without a shell in it: `docker run --rm <image> --version`, `docker image inspect` (User `65532`), and `docker export <container> \| tar -tf -` for `etc/ssl/certs/ca-certificates.crt`, `home/nonroot` and `var/lib/myownpki` owned by 65532 (`tar -tvf`) *Built:* as planned. The pin is the index `sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329` (tag `nonroot-48b5c0455fb00d6ea7223f1fc6862c46da736556`, uploaded 2026-10-31, 15 days before the step); the current `nonroot` index, uploaded 2026-11-12, was too young. It was read without Docker from the registry API; both platforms were present and both config blobs show user `65532`, `WorkingDir` `/home/nonroot` and `SSL_CERT_FILE` as in Debian 12. `deploy/docker/Dockerfile` (both places), `internal/config/config_test.go`, `THIRD_PARTY.md` and `docs/PLAN.md` follow. `scripts/ci/image-snapshot.sh` checks from outside, because the image has no shell: user 65532, `--version` (the runner's architecture only, no emulation) and, from `docker export`, `etc/ssl/certs/ca-certificates.crt` and `home/nonroot` and `var/lib/myownpki` as directories owned by 65532. The image was not run on a Docker host by the author (none on the development machine). | `go test ./internal/config`; `task ci:local`; the CI jobs `image` and `install`; `task release:snapshot` on a machine with Docker (not this one) |
| 71 | 0.3.11 | **Guide engine.** New package `internal/guides`, standard library only: the content lives in `internal/guides/content/*.md`, **embedded with `go:embed`**, in a closed subset of Markdown (headings `##` and `###`, paragraphs, `-` and `1.` lists, fenced code blocks with a language tag, tables, `**bold**`, `*italic*`, `` `code` ``, links, the note markers `> **Note:**` and `> **Warning:**`) with a small front matter (`title`, `summary`, `order`, `audience`, `site` = the permalink of the longer page on the documentation site, `sources` = repository files the text was checked against, like the site pages). A parser of about 300 lines turns it into `[]Block` data (`Heading`, `Paragraph`, `List`, `Code`, `Table`, `Note`); **text is never HTML**: raw HTML, an image, `javascript:` or any other unknown construct is a parse error (a test runs the parser over every embedded file). Links are allowed only to (1) UI paths that exist (checked against the route table by a test in `internal/web`), (2) other guides, (3) a fixed allow-list of the project's documentation and repository URLs (constants). Placeholders in code blocks come from a closed list (`{acme_directory}`, `{ca_name}`) and are replaced **after** parsing, from configuration and engine data only, never from the request; an empty value keeps a visible example (`https://pki.homelab.lan/acme/directory`). Limits: file at most 32 KiB, 200 blocks, 8 guides. `Registry` (`List`, `Get(slug)`, slugs `[a-z0-9-]`). No code runs from a guide *Built:* as planned, in `guides.go` (types and limits: 32 KiB, 200 blocks, 8 guides), `parse.go`, `inline.go` and `registry.go`; standard library only (a test reads the imports). Code languages are `bash`, `powershell`, `yaml`, `json`, `ini` and `text`. Placeholders are `{acme_directory}` and `{ca_name}`; they are allowed in code only, checked in place at their own brace, and replaced after parsing by `Guide.Resolve`. The tests cover the golden parse of a fixture, every refusal of the plan (raw HTML, `<script>`, an image, `javascript:`, an unknown placeholder, an unclosed fence, an oversize file), the embedded guides (site permalink, `sources`, no secret-like text), `FuzzParse`, and the standard-library rule. After the review: a link to the documentation site or the repository may not hold a `.` or `..` segment or an empty one (`..` could lead out of the allowed base once a browser normalizes it), zero-width and joiner characters are refused like bidirectional controls, and a line of 30,000 braces parses in linear time (it took seconds). | `go test ./internal/guides`: golden parse of a fixture; every embedded guide parses; every construct outside the subset is refused (table: raw HTML, `<script>`, an image, `[x](javascript:…)`, an unknown placeholder, an unclosed fence, 33 KiB); every `site` permalink exists in `site/` and every `sources` file exists; no guide text contains a password, token, key, a real fingerprint or an IP address; a seeded fuzz target `FuzzParse` (`go test -fuzz` short run); `go list -deps ./cmd/myownpki-agent` unchanged |
| 72 | 0.3.11 | **Guides in the UI.** `internal/web/app_guides.go`, `pages/guides/guides.templ`: `GET /guides` (a table: title, summary, who it is for) and `GET /guides/{slug}` (`layout.App`, blocks rendered with existing classes: `.section`, `.table`, the `<pre class="pem">` style for commands, messages for notes and warnings; a heading id per section; a "Longer version" link to the documentation site; the guide itself is complete without it). New navigation group **Help**: *First steps* (step 73) and *Guides*. Any signed-in user may read; guide pages are GET only and have no form; the permission of the page a link leads to still applies there. An unknown slug is 404 with the standard page. Routes go into the screenshot inventory (one shot, light) *Built:* as planned, with the page code in `internal/web/pages/help/` (`guide.templ`, shared with First steps) and the handlers in `internal/web/app_guides.go`: `GET /guides` (a table: guide, what it covers, for whom) and `GET /guides/{slug}`, signed-in users of any role, no form. A guide page has a contents list, a heading id per section, and a "Longer version" link to the documentation site; an unknown slug is the standard 404. New classes `.prose` and `.link-list` are shown on `/design`, and `.table tbody th` is a plain row header now. The navigation has the new group **Help** with *First steps* and *Guides*, and both routes are in the screenshot inventory and in the scans of the rendered pages. After the review the ACME directory is put into a guide only for a role that reads the whole tenant, as First steps does; every other role sees the documented example. | `go test ./internal/web ./internal/web/pages/...`: page tests (every guide renders; hostile placeholder values and a guide text with `<` and `&` are escaped by templ; no inline style, no script, every class defined in `web/styles`; every link is served or allow-listed); the scans of `realPages` include `/guides` and one guide; `task generate` leaves no diff; the screenshot inventory test; a viewer sees the pages |
| 73 | 0.3.11 | **First steps.** `GET /first-steps`: a read-only checklist, each row *done*, *open*, *not available to your role* or *not detected*, with a text, the link to the page that finishes it and the guide. Rows, in order: unseal (`sealed`), a certificate authority exists (links *New CA* and the guides *Build a CA* and *Offline root*), the CA's public base URL answers (what the dashboard already knows about CRL attention, **no new request**), a domain exists, ACME is configured (`a.d.ACMEDirectory`), a first certificate exists (not an agent certificate), a host or agent is added (*Add host*), backups (always *not detected*: link to the backup guide), trust the root (link to the trust portal and the guide), notifications (a configured channel if the alert service says so; else *not detected*). Every status comes from calls the dashboard and list pages already make, under the user's own permissions; a role limited to one CA sees the rows it may see and the rest as *not available to your role* (never an error). **It writes nothing, stores nothing, has no form and no button that changes state**: its buttons are links; actions happen on the existing pages with their own step-up. The dashboard shows one information message "Your instance is new – see First steps" **only while** no CA, no domain or no certificate exists (derived each time; no dismiss state, no migration); the message names no secret. `init` ends with one line "Next: sign in and open Help, First steps" (no URL guessing, no secret). Screenshot inventory: empty, partial and complete instance *Built:* as planned, in `internal/web/firststeps.go` (the facts and the ten rows) and `app_firststeps.go` (the page and the dashboard notice), rendered by `pages/help/firststeps.templ`. The ten rows are: unseal, certificate authority, public base URL and CRL, domain, ACME, first certificate, host with an agent (optional), backup, trusting the root, notifications (optional); backup and trust are always *Not detected*. Each state comes from calls the dashboard and the list pages already make, under the user's own permissions; a role limited to one CA sees *Not available to your role* for the tenant-wide rows. The page has no form and no state, and a test counts the rows of the databases that a GET could touch (certificates, CAs, domains, outbox, keys, agents, tokens, ACME accounts, versions and both audit logs) before and after a GET. The dashboard message "Your instance is new – see First steps." shows only to a role that reads the whole tenant, while there is no CA, no certificate or (ACME on) no domain. `myownpki init` ends with "Next: sign in and open Help, First steps.". | Page tests with a fixture per state (empty, partial, complete, sealed, viewer, CA-scoped operator, ACME off); proof that a GET performs no write (row counts of the audit log, `outbox` and the domain list before and after, as the preview tests do); the banner appears and disappears with the data; `init_test.go` for the extra line; the scans of `realPages`; `task generate` no diff |
| 74 | 0.3.11 | **The five guides** (content only, after step 71; can run beside 72 and 73): *Build a certificate authority* (online intermediate, when the root should stay offline, name constraints, the CRL base URL), *Offline root* (what stays off the server, importing an intermediate, `legacy/pki.sh`), *Connect certbot* (the EAB key from the UI, the directory URL, `--server`, trusting the root, a first `certbot certonly`, renewal), *Install the agent and add a host* (the Add host assistant, enrollment modes, a recipe with `--dry-run`, the rollback), *Back up and restore* (what a backup holds and does not, `myownpki backup`, `backup verify`, a restore drill). Each is about 1.5 to 4 KB, written for this instance, ends with the link to the long page, lists its `sources`, and says what it **cannot** show (no passphrase, recovery key, token or EAB secret: those exist only where they are created, once). The commands are the ones the long pages use, checked against `cmd/` and OPERATIONS *Built:* five guides, `build-a-ca`, `offline-root`, `connect-certbot`, `install-the-agent` and `backup-and-restore`, and a sixth, `using-the-guides` (order 900), which explains how to read them; six of the eight allowed. Each lists its `site` page and its `sources`. The test of the command programs allows `myownpki`, `myownpki-agent`, `certbot`, `sudo`, `curl`, `openssl`, `systemctl`, `install`, `docker` and `./pki.sh` (the plan's list plus the offline root tool), and refuses a pipe into a shell. After the review the certbot guide warns that the EAB MAC key on a command line is visible in the process list, the shell history and the sudo log, because the repository documents no certbot configuration file for the EAB options. **None of the guides has been run on a live instance.** | The parse test of step 71; a test that every command line in a `bash` block starts with `myownpki`, `myownpki-agent`, `certbot`, `sudo`, `curl`, `openssl`, `systemctl`, `install` or `docker`, and that none pipes into a shell (`curl … \| sh` is refused); `scripts/ci/site-check.sh` unaffected; a read-through against the pages listed in `sources`, reported as the review of this step |
| 75 | 0.3.11 | **Demo files.** `deploy/demo/docker-compose.yml` (project name `myownpki-demo`, its own volumes and network, nothing shared with `deploy/docker-compose.yml`): `init` (one-shot, `myownpki init --demo --with-ca --ca-base-url http://myownpki:8080`, secrets file into the data volume), `myownpki` (the image `${MYOWNPKI_IMAGE:-ghcr.io/der-felix/myownpki:0.3.11}`, `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, UI published on `127.0.0.1:9443` only, `acme.tls_issuer` so the ACME port speaks TLS with the demo CA, a healthcheck), `certbot` (a pinned image; `--standalone` on port 80 of its own container, a network alias for the demo name so the server's http-01 check reaches it, the root fetched from the public listener with its fingerprint printed for comparison), and, as the second act, `web` (a small build in `deploy/demo/web/Dockerfile`: `FROM` a pinned `nginx`, `COPY --from=${MYOWNPKI_IMAGE}` the agent tarball of its architecture from `/opt/myownpki/agent-dist`, **verified against `checksums.txt`** in a `RUN`, an entrypoint that starts the agent and nginx; the demo agent configuration uses hooks `nginx -t` and `nginx -s reload`; `profiles: [agent]`, so the first act runs without it). `deploy/demo/demo.sh` (Bash, `shellcheck`-clean): `up` (init once, start, wait for health), `unseal` (reads the passphrase from the demo secrets file and calls `POST /api/v1/system/unseal`; the password and TOTP sign-in uses the helpers of `test/install/systemd_test.sh`, moved into a shared file if both need them), `domain` (creates the demo domain with address policy `internal` and http-01: it needs the second factor, which is why the script and not the compose file does it), `certbot`, `run` (all of these in order), `down` (removes the volumes). The UI banner "DEMO instance" stays. A `README.md` in `deploy/demo/`: the commands per act and what to look at in the UI after each. **Honest scope** (decision 15): after `docker compose up` the server is sealed; `./demo.sh run` unseals, creates the domain and runs certbot; the agent act ends with one approval click in *Agents → Enrollment requests* *Built:* in `deploy/demo/`: `docker-compose.yml` (project `myownpki-demo`, own network and volumes), `config.yaml`, `demo.sh`, `certbot/run.sh`, `web/Dockerfile` and `web/entrypoint.sh` (the second act), `README.md`, `.env.example`, and `demo_test.go` (the static test of the plan). The commands are `up`, `unseal`, `domain`, `certbot`, `verify` (all in `run`), `agent`, `logs` and `down`; `verify` is the check of the chain with `openssl verify`, the name and the audit entry. The roadmap row "one command" holds as `./demo.sh run`, not as one `docker compose up`, as decision 15 said. The second act ends with one approval click. The certbot and nginx images are pinned by digest with rows in `THIRD_PARTY.md`. | **Without Docker** (`deploy/demo/demo_test.go`, parses the compose file with the repository's YAML library): every image is `name:tag@sha256:…` (no `latest`, nothing untagged); no `ports` except `127.0.0.1:` for the UI; the server service is `read_only` with `cap_drop: [ALL]` and `no-new-privileges`; no `privileged`, host network, `docker.sock` or inline secret; volumes are named volumes (no host path except read-only config); the project name differs from the production example's; every `${VAR}` has a default or is documented; every file the compose file names exists; `shellcheck deploy/demo/demo.sh` (installed here). `go test ./deploy/...` |
| 76 | 0.3.11 | **The demo in CI.** A step in the `image` job after the snapshot (it has built the image already): `MYOWNPKI_IMAGE=<snapshot tag> bash scripts/ci/demo-check.sh`: `docker compose config` (valid and resolves), the stack comes up, `demo.sh` unseals, creates the domain, certbot obtains a certificate for the demo name, **the chain verifies against the demo root with `openssl verify`** and the certificate's SAN equals the requested name, the audit log (through the API) has the issuance, `docker compose down -v` leaves no volume. On failure the compose logs are printed without the secrets file; the demo secrets are masked with `::add-mask::` like the TSIG key in `test/conformance/run.sh`. The agent act runs in CI only if the enrollment can be approved through the API in the same script (second factor from the demo TOTP secret); otherwise it is a live test. Images by digest, `THIRD_PARTY.md` rows. Not a required check *Built:* `scripts/ci/demo-check.sh`, a step of the job `image` after the snapshot (the job's timeout is 35 minutes now), registered in `scripts/ci/local.sh` so that `task ci:local` reports a SKIP without Docker or the snapshot image. It runs `docker compose config`, `demo.sh run` (unseal, domain, certbot, `openssl verify`, name and audit entry), builds the web image of the second act, and ends with `down -v`. The agent act itself is **not** run in CI (it needs the approval click); only its image builds. Not a required check. | The CI log; `bash scripts/ci/shellcheck-smoke.sh`; the static test of step 75 stays in `go test`; on this machine only the static part can run |
| 77 | 0.3.11 | **Docs, screenshots, release.** Pages: `site/recipes.md` (three new rows, the corrected warning, *What to verify* per recipe, the `combined` file and the sidecar-key alternative), `site/hosts.md`, `site/choose.md`, `site/index.md`, `site/best-practices.md`, `site/cli.md`, `site/faq.md` (also the stale "what comes next"), `site/hosts/salt.md`, `deploy/salt/myownpki/README.md` and `pillar.example` (the new recipe names, `files.combined` for `config_source`), cases `debian-apache2` and `debian-haproxy` in `deploy/salt/test/cases`; a new page `site/guides/guides-in-the-ui.md` (what the Help group shows and never does) and `site/demo.md` with `site/_data/nav.yml`; `site/upgrade.md` (agents first for `combined`; no migration; the image base); `site/install.md` and `README.md` (the image is Debian 13); `docs/OPERATIONS.md` (§12.9 recipes, a section on Help and First steps, the demo, the image base); `docs/RELEASING.md` (the digest rule); CHANGELOG `[0.3.11]` (undated; Added, Changed: base image; Upgrading: agents first, no migration; *Known limitations* names what is not live tested); screenshots (`first-steps`, `guides`, `guide`) if the maintainer wants PNGs; PLAN §10.1 row, lines 489 to 501 and `CLAUDE.md` status after the tag. **Version bump as in `46834a8`:** `README.md`, `api/openapi.yaml` (`info.version`), `deploy/docker-compose.yml`, `deploy/install-agent.sh` and `deploy/install.sh` (`DEFAULT_VERSION` and the `v=` example), `deploy/salt/myownpki/README.md`, `map.jinja` (the example in an error message), `pillar.example`, `docs/OPERATIONS.md`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh` (fixture names and the `DEFAULT_VERSION` assertion), **plus** `deploy/demo/docker-compose.yml` and `deploy/demo/README.md`; CHANGELOG dated by the maintainer *Built:* the version bump of `46834a8` (plus the demo, which already named 0.3.11), the CHANGELOG, the pages `site/recipes.md`, `hosts.md`, `cli.md`, `upgrade.md`, `index.md`, `choose.md`, `best-practices.md`, `faq.md`, `install.md`, the new `site/guides/guides-in-the-ui.md` with its nav entry, the Salt README, `pillar.example` and `site/hosts/salt.md`, and OPERATIONS §12.1, §12.3, §12.7, §12.9, §9 and a new chapter 17 (Help, First steps, the demo, the image base). `site/guides/offline-root.md` now says what each tool does for the CRL lifetime of an offline root (the server's 180 days is a planning value, `pki.sh` signs for `CRL_DAYS`, 30 by default). **Not done:** the Salt cases `debian-apache2` and `debian-haproxy` (the `salt formula` job would run them for the first time), `site/demo.md`, screenshots, and `docs/RELEASING.md` (the digest rule is in `THIRD_PARTY.md`). OPERATIONS §12.1 says **New CA** with the field *Parent CA*: the real UI has no *New intermediate CA* button (it exists only in the `/design` prototype list). | `scripts/ci/site-check.sh`; every documented command and URL checked against the code; `task ci:local` with every SKIP line reported; `bash scripts/ci/salt-test.sh --self-test`; a grep for the old version string and for `static-debian12` finds only history; `docs/RELEASING.md` |

**Order and parallelism.** Four lanes touch different files and can run at the same time, each as a stretch of commits inside `release/v0.3.11` (or short-lived topic branches merged into it, in any order):

1. **Lane A (agent and recipes), sequential:** 66, then 67 (commit 1 may run beside 66: it touches only `internal/agent`, while 66 touches `internal/recipe`, `internal/web` and the tests that name "apache"), then 68 (needs 66 and 67), then 69 (needs 66 to 68).
2. **Lane B (guides), one fork:** 71, then 72 and 74 in parallel (72: `internal/web`, `layout`, routes; 74: only `internal/guides/content`), then 73 (shares `app.go`, `layout/app.templ` and the inventory with 72, so after it).
3. **Lane D (image base):** 70 alone; it touches `deploy/docker/Dockerfile`, `internal/config/config_test.go`, `THIRD_PARTY.md` and `ci.yml` (the `image` job). Do it **before** lane C's CI step, so the demo is tested on the final base.
4. **Lane C (demo):** 75 (files under `deploy/demo/`, no conflict with anything), then 76 (edits the `image` job in `ci.yml`: after 70).

**Shared files, edit them one at a time:** `THIRD_PARTY.md` (69, 70, 76), `.github/workflows/ci.yml` (69, 70, 76), `internal/web/hostadd.go` and `app_hostadd.go` (66, 67, 68), `internal/web/app.go` and `layout/app.templ` (72, 73). Step 77 runs last and alone. An independent review of the diff (§17.4) happens after step 69 for the agent part and after step 74 for the guides part, before step 77 writes the docs.

**Live test for the maintainer** (a test domain such as `scratch.homelab.lan`, test hosts, not production):

1. Update the server to v0.3.11; `myownpki db status` is unchanged (no migration). Update the agent on the test hosts **first** (an older agent refuses `files.combined`).
2. **Apache on Debian or Ubuntu:** `myownpki-agent deployment add apache2 --recipe apache2 --name www.scratch.homelab.lan --webroot /var/www/html --dry-run`, then for real. Point `SSLCertificateFile` and `SSLCertificateKeyFile` of a vhost at the printed paths (`a2enmod ssl`). `apache2ctl configtest` passes. A *Renew now* from the UI: `openssl s_client -connect <host>:443 -servername www.scratch.homelab.lan` shows the new serial and the agent reports `deployed`. Corrupt `privkey.pem` by hand and run the deployment again: what does `configtest` say, and does the rollback restore the old pair? Note the answer for the recipe notes.
3. **Apache on Rocky or Alma** (`httpd`, SELinux enforcing): the same, plus `ls -Z /etc/ssl/myownpki`, and whether Apache can read the files without a `restorecon`.
4. **HAProxy:** `deployment add --recipe haproxy --name www…` twice with two names; try `crt /etc/ssl/myownpki/haproxy/` and one `crt` per file; `haproxy -c` and a reload serve the new certificate on both; a staged corrupt file is refused by `haproxy -c`; `systemctl show myownpki-agent -p ReadWritePaths` shows no log directory for HAProxy.
5. **Sandbox:** `journalctl -u myownpki-agent` for "Read-only file system" or "Permission denied" from any of the hooks; if one appears, the recipe gets the directory or `low_ports` and the notes change.
6. **First steps and guides:** `myownpki init --stdin …` on a fresh test instance, sign in: the dashboard says the instance is new, *Help → First steps* lists the rows in the right state, and creating a CA, a domain and a first certificate turns them done. Open each of the five guides and run its commands on a test host; correct every difference in the text. Sign in as a viewer: the pages open, and no row offers an action the role lacks.
7. **Demo (a Docker host):** `cd deploy/demo`, the commands of its README: unseal, domain, certbot gets a certificate, `openssl verify` against the root passes; then the agent act with one approval; `docker compose down -v` leaves nothing.
8. **Image:** `docker run --rm ghcr.io/der-felix/myownpki:0.3.11 --version`; `docker image inspect` shows user `65532`; `deploy/docker-compose.yml` with the new tag starts and `docker compose ps` shows `healthy`; a notification webhook or SMTP-over-TLS test (`myownpki notify test`) succeeds, which proves the CA certificates in the new base.

### 17.2 Decisions

The maintainer was not available; each row takes the cautious option. Review them together with §17.7.

| Topic | Decision | Why |
|---|---|---|
| **1. Recipes, not profiles** | Apache is two **recipes** (`apache2`, `httpd`) over the existing `nginx` profile; HAProxy is a recipe over the `file` profile with one new target (`combined`). The profile named `nginx` keeps its name (an alias such as `directory` would be a config change for nothing) | The roadmap says "profiles", but what differs between services is paths, hooks and sandbox, which is what recipes are. The deploy pipeline (test, reload, TLS check, rollback) stays exactly as live-tested for nginx |
| **2. Two Apache names** | `apache2` for Debian and Ubuntu, `httpd` for the Red Hat family; the names are the unit names, so an admin sees what the recipe reloads. No OS detection in the recipe table | The table is static data shared with the server's assistant, which does not know the host. A wrong guess is a failed test hook and a rollback; a name the admin chose is not. Unit, binary and log paths differ per family |
| **3. HAProxy one-file target** | New `files.combined` (certificate chain, then key, one `0600` file) with a refactor first. **Fallback:** the sidecar form (`<name>.pem` and `<name>.pem.key`) with no agent change | One atomic rename for a pair that must never disagree, and the form every HAProxy guide shows. The sidecar form is documented for the global `ssl-load-extra-files` default (3.0 manual) but its handling in a directory `crt` is not verified, and it leaves a window with two files. The cost of `combined` is a config key that older agents refuse (agents first) |
| **4. Apache `configtest` is not a key test** | Nobody should rely on it for the key pair: the guards are the agent's own pair check before writing, the TLS check after the reload and the rollback. Step 69 records what `configtest` really does and the docs say it | I believe `-t` ends before `mod_ssl` loads the key. If so, a file corrupted after writing is found only by the reload, and a graceful reload with a broken key can leave the service down, so that the rollback reload runs on a dead service. The recipe notes say so; it is the first live-test question |
| **5. Local check default** | Keep `127.0.0.1:443` for Apache and HAProxy like nginx, and say in the notes when it must change (`--check`, or none) | A check that fails on a valid setup (a bind to a LAN address, `accept-proxy`, SNI routing to another certificate) rolls back a good deployment every time. The notes make the failure explainable; the option stays the admin's |
| **6. Sandbox** | No `low_ports`, no log directory for HAProxy; Apache gets its log directory; the hint stops guessing for `-c` and `configtest` | Check modes bind nothing (to verify); a wrong hint trains people to widen the sandbox. Step 69 and live test 5 decide |
| **7. All three stay "examples"** | `Example: true` for `apache2`, `httpd` and `haproxy` until a live test; CI proves the files, the hook and the rollback against the real binaries, not the packaging, the unit or SELinux | The project's rule since v0.3.5: only what ran on a live host is not an example. CI containers are not the maintainer's hosts |
| **8. Guides are our content, not a copy of `site/`** | Five short, instance-aware guides in `internal/guides/content/`, each pointing to the long page on the documentation site; a test ties each to its `site` permalink and `sources` | The site pages are Jekyll sources (Liquid, kramdown) of 6 to 17 KB; transforming them at build time is fragile and the result would not be reviewed as UI. Drift is the price; the pointer and the `sources` list are the control, as for the site pages |
| **9. No Markdown dependency** | A strict subset parsed by about 300 lines of own code into typed blocks that templ renders (the pattern of `trustkit.Guide`). If the maintainer prefers `goldmark` (MIT, no module dependencies as far as I know, **not verified**), that is a **new dependency and needs the owner's OK**, and it would still need an HTML-free configuration and a link allow-list | The content is authored by the project, not attacker input, but the renderer decides what can ever reach the page: a closed block vocabulary makes "no raw HTML, no script, no off-site image" a parse rule, not a sanitizer. Cost: authors use a small subset |
| **10. Where guides appear** | Signed-in admin UI only, a new navigation group *Help*; **not** on the public listener | The public listener is unauthenticated and serves the trust portal only (§15); instance values in guides (the ACME directory) belong behind the login |
| **11. First steps = derived, stateless, read-only** | The page is a checklist computed on each request from calls the UI already makes, under the user's permissions. No "done" flag, no dismiss button, no migration, no redirect after sign-in; a plain information message on the dashboard while the instance has no CA, domain or certificate. It never writes, never shows a secret and never starts anything: its buttons are links to pages that have their own step-up | A stored dismissal would be state in `system.db` with a migration for a convenience. A derived checklist cannot go out of date and cannot be abused; the sensitive actions keep their second factor on the pages that own them. `init` cannot open a page, so it prints one line |
| **12. Guide values** | Placeholders come from a closed list, from configuration and engine data only (the configured ACME directory, a CA name), never from the request (`Host` header, query); an empty value shows the documented example text | A request-derived address in a command a user pastes into a shell is an injection path (the same rule as the trust portal) |
| **13. External links** | Only to the project's documentation site and repository (constants); plain `<a>`, no images, no embeds; the five guides are complete without the long page, so an air-gapped install does not depend on the site | CSP forbids third-party content anyway |
| **14. Permissions** | Guides and First steps for every signed-in role; each checklist row shows only what the role may read and says *not available to your role* otherwise; no new permission | Static text carries no tenant data; a new permission would be a second place to forget |
| **15. Demo scope** | Act 1 (CI-tested): server (demo instance), CA, domain, certbot with http-01 to a certificate, one script `demo.sh run` that does the unseal and the domain through the API with the secrets file the demo init wrote. Act 2 (live test): nginx plus the agent from the image's own packages, one approval click. Not "one command" without the unseal | The passphrase is never read from a file or variable, and a domain needs the second factor. Doing both in a script that reads the **demo** secrets file is honest because a demo instance is marked as one for good; the production compose file keeps its manual `init`. The roadmap's "one command shows http-01 end to end" holds as `demo.sh run` |
| **16. Demo and production stay apart** | Own project name, volumes, network, config and container names; no shared volume; `deploy/docker-compose.yml` changes only its version tag | A demo that shares a volume with a real instance can overwrite a CA |
| **17. The demo image** | `${MYOWNPKI_IMAGE:-ghcr.io/der-felix/myownpki:0.3.11}` so CI can use the snapshot; third-party images by digest; the agent for act 2 comes from the **server image's** own verified package, not from a download | One trust root (the signed release) and no `curl` at build time; a tag that exists only after publication is documented in the README |
| **18. Base image digest** | `static-debian13:nonroot` pinned by the **index digest**, chosen by the two-week rule: the newest index older than 14 days that carries a `nonroot-<commit>` tag (on 2026-11-16 that is the one uploaded 2026-10-31; the current `nonroot` index is from 2026-11-12), re-read on the day of the step. The Dockerfile keeps `:nonroot@sha256:…` in both places; `config_test.go` follows | The rule is the project's own (THIRD_PARTY). A fresh digest is the one most likely to be bad; a digest chosen by commit tag is as stable. No digest is written into this plan: it is looked up by the commands in step 70, and the maintainer approves the pin in the review of that commit |
| **19. Image checks in CI** | The `image` job also proves user 65532, a working `--version`, the CA bundle and the data directory in the exported file system | Distroless has no shell; the only checks are the binary and the exported tree. A base change is a security decision that should fail loudly, not at the first webhook |
| **20. Docs timing** | All documentation in step 77; the demo page says plainly that its image tag exists after the release | Four lanes never write the same docs, and the CHANGELOG is one story |
| **21. ADRs** | None changed. ADR-10 and ADR-19 hold: the agent still takes no command from the server, and issuance still goes through ACME | The task rule |

### 17.3 Dependencies

**None planned.** `go.mod`, `go.sum` and `deps_test.go` stay as they are: the guide engine is `bufio`, `strings`, `embed`; the checklist uses existing services; the demo test uses the repository's YAML module. **Needs the owner's OK only if decision 9 is reversed:** `github.com/yuin/goldmark` (MIT; to check with `go list -m` before asking). New **CI-only images** are not Go dependencies but pinned artifacts with rows in `THIRD_PARTY.md`: a Debian 13 base for the Apache test, the official `haproxy` image, `certbot/certbot` and `nginx` for the demo, and `distroless/static-debian13`. Each digest is read at its step with the two-week rule; none is invented here.

### 17.4 Security review (an independent reviewer checks, with the diff only)

- **Agent recipes (steps 66 to 69):** every hook is an absolute argv with no shell and no template of request data (`{name}` only in paths, and names are validated hostnames); the recipe table is compared with the services' documentation; what each recipe lets the sandbox write (a log directory, nothing else; never `/etc/apache2` or `/etc/haproxy`); owner root, key mode without rights for others; **no recipe edits a service configuration**.
- **`files.combined`:** one file with the private key: mode and owner are the key's, never the certificate's `0644`; atomic write in the target directory with an exclusive temp file (the existing `atomicTarget`); the combined buffer exists only in memory, is cleared after use and appears in no log, error text, journal field or status (a redaction test); the journal backup is `0600`; a symlink or a directory swap cannot redirect the write (`os.Root` containment is unchanged and tested for the new field); `combined` cannot name `state_dir`, `ca_bundle` or another deployment's file; step 67 commit 1 changes no behavior (the test diff is empty).
- **Rollback and honesty:** a failed test hook or reload restores the previous file exactly; the first installation removes it; no path leaves a half-written key; no document claims that `configtest` validates the key unless step 69 shows it.
- **Guides parser (steps 71, 72, 74):** the parser accepts only the closed subset; raw HTML, images, `javascript:` and unknown placeholders fail the build-time test; templ escapes everywhere and `templ.Raw` appears nowhere; links are same-origin UI paths, other guides or the constants; no guide contains a secret, a real address or a command that pipes a download into a shell; every embedded file is size-limited; the fuzz target finds no panic.
- **First steps:** a trace of every value: nothing from the request reaches a template except the slug of a guide, which is an allow-list lookup; the page performs **no write** (audit, outbox and row counts unchanged by a GET, a test); per-row permission checks use the same functions as the target pages; a CA-scoped role does not learn tenant-wide facts from the checklist (a test with a scoped role); no secret, token, passphrase or key is on any page.
- **Demo:** the compose file is hardened like the production one (`read_only`, `cap_drop`, no privileged, no socket, loopback publish); the **demo secrets file** never reaches a CI log (masked) and never an image layer; the agent in act 2 comes from the verified package of the image; nothing in the demo is documented as usable for production, and the instance stays marked as a demo.
- **Image base:** the digest in both Dockerfile places equals the one in `THIRD_PARTY.md`; the index has both platforms; user, data directory owner and CA bundle are checked by the CI job; `task vuln` clean; no new package in the image.
- **Dependencies and build:** empty `go.mod` and `go.sum` diff; `go list -deps ./cmd/myownpki ./cmd/myownpki-agent` unchanged; `CGO_ENABLED=0` builds.

**Result of the independent review (2026-11-16, agent recipes and guides).** No blocker. The findings were fixed before step 77: a killed agent could leave the exclusive temporary file of a write in a target directory, which for a combined file holds the private key and which HAProxy may load when `crt` is a directory, so the recovery step before the first pass removes files that match the exact temporary name and nothing else (a symlink, another name or a directory is left alone, each removal is a warning with the path only); a link to the documentation site or the repository with a `.` or `..` segment or `//` could lead out of the allowed base once a browser normalizes it, so these paths get the check of UI paths; the certbot guide shows `--eab-hmac-key` on a command line and now warns about the process list, the shell history and the sudo log; the buffers that hold the combined file and the previous pair are cleared after use; a line of 30,000 braces made the guide parser take seconds, so a brace is checked in place and zero-width characters are refused; and the guides put the real ACME directory into a command for a role limited to one CA, which First steps already hid, so every role that does not read the whole tenant gets the documented example.

### 17.5 Risks

| Risk | Handling |
|---|---|
| A reload with a broken key takes Apache down and the rollback reload fails on a dead service | The agent checks the pair before writing and the TLS check runs after the reload; step 69 recorded what `configtest` covers. Observed in CI (Apache 2.4.58, Ubuntu 24.04): `configtest` passes a mismatched key, and the graceful reload with a damaged key stopped Apache, which the rollback did not bring back (result `rolled_back`, process gone); the notes and `site/recipes.md` say so; live test 2 provokes it under the real unit on a test host. Open: what `systemctl reload` and the unit do with a stopped Apache |
| A recipe default (check on `127.0.0.1:443`, the test command with the default configuration path) is wrong for a valid setup and rolls back every renewal | The notes name the cases; every default is overridable; `--dry-run` shows the result; the first deployment of an example recipe is advised on a non-production host |
| Debian packages and official images differ (paths, `envvars`, modules), so a green CI says little about a host | CI uses the Debian 13 package for Apache (the layout of the recipe) and says in the test file what it does not cover; the Red Hat layout and SELinux are named as live-test only |
| `files.combined` makes `agent.yaml` incompatible with older agents | Agents first (`site/upgrade.md`, as for dns-01 and `system_trust`); a host without the key is untouched; the Salt `config_source` README says it |
| The refactor of step 67 introduces a bug in a shared path (nginx, Postfix) | Commit 1 changes no behavior and no test; the nginx e2e job and the whole `internal/agent` suite run on it; the diff is reviewed as a pure refactor |
| The guides drift from the long pages and the code | `site` and `sources` front matter, the command-prefix test, the limit of five guides and the "Longer version" link; a guide states what it cannot show; the live test walks each guide |
| A new admin never finds First steps | A Help group, a dashboard message while the instance is empty, and the extra line of `init`; a redirect after sign-in is **not** built (it would need state) |
| The demo gives people a sealed server and a script that holds the demo passphrase; someone copies the pattern to production | The demo says so in the banner, the README and the log at every start; the production compose file is unchanged and keeps the manual `init` and unseal; the server still never reads the passphrase from a file |
| The demo needs `acme.tls_issuer` and a bootstrap order (sealed server, then unseal) | The CI run follows step 4b of `test/install/systemd_test.sh`, which already does exactly this; the demo script waits for the issued certificate before certbot starts |
| Docker-only steps cannot run on the development machine | Static tests (YAML structure, pins, hardening, `shellcheck`) run locally; everything else is CI and the maintainer's Docker host; the plan says which is which |
| The base digest is older than two weeks but a security fix landed since | `govulncheck` covers Go, not the base; the digest is re-read at every release and `THIRD_PARTY.md` says how; a fix is a new digest by the same rule |
| `static-debian13` differs from 12 in a way the binary notices (CA bundle path, user, home) | The image checks of step 70 and live test 8 compare these; the binary has no glibc and uses no tzdata |

### 17.6 Not in v0.3.11

- Recipes for other services (Caddy, Traefik, Exim, Cockpit, Gitea, …), a recipe that edits a service configuration, `crt-list` management, HAProxy runtime-API updates without a reload, OCSP stapling files, a recipe table the admin edits in the UI, server-assigned deployments (ADR-10).
- Windows, macOS or FreeBSD agents, and an agent container image for production; the demo's agent image is a demo build.
- A Markdown renderer for the whole documentation, search in guides, translations (ADR-17), a guide editor, guides on the public listener, a "dismissed" flag, a redirect after sign-in, a wizard that creates a CA or a domain for you (the actions stay on their pages with step-up), a progress meter, telemetry.
- A hosted static UI demo on GitHub Pages (PLAN §10.1 names it as an addition; it is its own piece of work), a Kubernetes or Podman demo.
- Any ADR change, any migration, any REST change.

### 17.7 Open points for the owner (with the default I would take)

1. **Recipe names** `apache2` and `httpd`, or one name `apache` plus a flag? *Default: two names.* (Decision 2.)
2. **HAProxy one-file target** with the agent change and "agents first", or the sidecar `.key` form with no agent change? *Default: `files.combined`; the sidecar form is the documented fallback.* (Decision 3.) Say which before step 67 starts.
3. **Markdown:** keep the no-dependency parser, or allow `goldmark` (needs your OK, then `go list -m` and a THIRD_PARTY row)? *Default: own parser, no dependency.* (Decision 9.)
4. **Guides are short in-app texts** pointing to the site, not copies of the site. Acceptable? *Default: yes.* (Decision 8.)
5. **First steps without any stored state** (no dismiss, no redirect). Or do you want a per-user "hide" and accept a `system.db` migration? *Default: stateless.* (Decision 11.)
6. **Demo scope:** act 1 is automated by a script that reads the demo secrets file; act 2 needs one click. Is a scripted unseal acceptable for a demo? *Default: yes, for the demo instance only.* (Decision 15.) The alternative is a demo where the user types the passphrase.
7. **Demo images:** `certbot/certbot` and `nginx` pinned by digest, read at the step with the two-week rule. Anything you prefer (lego instead of certbot)? *Default: certbot, as PLAN §10.1 says.*
8. **Base digest timing:** pin the 2026-10-31 index now, or wait until the current `nonroot` index is two weeks old (2026-11-26)? *Default: the older index, re-read on the day.* (Decision 18.) Nobody should merge a digest that was not read from the registry that day.
9. **A required CI check for the new steps?** *Default: no separate required check; they run inside the existing `agent end-to-end` and `image` jobs.*
10. **The recipes stay "examples"** (decision 7) although CI runs the real binaries. *Default: yes, until the live test.*
11. **Optional systemd-sandbox test** of `apache2ctl configtest` and `haproxy -c` under the real unit (like `agent-e2e-nginx-systemd.sh`): about three more minutes of CI and one more exported root file system. *Default: not in 0.3.11; the live test covers the sandbox.*

**Still not live tested (for the CHANGELOG's *Known limitations* and the docs; updated at step 77):** all three new recipes on real hosts under the real systemd unit and its sandbox (Debian and Ubuntu for Apache, the Red Hat family with SELinux for `httpd`, HAProxy from the distribution package); the three questions that were open for CI are **answered by the first CI run** (Apache 2.4.58 and HAProxy 2.8.30 on Ubuntu 24.04, packages started by the test with a private configuration; the answers are in the recipe notes, `site/recipes.md` and the CHANGELOG): (1) `apache2ctl configtest` does **not** detect a key that does not match the certificate; (2) a failed graceful reload with a damaged key can stop Apache, and the agent's rollback restores the files (`rolled_back`) without bringing Apache back; (3) `haproxy -c` refuses a certificate and key that do not match, the directory form of `crt` skips the agent's temporary `.myownpki-*` file, and the order of certificate and key in the combined file does not matter. The same run showed that `apache2ctl configtest` creates `/run/apache2`, `/run/apache2/socks` and `/run/lock/apache2` when they are missing, so under `ProtectSystem=strict` (the recipe makes only `/var/log/apache2` writable) the test hook fails when Apache has not been started since the boot. **What remains for the live test:** all of this on real hosts and under the real systemd unit and its sandbox (the reload there is `systemctl reload`, not `apache2 -k graceful` on a private configuration, so whether the unit starts a stopped Apache again is open); `httpd` on the Red Hat family (the answers above come from the `apache2` package); SELinux and AppArmor; other Apache and HAProxy versions than 2.4.58 and 2.8.30; the local check against real bindings (`accept-proxy`, LAN-only binds); every statement about the services' paths, units and logs and the notes on SELinux; the claim that `check` hooks need no low ports (the recipes set none); the six guides as text on a real instance, every command in them (the certbot flags, the EAB flags and the agent and backup commands), and the First steps rows for each role; the demo on a Docker host (CI runs its first act on the snapshot image, **not** its agent act, which needs the approval click) and the agent in the demo's nginx container; the Debian 13 base on the maintainer's Docker host and with real webhooks and SMTP over TLS. **Not tested at all:** the Salt formula with the new recipes (no case was added; `combined` is passed through by the option list only). **Not verified by running:** the site build (Jekyll is not installed on the development machine; `scripts/ci/site-check.sh` ran and passed), the package `internal/publish` tests (blocked on this machine by Windows Defender, run in CI), and `task check` as a whole.

## 18. Quality round: v0.3.12

The roadmap row "Before Beta" (PLAN §10.1) is a stability round, not a feature: dead code and duplicates, consistent
error messages, a coverage report and the test gaps it shows, **Go fuzzing** of the parsers that read attacker input
(today `task fuzz` covers the ACME JWS parser only) and stricter lint rules; the outcome in the plan is "fewer surprises
in the beta". It is called **v0.3.12** here because v0.3.10 is released and v0.3.11 (Apache and HAProxy, guides, demo)
is in PR #49; **the number can shift** (§10.1: "order before numbers"). The step numbers below continue after 77 and
assume that §17 (v0.3.11) ends there; when #49 merges, §17 stands above this section. Written on 2026-11-16 as a
plan for review: the decisions in §18.5 are cautious defaults, not agreements. There is no product
feature in this release, no migration, no API change and no new dependency; the only changes to behavior are the
fixes that fuzzing finds, each with its own commit and a committed regression input.

Goal, checked in CI and on the maintainer's machine: `task fuzz` runs every target of §18.2 (the list is one file, a
test fails when a `Fuzz*` function is missing from it), every target has hostile seeds and asserts what the parser
promises, CI runs each for a few seconds on every code change and for minutes every night, and a finding is a failing
test in the repository before it is a fix; `task cover` prints one table that credits integration tests to the
package they exercise, and the security-relevant error paths of §18.1 steps 95 to 98 are tested; `task deadcode`
reports nothing that is not on a reviewed list; the lint configuration is stricter by the checks that measured clean or
nearly clean (§18.1 step 93); and after the release the admin sees the same product, only with fewer crash and
refusal surprises.

**Facts found in the repository (2026-11-16, `release/v0.3.12` = `origin/main` 65ee465; measured on the development
machine, Windows Server 2025, Go 1.27.4, golangci-lint 2.15.0 which is the pin in `Taskfile.yml`; `internal/publish`
was not run here, Windows Defender blocks its test binary):**

- **Fuzzing today.** One `Fuzz*` function exists in the whole repository: `FuzzParse` (`internal/acme/jose/jose_test.go:344`),
  with three `f.Add` seeds, asserting the accept rules of `jose.Parse` and running `Verify` on an embedded key. There is
  **no `testdata/fuzz` directory anywhere**, so no corpus and no regression input. `task fuzz` (`Taskfile.yml`, `FUZZTIME`
  default 30 s) runs only that target; CI runs it in job `check` right after `task check` (step "Fuzz the ACME JWS parser
  (short run)", `.github/workflows/ci.yml`; registered in `scripts/ci/local.sh`). Go runs one fuzz target per invocation
  and per package, so more targets need a loop. The daily schedule (04:17) runs only `vuln`; every other job has
  `github.event_name != 'schedule'`. `.gitignore` ignores `*.out`, `coverage.*` and `*.test`, not `testdata/fuzz`.
  Measured here: a 15 s run of `FuzzParse` works with `CGO_ENABLED=0` (4 workers, about 19,000 executions a second,
  36 s wall including the build; found inputs go to the Go cache, never into the tree). `ParseInner`, `ParseJWK`
  and `VerifyEAB` have unit tests but no fuzz target.
- **What the roadmap row names, and what exists.** There is **no `internal/guides`** (the guides in `site/guides/` are
  documentation; the code that writes install steps is `internal/trustkit/guide.go`, a generator of text from a CA's name,
  URL and SHA-256, not a parser; its User-Agent reader `trustkit.Detect` is the parser, unfuzzed). There is **no OCSP
  responder** (PLAN §10.1 "Phase 4"; `internal/ca` only writes the OCSP-signing preset, the public listener serves CRLs
  and CA files by GET), so there is no OCSP request parser. The server **never reads PKCS#12** (`internal/pkcs12` only
  writes, its package comment says so), so "PKCS#12 import" is not an upload. The real upload parsers are four: the CSR
  file of the wizard, a PEM certificate (external import, root import, an offline CA's certificate), the CRL of an
  offline root, and the legacy `.tar.gz`.

| Parser of attacker input | Where | Who can reach it | Tests today | Fuzz |
|---|---|---|---|---|
| ACME request envelope: `jose.Parse`, `ParseInner`, `ParseJWK`, `VerifyEAB` | `internal/acme/jose/jws.go`, `jwk.go`, `jws.go:161`; body read with `MaxBytesReader` 64 KiB in `internal/acme/server.go:393` | anybody on the public listener (before any account) | `jose_test.go`: RFC vectors, a negative test per rule | `FuzzParse` only |
| ACME payloads after the signature: `payload()` (`json.Unmarshal` into small structs), `normalize` (dns/ip identifiers), `planOrder`, the finalize CSR (`checkCSR`: base64url DER), revoke (`certificate` DER, `reason`), key change inner payload, `parseARIID` (GET path, no signature) | `internal/acme/server.go:475`, `order.go:37`, `finalize.go:107`, `revoke.go:37`, `account.go:327`, `ari.go:58` | an account holder, which on an `open` domain is anybody; `parseARIID` is unauthenticated | handler tests (`TestBadCSRs`, `TestRequestRules`, `ari_test.go`, `eab_test.go`); `checkCSR`, `normalize` and `parseARIID` have no direct test | none |
| CSR, PEM: `ca.parseCSR` (64 KiB, one block, no headers, no trailing data, signature checked) and `InspectCSR` | `internal/ca/csr.go:16`, `renewcert.go:179`; reached from the wizard, `POST /certificates`, the preview, `POST /csr/inspect` (`access: signedIn`, so a viewer can feed it) and the agent renewal | any signed-in user | `TestCSRChecks`, `TestMaliciousCSRGetsNoCAPowers`, `TestCSRNamesAreAWishList`, `TestIssueWithACSR` | none |
| CSR, DER: `agents.csrKey` (8 KiB) on enrollment and renewal | `internal/agents/enroll.go:661` | an agent with a join token (enrollment is pre-trust) | `agents_test.go`, `pass_test.go` (indirect) | none |
| CSR file upload: `uploadedCSR` (PEM or DER, 64 KiB) | `internal/web/app_issue.go:218` | operator and up | `TestIssueWithACSR` (indirect) | none |
| Certificate upload: `parseOneCertificate` (one PEM block, 64 KiB), then `ImportExternal` stores it with every SAN as a row (`certNames`, no cap on the count) | `internal/ca/lifecycle.go:890` (used at `lifecycle.go:717`, `offline.go:281`, `renewcert.go:244`); `POST /imports/external-certificate`, `POST /cas/import` | tenant admin (`ManageTenant`) | the contract test only; no unit test of the parser or of a hostile certificate | none |
| Names: `checkDNSName`/`NormalizeDNSName`, e-mail, URI, IP, name constraints (`checkNameConstraints`, `ncDomain`, `ncEmail`) | `internal/ca/names.go`, `profile.go:133` and `:183` | every name from a CSR, an API body, an ACME order | `names_test.go`; `ncEmail` 0 % covered | none |
| CRL upload: `crlDER`, `x509.ParseRevocationList`, the generation, number and freshness checks of `uploadCRL` (4 MiB) | `internal/ca/crlupload.go:270`, `:43` | admin with step-up | `crl_test.go` | none |
| Legacy archive: `legacy.FromArchive` (tar.gz, 64 MiB, 256 MiB unpacked, 100,000 entries), `parseKV`, `parseIndex`, `parsePrivateKey` and `decryptPKCS8` (PBKDF2 up to 10,000,000 iterations), reached by the wizard (`app_admin.go:463`) and `POST /imports` (base64 in JSON) | `internal/ca/legacy/*.go` | admin with step-up | `archive_test.go` (`TestArchiveRefuses`), `legacy_test.go` (these need `bash` and POSIX OpenSSL and skip on this machine) | none |
| Agent protocol: Connect-RPC messages (protobuf, generated), `validReport` (bounds), hostnames and patterns (`CheckHostname`, `CheckPattern`, `Matches`) | `internal/agents/rpc.go`, `report.go:75`, `names.go` | an enrolled agent (mTLS); `Enroll` and `EnrollStatus` before trust | `TestReportInputLimits`, `agents_test.go`; no direct test of the name functions | none |
| REST JSON bodies: `call.decode` (one object, unknown fields refused, 128 KiB) and the reflection walker `unknownFieldPath` | `internal/httpapi/body.go`, `jsonpath.go` | any signed-in role for the routes with a body | `jsonpath_test.go`, `behavior_test.go`, contract tests | none |
| Web forms: `parseForm` (urlencoded or multipart, 64 KiB) | `internal/web/app.go:402` | signed-in users, CSRF-protected | page tests | none |
| User-Agent: `trustkit.Detect` (first 512 bytes, fixed table); the generated install commands embed a CA name and URL | `internal/trustkit/detect.go`, `guide.go` | anybody on the public listener (trust page) | `detect_test.go`, `trustkit_test.go` (99 % covered) | none |
| Files of the operator: `config.Load` (64 KiB), `agent.yaml` (`LoadConfig`, 1 MiB), DNS credentials, agent state and journal JSON | `internal/config/config.go:399`, `internal/agent/config.go`, `dns_creds.go`, `state.go`, `deploy_journal.go` | the machine's administrator (not an attacker in the product's threat model; a hardening target) | `config_test.go` (17 tests), agent tests | none |
| Replies from attacker-chosen names: the http-01 body (1 KiB), the dns-01 TXT strings, the TLS scan certificate | `internal/acme/validate.go`, `internal/tlsscan` | any ACME client names a host | `validate_test.go`, `validate_guard_test.go` | none |

- **Containment.** `recover()` exists in the admin web server (`internal/web/server.go:177`), as an interceptor of the
  agent RPC (`internal/agents/recover.go`) and in `internal/agent/dns_wrap.go`. The ACME and publish handlers
  (`publicHandler`, `internal/server/server.go:799`) have none and rely on `net/http` (a panic ends the connection,
  the process lives). The ACME **validator runs in goroutines without `recover`**
  (`internal/acme/validate.go:101`): a panic while it processes a host's reply would end the whole server, which is a
  CA. That is why a crash found by fuzzing is not a cosmetic bug (§18.7) and why step 90 exists.
- **Dead code and duplicates are mostly clean.** `golangci-lint run` reports 0 issues (so `unused` finds nothing,
  tests included). `deadcode` from `golang.org/x/tools` (already in `go.mod` as an indirect module, v0.52.0; it builds with
  `go build golang.org/x/tools/cmd/deadcode` and **changes neither `go.mod` nor `go.sum`**) reports **38 functions
  unreachable from the three binaries**, of which **34 are reached by tests** (server accessors `AgentAddr`, `Endpoints`,
  `Sealed`; `clock.Fake`; `auth.Service.Login`, `StepUp`; `audit.Verify`; `tenant.Store.Set`; the `testinstance`
  helpers) and **4 are unreachable even with every test as a root**: `ca.LegacyCRLURL`, `ca.LegacyCertURL`
  (`internal/ca/crl.go:292`), `server.Server.ACME` (`server.go:606`) and `dnsserver.Server.Host`. `dupl` finds **0** at
  its default threshold 150, **3 pairs at 100** (`cmd/myownpki/ca.go:22` against `db.go:28`, `internal/settingsver/backends.go:25`
  against `:77`, one pair of page tests) and 16 pairs at 70. `deadcode` sees only functions: unused constants, types and
  variables of exported API are not covered by any installed tool.
- **Error messages.** `go-conventions.md` asks for wrapping with context and `%w`, domain errors in the owning
  package, no secrets or CSRs in strings. Measured over 316 non-test files: 811 `fmt.Errorf` (541 with `%w`), 262
  `errors.New`; **`revive`'s `error-strings` rule reports 0 findings** (lower case, no trailing punctuation). The
  deviations: **21 `fmt.Errorf` without a verb** (`internal/agents/names.go:35` and the like; `errors.New` is the form),
  **8 messages that start with a capital that is not an acronym** (`internal/ca/names.go:143`, `:147`, `:155`,
  `internal/agent/acme.go:335`, `internal/tools/screenshots/seed.go:103`, two test helpers), 1 `%v` where a `%w` belongs
  (`internal/tools/screenshots/instance.go:240`), and `deny("...")` (95 calls), `problemErr(...)` (70) and
  `badRequest(...)` (88) texts that **reach the client** and use one house style (a sentence, lower case, " – " for the
  second clause, 143 messages). The structural gap is in the other direction: about 1,550 `return err` or
  `return x, err` lines that pass an error up unwrapped (`wrapcheck` would report 1,225). `slog` calls use constant
  messages already (`sloglint` is on). 9 `Errorf` calls print a `%s` of a path, a body or a PEM name; none prints a CSR
  or a key (checked by reading the lines, not by a tool).
- **Coverage.** Standard toolchain: `go test -coverprofile`, `go tool cover -func`. Measured with
  `go test -count=1 -coverprofile=cover.out` over 74 packages (all but `internal/publish`); the whole run takes about
  10 minutes here (`internal/agent` 536 s with a second run competing, `ca` 184 s, `server` 203 s, `web` 193 s). Without
  generated code (templ, sqlc, protobuf), test helpers and `internal/tools`: **29,909 statements, 79.0 %** covered by
  each package's **own** tests. That number understates the integration tests, so a second run used
  `-coverpkg=./cmd/...,./internal/...` over the packages that matter (the merged blocks are counted once):

  | Package | own | combined | | Package | own | combined |
  |---|---|---|---|---|---|---|
  | `internal/ca` | 71.9 | 83.6 | | `internal/httpapi` | 86.0 | 86.0 |
  | `internal/acme` | 73.2 | 77.8 | | `internal/server` | 82.5 | 84.7 |
  | `internal/acme/jose` | 84.6 | 85.3 | | `internal/keys` | 86.6 | 88.0 |
  | `internal/agents` | 72.6 | 81.9 | | `internal/store` | 70.3 | 79.2 |
  | `internal/auth` | 68.5 | 82.3 | | `internal/ca/legacy` | 74.5 | 74.9 |
  | `internal/authz` | 78.2 | 92.7 | | `internal/web` | 80.7 | 80.8 |
  | `internal/agent` (own only) | 79.3 | n/a | | `cmd/myownpki` | 76.7 | 76.7 |

  The numbers are a **lower bound for Linux**: the tests that build a real `legacy/pki.sh` fixture skip on this machine
  (`legacytest.NeedPkiSh`: bash and POSIX paths, or `LEGACY_TEST_OPENSSL=/usr/bin/openssl`), which is why the whole legacy
  import (`importlegacy.go`, `importjob.go`, `readCA`) shows 0 to 40 %. Without those, the **largest uncovered blocks in
  security-relevant code** (combined run, uncovered of all statements of the function) are: ACME account update and
  deactivation `account` 25 of 45, `keyChange` 23 of 54, `newAccount` 18 of 68, `accountOrders` 15 of 15 (never
  called), `newOrder` 15 of 56, `challenge` 13 of 38, `finalize` 13 of 45, `joseFail` (the mapping of JWS errors to
  `badSignatureAlgorithm`, `badPublicKey`) 40 % covered, `certIdentifiers` (who may revoke which names) 54 %; in the CA
  `uploadCRL` 21 of 88, `signAndStore` 17 of 84, `revokeCA` 15 of 56, `installCACertificate` 14 of 60, `Export` 13 of 64,
  name constraints `ncOutsideParent` 18 % and `ncEmail` 0 %; in auth `CreateToken` (API tokens) 18 of 61, the passkey
  finish steps 18 of 68 and 15 of 50, `ConfirmTOTP` 0 of 13, `CreateUser` 11 of 55; in agents `applyDeployed` 24 of 79,
  `Enroll` 13 of 66, `admitBy` 12 of 36; in the server `peerIP` (the admin allow-list reads the peer address here)
  43 %, `build` 17 of 85; in backup `check` 12 of 66 and `create` 12 of 51. `authz` is at 92.7 %. Packages without any
  own test: `store/pkidb`, `systemdb`, `auditdb` (generated), `web/pages/*` (generated), `tools/*`, `testinstance`.
- **Lint today** (`.golangci.yml`, `default: standard` plus 30 linters, `gosec`, `errorlint`, `exhaustive`, `gocritic`
  default checks, `govet` with every analyzer but `fieldalignment`): **0 issues**. What more linters would find if
  switched on one at a time (counts of findings, tests included, non-test files in brackets; measured with
  `golangci-lint run --default none --enable ...`, nothing committed):
  low noise: `contextcheck` 15 (13), `errchkjson` 33 (17), `unparam` 19 (6), `perfsprint` 13 (10), `intrange` 9 (3),
  `wastedassign` 3 (3), `canonicalheader` 4 (2), `recvcheck` 3 (3), `containedctx` 3 (3), `dogsled` 6 (0), `mirror` 2 (1),
  `dupword` 6 (1), `fatcontext` 1 (0), `nilnil` 8 (7), `protogetter` 34 (22); `revive` with its default rules 99
  (79), of which 10 are real (`max` and `real` redefine a built-in: `internal/acme/util.go:111`, `agents.go:257`);
  `modernize` 173 (69), all mechanical (`new(x)` for `ptr(x)`, `maps.Copy`, `SplitSeq`, `wg.Go`);
  `gocritic` with every tag 797, of which the useful checks are `sloppyReassign` 43, `stringXbytes` 12, `builtinShadow`
  11, `regexpSimplify` 8, `emptyStringTest` 8, `httpNoBody` 7, `evalOrder` 6 (`hugeParam` 395 and `rangeValCopy` 213 are
  performance noise); `staticcheck` with `checks: ["all"]` 34, all comment forms (`ST1022`, `ST1000`); `exhaustive`
  without the `default:` shortcut 7; `errcheck` with `check-blank` 766 (195 outside tests: `_ = f.Close()` everywhere).
  Noise, not adopted: `lll` 4,131, `goconst` 1,904, `wrapcheck` 1,225, `cyclop` 690, `err113` 526, `gochecknoglobals`
  250, `testpackage` 197, `paralleltest` 125, `gocognit` 125, `prealloc` 74, `nonamedreturns` 37, `nestif` 21,
  `funlen` 15, `gocyclo` 12, `godox` 4. Left at zero: `copyloopvar`, `predeclared`, `whitespace`, `nakedret`,
  `unqueryvet`, `exptostd`, `iface`, `asasalint`, `gocheckcompilerdirectives`, `maintidx`.
- **Housekeeping found on the way.** `SECURITY.md` still says "There is no release yet", although v0.3.10 is out (step
  100 fixes the text). The `graphify` graph does not exist in this worktree, so all facts come from reading the code
  and running the tools, not from a graph query.

### 18.1 Work plan

Every step is one commit (or the series named in it), builds and passes `task check`. Steps 78 and 79 come first; the
rest is grouped in §18.4.

| # | In | Step | Verifies with |
|---|---|---|---|
| 78 | 0.3.12 | **Measure first: `task cover`.** `Taskfile.yml`: `cover` runs `go test -count=1 -coverpkg=./cmd/...,./internal/... -coverprofile=coverage.out $COVER_PKGS` (the list defaults to all packages; a machine that cannot run one leaves it out, as here with `internal/publish`) and then `scripts/ci/cover-summary.sh`, an awk script that merges duplicate blocks (the merged profile of several test binaries lists a block once per binary), leaves out generated code (`*_templ.go`, `internal/gen`, `internal/store/{pkidb,systemdb,auditdb}`, `internal/tools`) and test helpers, and prints one line per package (statements, covered, percent) and the total; `task cover:func` prints the uncovered statements per function (the ranking used in §18 Facts); `task cover:html` opens `go tool cover -html`. `coverage.out` is already ignored. The script also counts skipped tests from `go test -json` and prints "N tests skipped" so a Windows number is never read as a Linux one. The baseline table of the Facts goes into this section as *Built*. **No threshold and no CI gate** (decision 6) | `task cover`; the script on a saved profile of this section's run gives the numbers above (a golden test with a small profile in `scripts/ci/testdata/`); `task check` |
| 79 | 0.3.12 | **One list of fuzz targets, one script, two CI jobs.** `scripts/ci/fuzz-targets.txt` (one line per target: `package target [extra go test flags]`, for example `-parallel 2`), `scripts/ci/fuzz.sh` (for each line: `go test <pkg> -run '^$' -fuzz '^<target>$' -fuzztime $FUZZTIME`; stops at the first failure, then prints every new file under `testdata/fuzz` between lines, so a crash in CI is readable without downloading anything); `task fuzz` calls it (`FUZZTIME` default 10s, `FUZZ_ONLY=<target>` for one); a test in `scripts/ci` (the `lint-meta-registry.sh --self-test` pattern) fails when a `func Fuzz` in any `_test.go` is missing from the list or the list names a target that does not exist; the `scripts/ci/local.sh` registry line moves from job `check` to a new job `fuzz` (same command, `task fuzz`). `.github/workflows/ci.yml`: the fuzz step leaves job `check`; new job `fuzz` (`needs: changes`, same `if` as `check`, `timeout-minutes: 20`, runs in parallel to `check`) with `FUZZTIME=10s`; new job `fuzz-long` (runs only for the events `schedule` and `workflow_dispatch`, so without `needs: changes`, which is skipped on schedule; `timeout-minutes: 75`, `FUZZTIME` from the dispatch input, default `2m`) so the daily 04:17 run does more than the vulnerability scan. `FuzzParse` is the first list entry | `bash scripts/ci/fuzz.sh` locally with `FUZZTIME=2s`; the self-test with a target removed and one invented; `task ci:local -- --only fuzz`; `task lint:ci` (actionlint); a pull request run shows the new job |
| 80 | 0.3.12 | **JOSE targets.** In `internal/acme/jose`: `FuzzParse` gets seeds for RS256, ES384, EdDSA, the `kid` form, a key change body and the three failure shapes (duplicate members, `crit`, `b64`); new `FuzzParseInner`, `FuzzParseJWK` (accepted key: allowed type and curve, RSA at least 2048 bits, `Canonical()` parses again to the same thumbprint) and `FuzzVerifyEAB` (accepted: the returned key ID is the header's, the MAC is HS256 only). Invariants and the shared rules in §18.2 | `go test ./internal/acme/jose` (seeds as unit tests); `task fuzz FUZZ_ONLY=FuzzParseJWK` |
| 81 | 0.3.12 | **ACME pure-function targets.** New `internal/acme/fuzz_test.go`: `FuzzNormalizeIdentifier`, `FuzzParseARIID` (round trip against `ariID`), `FuzzCheckCSR` (a fixed order and account key; accepted: the signature verifies, DNS names and IPs equal the order's exactly, no e-mail or URI, key is not the account key). They call `normalize`, `parseARIID` and `(*Server).checkCSR` unchanged | `go test ./internal/acme -run 'Fuzz' -count=1` (seeds only); a mutation check: weaken one rule in `checkCSR` by hand, the target fails inside 10 s, revert |
| 82 | 0.3.12 | **CA targets.** New `internal/ca/fuzz_test.go`: `FuzzParseCSR` (and `InspectCSR` on the same bytes: never panics, every list in the result is bounded by `maxSANs`/`short`), `FuzzParseCertificate` (`parseOneCertificate`: one PEM block of type `CERTIFICATE`, no headers, nothing after it, at most 64 KiB; an accepted certificate re-encodes to the same DER; `certNames` of it has no duplicate row), `FuzzNames` (DNS, e-mail, URI, IP, name-constraint values in one target with a mode byte: idempotent canonical form, lower case, at most 253 characters, no trailing dot, a wildcard only as the whole left label with two labels behind it), `FuzzCRLDER` (`crlDER` then `x509.ParseRevocationList`). Seeds: certificates and CSRs generated in the test (conventions), plus a CSR with a SAN extension that claims `CA:TRUE`, a 64 KiB + 1 input, PEM with headers, two blocks, `NEW CERTIFICATE REQUEST` | `go test ./internal/ca -run 'Fuzz' -count=1`; `task fuzz FUZZ_ONLY=FuzzParseCSR` |
| 83 | 0.3.12 | **Legacy import targets.** New `internal/ca/legacy/fuzz_test.go`: `FuzzFromArchive` (seeds built with `archive/tar` and `compress/gzip`: a normal tree, `..`, absolute, backslash, NUL, duplicate names, a symlink, a header that claims 1 TiB with a tiny body, 100,001 entries, a gzip of zeros; invariants: no panic, an accepted FS holds only `fs.ValidPath` names and at most the limits, `fs.WalkDir` ends), `FuzzParseKV`, `FuzzParseIndex` (an entry has a canonical hex serial, status V, E or R, increasing line numbers; a line over 64 KiB is a note, not a panic), `FuzzParsePrivateKey` (a passphrase is given; the target skips an input whose PBKDF2 count is above 100,000 so one slow input does not stall the run, and counts how often it skipped; decision 9) | `go test ./internal/ca/legacy`; `task fuzz FUZZ_ONLY=FuzzFromArchive` (watch memory: the target runs with `-parallel 2` in `fuzz-targets.txt`) |
| 84 | 0.3.12 | **Agent protocol targets.** New `internal/agents/fuzz_test.go`: `FuzzCSRKey` (accepted: at most 8 KiB, valid signature, ECDSA, Ed25519 or RSA, the result is a 43-character base64url SHA-256), `FuzzValidReport` (a `ReportInput` decoded from the fuzz bytes with `encoding/json`; accepted: every bound of `validReport` re-checked by an independent function in the test), `FuzzHostnamePattern` (`CheckHostname`, `CheckPattern`, `Matches`: an accepted pattern matches only names that are accepted host names; `*` never spans a label; accepting is idempotent) | `go test ./internal/agents -run Fuzz`; `task fuzz FUZZ_ONLY=FuzzValidReport` |
| 85 | 0.3.12 | **REST body target.** New `internal/httpapi/fuzz_test.go`: `FuzzDecodeBody` runs `call.decode` over three target types (the issue request, a domain request, one with a nested map): accepted means one object and nothing after it, and a second round trip (`json.Marshal` then `decode`) gives an equal value; a refusal is a `*bodyError` with status 400 or 413, its text is at most 300 bytes whatever the input, and `unknownFieldPath` returns a valid JSON Pointer (RFC 6901) that names a field the decoder refused | `go test ./internal/httpapi -run Fuzz`; `task fuzz FUZZ_ONLY=FuzzDecodeBody` |
| 86 | 0.3.12 | **Upload target in the wizard.** New `internal/web/fuzz_test.go`: `FuzzUploadedCSR` builds a multipart request around the fuzz bytes and calls `uploadedCSR`: no panic; a file over 64 KiB is refused; an accepted file is returned as PEM text of one `CERTIFICATE REQUEST` block that `x509.ParseCertificateRequest` accepts | `go test ./internal/web -run Fuzz` |
| 87 | 0.3.12 | **Trust page targets.** New `internal/trustkit/fuzz_test.go`: `FuzzDetect` (the result is one of the fixed platforms, the work is bounded by 512 bytes, no byte of the input appears in the result) and `FuzzGuide` (a root with a fuzzed name and URL: when `CertURL` accepts it, no line of any block contains a shell metacharacter outside the quoting the generator adds, checked by a small tokenizer in the test; when it refuses, no command is produced) | `go test ./internal/trustkit -run Fuzz` |
| 88 | 0.3.12 | **Spike: one ACME handler target.** Widen `newEnv`, `client`, `csrFor` and the `env` helpers of `internal/acme/client_test.go` from `*testing.T` to `testing.TB` (the fuzz function has a `*testing.F`), then `FuzzACMEPayload(endpoint byte, payload []byte)`: a valid account, a valid nonce and a correctly signed JWS around the fuzzed payload for `new-account`, `new-order`, `finalize`, `revoke-cert`, `key-change` and `account`; invariants: no panic, no status 5xx, the answer is `application/problem+json` for every 4xx, and no row of another account changes. **Kept only if it runs at 200 executions a second or more** (one server per worker process, rate limits raised in the test, a cap on rows); otherwise it stays as a test that runs its seeds and is listed under "on demand" | `go test ./internal/acme -run FuzzACMEPayload`; the exec rate printed by `go test -fuzz` is written into this section |
| 89 | 0.3.12 | **Triage and fix: a reserved slot.** Every finding of steps 80 to 88 becomes one commit `fix(<area>): <what> (found by fuzzing)` holding the minimized input as `testdata/fuzz/<Target>/<hash>` (Go's own file, never edited), the fix, and a plain unit test of the invariant. The classes and who decides are in §18.7. A finding is never "fixed" by loosening the target | `go test` on the package replays the seed (it fails on the parent commit, passes on the fix); the 10 s run of the target |
| 90 | 0.3.12 | **Contain a panic in the ACME validator** (decision 10, only with the owner's OK): `validator.start` (`internal/acme/validate.go:101`) recovers, fails the challenge with `serverInternal`, writes an audit entry with the panic's type and no text, and logs the stack at error level; a test makes the validator panic through the network seam (`SetNetwork`) and checks the server lives, the challenge is `invalid` and the next challenge works | `go test ./internal/acme -run Validator`; `task check` |
| 91 | 0.3.12 | **Dead code.** `task deadcode` (new, not in `check`): `go run golang.org/x/tools/cmd/deadcode -test ./...`, no `go.mod` change (decision 7). Delete the four unreachable functions; for the 34 that only tests reach, decide per item: move to `_test.go` or `internal/testutil` when only tests use it, keep (with a comment naming the user) when a build-tagged test, the agent end-to-end or documentation uses it. Report with the commit what stayed and why. One commit per package | `task deadcode` prints only the reviewed list (kept in `scripts/ci/deadcode-known.txt`; the task fails on a new line); `task check` |
| 92 | 0.3.12 | **Duplicates.** Fix the two pairs outside tests (`cmd/myownpki/ca.go` and `db.go`, `internal/settingsver/backends.go`), then enable `dupl` with `threshold: 100` and `_test.go` excluded | `golangci-lint run` (0 issues); `task check` |
| 93 | 0.3.12 | **Lint round, a series.** Each commit enables one group and fixes its findings, so `task check` is green after every commit: (a) `contextcheck`, `errchkjson`, `wastedassign`, `containedctx`, `recvcheck` (each finding is read: a detached context for logging stays, with a `//nolint:contextcheck // reason`); (b) `unparam`, `intrange`, `perfsprint`, `mirror`, `canonicalheader`, `dupword`, `dogsled`, `fatcontext`; (c) `revive` with the rules `error-strings`, `error-naming`, `redefines-builtin-id`, `context-as-argument` and `package-comments` (rename the ten shadowed `max` and `real`; the two error rules measured 0); (d) `gocritic` with `enabled-checks` `sloppyReassign`, `stringXbytes`, `builtinShadow`, `regexpSimplify`, `emptyStringTest`, `httpNoBody`, `evalOrder`, `redundantSprint`; (e) `staticcheck` with `checks: ["all", "-ST1000", "-ST1003"]` only if the owner wants the comment forms (decision 8); (f) `exhaustive` without the `default:` shortcut, only where it measured 7 and the switches are real enums. `nilnil` and `protogetter` are **not** enabled unless the owner asks: they change shapes of return values or add noise in generated-style code. Every new linter has a one-line reason in `.golangci.yml`, as the existing ones. **Result (2026-11-16):** (a), (b) without `dupword`, (c), (d) with six of the eight checks and (f) are enabled, one commit each, `golangci-lint run` reports 0 issues on linux, darwin, freebsd and windows after every commit. Left out: `dupword` (12 of 13 findings are test data where the repeat is meant, and its automatic fix broke two tests), `sloppyReassign` (43 findings; its fix collides with `govet` shadow) and `redundantSprint` (three tests print a redacting type through `fmt` on purpose); `perfsprint` runs without its string-concatenation and loop rules, `unparam` without "always receives", `exhaustive` ignores the open sets of the standard library and the protobuf enums, `staticcheck` all-checks and `nilnil`/`protogetter` stay off as decided. The lint round found no defect in the product: `errchkjson` found seven tests whose "the text is not in the audit log" check ran on an empty text when `json.Marshal` failed (they fail now), and `contextcheck` found `myownpki config check` not stopping on Ctrl-C (it takes the context now) | `golangci-lint run` after each commit; `task check` |
| 94 | 0.3.12 | **Error messages.** Write the rule into `.claude/skills/myownpki/references/go-conventions.md` (lower case start unless an acronym, no trailing punctuation, `%w` when an error is returned, `errors.New` for a constant text, wrap once at the boundary that adds context, texts that reach a client are sentences with " – " and are changed only when wrong); fix the 21 verb-less `Errorf`, the 8 capitals and the one `%v` of the Facts (the `perfsprint` and `revive` groups of step 93 find most of them); review the 9 `%s` calls once more and record the result here. **Texts that reach a client (`deny`, `problemErr`, `badRequest`) are not reworded** (decision 11); a `wrapcheck` pass is not done. **Result (2026-11-16, measured again):** the 22 verb-less `Errorf` calls are `errors.New` with the same text since the `perfsprint` commit of step 93, and `perfsprint` now keeps it that way; the "8 capitals" are acronyms and proper names (URI, ARI, CRLs; in tests Ed25519, ECDSA, OpenSSL and the WebAuthn error names), which the rule allows, so no message was reworded; `staticcheck` (ST1005) and `revive` (`error-strings`) report 0 on the tree and fail on a real capital or a trailing dot (tried with a probe file); the `%v` that the Facts named prints a list of host names, not an error, and is right (the other `%v` calls in `Errorf` print a file mode, an OID or a recovered panic value); the `%s` and `%q` calls with a path, a response body or a PEM block name were read again: paths are the administrator's own, the `/healthz` body is read with a limit of 64 bytes, a PEM block name is clipped to 40 characters and quoted, and none prints a CSR, a key or a secret; no text of `deny`, `problemErr` or `badRequest` changed | `go test ./...` unchanged; `golangci-lint run`; a `git diff` that touches no `testdata` and no contract test |
| 95 | 0.3.12 | **Test gaps: ACME accounts and orders.** In `internal/acme` (after step 88, same files): account update and deactivation (`account`), `keyChange` refusals (new key already in use, wrong old key, bad inner JWS, account mismatch), `newAccount` (bad contact URL, `onlyReturnExisting`, EAB failures, terms), `accountOrders` (the list, paging, another account's orders), `challenge` and `finalize` error branches (wrong state, order expired, processing), `joseFail` for every error class, `certIdentifiers` (who may revoke which certificate: account that owns it, certificate key, a stranger), the nonce store (expiry, reuse, size cap). Table tests on the existing `env` | `go test ./internal/acme`; the combined coverage of `internal/acme` is written into this section |
| 96 | 0.3.12 | **Test gaps: CA.** In `internal/ca` (after step 82): `uploadCRL` (older number, wrong generation, thisUpdate in the future, an intermediate that the CRL lists, a delta CRL, DER and PEM, a CRL of another CA), name constraints (`ncOutsideParent`, `ncEmail`, IP and URI rows, an issuing CA wider than its parent), `revokeCA` and `installCACertificate` (the offline root path), `Export` (the step-up and key-never-written rules), `ImportExternal` (today only the contract test: a CA certificate is refused, a duplicate fingerprint, a certificate with thousands of SANs, a viewer is refused), `signAndStore` failure paths (a failing store after signing leaves no half certificate). Needs no `pki.sh` | `go test ./internal/ca`; combined coverage noted |
| 97 | 0.3.12 | **Test gaps: auth, server, backup.** `internal/auth`: `CreateToken` (scope, expiry, no token for a token), the passkey finish steps with the virtual authenticator (replayed challenge, wrong origin, counter that goes back, unknown credential), `ConfirmTOTP`; `internal/server`: `peerIP` and the allow-list listener (IPv4-mapped IPv6, a unix or odd `net.Addr`), `build` refusal paths; `internal/backup`: `check` and `create` failure paths (a full disk is simulated by a failing writer, a modified database is refused). Authorization is already at 92.7 % and gets only the three uncovered helpers | `go test ./internal/auth ./internal/server ./internal/backup` |
| 98 | 0.3.12 | **Test gaps: agents.** `internal/agents`: `applyDeployed` (the predecessor policy per state), `Enroll` and `admitBy` refusals (token used up, wrong pattern, name already enrolled, CSR key reuse), the report limits at the exact boundary (100 names, 253 characters, 64 hex digits), `deliverAgain`. The rpc layer is covered by the end-to-end tests; no new e2e | `go test ./internal/agents` |
| 99 | 0.3.12 | **One mechanical commit: `modernize`.** `golangci-lint run --fix --enable-only modernize` (173 findings, 69 outside tests), reviewed as a diff that must be reproducible by the same command, **only after PR #49 and every other open branch are merged** (it touches many files and would conflict with them). Skipped findings stay with a `nolint` and a reason | `golangci-lint run`; `task check`; `git diff --stat` shows only the files the tool changed; the command run again produces no diff |
| 100 | 0.3.12 | **Docs and release.** CONTRIBUTING (the tasks `cover`, `fuzz`, `deadcode`, what a seed is, how to run one target for an hour), `SECURITY.md` ("Supported versions" says there is no release: say that the latest release and `main` get fixes), `site/security.md` (what is fuzzed and what is not), `docs/RELEASING.md` (a fuzz run of one hour per target before a tag is an optional checkbox), `.claude/skills/myownpki/references/go-conventions.md` (the Testing section: fuzz and cover), PLAN §10.1 row ✅ after the tag and the "Before Beta" line, CHANGELOG `[0.3.12]` (undated; **Changed:** CI runs more fuzz targets; **Fixed:** one line per finding after the fix is released, in plain words; **Added:** `task cover`, `task fuzz`, `task deadcode`; no Upgrading section needed: no migration, no setting). Version bump as in step 65 (`DEFAULT_VERSION` in `deploy/install.sh` and `deploy/install-agent.sh`, `test/install/agent_functions_test.sh`, `api/openapi.yaml`, `deploy/docker-compose.yml`, README, `docs/OPERATIONS.md`, `docs/RELEASING.md`, the status line of `CLAUDE.md`); CHANGELOG dated by the maintainer | `scripts/ci/site-check.sh`; every documented command run once; `task ci:local` with every SKIP line reported; `docs/RELEASING.md` |

**Built: the fuzz list, steps 90 and 95 (differences from the plan).**

- *Fuzz list.* `scripts/ci/fuzz-targets.txt` lists 24 targets and `fuzz.sh --check` passes. `FuzzACMEPayload` is in
  (tier 2, step 88's gate is met: the spike measured about 300 executions a second with two workers, 200 was the
  bar) with `-parallel 2`, because each worker builds its own server and SQLite database. `internal/guides`
  `FuzzParse` (the guide engine of step 71) exists in the tree too and is listed; the table in 18.2 does not
  name it, so the CI count in 18.3 is 24 targets, not 22 (about 4 minutes of fuzzing at 10 s a target).
- *Step 90.* `validator.start` runs `validate` through `guarded`, which recovers: the challenge becomes `invalid`
  with `serverInternal`, the audit entry (`acme.challenge.validate`, result `failure`) carries `"panic": "<type>"`
  and never the panic's text, and the log has one error record with the stack. **The recover also had to go into
  `policyDial`:** `net/http` calls the dialer (and, through it, the `lookupIP` of `SetNetwork`) in a goroutine of
  its own, so a panic there is outside `guarded` and ended the process (checked by removing it). Tests
  (`validate_panic_test.go`): a string, an error and a struct as panic value and a nil dereference, at the
  lookup edge, the dial edge and the TXT lookup; the answer, the audit entry and the log never hold the text;
  the server answers the next order; and more panicking checks than `parallelChecks` in a row do not block the
  next one (the slot is released).
- *Step 95.* New files `account_test.go`, `account_orders_test.go`, `order_branches_test.go`,
  `server_branches_test.go`, `expire_test.go`: `newAccount` (two dozen contact, payload and EAB cases, an existing key,
  EAB failures, sealed), account update and clear, deactivation, 17 `keyChange` refusals, `accountOrders`,
  the `challenge`, `authz` and `finalize` states (wrong state, expired, processing, valid, CSR errors that end
  the order and request errors that do not), `joseFail` for every class, `fail`, the request rules of `read`,
  the nonce store, `certIdentifiers` and an account that revokes a certificate with several names, `ExpireStale`,
  the dns-01 failures. Coverage of `internal/acme` (`go test -coverprofile`, this machine, Windows):
  **76.7 % before step 95 (after step 90), 82.3 % after.** What stays low is the admin side
  (`Pending`, `Accounts`, `Names`, `Orders`: used by `internal/server`, which measures them) and the agent binding.
- *Found by a test:* `accountOrders` read the 1000 newest orders of **all** accounts and then kept the caller's; an
  account whose orders were older than the newest 1000 of the others got an incomplete or empty list. Fixed with
  a query by account (`ListACMEOrdersOfAccount`, index `acme_orders_account`) in its own commit. Severity low:
  a correct, authenticated, own-data read; clients (certbot, lego) do not depend on this list.
- *Notes for the maintainer, not changed:* a request that fails the contact check still counts against the
  10-accounts-per-address limit (the limit is checked first); the 409 of a `keyChange` to the account's own key says
  "belongs to another account already".

**Built: steps 99 and 100 (2026-11-16).**

- *Step 99.* `golangci-lint run --fix --enable-only modernize` ran after PR #49 and `main` were merged into the branch:
  126 Go files (60 outside tests), 365 lines added and 490 removed, in one commit. What it did: `errors.AsType` for a `var`
  and `errors.As` (24 places), `strings.SplitSeq` and `FieldsSeq`, `slices.Contains` and `slices.Backward`, `maps.Copy`,
  `CutPrefix`, `CutSuffix` and `CutLast`, `max()`, `reflect.Type.Fields`, `sync.WaitGroup.Go`, `new(value)` for the pointer
  helpers of tests (seven helpers that nothing calls any more are deleted), and promoted fields in the literals of embedded
  structs. **Reviewed, one rewrite refused:** `omitzero` for four `time.Time` fields of `agent.DeploymentResult` would drop
  the zero times from the JSON (`omitempty` never did anything for a struct); `omitempty` is removed instead and the output
  is the same as before. The tool skipped two files because two of its own edits collided (`deploy.go`,
  `trustkit/fuzz_test.go`); both were finished by hand, as were an unnamed loop variable, a shadowing one and a blank line it
  left behind. `modernize` is **not** a permanent linter: the plan asks for one commit, and a newer `golangci-lint` would
  add rules and findings. The same command now reports 0 issues on linux, darwin, freebsd and windows with and without the
  tags `conformance` and `e2etest`; the tests of every touched package pass (not `internal/publish`: Defender, see above).
- *Step 100.* Documentation (`CONTRIBUTING.md`, `SECURITY.md` "Supported versions", `site/security.md`,
  `site/contributing.md`, `docs/RELEASING.md` with the optional fuzz hour, `go-conventions.md` Testing), the CHANGELOG
  section `[0.3.12]` and the version 0.3.12 in the files that the bump of 0.3.11 changed. `CLAUDE.md` and `PLAN.md` follow
  after the tag. Coverage of this release (`task cover`, Windows, 23 tests skipped, `internal/publish` left out): **85.3 %
  of 31,181 statements**; combined numbers `acme` 87.1 %, `ca` 86.3 %, `agents` 84.2 %, `auth` 84.2 %, `server` 85.8 %,
  `jose` 88.7 %, `backup` 87.2 %, `httpapi` 86.2 %, `web` 81.3 %, `ca/legacy` 80.9 % (the baseline of the Facts: 79.0 %
  own-package, combined `acme` 77.8 %, `ca` 83.6 %, `agents` 81.9 %, `auth` 82.3 %, `server` 84.7 %).

### 18.2 Fuzz targets and invariants

Every target follows the same rules, so a reviewer can check them in one pass:

1. **No panic** on any input, and the production function is called **unchanged**: a target never copies logic, never
   sets a limit lower, never skips the size check. If a function needs a seam to be called (an unexported method on
   `Server`), the call is made from the same package's test.
2. **Bounded.** The production limit is the bound (64 KiB for a CSR, 8 KiB for an agent CSR, 4 MiB for a CRL, 128 KiB
   for a JSON body, 64 MiB for the archive); a target measures its own wall time per input and fails above 2 s (10 s for the legacy archive, whose seeds are hostile on purpose; ten times as much under `-race`, `internal/testutil/racemode`)
   (`time.Now` is allowed in tests), except the PBKDF2 case of decision 9. Memory is bounded by the same limits; the
   archive target runs with two workers.
3. **Accept means promise.** When the parser says yes, the target re-checks, with code that does not share the
   parser's helpers, what the function documents: a CSR was PEM of one block and signed by its own key; a name is
   lower case LDH; a JWS has an allowed algorithm, a nonce, a URL and exactly one of `jwk` and `kid`.
4. **Round trip where one exists:** `ParseJWK` then `Canonical` then `ParseJWK` (same thumbprint); `ariID` then
   `parseARIID`; JSON decode, encode, decode; `normalize` applied twice equals applied once.
5. **Errors are bounded text:** a refusal never echoes more than the `short()` or `clip()` limit of attacker text.
6. **No I/O:** no network, no temporary file, no database, no real clock; certificates and keys are generated in the
   test (conventions), one per process, not per input.
7. **Seeds in code (`f.Add`)** are readable and produced by the test; files under `testdata/fuzz/` are only what the
   fuzzer wrote after a crash (kept as regression inputs) or a binary seed that cannot be written as code, each with a
   comment line in its package's test saying what it is.

| Target | Package | Calls | Tier |
|---|---|---|---|
| `FuzzParse` (extended), `FuzzParseInner`, `FuzzParseJWK`, `FuzzVerifyEAB` | `internal/acme/jose` | the ACME envelope | 1 |
| `FuzzNormalizeIdentifier`, `FuzzParseARIID`, `FuzzCheckCSR` | `internal/acme` | payload helpers | 1 |
| `FuzzParseCSR`, `FuzzParseCertificate`, `FuzzNames`, `FuzzCRLDER` | `internal/ca` | CSR, uploaded certificate, names and name constraints, CRL upload bytes | 1 |
| `FuzzFromArchive`, `FuzzParseKV`, `FuzzParseIndex`, `FuzzParsePrivateKey` | `internal/ca/legacy` | the archive and the old files | 1 |
| `FuzzCSRKey`, `FuzzValidReport`, `FuzzHostnamePattern` | `internal/agents` | agent protocol input | 1 |
| `FuzzDecodeBody` | `internal/httpapi` | REST bodies | 1 |
| `FuzzUploadedCSR` | `internal/web` | the wizard's file | 1 |
| `FuzzDetect`, `FuzzGuide` | `internal/trustkit` | the public trust page | 1 |
| `FuzzACMEPayload` | `internal/acme` | handlers with a real database | 2, only if fast enough (step 88) |
| `FuzzConfigLoad`, `FuzzAgentConfig`, `FuzzDNSCredentials` | `internal/config`, `internal/agent` | files of the operator | 2, **not in this release** (open point 6) |

That is 22 targets of tier 1 in eight packages (`FuzzParse` included), and tier 2 is the handler-level one.

### 18.3 CI budget for fuzzing

| Where | When | Time per target | Total |
|---|---|---|---|
| Job `fuzz` (new, parallel to `check`) | every pull request and push that changes code | 10 s (`FUZZTIME=10s`) | 22 targets, about 3.7 minutes of fuzzing plus about 15 s of build per package (measured on `jose`: 14 s) = about 6 minutes; `timeout-minutes: 20`. `check` gets shorter by the 30 s it spends today |
| Job `fuzz-long` (new) | the daily 04:17 run and `workflow_dispatch` with an input `fuzztime` | 2 minutes by default | 22 targets, about 45 minutes plus builds; `timeout-minutes: 75`. A failure shows the crashing input in the log (step 79) |
| `task fuzz FUZZTIME=30m FUZZ_ONLY=<target>` | by hand before a release, or after a change to a parser | free | the maintainer's machine; `docs/RELEASING.md` names it as an optional checkbox |
| `go test ./...` and the race job | always | the seeds and every file in `testdata/fuzz` run as ordinary tests, a few milliseconds each | a crasher stays a regression test forever |

The fuzzer's own cache is not kept between runs (decision 5), so the nightly run starts from the seeds in the code and
the committed regression inputs; the price is finding new things a little slower, the gain is no new third-party action
(`actions/cache`) in a workflow that pins every action by SHA. The repository is public, so the minutes cost nothing.

### 18.4 What can run in parallel

Steps 78 and 79 go first and in this order (both edit `Taskfile.yml`). After 79 the groups below touch **different
files and packages**; inside a group the steps are in order. One fuzz-list line per target is added by its own step;
the one-line merge conflicts in `scripts/ci/fuzz-targets.txt` are resolved by whoever merges second.

- **Group A (`internal/acme`):** 81, then 88, then 95 (88 changes the helpers of `client_test.go` that 95 uses).
- **Group B (`internal/ca`):** 82, then 96.
- **Group C (`internal/agents`):** 84, then 98.
- **Independent, any time after 79:** 80 (`jose`), 83 (`ca/legacy`), 85 (`httpapi`), 86 (`web`), 87 (`trustkit`), 97
  (`auth`, `server`, `backup`).
- **Then, in order and alone:** 89 (findings; it can start as soon as the first target finds something), 90 (only
  with the OK), 91, 92, 93 (a series), 94, 99, 100. The lint and dead-code steps run **after** the test steps so the
  new tests are made lint-clean once; 99 runs last of all because it touches many files; 100 is last.

### 18.5 Decisions

The maintainer was not available; each row takes the cautious option. Review them together with §18.8.

| Topic | Decision | Why |
|---|---|---|
| **D1. What gets a fuzz target** | The parsers of §18.2 tier 1: everything that reads bytes from outside the trust boundary (public listener, agent listener before and after trust, signed-in users' uploads and bodies, the legacy archive). Files that only the machine's administrator writes (config, `agent.yaml`, DNS credentials, state) are tier 2 and not in this release | The security rules call CSRs, uploads, ACME payloads and agent reports attacker input; an operator who can write `agent.yaml` already owns the host. Fewer targets keep the CI budget and the triage load small |
| **D2. Function level, not handler level** | Targets call the pure parsing function (no database, no server); one handler-level target is a spike with a speed gate (step 88) | A target that needs SQLite runs hundreds of times slower and finds the same parser bugs less often. The parts that are only reachable through a handler are small (payload structs) and covered by the handler test table |
| **D3. Seeds in code, regression inputs in the tree** | `f.Add` seeds are written by the tests; `testdata/fuzz/` holds only what a crash produced (and a rare binary seed), committed with its fix, never alone | Conventions: test certificates are generated in the test. A crasher committed before its fix would publish an unfixed bug on a public repository |
| **D4. CI time** | 10 s a target on every code change in a parallel job, 2 minutes a target every night, 30 minutes by hand before a release | A PR gate must stay short; the long run finds the rare cases without blocking anyone. Both numbers are inputs of the script and cost one edit to change |
| **D5. No corpus cache, no artifact upload** | No `actions/cache` and no `actions/upload-artifact` for the fuzz cache; a failing input is printed into the log by the script | A new third-party action needs the owner's OK (and a SHA pin); the log is enough to reproduce, because the input is small |
| **D6. Coverage is a report, not a gate** | `task cover` prints the table; no minimum in CI and no badge. After the first Linux numbers exist, a floor per security package (for example 80 % for `acme`, `auth`, `authz`, `ca`, `agents`) can be proposed | A gate on an unknown Linux number would be a guess; a gate on the Windows number is wrong. Chasing a percent produces tests that assert nothing; the ranked gap list is more useful |
| **D7. Dead-code tool** | `task deadcode` runs `go run golang.org/x/tools/cmd/deadcode -test ./...` with the version already in `go.mod`; no `tool` directive, no change to `go.mod` or `go.sum`; a known-list file makes new findings fail the task, but the task is not part of `task check` | Proven here: it builds with the module cache and changes nothing. A `tool` line in `go.mod` would pin it but is a change to the module file, which needs the owner's OK (open point 3) |
| **D8. Stricter lint = what measured clean or nearly clean** | Groups (a) to (d) and (f) of step 93; `staticcheck` all-checks only on request; no `wrapcheck`, `err113`, `lll`, `goconst`, `cyclop`, `gocognit`, `gochecknoglobals`, `testpackage`, `paralleltest`, `nonamedreturns`, `errcheck check-blank` | Principle of `.golangci.yml`: "pure style linters are left out on purpose – they create noise, not safety". 5,000 findings of style would hide the 15 real ones |
| **D9. PBKDF2 in the legacy key reader** | The limit of 10,000,000 iterations stays; the fuzz target skips inputs above 100,000 and counts them. If the owner agrees, a later change lowers the limit (OpenSSL writes 2,048 to 600,000) | An admin-supplied, step-up-protected file; 10 M iterations take seconds, not a denial of service of the public listener. A lower limit could refuse a real archive; that is the owner's call |
| **D10. Panics in background goroutines** | Step 90 recovers in the ACME validator and counts the panic as a failed challenge plus an audit entry. Nothing else gets a blanket `recover` | A panic in a goroutine ends the process; a CA that dies on a hostile host reply is the worst class of finding. A `recover` hides bugs elsewhere, so it is added where attacker data is processed in a goroutine, not everywhere |
| **D11. Error messages** | Fix Go-internal errors and the rule text; **do not reword texts the client sees** | `deny`, `problemErr` and `badRequest` texts are part of the API as a client reads it, are asserted by contract tests, and are already in one house style; the structural gap (unwrapped `return err`) is not a bug |
| **D12. Dead code policy** | Delete what nothing reaches, even tests; move test-only helpers into test files; keep what a build-tagged test or a documented seam uses, with a comment that names the user | A deleted function can always come back from git; a production binary that carries test helpers is a small, real attack surface |
| **D13. Findings go through a public history only after the fix** | A crash found in a **released** version is a vulnerability if it is remotely reachable before authentication (public listener, agent enrollment); then the fix is prepared on a branch without the seed, and the owner decides about a private advisory (`SECURITY.md`) before anything is pushed. Everything else is fixed in the open | The repository is public; a seed file is a proof of concept. The same rule applies to the CHANGELOG line, which is written after the release |
| **D14. The number** | `v0.3.12`; if the order of releases changes, the section keeps its number 18 and steps 78 to 100 move to the new version | §10.1: "order before numbers" |

### 18.6 Dependencies

None. `testing` (`testing.F`), `go tool cover`, `golang.org/x/tools/cmd/deadcode` through the existing module requirement
(no new module and no change of `go.mod` or `go.sum`, proven by a build in this worktree), the installed `golangci-lint`
2.15.0. **Needs the owner's OK only** if the owner chooses an option that adds something: a `tool` directive for
`deadcode` (D7), `actions/cache` or `actions/upload-artifact` for the fuzz cache (D5), or OSS-Fuzz or ClusterFuzzLite
(not planned). `THIRD_PARTY.md` does not change.

### 18.7 Security review (an independent reviewer checks, with the diff only)

Fuzz findings are bugs in attacker-facing code. **Triage**, in this order, by the first row that applies:

| Class | Example | Handling |
|---|---|---|
| **P1** | an input that a parser **accepts** and must refuse (a CSR with a second block, a JWS with two key members, a name that skips the policy); a panic or unbounded memory or time reachable **before authentication** (ACME, trust page, agent `Enroll`) or inside a goroutine that ends the process | fix first, in the release; D13 decides if a private advisory comes first; the commit message says what, not how; the regression input is committed **with** the fix |
| **P2** | a panic after authentication that `net/http` or `recover` contains; an input that takes more than 1 s per KiB; an error text that echoes more attacker input than `short()` | fix in the release; the seed is committed with the fix |
| **P3** | a round-trip or idempotence failure without a security effect; a message in the wrong style | fix if small, otherwise a line in the backlog and the target's assertion relaxed **with a comment that names the open item** |

What the reviewer checks, in the diff:

- **Targets are test code and weaken nothing:** no production function is copied, no limit is lowered or skipped, no
  seed or file under `testdata/fuzz` contains a real key, token or customer name (all keys are generated in the test),
  a target does no I/O.
- **Fixes only narrow:** a fix never widens what a parser accepts; the status codes and problem types of the released API
  stay as they are unless the old behavior was the bug (then it is named in the CHANGELOG); the hostile-name,
  hostile-CSR and escaping tests of the existing suites run unchanged.
- **No secret reaches a log or an error:** a new error text includes no CSR, key, token or passphrase; the 9 `%s` spots
  of §18 Facts are read again.
- **Step 90** (if approved): the recover handler records the type of the panic and a stack in the log, never the
  request data; the challenge fails closed (`invalid`), never `valid`; no second goroutine is left running.
- **Mechanical commits** (`modernize`, `deadcode`): the reviewer re-runs the tool and gets the same diff; deleted
  functions are not referenced by `//go:build` files (`go vet -tags conformance,e2etest ./...` is run for the change) and not
  by the agent end-to-end tests.
- **The CI job is read-only:** the new jobs keep `permissions: contents: read`, use no secret, pin nothing new; a
  fuzz failure prints input but uploads nothing.
- **Seeds and the policy:** every refused input of the new unit tests of steps 95 to 98 asserts the *reason*, not only
  the status, and a viewer, an operator and another tenant's admin each get the answer the authorization table gives
  (403 or 404).

### 18.8 Risks and open points

| Risk | Handling |
|---|---|
| A target finds a P1 on the first run (several parsers have never been fuzzed) | The slot of step 89 exists; D13 is the process. Expect the first findings in `legacy` (archive, key files) and the name and constraint parsers, which are the most hand-written |
| A fuzz target is flaky or slow and the PR job becomes a nuisance | The 2 s ceiling per input, `-parallel` per target in the list, and the rule that a target that cannot be made deterministic moves to the nightly job only |
| A mass lint or `modernize` commit conflicts with other branches | Steps 91 to 94 and 99 run after the test steps and, for 99, after every other branch is merged; the rest of the release is new files |
| The tests that the fuzz plan adds raise the CI time of `go test ./...` | Seeds run in milliseconds; the new unit tests of steps 95 to 98 are table tests on existing helpers and add seconds, not minutes (the whole suite takes about 10 minutes on this machine, almost all in `agent`, `server`, `web`, `ca` and `acme`) |
| A fixed finding changes behavior a client relies on | Fixes only narrow acceptance, are covered by the existing contract and ACME conformance runs (`task acme:lego`, the conformance job), and are listed in the CHANGELOG |
| Windows numbers mislead (legacy tests skip) | `task cover` prints the skip count; the first authoritative table comes from Linux CI (D6) |
| Fuzzing consumes memory on the archive target | `-parallel 2`, the production 256 MiB cap per input, and the 20 minute job limit |

**Not in v0.3.12:** an OCSP responder and its fuzzing (there is none), a PKCS#12 reader (the server does not read them),
fuzzing of third-party libraries (`x509`, `protobuf`, `miekg/dns`, `lego`: their own projects fuzz them; our targets test
our wrapper and the rules around them), tier 2 targets (config, `agent.yaml`, DNS credentials, state, journal, name-constraint
input of the admin), a coverage gate, mutation testing, OSS-Fuzz or ClusterFuzzLite, a persistent fuzz corpus, fuzzing
on Windows or macOS in CI, `wrapcheck`, `err113`, `lll`, `goconst` or any other style linter, a rewording of the texts that
clients see, refactoring for its own sake, performance work (`hugeParam`), any ADR change, any API, migration or
configuration change, and any new dependency.

**Open points for the maintainer:**

1. **CI budget** (D4): 10 s a target on every code change, 2 minutes a target nightly. Say if the PR gate should be
   shorter (5 s) or the night longer (10 minutes, about three hours).
2. **Fuzz cache between nightly runs** (D5): needs `actions/cache`, a new pinned action. Default: no.
3. **`tool` directive for `deadcode`** (D7): a one-line change of `go.mod`. Default: no, `go run` with the version
   already required.
4. **Coverage floors** (D6): after the first Linux table, a minimum for the security packages? Default: report only.
5. **`modernize`** (step 99): 173 mechanical rewrites in one commit after the other branches are merged. Default: yes.
6. **Tier 2 targets** (config files and agent files): in this release or later? Default: later.
7. **Step 90** (a `recover` in the ACME validator): default yes, because the alternative is that a panic ends the CA.
8. **`staticcheck` with all checks** (the 34 comment-form findings) and **`exhaustive` without the `default:` shortcut**:
   default no for the first, yes for the second where the switch is a real enum.
9. **PBKDF2 limit** (D9): keep 10,000,000, or lower it to 1,000,000 once the fuzz target has shown how long an input
   takes. Default: keep.
10. **A finding in a released version** (D13): who decides between a quiet fix in the next release and a private
    advisory, and does `SECURITY.md` promise fixes for the last release only? Default: the owner decides; the text of
    step 100 says "the latest release and `main`".
11. **Handler-level ACME target** (step 88): kept only above 200 executions a second. Default: yes, as a gate.
12. **Not verified:** nothing of the plan is built. Measured here: the baseline lint run (0 issues), the extra linter
    counts, `deadcode` (38, 34 and 4), `dupl` at three thresholds, the own-package coverage of 74 packages and the
    combined coverage of 21 packages, one 15 s fuzz run of `FuzzParse`. **Not measured:** the numbers on Linux CI,
    the number of tests that skip on this machine (`task cover` will print it), the tests of `internal/publish` (Defender
    blocks the binary here; the package is left out of every number), the speed of the planned targets, whether every
    target runs with `CGO_ENABLED=0` on all five platforms (only `jose` was run), the exact number of `deadcode` hits
    that are test seams in the agent end-to-end build (it needs the `e2etest` tag), whether `revive` or `gocritic` flag
    the same line twice after step 93, and whether a persistent `recover` in `validator.start` changes the timing of
    the conformance run. The facts come from reading the code and running the tools named in each bullet; no
    `graphify` query was possible (no graph in this worktree).

**Owner decisions found while building v0.3.12** (none of this is changed in the release; each point needs the
maintainer's call):

1. **The backup manifest is unsigned.** Editing `pki.db` and rewriting the hashes in the manifest passes `Verify` and
   `Restore`.
2. **`ImportExternal` has no SAN cap.**
3. **The lists of `InspectCSR` are not capped at `maxSANs`.**
4. **A valid DER CSR whose subject text starts with `-----BEGIN` is treated as PEM.**
5. **`keys.ChooseRecoveryOutput`, `auth.Service.ConfirmTOTP` and `tenant.Store.Version` have callers only in tests**
   (step 91 moved them into test files). Check whether `init` should use them; if not, they stay test helpers.
6. **`auth.Draft.Confirmed` is unused.**
7. **`apache2ctl configtest` needs `/run/apache2` after a boot** (a limitation of the `apache2` recipe, described in the
   0.3.11 notes).
8. **Salt test cases for Apache and HAProxy and `site/demo.md` are not added.**
9. **The live tests of the v0.3.11 recipes, of the demo's agent act and of the flags of the certbot guide are the
   owner's** (the live test is pending).

## 19. Beta: v0.9.0

The roadmap row "Beta" (PLAN §10.1) is a phase, not a feature: **feature freeze, upgrade tests between versions, only fixes**.
Owner decisions of 2026-11-16 (not reopened here): (1) the beta consists of **ordinary releases v0.9.0, v0.9.1, …** from the
freeze on, with no pre-release tags; `install.sh`, `:latest` and the Salt formula behave as for every release; **v1.0.0 follows
when the beta has no open finding that the owner rates a blocker**; (2) before the freeze the **security-relevant open points
of §18.8 "Owner decisions found while building v0.3.12"** are fixed (points 1 to 4); the rest (points 5, 6 and 8: functions
that only tests call, `auth.Draft.Confirmed`, Salt test cases for Apache and HAProxy and `site/demo.md`, plus the demo's
version text) are small clean-ups inside the beta, none of them a blocker. Written on 2026-11-16 as a plan for review; the
steps continue after 100 and **nothing is built**. The release number can shift (§10.1: "order before numbers"); the section
keeps number 19. **No ADR (§2) is changed by any step.** Step 101 touches two owner-approved design records (PLAN §5 key list,
§14 backup row) and is therefore marked "needs owner decision": the main session asks before step 102 starts.

**Status (2026-11-16): v0.9.0 is released** (tag `v0.9.0`, commit `2b483f0`, marked `latest`). Steps 101 to 124 are done. Step 125
is partly done: the release is pinned in `scripts/upgrade/releases.txt` (with `--packages`). **Open (decision D14):** the
maintainer's live tests of v0.3.6 to v0.3.12 are not finished (Salt formula, dns-01 in the agent, charts and analysis, trust
portal, preview and settings history, Apache and HAProxy recipes, guides and demo); the "Known limitations" of the CHANGELOG
`[0.9.0]` name them, and the notes of each 0.9.x release say what is still open. The exit criteria of 19.9 are **pending**; v1.0.0
follows when they are met.

Goal, checked by CI and by the owner: (a) the four security points are fixed with tests; (b) the freeze rules are written where
contributors and sessions read them; (c) **an installation made by a released version keeps working after the update**, proved
by a test that runs the old release binaries, not only the current source built twice; (d) a stranger can install the beta,
knows what to test and how to report, and knows what never to post; (e) the clean-ups are done or listed.

### 19.1 Facts (what exists today)

Measured here: git tags and migration counts, release assets (`gh release view`, read only), the code lines named below.
Read, not run: everything else. Nothing was built or executed in this worktree.

- **The upgrade test of today is narrow.** `task upgrade:test` (`Taskfile.yml`, `UPGRADE_FROM: 0.1.0`, test
  `internal/acme/upgrade_test.go`) builds v0.1.0 with `go install …@v0.1.0`, makes an instance and a backup with it, restores
  that backup with the **current code in the test process**, migrates, unseals and issues **one** certificate by ACME. It runs
  in job `check`, needs the Go module proxy, runs on Windows too, and tests no server process, no in-place update, no agent, no
  rollback and no release binary. The CI job `install` has a step "second build for update"
  (`scripts/ci/install-second-build.sh`): the **same source** with another version string, so the update path, the automatic
  backup and the rollback of `install.sh` are tested, but with an unchanged schema and unchanged data.
- **Migrations:** `internal/store/migrate` keeps a checksum per applied migration in the database and refuses an applied file
  that changed (`ErrModified`) or a database from a newer binary (`ErrNewer`), at start and in `db status` (exit 1). Nothing in
  the **repository** pins the checksum of a released file: a changed `0007_….sql` is noticed only on a database that already
  applied the old text. Migration counts per release (pki.db/system.db, measured with `git ls-tree`): v0.1.0 7/8, v0.2.0 10/9,
  v0.2.2 10/10, v0.3.0 13/11, v0.3.1 17/13, v0.3.3 17/14, v0.3.4 18/14, v0.3.5 19/14, v0.3.8 20/14, v0.3.10 to v0.3.12 21/15;
  audit.db is 2 throughout.
- **Release assets exist for every stable tag** (measured): `myownpki_<v>_linux_amd64.tar.gz` 15 to 19 MB, `checksums.txt` and
  its cosign bundle; `install.sh` from v0.2.2, `install-agent.sh` and the agent archive from v0.3.0 (9 to 10 MB), the agent
  `.deb` and `.rpm` from v0.3.5. v0.1.0 has no `install.sh`. Two release candidates (v0.3.0-rc.1, -rc.2) exist and are not used.
- **Agent protocol:** `check-agent-protocol.sh` runs `buf breaking` (`WIRE_JSON`) against `origin/main` only. The documents promise
  one direction: "update the server before the agents; mixed operation is supported" (`docs/OPERATIONS.md` §9, about v0.3.0
  agents and a newer server). **New agent against old server is not promised** (it happens only after a server rollback).
- **Backup:** format `myownpki-backup/1`; the manifest holds SHA-256 and size per file, the migration version, the head of every
  audit chain and the checkpoint key fingerprint; `check` refuses added, missing or changed files, wrong chains and a wrong SAN
  index (`internal/backup/restore.go`). Files and manifest are written by the same hand, so **whoever can write the backup
  directory can change `system.db` or `pki.db`, recompute the hashes and rewrite the manifest, and `Verify` and `Restore` pass**
  (read, not tried). The audit chains are protected when `--checkpoint-key` is passed (the signing key comes from the root key);
  private keys stay wrapped under the root key. Open: users, role bindings, domain rules, policies and revocation rows. The
  default `auth.key` lies in the data directory and **is part of the backup** (`backup.go` `create`), so a forged user row could
  carry a TOTP secret the forger chose. The daily timer runs `myownpki backup scheduled` as its **own process with no
  passphrase** (the server never reads it from a file, PLAN §5): a key derived from the root key does not exist there.
- **The caps:** `maxSANs = 100`, `short()` = 80 characters, `MaxCSRSize` and `MaxCertSize` = 64 KiB (`internal/ca`). The issuance
  path checks the count (`names.go:250`); `importExternal` (`renewcert.go:239`) does not (a 64 KiB certificate holds about 3,000
  names; `certNames` de-duplicates with `slices.Contains`, quadratic) and `TestImportExternalWithThousandsOfSANs` asserts that
  3,000 names are **recorded on purpose**. `InspectCSR` (`renewcert.go:179`) copies every name unclipped (about 6,000 in 64 KiB;
  the fuzz bound is `items > len(data)/2+8`, so the missing cap does not fail it). `uploadedCSR` (`internal/web/app_issue.go:238`)
  takes a file for PEM when `-----BEGIN` is **anywhere** in it; the seed `makeDER("-----BEGIN not a pem")` of `FuzzUploadedCSR`
  exists, and the target's oracle repeats the same test, so it cannot fail.
- **The three test-only functions** (read): `keys.ChooseRecoveryOutput` is a test helper that restates a rule `init` enforces by
  mode (`setup.go:263`: `--stdin` needs `--recovery-key-file`; interactive needs a terminal, `cmd/myownpki/init.go:62`; demo
  writes a file); the type `RecoveryOutput`, `ShowOnTerminal`, `WriteToFile` and `ErrRecoveryKeyNeedsFile` (`keys/recovery.go:178`)
  are used by nothing else, which `deadcode` does not report (no types or constants). `auth.Service.ConfirmTOTP` is test code
  (`totp_confirm_test.go:207`): interactive `init` confirms through `Draft.Confirm`, `--stdin` and `--demo` through the first
  login (`users.go` `confirmedStep`). `tenant.Store.Version` (`versions_test.go:335`) is covered in production by `Settings.Version`
  (`settings.go:117`). **Answer: `init` needs none of them; they stay test helpers**, and `Draft.Confirmed` (unused) goes.
- **Stale text:** `deploy/demo` names `ghcr.io/der-felix/myownpki:0.3.11` in four files (the release is 0.3.12); the compare links
  at the bottom of `CHANGELOG.md` stop at v0.3.10 (`[Unreleased]` compares `v0.3.10...HEAD`; `[0.3.11]` and `[0.3.12]` are missing);
  `.github/ISSUE_TEMPLATE/` does not exist.

### 19.2 Work plan

Sizes are estimates by reading, not measured: S under half a day, M about one day, L two to three days. Every step is one
commit (or the series named), builds and passes `task check`; `task ci:local` is run and every SKIP line is reported. Details of
steps 101 to 105 are in 19.3, of 106 in 19.4, of 107 to 115 in 19.5, of 116 to 118 and 124 in 19.6, of 119 to 123 in 19.1
("Stale text", "The three test-only functions").

| # | Size | Step | Verifies with |
|---|---|---|---|
| 101 | S | **Backup authenticity: decision record (needs owner decision D1; nothing is built before the answer).** PLAN §14 backup row and §5 key list say what the signature promises and what it does not; `references/security.md` lists the new key | owner reads 19.3; no code |
| 102 | L | **Backup signature (option b, only after D1).** New `internal/backup/sign.go`, changes in `backup.go`, `restore.go`, `prune.go`, `cmd/myownpki/backup.go`, `internal/setup` (init prints the fingerprint); format `myownpki-backup/2`; tests in `backup_failure_test.go` (tamper, re-sign with a foreign key, downgrade, format 1, lost key, key not in the backup), a seed set for a new `FuzzManifest` (line in `fuzz-targets.txt`); docs `site/guides/backup-and-restore.md`, OPERATIONS | `go test ./internal/backup ./cmd/myownpki`; the by-hand tamper in 19.3; `task fuzz FUZZ_ONLY=FuzzManifest` |
| 103 | S | **`ImportExternal` cap.** `checkExternalNames` in `internal/ca/renewcert.go`; `TestImportExternalWithThousandsOfSANs` becomes a refusal test; seed of 101 names in `FuzzParseCertificate` | `go test ./internal/ca -run 'ImportExternal\|Fuzz'` |
| 104 | S | **`InspectCSR` cap** and clipping in the same file (same file as 103: after it); the wizard's `prefill` uses the helper; `FuzzParseCSR` bound tightened | `go test ./internal/ca ./internal/web ./internal/httpapi` |
| 105 | S | **Upload: DER decided by parsing.** `uploadedCSR` in `internal/web/app_issue.go`; the oracle of `FuzzUploadedCSR` changes | `go test ./internal/web -run 'Upload\|Fuzz'` |
| 106 | S | **Freeze rules** (19.4): `CONTRIBUTING.md`, `site/contributing.md`, `CLAUDE.md` rule (status line follows with 124), `.github/pull_request_template.md` | `scripts/ci/site-check.sh`; read |
| 107 | M | **Released migrations are frozen.** `internal/store/testdata/released-migrations.txt` (kind, version, name, SHA-256, first release), test `TestReleasedMigrationsAreFrozen` over `store.Migrations(kind)` (same checksum as the runner, CRLF-normalized), `scripts/ci/pin-migrations.sh` (`--from-tag vX` recomputes from git; `--check` needs tags) | the test fails when a pinned file changes or disappears, passes for a new unpinned file; run the script against v0.3.12 and diff |
| 108 | M | **Release asset list and fetch.** `scripts/upgrade/releases.txt` (version, asset, SHA-256), `fetch.sh`, `pin-release.sh`, `--self-test` with a local file server | self-test; `task upgrade:fetch` twice (second run offline) |
| 109 | L | **Harness core for one start version** (the previous release): `test/upgrade/run.sh`, `lib.sh` (TOTP from the demo secrets file, REST helper, ports), config template, populate steps, update in place, assertions A1 to A4, A8, A10 of 19.5 | `task upgrade UPGRADE_ONLY=0.3.12` |
| 110 | M | **ACME and rules in the harness:** lego (pinned `LEGO_VERSION`, the conformance job's way) before and after; domain rule and settings versions (A5, A6); rollback by restore with the old binary (A9) | the same task for 0.3.12 |
| 111 | M | **Agent in the harness (A7):** old agent archive enrolls, heartbeats, reports; stays running over the update. Renew-now by the old agent is a spike inside this step; if it needs port 80 and root it moves to 113 | harness log shows `last_seen` advancing after the update |
| 112 | M | **The matrix:** capability profile per version (`test/upgrade/profiles.sh`: ACME from 0.2.0, agent from 0.3.0, enrollment pass from 0.3.5, settings versions from 0.3.10), the version list of 19.5, stored-data edge cases | `task upgrade` (all); `UPGRADE_ONLY=0.1.0` |
| 113 | L | **systemd level:** `test/install/upgrade_systemd_test.sh`: `install.sh` of release V from the cache installs, this tree's `install.sh` updates (V = 0.2.2 and the previous release); automatic backup by the old binary, rollback text, timer, drop-ins | CI job `install` on the disposable runner; locally only with `MYOWNPKI_CI_DISPOSABLE=1` |
| 114 | M | **CI wiring** (touches `ci.yml`, `local.sh`, `changes.sh`, `Taskfile.yml`, CONTRIBUTING): job `upgrade` (matrix) and `upgrade-nightly`, output `upgrade` of `changes.sh`, registry lines with SKIP reasons, `task upgrade`, `task upgrade:fetch`, `lint-meta` registry self-test | `task lint:ci`; `task ci:local -- --only upgrade`; a PR run |
| 115 | S | **Protocol guard:** `check-agent-protocol.sh` also runs `buf breaking` against the tag `v0.3.0` (nightly) and the last release (every run); OPERATIONS §9 states both directions | script run; read |
| 116 | M | **Issue templates:** `.github/ISSUE_TEMPLATE/bug.yml`, `feedback.yml`, `config.yml` (blank issues off; contact link to the private advisory); labels as commands in RELEASING (the owner runs them) | `task lint:ci` does not cover issue forms: the owner opens "New issue" after the push and checks all three |
| 117 | M | **Beta page and banner:** `site/beta.md`, `_data/nav.yml`, README banner, `SECURITY.md` supported versions ("the latest 0.9.x"), `site/upgrade.md` notes | `scripts/ci/site-check.sh`; every command on the page run once |
| 118 | S | **Known limitations of the beta** collected from CHANGELOG 0.3.12 and §18.8 into the page and the `[0.9.0]` notes | read |
| 119 | S | **Demo image tag:** a test in `deploy/demo/demo_test.go` that the tag equals `DEFAULT_VERSION` of `install.sh`; the four files get the version; the bump list names them | `go test ./deploy/demo` |
| 120 | S | **CHANGELOG compare links:** `[Unreleased]`, `[0.3.11]`, `[0.3.12]`, later `[0.9.0]`; a check in `site-check.sh` or the release awk that every `## [x]` has a link | `scripts/ci/site-check.sh` |
| 121 | S | **Dead code:** delete `auth.Draft.Confirmed`; move `RecoveryOutput`, its constants and `ErrRecoveryKeyNeedsFile` into `keys_test.go` next to `ChooseRecoveryOutput` | `task deadcode`; `task check` |
| 122 | S | **Salt test cases** for `apache2` and `haproxy` in `deploy/salt/test/cases/` (pillar, hashes of the fixtures) | `sudo bash scripts/ci/salt-test.sh` (CI job `salt`); `--self-test` locally |
| 123 | S | **`site/demo.md`:** what the demo is and how to run it (`deploy/demo/README.md` is the source), nav entry | `scripts/ci/site-check.sh` |
| 124 | M | **Release 0.9.0:** version bump in the files of the commit `chore(release): bump the version to 0.3.12` (README, `api/openapi.yaml`, `deploy/docker-compose.yml`, `deploy/install.sh` and `install-agent.sh`, `deploy/salt/myownpki/{README.md,map.jinja,pillar.example}`, `docs/OPERATIONS.md`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`) plus the demo files (step 119); CHANGELOG `[0.9.0]` (19.6); RELEASING additions (19.6); `CLAUDE.md` status line and PLAN §10.1 after the tag | `task ci:local`; `bash scripts/ci/site-check.sh`; the RELEASING checklist |
| 125 | – | **After the tag (owner):** pin the release (`pin-release.sh v0.9.0`, a commit on `release/v0.9.1`), live tests of §19.9, announce the beta | the list gets its first 0.9 line |

### 19.3 Security items before the freeze (steps 101 to 105)

**Backup authenticity (101, 102).** Threat: someone who can write the backup directory (an offsite share, a USB disk, a bucket) but
holds neither the host nor the passphrase. Options:

| Option | Does | Against it |
|---|---|---|
| (a) MAC (HMAC-SHA-256) with a key derived from the root key | no new secret to keep | the daily timer has no passphrase, so it cannot MAC; a sealed server could not back up; `backup verify` of an old backup would need the passphrase of its time. **Rejected for the timer** |
| **(b) Ed25519 signature by a dedicated backup key (recommended)** | a key file `<data_dir>/backup-signing.key` (0600, `O_EXCL`), made by `init` or by the first `backup`; **never copied into a backup**; `manifest.sig` holds the algorithm, the public key and the signature over the exact bytes of `manifest.json`; the fingerprint is pinned like the checkpoint key | one more fingerprint to note; whoever holds the backup **and** the key can re-sign; a lost key file means new backups get a new key |
| (c) document only | "the backup directory is as sensitive as the CA"; `verify` is integrity, not authenticity | the PLAN §14 sentence "a manipulated backup never becomes the PKI" stays false |

Design of (b): the format becomes `myownpki-backup/2` (an old binary refuses it with its existing "format … is not …" text, no
migration, no config key, no schema change). `check` accepts `manifest.sig` next to `manifest.json` (as for `prune.go`'s list of
expected files) and verifies it **before** it trusts any field. Verify and restore take `--backup-key FP` (at least 16 hex digits, as
`--checkpoint-key`); without it the local key file's fingerprint is used when the file exists (`backup scheduled` always does), else
the output says `note: signed by key SHA256:… – compare it with the one noted at init`. A valid signature by another key without a
pin is accepted with that note (the forger signs with his own key; the pin is what stops him): the guide says to note the
fingerprint and to pass it at restore. **Backups of older versions (format 1) still verify and restore**, with `note: this backup
has no signature (made before 0.9.0) – nobody can tell whether it was changed after it was made`, exit 0. **Downgrade:** when
`--backup-key` is given, an unsigned backup is refused unless `--allow-unsigned`; a format-2 backup without a valid signature is
always refused. The `system.backup` audit entry carries the key fingerprint, so a changed key shows in the log. Failure modes:
sealed server (no effect: backup, verify and restore never needed the passphrase); lost key file (old backups still verify with the
public key in `manifest.sig` and the noted fingerprint; the next backup makes a new key and says so, it cannot tell a first run
from a loss); restore into a new data directory (no key comes along: the restore output says the first backup there makes a new
one); rotation = delete the file. Rollback: `install.sh` makes its update backup with the **old** binary (format 1), so its
documented rollback keeps working; a format-2 timer backup needs a 0.9 binary. **ADR check: no ADR is touched** (ADR-07 is
replication, Litestream stays after 1.0); this adds a key to the inventory of PLAN §5 and changes the sentence of §14, both
owner-approved design records: **needs owner decision D1**. If D1 is (c), step 102 shrinks to the docs (S).

**Result of step 101 (2026-11-16, D1 = (b)).** The owner chose (b). The decision record is in the repository: PLAN §5 has the
backup key in its key list (what the signature promises, what it does not, the lost-key case), the PLAN §14 backup row says
what `verify` and `restore` check now and when a pin is needed, `references/security.md` lists the key, and OPERATIONS §6
has the chapter "The backup key" with a table of what `backup verify` prints. Details that step 102 fixed where this
section left room:

- **Fingerprint:** `SHA256:` and the first 16 bytes of the SHA-256 over the raw public key as 32 hex digits (the same
  shape as the checkpoint key's, with the prefix so the two cannot be mixed up). `--backup-key` takes it with or
  without the prefix, upper or lower case, at least 16 digits.
- **`--allow-unsigned` is narrow:** it waives only the missing signature of a **format 1** backup. A format 2 backup
  without a valid signature, and a valid signature by a key other than the pinned one, are refused with and without it
  (the signature of a key you did not expect is no "unsigned" backup).
- **Key of the host without a flag (corrected by the main session after the upgrade test):** `backup verify` (not
  `restore`) looks up the key file of its own host when `--backup-key` is not given and the configuration can be read, but
  only as a **hint** (`Check.HostKey`), never as a pin: signed by it is reported as the host's key; signed by another key
  passes with the note "signed by key X, not this host's key Y" (a legitimate case: the backup of another host); a format 1
  backup passes as unauthenticated, with or without a host key. Only an explicit `--backup-key` refuses. `backup scheduled`
  pins the key that just signed. `restore` goes into an empty data directory, where no key file can exist, so it has none.
- **Layout of format 2:** the same manifest fields as format 1 (an older binary answers "backup format … is not …", not
  "unknown field"), plus `manifest.sig` (JSON: `format`, `algorithm`, `public_key`, `signature`, hex). The signature covers
  `"myownpki-backup-manifest-v1" 0x00` and the exact bytes of `manifest.json`. `manifest.sig` is written first, `manifest.json`
  last, so a crash never leaves something that looks complete.
- **The key's own package:** `internal/backup/backupkey` (not `sign.go`), because `internal/setup` creates the key at
  `init` and `internal/backup`'s tests build instances through `internal/setup`; one package would be an import cycle.
- **Who runs it:** a manual `myownpki backup` as root would create the key file owned by root, and the timer (service user)
  could not read it. OPERATIONS shows `runuser -u myownpki`, and the error for a key file that cannot be read says so.

**`ImportExternal` (103).** `importExternal` counts DNS, IP, e-mail and URI names **before** `certNames` and refuses above
`maxSANs`: `deny("%d names – at most %d per certificate", n, maxSANs)` (the sentence of `names.go:251`). The function is
`checkExternalNames(cert)` so a fuzz target can call it unchanged. A REST client sees **422 `policy-violation`** with that reason,
the audit log gets the existing denied row. A public certificate with more than 100 names (some multi-domain commercial
certificates) can no longer be recorded: D3. Tests: 100 accepted, 101 refused, mixed types, nothing stored, one denied audit row.

**`InspectCSR` (104).** One helper keeps the first `maxSANs` names over all four lists in the order DNS, IP, e-mail, URI, clips each
with `short()`, clips subject and common name, and adds to `Problems`: `"%d names – at most %d per certificate; the list shows the
first %d"`. The answer stays 200 (a preview shows what is wrong); `prefill` of the wizard uses the same helper. Tests: the 2,500-name
seed, order, clipping; `FuzzParseCSR` asserts at most `maxSANs` names and 80-byte strings.

**Upload (105).** A file is DER when `x509.ParseCertificateRequest` accepts it (strict: one request, nothing after it; a PEM text
never parses, it starts with `-`); otherwise a file containing `-----BEGIN` is PEM, as before (`openssl req -text` output with the
block behind it stays accepted, CHANGELOG 0.3.12); otherwise the existing sentence "The file is neither a PEM nor a DER certificate
request." A valid DER request whose subject text contains `-----BEGIN` is accepted instead of failing later with "no PEM block
found". Rated P3 (§18.7): no bypass found, `parseCSR` still checks everything (read, not tried).

### 19.4 Feature freeze rules (step 106)

The freeze starts with the tag v0.9.0 and lasts until v1.0.0. Written into `CONTRIBUTING.md` (new section "Feature freeze"),
`site/contributing.md`, a `CLAUDE.md` rule ("during the beta refuse feature work, name the post-1.0 list"), the PLAN §10.1 row and
a pull request template with one checkbox.

| Allowed | Not allowed (needs an exception) |
|---|---|
| **Fixes** (`fix:` or `fix(<area>):`; the commit says what was wrong) | features, new pages, new settings or configuration keys, new CLI commands |
| **Docs** (`docs:`), **tests** and CI for them (`test:`, `ci:`) | REST additions (a path, a field), changes to `api/openapi.yaml` except to correct it |
| **Security hardening** that only narrows what is accepted (`fix(security):` in the PR title; the §18.7 rules apply) | schema changes, except a **new** migration that fixes a defect (never an edit of a released file: step 107) |
| **Dependency security updates** (`deps/<short>` branch, `chore(deps):`, the two-week rule's security exception of PLAN §13) | new dependencies, protocol changes in `proto/` beyond what `buf breaking` accepts, new agent profiles or recipes, any ADR change |

An exception is the owner's: he writes "freeze exception" on the issue or pull request and adds the label `freeze-exception`; the
commit body names the issue and the CHANGELOG lists it under *Changed*. A session never decides it. **The post-1.0 list**
(PLAN §10.1 "After v1.0", §12 Backlog) stays as it is; ideas from testers get the label `post-1.0` and are looked at after 1.0.

### 19.5 Upgrade tests

**Layers.** U0 is the existing `task upgrade:test` and stays unchanged: from-source old binary, in-process, runs on the owner's
Windows machine (restore on Windows is the point). **U1 (new, steps 107 to 112, 114): release binaries, black box, Linux amd64.**
**U2 (new, step 113): the `install.sh` path as root on the disposable runner.** U1 and U2 do not run on Windows or macOS: the
assets are Linux builds and U2 needs systemd; the Windows-specific risk (files that cannot be removed while open) has unit tests.

**Start versions** (full run; the pull-request subset is marked *PR*):

| Start | pki/system | Why |
|---|---|---|
| v0.1.0 *PR* | 7/8 | oldest schema, makes format-1 backups; the chain from here applies **every** migration in one start; no ACME, no agent |
| v0.2.2 | 10/10 | first with `install.sh`, timer backups and own TLS; ACME; the last before agents |
| v0.3.0 | 13/11 | first agent, baseline of the protocol |
| v0.3.5 *PR* | 19/14 | enrollment passes, `deployment add`, endpoints: the biggest middle jump (13 to 19) |
| v0.3.10 | 21/15 | before the quality round: data written by parsers that were lenient (a stored CRL with trailing data, 0.3.12 notes) must still load |
| **previous release** *PR* | 21/15 | what operators run on release day: v0.3.12, after the tag v0.9.0, then v0.9.x. Never dropped |

v0.3.11 is left out (same schema and data model as v0.3.12); a line in `releases.txt` adds it. Release candidates are not used.

**Fetching** (step 108): `releases.txt` lists `version asset sha256` for the server archive, the agent archive, `install.sh` and
`checksums.txt`; `fetch.sh` downloads `https://github.com/Der-Felix/MyOwnPKI/releases/download/v<V>/<asset>` with `curl --fail
--location --proto =https --tlsv1.2 --retry 3` into `UPGRADE_CACHE` (default `.tools/upgrade/cache`), compares the SHA-256 and
refuses and deletes on a mismatch, refuses a version that is not in the list (no `latest`), and **never runs a download before it
is verified**; `install.sh` is run from the cache, never piped. `pin-release.sh v<V>` (owner, after each release) downloads
`checksums.txt` and its bundle, verifies it with `cosign verify-blob` and the identity of `release.yml` for that tag (cosign is
optional; without it the script says so and needs `--no-cosign`), and prints the lines for review. The hashes thus come from the
signed file, and CI compares only hashes. **Network:** (1) the asset download from github.com and its CDN, (2) `go install` of
lego (module proxy and checksum database; skipped when `LEGO_BIN` or `.tools/lego` exists), (3) at pin time only: GitHub and
Sigstore's TUF mirror. **Offline:** `task upgrade:fetch` once, then `UPGRADE_OFFLINE=1 task upgrade`; a missing asset is a SKIP line.

**Populate** (old binary, throwaway data directory, `init --demo --with-ca`, secrets from `init-demo-secrets.txt`, unseal through
the REST API): two certificates by REST, one revoked; from 0.2.0 a domain rule and one ACME issuance with lego (account kept);
from 0.3.0 an agent enrollment by its archive (join token needs the second factor); from 0.3.5 an enrollment pass; from 0.3.10 a
settings version; an audit entry; `myownpki backup` (the pre-update backup); the facts are written to a file (serials, CRL,
audit head, domain JSON).

**After the update** (the new binary on the same data directory and the old, unchanged `config.yaml`):

1. A1 `db status` before the start: exit 3 and "pending" (exit 0 for the same schema); after the start every database "up to date";
   no `ErrModified`, no `ErrNewer`.
2. A2 the old binary on the migrated data refuses with the `ErrNewer` text and changes nothing (the safety net of the rollback).
3. A3 the pre-update leaf verifies with `openssl verify` against the unchanged chain; the revoked one is still revoked in the CRL
   (`openssl crl -verify`), the CRL number is not lower, the CA certificate fingerprint is unchanged.
4. A4 `audit verify --expect-head` with the old head and `--checkpoint-key` from init passes for every scope (the old log is a prefix).
5. A5 a second ACME issuance with the old lego account works; the directory document keeps its endpoints.
6. A6 the domain rule and, from 0.3.10, its version history read back; a `PUT` with the old `ETag` works.
7. A7 the **old agent**, unchanged and still running, keeps heartbeating (`last_seen` advances, its version is the old one) and its
   report is accepted. New agent against old server is **not promised and not tested** (D9); step 115 guards the wire format.
8. A8 `backup verify` and `restore` of the pre-update backup with the **new** binary (after 102: the "no signature" note, exit 0), then start,
   unseal, A3 and A4 again; a backup made after the update verifies.
9. A9 rollback: stop, move the data away, `restore` the pre-update backup with the **old** binary, start, unseal, same facts as before.
10. A10 `config check` accepts the old `config.yaml` (and the old `agent.yaml`, strict parsing): removing a key in the beta fails here.

**CI placement and budget** (estimates; measuring is the first job of step 109): job `upgrade` (`needs: changes`, matrix over the
*PR* subset, `timeout-minutes: 20`) runs on pull requests whose changed paths include `internal/store/**`, `internal/backup/**`,
`internal/keys/**`, `internal/config/**`, `cmd/myownpki/**`, `proto/**`, `deploy/**`, `scripts/upgrade/**`, `test/upgrade/**`,
`Taskfile.yml`; `changes.sh` gets a second output `upgrade`, true for every non-PR event and when in doubt. **Pushes to main run
the full matrix** (so the check before a tag is the green main run); job `upgrade-nightly` (schedule and `workflow_dispatch`, full
matrix) runs with the daily scan. Per start version about 2 to 4 minutes plus about 40 MB of download (not measured). Not a
required check, like `salt`. `permissions: contents: read`, no secret, no new third-party action, no cache (D5 of §18.5).
`task upgrade` has the registry lines of `local.sh` with SKIP reasons ("needs Linux amd64", "needs the cached assets").
**Migration pin (107):** the file lists every released file with its first release; a new file is allowed until the release
commit adds it with `pin-migrations.sh`; the release workflow step is not changed, `docs/RELEASING.md` gets the line.

### 19.6 Beta for outside testers (steps 116 to 118, 124)

- **Page `site/beta.md`:** what the beta is and what is frozen; install (`install.sh --version 0.9.x`, the container tag, the
  demo); the tester checklist: install with `install.sh`, `init` and the recovery key, issue by ACME with certbot, lego and Caddy,
  the agent on a Debian host (package), backup, `backup verify --backup-key`, restore into an empty directory, update from 0.3.12,
  the trust portal on a phone, the demo; known limitations (the apache2 `/run/apache2` note, the pending live test of the 0.3.11
  recipes, fuzzing covers parsers and not operator files, Windows and FreeBSD agents later); how to report.
- **Reports:** issue forms `bug` (version, install method, what was expected and seen, `myownpki --version`, `db status`), `feedback`,
  a contact link to the private advisory for security; labels `bug`, `feedback`, `beta`, `post-1.0`, `freeze-exception`,
  `blocker` (the owner sets the last two). **Never post:** keys or the recovery key, the unseal passphrase, API tokens, join tokens
  and enrollment passes, session cookies, backup directories or files, `init-demo-secrets.txt`, `auth.key`, TOTP seeds or
  `otpauth://` links, DNS credentials, `agent.yaml` with credentials. Logs are asked for with a check that they hold none.
- **README banner:** "Status: public beta (v0.9.x). The feature set is frozen; only fixes follow until v1.0. Try it, break it,
  report it; never post secrets." with the link to the page.
- **CHANGELOG `[0.9.0]`:** an intro paragraph (the freeze, the upgrade tests, no new feature), **Fixed** (the three input caps,
  the demo text), **Security** (the backup signature, in plain words after the release for anything reachable before login:
  none of 101 to 105 is), **Added** (upgrade tests, beta page, issue forms, freeze rules), **Changed** (backup format 2, README),
  **Upgrade notes** (a backup of format 2 needs a 0.9 binary; install.sh's update backup does not; `outdated_agent` on the Analysis
  page flags every 0.3.x agent as a warning because the minor version differs).
- **`docs/RELEASING.md` additions** under "Before the tag": job `upgrade` green on `main` for **every** start version (no SKIP of
  it accepted); `scripts/ci/pin-migrations.sh --check` against the previous tag; the demo tag test; after the publish: `pin-release.sh`
  and the labels command once.

### 19.7 Order of work and parallelism

1. **First, alone:** 101 (the owner decides D1), meanwhile all others may start.
2. **Parallel from the start** (different files): **Agent 1** 102 (`internal/backup`, `cmd/myownpki/backup.go`, `internal/setup`,
   guides); **Agent 2** 103, 104, 105 in this order (103 and 104 share `renewcert.go`; 105 is `internal/web`); **Agent 3** 107, 108,
   109, 110, 111, 112 in order (`scripts/upgrade`, `test/upgrade`, `internal/store` tests); **Agent 4** 116 to 123 (docs, site,
   templates, demo, Salt, `keys`/`auth` clean-ups; 117 and 120 touch README, SECURITY and CHANGELOG, which nobody else edits
   before 124).
3. **After Agent 3:** 113 and 114 (114 edits `ci.yml`, `local.sh`, `changes.sh`, `Taskfile.yml`, so one agent), then 115
   (`ci.yml` again: same agent). `CONTRIBUTING.md` is edited by 106 first, then by 114 (one paragraph): 106 merges before 114.
4. **106** may run with Agent 4. **Then, in order and alone:** 124, then the owner's steps. `CHANGELOG.md` is edited by 124 only, plus
   120 for the links; the per-step lines are collected from the commit list at 124 (§18.5 D13: no line for a security fix before it is released).
5. A merge conflict is expected in `scripts/ci/fuzz-targets.txt` (102) and `site/_data/nav.yml` (117, 123): one line each.

### 19.8 Decisions (owner; defaults are the cautious option)

> **Decided by the owner on 2026-11-16:** D1 = (b), a dedicated Ed25519 backup key with a pinned fingerprint and format 2 (step 101 is therefore a decision record the main session approves, not a question); D14 = v0.9.0 is tagged when steps 101 to 118 and the upgrade test are green, with the pending live tests listed as open in the release notes. All other decisions stay at their defaults unless the owner objects.

| Topic | Default | Why / alternative |
|---|---|---|
| **D1. Backup authenticity** (**no ADR; touches PLAN §5 key list and §14 backup row: needs owner decision**) | (b) a dedicated Ed25519 backup key and a pinned fingerprint, format 2 | (a) cannot work for the timer; (c) leaves the §14 sentence false |
| D2. Backups without a signature | restore with a note; refused when `--backup-key` is given, unless `--allow-unsigned` | "must still restore" (owner); refusing by default would lock out every old backup |
| D3. SAN cap of `ImportExternal` | refuse above `maxSANs` (100) | the old test chose "record everything"; alternative: a larger constant (250) or record the first 100 and warn |
| D4. `InspectCSR` | keep 100, clip, say so in `Problems` | a preview should not fail where the issuance would explain |
| D5. What the freeze allows | fixes, docs, tests, narrowing security changes, dependency security updates; a new migration only to fix a defect | the exception route of 19.4 for the rest |
| D6. Start versions | v0.1.0, v0.2.2, v0.3.0, v0.3.5, v0.3.10 and the previous release; *PR* subset of three | 19.5; adding one is one line in `releases.txt` |
| D7. Old binaries | release assets with pinned SHA-256 in the repository (cosign checked when pinning); U0 stays source-built | a Linux-only black box plus a cross-platform in-process check |
| D8. CI | `upgrade` on pull requests by path, full on main and nightly; not a required check | cost and noise; the tag check is the green main run |
| D9. New agent, old server | not promised, not tested; the wire guard of step 115 only | agents update after the server (OPERATIONS §9) |
| D10. Demo image tag | a manual bump with a test against `DEFAULT_VERSION` | a static compose file cannot read the version at build time |
| D11. Test-only functions | keep as test helpers (move the unused types and constants next to them); delete `Draft.Confirmed` | §18.5 D12 |
| D12. Issue forms and labels | as in 19.6; the owner runs the label commands | they publish |
| D13. Exit from the beta | the criteria of 19.9 | the owner may shorten or lengthen the two weeks |
| D14. v0.9.0 date | after the owner's live tests of 0.3.11 or with their result listed as known limitations | they are pending since 0.3.11 |

### 19.9 Triage, risks, done, exit

| Finding in the beta | Handling | Blocks v1.0 |
|---|---|---|
| **Blocker:** data loss or a refused start after an update, a restore that loses data, a failing upgrade test from a listed version, an old agent that stops working with the new server, a certificate issued outside policy, §18.7 class P1 | fix in the next 0.9.x at once; D13 of §18.5 for a private advisory | yes |
| **Major:** a wrong result with a workaround (a page broken, an alert wrong, a guide command that fails) | next 0.9.x if small, else a "known limitation" of 1.0; the owner decides | the owner decides |
| **Minor:** text, layout, a doc error, §18.7 P2 and P3 | fixed when cheap | no |
| **Wish:** a feature or setting | label `post-1.0`, never built in the beta | no |

| Risk | Handling |
|---|---|
| The old binaries need ports, TOTP timing and lego against a real listener: a flaky matrix | step 109 measures one version first; ports are chosen free, TOTP waits for the next window (`demo.sh` does); a version that stays flaky moves to the nightly set |
| The runner's address for http-01 (the conformance job already uses the host IP) | the same way; if lego cannot be used for an old version, that version issues over REST only |
| Format 2 locks old binaries out of timer backups (rollback after some days) | in the upgrade notes; `install.sh` backs up with the old binary |
| A fix in the beta changes behavior a client relied on | fixes only narrow; the CHANGELOG lists them (§18.5 D13) |
| Nobody tests: a beta with no reports | the owner's own live tests are the baseline; the page asks for a checklist report |
| The freeze is broken by habit | the PR template, the `CLAUDE.md` rule and the exception label |

**Done for v0.9.0:** steps 102 to 105 merged with their tests (or D1 = (c) with the docs); the freeze rules are in place; steps 107
to 112 and 114 merged and **job `upgrade` green on `main` for all start versions** (step 113 green on the `install` job); the beta
page, issue forms and README banner merged; steps 119 to 123 merged or listed in the notes; `task ci:local` run with every SKIP
reported; the owner's live tests of 0.3.11 and of the update on the homelab done or named as open; the release candidate rehearsal
of RELEASING passed; the CHANGELOG dated by the owner. **Exit to v1.0.0:** no open finding the owner rates a blocker; two weeks
without a new defect found by an outside tester (D13); the upgrade test green from **every** listed start version on `main` and
nightly in those two weeks; the owner's live tests done; a restore and an update of a real instance rehearsed once by the owner;
`docs/PLAN.md`, `CLAUDE.md`, README and SECURITY say 1.0; the post-1.0 list untouched.

**Not verified (honest):** measured here: the tag list, migration counts per release, the asset names and sizes of six releases,
the line numbers cited. Read, not run: every code path of 19.1 and 19.3 (the forged-backup attack, the DER-with-BEGIN refusal,
the 3,000-name import), the lego-on-the-runner assumption, that `go install` of old tags still builds with Go 1.27.4 (the v0.1.0
case runs in CI today; the others are not run), that every old version accepts `init --demo --with-ca` with the same flags
(v0.1.0 does), runtime and download size of the matrix, whether an old agent can enroll without port 80 for renewals, and the
Windows behavior of anything in U1. The `graphify` graph exists only in the main checkout; one query was run there (the backup
package), the rest comes from reading the files and from `git` and `gh` read-only calls.
