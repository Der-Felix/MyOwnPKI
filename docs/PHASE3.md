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
| 26 | 0.3.4 | **Endpoints and scanner**, in three commits. (a) `internal/netguard`: the address policy and the resolve-once dial of `internal/acme/validate.go` (`allowedAddr`, `policyDial`, `cgnat`) move into a shared package that http-01, the agent enrollment check (`acme.HTTP01Checker`) and the scan all call; the port rule (80/443) stays in `acme`, the scan has its own. (b) `pki.db` migration 0018 `endpoints` (§10.2), `internal/tlsscan`: store, `Service` (create, list, delete, scan now, with `authz`, audit through the `pki.db` outbox and the limits), sqlc queries. (c) `Scanner` and its job: a dispatcher every 30 seconds hands due endpoints to a pool of 4 workers and returns at once; per scan: resolve once through `acme.resolver`, the address policy of the covering domain, one TCP connection, a TLS handshake with `InsecureSkipVerify` only to *collect* the chain, close. The chain is then verified **separately** against this PKI's CAs (`ca.Engine.TrustAnchors`, new, read-only) and stored as `trusted`, `incomplete` or `untrusted`. The `monitor:` keys `scan_interval`, `scan_timeout`, `scan_ports`, `scan_max_endpoints` go into `internal/config` (`Monitor`, `envFields` in `env.go`, validation), `deploy/config.example.yaml`, tests and `cmd/myownpki/config.go` (`printMonitoring`). | `netguard` table tests (loopback, link-local, multicast, unspecified, reserved, private under `public`, CGNAT, IPv4-mapped IPv6, IPv6 zone) and the **unchanged** `internal/acme` validation tests still green; a rebinding test (a second lookup would answer 127.0.0.1, the connection still goes to the first, checked address); scanner tests against a local TLS server (right, older, foreign, expired, wrong name, leaf-only chain, client certificate required, plain HTTP on the port, accepts TCP and never answers, closed port) with the network edges injected; `go test -race`; a scan runs while the keyring is sealed; closing the server stops running scans |
| 27 | 0.3.4 | **Evaluation.** `internal/tlsscan` holds the pure function `Assess` (endpoint, what the PKI issued for the name, now: state); `internal/monitor/scan.go` feeds it from the certificates the evaluator already loads (valid ones, the superseded rule of `nameSet` in `certificates()`, `evaluate.go`) plus a fingerprint lookup for a served certificate that is not in the expected set (`ca.Engine.CertificateByFingerprint`, new, read-only, same 404 rule as `Certificate`, over the existing sqlc query `GetCertificateByFingerprint`). The kinds `scan_mismatch`, `scan_expiry`, `scan_unreachable`, `scan_chain` (§10.2) become findings of `Evaluator.Evaluate`; `alerts` (system.db) needs no migration (`kind` has no CHECK). Thresholds are `monitor:` keys with ranges. Resolve on recovery; digests and channels are unchanged (`notify` is not touched; the kinds travel as free text). The dashboard figure *Open alerts* counts them with no change (`alertNumber` counts every open alert); the dashboard's message list (`alertMessages`) keeps its allowlist and does not show them. | Fake-clock tests per kind: nothing before the confirmation scan; `scan_mismatch` opens only after the grace time and a second scan of the same fingerprint and resolves with the next good scan; `scan_unreachable` opens at the Nth consecutive failure and not for a reboot; no duplicates across runs; an unmanaged name gives state `unmanaged` and no `scan_mismatch`; wildcard and IP endpoints; a deleted endpoint resolves its alerts; one digest with a mismatch opened and another alert resolved in the same run |
| 28 | 0.3.4 | **REST and UI.** `api/openapi.yaml` first: `listEndpoints`, `createEndpoint`, `deleteEndpoint`, `scanEndpoint` (tag `monitoring`; `x-required-role` viewer, admin, admin, operator), the `Endpoint` schema, the new `Alert.kind` values. Handlers in `internal/httpapi/endpoints.go`, routes in `routes.go` (`signedIn`), a `WaitError`-style 429 with `Retry-After` for scan now (as `notify.WaitError` in `problem.go`). Page *Endpoints* (`internal/web/app_endpoints.go`, built from `admin.DetailPage`, `TableData` and `FormData` like *Alerts*; nav entry under Overview in `layout/app.templ`, `Real: true`, hidden without `pki.read` or when monitoring is off, as *Alerts*): add form, table with state, served fingerprint, expiry, issuer, last scan and error, a *Scan now* and a *Remove* button per row (plain POST forms that end in 303). New permissions `endpoint.manage` (admin) and `endpoint.scan` (operator, admin) in `internal/authz`; audit actions `endpoint.create`, `endpoint.delete`, `endpoint.scan`; labels for the four kinds in `alertKinds` (`internal/web/app_alerts.go`). | Contract tests (every operation of the spec has a route and the reverse); `task lint:api`; role tests (viewer reads, operator scans but cannot add, admin adds, a role limited to one CA gets 403); the validation table below; audit entries incl. denied ones; scan now answers 429 inside 60 seconds; a hostile served subject (`<script>`) renders as text; the page renders with and without monitoring; no inline styles or undefined classes (the UI tests) |
| 29 | 0.3.4 | **Docs and release.** OPERATIONS chapter 14 "TLS scan" (set-up, each state and alert with what to do, ports and limits, troubleshooting, the end-to-end check below), a pointer row in §13.6, an upgrade paragraph in OPERATIONS §9 ("From v0.3.3 to v0.3.4: pki.db migration 0018, additive"); CHANGELOG 0.3.4; version bump to 0.3.4 in the files of commit `6a8016d` ("docs: prepare v0.3.3 release": `CHANGELOG.md`, `README.md`, `deploy/docker-compose.yml`, `deploy/install-agent.sh`, `deploy/install.sh`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`) and the `v=0.3.3` examples in `docs/OPERATIONS.md`; PLAN §10.1 and this file marked as built. | `task check`, `task ci:local` (every SKIP line reported), Linux CI incl. the image job, the live test below |

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
| What the guard always refuses | the function http-01 uses today: unspecified, loopback, link-local (incl. 169.254.0.0/16, fe80::/10), multicast, 0.0.0.0/8, 240.0.0.0/4; under policy `public` also RFC 1918, fc00::/7 and 100.64.0.0/10. Private ranges are allowed under `internal` (the default) | One implementation (`internal/netguard`), one set of tests. The server cannot scan its own 127.0.0.1, but its LAN address is allowed: a bare handshake gives nothing a client does not get anyway |
| Ports | only those in `monitor.scan_ports`; default `443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443` (TLS from the first byte); 1–65535, at most 32 entries; an endpoint's own port only, nothing derived or followed | A tenant admin cannot turn the server into a port scanner; widening the list is a decision of whoever edits the configuration on the server. STARTTLS ports (25, 143, 587) need protocol bytes and are out (§10.3) |
| Number of endpoints | `monitor.scan_max_endpoints`, default **100** (1–500); beyond it adding is refused with 409 | Bounds work and memory; the order of `agents.MaxDeployments` |
| Host syntax | a fully qualified DNS name by the rules of `agents.CheckHostname`/`checkDNSName` (lower case, at least two labels, letters, digits, hyphen, no wildcard, a trailing dot is trimmed; the check is shared, not copied) or an IP literal (IPv6 without brackets, no zone, IPv4-mapped is unmapped) | Attacker-style input is rejected at the door, with a table test; the guard is the second wall (`localhost` falls out by syntax, `127.0.0.1` by the guard) |
| SNI | optional per endpoint. Empty: a DNS host is sent as SNI; an IP host sends **no** SNI (RFC 6066 forbids IP literals). Set: that name is sent, and it is the name the certificate is expected for | An IP endpoint with virtual hosts needs a name. The SNI is a validated DNS name and never a connect target |
| IPv6 | supported. The resolver's A and AAAA answers are checked one by one in its order; at most **4** addresses are tried per scan, 3 seconds each, inside the endpoint timeout; no Happy Eyeballs | The guard tries every address today; the cap is new for the scan (a `MaxTries` field) so a name with 50 records cannot hold a worker |
| Timeout | `monitor.scan_timeout`, default **10 s** (2–30 s), for resolve, connect and handshake together | As `validateTimeout` |
| Interval and jitter | `monitor.scan_interval`, default **15 m** (5 m–24 h, or `off`); the next scan of an endpoint is the interval plus a random 0–10 % (injectable source); a new endpoint is scanned at the next dispatch | 15 minutes finds a stuck deployment the same morning for one handshake per endpoint; jitter keeps 100 endpoints from firing together after a restart. `off` is for operators who forbid outbound connections; the page then says so |
| Concurrency and memory | dispatcher every 30 s; **4** workers; an endpoint in flight is skipped; its `next_scan_at` moves forward when it is claimed, so a crash cannot rescan at once; `Close()` cancels and waits (as `acme.Server.Close`); a handshake message is bounded by `crypto/tls` (64 KiB); only the leaf and 8 intermediates are looked at | The scheduler (`scheduler.runDue`, `internal/server/jobs.go`) is **one goroutine** that runs the jobs one after the other: a scan inside `runDue` would stall the CRL, ACME and alert jobs. So the job only dispatches |
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
| `older` | the served leaf is a valid certificate of this PKI but superseded | `scan_mismatch` |
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
`127.0.0.1`, `[::1]`, `0.0.0.0`, `169.254.169.254`, `fe80::1%eth0`, `::ffff:127.0.0.1`, `a b`,
`*.homelab.lan`, `-x.homelab.lan`, a 254-character name, an empty host, `xn--` garbage,
`http://proxy.homelab.lan`, port `0`, `22`, `80`, `65536`, `-1`, a duplicate, the 101st endpoint, a host
no domain covers, a body larger than 4 KiB; `proxy.homelab.lan.` is accepted and stored without the dot.
Every refusal names the field and the rule, never an address that was resolved.

**Test strategy.** No real hosts and no real DNS: names are `homelab.lan`, addresses `192.0.2.x`. A
local TLS server (`net.Listen("tcp", "127.0.0.1:0")` with `crypto/tls`) serves a certificate; the
network edges are replaced the way `acme.Server.SetNetwork` does it – `dial` connects to that
listener and `lookupIP` answers `192.0.2.10` – while the address policy, the port rule and
everything around them run unchanged. Certificates come from the real engine of
`internal/testinstance` (`Engine.Issue`; a renewal for the *older* case; revocation; a second
throw-away CA generated in the test for *foreign*; `clock.Fake` advanced for *expired*), so the
comparison runs on real rows. The failure servers are small goroutines: leaf only, wrong name,
requires a client certificate, plain HTTP, accepts and stays silent, closed port. Everything runs
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
| 30 | 0.3.5 | **`myownpki-agent deployment add`, `list`, `remove` and `sandbox sync`**, in three commits. (a) *One model of the sandbox.* `agent.Config` gains the optional block `sandbox: {write: [dirs], low_ports: bool}` (§11.2); `RenderDropins(cfg, existing)` in `internal/agent` derives `10-paths.conf` (`state_dir`, `paths`, `sandbox.write`) and decides `20-low-ports.conf`; `Setup` calls it instead of its own string. The three bugs of the list above are pinned by failing tests first: a manual `/var/log/nginx` entry survives, `20-low-ports.conf` survives, a standalone *deployment* makes the capability needed. `setup` gets `--acme-directory URL` (written into a new `agent.yaml`). `sandbox sync [--dry-run] [--adopt\|--prune]` recomputes both drop-ins from `agent.yaml` (what a Salt run calls after it rendered the file). (b) *The editor and the commands.* `internal/agent/edit.go` changes `agent.yaml` through the `yaml.Node` API of the existing `go.yaml.in/yaml/v3` (no new dependency): comments and key order stay, `deployments: []` becomes a block, new hooks and `paths` entries are appended; the result is parsed with `ParseConfig` (the same `Validate` as `run` and `config check`) **before** anything is written. `deployment add NAME` takes the flags of §11.2; it writes the drop-ins first and `agent.yaml` second (a crash in between leaves a wider sandbox, never a missing one), restores the drop-in bytes when the second write fails, keeps the previous file as `agent.yaml.bak`, runs `systemctl daemon-reload` when a drop-in changed and prints the one restart command (or does it with `--restart`). `--dry-run` prints a unified diff of all three files and writes nothing. `list` prints name, profile, names, targets, hooks and check; `remove NAME` removes the deployment and recomputes the drop-ins (it keeps `paths` unless `--prune-paths`, and never touches deployed files or state). (c) *Recipes.* `internal/recipe` (data only, no imports, so the server can use it without linking lego) holds nginx, Postfix, Dovecot and Proxmox VE (§11.2); `deployment add --recipe NAME` fills defaults, explicit flags win, `--dry-run` shows the expansion and prints "example recipe, test on a non-production host" for the three non-nginx ones | Table tests with a temp root and a fake `systemctl` (the `setupSystemd` seam of `setup.go`); **golden files** for the YAML round trip (comments, flow lists, an empty `deployments: []`, hooks and `paths` already present, a file with anchors/aliases/merge keys or two documents is refused with "edit it by hand"); `Validate` problems are reported before a byte is written; a second `add` of the same name is refused; `--dry-run` writes nothing (file tree compared before and after); failure injection on the second write restores the drop-in; every recipe passes `deployment add --recipe X --dry-run` followed by `config check` in a temp root; paths refused: `/`, `/etc`, `/usr`, `/var`, `/root`, `/home`, `..`, relative, a symlink out of the root; non-root run changes nothing; **setup regression**: a pre-v0.3.5 host whose `10-paths.conf` has `/var/log/nginx` and whose `20-low-ports.conf` exists keeps both through `setup`, `sandbox sync` and `deployment add`; `go test -race`; Linux CI: the agent end-to-end job runs `deployment add --recipe nginx` on the real nginx container, `systemd-analyze verify`, restarts the unit under real systemd and sees the certificate served |
| 31 | 0.3.5 | **The automation path: the enrollment pass** (§11.2 decides it), in four commits. (a) *Schema and service.* `pki.db` migration 0019 adds `kind`, `max_uses`, `use_count`, `revoked_at`, `revoked_by` to `join_tokens` (additive; existing rows become `kind = 'token'`, `max_uses = 1`, `use_count` 1 where `used_at` is set). `agents.CreateJoinToken` takes a kind; one conditional `UPDATE` consumes a use atomically (`UseJoinToken` in `queries/pki/agents.sql`); `checkToken`, `admits` and `initialNames` in `enroll.go` follow the pass rules; `DeleteJoinToken` deletes only `use_count = 0`; new `RevokeJoinToken`. sqlc regenerates `pkidb`. (b) *REST, spec first.* `createAgentJoinToken` accepts `kind`, `max_uses`; `listAgentJoinTokens` and the schemas gain the new fields; new `revokeAgentJoinToken` (`POST /agent-join-tokens/{joinTokenId}/revoke`, admin, `x-step-up`); `hostname` filter on `listAgents` and `listAgentEnrollments`; **install facts** `getAgentInstall` (`GET /agent-install`, viewer): server URL, ACME directory, root SHA-256 and URL, and the manifest of package files with SHA-256, built by the code that builds the guided commands today (`agentTLSTrust`, `agentdist`) moved into a shared function. (c) *UI.* *Agents → Join tokens* gets the pass form (label, names, uses, hours), a state column (`active 3 of 10`, `used up`, `expired`, `revoked`), a *Revoke* button, and per pass the list of hosts it admitted; the step-up summary in `app_stepup_summaries.go`. (d) *Pinning tests of the contract:* an API token with the admin role gets `403` on creating a pass | Fake-clock and `-race` tests in `internal/agents` with real SQLite: 20 concurrent enrollments on a pass of 5 uses give exactly 5 valid and 15 "no uses left", none lost on a restart in between; expiry to the second; revoke ends use at once; pattern match exact and wildcard (one label or more below the suffix, never the bare suffix); a host with an active agent is refused by a pass (goes to the queue naming why); a pass admits only after a passed check in every mode (`auto`, `verified`), never in `manual`; the admitted agent has `agent_names` = its host name only; a single-use token behaves exactly as before (existing tests unchanged); the audit entry of an enrollment names the pass and the use number, never the secret (grep over the whole audit and log output); `createAgentJoinToken` via a token with the admin role is `403`, via a session without a fresh second factor is `step-up-required`, via a session with one is `201`; viewer token lists passes (no secret) and reads agents and enrollments; contract test (every spec operation has a route and the reverse); `task lint:api`; migration test from the 0018 database; **an end-to-end test**: pass created, two `agent.Setup` runs with `--token-file` in temp roots admitted with the fake checker, third refused, pass revoked, fourth refused |
| 32 | 0.3.5 | **The *Add host* assistant.** *Agents → Install agent* becomes *Add host* (same route `/agents/install`, the button on the agent list is renamed) with four steps shown by the existing `.steps` component. (1) *Form:* host FQDN, architecture, package format, enrollment http-01 mode and webroot (as today), **service** (`nginx`, `postfix`, `dovecot`, `proxmox`, or "agent only"), certificate names (the host name by default), admission (one-use token or "none: I approve it in the UI"). (2) *Commands, shown once* (the POST result, as today): the independent values, the token file, install + `setup` (with `--acme-directory`), then `deployment add --recipe …` with the names, then the restart. (3) *Progress page* `GET /agents/add/{hostname}`: whether an enrollment is waiting (host, source address, check result, token valid; *Approve* and *Refuse* for an admin), the agent once admitted (status, last seen, version), each deployment with state, serial, expiry and last error; refreshes every 5 seconds through `<meta http-equiv="refresh">` on the passive route `/agents/add/{hostname}/status` (new `view.Page.Refresh`, `layout/app.templ`); the first view counts as activity, the refreshes do not. (4) *Done:* the certificate is deployed. Step-up is the existing machinery: `a.protected` routes with allowlisted fields and entries in `actionSummary` (`app_stepup_summaries.go`) | Handler tests: only `agent.manage` reaches the form and the POST, viewers and operators get 403, the progress page needs the tenant-wide `pki.read` and shows no button without `agent.manage`; **the token appears exactly once** (the POST response, `Cache-Control: no-store`), never in a URL, a redirect, the progress page, a log line or an action summary; hostile input (`$(reboot)`, quotes, newlines, `<script>` in the host, names, webroot) is refused by validation or `shellQuote`d, and a pending enrollment with a hostile hostname renders as text; every generated `deployment add` line is executed against `agent.AddDeployment` with `--dry-run` in a temp root (the recipe table cannot drift from the CLI); the approve button works through the step-up continuation of v0.3.1 exactly once; the progress page walks through "nothing yet", "waiting", "admitted", "deployment failed" and "deployed" with the fake clock; the refresh meta is present only on the progress pages; no inline style, no undefined CSS class (the UI tests); screenshots of step 1 and 3, light and dark, with `task screenshots` at the milestone only |
| 33 | 0.3.5 | **Docs, recipes and release.** (a) Merge `origin/main` (brings `site/`) and `fix/agent-absolute-path`. (b) OPERATIONS: §12.2 (join token text: tokens, pass, who may create what), §12.3 (the sandbox paragraphs now describe `deployment add`, `sandbox sync` and the `sandbox:` block; hand-editing the drop-in becomes the exception), new §12.7 *Adding a host* (assistant, `deployment add`, the pass, a Salt or CI roll-out, what to do when a pass leaks), new §12.8 pointing to the recipes, an upgrade paragraph in §9 ("From v0.3.4 to v0.3.5: `pki.db` migration 0019, additive; agents need no update; a v0.3.5 agent is needed for `deployment add`"). (c) The public site: `site/hosts.md` (guided installation becomes *Add host*, `agent.yaml` and sandbox sections use `deployment add`), **new `site/hosts/recipes.md`** (nginx, Postfix, Dovecot, Proxmox VE: the exact commands of §11.2, marked as examples) with a child entry in `site/_data/nav.yml`, `site/hosts/salt.md` (the section "The limit of v0.3.3" is replaced by the pass; the hand-written `10-paths.conf` state is replaced by `sandbox sync`), `site/cli.md`, `site/api.md`, `site/security.md` and `site/best-practices.md` (automation tokens are viewer tokens; why a pass and not a token), `site/troubleshooting.md`, `site/upgrade.md`; prose that names a version (`grep -n "0\.3\." site`). (d) CHANGELOG 0.3.5; version bump to 0.3.5 in the files of commit `6a8016d` ("docs: prepare v0.3.3 release": `CHANGELOG.md`, `README.md`, `deploy/docker-compose.yml`, `deploy/install-agent.sh`, `deploy/install.sh`, `docs/RELEASING.md`, `test/install/agent_functions_test.sh`) plus the `v=0.3.x` and `_0.3.x_` examples in `docs/OPERATIONS.md` (§2.1 and §12.2; `site/` reads the version from `CHANGELOG.md` through `scripts/ci/site-prepare.sh`); PLAN §10.1 and this file marked as built. (e) The live test below | `task check`, `task ci:local` (every SKIP line reported), `scripts/ci/site-check.sh` (nav, links), Linux CI incl. the agent end-to-end and image jobs, the live test below; every command in the recipes is run once in a throw-away container or VM and the result (worked, needed a change) is written into the recipe page |

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
