# Night log – v0.2

> Autonomous run, night of 2026-10-22 → 2026-10-23, branch `night/v0.2` (from `fix/release-notes`,
> not merged, not pushed). Plan: docs/PHASE2.md with the owner's decisions of 2026-10-22 (§4).
> Rules: one local commit per finished part, only when `task check` and `task generate:check` are
> green; never push, no tags, nothing published. No new module in the release binary; Pebble, lego
> (`go run …@<version>`), certbot and BIND (containers, own CI job) only as test tools. No ADR
> changes; decisions taken alone are the reversible variant and listed per step.
>
> Written in English (ADR-17). The owner's report is at the top; the step-by-step record follows.

## Report for the owner

**Result: v0.2 is built – steps 1–15 of docs/PHASE2.md plus the security fix you asked for.**
Everything is on the local branch `night/v0.2` – **not merged, not pushed, no tag, nothing
published. No stash.** One part is only checkable in CI: the conformance job (part C).

### Commits on `night/v0.2` (oldest first, all local)

| Commit | What |
|---|---|
| `7a1fa05` | docs: owner decisions for phase 2 |
| `aa28744` | step 1 – domains |
| `5b87980` | step 2 – ACME issuance through the engine |
| `66f2f89` | step 3 – JWS/JWK in own code |
| `ab99474` | steps 4–9 – ACME server (walking skeleton) |
| `26a0b93` | step 10 – revokeCert |
| `22bb2dd` | night log after step 10 (first stop) |
| `b97053b` | **security fix**: http-01 reads nothing back, redirects only within the order |
| `39b90e5` | step 11 – rate limits as tenant settings |
| `52adcdc` | night log – report after step 11 |
| `d47d18a` | step 12 – ARI (renewalInfo, replaces) |
| `24e0a5a` | night log – report after step 12 |
| `2a23f4c` | step 13 – approvals in the UI, EAB keys, screenshots |
| `f0242ad` | night log – report after step 13 |
| `d3daef9` | step 14 – conformance job (CI only) |
| `b0e0b23` | night log – report after step 14 |
| `7d6718d` | step 15 – upgrade test from v0.1.0 |
| `539be49` | step 15 – OPERATIONS chapter 10, CHANGELOG 0.2.0, README |
| _this commit_ | this report; restores the phase-1 report below (see "Found on the way") |

### Done – in short

- **Security fix** (`b97053b`): the http-01 validator tells the client only status and length –
  never the target's answer, transport or DNS error texts, or addresses; redirects only to
  identifiers of the same order (an IP only to itself). Five mutation checks.
- **Step 11** rate limits: three limits as tenant settings (system.db 0009, API, form), 429 with the
  real `Retry-After`, IPv6 per /64, a capped counter map (oldest go first).
- **Step 12** ARI: window at 2/3 of the lifetime with a per-certificate shift; revoked → renew now;
  `replaces` checked (own account, shared name, once → 409); `renewal_of` recorded. **lego asks
  renewalInfo, waits while the window is ahead, and renews a revoked certificate at once.**
- **Step 13** UI: *ACME → Accounts / New names / EAB keys / Orders*, dashboard notices, EAB keys
  shown once. **lego registers with EAB against the own HS256 code.** Screenshots light/dark.
- **Step 14** conformance job: lego, certbot (http-01, dns-01 via certbot-dns-rfc2136 against
  BIND, revoke), acme.sh; Pebble as control; images by digest – **only checkable in CI**.
- **Step 15**: upgrade test (the released v0.1.0 → backup → restore → migrate → ACME issue,
  `openssl verify`), OPERATIONS.md chapter 10 with Caddy/nginx/Traefik, CHANGELOG 0.2.0 under
  `[Unreleased]` without a date.
- Every step: `task check` and `task generate:check` green before its commit.

### Decisions to confirm (since your review of `22bb2dd`; details and "how to reverse" in the tables below)

1. Security fix: also network/DNS error texts and addresses are hidden (more than the body) – table "Security fix after part A".
2. Step 11: `acme_limits` **optional** in `PUT /settings` (no break for v0.1 clients); the challenge-start limit stays a constant; cap 100 000 counters.
3. Step 12: the window for 90 days: day 60–63 to 69–72; renewalInfo answers for every certificate of this PKI.
4. Step 13: reads need a tenant-wide role; EAB keys 1–90 days (default 7); not built: deactivating accounts and deleting EAB keys in the UI.
5. Step 14: **Pebble as control** – it has no suite that tests a server (your plan said "Pebble test suite"); BIND 9.18 because 9.20's tag is younger than two weeks; the conformance test is compiled and linted in every `task check`.
6. Step 15: v0.1.0 via `go install …@v0.1.0` for the upgrade test; README status "v0.2 in preparation"; OPERATIONS title "v0.2".

### Found on the way (worth knowing)

- revokeCert with the certificate key was refused for **every** key type (`Equal(any)` vs.
  `Equal(crypto.PublicKey)`); the test with a foreign key had passed by accident. Fixed in step 10.
- v0.1 refuses unknown `MYOWNPKI_*` variables: a downgrade must remove `MYOWNPKI_ACME_*` (OPERATIONS §9).
- A long URL in an order error ran past the table edge – seen in the screenshot; cells can now wrap.
- **My report script had emptied the phase-1 report** further down in this file (commits `52adcdc`
  to `b0e0b23`). This commit restores it byte for byte from `22bb2dd`; the script now touches only
  the first report.

### Not done / open

- The conformance job has never run (no Docker here). Likely first-run points: the runner address
  from `hostname -I`, certbot's credentials-file warning, acme.sh's standalone mode.
- `task lint:api` (vacuum) not run locally (not installed) – CI runs it for the `acme_limits` schema.
- Traefik and Caddy as ACME *clients*: documented (OPERATIONS 10.6), not tested.

### What you should test

1. **Locally**, one after the other:

   ```bash
   task check
   ```

   ```bash
   task acme:lego
   ```

   ```bash
   task upgrade:test
   ```

2. **CI after your push**: the `check` job now runs the upgrade test; the new job **"ACME
   conformance"** runs lego (`task acme:lego`) and the conformance run. Expect to look at it once.
3. **The screenshots** in `docs/screenshots/` (`acme-*.png`, all others regenerated with the new menu).
4. **By hand: a certificate through Caddy with lego (and certbot)** – the guide below.

### Guide: a certificate on this machine, Caddy as the proxy, lego as the client (PowerShell)

You need Caddy (`caddy.exe` from caddyserver.com) and OpenSSL (Git for Windows). lego is in
`.tools\` after `task acme:lego`. Names: `pki.homelab.lan` is the proxy, `nas.homelab.lan` the
client – it must resolve to this machine's **LAN address**, because the validator never connects to
loopback.

1. Build and make a test directory:

   ```powershell
   task build
   ```

   ```powershell
   New-Item -ItemType Directory -Force C:\acme-test
   ```

2. Write `C:\acme-test\config.yaml`:

   ```yaml
   data_dir: "C:/acme-test/data"
   admin:
     listen: "127.0.0.1:9443"
   public:
     listen: "127.0.0.1:8080"
   acme:
     base_url: "https://pki.homelab.lan:8443/acme"
     listen: "127.0.0.1:8081"
     trusted_proxies: "127.0.0.1, ::1"
   ```

3. Names in the hosts file (PowerShell as administrator; replace `192.168.10.5` with your LAN
   address from `ipconfig`):

   ```powershell
   Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "127.0.0.1 pki.homelab.lan"
   ```

   ```powershell
   Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "192.168.10.5 nas.homelab.lan"
   ```

4. A demo instance with the test CA, then start it (keep this window open):

   ```powershell
   bin\myownpki.exe init --demo --with-ca --ca-base-url http://pki.homelab.lan:8080 --config C:\acme-test\config.yaml
   ```

   ```powershell
   bin\myownpki.exe serve --config C:\acme-test\config.yaml
   ```

   Open https://127.0.0.1:9443, sign in and unseal with the values from
   `C:\acme-test\data\init-demo-secrets.txt`.

5. In the UI: *ACME → Domains → New domain*: `homelab.lan`, CA `issuing`, approval *approved
   accounts*, http-01 on.

6. The proxy's certificate from your own CA (OPERATIONS 10.2) – key and CSR in Git Bash:

   ```bash
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /c/acme-test/pki.homelab.lan.key -out /c/acme-test/pki.homelab.lan.csr -subj "/CN=pki.homelab.lan" -addext "subjectAltName=DNS:pki.homelab.lan"
   ```

   In the UI: *Issue certificate* → preset *server* → paste the CSR → issue → *Download fullchain*,
   save as `C:\acme-test\pki.homelab.lan.fullchain.pem`.

7. The root, as PEM:

   ```powershell
   curl.exe -o C:\acme-test\root.crt http://127.0.0.1:8080/ca/root/1.crt
   ```

   ```powershell
   openssl x509 -inform DER -in C:\acme-test\root.crt -out C:\acme-test\root.pem
   ```

8. Write `C:\acme-test\Caddyfile` – `disable_redirects` keeps Caddy off port 80, which lego needs
   for http-01:

   ```
   {
   	auto_https disable_redirects
   }

   https://pki.homelab.lan:8443 {
   	tls C:/acme-test/pki.homelab.lan.fullchain.pem C:/acme-test/pki.homelab.lan.key
   	handle /acme/* {
   		reverse_proxy 127.0.0.1:8081
   	}
   }
   ```

   Start Caddy in a second window and check the directory in a third:

   ```powershell
   caddy run --config C:\acme-test\Caddyfile --adapter caddyfile
   ```

   ```powershell
   curl.exe --cacert C:\acme-test\root.pem https://pki.homelab.lan:8443/acme/directory
   ```

9. lego trusts your root through an environment variable; the first run is refused ("waits for
   approval"):

   ```powershell
   $env:LEGO_CA_CERTIFICATES = "C:\acme-test\root.pem"
   ```

   ```powershell
   .tools\lego.exe run --server https://pki.homelab.lan:8443/acme/directory --path C:\acme-test\lego --email admin@homelab.lan --accept-tos --domains nas.homelab.lan --http
   ```

   The dashboard now says "1 ACME account(s) wait for approval" → *Review* → *Approve account*
   (second factor). Run the same lego command again – this time it gets the certificate.

10. Check it:

    ```powershell
    openssl verify -CAfile C:\acme-test\root.pem -untrusted C:\acme-test\lego\certificates\nas.homelab.lan.issuer.crt C:\acme-test\lego\certificates\nas.homelab.lan.crt
    ```

    *ACME → Orders* shows the order as *valid* with a link to the certificate.

11. ARI and revocation: the same `lego run` again does **not** renew (window ahead). Then revoke –
    and the next `lego run` renews at once:

    ```powershell
    .tools\lego.exe certificates revoke --server https://pki.homelab.lan:8443/acme/directory --path C:\acme-test\lego --email admin@homelab.lan --cert.name nas.homelab.lan --reason 4 --keep
    ```

12. EAB: *ACME → EAB keys → New key*, copy kid and MAC, then a fresh lego account without the
    queue:

    ```powershell
    .tools\lego.exe run --server https://pki.homelab.lan:8443/acme/directory --path C:\acme-test\lego-eab --email admin@homelab.lan --accept-tos --domains nas.homelab.lan --http --eab --eab.kid <kid> --eab.hmac <MAC>
    ```

13. certbot has no current Windows build – use a Linux host with Docker in the same network. On it,
    `pki.homelab.lan` must resolve to this machine and its own name (e.g. `web.homelab.lan`) to
    itself; on this machine add `web.homelab.lan` with the Linux host's address to the hosts file.
    Copy `root.pem` there, then:

    ```bash
    docker run --rm --network host -v /tmp/certbot:/etc/letsencrypt -v "$PWD/root.pem:/root.pem:ro" -e REQUESTS_CA_BUNDLE=/root.pem certbot/certbot:v5.8.0 certonly --server https://pki.homelab.lan:8443/acme/directory --standalone -d web.homelab.lan --agree-tos -m admin@homelab.lan
    ```

    Caddy listens on all interfaces; allow inbound port 8443 in the Windows firewall for the Linux
    host, and port 80 on the Linux host for this machine (the validator connects there).

14. Clean up: stop Caddy and the server (Ctrl+C), remove the two lines from the hosts file, delete
    `C:\acme-test`.

## CI run 39849783550 (PR 5) – three red jobs

Green in that run: check, Windows, macOS, cross, vuln, Bash suite. One commit per fix, each with
`task check` and `task generate:check` green; not pushed.

| Job | Cause | Fix | How to reverse |
|---|---|---|---|
| ACME conformance (both certbot cases) | certbot runs as root in its image and writes `live/` with mode 0700 – the test (runner user) can't read `fullchain.pem` | Client containers run with `--user "$(id -u):$(id -g)"`; certbot's config/work/logs dirs are in the mounted work directory; the acme.sh image is built for any user (`chmod -R o+rwx` on `/acmebin` and `/acme.sh`, `HOME=/acme.sh` – read in its 3.1.5 Dockerfile). Port 80 without root: run.sh already lowers `ip_unprivileged_port_start`. No permission loosened | Remove the `--user` lines in `confEnv.docker` |
| lint:api | vacuum `no-unnecessary-combinator`: `DomainUpdate` was an `allOf` with one `$ref` | Direct `$ref` (OpenAPI 3.1 allows `description` next to it). vacuum 0.30.6 now local in `~/go/bin`: the release's `checksums.txt` lists the linux archive with CI's `VACUUM_SHA256`, the windows archive was verified against that file. `task lint:api`: 0 warnings, 10 infos (allowed) | – |
| race (exit 143 after ~3 min) | See below – most likely memory | Diagnostics and `timeout-minutes: 20` | Revert the race job and `failed-tests.sh` |

### The race job: what a) found

- **No test signals a process group.** No `Setpgid`/`Setsid`, no `kill`/`pkill`, no `syscall.Kill`,
  no `Signal(` anywhere in Go code, scripts or workflows; every child process in tests is
  `exec.CommandContext` (on cancel: SIGKILL to the child only). The only `timeout` is the legacy
  `with_timeout` (`timeout 3 …`): GNU timeout puts itself in its own process group, so its
  `kill(0)` reaches only that group. Upgrade, lego and conformance tests skip themselves in this job
  (no `UPGRADE_FROM_BIN`/`LEGO_BIN`); there is no fuzz corpus on disk.
- **But the tests need a lot of memory – because of Argon2id.** `testinstance` builds the key ring
  with `keys.New`, that is with the **production** KDF parameters (t=4, **256 MiB**, p=4): every
  instance derives three times (init, unseal in `setup.Run`, unseal in the test). Peak memory per
  test binary measured here, **without** -race (4 CPUs like the runner):

  | Package | Peak memory | Time | With test KDF parameters (8 MiB, t=1, p=1; tried and reverted) |
  |---|---|---|---|
  | internal/acme | 2366 MiB | 17.5 s | 408 MiB, 3.9 s |
  | internal/server | 2379 MiB | 5.7 s | 520 MiB, 2.1 s |
  | internal/httpapi | 2320 MiB | 13.1 s | – |
  | internal/web | 2084 MiB | 15.3 s | 522 MiB, 5.5 s |
  | cmd/myownpki | 1685 MiB | 8.0 s | – |

  `go test ./...` runs up to 4 packages at once, the race detector needs 5–10× the memory (Go docs)
  – far over the runner's 16 GB. Exit 143 (SIGTERM, not the OOM killer's SIGKILL) fits the runner
  shutting the job down; the job log shows it if it says "The runner has received a shutdown
  signal". internal/acme is new in v0.2 and is the largest of the five.
- **Why only "ok …/api":** plain `go test ./...` holds each package's output back until the package
  ends – the running ones were invisible, and a kill drops their buffers.

### b) – what the next run shows

- `go test -race -json` into `$RUNNER_TEMP/test.json` (via `tee`); the log gets readable text from
  `failed-tests.sh --text`: "started <package>", ok lines, everything of a failed package.
- `failed-tests.sh` reads the JSON: failures as before; **if a package started and never ended**
  (killed or timed out), one more annotation lists those packages and the tests that had started
  and not ended, latest first (parallel tests waiting for their turn are marked), with the last
  output lines. Tested locally with a cut-off log, under gawk and gawk `--posix`.
- Memory every 15 s in the log; on a failure the last two minutes go to the summary, and OOM-killer
  lines from `dmesg` become an annotation.
- `timeout-minutes: 20` for the job; the annotation step also runs after the timeout (`cancelled()`).

### c) The fix (owner decision 2026-10-23: the real fix, not `-p 2`)

| Decision | Why | How to reverse |
|---|---|---|
| `keys.TestKDF()` option on `keys.New`, `setup.Options.TestKDF`, `auth.TestParams()`; the weak values (t=1, 8 MiB, p=1) in **one** place, `keys.testArgon2` (exported via `keys.TestArgon2()`); used by `testinstance`, the server, ca and cmd test helpers, and the keys/setup/auth tests | Test instances derived 3× 256 MiB each; the values were copied in four places | Remove the option from the helpers (the guards can stay) |
| Lock 1: the option, `TestArgon2` and `auth.TestParams` **panic** outside a test binary (`testing.Testing()`), `setup.Run` returns an error; no flag, config key or env variable | Weak parameters must never reach a real instance by accident | – |
| Lock 2: **unseal refuses** a passphrase slot below t=4, 256 MiB, p=4 outside a test binary (`ErrWeakKDF`, audited `denied`/`weak_kdf`, before any derivation); same for every passphrase check; the recovery key still unseals and a new passphrase gets the production values | A key ring made by a test build must not protect real keys; the error names the way out | Remove the `checkUnsealParams` call in `openSlotWithPassphrase` |
| The test mode is read once at `keys.New` into an unexported field, so a test can run the **whole** unseal path as a server binary | Otherwise the call site of lock 2 is untestable (a mutation removing it survived in the first draft) | – |
| v0.1.0: `defaultArgon2` unchanged since its first commit (`abb0d18`), set only in `keys.New`; the upgrade test now reads the restored slot: `{"t":4,"m":262144,"p":4}` | Lock 2 must not lock out an existing installation | – |
| `cmd/myownpki` stays at ~1.3 GB: `passphrase change/reset` through the real CLI code stores the production values (no flag allowed), and the test verifies them | A second test of the production path; one sequential test | – |

Tests: `TestWeakKDFOnlyInTestBinaries` (option and minimum with the test mode as an argument; t, memory
and lanes each one step below), `TestTestKDFIsStored` (the weak slot as a server binary: refused,
`denied` in the audit log, recovery key → new passphrase → unseal works), `TestProductionArgon2Parameters`
(init and unseal with t=4, 256 MiB, p=4: 474 ms here), `TestTestKDFOnlyInTestBinaries` (setup).
Mutations, all caught: unseal ignores the minimum; option allowed outside tests; `allowTestKDF`
always ok; minimum ignores t; minimum ignores p; setup guard off; TestKDF without effect.
`task upgrade:test` green. The release binary has no `-test.*` flags (`testing` only for `Testing()`).

Peak memory and time per test binary, without -race, 4 CPUs (same method as above):

| Package | Before | After |
|---|---|---|
| internal/acme | 2366 MiB, 17.5 s | **121 MiB, 3.0 s** |
| internal/server | 2379 MiB, 5.7 s | **229 MiB, 1.8 s** |
| internal/web | 2084 MiB, 15.3 s | **139 MiB, 3.9 s** |
| internal/httpapi | 2320 MiB, 13.1 s | 130 MiB, 2.8 s |
| cmd/myownpki | 1685 MiB, 8.0 s | 1335 MiB, 3.5 s (see above) |
| internal/keys | 571 MiB, 2.1 s | 937 MiB, 2.2 s (now init **and** unseal with production values) |

`go test -race ./...` could not run here: no C compiler on this machine (cgo needs gcc). **Only
checkable in CI** – the race job's memory log (b) shows the peak.

## Owner decisions applied (commit "docs: owner decisions for phase 2")

| Decision | Why | How to reverse |
|---|---|---|
| ACME is **off while `acme.base_url` is empty**; when set it must be `https://`. `acme.listen` defaults to 127.0.0.1:8081 | A v0.1 config has no `acme` section – requiring `base_url` always would stop every upgraded server from starting | Make `base_url` required |
| `acme.trusted_proxies` defaults to loopback (`127.0.0.1, ::1`) | Matches the default listener: a proxy on the same host works without extra settings | Empty default (nothing trusted → every request 403) |
| Sealed server as the owner proposed: finalize stores the CSR, the order stays `processing` with `Retry-After`, issued at the unseal and by a job every minute | The CSR and the authorizations are already proven – waiting costs nothing and needs no new client action. The alternatives are worse: refusing finalize (`serverInternal`) makes the order `invalid` and the client must start again with new challenges; queueing in memory loses the request at a restart. Clients that stop polling (lego and certbot give up after a while) just run again later and get a new order – the old one is issued but unused, which is harmless | Refuse finalize while sealed |

## Part A – Steps 1–9: domains to finalize (walking skeleton)

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| Domain logic lives in `internal/ca` (engine methods, `domains.go`), not a new `internal/domain` package | It needs the CA's name constraints, `loadIssuer` and the pki.db writer; a package of its own would copy them | Move it out behind an interface |
| Managing domains needs `ca.manage` (admins, with step-up); reading them `pki.read` | A domain decides what is issued automatically – as weighty as a CA setting. No new permission (authz stays as approved) | A permission `domain.manage` |
| A domain name has at least two labels (no `lan`, no TLD), punycode, lower case, no wildcard; the CA must be an active intermediate with an online key, and its name constraints must permit the domain (and `x.<domain>` when sub-domains are included) | A one-label domain would hand out a whole namespace; a root never issues leaves | Allow one label with a warning |
| IP ranges of a domain (RFC 8738 IP identifiers) are a JSON column `ip_ranges` of `domains`, not a table `domain_ips` | One row = one policy, read in one query; the list is short | A table |
| Deleting a domain is always allowed and audited; finalize checks the domain again, so pending orders of a deleted domain fail there | Nothing dangles: no issuance without a domain | Refuse while orders are open |
| **One policy engine:** `ca.Request` gets an optional `ACME *ACMEOrder` (order ID, account). The engine then requires every name to lie in a domain, all of one CA and one preset, and takes CA, preset and validity (default 90 days, capped by the CA) from the domains. UI/API issuance without it is unchanged | ADR-19: ACME goes through the same `Issue` – names, constraints, key policy, build, audit. Phase 1 issuance must not change (PHASE2 step 2) | – |
| Order and certificate in **one pki.db transaction**: `Issue` takes an optional hook that runs in its storing transaction (ACME sets the order to `valid` with the certificate ID there) | ADR-06 / PHASE2 §1: a crash can't leave a certificate without its order, or a second issuance for the same order | Two transactions with an idempotent retry |
| ACME issuances use the principal `authz.System("acme")` and the audit actor `acme_account:<id>` | ACME clients are not users; the ACME layer has already checked account, approvals and challenges | A role for ACME accounts |
| JOSE in `internal/acme/jose`: strict top-level and header parsing with a token reader that refuses duplicate names; the algorithm from the key (P-256 → ES256, P-384 → ES384, RSA ≥ 2048 → RS256, Ed25519 → EdDSA), header must match; ES signatures exactly 64/96 bytes R‖S; a `jwk` with private members (`d`, …) refused; RSA exponent odd and ≥ 3 | Owner Q3 | – |
| **EAB is the one place with HS256:** the inner JWS of `externalAccountBinding` is an HMAC by RFC 8555 §7.3.4; it is verified by a separate function with HS256 only, never by the outer verifier | The outer rule "no HS*" stays absolute | – |
| ACME runs in `internal/acme` as an `http.Handler` on `acme.listen`; the server starts that listener only when `acme.base_url` is set | Off by default, like everything that opens a port | – |
| Peers outside `acme.trusted_proxies` get **403** with an ACME problem; the client address for rate limits and audit is the last X-Forwarded-For entry that is not a trusted proxy | Owner Q1 | – |
| Account status to the client is RFC's `valid`; whether it is **approved** is our own column. With approval level `account` an unapproved account's `newOrder` gets `unauthorized` "waits for approval in MyOwnPKI (account …)" – the client retries later. A valid EAB approves at once | RFC 8555 knows no "pending" account; standard clients handle a refused order and rerun | Refuse `newAccount` without EAB |
| Approval level `new_name`: `newOrder` with a name never issued before records a request in `acme_names` and answers `unauthorized` "name … waits for approval" | Simpler and clearer than an authorization that waits; the same client rerun works | A pending authorization |
| Nonces in memory (at most 100,000, 1 hour); a restart answers `badNonce`, which clients retry | RFC 8555 §6.5 | A table |
| Validators run in a bounded pool (4 at a time) after the challenge POST; the answer is `processing`, the client polls | No long request; SSRF limits per security.md | – |
| http-01: port 80 only – the tests replace the dialer, never the port rule | A test switch must not become a production switch | – |
| lego as the end-to-end check: a test that runs only with `LEGO_BIN` set (Taskfile `acme:lego` builds lego `@v4.x` with `go install` into a temp dir); a TLS reverse proxy in the test plays Caddy | Owner: test tool only, no go.mod entry | – |

### Done (part A)
- Step 1 `aa28744`: domains (pki.db 0008, engine, API `/domains` in the spec and the contract run, UI under ACME > Domains).
- Step 2 `5b87980`: `ca.Request.ACME` – CA, preset and validity from the domains; the order set valid inside the storing transaction.
- Step 3 `66f2f89`: `internal/acme/jose` (own JWS/JWK code, RFC vectors, a negative test per rule, `FuzzParse`, `task fuzz` and 30 s in CI).
- Steps 4–9 `ab99474`: config `acme.*`, pki.db 0009, `internal/acme` (directory, nonces, accounts, key change, orders, authorizations, challenges, http-01/dns-01 validation, finalize, certificate), the third listener, finalize while sealed with the dashboard notice. **Walking skeleton reached: lego v5.5.2 registers, orders by http-01, gets the certificate, `openssl verify` OK.**
- Changes against the design table, taken while building:
  - EAB MAC keys are **not** rows of `keys` (its CHECK allows only `ca`/`leaf`; changing it means rebuilding the table with its triggers): `acme_eab_keys` holds the envelope itself, with a new key-ring purpose `acme-eab` bound into the encryption. Overwritten when used (one key, one account).
  - Pending authorizations and orders live **24 hours** (Let's Encrypt: 7 days); valid authorizations 7 days (owner Q6).
  - A domain's preset must allow **serverAuth** (`client` offers DNS names but is no TLS server certificate).
  - ACME wildcards work with the domain's preset (`server`): the engine allows the wildcard names of an ACME order without the `wildcard` preset's extra base name – the certificate names exactly the order.
  - lego and later pebble are built into **`.tools/`** (gitignored), not `bin/` – `task build:verify` checks every file in `bin/` for CGO.
  - lego's module is `github.com/go-acme/lego/v5` (the CLI lives at the module root since v5).

### Tests (part A)
- `internal/ca`: domains (defaults, 21 refusals, lookup incl. suffix tricks, permissions), ACME policy (domains decide CA/preset/validity, CSR names ignored, hook rollback, lowered CA maximum).
- `internal/acme`: directory/nonce/proxy/X-Forwarded-For, http-01 to certificate (incl. IP identifier, reuse, other account gets 404), dns-01 wildcard, failed challenges (loopback target, wrong content), unknown names/IPs, approval levels, finalize while sealed, five bad CSRs, `orderNotReady`, request rules (replayed nonce, wrong URL, jwk vs kid, foreign key, unknown account, content type, onlyReturnExisting, tel: contact), key change and deactivation; `TestLegoWalkingSkeleton`.
- `internal/server`: the ACME listener and its directory; no ACME on the public port. `internal/config`: the `acme` section.
- Mutations caught: CSR name check off; address policy off; wrong key authorization (lego fails with `incorrectResponse`); duplicate check and R‖S length in jose.

### Not verifiable tonight (part A)
- certbot, acme.sh, Traefik and Caddy (part C/D: CI job and the guide).
- A real DNS server for dns-01 (the tests replace the lookup; BIND comes in the CI job).

## Security fix after part A: http-01 reads nothing back

Owner finding: with the address policy `internal`, the validator could be used to read the inside network – a redirect to `http://192.168.1.1/` put the start of that page into the challenge error.

| Change | Why | How to reverse |
|---|---|---|
| Errors carry only status and length (`answered 37 bytes that are not the key authorization`, `answered with status 401`) | The answer of a target never reaches the client | `http01()` in `internal/acme/validate.go` |
| Network and DNS errors are named by kind (`timed out`, `could not connect`, `TLS handshake failed`, `the connection failed or the answer was not HTTP`, `no such name`) – never their text | Go's errors quote what the target sent (`malformed HTTP response "SSH-2.0-…"`), name inside addresses and the resolver | `netProblem()`, `dnsProblem()` |
| Dial failures: counts of refused and unreachable addresses, no addresses; the details go to the server log (Info) | Resolved addresses of inside names are topology | `policyDial()` |
| Redirects only to identifiers of an order the authorization belongs to; an IP identifier only to exactly that address; else `incorrectResponse` "redirect to a host outside this order" (PHASE2 §2 step 7, as planned) | The validator is not a free HTTP client; the dialer still checks the address policy on every hop | `CheckRedirect` + `orderHosts()` |

Tests (`internal/acme/validate_test.go`): redirects to a foreign host in the domain, a host elsewhere, an IP outside, an IP in the range but not in the order, another IP for an IP order, the metadata address – all refused, the target not in the message; same host on 443 and another identifier of the order – valid. A target with a secret in the page, in an error page with a header, in a long page, in a redirect path, a non-HTTP banner, an unreachable address: the secret/address is in neither the challenge error, the audit entry (`details_json`) nor the server log.

Mutation checks (each made a test fail, then reverted):

| Mutation | Caught by |
|---|---|
| Redirect host check off | `TestHTTP01RedirectsStayInTheOrder` |
| Old message `answered %q` with the body | `TestHTTP01ReadsNothingBack` |
| Transport error text in the message | `TestHTTP01ReadsNothingBack` (banner) |
| Other identifiers of the order not allowed | `TestHTTP01RedirectsStayInTheOrder` (www → nas) |
| Dial error text in the message | `TestHTTP01ReadsNothingBack` (unreachable) – survived at first, because the test dialer's error had no address; the stub now names the address like a real dialer |

## Part B – Steps 10–13

| Decision | Why | How to reverse |
|---|---|---|
| revokeCert accepts the ordering account, an account with valid authorizations for **every** name of the certificate, or the certificate's own key (RFC 8555 §7.6) | The RFC's three ways; the key path lets someone report a leaked key without the account | Drop a branch in `revoker()` (`internal/acme/revoke.go`) |
| `keyCompromise` only from the ordering account or the certificate key – not from an account that merely holds the names | keyCompromise blocks the key for all later certificates; an account that never held the key must not block it (Let's Encrypt does the same) | Remove the check in `revoker()` |
| Certificates with email/URI names (or none) can't be revoked over ACME by name holders – "revoke it in the UI" | No ACME authorization covers those names | – (follows from RFC 8555) |
| Reasons 2, 6, 8, 10 (and unknown codes) → `badRevocationReason` | Same list as the UI (`ca.LeafReasons`): no hold, no CA reasons | `revocationReason()` |
| `alreadyRevoked` is answered only after the signer is authorized | Otherwise anyone could ask whether a certificate is revoked – that is the CRL's job | Swap the order in `revokeCert()` |
| Refused revocations are audited as `certificate.revoke/denied` (actor: the account, or `key:<thumbprint>`) | An attempt to revoke a foreign certificate is worth a trace | `refuseRevoke()` |
| Revocation while sealed: 200, stored at once, the CRL is signed at the unseal | Same as the UI (PHASE1 step 9); a revocation must never wait | – |

- Note: lego v5.5.2 prints `v5.6.1+dev-release` as its version – a constant in lego's source. `go version -m .tools/lego.exe` shows module `v5.5.2` with its checksum.

### Step 11 – rate limits

| Decision | Why | How to reverse |
|---|---|---|
| Three limits are tenant settings (system.db 0009, `acme_limits` in `/settings`, the settings form): orders per account, failed validations per name, new accounts per address – per hour, defaults 300 / 5 / 10 (the former constants) | Owner plan step 11; an admin tunes them without a restart – the ACME server reads them at every request | Drop migration 0009 before a release; the server falls back to `DefaultLimits` |
| Validation starts per account (300/h) stays a constant | Not in the plan's list; a guard against a runaway client, not a policy | Add a column like the others |
| `acme_limits` is **optional in PUT /settings**, always in the answer | v0.1 API clients send the settings without it – absent keeps the stored limits (no breaking change) | Make it required in the spec (breaking) |
| 429 carries the real wait as `Retry-After` (rounded up, ≥ 1 s) and in the text | RFC 8555 §6.6; a fixed 30 s made clients retry 120 times an hour | `acmeError.retry` |
| New accounts count per IPv6 **/64** | One host usually holds a whole /64; per address the limit is void | `ipKey()` |
| Limiter cap 100 000 windows (~10 MB): expired go first, then the oldest tenth at once | Many addresses or failing names can't grow memory without bound; beyond the cap only the oldest counters reset, never the newest | `limiterKeys`, `evict()` |

Tests: `TestRateLimits` (fake clock: accounts, orders, failed validations; `Retry-After` 3600 → 2400 after 20 minutes; open again after the hour; a raised limit counts at the next request), `TestLimiterCap` (50 000 addresses, cap 1 000, the newest keeps its count), `TestIPKeyAndRetry`, API contract cases (valid → 200, 0 → 422), UI (defaults shown, stored, three bad values refused).

Mutation checks: fixed Retry-After, no eviction, newest evicted first, no /64 grouping, settings ignored – each made a test fail.

Not checked locally: `task lint:api` (vacuum is not installed here; the spec change follows the existing schemas) – CI runs it.

### Step 12 – ARI (RFC 9773)

| Decision | Why | How to reverse |
|---|---|---|
| Window: opens at 2/3 of the lifetime plus a per-certificate shift of up to 1/30 of the lifetime, 1/10 of the lifetime wide. 90 days: from day 60–63 to day 69–72 | pki-rules.md §5 "2/3 with jitter"; the shift comes from the serial (stable between questions), so certificates issued in one batch don't renew in one hour; the client picks a random moment inside (RFC 9773 §4.2); at least 18 days stay before expiry | `renewalWindow()` in `internal/acme/ari.go` |
| Revoked certificate: a window in the past (renew now) | RFC 9773 §4.2 – a revoked certificate should be replaced at once | – |
| `Retry-After: 21600` (6 h) | RFC 9773 §4.3 suggests hours; often enough to notice a revocation the same day | `ariRetryAfter` |
| `replaces` in newOrder is checked: the certificate belongs to an order of the **same account**, shares a name, and no other live order replaces it (else 409 `alreadyReplaced`, checked again inside the transaction) | RFC 9773 §5; unknown and foreign certificates get the same answer (no probing) | `checkReplaces()` |
| The renewal's certificate records `renewal_of` (as a renewal in the UI) | The certificate history shows ACME renewals like the others | `RenewalOf` in `issue()` |
| renewalInfo answers for every certificate of this PKI (also UI-issued), not for external ones | The identifier is in the certificate itself; the answer is a window, nothing secret | `certByARIID()` |
| pki.db 0010: `acme_orders.replaces` and an index on `certificates.serial_hex` | renewalInfo looks certificates up by serial; the existing unique index starts with `ca_id` | Drop the migration before the release |

Tests: `TestRenewalInfo` (window inside the lifetime at 2/3, stable, unknown → 404, six malformed identifiers → 400 incl. a negative and a non-minimal serial, revoked → window in the past), `TestRenewalWindow` (50 serials, 90 days: start day 60–63, width 9 days, ≥ 40 different starts), `TestReplaces` (foreign account, no shared name, garbage, second renewal → 409, `renewal_of` stored). **lego**: a second `lego run` asks renewalInfo and does not renew; after `lego certificates revoke` the next `lego run` renews at once with `replaces`, and the new certificate's `renewal_of` is the old one.

Mutation checks: revoked window not in the past, account not checked, no jitter, `replaces` not stored, no shared-name check – each made a test fail. Not testable: the second count inside the transaction (needs two requests in the same instant); the first count catches every sequential case.

### Step 13 – approvals in the UI

| Decision | Why | How to reverse |
|---|---|---|
| New pages under ACME: **Accounts** (waiting queue, all accounts, account detail), **New names** (queue, decide, approve in advance), **EAB keys**, **Orders** (newest 200) | Owner Q2 and the plan; Orders replaces the "phase 2" placeholder | Remove the routes in `internal/web/app.go` |
| Approving and deciding: one form with a select per queue (no button per row) | Calm and plain (frontend.md); one POST target per action, CSRF as everywhere | – |
| Approve, decide and create EAB keys need **ca.manage on the tenant with a fresh second factor**; reading the pages needs a **tenant-wide** role | An approval lets an account obtain certificates; the pages show every account of the tenant – a role on one CA doesn't see them | `authorize()` / `readable()` in `internal/acme/admin.go` |
| EAB key: 256 random bits, valid 1–90 days (default 7), shown **once** on the POST answer (`Cache-Control: no-store`, no redirect), with lego and certbot command lines; stored only as an envelope (key ring purpose `acme-eab`), overwritten when used; creating one needs an unsealed server | Owner Q2 "shown once"; an unused key should not live long | `CreateEABKey()` |
| Dashboard: "N ACME account(s) wait for approval" and "N new name(s) wait for approval", each with a Review link | Owner plan step 13 "dashboard counters" | `app_pki.go` |
| ACME off (no `acme.base_url`): the pages say how to switch it on | An admin who clicks the menu learns why it is empty | `acmeOff()` |
| Table cells get an optional `Break` (the existing `.break` class) – used for error details and contacts | A long URL in an order error ran past the table edge (seen in the screenshot) | `admin.Cell.Break` |
| Not built: deactivating an account and deleting an unused EAB key from the UI | Not in the plan; an unused key expires by itself | Later step |

Tests: `TestEABKeys` (five bad inputs, waiting account can't order, wrong MAC, EAB account orders at once, key used twice, expiry, no MAC in the audit log or in plain text in the database, sealed → `ErrSealed`), `TestACMEApprovalPages` (dashboard counters, approve, approve twice refused, refuse/approve-in-advance/garbage name escaped, EAB shown once with `no-store` and not in the list, three bad EAB forms, viewer sees no forms and can't approve or create a key, CA-scoped operator gets 403), `TestACMEPagesOff`, the four pages in the page sweep (no inline style/script). **lego** `TestLegoEAB`: without EAB refused under "approved accounts", with `--eab` it registers and gets the certificate – the own HS256 code against a real client.

Mutation checks: EAB without authorization, reads without a tenant role, dashboard counter off – each made a test fail. Not observable by a test: clearing the MAC from memory after use.

Screenshots (`task screenshots`, headless Edge, neutral demo instance): new `acme-accounts`, `acme-names`, `acme-orders` (light) and `acme-accounts-dark`, `acme-names-dark`; all others regenerated (the menu has the new ACME entries; the dashboard shows the two waiting notices).

## Part C – Step 14: conformance job (**only checkable in CI**)

| Decision | Why | How to reverse |
|---|---|---|
| A Go test with the build tag `conformance` (`internal/acme/conformance_test.go`) plus `test/conformance/run.sh` for the environment, called by `task acme:conformance` and the new CI job `conformance` | The test reuses the instance and proxy of the lego test, with **nothing replaced**: `acme.resolver` is BIND, the dialer is real, the clients answer on port 80; the checks stay in Go, the script only starts BIND and builds the tools | Delete the job, the task and the two files |
| **Pebble as control**, not as a "test suite": the same lego run goes against Pebble first | Pebble is Let's Encrypt's test *server*; it has no suite that tests a server. As a control it proves the harness (DNS, port 80, TLS trust): a client that works against Pebble and fails against us shows a fault of ours | Drop the subtest "control: lego against Pebble" |
| Clients: lego (http-01 with revoke; dns-01 wildcard via RFC 2136 `dnsupdate`), certbot (register, http-01 standalone, revoke; dns-01 wildcard with certbot-dns-rfc2136), acme.sh (http-01 standalone); every certificate is checked with `openssl verify` against the root | The plan's list; each client also uses a different key type (RSA 2048, P-384, P-256) | – |
| Images by digest (tag and push date beside it), all ≥ 2 weeks old on 2026-10-22: `internetsystemsconsortium/bind9:9.18` (2026-09-15), `certbot/dns-rfc2136:v5.8.0` (2026-09-01), `neilpang/acme.sh:3.1.5` (2026-09-19). Newer tags (bind9 9.20, acme.sh 3.1.6) were pushed within the last two weeks | Owner rule | Change the three lines in `run.sh` |
| BIND on 127.0.0.1:5300, zone `homelab.lan` with a wildcard A record to the runner's address; a **TSIG key generated per run** (`openssl rand`), masked in the log, only in the work directory | No secret in the repository or the log; port 5300 avoids systemd-resolved on 53 | – |
| Port 80 without root: `sysctl net.ipv4.ip_unprivileged_port_start=80` (sudo, CI only) | lego runs as the runner user | – |
| The conformance test is compiled and linted in every `task check` (`build-tags: [conformance]` in `.golangci.yml`) | A job that runs rarely must not rot | Remove the line |
| Pebble itself contains go-jose and miekg/dns | It is a test tool built into `.tools/`, never part of our module or release (owner rule: not in *our* code) | – |
| Traefik and Caddy: a documented manual test (plan), not in CI | Part D, the guide in the report | – |

### What I could check locally (Windows, no Docker)
- `go vet -tags conformance` and golangci-lint with the tag: clean. ShellCheck on `run.sh`, actionlint on the workflow: clean.
- The three image digests: read from the registry (manifest digest = the pinned one); **entrypoints read from the image configs**: bind9 `named -u bind` (so `run.sh` passes only `-g -c …`), certbot `certbot`, acme.sh `/entry.sh` with the verb as first argument.
- Pebble v2.10.1 builds with `go install`; its module has `test/certs/localhost/{cert,key}.pem` and `pebble.minica.pem`.
- lego's file names from its source (`*` → `_`); the test finds files by name anyway.

### Erst in CI prüfbar
- The whole run: BIND start, the dynamic updates, the clients against the server, port 80 on the runner.
- Likely first-run issues to look at: the runner address from `hostname -I` (first address), certbot's credentials file warning (mode 600, read by root in the container), acme.sh's standalone mode (socat in the image).

## Part D – Step 15: docs, CHANGELOG, upgrade test

| Decision | Why | How to reverse |
|---|---|---|
| Upgrade test: `task upgrade:test` installs **the released v0.1.0** with `go install github.com/Der-Felix/MyOwnPKI/cmd/myownpki@v0.1.0` (pinned, checked against the Go checksum database) into `.tools/v0.1.0/`; v0.1.0 runs `init --demo --with-ca` and `backup`; this build restores, migrates (pki.db 0008–0010, system.db 0009) and issues by ACME with the CA of v0.1.0 (`openssl verify`) | A real v0.1.0 backup instead of a committed fixture (a fixture would hold a demo passphrase); `Taskfile.yml` `UPGRADE_FROM` names the release | Delete `internal/acme/upgrade_test.go` and the task |
| `testinstance.OpenExisting(t, dataDir, secretsFile)`: opens a data directory made elsewhere and first runs `store.Migrate` – like `server.Open` | The upgrade test needs the migrated instance with the test network of the ACME tests | – |
| CI: the upgrade test runs in the `check` job; `task acme:lego` (EAB, ARI, revoke) in the conformance job | Until now the lego tests ran only locally | Remove the two steps |
| Found: **v0.1 refuses unknown `MYOWNPKI_*` variables** – so `MYOWNPKI_ACME_*` stops a v0.1 binary. The test runs v0.1.0 without `MYOWNPKI_*`; OPERATIONS §9 says it for a downgrade | Strict variables catch typos – right; but a downgrade must remove the new ones | – |
| OPERATIONS.md: new **chapter 10 "ACME server"** at the end (sections 1–9 keep their numbers); title "v0.2"; ACME listener in the table of §1; v0.1 → v0.2 in §9 | The chapter the plan asked for; the numbers of 1–9 are referenced elsewhere | – |
| The proxy's own certificate is made from a **CSR on the proxy host** (key never leaves it); the server-generated key with *Export* is the alternative | The safer default; matches the UI's two ways | – |
| Every proxy example also serves the public listener on plain HTTP port 80, without a redirect to https | CRL and AIA URLs in the certificates are `http://`; a redirect breaks revocation checks on some clients | – |
| CHANGELOG: 0.2.0 under `[Unreleased]` with a short upgrade note, *Added/Changed/Security*, no date | Owner: date at the release (RELEASING.md) | – |
| README: status "v0.1 released; v0.2 (the ACME server) in preparation", a row of ACME screenshots, the docs table | The README must not claim ACME is still to come once this is merged | Your wording at the release |
| `docs/PLAN.md` unchanged | Its release plan already describes v0.2 as built; it has no status column | – |

Tests: `TestUpgradeFromV01` passes locally (Windows); mutation: without the migration it fails with "no such column acme_orders_per_hour" and "no such table domains".

### First stop (usage limit) – resolved in the continuation run
- Done in part B: step 10 (`26a0b93`) – revokeCert; lego registers, orders **and revokes**; `openssl verify -crl_check` refuses the revoked certificate; revocation with P-256, P-384, RSA-2048 and Ed25519 certificate keys; P-521 by the account (P-521 is not on the JWS allowlist).
- Not started: steps 11–15 (no stash – no unfinished code).
- Found for step 11, not fixed yet:
  - `fail()` sends a fixed `Retry-After: 30` on 429 instead of the limiter's real wait.
  - The limiter map is bounded only by dropping expired windows. Many fresh keys (IPv6 addresses, failing sub-names) can grow it. Plan: group IPv6 by /64 for new accounts, plus a hard cap that evicts entries.
  - "Limits in the tenant settings" needs a system.db migration (columns on `tenants`), `TenantSettings` in the OpenAPI spec, and the settings form.

# Night log – Phase 1, steps 14–20 and release

> Autonomous run, night of 2026-10-21 → 2026-10-22, branch `night/v0.1` (not merged, not pushed).
> Rules: one local commit per finished part, only when `task check` and `task generate:check` are
> green; never push, no tags, no releases. Approved new dependencies: go-webauthn/webauthn,
> GoReleaser, cosign, syft (CI tools, pinned SHA-256), distroless static-debian12:nonroot (by digest).
> No ADR changes; decisions taken alone are the reversible variant and listed below.
>
> Written in English (ADR-17). The owner's report is at the top; the step-by-step record follows.

## Report for the owner

**Result:** phase 1 is complete (steps 14–20), v0.1.0 is ready to release (part C), and the plans
for v0.2 and v0.3 are written (part D). Everything is on the local branch `night/v0.1` – **not
merged into main, not pushed, no tag, nothing published.** No stash is left over.

### Commits (22 plus the commit of this report, oldest first, all on `night/v0.1`)

| Part | Commits |
|---|---|
| A – step 14 | `1f5e215` root issues no leaves · `81a3164` locked name costs a hash · `48cd708` certificate counts · `7b947b2` shared test instance · `a0b1c6f` real UI · `69cd693` UI on the admin listener · `2fe352b` screenshot tool · `6514131` docs |
| 15 legacy import | `a3bbaf5` |
| 16 backup / restore | `80b1c7f` |
| 17 passkeys | `fc5f8ba` |
| 18 REST API part 2 | `36f0cfe` PKCS#12 export · `00a08be` revoke/renew/CSR · `973417c` CA management · `96e6c43` users/tokens/settings · `8a4c425` import jobs, audit, all 58 operations |
| 19 UI part 2 | `311088b` pages · `d4ab257` screenshots and notes |
| 20 wrap-up | `1bbd1d7` healthcheck, passphrase change/reset, end-to-end test · `bb20b65` operations guide |
| C release | `71aa10b` GoReleaser, Dockerfile, release workflow, CHANGELOG, README, RELEASING |
| D plans | `4c7e7ed` PHASE2.md, PHASE3.md |

Every commit was tested on its own (`go vet` + `go test ./...` in a separate worktree, with the
pki.sh fixture); `task check` and `task generate:check` were green before each commit.
`71aa10b` was reworded once right after it was made (a split into two commits failed and the docs
landed in it – the message now says so; content unchanged).

### Done – in short
- **15** `myownpki import legacy` (and archive upload in UI/API): serials, revocations (time and
  reason) and CRL numbers identical; CI builds the fixture with the real `pki.sh`.
- **16** `myownpki backup` / `backup verify` / `restore` with manifest, hashes, audit chains and the
  SAN index check.
- **17** passkeys as second factor and step-up (API; tested with a virtual authenticator).
- **18** all 58 API operations served and contract-tested, PKCS#12 export, "delete key after
  download", API tokens; vacuum: 0 warnings.
- **19** UI part 2: revoke, renew, export, CAs incl. the offline flow, legacy import, audit,
  presets, users, tenant settings, own account; screenshots light/dark.
- **20** `TestPkiShReplaced` (pki.sh → import → issue → revoke → `openssl verify -crl_check` →
  backup → restore → same CRL), `myownpki healthcheck`, `docs/OPERATIONS.md` with the passphrase
  warning, **new** `myownpki passphrase change` / `reset` (see decision 3 below).
- **C** `.goreleaser.yaml`, `deploy/docker/Dockerfile`, `.github/workflows/release.yml`,
  `deploy/docker-compose.yml`, CHANGELOG, README, `docs/RELEASING.md` (your checklist).
  `goreleaser check` and three snapshot builds: **archives byte-identical** between runs.
- **D** `docs/PHASE2.md` (ACME server) and `docs/PHASE3.md` (agent, monitoring) with open questions.

### Decisions for you to confirm (each reversible; details in the step tables below)

1. **Imported pki.sh root = offline root** by default (`--root-key online` imports its key). (15)
2. Import refuses as a whole: existing CA name/subject, Ed25519 CA, a bad signature. (15)
3. **New console command `myownpki passphrase change|reset`** – the recovery key had no command
   that used it, so a lost passphrase would have meant lost CA keys. (20)
4. **PKCS#12 written by our own code** (no module approved): AES-256 + PBKDF2-SHA256, 600,000
   iterations, password ≥ 12 characters; no legacy 3DES format. (18)
5. **API tokens never count as step-up** (no revoke, key download, CA management by token). (18)
6. `DELETE /users/{id}` disables; a refused API import answers 201 with a `failed` job; passkey
   removal is `POST …/remove`. (18)
7. Pages that show a secret once answer the POST directly with `no-store` (exception to PRG). (19)
8. **No passkey button in the UI** until esbuild or one small script is approved (ADR-04). (17)
9. Backups are not signed; integrity = SHA-256 + audit chains + signed checkpoints. (16)
10. `healthcheck` pins the served certificate file; `127.0.0.1` must stay in
    `admin.allowed_networks` when that is set. (20)
11. Release: only the **server binary** (agent/ctl are stubs); symbols kept; **no `latest`** image
    tag; image tag `0.1.0`; no buildx SBOM on the image (archive SBOMs instead). (C)
12. **Multi-arch image via Docker's containerd image store** on the runner instead of an extra
    BuildKit image (not approved). (C)
13. Tool versions: GoReleaser **2.18.2**, cosign **3.1.3**, syft **1.54.1**, distroless digest
    `afa5c872…` (all ≥ 2 weeks old, checksum files verified with Sigstore). (C)
14. CHANGELOG date **2026-10-22** – correct it if you tag later (RELEASING.md step 2). (C)
15. The compose file publishes the admin port on the host's **loopback only**. (C)

### What I could not check tonight
- **The release workflow** (only runs on a pushed tag) and **the container image** – there is no
  Docker on this machine. The first real tag is the test; RELEASING.md says how to undo a failed
  attempt before publishing.
- Passkeys in a real browser with a real authenticator; PKCS#12 import on Windows/macOS.
- `TestPkiShReplaced` runs locally only in Git Bash with `LEGACY_TEST_OPENSSL=/usr/bin/openssl`
  (green); in CI on Linux it always runs.

### Tomorrow in the browser (demo instance)

A test config `C:\pki-test\config.yaml` with one line: `data_dir: "C:/pki-test/data"`. Then, one
after the other (the second keeps running; the demo password and the TOTP secret are in
`C:\pki-test\data\init-demo-secrets.txt`), and open <https://127.0.0.1:9443/>:

```bash
go run ./cmd/myownpki init --demo --with-ca --ca-base-url http://pki.homelab.lan --config C:/pki-test/config.yaml
```

```bash
go run ./cmd/myownpki serve --config C:/pki-test/config.yaml
```

1. Sign in, unseal; dashboard and the navigation (Presets, Users and roles, Audit log, Legacy
   import, Tenant settings).
2. Issue a certificate, open it, **Renew**, **Export** as PKCS#12 (open it with your OS), tick
   "delete the key afterwards" once, **Revoke** – the step-up page should come first.
3. CAs: new intermediate; import an offline root and walk the **offline signing** page (CSR,
   extension file, upload the signed certificate, upload the root CRL).
4. **Legacy import**: upload a `.tar.gz` of a real `pki.sh` directory, read the report.
5. Users: create one (authenticator link shown once), change roles, disable; Tenant settings with
   a wrong country code; Audit log filters and "older".
6. My account: new API token (shown once), new recovery codes, the passkey list.
7. Dark theme on two pages; keyboard only through one form.
8. Read `docs/OPERATIONS.md` and `docs/RELEASING.md`, then the open questions in PHASE2/PHASE3.

## Step 14 – finish (review points 1–4)

### Done
- A root CA signs intermediate CAs and CRLs only; an end-entity request at a root is a
  `ca.DeniedError` ("a root CA only signs intermediate CAs and CRLs – issue from an
  intermediate"), audited as `denied`. The API answers 422 `policy-violation`; the wizard does
  not offer roots. Decision 81, `pki-rules.md` §3.
- "Issue certificate" in the menu and on the dashboard only when the user may issue at ≥1
  intermediate (decision 82). The server still refuses on its own.
- The instance audit carries the client address for sign-in success and failure (wrong
  password, unknown name, wrong code), step-up success and failure, unseal success and
  failure – `TestAuditHasTheAddress`. Decision 80 holds as written.
- CA list: column "Signed" (certificates and intermediate CAs), "–" for a root's maximum
  validity, readable key storage labels (decision 83). Only `authorities.png` regenerated.

### Tests
`task check` green; mutation checks (root rule, root in the wizard, menu for non-issuers,
sub-CA count) each made a test fail. Eight commits, each built and tested on its own.

### Not verifiable tonight
Nothing open for step 14; the owner's browser test of M1 is still to do.

## Step 15 – Legacy importer

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| Reader `internal/ca/legacy` (parses a `pki/` directory as an `fs.FS`, never executes or `source`s anything) + engine `ImportLegacy` (one pki.db transaction: all or nothing) + CLI `myownpki import legacy DIR [--dry-run]` | The legacy files are input from another tool: parsing stays apart from writing. An `fs.FS` lets step 18 feed an uploaded archive the same way | – |
| Source of truth for certificates: each CA's `index.txt` + `newcerts/<serial>.pem`; `issued/<name>/cert.meta` only adds preset and key | `issued/` holds only the newest certificate of a name; `newcerts/` holds every certificate a CA ever signed, so renewed and revoked ones are not lost | – |
| The **root is imported as an offline root** (certificate only, its CRL as `uploaded`); `--root-key online` imports its key encrypted instead | A root signs only intermediates and CRLs (decision 81); `legacy/pki.sh` stays the offline root tool (`pki ca-sign`, `pki crl --ca root`) | Default to `online` |
| Intermediates are imported **with their key** (encrypted in pki.db, generation 1, `legacy_urls = 1` when `AIA_BASE_URL` was set) | Without the key the CA can't issue or sign CRLs on the server | – |
| CRL numbers: `crlnumber` is **hex** (OpenSSL); `cas.crl_number` = the last number used (file − 1); the current `crl/ca.crl` is kept as evidence (`crls.source = uploaded`) after its signature is checked; an online CA signs its next CRL **in the import transaction** – so the numbering continues exactly where pki.sh stopped | Decision 62 (no CA without a CRL); CRL numbers must never go back (RFC 5280 §5.2.3) | – |
| Revocations keep time and reason; `keyTime`/`CAkeyTime` become the invalidity date; `certificateHold` → `unspecified` with the warning of decision 36; `CACompromise` on an **end-entity** certificate → `keyCompromise` with a warning (the table allows cACompromise only for CAs); `removeFromCRL` entries are reported and skipped | Keeps what relying parties see on the CRL; every change is named in the report and the audit entry | Extend the reasons (new migration) |
| keyCompromise / cACompromise put the key into `blocked_keys` (decision 29) | Same rule as a revocation on the server | – |
| Encrypted keys: passphrases from the legacy variables `PKI_CA_PASS_<NAME>`, `PKI_CA_PASS`, `PKI_KEY_PASS` (PBES2 decrypted with the standard library); a CA key that can't be decrypted **blocks** the import, a leaf key that can't is skipped with a warning (the certificate is imported) | Same names as pki.sh uses for automation; a CA without its key would be useless, a leaf without a key is still a valid record | Add a prompt per key |
| Self-signed leaves (`CA="selfsigned"`) are imported as `external` | They have no CA here, but are still certificates the operator watches | Skip them |
| Older certificates of the **same** CA key (pki.sh `renew-ca`, from `archive/` and `newcerts/`) go into a new immutable table `ca_certificate_history` (pki.db migration 0006); the newest certificate is generation 1 | PHASE1 note for step 15; they verify the same leaves and must stay as evidence | – |
| Refused as a whole: a CA name or subject that exists already, an Ed25519 CA (decision 22), a certificate whose signature doesn't verify with its CA, a CA key that doesn't match its certificate, index entries without their certificate file. Warnings only: unknown preset names, leaf keys that can't be read, stale CRLs, validity above the CA maximum (397 days) | The import is all or nothing; `--dry-run` lists every problem first | – |
| `max_validity_days` 397 for imported intermediates, `crl_days` from `pki.conf` `CRL_DAYS`; imported certificates are not checked against the maximum | Keeps the owner's default for new certificates; old ones are records, not requests | `--max-validity-days` later |
| Audit: one `ca.import_legacy` entry per CA (counts, warnings) and one `import.legacy` summary, all in the import transaction (outbox) | Thousands of certificates would flood the log; the counts and serials are in the database | One entry per certificate |
| The CLI needs the unseal passphrase (like `user reset-2fa`), `--dry-run` doesn't; API import jobs (`import_jobs`) come with step 18 | Keys are encrypted with the root key | – |

### Done
- `internal/ca/legacy`: reads `pki.conf`, every CA (`ca.meta`, `certs/ca.crt`, `private/ca.key`,
  `index.txt`, `newcerts/`, `crlnumber`, `crl/ca.crl`, `archive/`) and `issued/` (current and
  archived versions); PKCS#8 keys, PBES2-encrypted ones with the standard library only.
- `ca.ImportLegacy`: checks everything first (dry run = the same checks), then one pki.db
  transaction: CAs, generation 1, name constraints and EKU limit from the certificate, history of
  `renew-ca`, certificates with SANs, revocations, blocked keys, pki.sh's CRL as evidence, the next
  CRL of every online CA, audit entries.
- `myownpki import legacy DIR [--dry-run] [--base-url URL] [--root-key offline|online]`.
- `internal/ca/legacy/legacytest`: a pki.sh-shaped directory written in Go, for the CLI test on
  every platform.

### Tests
- `TestImportLegacyPkiSh` (pki.sh fixture: 2 intermediates, one with name constraints, three
  revocation reasons, a renewed certificate, `renew-ca`, an encrypted key, a self-signed
  certificate): serials, revocation time and reason per CA identical before/after; pki.sh's CRL
  kept with its number; the server's CRL has exactly the number of `crlnumber` and the same
  entries (serial, time, reason); `openssl verify -crl_check_all` refuses every revoked leaf and
  accepts the others; the imported intermediate issues with the new URLs (`openssl verify`); a
  second import is refused; audit entries.
- `TestImportLegacyRootOnline` (root key imported, other base URL, encrypted leaf key without
  passphrase), `TestImportLegacyRefuses` (missing `newcerts/` file: refused, nothing written,
  `denied` in the audit log), reader unit tests (index lines incl. keyTime/holdInstruction and
  UTCTime 1950, key/value files, PBES2 incl. wrong passphrase and iteration cap), CLI test.
- Mutation: the CRL number one too high made `TestImportLegacyPkiSh` and
  `TestImportLegacyRootOnline` fail.

### Not verifiable tonight
- A real, years-old pki.sh directory (RSA 4096 CAs with passphrases, many certificates): only the
  fixture. The owner's own `pki/` is the real test – first with `--dry-run`.
- The API/UI import (archive upload as an import job) is step 18/19.

## Step 16 – Backup and restore

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| A backup is a **new directory** (never overwritten, 0700, files 0600) with the database copies, `auth.key` when it lives in the data directory, and `manifest.json` written last | Inspectable with plain tools; the operator tars or encrypts it with whatever the site uses; a half-written backup has no manifest and is refused | One archive file (tar) |
| Each database is copied with **`VACUUM INTO`** on a read-only connection – works while the server runs | One consistent snapshot per file without stopping anything (SQLite docs) | Online backup API |
| Order: `system.db`, every tenant's `pki.db`, then **the audit databases last** (instance, then tenants) | PHASE1 "Backup consistency": the audit copies then hold at least every entry the others mark delivered; a redelivery after restore is deduplicated by `outbox_id` | – |
| Manifest: format version, time, MyOwnPKI version, per file path/kind/SHA-256/size/migration version, per audit log the head (`seq:hash`), entry count, newest checkpoint and checkpoint key fingerprint; tenants; whether `auth.key` is inside | What PHASE1 step 16 asks for; the heads let a restore prove that no log was cut off or rewritten | – |
| `myownpki backup DIR`, `myownpki backup verify DIR [--checkpoint-key FP]`, `myownpki restore DIR` | A backup that was never checked is a hope: `verify` runs every restore check without writing | – |
| Restore only into an **empty or missing** data directory; checks before writing anything: manifest, SHA-256 of every file, `PRAGMA integrity_check`, kind/scope, migration versions (newer than this binary → refused), every audit chain intact **and** ending exactly at the manifest head, checkpoint key (pinned with `--checkpoint-key`, else all the same and printed for comparison), and the **SAN index**: every certificate's names in `certificate_sans` match the names in its DER | A restore must not bring back a damaged or manipulated PKI; the SAN index is what search and (phase 2) ACME rely on | – |
| `system.backup` / `system.restore` entries in the instance audit log (the backup entry is written before the audit copy, so the backup contains it) | Who took and restored backups is audit-worthy | Leave out |
| The manifest is **not signed**; integrity rests on SHA-256 + audit chains + signed checkpoints, pinned by the fingerprint noted at init | Signing would need the passphrase at every backup (cron); the checkpoint signatures already need the root key to forge | Add an HMAC with a key from the root key |
| Prominent warning at every backup: keep the unseal passphrase and the recovery key apart from the backup | Owner decision 2 | – |
| A backup is refused when a live audit chain is broken or two logs use different checkpoint keys | A broken chain is an incident to look at first (`audit verify`); a restore would refuse such a backup anyway | Write it with a warning instead |

### Done
- `internal/backup`: `Create` (order system → tenant business databases → audit logs, `store.Snapshot` =
  `VACUUM INTO` on a connection without query_only), `Verify` and `Restore` (all checks on a work copy
  next to the data directory, then one rename), `system.backup`/`system.restore` audit entries.
- `ca.CheckSANIndex`: names in `certificate_sans` against the names in each certificate (DNS and
  e-mail domain without case, IPs canonical).
- `myownpki backup DIR`, `myownpki backup verify DIR [--checkpoint-key FP]`,
  `myownpki restore DIR [--checkpoint-key FP]`; the backup prints the passphrase warning, the audit
  heads, the checkpoint key and whether `auth.key` is inside.

### Tests
- `TestBackupRestoreRoundTrip`: pki.db and system.db tables identical after the restore, auth.key
  restored, chains verify, backup + restore entries, no second backup into the same directory, no
  restore into a used data directory.
- `TestBackupDuringWrites`: certificates are issued and delivered while the backup runs; after the
  restore every certificate has exactly one issue entry and a second delivery adds nothing.
  **Mutation:** audit logs copied first → 10 certificates without their audit entry, the test fails.
- `TestTamperedBackupRefused`: changed file, missing file, extra file, no manifest, path outside the
  backup, head moved, audit entry changed (hash fixed in the manifest), SAN index changed (hash
  fixed) – each refused, no data directory created; unknown manifest fields refused.
- CLI test: backup, verify, restore refused into the used directory, restore into a new one.

### Not verifiable tonight
- A backup of a server under real load on Linux (the concurrency test runs in-process).
- Restore across machines with different paths of `auth.key_file` (only the note is tested).

## Step 17 – Passkeys (WebAuthn)

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| `github.com/go-webauthn/webauthn` **v0.18.2** (2026-09-19, BSD-3); it brings fxamacker/cbor, go-webauthn/x, golang-jwt/jwt/v5, google/go-tpm, go-viper/mapstructure, tinylib/msgp, philhofer/fwd, x448/float16 (all MIT/BSD/Apache-2.0) | Approved for step 17; the newest version older than two weeks; the transitive modules come with it (listed in THIRD_PARTY.md) | – |
| A passkey is a **second factor** (after the password) and works for **step-up** – not passwordless sign-in | The spec (`/auth/webauthn/*`) and security.md say "second factor"; a password + passkey keeps one sign-in model | Discoverable login later (`BeginDiscoverableLogin`) |
| Passkeys only when `auth.passkey_origin` is set (e.g. `https://pki.homelab.lan:9443`); RP ID = its host name. Without it the endpoints answer 404 and sign-in offers TOTP only | WebAuthn binds every passkey to the RP ID: it must be the name users type, which the server can't guess. Browsers refuse WebAuthn on certificate errors – passkeys need the admin certificate from the own CA (or an operator certificate) | – |
| Registering a passkey: signed in, **fresh step-up and the current password** (decision 45, own authenticator); afterwards the credentials epoch rises (device cookies void) and other sessions end; audited `user.passkey_add` | The second factor is never added with the password alone | – |
| User verification **required**, attestation `none` (no vendor list), resident key preferred; at most 10 passkeys per user | UV makes the passkey itself two factors; attestation lists are for regulated sites, not a homelab PKI | – |
| Ceremony state (challenge) **in memory**, bound to the session that started it, 5 minutes, at most 10,000 at once | Like the throttle: a restart only loses ceremonies in progress | Store in system.db |
| A failed assertion counts like a wrong TOTP code (throttle, lockout, audit); a sign counter that goes backwards is refused as a cloned authenticator (audited `cloned`) | Same rules for every second factor | Warn only |
| `user reset-2fa` also removes the passkeys | The lost device may be the security key; reset means "only the new secret works" | Keep passkeys |
| **No passkey button in the browser UI yet**: it needs a script (`navigator.credentials`), ADR-04 wants TypeScript bundled with esbuild, which is not approved. API and service are complete and tested | No ADR change at night; question to the owner below | Approve esbuild (or one plain JS file) |
| Spec: `beginWebAuthnRegistration` takes `{"password"}`; new `GET /users/me/webauthn` and `POST /users/me/webauthn/{id}/remove` (list, remove with step-up + password) | Decision 45 needs the current password; a passkey must be removable | – |

### Done
- `internal/auth/passkey.go`: relying party (`NewPasskeys`), registration (step-up + current
  password, exclusion of known credentials, UV required), sign-in as second factor and step-up,
  list and remove; ceremonies in memory, bound to the session, used once; clone detection in Go
  and in the SQL update; reset-2fa removes passkeys.
- system.db migration 0007 `webauthn_credentials`; config `auth.passkey_origin`
  (`MYOWNPKI_AUTH_PASSKEY_ORIGIN`), checked by `config.PasskeyRPID` (https or http://localhost,
  host name, no path).
- API: `beginWebAuthnLogin`, `finishWebAuthnLogin`, `listWebAuthnCredentials`,
  `beginWebAuthnRegistration` (now with `{"password"}`), `finishWebAuthnRegistration` (201 with the
  passkey, `?name=`), `deleteWebAuthnCredential`; `login` lists `webauthn` in `methods` when the
  user has a passkey. The 405 fallback is now registered per method (a method-less pattern for
  `/users/me/webauthn/finish` clashed with `DELETE /users/me/webauthn/{id}` in Go's mux).
- `internal/auth/passkeytest`: virtual authenticator (ECDSA P-256, attestation none, own minimal
  CBOR encoder – no extra module).

### Tests
- `TestPasskeyRegistrationAndLogin`: registration, credentials epoch +1, other sessions end,
  sign-in with password + passkey (new session ID, device cookie), answer used twice refused,
  step-up with the passkey, list, remove (wrong password refused), audit entries.
- `TestPasskeyRefusals`: passkeys off, registration without the password, a passkey from another
  origin (phishing), no user verification, excluded authenticator, a user without passkeys, a
  counter that goes back (cloned), reset-2fa removes passkeys.
- Contract test: every new operation with success, no session and step-up cases, schema-checked.
- Mutations: clone detection off → test fails; a second allowed origin → the phishing case fails.
- `task vuln`: 0 vulnerabilities reached; the module list shows the known GO-2026-5932
  (`x/crypto/openpgp`, not used, blocked by depguard).

### Not verifiable tonight
- A real browser and a real authenticator (Windows Hello, a YubiKey, a phone): no UI button yet,
  and WebAuthn needs the admin certificate trusted by the browser.
- **My own mistake, repaired at once:** a diagnostic command line ended with `git checkout HEAD~0;
  git stash`, which put the uncommitted step-17 work into a stash and detached HEAD. `git stash pop`
  and `git switch night/v0.1` restored everything (same files, same branch tip); nothing was lost.

## Step 18 – REST API, part 2

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| **PKCS#12 written by our own code** (`internal/pkcs12`, ~250 lines): PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) for the key, certificates unencrypted, MAC HMAC-SHA256 with the RFC 7292 KDF, 600,000 PBKDF2 iterations; a password of at least 12 characters is required | No PKCS#12 module is approved tonight; this is what OpenSSL 3 writes by default and what Windows 10 1709+, macOS and Java import. Checked with `openssl pkcs12` in the tests | Approve `software.sslmate.com/src/go-pkcs12` (BSD-3) and swap |
| **No "legacy" PKCS#12 (3DES/RC2-SHA1)** | Weak by today's rules; only very old Windows/Android need it | Add a `pkcs12-legacy` format |
| Export formats: `pkcs8-pem` (as before), `pkcs12` (+ `password`), `combined-pem` (certificate, chain, key – HAProxy); option `delete_key_after_download` destroys the stored key **after** the file was built and audited | Owner 2026-10-17; the export is the last chance to get the key | – |
| Deleting a key: pki.db migration 0007 adds `keys.destroyed_at`; the DEK and the ciphertext are overwritten (one zero byte each, `PRAGMA secure_delete` on), the row stays (certificates point to it and are immutable). Older backups still hold the encrypted key – the answer says so | The schema's CHECK needs non-NULL values; a table rebuild with foreign keys isn't worth it | Table rebuild with NULLs |
| `deleteUser` **disables** the user (users are never deleted, decision 47); the spec says so | The audit log keeps user IDs | – |
| `createUser` returns the otpauth URI and the recovery codes **once** to the instance admin, who hands them over (as `init --otpauth-file`); the first sign-in confirms the secret | The second factor is fixed at creation (security.md) | – |
| Own TOTP change: `POST /users/me/totp` takes `{"password"}`, `/users/me/totp/confirm` answers 204; new `POST /users/me/recovery-codes` `{"password"}` → new codes | Decision 45 (own authenticator needs the current password); the spec drafted confirm as returning codes, but the recovery codes don't change with the authenticator | – |
| **API tokens**: system.db migration 0008 `api_tokens`; `mop_` + 32 random bytes (Base32), only the SHA-256 stored, shown once; expiry required (≤ 1 year); scope = roles that the owner has (never more), checked at every request; `Authorization: Bearer`; creating one needs step-up; **a token never satisfies step-up** (no revoke, key download, CA management by token); last use recorded at most once a minute; a disabled user's tokens stop working | security.md "API tokens: random, shown once, stored hashed, scoped, expiring"; step-up means a human with a second factor | Allow step-up operations for tokens with a separate scope |
| CA management, new in the spec: `POST /cas/{id}/renew`, `POST /cas/{id}/retire`, `PATCH /cas/{id}` (CRL days, max. validity), `POST /cas/{id}/revoke`, `PUT /cas/{id}/crl` (offline root CRL upload); `GET /cas/{id}/csr` answers the offline bundle as JSON (CSR, extension file, days, digest, serial, instructions) | PHASE1 step 18 lists them; the engine has all of them since step 8/9 | – |
| Legacy import over the API: `POST /imports/legacy` takes a `.tar.gz` of the pki.sh directory (≤ 64 MiB, ≤ 100,000 entries, regular files only, no `..`, no absolute paths), runs the import **synchronously** (dry run with `?dry_run=true`) and records it in `import_jobs` (pki.db 0007); `GET /imports/{id}` returns the report | Background jobs need a job runner; a homelab PKI imports in seconds | Run it in the job runner later |
| `POST /imports/external-certificate`: a PEM certificate of another CA, stored as `external` for expiry monitoring (tenant admin) | Already in the spec draft | – |
| Audit: `GET /audit` (tenant log, operator and up – the viewer has no audit access, decision 46; filter by action, result, time; cursor = seq), `POST /audit/verify` (tenant and, for instance admins, instance log; optional checkpoint key pin) | – | – |
| Tenant settings: `GET/PUT /settings` – `allow_server_keygen` and subject defaults (O, OU, L, ST, C) in system.db `tenant_settings` (migration 0009); the API and the UI fill missing subject fields of a request from them | PHASE1 note "Subject defaults per tenant (step 19)" | – |
| `inspectCSR` parses an uploaded CSR and shows subject, names, key, signature check and the problems the policy would raise for a preset – nothing is stored | The wizard (step 19) and scripts want the answer before issuing | – |
| vacuum is not installed on this machine: the spec is checked by `api/openapi_test.go` and the contract tests locally; vacuum runs in CI | PHASE1 note (step 13) | Install vacuum locally |

### Done
- **58 operations**, every one served and every one in the contract run (success, no session,
  low role, no read access and step-up where the spec asks); `TestEverySpecOperationIsServed`
  checks spec ↔ route table in both directions.
- Export (PKCS#12, PKCS#8 PEM, combined PEM, delete after download) – commit `36f0cfe`.
- Certificates: revoke, renew, CSR inspection, external certificates – `00a08be`.
- CAs: create, import offline root, offline bundle and upload, renew, retire, limits, revoke,
  CRL download, sign, upload – `973417c`.
- Users, own account, API tokens (system.db 0008), tenant settings – `96e6c43`.
- Legacy import over the API (base64 `.tar.gz`, unpacked in memory, recorded as an import job),
  audit list (filters, cursor) and chain verification.
- Changes against the design table above, taken while building:
  - A refused API import answers **201 with a job of status `failed`** (all problems listed),
    not 422 – the spec rules want every error answer to be a shared problem response; 422 stays
    for an unreadable archive.
  - Removing a passkey is `POST /users/me/webauthn/{id}/remove` (not `DELETE` with a body –
    vacuum's `no-request-body`); the body carries the current password.
  - The 405 fallback is registered per method (a method-less pattern clashed in Go's mux).
  - A revocation of a certificate the caller may not read answers 404 (decision 64), as reads do.
  - Import jobs: without a tenant-wide role 404, with a too low one 403.
- vacuum 0.30.6 (the CI version) run locally with `go run`: 0 errors, 0 warnings, 8 infos
  (`description-duplication`). Unused components removed.

### Tests
- Contract run over all 58 operations, including the offline flow with a root signed in Go, a
  passkey ceremony, a TOTP change confirmed with the new secret, a token, an archive import.
- `TestExportFormatsAndKeyDeletion` (OpenSSL opens the PKCS#12, key gone afterwards, 409),
  `TestAPITokens` (issues with its roles, no step-up, no sign-in, no token creation, revoked →
  401), PKCS#12 tests with OpenSSL (ECDSA, RSA, Unicode password, wrong password), archive tests
  (same result as the directory, `..`, links and absolute paths refused).
- Mutations: wrong PBKDF2 PRF OID, wrong PKCS#12 KDF ID for the MAC – both caught by OpenSSL.

### Not verifiable tonight
- Import of a PKCS#12 file on real Windows / macOS / Java (OpenSSL 3 accepts it; the format is
  what OpenSSL 3 writes by default).
- A large legacy archive over the API (memory use with ~90 MB of JSON).

## Step 19 – Web UI, part 2

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| Three generic page templates (`pages/admin`: a form page, a table page, a detail page with sections and inline command forms) instead of one hand-made page per function | Many small admin pages in one calm, consistent look (frontend.md "calm and plain"); the existing CSS classes only; less templ code to review | Hand-made pages where a function needs more |
| Still no htmx and no JavaScript: plain forms with PRG (decision 74) | Same rules as step 14 | – |
| **Exceptions to PRG** – the answer to the POST shows a secret once and is `Cache-Control: no-store`: a new user's otpauth link and recovery codes, the own new TOTP secret, new recovery codes, a new API token, the key export file | A secret must not travel in a cookie or a URL, and must not be shown twice | Store them encrypted for one GET |
| Certificate detail: Revoke (reason, confirmation, step-up), Renew (new key or new CSR), Export (PKCS#12 with password / PEM / combined, "delete the key afterwards") | Steps 18/19 | – |
| CAs: new CA (root or intermediate), import offline root, offline signing page (CSR, extension file, instructions, upload), renew, retire, revoke, limits, sign CRL, upload root CRL | Step 19 list | – |
| Administration: legacy import (archive upload, report page), audit log (filters, pages; operators and up), presets (read-only), users and roles (instance admins), tenant settings (admins), own account (password, authenticator, recovery codes, API tokens, passkeys list) | Step 19 list; the own account is where tokens and passkeys live | – |
| Navigation: the new entries appear only for users who may use them (decision 82) | No dead links | – |
| Screenshots: new light pages (users, audit log, legacy import report, CA offline signing) plus dark variants of two; the same neutral demo instance | Owner's step 14 rule | – |

### Done
- `internal/web/pages/admin` (form, table, detail templates) and the pages: certificate revoke /
  renew / export, CA new / import offline root / offline signing / manage (limits, CRL, root CRL
  upload, renew, retire, revoke), presets, users and roles, tenant settings, audit log (filters,
  older pages), legacy import with report, My account (password, authenticator, recovery codes,
  API tokens, passkeys list and removal) – commit `311088b`.
- Navigation: Presets, Users and roles, Audit log, Legacy import, Tenant settings – shown only to
  users who may use them; "My account" in the user menu. The prototype (`serve --dev`) shows the
  new entries disabled ("real UI").
- Screenshots of the neutral demo instance (O=Homelab, homelab.example, 192.0.2.10), all
  regenerated because the navigation changed: new `users`, `audit-log`, `offline-signing`,
  `legacy-import`, and dark `certificate-detail-dark`, `users-dark` next to `dashboard-dark`.

### Tests
- Every new page is in the rendered-page set: no inline styles, scripts, event handlers or icons.
- `TestCertificateActions` (renew → 303 to the successor; PKCS#12 export opened by OpenSSL; key
  gone after "delete"; revoke needs the confirmation, 303, Revoke no longer offered; without a
  fresh second factor → step-up page), `TestViewerSeesNoCommands`, `TestCAOfflineFlowInTheUI`
  (new intermediate, limits, CRL, retire; offline root import, pending intermediate, the offline
  page with CSR and extension file, the signed certificate installed, root CRL uploaded),
  `TestAdministrationPages` (settings incl. a refused country, user creation shown once with
  `no-store`, role, disable, API token shown once, audit page, legacy import upload with report).

### Not verifiable tonight
- The pages in a real browser beyond the screenshots (keyboard use, screen reader).
- Adding a passkey in the UI (needs a script, see step 17).

## Step 20 – Phase 1 wrap-up: end-to-end test, operations guide, healthcheck

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| End-to-end test in `cmd/myownpki` (`TestPkiShReplaced`), one process: the real `legacy/pki.sh` builds the PKI, then the console commands (`init --demo`, `import legacy`, `backup`, `backup verify`, `restore`, `audit verify`) and a real server with both listeners; issue and revoke through the REST API like a browser (cookie, CSRF, TOTP); the CRL fetched from the URLs **inside** the old and the new certificates and checked with `openssl verify -crl_check` | Tests what an admin does, not the engine alone; a second process would need killing by PID and free ports | Run the built binary as a subprocess |
| The pki.sh runner moves from the ca tests to `legacytest.PkiSh` / `NeedPkiSh` (same skip rules: Linux, or Git Bash with `LEGACY_TEST_OPENSSL`) | Two packages need it now | – |
| `init --demo` in the test (not `--stdin`) | `--stdin` confirms TOTP at the first sign-in – another API flow; the demo file has every secret | Use `--stdin` and the first-login flow |
| **`myownpki healthcheck`**: reads the config, asks `https://<admin listen>/healthz` on loopback (0.0.0.0/:: → 127.0.0.1/::1), **pins the exact certificate file** the server serves (bootstrap or `admin.tls_cert_file`) instead of CA verification, no proxy, 5 s timeout; exit 0 / 1 | A distroless image has no curl; skipping TLS checks would talk to anything on the port; the bootstrap certificate is self-signed | Verify against a CA bundle instead |
| A certificate file changed without a restart makes the check fail ("serves another certificate") | The server serves something else than what is on disk – worth an alarm | Accept both |
| **New: `myownpki passphrase change` / `passphrase reset`** (console). The key ring had `ChangePassphrase` / `ResetPassphrase` since step 6, PLAN §5 promises "passphrase reset with the recovery key", but no command used them – a lost passphrase would have meant lost CA keys despite the recovery key. `change` unseals in its own process, changes, seals (all audited); `reset` works sealed. Two lines on stdin without a terminal | The operations guide's passphrase warning needs a way out that works | Remove the command; rotating the recovery key stays open |
| Operations guide `docs/OPERATIONS.md`: passphrase warning first, secrets table, install, init, running, healthcheck, moving from pki.sh, backup/restore, passphrase, emergencies, upgrades | Step 20 list | – |
| `deploy/config.example.yaml` gets `auth.passkey_origin` (missing since step 17) and a test that every setting is in the example | Found while writing the guide | – |

### Done
- `TestPkiShReplaced`: pki.sh (root, `server-ca`, two leaves, one revoked as *superseded*, CRL) →
  `init --demo` → `import legacy` → server → `healthcheck` ok → API sign-in, issue
  `new.homelab.example`, revoke as *keyCompromise* → the CRL from the legacy URL of the old
  certificate and from the new URL are the same file; it lists both serials with their reasons,
  its number continues the pki.sh numbering; `openssl verify -crl_check` says OK for the imported
  valid leaf and "certificate revoked" for the new one; `openssl crl -text` shows both reasons →
  `backup` while the server runs → `backup verify` → `restore` into a new data directory →
  `audit verify` → the restored (sealed) server serves the identical CRL and `healthcheck` is ok.
- `myownpki healthcheck` (`cmd/myownpki/healthcheck.go`, `server.AdminCertFile`).
- `myownpki passphrase change|reset` (`cmd/myownpki/passphrase.go`).
- `docs/OPERATIONS.md`; `deploy/config.example.yaml` with `passkey_origin`.
- PLAN.md: status, roadmap row, §14 night-run rows for steps 18–20; PHASE1 row 20.

### Tests
- `TestPkiShReplaced` (Git Bash with `LEGACY_TEST_OPENSSL=/usr/bin/openssl`: green in 18 s; CI on
  Linux runs it, skipped elsewhere like the step 15 fixture).
- `TestHealthcheck` (TLS stand-in: missing file, ok, wrong answer, nothing listening),
  `TestHealthcheckCommand`, `TestLocalAddr`.
- `TestPassphraseCommands` (wrong proof, weak passphrase, one line only, change, reset with
  another and with the right recovery key; both audited).
- `TestExampleFileHasEveryKey`.
- Mutation: the certificate pin of the healthcheck disabled → `TestPkiShReplaced` fails
  ("healthcheck against another certificate: <nil>").

### Not verifiable tonight
- `healthcheck` inside the real container (step C builds the image; Docker isn't on this machine
  – see the release part).
- The operations guide followed by someone else on a fresh machine.

## Part C – Release pipeline for v0.1.0

### Design (decided before building)
| Decision | Why | How to reverse |
|---|---|---|
| Tool versions (two-week rule, cut-off 2026-10-07): **GoReleaser v2.18.2** (2026-09-17; v2.18.3 is from 2026-10-09), **cosign v3.1.3** (2026-08-06), **syft v1.54.1** (2026-10-06). SHA-256 from each project's `checksums.txt`, whose Sigstore signature was verified with cosign tonight (GoReleaser and syft: their release workflow identities; cosign: `keyless@projectsigstore.iam.gserviceaccount.com`) | Same pinning as golangci-lint; the checksum files themselves are signed | Newer versions after two weeks |
| **distroless `static-debian12:nonroot` pinned by digest `sha256:afa5c872…7f7ab`** (the index of the `nonroot` tag, uploaded 2026-08-21) | Owner approval; two months old | New digest from `gcr.io/v2/distroless/static-debian12/manifests/nonroot` |
| Only the server binary `myownpki` is released (archives and image); `myownpki-agent` and `myownpki-ctl` only print `--version` so far | A release must not ship stubs that look like features | Add them to `builds` when they do something |
| Targets linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64; `CGO_ENABLED=0`, `-trimpath`, `mod_timestamp` and the version date from the **commit** time; archive files get the commit time too | Reproducible: the same commit gives byte-identical archives (checked locally with two snapshot runs) | – |
| Symbols are **not** stripped (no `-s -w`) | `govulncheck -mode=binary` and stack traces work on release binaries; the size is secondary | Add `-s -w` |
| Archives: `.tar.gz`, `.zip` for Windows, with LICENSE, README, CHANGELOG, THIRD_PARTY, docs/OPERATIONS.md, deploy/config.example.yaml | What an admin needs offline | – |
| `checksums.txt` (SHA-256 of archives and SBOMs) signed keyless with cosign → `checksums.txt.sigstore.json`; archives are not signed one by one | GoReleaser's documented pattern; one signature covers everything, `sha256sum --check` does the rest | Sign each archive |
| SBOM: SPDX JSON per archive with syft, **without `--enrich`** | `--enrich` looks up data on the network during the build – not reproducible | Add it back |
| Image `ghcr.io/der-felix/myownpki:<version>` (e.g. `0.1.0`), linux/amd64 + linux/arm64, signed keyless with cosign; **no `latest` tag**, no buildx SBOM attestation | `latest` before 1.0 invites accidental upgrades; the buildx SBOM needs an extra scanner image (not approved) | Add `latest` / `sbom: true` |
| Multi-platform build without an extra BuildKit image: the release job switches Docker to the **containerd image store** and restarts it; the Dockerfile has no `RUN`, so no QEMU either | The documented `docker buildx create` pulls an unpinned `moby/buildkit` image that would hold the registry credentials | Pin a BuildKit image by digest and use `buildx create` |
| Dockerfile: the pinned base, the binary in `/usr/local/bin`, the data directory `/var/lib/myownpki` created empty and owned by `nonroot` (copied from the base image's empty `/home/nonroot`, no `RUN`), `VOLUME`, `EXPOSE 9443 8080`, `HEALTHCHECK myownpki healthcheck`, `CMD ["serve"]`; the config is mounted at `/etc/myownpki/config.yaml` | Owner: only the binary, a volume, a healthcheck; a new named volume takes over the directory's owner, so the non-root server can write | – |
| `.github/workflows/release.yml`: only on pushed `v*` tags; `permissions: {}` at the top, `contents: write`, `packages: write`, `id-token: write` only on the job; actions pinned by SHA; tests before the build; release notes = the CHANGELOG section of the tag; GoReleaser makes a **draft** release | Owner list; a draft can be checked and deleted before anyone sees it | – |
| The image is pushed already when the draft is created (GoReleaser can't hold it back); GHCR makes a new package **private** – the owner sets it public after checking (RELEASING.md) | Nothing is public before the owner looks at it | – |
| `ci.yml`: only `cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}` | Owner: every main run finishes | – |
| Taskfile: `release:check` (goreleaser check) and `release:snapshot` (snapshot without signing and without the image – no Docker here) | Local checks without remembering flags | – |
| `deploy/docker-compose.yml` with `deploy/docker/config.yaml` (admin on `0.0.0.0:9443` in the container, published on the host's loopback only) | A single server; remote admin access is a deliberate change, as with the binary | Publish on all host addresses |
| CHANGELOG.md (Keep a Changelog) with the date of the night; RELEASING.md tells the owner to correct it if the tag is pushed later | – | – |

### Done
- `.goreleaser.yaml`, `deploy/docker/Dockerfile`, `deploy/docker/config.yaml`,
  `deploy/docker-compose.yml`, `.github/workflows/release.yml`; `ci.yml` cancels in-progress runs
  only outside main; Taskfile `release:check` and `release:snapshot`.
- `CHANGELOG.md` (Keep a Changelog, 0.1.0 dated 2026-10-22), README for v0.1 (status, install
  from a release and with Docker, `cosign verify-blob` / `cosign verify`, new screenshots in the
  table), `docs/RELEASING.md` (owner checklist incl. GitHub settings), THIRD_PARTY.md and PLAN §13
  / §14 rows for the tools and the base image.
- Changes against the design table, taken while building:
  - `GOTOOLCHAIN=local` is **not** in `.goreleaser.yaml`: locally it built with the installed
    Go 1.27.0 instead of the pinned 1.27.2 (seen in `--version` of the snapshot); now the local
    build fetches go1.27.2 like `task`, and release.yml sets `GOTOOLCHAIN=local` with 1.27.2.
  - Archive files get mode 0644 (the binary 0755) explicitly: a Windows checkout gave 0666.
  - The release notes leave out the link definitions at the end of CHANGELOG.md; the links in
    the 0.1.0 section are absolute (relative links don't work on the release page).

### Tests
- `goreleaser check` (2.18.2): valid, no deprecations.
- `goreleaser release --snapshot --clean --skip=sign,docker` three times: archives for all five
  targets with binary, LICENSE, README, CHANGELOG, THIRD_PARTY, OPERATIONS and the example config;
  `--version` says `v0.0.1-snapshot (commit …, 2026-10-21T06:51:45Z, go1.27.2, windows/amd64)`;
  build info `CGO_ENABLED=0`, `-trimpath=true`. **Runs 2 and 3: every archive byte-identical.**
  The SBOMs differ only in `created` and `documentNamespace` – SPDX wants both unique per
  document, and syft ignores `SOURCE_DATE_EPOCH`; their content is the same.
- actionlint 1.7.12 (the CI version, SHA-256 checked) with ShellCheck 0.11.0 on both workflows:
  no findings. The release-notes `awk` tried on CHANGELOG.md (section found; a missing version
  gives nothing, so the job stops).
- `TestDockerFiles`: the container config is valid; the Dockerfile has the ports, the volume, the
  healthcheck and one pinned base image for both stages.
- Checked by hand in the base image (layers downloaded from gcr.io): `/home/nonroot` is empty,
  0700, owned by 65532 – the source of the data directory; the image config has `User 65532`.

### Not verifiable tonight
- **The release workflow itself** (it runs only on a pushed tag – the owner's step), in
  particular: Docker's switch to the containerd image store on the runner, the multi-platform
  push to GHCR, the keyless signatures (need GitHub's OIDC token), the draft release.
- **The container image**: no Docker on this machine – neither the build, nor that a new named
  volume takes over the owner of `/var/lib/myownpki`, nor `HEALTHCHECK` with
  `myownpki healthcheck`, nor `deploy/docker-compose.yml` (`read_only`, `cap_drop`).
- `cosign verify-blob` against our own release (the commands are the ones that verified
  GoReleaser's, syft's and cosign's own checksum files tonight).

## Part D – Design documents for v0.2 and v0.3

### Done
- `docs/PHASE2.md` (v0.2): data model (domains, ACME accounts, EAB keys, orders, authorizations,
  challenges, approved names; nonces and rate limits in memory), approval levels, configuration
  (resolver, ACME base URL, a TLS port for ACME), 15 steps with test criteria, dependencies to ask
  for, 9 open questions.
- `docs/PHASE3.md` (v0.3): data model (agents, join tokens, deployments, heartbeats, endpoints,
  alerts, notification channels), the agent configuration with its hook allowlist, 14 steps with
  test criteria, dependencies to ask for, 9 open questions.
- No code, no ADR change. Both documents keep ADR-19 (one issuance path), ADR-10/11 and the SSRF
  and agent-trust rules of security.md as the frame.

### Not verifiable tonight
- Everything in them is a proposal; the open questions (above all PHASE2 Q1 "HTTPS for ACME" and
  PHASE3 Q2/Q3 "Connect-RPC" and "lego") decide the shape.

# Night log – Phase 0, steps 4–8

> Autonomous run, night of 2026-10-12 → 2026-10-13. Rules: local commits only, never push,
> only approved dependencies (templ, govulncheck, go.yaml.in/yaml/v3), no ADR changes,
> reversible choices documented here.
>
> Written in English (ADR-17). The decisions and their reasons were carried over to
> docs/PLAN.md §13–§14; this file keeps the step-by-step record and how to reverse each choice.

## Step 4 – CI (GitHub Actions) and Dependabot

### Done
- `.github/workflows/ci.yml` with jobs:
  - `check`: `task check` (tools, fmt, lint, test, build) + `task generate:check`
  - `race`: `task test:race` (CGO only here – the race detector needs a C compiler)
  - `test-os`: `go test ./...` natively on `windows-2025` and `macos-15`
  - `cross`: `task cross` (linux/amd64, linux/arm64, darwin/arm64, windows/amd64, freebsd/amd64)
  - `vuln`: `task vuln` – on every push/PR **and daily at 04:17 UTC** (all other jobs skip the schedule)
  - `shellcheck`: legacy sources + the compiled standalone script
- `.github/actions/setup/action.yml`: shared setup (Go, Task, optional golangci-lint and sqlc)
- `.github/dependabot.yml`: weekly grouped PRs for Go modules and GitHub Actions
- `Taskfile.yml`: `SQLC_VERSION` 1.31.1; `tools:check` verifies sqlc once `sqlc.yaml` exists

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| Third-party actions pinned to **commit SHA** (checkout v7.0.1, setup-go v7.0.0), not tags | A tag can be moved to malicious code after the fact; a SHA cannot. For a CA's build pipeline that matters | Replace SHA with tag |
| Only GitHub's own actions; golangci-lint, ShellCheck and sqlc downloaded with **pinned SHA-256** instead of their marketplace actions | Fewer third parties with code execution in CI; checksum detects a swapped release file | Use `golangci/golangci-lint-action` etc. |
| `GOTOOLCHAIN=local` in CI | CI must use exactly the Go installed by setup-go; `tools:check` then proves it is 1.27.2 | Remove the env var |
| `permissions: contents: read`, `persist-credentials: false` | Least privilege: a compromised step cannot push or read a token from `.git/config` | – |
| Runner images pinned (`ubuntu-24.04`, `windows-2025`, `macos-15`) instead of `*-latest` | "latest" changes underneath us; failures should come from our changes | Use `*-latest` |
| ShellCheck at **severity error**, not warning | Legacy currently has 25 warnings (see below); CI would be red from day one. Errors are still blocked | Raise to `--severity=warning` after fixing |
| sqlc installed in CI only if `sqlc.yaml` exists | sqlc is not used in phase 0; owner installs it in phase 1 | – |
| No `actionlint` | Not an approved dependency/tool. Instead YAML was parsed with go.yaml.in/yaml/v3 (scratch program, not in the repo) and every `uses:` was checked for SHA pinning | Proposal: add actionlint as a pinned CI tool |

### Not verifiable tonight
The workflow has **never run** – it only runs after a push, which is the owner's decision.
Locally simulated: `task check`, the ShellCheck command (exit 0), YAML parsing, SHA pinning.
Risk: small typos in shell steps of the workflow would only show on the first run.

### Findings in legacy (not changed)
ShellCheck 0.11.0 on the modular sources: 71× SC2034 (variables set in one file and used in
another – false positives of the modular layout), 22× SC2207 (completions), notes only otherwise.
On the compiled standalone script only 3 warnings remain:
- `C_MAG`, `C_CYN` in `lib/core.sh` – colour constants never used
- `rootder` in `lib/export.sh:148/158` – assigned, never used (harmless leftover; possibly the
  guide was meant to mention the DER root `publish/root.crt`)

## Step 5 – Presets as YAML, loader, tests

### Done
- `presets/*.yaml` – the 12 legacy presets, each with comments explaining *why* (key usages, SANs,
  validity); `presets/README.md` describes the format; `presets/presets.go` embeds the files.
- `internal/ca/preset` – strict loader (`Builtin()`, `Load(fs)`, `Parse()`), resolved accessors
  `KeyUsageFor(alg)`, `ExtKeyUsages()`, `ExtKeyUsageOIDs()`.
- Tests:
  - `TestLegacyParity` parses `legacy/lib/presets.sh` and compares every field of every preset
    (mutation-tested: changing one YAML value makes it fail).
  - `TestParseRejects` – 28 broken presets, each must be rejected with a specific message.
  - `TestPresetCertificates` – 12 presets × 3 key types (RSA 2048, ECDSA P-256, Ed25519): issue a
    throw-away certificate, parse it with crypto/x509, and run `openssl verify -purpose <purpose>`.
  - `TestPresetCertificatesWrongPurpose` – 6 negative checks (e.g. a client certificate must fail
    `sslserver`), so the OpenSSL check is not a rubber stamp.
- New dependency: `go.yaml.in/yaml/v3 v3.0.5` (approved; MIT/Apache-2.0). govulncheck: clean.

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| YAML schema with `key_usage.rsa` / `key_usage.other` | Legacy only knew RSA and Ed25519 (`KU_RSA`, `KU_ED`); pki-rules.md says the non-RSA column applies to ECDSA too | Rename fields |
| `required_any_of` instead of legacy `"dns\|ip"` string | A list is unambiguous and validates per element | – |
| EKUs by name; dotted OID only for EKUs without a name (`1.3.6.1.5.5.8.2.2`) | One spelling per usage → duplicates detectable | Allow OIDs for known EKUs |
| `ipsecIKE` as a name for 1.3.6.1.5.5.7.3.17 | Readable; crypto/x509 has no constant, so it goes into `UnknownExtKeyUsage` | Write the OID |
| `keyAgreement`, `encipherOnly`, `decipherOnly` rejected | `other` covers Ed25519, which can't do key agreement; no legacy preset uses them | Split `other` into `ecdsa`/`ed25519` and allow it for ECDSA |
| Cross-field rules (serverAuth ⇒ DNS/IP SAN, emailProtection ⇒ e-mail SAN, timeStamping only + critical, ocsp_no_check ⇒ OCSPSigning, openssl_purpose ⇔ EKU, customizable ⇒ family custom) | Each encodes an RFC/CA-B Forum requirement; all 12 legacy presets already satisfy them | Remove the rule in `validate.go` |
| `validity_days` 1–3650 | Sanity bound only; real lifetime policy is phase 1/2 | Change constants |
| Preset files limited to 64 KiB, one YAML document per file | Cheap protection once presets can be uploaded | – |
| No `sort_order` field, `Names()` sorted alphabetically | The UI order is a UI decision for phase 1 | Add a field |

### Findings for phase 1 (important)
- **crypto/x509 always writes extendedKeyUsage as non-critical.** The `timestamp` preset needs a
  critical EKU (RFC 3161), so the CA engine must build that extension by hand – exactly what the test
  helper `issue()` in `x509_test.go` does (`ExtKeyUsageOIDs()` + `asn1.Marshal`). Same for
  `id-pkix-ocsp-nocheck` (via `ExtraExtensions`).
- crypto/x509 always marks keyUsage and basicConstraints critical – matches pki-rules.md.

## Step 6 – OpenAPI draft for phase 1

### Done
- `api/openapi.yaml` (OpenAPI 3.1.0, 49 operations): system (health, status, seal/unseal), auth
  (login, TOTP, WebAuthn, step-up, session, logout), users (CRUD, roles, own password, TOTP and
  passkey enrollment), API tokens, presets, CAs (create root/intermediate, offline-signing flow,
  import, certificate/CSR/CRL download, CRL regeneration), certificates (list with filters, issue
  from CSR or server-generated key, download public parts, export with key, revoke, renew, CSR
  inspection), imports (legacy pki/ archive as background job, external certificates), audit log
  (list, chain verification).
- `api/api.go` embeds the spec (`api.Spec`) for serving it later.
- `api/openapi_test.go` – structural checks without a new dependency: valid YAML, version 3.1.x,
  every local `$ref` resolves, operationIds unique and lowerCamelCase, declared tags, every operation
  has `x-required-role`, `none` ⇔ `security: []`, authenticated ops document 401, step-up ops
  document 403, request bodies document 400, all error responses are shared problem+json responses,
  no password/passphrase query parameters, every `format: password` property is `writeOnly`.
  Mutation-tested (missing role, broken $ref, password query parameter are all caught).

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| Problem types as URNs `urn:myownpki:problem:<name>` | RFC 9457 allows any URI; a URL would need a domain, and the project domain is still an open point (PLAN §12) | Switch to `https://<domain>/problems/<name>` |
| `x-required-role` and `x-step-up` vendor extensions on every operation | Makes RBAC and step-up reviewable in the spec and testable; code generation can read them later | Remove the extensions |
| `/health` unauthenticated, returns only `{"status":"ok"}`; version/seal state only via authenticated `/system/status` | Load balancers need a health check; an anonymous endpoint must not reveal version info | – |
| Export with private key is `POST /certificates/{id}/export` with password in the body | Passwords in URLs end up in proxy logs and browser history | – |
| Issuance with CSR **or** server-generated key (`oneOf`) | Phase 1 replaces pki.sh, which generates keys server-side; CSR is documented as preferred (ADR-11 spirit) | Drop the `key` variant |
| `certificateHold` not offered as revocation reason | "Temporary revocation" is poorly supported and confusing; RFC 5280 lists it but CA/B BR forbid it | Add it to the enum |
| Role scopes only `tenant` and `ca` | Domain and agent-group scopes belong to phases 2/3 | Extend enum |
| No tenant in any path | security.md: tenant comes from the authenticated context | – |
| Not included: batch upload (PLAN §6.1), encrypted backup download, ACME, domains, agents | Not in the phase 1 row of the roadmap or belong to later phases | Add in phase 1 if wanted (open question) |
| No OpenAPI linter (vacuum/spectral) | Not an approved dependency; structural test instead | Proposal: add `vacuum` (MIT, Go) as a pinned CI tool |

### Open points for phase 1 (see docs/PHASE1.md)
- Code generator: oapi-codegen supports OpenAPI 3.1 only partially; ogen supports it. Needs a decision
  and approval (new dependency).
- Does the UI really need server-side key generation, or only CSR signing? (security trade-off)

## Step 7 – Design tokens, component CSS, /design, serve --dev

### Done
- `web/styles/tokens.css` (brand/neutral tokens themeable, **status tokens fixed**, light + dark via
  `prefers-color-scheme` and `data-theme`, density via `data-density`), `base.css`, `components.css`
  (buttons, badges, tables, toolbar, KPI tiles, forms, notices, key/value details, PEM blocks, empty
  state, chart box, dev banner, gallery helpers), `layouts.css` (shell B "Standard" only).
- `web/icons.svg` – sprite with 6 outline icons (ok, warn, crit, info, download, search).
- templ: `internal/web/components` (Icon, Badge, Stat, Note, FormRow, DevBanner),
  `internal/web/layout` (shell B), `internal/web/pages/design` (gallery with realistic homelab data).
  Generated `*_templ.go` files are committed; `go generate ./...` / `task generate` regenerates them.
- `internal/web` – handler with `/design`, `/static/…`, redirect `/` → `/design`; security headers on
  every response (CSP from security.md + `img-src 'self'; form-action 'self'`, nosniff,
  Referrer-Policy, X-Frame-Options, COOP/CORP, Permissions-Policy); request logging; panic recovery.
- `myownpki serve --dev [--listen 127.0.0.1:9443]`; `task dev` runs it.
- Tests: routes and headers (also on 404/redirects), dev banner only in dev mode, **no inline
  style/script/event handler/javascript: URL** in the rendered page and in all `.templ` sources, every
  used CSS class is defined, every `var(--x)` exists in tokens.css, no hard-coded colors outside
  tokens.css, listen-address validation (14 cases), graceful shutdown, UTC log timestamps.
  Mutation-tested: an inline `style=` and an undefined class are both caught.
- Visually checked in the built-in browser: light, dark, compact, 375 px phone width – no console/CSP
  errors, no horizontal overflow; serials and dates don't wrap inside tables.

### Decisions
| Decision | Why | How to reverse |
|---|---|---|
| `--dev` is a CLI flag only; dev mode accepts only the IP literals `127.0.0.1` / `::1` (no names, no zones, no port 0) | Owner's rule: a name like `localhost` can resolve elsewhere; nothing unauthenticated may reach the network | – |
| `serve` without `--dev` refuses to start (exit 2) | TLS and login don't exist yet | Phase 1 |
| Dev banner on stderr at start **and** sticky on every page (`role="alert"`) | Owner's rule | – |
| Default dev port 9443 (the future admin port), plain HTTP | Same URL habit as later; only loopback | Change `defaultDevListen` |
| No JavaScript at all in phase 0; dark mode shown as a second preview with `data-theme="dark"` | Islands need esbuild (not approved yet); no theme switch needed for a gallery | Add an island in phase 4 |
| No htmx vendored yet | Not needed for a static page; vendoring needs owner approval (third-party file) | Vendor in phase 1 |
| Status colors fixed per light/dark mode | ADR-12 forbids themes changing them, but dark mode needs different shades for contrast | – |
| System font stack, no web fonts | Nothing to download/licence, no CSP exception | – |
| US English spelling in UI and code (`color`) | misspell linter is set to US (ADR-17) | Change locale |
| Static assets `Cache-Control: no-cache`, explicit Content-Type for .css/.svg | Asset URLs aren't fingerprinted yet; on Windows Go would take MIME types from the registry, and with `nosniff` a wrong type breaks the page | Fingerprint assets later |
| HSTS not sent | Only meaningful over TLS (phase 1) | – |
| Log timestamps converted to UTC | go-conventions "UTC everywhere" – the first run logged `+02:00` | – |
| Sample data uses `it-admin@homelab.lan` | No real names in demo data | – |

### Notes
- `favicon.ico` returns 404 (browser request). Harmless; a real icon can come with the branding work.
- Screenshots in the built-in browser only worked intermittently (window in the background), so the
  checks were done mainly via computed styles; a few screenshots were possible.

## Step 8 – Documentation

- `docs/PLAN.md`: status, roadmap (phase 0 ✅), repository layout, §12 open points updated, new §13
  "Tooling and conventions" (explicitly *not* ADRs; the ADR table is unchanged).
- `README.md`: status, layout, development quick start. `CLAUDE.md` and
  `.claude/skills/myownpki/references/go-conventions.md`: the two "decide in phase 0" items resolved.
- `docs/PHASE1.md`: written proposal for phase 1 (data model, step order, dependencies, open questions).
  No phase 1 code was written.

