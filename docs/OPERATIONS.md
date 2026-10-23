# Operations guide – MyOwnPKI v0.2

For the administrator who runs MyOwnPKI: installing it, the first start, daily work, backup and
restore, moving from `pki.sh`, and what to do when something is lost. Installing with `install.sh`
as a systemd service is §2; Docker and the release archives are in the [README](../README.md); the
full design is in [PLAN.md](PLAN.md).

> **Read this first – the passphrase.** The unseal passphrase (or the recovery key) decrypts every
> CA key. **Without one of the two, the CA keys are gone for good**: no support, no back door, no
> recovery from a backup. And **whoever has a backup plus the passphrase or the recovery key can
> sign as your CAs.** So:
> - keep the passphrase, the recovery key and the backups in **three different places**
>   (for example: password manager, a printed sheet in a safe, a backup disk);
> - never store the passphrase on the server, in a script, in an environment variable or next to
>   the backups;
> - test once a year that you can still unseal with the passphrase and that the recovery key on
>   paper is readable.

## 1. What runs and where

| Part | What it is | Default |
|---|---|---|
| Admin listener | Web UI and REST API, HTTPS only | `127.0.0.1:9443` |
| Public listener | CRLs and CA certificates over plain HTTP, no login | `:8080` |
| ACME listener | ACME for the reverse proxy only, plain HTTP; off until `acme.base_url` is set ([chapter 10](#10-acme-server)) | `127.0.0.1:8081` |
| Data directory | `system.db` (users, sessions, key ring), `audit.db` (instance audit log), `tenants/default/pki.db` (CAs, certificates, encrypted keys) and `tenants/default/audit.db`, `tls/` (bootstrap certificate), `auth.key` | `/var/lib/myownpki` |
| Config file | YAML, every key also as `MYOWNPKI_*` variable | `/etc/myownpki/config.yaml` (Windows: `%ProgramData%\MyOwnPKI\config.yaml`) |

The secrets you get at `init`, and what each one protects:

| Secret | Protects | Where it lives | If lost |
|---|---|---|---|
| Unseal passphrase | All CA keys (Argon2id → key-encryption key) | Only in your head / password manager | `myownpki passphrase reset` with the recovery key |
| Recovery key (9 groups of 6) | The same as the passphrase – the second way in | On paper, offline | Nothing lost as long as the passphrase is known; a command to rotate it is planned |
| Admin password + authenticator (TOTP) | Sign-in to the UI and the API | User's password manager and phone | Another instance admin, or `myownpki user reset-2fa` |
| `auth.key` | TOTP secrets and recovery codes of all users | Data directory (or `auth.key_file`) | `myownpki user reset-2fa --new-auth-key`, then reset-2fa for every user |
| Checkpoint key fingerprint | Proves that the audit log is the one you had | Write it down at `init` | `audit verify` works without it, but can't prove the log wasn't replaced |

## 2. Install and configure

### 2.1 With install.sh – the default

On a Linux machine with systemd (Debian, Ubuntu and others; amd64 or arm64), `install.sh` installs
MyOwnPKI as a service with one command. Download it with the checksum file, check it, then run it –
never pipe a script from the internet into a shell:

```bash
v=0.2.1
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install.sh"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
sha256sum --check --ignore-missing checksums.txt
```

With [cosign](https://github.com/sigstore/cosign/releases) installed, check the signature of
`checksums.txt` too (as in the README) – `install.sh` then does the same for the archive it
downloads. Then, as root:

```bash
sudo bash install.sh --tls-names "pki.homelab.lan, 192.168.10.5"
```

What it does:

- It downloads the release archive of its own version (`--version` picks another one; `--archive`
  installs a local archive – `checksums.txt` and, if you have it, `checksums.txt.sigstore.json`
  next to it), checks its SHA-256 against `checksums.txt` and, when cosign is installed, the
  signature of `checksums.txt` (it must come from the release workflow at that tag). A mismatch
  stops it before anything is installed.
- It creates the system user `myownpki` and `/var/lib/myownpki` (0700), and installs
  `/usr/local/bin/myownpki` and the unit `/etc/systemd/system/myownpki.service`.
- `/etc/myownpki/config.yaml` (root:myownpki, 0640) is written **only if there is none** – an
  existing config is never changed. It is the example config with four values, each shown in the
  result:

  | Key | Default | Option |
  |---|---|---|
  | `admin.listen` | `0.0.0.0:9443` | `--admin-listen` |
  | `admin.tls_names` | `hostname -f` and the machine's addresses | `--tls-names` |
  | `admin.allowed_networks` | `127.0.0.1` and the /24 of each own IPv4 address | `--allowed-networks` (the address the health check uses is always added) |
  | `public.listen` | `:8080` | `--public-port-80` sets `:80` |

  The new file must pass `myownpki config check` before it is put in place.
- The first installation **enables the service but doesn't start it**, and ends with the next
  commands: `init` at the terminal as the service user (§3), `systemctl start myownpki`, the admin
  certificate's fingerprint from the journal, and the address to unseal in the browser:

  ```bash
  runuser -u myownpki -- /usr/local/bin/myownpki init --config /etc/myownpki/config.yaml
  ```

  ```bash
  systemctl start myownpki
  ```

  ```bash
  journalctl -u myownpki -o cat | grep fingerprint_sha256
  ```

- Running it again changes nothing that is already in place ("Changes: none"). An update is §9.

The unit runs the server in a strict sandbox: no capabilities, a read-only system except
`/var/lib/myownpki`, private `/tmp`, devices and users, only IPv4/IPv6/Unix sockets, no
namespaces, no writable-and-executable memory, the system calls of a normal service.
`systemd-analyze security myownpki.service` rates it below 2.0 ("OK"; the CI job checks that and
shows the value in its summary). Without a reverse proxy in front of the public listener,
`--public-port-80` adds the drop-in `myownpki.service.d/public-port-80.conf`: binding port 80 is
then the only capability the service has. With a `data_dir` other than `/var/lib/myownpki`,
change `StateDirectory=` and `ReadWritePaths=` with `systemctl edit myownpki`.

### 2.2 With Docker, or by hand

The container image and `deploy/docker-compose.yml` are in the README. By hand – another init
system, FreeBSD, macOS, Windows:

1. Install the binary from a release archive and create a system user, for example `myownpki`, that
   owns the data directory (mode 0700).
2. Copy [`deploy/config.example.yaml`](../deploy/config.example.yaml) to the config path, set
   `data_dir`, and check it:

   ```bash
   myownpki config check --config /etc/myownpki/config.yaml
   ```

### 2.3 Settings to decide

For a config written by hand (install.sh sets these from its defaults or options):

1. Who may reach the admin listener. Loopback is the default of the example config. For remote
   administration set `admin.listen: 0.0.0.0:9443` **and** `admin.allowed_networks` (for example
   `127.0.0.1, 192.168.10.0/24`). Keep `127.0.0.1` in the list: `myownpki healthcheck` connects
   through loopback. Never expose the admin listener to the internet.
2. Add the names you type into the browser to `admin.tls_names` (for example
   `pki.homelab.lan, 192.168.10.5`), or give your own certificate with `admin.tls_cert_file` /
   `admin.tls_key_file`.
3. The public listener must be reachable under the base URL that is baked into every certificate
   (AIA and CRL distribution point) – usually a reverse proxy on port 80 in front of `:8080`.

## 3. First start: `init`

Run it once, at a terminal, as the service user:

```bash
myownpki init --config /etc/myownpki/config.yaml
```

It asks for the unseal passphrase (at least 16 characters, twice), the first admin user and
password, shows the **recovery key** and asks you to type two groups again, shows the TOTP setup
for the authenticator app and wants one code, and ends with the recovery codes and the **checkpoint
key fingerprint**. Write down the recovery key and the fingerprint now.

- Automation (no terminal): `init --stdin --admin-user NAME --recovery-key-file FILE --otpauth-file FILE`
  takes the passphrase and the password as two lines on standard input; move both files off the
  server after reading them.
- Trying it out: `init --demo --with-ca --ca-base-url http://pki.homelab.lan` generates every secret
  into one file and stays marked as a demo – never for real use.

## 4. Running the server

```bash
myownpki serve --config /etc/myownpki/config.yaml
```

- The server starts **sealed**: the UI works, CRLs and CA certificates are served, but nothing can
  be signed. An instance admin unseals it in the UI (banner → *Unseal*) or with `serve --unseal` at
  the terminal. Every attempt is audited; wrong passphrases are slowed down.
- At start the log names the admin certificate's SHA-256 fingerprint. Compare it with what the
  browser shows the first time – a changed fingerprint is logged as a warning.
- *Seal* (UI or `POST /api/v1/system/seal`) removes all keys from memory at once – the emergency
  stop when you suspect someone on the server.
- Database migrations run at start like `myownpki db migrate`; back up before an upgrade.
- Stop the server with SIGTERM or Ctrl+C: it finishes requests, seals and writes a last audit
  checkpoint (within 8 seconds). With systemd, use `KillSignal=SIGTERM` and `TimeoutStopSec=30`.

### Health checks and monitoring

```bash
myownpki healthcheck --config /etc/myownpki/config.yaml
```

Asks `/healthz` of the admin listener on this machine; exit code 0 = healthy, 1 = not. It checks
the connection against the exact certificate file the server serves (no CA involved), so it never
talks to something else on the port. `/healthz` says nothing about the seal state on purpose – a
sealed server is healthy but can't sign; watch the log for `crl attention` (a CRL gets old while
sealed) and alert on it.

Logs go to standard error as JSON (`log.format: text` for reading at a console). They never
contain secrets. The audit log is separate, hash-chained and signed:

```bash
myownpki audit verify --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint from init>
```

## 5. Moving from `pki.sh`

`pki.sh` stays as the **offline root** tool; MyOwnPKI takes over the intermediates, the issued
certificates and the CRLs. Old certificates keep working: their CRL URLs (`<base>/<ca>.crl`) are
served by the public listener, with the CRL numbers continuing where `pki.sh` stopped.

1. Look first – nothing is written:

   ```bash
   myownpki import legacy /path/to/pki --dry-run
   ```

2. Import. CA keys encrypted by `pki.sh` need their passphrase in `PKI_CA_PASS_<NAME>` (or one
   `PKI_CA_PASS` for all), encrypted leaf keys in `PKI_KEY_PASS`. The command asks for the unseal
   passphrase to encrypt the keys into MyOwnPKI.

   ```bash
   myownpki import legacy /path/to/pki
   ```

3. The root's key stays in `pki.sh` (`--root-key offline`, the default). Sign the root's CRL there
   as before and upload it in the UI (the root's page → *Upload the root's CRL*). `--root-key online` imports
   the root key as well – only for a homelab that accepts an online root.
4. Point the web server that served the old CRL URLs to the public listener.

The import keeps serial numbers, revocations (time and reason) and CRL numbers identical; the
report lists anything it could not take over. The UI offers the same import as an archive upload
(*Administration → Legacy import*).

## 6. Backup and restore

```bash
myownpki backup /backup/myownpki-2026-10-21 --config /etc/myownpki/config.yaml
```

- Works while the server runs (a consistent copy of every database). Writes a new directory with a
  `manifest.json` (file hashes, migration versions, audit heads, checkpoint key).
- **Contains the CA and certificate keys – encrypted with the root key.** The backup alone can't
  sign; the backup **plus the passphrase or the recovery key** can. Keep them apart (see the top).
- `auth.key` is in the backup when it lives in the data directory. If it lives elsewhere
  (`auth.key_file`), back it up separately – or every user needs `user reset-2fa` after a restore.
- Check a backup without touching anything (do it now and then, and always before you rely on it):

  ```bash
  myownpki backup verify /backup/myownpki-2026-10-21 --checkpoint-key <fingerprint>
  ```

Restore into an **empty or missing** data directory, with the server stopped:

```bash
myownpki restore /backup/myownpki-2026-10-21 --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
```

It runs every check first (hashes, database integrity, audit chains and heads, the certificate name
index) and writes nothing if one fails. Then start the server and unseal it with the passphrase
**that was valid when the backup was taken**. Certificates issued after the backup are not in it;
their serial numbers are still in the issued certificates and the audit trail of your clients.

## 7. Passphrase and recovery key

```bash
myownpki passphrase change --config /etc/myownpki/config.yaml
```

New passphrase, proven with the current one. Works while the server runs and doesn't change its
seal state.

```bash
myownpki passphrase reset --config /etc/myownpki/config.yaml
```

The passphrase is lost: a new one, proven with the recovery key. Both commands are audited.
Backups taken before the change still open only with the **old** passphrase (or the recovery key) –
keep the old one with those backups until they have aged out.

## 8. When something is lost or wrong

| Situation | What to do |
|---|---|
| A user is locked out (too many wrong passwords) | Wait 15 minutes, or an instance admin clicks *Unlock now* on the user page, or `myownpki user unlock NAME` |
| A user lost the phone / authenticator | At the server console: `myownpki user reset-2fa NAME` (needs the unseal passphrase or `--recovery-key`); the user confirms the new secret at the next sign-in. A reset in the UI is planned |
| `auth.key` lost or broken | `myownpki user reset-2fa NAME --new-auth-key`, then reset-2fa for every other user |
| Unseal passphrase lost | `myownpki passphrase reset` with the recovery key |
| Passphrase **and** recovery key lost | The CA keys can't be recovered. Create new CAs, issue new certificates, retire the old CAs |
| A leaf key may be compromised | Revoke the certificate with reason *keyCompromise*; the key is blocked for every later request |
| An intermediate's key may be compromised | Revoke the intermediate at the root (offline: in `pki.sh`, then upload the root CRL), create a new intermediate, re-issue |
| Someone may be on the server | *Seal* at once, take the server off the network, check `audit verify`, restore onto a clean machine |
| The admin certificate fingerprint changed unexpectedly | Don't sign in; check the log for "new admin TLS certificate" and why (renewal 30 days before expiry, new names) |

## 9. Upgrading

**With install.sh** (§2.1): download and check the `install.sh` of the new release as in §2.1 and
run it as root. Over an initialized instance with a different binary it updates:

1. `myownpki config check` of your config with the new binary – if that fails, nothing changes;
2. `myownpki backup` (with the running version) to `/var/backups/myownpki/<time>-<old version>`
   and `myownpki backup verify` of it;
3. the new binary (the old one stays as `/usr/local/bin/myownpki.previous`), `systemctl restart`,
   and `myownpki healthcheck` for up to 30 seconds;
4. if the new version is not healthy: the old binary back and a restart. If the old one is not
   healthy either (the new version may have migrated the databases), the message has the commands
   to restore the backup from step 2.

After the restart the server is **sealed** – unseal it in the browser. The config and the unit's
drop-ins stay as they are.

**By hand or with Docker:**

1. `myownpki backup …` and `myownpki backup verify …`.
2. Replace the binary (or pull the new image), start the server – migrations run at start.
3. `myownpki db status` shows the versions; a newer database than the binary is refused, so going
   back means restoring the backup from step 1.

From v0.1 to v0.2: the migrations add the domains and the ACME tables (`pki.db`) and the ACME rate
limits in the tenant settings (`system.db`). ACME stays off until `acme.base_url` is set
([chapter 10](#10-acme-server)). Going back to v0.1 means the backup from step 1 – and removing every
`MYOWNPKI_ACME_*` variable: v0.1 refuses unknown `MYOWNPKI_*` variables and would not start.

## 10. ACME server

Since v0.2 MyOwnPKI issues certificates over ACME (RFC 8555) – the protocol of Let's Encrypt –
to certbot, acme.sh, lego, Traefik, Caddy and every other ACME client. Clients renew on their own;
nobody copies certificates by hand any more.

### 10.1 How it fits together

```
client (certbot, Traefik, …) ──https──▶ reverse proxy ──http──▶ acme.listen (127.0.0.1:8081)
         ▲                                (TLS ends here)                │
         └───────── http-01: port 80 / dns-01: TXT record ◀── validator ─┘
```

- ACME runs **only behind a reverse proxy** that ends TLS. MyOwnPKI has no TLS listener for ACME
  of its own; `acme.listen` speaks plain HTTP and is meant for the proxy only.
- `acme.base_url` is the https URL clients use, including a path, e.g.
  `https://pki.homelab.lan/acme`. Every URL the server hands out is built from it – it never
  trusts `X-Forwarded-Host` or `X-Forwarded-Proto`.
- `acme.trusted_proxies` lists who may connect to `acme.listen`; everybody else gets 403. Only from
  those addresses is `X-Forwarded-For` believed (for rate limits and the audit log): the server
  takes the last entry that is not a trusted proxy, so a client can't fake its address.
- Without `acme.base_url` ACME is off – an upgraded v0.1 configuration keeps working unchanged.

The configuration (all keys also as `MYOWNPKI_ACME_*` variables):

```yaml
acme:
  base_url: https://pki.homelab.lan/acme   # empty = ACME off
  listen: 127.0.0.1:8081                    # for the proxy only, plain HTTP
  trusted_proxies: "127.0.0.1, ::1"         # the proxy's address(es)
  resolver: 192.168.10.53                   # DNS server that knows your internal names (split DNS)
```

Check it, then restart the server:

```bash
myownpki config check --config /etc/myownpki/config.yaml
```

### 10.2 The proxy's own certificate

The proxy needs a TLS certificate before any client can talk ACME – get it once from your own CA.
The key is made on the proxy host and never leaves it:

1. On the proxy host, make a key and a CSR:

   ```bash
   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout pki.homelab.lan.key -out pki.homelab.lan.csr -subj "/CN=pki.homelab.lan" -addext "subjectAltName=DNS:pki.homelab.lan"
   ```

2. In the UI: *Issue certificate* → preset *server* → paste the CSR → issue. Click *Download
   fullchain* and save the file as `pki.homelab.lan.fullchain.pem` next to the key. (With the
   REST API: `POST /api/v1/certificates` with the CSR, then
   `GET /api/v1/certificates/{id}/download/fullchain`.)
3. Put a reminder in your calendar, or watch *Expiring soon* on the dashboard: this one certificate
   is renewed by hand (or, once ACME runs, by the proxy itself – Caddy and Traefik can be ACME
   clients of your own CA, see 10.6).

Alternatively the server makes the key: *Issue certificate* with a server-generated key, then
*Export* → *Certificate, chain and key in one PEM* (needs a fresh second factor; audited).

### 10.3 Proxy examples

Each example serves ACME under `/acme/` with TLS **and** the public listener (CRLs, CA
certificates) on plain HTTP port 80 – certificates point to `http://…` for CRLs, and a redirect to
https there would break revocation checks on some clients.

**Caddy** (`Caddyfile`):

```
https://pki.homelab.lan {
	tls /etc/caddy/pki.homelab.lan.fullchain.pem /etc/caddy/pki.homelab.lan.key
	handle /acme/* {
		reverse_proxy 127.0.0.1:8081
	}
}

# Plain HTTP for CRLs and CA certificates – no redirect to https.
http://pki.homelab.lan {
	reverse_proxy 127.0.0.1:8080
}
```

Use `handle`, not `handle_path`: the path `/acme/…` must reach MyOwnPKI unchanged.

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name pki.homelab.lan;
    ssl_certificate     /etc/nginx/pki/pki.homelab.lan.fullchain.pem;
    ssl_certificate_key /etc/nginx/pki/pki.homelab.lan.key;

    location /acme/ {
        proxy_pass http://127.0.0.1:8081;   # no URI after the port: the path stays /acme/…
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80;
    server_name pki.homelab.lan;
    location / {
        proxy_pass http://127.0.0.1:8080;   # CRLs and CA certificates
    }
}
```

**Traefik** (file provider, dynamic configuration):

```yaml
http:
  routers:
    myownpki-acme:
      rule: "Host(`pki.homelab.lan`) && PathPrefix(`/acme/`)"
      entryPoints: [websecure]
      service: myownpki-acme
      tls: {}
    myownpki-public:
      rule: "Host(`pki.homelab.lan`)"
      entryPoints: [web]
      service: myownpki-public
  services:
    myownpki-acme:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8081"
    myownpki-public:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
tls:
  certificates:
    - certFile: /etc/traefik/pki/pki.homelab.lan.fullchain.pem
      keyFile: /etc/traefik/pki/pki.homelab.lan.key
```

If the proxy runs in a container, `127.0.0.1` is the container itself: let MyOwnPKI listen where
the proxy can reach it (e.g. `acme.listen: 0.0.0.0:8081` as in the Docker example) and put the
container network into `acme.trusted_proxies` (the Docker example has `172.16.0.0/12`).

Check from any machine that trusts your root (10.4):

```bash
curl https://pki.homelab.lan/acme/directory
```

The answer lists `newAccount`, `newOrder`, `revokeCert` and `renewalInfo` – all under
`https://pki.homelab.lan/acme/`. The answer "reachable only through its reverse proxy" (403) means
the proxy's address is not in `acme.trusted_proxies`.

### 10.4 Trusting your root on the clients

Clients check the proxy's certificate like any website, so they must trust your root CA. The root
is on the public listener as `/ca/<root name>/<generation>.crt` (DER):

```bash
curl -o homelab-root.crt http://pki.homelab.lan/ca/root/1.crt
```

```bash
openssl x509 -inform DER -in homelab-root.crt -out homelab-root.pem
```

Compare the fingerprint with the one in the UI (*Certificate authorities* → the root) before you
trust it:

```bash
openssl x509 -in homelab-root.pem -noout -fingerprint -sha256
```

Then either install it system-wide (Debian/Ubuntu: copy the `.pem` as `.crt` into
`/usr/local/share/ca-certificates/` and run `update-ca-certificates`; Windows:
`certutil -addstore Root homelab-root.crt`; macOS: Keychain Access → System → trust), or give it
to the one client only: certbot `REQUESTS_CA_BUNDLE=/path/homelab-root.pem`, lego
`LEGO_CA_CERTIFICATES=/path/homelab-root.pem`, acme.sh `--ca-bundle /path/homelab-root.pem`, Caddy
`acme_ca_root`, Traefik `LEGO_CA_CERTIFICATES` in its environment.

### 10.5 Domains, approvals and EAB keys

ACME issues for a name only when a **domain** covers it (*ACME → Domains*). A domain says:

| Setting | Meaning |
|---|---|
| Signing CA | An online intermediate whose name constraints permit the domain |
| Names below it | `nas.homelab.lan` for the domain `homelab.lan` |
| Challenges | http-01 (the server fetches a file from the client's port 80) and/or dns-01 (it reads a TXT record) |
| Wildcards | `*.homelab.lan` – proven by dns-01 only; off by default |
| Approval | *open*: any account that passes the challenge. *approved accounts* (default): a new account waits in *ACME → Accounts* until an admin approves it, or brings an EAB key. *new names*: the first certificate for a name waits in *ACME → New names* |
| Preset, validity | The certificate's profile (must allow serverAuth); 90 days by default, never beyond the CA |
| Addresses http-01 may reach | *internal networks too* (homelab) or *public only* – loopback and link-local are never reached |
| IP ranges | Which IP addresses may be in certificates (http-01 only) |

An **EAB key** (*ACME → EAB keys*, external account binding) lets one client skip the approval
queue: create it, copy the key ID and the MAC key (shown once), and give both to the client – the
page shows the certbot and lego command lines. A key binds one account and expires (7 days by
default). Creating keys and approving need `ca.manage` on the tenant with a fresh second factor;
the dashboard shows what waits.

### 10.6 Connecting clients

With the root trusted (10.4) and a domain in place:

```bash
certbot certonly --server https://pki.homelab.lan/acme/directory --standalone -d nas.homelab.lan
```

```bash
lego run --server https://pki.homelab.lan/acme/directory --email admin@homelab.lan --accept-tos --domains nas.homelab.lan --http
```

```bash
acme.sh --issue --server https://pki.homelab.lan/acme/directory --standalone -d nas.homelab.lan
```

With an EAB key add `--eab-kid … --eab-hmac-key …` (certbot), `--eab --eab.kid … --eab.hmac …`
(lego), or register first with `acme.sh --register-account --eab-kid … --eab-hmac-key …`.

**Caddy** as a client for its own sites (global options):

```
{
	acme_ca https://pki.homelab.lan/acme/directory
	acme_ca_root /etc/caddy/homelab-root.pem
}
```

**Traefik** as a client (static configuration; `LEGO_CA_CERTIFICATES=/etc/traefik/homelab-root.pem`
in its environment):

```yaml
certificatesResolvers:
  homelab:
    acme:
      caServer: https://pki.homelab.lan/acme/directory
      email: admin@homelab.lan
      storage: /etc/traefik/acme-homelab.json
      httpChallenge:
        entryPoint: web
```

**Renewal** needs no setup: clients with ARI (RFC 9773, e.g. lego, Caddy) ask the server when to
renew; the window opens at about 2/3 of the lifetime (day 60–63 of 90) and lasts 9 days. A revoked
certificate gets a window in the past, so its client renews at once. Clients without ARI renew by
their own rule (certbot: 30 days before expiry) – also fine.

**Revocation** from the client – `certbot revoke --cert-path …`, `lego certificates revoke …` – signs
the CRL at once. The certificate's own key can revoke it too (a leaked key, without the account).

### 10.7 Split DNS and the network

The **validator** – the part of MyOwnPKI that checks a challenge – connects to the client:

- It resolves names through `acme.resolver` (empty: the system resolver). With split DNS point it
  to the DNS server that knows your **internal** names; otherwise `nas.homelab.lan` doesn't
  resolve, or resolves to the public address.
- http-01: the PKI host must reach the client's port 80 (firewall!). Redirects are followed only to
  names of the same order and to ports 80/443. With *public only* the address must be public.
- dns-01: the TXT record `_acme-challenge.<name>` must be in the zone the resolver reads. With split
  DNS that is the **internal** zone – point the client's DNS plugin (e.g. certbot-dns-rfc2136) at
  the internal server. A zone hosted at a provider works the same way with the provider's plugin
  (e.g. certbot-dns-cloudflare), as long as `acme.resolver` sees that zone.
- The error a client gets names only the kind of problem ("could not connect", "answered with
  status 404", "no TXT record") – never what the target answered. The server log (level info) has
  the addresses.

### 10.8 Sealed server, rate limits, audit

- **Sealed**: accounts, orders and challenges still work. A *finalize* waits: the order stays
  *processing* (clients poll with Retry-After) and is issued at the unseal; the dashboard says how
  many wait. New accounts with an EAB key and new EAB keys need an unsealed server.
- **Rate limits** (*Administration → Tenant settings*, per hour): new orders per account (300),
  failed validations per name (5), new accounts per client address (10; IPv6 per /64). Over a
  limit the client gets 429 with `Retry-After` – the real wait.
- **Audit**: every account, order, validation, approval, EAB key, issuance and revocation is in the
  audit log (actor `acme:<account>`).

### 10.9 When a client fails

| The client says | Usually | Check |
|---|---|---|
| `rejectedIdentifier: no domain covers …` | No domain for the name, or a wildcard on a domain without wildcards | *ACME → Domains* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | *ACME → Accounts*, or an EAB key |
| `connection: … could not be reached` | The client's port 80 is closed for the PKI host, or the name resolves elsewhere | `acme.resolver`, firewall; the server log has the address |
| `connection: … address policy … refuses` | The name resolves to loopback or link-local, or to a private address on a *public only* domain | The domain's address setting |
| `incorrectResponse: … answered with status 404` | The client's web server doesn't serve `/.well-known/acme-challenge/` | The client's http-01 mode (standalone, webroot) |
| `dns: … has no TXT record` | The TXT record went to another zone than the resolver reads | Split DNS (10.7) |
| `rateLimited` | A limit of 10.8 | Wait for `Retry-After`, or raise the limit |
| TLS error, unknown authority | The root is not trusted on the client | 10.4 |
| `unauthorized: the ACME server is reachable only through its reverse proxy` | The proxy (or the client, past the proxy) is not in `acme.trusted_proxies` | 10.1 |
