# Operations guide – MyOwnPKI v0.3

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
| Public listener | CRLs and CA certificates over plain HTTP, no login; the trust page at `/` ([chapter 11](#11-the-public-trust-page)) | `:8080` |
| ACME listener | ACME for the reverse proxy only, plain HTTP – or, with `acme.tls_issuer`, with its own TLS for the clients ([10.10](#1010-without-a-reverse-proxy-acme-with-its-own-tls)); off until `acme.base_url` is set ([chapter 10](#10-acme-server)) | `127.0.0.1:8081` |
| Data directory | `system.db` (users, sessions, key ring), `audit.db` (instance audit log), `tenants/default/pki.db` (CAs, certificates, encrypted keys) and `tenants/default/audit.db`, `tls/` (bootstrap certificates and the ones the server issues itself, §2.4), `auth.key` | `/var/lib/myownpki` |
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
v=0.2.2
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install.sh"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
sha256sum --check --ignore-missing checksums.txt
```

With [cosign](https://github.com/sigstore/cosign/releases) installed, check the signature of
`checksums.txt` too (as in the README) – `install.sh` then does the same for the archive it
downloads. Then, as root:

```bash
sudo bash install.sh --tls-names "pki.homelab.lan, 192.0.2.5"
```

What it does:

- It downloads the release archive of its own version (`--version` picks another one; `--archive`
  installs a local archive – `checksums.txt` and, if you have it, `checksums.txt.sigstore.json`
  next to it), checks its SHA-256 against `checksums.txt` and, when cosign is installed, the
  signature of `checksums.txt` (it must come from the release workflow at that tag). A mismatch
  stops it before anything is installed.
- It creates the system user `myownpki` and `/var/lib/myownpki` (0700), and installs
  `/usr/local/bin/myownpki` and the unit `/etc/systemd/system/myownpki.service`.
- It installs the daily backup – `myownpki-backup.service` and `.timer`, backups in
  `/var/backups/myownpki` (0700) – and enables the timer the first time (§6.1; `--no-backup-timer`,
  `--backup-keep N`).
- `/etc/myownpki/config.yaml` (root:myownpki, 0640) is written **only if there is none** – an
  existing config is never changed. It is the example config with four values, each shown in the
  result:

  | Key | Default | Option |
  |---|---|---|
  | `admin.listen` | `0.0.0.0:9443` | `--admin-listen` |
  | `admin.tls_names` | `hostname -f` and the machine's addresses | `--tls-names` |
  | `admin.allowed_networks` | `127.0.0.1` and the /24 of each own IPv4 address | `--allowed-networks` (the address the health check uses is always added) |
  | `public.listen` | `:8080` | `--public-port-80` sets `:80` |
  | `acme.base_url`, `acme.listen`, `acme.tls_issuer` | ACME off | `--acme https://pki.homelab.lan/acme` sets the URL, `acme.listen` to its port (`:443` without one) and `acme.tls_issuer` to `--acme-ca` (default `issuing`, the intermediate of `init --with-ca` – give the name of your own intermediate) – ACME with its own TLS, [10.10](#1010-without-a-reverse-proxy-acme-with-its-own-tls) |

  The new file must pass `myownpki config check` before it is put in place. With an existing
  config, install.sh says which values to set by hand.
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
`systemd-analyze security myownpki.service` rates it **1.2** ("OK"; measured 2026-10-23 on the
GitHub runner ubuntu-24.04). The CI job fails above 2.0 and shows the value in its summary;
other systemd versions may rate a little differently.

Ports below 1024 without a reverse proxy – the public listener on `:80` (`--public-port-80`), ACME
with its own TLS on `:443` (`--acme`) – need the drop-in `myownpki.service.d/low-ports.conf`:
binding such a port is then the only capability the service has (it also drops `PrivateUsers=`,
because a capability inside a private user namespace doesn't count for the host's network). Since
v0.2.2 the CI job measures the unit **with** this drop-in and still requires less than 2.0. Its
old name `public-port-80.conf` (v0.2.1) does the same; an installed one stays in place and
install.sh adds no second one. The drop-in is installed even when the config exists already, and
never removed. With a `data_dir` other than `/var/lib/myownpki`, change `StateDirectory=` and
`ReadWritePaths=` with `systemctl edit myownpki`.

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
   `127.0.0.1, 192.0.2.0/24`). Keep `127.0.0.1` in the list: `myownpki healthcheck` connects
   through loopback. Never expose the admin listener to the internet.
2. Add the names you type into the browser to `admin.tls_names` (for example
   `pki.homelab.lan, 192.0.2.5`), or give your own certificate with `admin.tls_cert_file` /
   `admin.tls_key_file` – or let the server issue its own from your CA with `admin.tls_issuer`
   (§2.4).
3. The public listener must be reachable under the base URL that is baked into every certificate
   (AIA and CRL distribution point) – usually a reverse proxy on port 80 in front of `:8080`.

### 2.4 Certificates the server issues itself (`tls_issuer`)

Since v0.2.2 the server can give the admin listener – and the ACME listener, [10.10](#1010-without-a-reverse-proxy-acme-with-its-own-tls) –
a certificate from **your own CA**, so browsers that trust your root show no warning and nobody
compares fingerprints any more:

```yaml
admin:
  tls_names: "pki.homelab.lan, 192.0.2.20" # exactly the names of the certificate
  tls_issuer: issuing                      # the name of the CA (as in `myownpki ca list`), not its CN
```

How it behaves:

- **Issued while unsealed, through the normal policy.** At the unseal (and every 15 minutes after)
  the server makes a new ECDSA P-256 key, sends a CSR through the same CA engine as the UI – preset
  *server*, the CA's name constraints and limits apply – and gets a certificate for exactly the
  names in `admin.tls_names`. The tenant audit log shows it as `certificate.issue` by the actor
  *system / server*; the certificate is in *Certificates* like any other.
- **Short-lived:** 90 days, less when the CA allows less (*max validity*) or ends earlier. Renewed
  at 2/3 of the lifetime (after 60 days), and at once when the names change, the certificate was
  revoked, or the CA got a new certificate (renewal with a new key).
- **Works while sealed.** Signing needs the unsealed key ring, the listener doesn't: key and
  certificate lie in `<data_dir>/tls/admin.key` (0600, unencrypted – like the bootstrap key) and
  `admin.crt` (the certificate and the issuing CA, *fullchain* without the root). So a restart
  serves the issued certificate at once, even before the unseal.
- **Falls back to the bootstrap certificate** while there is no valid issued one: before the first
  unseal, and when it expires while the server stays sealed (a warning in the log every 15 minutes
  and on the dashboard). The unseal issues a new one. The switch happens per connection – **no
  restart**, and `myownpki healthcheck` accepts both.
- **A refused issuance** – a name outside the CA's name constraints, an unknown or offline CA – is
  logged with the engine's reason and shown on the dashboard as an error; the server keeps the
  bootstrap (or the still valid issued) certificate and tries again after 6 hours (other errors:
  after 15 minutes), or at the first unseal after a restart.
- **Name an intermediate, never a root.** A root usually has no name constraints, so a listener
  certificate straight from it would bypass the ones of your intermediate (and the engine signs no
  end-entity certificate with a root anyway). With a root in `admin.tls_issuer` or
  `acme.tls_issuer` the server says so at the start – `CA root is a root – name the issuing
  intermediate in admin.tls_issuer (intermediates of root: issuing)` – in the log and as an error
  on the dashboard, issues nothing and serves the **bootstrap certificate**, even when an older
  issued one is still valid. `myownpki config check` prints the same warning on stderr when it can
  read the CA database (the config stays valid, exit code 0, like the server, which starts).
- `admin.tls_issuer` and `admin.tls_cert_file` exclude each other; `config check` says so.

> **PKI background – why the key may lie unencrypted.** The CA keys are what must never leak: they
> sign. The listener's key only proves "this is the server" for 90 days at most, for exactly the
> names in its certificate – and the CA's name constraints limit even that. If it leaks, revoke the
> certificate in the UI: the server issues a new one at once (with a new key).

Check what the listener serves, and that it verifies against your root:

```bash
openssl s_client -connect pki.homelab.lan:9443 -servername pki.homelab.lan -CAfile root.pem -verify_return_error </dev/null | grep -E "Verify return code|subject=|issuer="
```

```bash
journalctl -u myownpki -o cat | grep -E '"TLS certificate (issued|can.t be issued)"|tls_issuer'
```

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

### 6.1 Daily backups with the systemd timer

Since v0.2.2 install.sh (§2.1) installs `myownpki-backup.service` and `myownpki-backup.timer` and
enables the timer. Once a day (at a random time in the first hour after midnight; a run missed
while the machine was off follows at the next start) it runs:

```bash
myownpki backup scheduled /var/backups/myownpki --keep 14 --config /etc/myownpki/config.yaml
```

1. a backup into `/var/backups/myownpki/<UTC time>`, e.g. `20261025T003512Z` (0700, the service
   user) – audited as *system / backup-timer*;
2. every restore check on it (as `backup verify`);
3. only if the check passed: **prune** – the newest 14 scheduled backups stay, older ones are
   deleted.

What prune deletes, and what never:

| In `/var/backups/myownpki` | Prune |
|---|---|
| `20261025T003512Z` – made by the timer, complete | kept if among the newest 14, else **deleted** |
| `20261024T101500Z-v0.2.1` – install.sh's backup before an update | **never** – your way back before a migration; delete it yourself when the new version runs well |
| `20261025T003512Z-unverified` – a timer backup that failed its check | **never**, not counted; the run ended with an error – look at it |
| a scheduled name that isn't a complete backup (no `manifest.json`, a file more or less than the manifest lists, another size, a symbolic link) | **never**; named as "Left alone" in the journal |
| anything else (your own backups, notes) | never looked at |

So the update backups don't count against the 14 – an update never pushes a daily backup out, and
the daily ones never push out the backup taken before a migration.

The timer's unit has the sandbox of the server's unit and **no network**. Writable are only
`/var/backups/myownpki` and `/var/lib/myownpki` – the data directory because SQLite has to write its
lock files to read a database that is in use, and every backup is an audit entry.

Everyday commands:

```bash
systemctl list-timers myownpki-backup.timer
```

```bash
systemctl start myownpki-backup.service
```

```bash
journalctl -u myownpki-backup.service -o cat
```

```bash
runuser -u myownpki -- myownpki backup prune /var/backups/myownpki --keep 14 --dry-run
```

- **Another number:** `install.sh --backup-keep 30` (writes the drop-in
  `myownpki-backup.service.d/keep.conf`), or `systemctl edit myownpki-backup.service` with
  `[Service]` / `Environment=BACKUP_KEEP=30`.
- **Off:** `install.sh --no-backup-timer`, or `systemctl disable --now myownpki-backup.timer`.
  install.sh enables the timer only when it installs it the first time; later runs leave it as you
  set it.
- A failed run shows in `systemctl --failed` and in the journal – watch it like the service.
- **The dashboard warns** when a `…-unverified` directory lies in `/var/backups/myownpki` (until you
  delete it), and when the newest timer backup is older than **48 hours** – one daily run missed:
  the timer is off or the backup fails. It looks only when the timer is installed or has written a
  backup; with `--no-backup-timer` and no timer backup ever, it stays quiet. When the timer has
  been on for 48 hours without a single backup, that is a warning too. The server only reads the
  directory listing (no new rights for its unit: `/var` is read-only for it, not hidden, and the
  directory belongs to `myownpki`). Install.sh's update backups don't count.
- `/var/backups/myownpki` is on the same disk as the data directory: copy it elsewhere (rsync, your
  backup software) – a backup on the same disk doesn't survive the disk. Keep the passphrase and
  the recovery key away from that copy.

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
3. the new binary (the old one stays as `/usr/local/bin/myownpki.previous`) – install.sh checks
   that `/usr/local/bin/myownpki --version` is the new version –, `systemctl restart`,
   `myownpki healthcheck` for up to 30 seconds, and that the running service is the new binary
   (a healthy service could still be the old one);
4. if one of these checks fails: the old binary back, a restart, and install.sh ends with an
   error – an update is only reported as done when the new version runs. If the old one is not
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

- By default ACME runs **behind a reverse proxy** that ends TLS; `acme.listen` speaks plain HTTP
  and is meant for the proxy only. Since v0.2.2 there is a second way without a proxy:
  `acme.tls_issuer` gives `acme.listen` its own TLS with a certificate the server issues itself
  ([10.10](#1010-without-a-reverse-proxy-acme-with-its-own-tls)). The proxy way stays supported
  and is what you get when `acme.tls_issuer` is empty.
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
  resolver: 192.0.2.53                      # DNS server that knows your internal names (split DNS)
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

Clients check the proxy's certificate like any website, so they must trust your root CA. Since
v0.2.2 the trust page at `/` of the public listener walks every platform through it ([chapter
11](#11-the-public-trust-page)). By hand: the root
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
| TLS error, unknown authority, or a certificate for "MyOwnPKI ACME (bootstrap)" | With `acme.tls_issuer`: no issued certificate yet (the server was not unsealed since the start) or it expired while sealed | 10.10, the dashboard |

### 10.10 Without a reverse proxy: ACME with its own TLS

Since v0.2.2 `acme.tls_issuer` names a CA of your instance, and the ACME listener speaks TLS
itself with a certificate the server issues from it for the host of `acme.base_url` – the same
mechanism as for the admin listener (§2.4: preset *server*, ECDSA P-256, 90 days at most, renewed
at 2/3, issued only while unsealed, the CA's name constraints apply, audited as *system*):

```yaml
acme:
  base_url: https://pki.homelab.lan/acme # the host is the name in the certificate
  listen: ":443"                         # the port of base_url; reachable by the clients
  tls_issuer: issuing                    # the CA's name (myownpki ca list)
  resolver: 192.0.2.1
```

With install.sh (§2.1) on a new machine: `--acme https://pki.homelab.lan/acme --acme-ca <your intermediate>`
writes these keys and installs the drop-in `low-ports.conf` for port 443. On an existing
installation, set the keys by hand; `install.sh --acme …` then only adds the drop-in.

What changes against the proxy way:

- `acme.listen` is **its own listener** with TLS – never the admin listener (that one is limited
  by `admin.allowed_networks`) and never the public CRL port.
- Every client may connect: `acme.trusted_proxies` and `X-Forwarded-For` are **ignored**. The
  client address in the rate limits and the audit log is the direct peer – a client can't pick
  another one with a header. The server logs this at start.
- Until the first unseal after a start without an issued certificate (and when it expired while
  sealed), the listener serves a self-signed *MyOwnPKI ACME (bootstrap)* certificate. Clients
  refuse it – on purpose: an ACME client must never talk to a server it can't verify. The
  dashboard and the log say so; the unseal fixes it.
- Clients need your root as trust anchor (10.4) – for certbot `REQUESTS_CA_BUNDLE`, for lego
  `LEGO_CA_CERTIFICATES`, for acme.sh `--ca-bundle`.

Check it from a client:

```bash
curl --cacert root.pem https://pki.homelab.lan/acme/directory
```

## 11. The public trust page

Since v0.2.2 the public listener serves a page at `/` – `http://pki.homelab.lan/` behind port 80 –
that everybody may open without signing in. Send people there instead of mailing root files:

- every active CA, **roots first**: name, common name, validity and the **SHA-256 fingerprint**
  in large type; after a root renewal also the older generation while it is valid;
- downloads as DER (`/ca/<name>/<generation>.crt`, the URL in every certificate's AIA, unchanged)
  and PEM (`/ca/<name>/<generation>.pem`, new);
- per root two **Windows helpers** (`.cmd`): *this computer* (LocalMachine, asks for administrator
  rights itself) and *my user only* (CurrentUser, no administrator rights);
- guides for Windows, macOS, iPhone/iPad (including *Certificate Trust Settings* – without that
  step iOS installs a root but doesn't trust it for websites), Android, Linux and Firefox.

Only public data, no JavaScript, a strict Content Security Policy (`default-src 'none'`, the own
stylesheets and logo only), cached for 5 minutes (the files for 15) with ETags.

**Switch it off** in *Administration → Tenant settings* (*Public trust page*), or through the API
(`PUT /api/v1/settings` with `"trust_page": false`). Off, `/` and the Windows helpers answer 404;
the CA certificates, their PEM copies and the CRLs stay – certificates point to them.

> **PKI background – why compare the fingerprint.** A root is the anchor every check ends at:
> whoever slips you a false root can impersonate every website for you. The page comes over plain
> HTTP (it must work before anything trusts your PKI), so someone in the network path could change
> it. The fingerprint is the check: compare it with one you got another way – the admin UI
> (*Certificate authorities*), a printout, your administrator.

### 11.1 The Windows helpers

Each `.cmd` is one file that is both a batch file and a PowerShell script. Double-clicked, it:

1. shows the SHA-256 fingerprint of the root it carries, computed from the embedded certificate;
2. compares it with the fingerprint written into the file and **stops** (exit code 2, nothing
   imported) if they differ – a file changed on the way;
3. *this computer*: asks for administrator rights (UAC) and runs again elevated;
4. imports the root into *Trusted Root Certification Authorities* of the computer or the user
   (Windows asks once to confirm the user variant) and waits for Enter.

Switches: `/check` only checks (exit 0 when the fingerprint fits), `/quiet` doesn't wait for
Enter. Any other argument stops it with exit code 64 – a typo never becomes an import. The file is
ASCII with CRLF line ends. Check a downloaded helper without importing:

```bat
cmd /c root-trust-computer.cmd /check
```

Windows may warn about a downloaded `.cmd` (SmartScreen, *Unblock* in its properties) – that is
normal for scripts from the network. The fingerprint check proves that the file is intact; that it
is **your** root, only the comparison with a fingerprint from another way proves.

## 12. Agent

`myownpki-agent` enrolls a Linux host, obtains certificates through ACME with http-01 and installs
them with the `nginx` or `file` profile. It writes only below local `paths`, runs only hooks from
local `agent.yaml`, and receives desired state rather than commands from the server. Linux is the
supported deployment platform in v0.3.0; Windows, macOS and FreeBSD are build/test targets only.

### 12.1 Agent CA and server

Create an intermediate **directly below the root**, not below an intermediate with `pathlen: 0`.
In *Certificate authorities → New intermediate*, choose the root as parent and set the EKU limit to
**clientAuth only**. Name it `agent-ca`. It signs only the agents' 7-day client certificates; it is
not the CA that issues the agent listener's server certificate.

Enable the listener in `/etc/myownpki/config.yaml`:

```yaml
agent:
  base_url: https://pki.homelab.lan:8444
  listen: ":8444"
  tls_issuer: issuing   # issues the listener's server certificate
  ca: agent-ca          # signs and authenticates agent client certificates
```

Unseal the server so it can issue both certificates. `myownpki config check` and startup check the
agent CA and its EKU limit. Also configure ACME (chapter 10) and a domain covering every name the
agent may order. Agents use the same root as trust anchor for the agent and ACME listeners.

### 12.2 Join token and verified installation

In *Agents → Join tokens → Create token*, enter the host's exact name and, if needed, patterns such
as `*.apps.homelab.lan`. Store the one-time token in a root-only file on the host, for example
`/root/myownpki-join-token` with mode 0600. Do not put it in `agent.yaml` or on a command line.

Download the installer and checksum file, verify, and only then execute. Never pipe a download
into a shell:

```bash
v=0.3.0
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install-agent.sh"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
sha256sum --check --ignore-missing checksums.txt
```

Verify `checksums.txt` with cosign as described in the README when available. The installer checks
the archive against `checksums.txt` again after downloading it; with cosign installed it also checks
the release-workflow signature. For an offline host, put the agent archive and checksum files in one
directory and use `--archive` instead.

Webroot enrollment (recommended when nginx already answers port 80):

```bash
sudo bash install-agent.sh \
  --server https://pki.homelab.lan:8444 \
  --ca-bundle root.pem \
  --token-file /root/myownpki-join-token \
  --webroot /var/www/html
```

Without `--webroot`, enrollment uses standalone http-01 on port 80 and the installer adds the
`20-low-ports.conf` capability drop-in. The token file is deleted only after successful admission;
a pending or failed enrollment keeps it. The initial `agent.yaml` has no deployments. It is never
overwritten on later runs. Re-run the script with a newer release to update the binary and restart
the service; there is no agent self-update.

### 12.3 agent.yaml and deployment profiles

The file is `/etc/myownpki-agent/agent.yaml`, state is `/var/lib/myownpki-agent` (0700, files 0600).
After editing, run `myownpki-agent config check` and `systemctl restart myownpki-agent`.

An nginx profile with webroot enrollment and ACME:

```yaml
server: "https://pki.homelab.lan:8444"
ca_bundle: "/etc/myownpki-agent/root.pem"
hostname: "proxy1.homelab.lan"
state_dir: "/var/lib/myownpki-agent"
log_level: "info"
acme_directory: "https://pki.homelab.lan/acme/directory"
enrollment:
  challenge: webroot
  webroot: "/var/www/html"
hooks:
  nginx-test: ["/usr/sbin/nginx", "-t"]
  nginx-reload: ["/usr/bin/systemctl", "reload", "nginx"]
paths: ["/var/www/html", "/etc/nginx/myownpki"]
deployments:
  - name: proxy
    profile: nginx
    names: ["proxy1.homelab.lan"]
    challenge: webroot
    webroot: "/var/www/html"
    dir: "/etc/nginx/myownpki/proxy"
    test_hook: nginx-test
    reload_hook: nginx-reload
    check: "127.0.0.1:443"
```

The agent writes `fullchain.pem` and `privkey.pem` in `dir`. Reference those paths from the nginx
server block. `check` is the local TLS endpoint whose SNI certificate must match the deployed leaf.

The `file` profile fits existing paths and nginx configuration. Replace the deployment above with:

```yaml
  - name: proxy
    profile: file
    names: ["proxy1.homelab.lan"]
    challenge: webroot
    webroot: "/var/www/html"
    files:
      fullchain: "/etc/nginx/myownpki/proxy.fullchain.pem"
      key: "/etc/nginx/myownpki/proxy.key"
    key_mode: "0600"
    test_hook: nginx-test
    reload_hook: nginx-reload
    check: "127.0.0.1:443"
```

`files.certificate` and `files.chain` are available when separate files are needed. Optional
`owner`, `group` and `key_mode` apply locally. Deployments sharing a nonempty reload hook are staged,
tested, reloaded and, on failure, rolled back as one group. Automatic renewal runs at 2/3 of the
lifetime or earlier when ARI requests it. *Renew now* uses the same path; failures back off rather
than retrying continuously.

The systemd unit runs as root because configured owners and `systemctl reload` need it, but with
`ProtectSystem=strict`, `NoNewPrivileges=yes`, private `/tmp`, restricted address families and
`@system-service` system calls. Its base writable path is only the state directory. The installer
adds the enrollment webroot to `10-paths.conf`. Whenever you add or change `paths`, update that
drop-in to contain **exactly the state, webroot and deployment parent directories**, then run
`systemctl daemon-reload` and restart. When a hook runs nginx, also add `/var/log/nginx`, because
`nginx -t` opens its log files:

```ini
[Service]
ReadWritePaths=/var/lib/myownpki-agent /var/www/html /etc/nginx/myownpki /var/log/nginx
```

Do not make `/etc`, `/var` or `/` writable. The sandbox prevents writes outside the allowed paths
and thereby contains filesystem mistakes in the agent. It is **not a security boundary against
code running as root in the agent process**: `systemctl reload` needs access to systemd over D-Bus,
and the same access would also allow `systemd-run`. The actual protection is that the agent accepts
no commands from the server and runs hooks only from the root-owned `agent.yaml`.

Standalone mode needs the packaged `agent-low-ports.conf` drop-in for `CAP_NET_BIND_SERVICE`;
webroot mode does not. Hooks run inside this sandbox. In v0.3.0, hooks using `sudo` or another user
switch do not work with `NoNewPrivileges=yes`.

CI runs `systemd-analyze verify` and `systemd-analyze security myownpki-agent.service`. The full
report and measured overall exposure are documented in the **agent end-to-end** job summary for
each run; values can differ between systemd releases. No unmeasured local value is claimed here.

### 12.4 Firewall

| From | To | Port | Purpose |
|---|---|---|---|
| Agent host | Server | 8444/tcp | agent channel with mTLS |
| Agent host | Server | ACME HTTPS port (443 or the reverse proxy) | certificate orders |
| Server | Agent host | 80/tcp | http-01 for enrollment and orders |

Nothing else needs to be opened on the host. Standalone port 80 is listened on only while a check
runs; the web server must answer it in webroot mode. The agent makes outbound connections; the
server never connects to an administrative agent port.

### 12.5 Status and troubleshooting

```bash
myownpki-agent config check
myownpki-agent status
systemctl status myownpki-agent
journalctl -u myownpki-agent -n 100 --no-pager
```

Check the agent page in the UI for last seen, version, deployment state, serial, expiry and last
error. Reports arrive every five minutes with jitter and immediately after a pass; *silent* means
three missed reports. An open renewal on a silent agent stays pending and can be withdrawn.

- **TLS trust or hostname errors:** compare `ca_bundle` with the root and `server` with the listener
  certificate's DNS name. A bootstrap certificate is not accepted.
- **Enrollment waits for approval:** approve it under *Enrollment requests*; `run` finishes it.
- **http-01 fails:** check DNS, the server-to-host port 80 route, webroot contents and the domain
  policy. In webroot mode the directory must exist and be below `paths`.
- **Name refused:** the ACME server checks every name against *Names it may order* at order and
  issuance. Add the exact name or a suitable `*.suffix` pattern; the UI marks uncovered names.
- **Permission or sandbox errors:** compare `ReadWritePaths` with every target and webroot. Include
  `/var/log/nginx` for nginx hooks. Hooks with `sudo` are unsupported.
- **Deployment rolled back:** inspect the original and rollback errors. The old files and leaf are
  restored when possible; fix configuration/material before the next attempt.
- **Rate limited:** reports and watches are limited per agent to 60 and 120 calls per 10 minutes;
  ordinary scheduling stays well below this. Look for a second process or a broken client loop.

### 12.6 Revoke and enroll again

*Revoke agent* is permanent for that agent ID, puts its agent certificates on the agent CA's CRL
and cuts it off at its next call. **Certificates already deployed stay valid**; revoke those
separately only when intended. *Disable* is the reversible alternative.

To enroll the host as a new agent, create a new join token, stop the service and remove the old
identity and account binding:

```bash
sudo systemctl stop myownpki-agent
cd /var/lib/myownpki-agent
sudo rm -f agent.json agent.key agent.crt pending.key enrollment.json
sudo rm -f acme-*.key acme-*.json
sudo myownpki-agent enroll --token-file /root/myownpki-join-token
sudo systemctl start myownpki-agent
```

The `acme-<directory-hash>` files must be removed together because the old ACME account belongs to
the revoked agent ID. Keep `deployments.json`, `deployment-journal.json`, `deploy-backup-*` and
`webroot-files.json`: they carry deployment history, rollback data and crash cleanup state. Delete
those only as part of a separate, manually verified reset of deployment state.
