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
| Public listener | CRLs and CA certificates over plain HTTP, no login; the trust portal at `/` ([chapter 11](#11-the-public-trust-page)) | `:8080` |
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
v=0.3.9
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
- It also downloads the exact release's agent `.deb`, `.rpm` and tarball for both Linux amd64 and
  arm64, verifies every one against the same `checksums.txt`, and publishes the complete set at
  `/var/lib/myownpki/agent-dist`. A missing, wrong-version or changed artifact stops installation.
  During a server update the previous complete set is retained and restored if the update rolls
  back; the installer never installs or enrolls an agent on the PKI server itself.
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

The container image and `deploy/docker-compose.yml` are in the README. The image already contains
the same exact-version agent artifacts and `checksums.txt` under `/opt/myownpki/agent-dist`, with
`agent.package_dir` pointing there. They are read-only to the non-root server and need no runtime
download. By hand – another init system, FreeBSD, macOS, Windows:

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

### Step-up confirmation lifetime

Sensitive actions need a fresh second factor. A tenant admin chooses how long that confirmation
stays valid in *Administration → Tenant settings*: **5, 10, 15, 30 or 60 minutes**, default **5**.
The same value is available as `step_up_minutes` in `GET` and `PUT /api/v1/settings`; viewers and
operators can read settings but cannot change them. Every change is audited as `tenant.settings`
with the old and new values.

The lifetime is snapshotted with each TOTP, recovery-code or passkey proof. Changing the setting
affects only proofs created afterwards: an existing confirmation neither gains nor loses time, and
`step_up_valid_until` in the session API shows its actual expiry. Existing sessions upgraded from an
older release keep the previous five-minute lifetime.

The agent enrollment mode (`agent_enrollment`: `verified`, `auto` or `manual`, chapter 12) is the one tenant
setting that needs a fresh proof: `auto` admits a host without a person, which weighs as much as approving
an enrollment. Saving the settings with a different mode asks for the code first; saving them with the mode
as it is, or any other setting alone, does not. `PUT /api/v1/settings` with a different `agent_enrollment`
answers `403` `step-up-required` to a session without a fresh proof and `403` `forbidden` to an API token,
whatever its role, and stores nothing. A script that sets the mode has to stop doing so: change it in the UI.
The audit entry `tenant.settings` names the old and the new mode (`was_agent_enrollment`,
`agent_enrollment`).

In the web UI, a protected form that needs a fresh proof opens a confirmation page naming the action
and its non-secret target. A correct code runs that action once; there is no need to fill in the form
again. Downloads and one-time secrets appear in the continuation response as before. The pending
action is bound to the session, user and credentials generation, is protected by CSRF, and expires
after **5 minutes regardless of the longer proof lifetime above**. It exists only in server memory:
a restart, expiry, changed credentials or another session requires starting the action again. A
failed business action is consumed too, so retrying cannot repeat it accidentally. REST behavior is
unchanged: API clients repeat the original operation with a fresh proof.

A session has at most one open confirmation: starting another invalidates the previous pending ID.
The server keeps at most **64** pending actions and **64 MiB** of pending legacy archives in total;
when either budget is full, the form reports “too many open confirmations – try again later” without
replacing existing state. Expired entries and their archive bytes are reclaimed whenever an action
is created, read or consumed.

### Health checks and monitoring

```bash
myownpki healthcheck --config /etc/myownpki/config.yaml
```

Asks `/healthz` of the admin listener on this machine; exit code 0 = healthy, 1 = not. It checks
the connection against the exact certificate file the server serves (no CA involved), so it never
talks to something else on the port. `/healthz` says nothing about the seal state on purpose – a
sealed server is healthy but can't sign. Since v0.3.3 the server reports that itself, and a CRL that
gets old, expiring certificates and silent agents too: by e-mail or webhook, see
[chapter 13](#13-monitoring-and-notifications). Watching the process from outside (`healthcheck`, the
log) stays useful for a server that is down.

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

Restore into an **empty or missing** data directory, with the server stopped. With the packaged
install (§2.1) stop the service, move the old data directory away, create an empty one, run
`restore` **as root** – not as the service user: it builds its work copy next to the data directory
(in `/var/lib`), which the service user cannot write to – and hand the result back:

```bash
systemctl stop myownpki
mv /var/lib/myownpki /var/lib/myownpki.old
install -d -m 0700 -o myownpki -g myownpki /var/lib/myownpki
myownpki restore /backup/myownpki-2026-10-21 --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
chown -R myownpki:myownpki /var/lib/myownpki
systemctl start myownpki
```

(`restore` replaces the empty directory by the restored one, which belongs to root until the
`chown -R`; a data directory owned by someone else also makes `install.sh` refuse to continue.)
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

From v0.3.8 to v0.3.9: no migration, no configuration change and no change to the agent protocol (`myownpki db status`
shows the same versions), so going back needs no restore. The release turns the page at `/` of the public listener
into the trust portal ([chapter 11](#11-the-public-trust-page)): the setting `trust_page` keeps its name and meaning but
has a new label, the downloads and the Windows helpers have new file names with the first 8 hex digits of the
certificate's SHA-256 (`/ca/…` URLs unchanged), and the page has new headings. It also adds `trust install`,
`trust remove`, `trust status`, `setup --system-trust`, the `agent.yaml` key `system_trust` and the pillar key
`system_trust` ([§12.12](#1212-the-root-in-the-system-trust-store)). **Update the agents before you enable
`system_trust`:** an agent of v0.3.8 or older refuses an `agent.yaml` with that key (unknown keys are errors on
purpose) and does not start. Nothing changes on an agent until you ask for it. To go back to an older agent, remove the key first:
`trust remove` does it and also takes the root out of the store. Update the server first, as always.

From v0.3.7 to v0.3.8: pki.db migration 0020 adds two indexes (`certificates_created_at` and the partial
`acme_orders_certificate`) for the issuance chart; it is indexes only, so no column, row or constraint changes.
There is no configuration change and no change to the agent or its protocol. The release adds the *Reports* and
*Analysis* pages, two charts on the dashboard and `GET /api/v1/reports` and `GET /api/v1/analysis`
([chapter 15](#15-reports-and-analysis)); they need the tenant-wide read permission and nothing to set up. An older
binary refuses the migrated database, so going back means the backup from step 1.

From v0.3.6 to v0.3.7: no migration and no change to the server's behavior (`myownpki db status` shows
the same versions), so going back needs no restore. The release adds dns-01 to the agent
([§12.11](#1211-dns-01-in-the-agent)), the `deployment add` flags `--challenge dns-01`, `--dns-*` and
`--check-name`, and the same options in the Salt formula. **Update the agent before you add a dns-01
deployment:** an agent of v0.3.6 or older refuses an `agent.yaml` that has `dns_providers`, `dns_provider`
or `check_name` (unknown keys are errors on purpose) and does not start. An existing `agent.yaml` works
with v0.3.7 unchanged. To go back to an older agent, remove the dns-01 deployments (`deployment remove NAME`)
and the `dns_providers` block first. Update the server first, as always.

From v0.3.5 to v0.3.6: no migration, no configuration change and no change to the server or the agent
code. The release adds the Salt formula in the repository ([§12.10](#1210-rolling-out-with-salt));
nothing uses it until you copy it to a Salt master. Update the server first, as always. With the
formula, updating the agents is a change of `version` and `package.sha256` in the pillar and a
`state.apply`: on an enrolled host it installs the verified package and runs `setup` again.

From v0.3.4 to v0.3.5: pki.db migration 0019 adds the columns `kind`, `max_uses`, `use_count`,
`revoked_at` and `revoked_by` to the join tokens (the enrollment pass, [§12.8](#128-enrollment-passes)).
It is additive: every existing token stays a single-use token, a used one counts as one use, and no
certificate, agent or enrollment changes. Nothing needs to be configured. **Update the server first.**
An agent of v0.3.4 keeps reporting and nothing changes on it, but `deployment`, `sandbox sync`,
`setup --acme-directory` and the `sandbox:` key of `agent.yaml` need the v0.3.5 agent
([§12.7](#127-adding-a-host)).

**Run `setup` once on every existing agent** (*Agents → Update* shows the commands) to get the
drop-in fixes. On a host that was set up before v0.3.5 the update now behaves like this:

- `10-paths.conf` is no longer rewritten from `agent.yaml` alone. An entry you added by hand,
  typically `/var/log/nginx` for nginx hooks, **stays**, and `setup` says so: `Kept in 10-paths.conf
  (agent.yaml does not explain them): /var/log/nginx`. Directories that `agent.yaml` needs and the
  file lacks are appended (`Added to 10-paths.conf: …`). `myownpki-agent sandbox sync --adopt` writes
  the kept entries into the `sandbox:` block of `agent.yaml`, so that the file explains them.
- `20-low-ports.conf` stays when `setup` is run without `--low-ports` and enrollment uses webroot.
  v0.3.4 removed it then, although the nginx hooks need it. A standalone challenge of a deployment
  now also counts as a reason to install it, not only the enrollment's.
- A file that already holds everything is not rewritten, and an `20-low-ports.conf` that differs from
  the packaged one is not overwritten (`setup` says so).

Going back to v0.3.4 means the backup from step 1, because v0.3.4 refuses the newer `pki.db`; a
v0.3.4 agent binary also refuses an `agent.yaml` that has a `sandbox:` block (remove the block first).
One setting changed its rules in this release: switching the agent enrollment mode needs a fresh
second factor and no API token can do it (§4, *Step-up confirmation lifetime*).

From v0.3.3 to v0.3.4: pki.db migration 0018 adds the table for the TLS scan's endpoints; it is
additive and changes no certificate. Nothing needs to be configured: the scan starts with no endpoint
and connects nowhere until an admin enters one ([chapter 14](#14-tls-scan)), the new `monitor.scan_*`
keys have defaults, and the permissions `endpoint.manage` (admin) and `endpoint.scan` (operator, admin)
come with the built-in roles. **One behavior change:** the address guard that http-01 validation, the
agent enrollment check and the scan share now refuses more ranges outright: the IPv6 forms that embed
or translate to an IPv4 address (NAT64, IPv4-compatible, 6to4, Teredo, IPv4-translated), an address with
a zone, and the non-global ranges `192.0.0.0/24`, `198.18.0.0/15`, `192.88.99.0/24`, `fec0::/10`,
`100::/64` and `5f00::/16` (the full list is in §14.8; the documentation ranges stay allowed). A service
that really lives in such a range can no longer be an http-01 target or an enrollment host. Going back to v0.3.3 means the backup from step 1, because
v0.3.3 refuses the newer database.

From v0.3.2 to v0.3.3: system.db migration 0014 adds the tables for alerts and queued
notifications; it is additive and changes no certificate. No configuration change is needed. Alerts
start with the first check, one minute after the start, and the server tells nobody until you
configure `notify:` ([chapter 13](#13-monitoring-and-notifications)). The first message after you do
lists every alert that is open then. Expect a `sealed` alert if you leave the freshly updated server
sealed for more than 10 minutes, and `agent_silent` for agents that stopped reporting. The container
image sets no `notify` values; add the `MYOWNPKI_NOTIFY_*` variables to your Compose file.

From v0.3.1 to v0.3.2: no migrations and no configuration change. Update the server first, as
always: until then the agent listener of a v0.3.1 server serves no agent packages, so guided
installation and package updates of agents need the server at v0.3.2.

From v0.3.0 to v0.3.1: system.db migration 0013 adds independent predecessor defaults; pki.db
migrations 0014–0017 add revocation plans and accepted deployment history (0014), the installed
package format (0015), check-less written proof (0016) and optional per-account predecessor
policies (0017). All are additive: existing certificates and revocations are unchanged and an
unchanged agent serial creates no plan or revocation. The owner-confirmed factory values are agent:
immediate after confirmed deployment; other certificates: after seven days. Review both defaults
under *Administration → Tenant settings* after upgrading.

**Update the server before the agents.** Mixed operation is supported: v0.3.0 agents keep sending
valid TLS `served_fingerprint` values, which always take precedence even without the newer
`check_configured` field. Newer agents add `written_fingerprint` only for check-less deployments;
older agents with neither proof field cause no predecessor action. Do not revoke certificates merely
because an older agent has not reported the new fields.

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
v0.2.2 the trust page at `/` of the public listener walks every platform through it, since v0.3.9 as the trust portal ([chapter
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
| Addresses http-01 may reach | *internal networks too* (homelab) or *public only* – some ranges are never reached under either setting (loopback, link-local and more; the full list is in §14.8; the agent enrollment check and the TLS scan follow the same setting) |
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

For a non-agent ACME account, a completed order is a predecessor renewal only when an older valid
order of **the same account** has the identical normalized, sorted, duplicate-free DNS/IP name set.
The tenant's *Other certificates* predecessor policy applies at issuance: immediate, after 1–30 days,
or never, always with reason `superseded`. An admin can override it per non-agent account on the
account page or with `GET`/`PUT`/`DELETE /api/v1/acme/accounts/{id}/predecessor-policy`, audited and
with step-up. **Use one account per host:** multiple hosts sharing an account and exact name set
schedule or revoke each other's predecessors; choose `never` when that is not intended. No ACME
extension or client setting is needed. A similar name, a subset/superset or another account never
selects a predecessor. Agent-linked accounts wait for the deployed report instead (chapter 12).

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
  (e.g. certbot-dns-cloudflare), as long as `acme.resolver` sees that zone. Since v0.3.7 the agent
  writes the record itself (RFC 2136 or Cloudflare), so an agent host needs no client-side plugin:
  [§12.11](#1211-dns-01-in-the-agent).
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
| `connection: … address policy … refuses` | The name resolves to a range that is never reached (loopback, link-local and others; the list is in §14.8), or to a private address on a *public only* domain | The domain's address setting |
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
that everybody may open without signing in. Since v0.3.9 it is the **trust portal**: it guesses the
visitor's platform, shows the steps and commands for it, and serves a configuration profile for iPhone,
iPad and Mac. Send people there instead of mailing root files ([§11.2](#112-the-portal-page-and-its-routes)):

- every active CA, **roots first**: name, common name, validity, DER and PEM downloads, and the
  authoritative **SHA-256 fingerprint** of every root; after a root renewal also the older generation
  while it is valid. The SHA-1 value is shown with the Windows steps only, for comparison with the Windows
  certificate dialog;
- the downloads as DER (`/ca/<name>/<generation>.crt`, the URL in every certificate's AIA, unchanged)
  and PEM (`/ca/<name>/<generation>.pem`);
- the steps and commands for Windows, macOS, iPhone and iPad (including *Certificate Trust Settings* –
  without that step iOS installs a root but doesn't trust it for websites), Android, Debian and Ubuntu,
  Fedora and RHEL, Firefox and Java, **for every root shown**;
- per root a configuration profile ([§11.3](#113-the-configuration-profile)) and two **Windows helpers**
  (`.cmd`, [§11.1](#111-the-windows-helpers)): *this computer* (LocalMachine, asks for administrator
  rights itself) and *my user only* (CurrentUser, no administrator rights);
- intermediates as a table of downloads only: servers send them, nothing is installed.

Only public data, no JavaScript, a strict Content Security Policy (`default-src 'none'`, the own
stylesheets and logo only, no `script-src`).

**Switch it off** in *Administration → Tenant settings*, setting `trust_page` (label: *Trust portal at /
of the public listener (CA certificates, fingerprints, install steps per platform)*; help text: *Covers the
portal page at /, its ?os= choice, the configuration profile for iPhone, iPad and Mac, and the Windows
helpers. The downloads under /ca/ and /crl/ stay served either way: certificates point to them.*), or
through the API (`PUT /api/v1/settings` with `"trust_page": false`). It is asked on every request, so a
change applies at once. Off, `/`, `/?os=…`, the profile and the Windows helpers answer 404 (the same 404 as
for a path that never existed); the CA certificates, their PEM copies and the CRLs stay – certificates point
to them – and so do the page's stylesheets and logo under `/static/`.

> **PKI background – why compare the fingerprint.** A root is the anchor every check ends at:
> whoever slips you a false root can impersonate every website for you. The page comes over plain
> HTTP (it must work before anything trusts your PKI), so someone in the network path could change
> it, **the fingerprints on it included**. The fingerprint is the check, but only when you compare it
> with one you got another way: the admin UI (*Authorities*, the root, which also has a ready-made
> *Message for your users*), `myownpki ca show NAME` on the server, a printout, your administrator.
> The first block of the page says exactly this.

### 11.1 The Windows helpers

Each `.cmd` is one file that is both a batch file and a PowerShell script. It contains no expected
fingerprint. Double-clicked, it:

1. computes SHA-256 and SHA-1 from the embedded certificate's DER and shows both; SHA-1 is only for
   the Windows dialog and never authorizes import;
2. requires either `-ExpectedSha256 <value>` matching the exact 64-hex **Root SHA-256 for automation**
   on the authenticated root CA page, or an interactive `YES` after your independent SHA-256 comparison;
3. stops before the store on a malformed value, mismatch, changed certificate, missing/negative answer,
   EOF, or any other input (argument error 64, mismatch 2, missing authorization 3);
4. *this computer*: asks for administrator rights (UAC), forwards the validated expected value and
   `/quiet`, and recomputes/reauthorizes in the elevated child;
5. only then imports the root into *Trusted Root Certification Authorities* of the computer or user.

`/check` displays both values and performs any supplied expected-value check but never imports.
`/quiet` suppresses the final pause; it never replaces independent authorization. A matching expected
value imports noninteractively. Any unknown argument or missing parameter value stops with exit 64.
The file is ASCII with CRLF line ends. Check a downloaded helper without importing:

```bat
cmd /c root-1a2b3c4d-trust-computer.cmd /check
cmd /c root-1a2b3c4d-trust-computer.cmd /check -ExpectedSha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Windows may warn about a downloaded `.cmd` (SmartScreen, *Unblock* in its properties) – that is
normal for scripts from the network. Use only the SHA-256 value from the authenticated admin UI or
another independent channel; never copy an expectation from the download page or helper itself.

The portal's PowerShell and shell blocks ([§11.2](#112-the-portal-page-and-its-routes)) are different on this
point: they **do** contain the root's SHA-256, taken from the page, and only check the download against it. That
does not contradict the rule above, which is about the helpers: the embedded value shows that a download matches
the page, not that the page is genuine, and every block says so. The helpers keep the stricter path (a value
from the admin UI that you give them).

### 11.2 The portal page and its routes

| Route | What it serves |
|---|---|
| `/` | The portal. One optional query value `os` selects a platform |
| `/ca/<name>/<generation>.crt`, `.pem` | DER and PEM of a CA certificate (always served, also with the portal off) |
| `/crl/<name>/<generation>.crl` | The CRL (always served) |
| `/trust/<name>/<generation>/machine.cmd`, `user.cmd` | The Windows helpers of a root ([§11.1](#111-the-windows-helpers)) |
| `/trust/<name>/<generation>/profile.mobileconfig` | The configuration profile of a root ([§11.3](#113-the-configuration-profile)) |
| `/static/styles/…`, `/static/brand/…`, `/favicon.ico` | The stylesheets and logo of the page |

The helpers and the profile are served for **roots** only, and only for a generation the page lists. An
intermediate never gets a command, a helper or a profile.

**The platform.** The server reads the `User-Agent`: only its first 512 bytes count, ASCII letters are folded to
lower case, and an ordered list of fixed substrings decides, the first match wins. No regular expression is
used, so there is no backtracking, and no part of the header is kept or written anywhere.

| The header contains | Platform |
|---|---|
| `iphone`, `ipad`, `ipod` or `like mac os x` | iPhone and iPad |
| `android` | Android |
| `windows` | Windows |
| `macintosh` or `mac os x` | macOS |
| `cros` | none (ChromeOS) |
| `ubuntu` or `debian` | Debian and Ubuntu |
| `fedora`, `red hat` or `centos` | Fedora, RHEL, Rocky and Alma |
| `linux` or `x11` | Linux: both families are shown |

`firefox/` (not on iOS) is a flag, not a platform: the page adds a note that Firefox keeps its own list of
authorities. The result is a guess and the page says so; an iPad that asks for the desktop version of web sites
sends a Mac string and is shown macOS steps (the macOS block names this case).

**The choice.** `/?os=<value>` with one of `windows`, `macos`, `ios`, `android`, `debian`, `fedora`, `firefox`,
`java` or `all` overrides the guess (`all` shows every platform). Anything else – an unknown value, an empty
one, a repeated one, one longer than 16 bytes – counts as not given. The value is compared with that list and
never echoed. With neither a choice nor a guess the page shows the list of systems and no steps.

**The commands.** Each block for a root carries only values from the database: the root's SHA-256, its download
address (the CA's public base URL plus `/ca/<name>/<generation>.crt`, the base URL inside its certificates,
never the `Host` header of the request) and its name. The base URL must be `http` or `https`, with a host of
letters, digits, dots and hyphens, an optional port and an optional path of letters, digits and `._~/-`; the
name must be a valid CA name. Otherwise the block shows no command and says to compare the file by hand. The
Linux, macOS and Java chains are joined with `&&`, so a failed check stops everything after it, and every chain
starts with `tmp=$(mktemp -d) && cd "$tmp"`: the download, check and install happen in a new private
directory. That directory is **not removed** afterwards. Windows uses one PowerShell `if`/`else` statement
that imports into `Cert:\CurrentUser\Root`, or `Cert:\LocalMachine\Root` in a PowerShell started as
administrator.

**File names.** The files the commands create are `myownpki-<name>[-<generation>]-<8hex>.crt` (Debian family) or
`.pem` (RedHat family): the generation appears for an older generation only, and the last part is the first 8
hex digits of the certificate's SHA-256, so two certificates never get the same name (the CA `root-2` at
generation 1 and the CA `root` at an older generation 2 would both be `root-2` without it). The downloads of the
page, the profile and the Windows helpers use the same base name: `<name>[-<generation>]-<8hex>.crt`, `.pem`,
`.cer` (the DER file Windows opens with its certificate dialog), `.mobileconfig`, and
`<base>-trust-computer.cmd` and `<base>-trust-user.cmd`.

**Headers and caching.**

| Response | Headers |
|---|---|
| The page | `Vary: User-Agent` always; `Cache-Control: private, max-age=300` when the `User-Agent` told the page something (a platform or Firefox) and no `?os=` was given, `public, max-age=300` otherwise; an `ETag`; `HEAD` and `If-None-Match` work. The strict CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` |
| The profile, the helpers | `public, max-age=900` with an `ETag`; the profile as `application/x-apple-aspen-config` with `Content-Disposition: attachment`, the name built from the validated CA name |

A shared cache in front of the listener (a reverse proxy that caches) may therefore serve the profile and the
helpers for up to 15 minutes, and a page it stored as `public` for up to 5 minutes, **after you switched the
portal off**.

**No redirects, no state.** None of the portal's own routes redirects, and no response of it has a `Location`
header. The router in front of them (Go's `ServeMux`) answers `307` for a path that is not clean, such as
`//ca/root/1.crt` or `/a/../ca`, before any route runs. A request writes nothing: no log line, no counter, no
audit entry. **There is no rate limit on the public listener** (its timeouts and its 8 KiB header limit apply);
a server that is reachable from the internet should be limited in its reverse proxy.

**The root's page in the admin UI.** *Authorities*, a root: the row *Trust portal* shows the address (the root's
public base URL plus `/`), *Switched off in Administration → Tenant settings.* while `trust_page` is off, *This
root is not offered on the portal (status: …)* when the portal does not list it (the CA is not active, or its
certificate waits for its signature, is revoked, is not valid yet or has expired), or a hint without an address
when the base URL is empty or not a plain `http://` or `https://` address. The block *Message for your users*
below the properties is a plain text to copy into a mail or a wiki page: the address, the root's name, its
SHA-256 fingerprint, a sentence to compare it with the value on the page before installing, and a sentence about
the second step on an iPhone or iPad. It is escaped text, with no script and no clipboard button, and it is not
shown for an intermediate or while the portal does not offer the root.

### 11.3 The configuration profile

`/trust/<name>/<generation>/profile.mobileconfig` is generated from the root's certificate on every request and
contains **only the public certificate**: one `Configuration` dictionary with a single payload of the type
`com.apple.security.root`. The display name is the common name (control characters removed, at most 64
characters), the identifier is `local.myownpki.root.<first 32 hex digits of the SHA-256>`, and the UUIDs are
derived from the SHA-256 (the first 16 bytes of a SHA-256 over a fixed label and the fingerprint, with the
version nibble 8 and the variant bits set). There is no date, host name, serial number or scope, no other payload
type, and `PayloadRemovalDisallowed` is `false`: the user can always remove it. The same root gives the same bytes
every time, so installing it again replaces the profile; a renewed root has another fingerprint and can be
installed next to the old one.

The profile is **unsigned**, so iOS, iPadOS and macOS show it as *Not Signed*. A signature would need a
certificate the device already trusts, which is what is missing. On iOS and iPadOS the second step is on the page
and in the admin message: *Settings, General, About, Certificate Trust Settings*, then switch the root on; without
it the root is installed but not trusted for web sites. On a Mac, if Keychain Access still shows the certificate
as not trusted, set *When using this certificate* to *Always Trust*. How a real device shows the profile, which
menu names it uses and what macOS does with a profile that names no scope were not tried on a device.

## 12. Agent

`myownpki-agent` enrolls a Linux host, obtains certificates through ACME with http-01 (since v0.3.7
also with dns-01, [§12.11](#1211-dns-01-in-the-agent)) and installs them with the `nginx` or `file`
profile. It writes only below local `paths`, runs only hooks from
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
  package_dir: /var/lib/myownpki/agent-dist  # exact-version downloads staged by install.sh
```

Unseal the server so it can issue both certificates. `myownpki config check` and startup check the
agent CA and its EKU limit. Also configure ACME (chapter 10) and a domain covering every name the
agent may order. Agents use the same root as trust anchor for the agent and ACME listeners.

The agent listener anonymously serves only `GET` and `HEAD` for the six exact-version artifacts and
`checksums.txt` below `/agent-packages/`. There is no directory listing, arbitrary path, redirect,
upload or symlink following; missing or incomplete development directories return 404. These public
reads do not change enrollment or any other RPC's existing mTLS authentication. Package sizes are
bounded. Set `MYOWNPKI_AGENT_PACKAGE_DIR` instead of editing YAML when using environment overrides.

### 12.2 Guided and verified installation

Since v0.3.5 the default is *Agents → Add host*, the assistant of [§12.7](#127-adding-a-host): it asks
for the service as well, shows the same verified install and `setup` commands plus the
`deployment add` command, and follows the host until its certificate is deployed. The page described
in the rest of this section, *Agents → Install agent*, is unchanged and still available. An admin
chooses the exact host FQDN, Linux architecture, package format and standalone/webroot enrollment,
then confirms with a fresh second factor. The result contains the complete root download/fingerprint
check, verified package and `checksums.txt` downloads, package-manager or tarball installation, and
`myownpki-agent setup` commands. Run them as root on the target host, not on the PKI server.

The root SHA-256 and package SHA-256 shown in that authenticated response are independent expected
values. The downloaded certificate and `checksums.txt` never supply their own authorization values:
the root arrives over HTTP and is accepted only when its DER SHA-256 matches the UI literal; package
downloads then use HTTPS with that verified root and are checked against the independent package
literal before installation. The response also shows root SHA-1 solely for Windows dialog comparison;
it is never used by a command or authorization check. Do not substitute a value from a download page
or an unauthenticated source.

The optional guided join token is scoped to exactly that hostname, works once and expires after 15
minutes. It appears only in the one-time, `no-store` response. Write it with the displayed here-doc
to `/root/myownpki-join-token`, mode 0600; setup receives only `--token-file`. The token never goes
into an argument, URL, action summary, report or access log, and later pages cannot show it again.
Tokenless guided commands still require fresh step-up. The alternative *Agents → Join tokens →
Create token* flow remains available for exact names or patterns such as `*.apps.homelab.lan`; store
its secret the same way and never put it in `agent.yaml` or on a command line. Its one-time page shows
the same root check and a `setup` command for a host where the package or tarball is already
installed: it writes the token file, detects the installed format, and passes `--hostname` for a
token with one exact name (otherwise `hostname -f`, which must match one of the patterns).

What admits a host is the tenant's enrollment mode (*Administration → Tenant settings*,
`agent_enrollment`). In `verified`, the default, a host needs a valid token (or pass, [§12.8](#128-enrollment-passes))
**and** a passed http-01 check; with only one of the two it waits in *Enrollment requests* for an
admin. `auto` admits a host that has either (a pass always needs the check), so a machine that answers port 80 for a name below one
of your domains gets in without a person; `manual` always waits. Because `auto` weighs as much as an
approval, **changing the mode needs a fresh second factor** and an API token can never change it
(§4, *Step-up confirmation lifetime*).

Download the root PEM independently and compare its fingerprint with the authenticated admin UI.
`setup` requires this expected value and checks SHA-256 over the certificate DER, not the PEM text.
The root file must contain exactly one self-signed CA certificate:

```bash
openssl x509 -in root.pem -outform DER | sha256sum
```

Download the matching Linux amd64/arm64 `.deb`, `.rpm` or agent tarball together with `checksums.txt`
and its signature. Verify `checksums.txt` with cosign as described in the README, then check the
selected artifact before installing it. Never pipe a download into a shell:

```bash
v=0.3.9
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
# Also download myownpki-agent_0.3.9_linux_amd64.deb (or the artifact you use).
sha256sum --check --ignore-missing checksums.txt
```

Install a package with `sudo dpkg -i myownpki-agent_0.3.9_linux_amd64.deb` or
`sudo rpm -Uvh myownpki-agent_0.3.9_linux_amd64.rpm`. Packages contain the binary, the pristine
`/etc/myownpki-agent/agent.yaml` conffile (`noreplace`), and unit/drop-in examples below
`/usr/share/myownpki-agent/examples`. They have no maintainer scripts and never enable or start the
service. For a tarball, verify and unpack it, then install `myownpki-agent` as
`/usr/local/bin/myownpki-agent`; its `deploy/` tree contains the same example sources. Packages and
tarballs run exactly the same setup code. Both put the binary at `/usr/local/bin/myownpki-agent`,
and the commands here and in the UI call it by that absolute path: root's `PATH` does not include
`/usr/local/bin` on every distribution (Debian 13, for example), and a bare `myownpki-agent` then
fails with `command not found`.

Run setup as root. Webroot enrollment is recommended when nginx already answers port 80:

```bash
sudo /usr/local/bin/myownpki-agent setup \
  --server https://pki.homelab.lan:8444 \
  --ca-bundle root.pem \
  --root-sha256 AA:BB:CC:... \
  --token-file /root/myownpki-join-token \
  --webroot /var/www/html
```

Without `--webroot`, enrollment uses standalone http-01 on port 80 and setup installs the
`20-low-ports.conf` capability drop-in. `--low-ports` installs it explicitly in webroot mode too.
Setup validates Linux/root, systemctl, all files, the FQDN and configuration before changing the host.
It writes files atomically with their required modes, installs the unit and writable-path drop-in,
and enrolls before enabling or starting anything. A pending enrollment leaves the service disabled
and prints `systemctl enable --now myownpki-agent` for use after approval; rerunning setup polls the
pending request. Admission enables and starts the service. An already-enrolled update keeps local
configuration and restarts it.

`--system-trust` adds the root that `setup` just verified to the host's system trust store and records
`system_trust` in `agent.yaml`, as the last step after enrollment (Debian and RedHat families, off by default,
[§12.12](#1212-the-root-in-the-system-trust-store)). An unsupported host is refused before any file is written.

The token file is deleted only when that invocation newly obtains admission; pending, failed, polled
and already-enrolled runs keep it. The initial `agent.yaml` has no deployments. Setup preserves every
customized existing file. The byte-identical pristine example shipped by a package may be replaced
exactly once with the host-specific configuration. There is no agent self-update. Setup records the
selected `--package-format` (`deb`, `rpm` or the default `tarball`) in the root-only state directory
and reports it through the additive agent protocol. Existing agents and old reporters are treated as
legacy tarballs; pki.db migration 0015 adds this metadata without changing enrollment state.

The agent list compares strict semantic versions, including prerelease ordering. It marks only an
older agent; equal or newer agents get no downgrade suggestion. An admin's update link generates the
same verified commands for the reported installed format and architecture, without a join token.
Update preserves `agent.yaml` and restarts an already enrolled service. There is no automatic update
or remote command.

`deploy/install-agent.sh` remains a deprecated v0.3.1 compatibility wrapper. It only downloads or
accepts a verified archive, checks its checksum/signature, installs the binary and forwards to
`setup`; it has no separate installation or enrollment logic and will be removed in a later
release.

### 12.3 agent.yaml and deployment profiles

The file is `/etc/myownpki-agent/agent.yaml`, state is `/var/lib/myownpki-agent` (0700, files 0600).
After editing, run `/usr/local/bin/myownpki-agent config check` and `systemctl restart myownpki-agent`.
Since v0.3.5 you do not have to write a deployment by hand: `myownpki-agent deployment add`
([§12.7](#127-adding-a-host)) adds it to this file and adjusts the systemd drop-ins in one step, and
[§12.9](#129-recipes) has ready-made ones for nginx, Postfix, Dovecot and Proxmox VE. Do not mix the
two ways for the same file in a configuration tool: either an admin uses `deployment add`, or Salt
renders the whole file and then runs `sandbox sync`, because a rendered file overwrites what `add` wrote.
The Salt formula ([§12.10](#1210-rolling-out-with-salt)) offers both and refuses the mix.

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

**dns-01 (since v0.3.7).** A deployment may set `challenge: dns-01` instead of `standalone` or `webroot`.
It then names an entry of the new top-level map `dns_providers` with `dns_provider`, takes no `webroot`,
and may carry wildcard names (`*.homelab.lan`, only with dns-01). The optional `check_name` is the SNI of
the local TLS `check`; it is required when every name is a wildcard:

```yaml
dns_providers:
  homelab-dns:
    type: rfc2136                 # or cloudflare
    credentials_file: "/etc/myownpki-agent/dns/homelab.yaml"
    nameserver: "192.0.2.53"      # rfc2136 only, required
deployments:
  - name: wild
    profile: nginx
    names: ["*.homelab.lan", "homelab.lan"]
    challenge: dns-01
    dns_provider: homelab-dns
    dir: "/etc/nginx/myownpki/wild"
    test_hook: nginx-test
    reload_hook: nginx-reload
    check: "127.0.0.1:443"
    check_name: "www.homelab.lan"
```

Every key of `dns_providers`, the credentials file and the DNS server settings are in
[§12.11](#1211-dns-01-in-the-agent).

`files.certificate` and `files.chain` are available when separate files are needed. Optional
`owner`, `group` and `key_mode` apply locally. Deployments sharing a nonempty reload hook are staged,
tested, reloaded and, on failure, rolled back as one group. Automatic renewal runs at 2/3 of the
lifetime or earlier when ARI requests it. *Renew now* uses the same path; failures back off rather
than retrying continuously.

**Predecessor handling.** The renewal confirmation offers *Revoke now*, *Revoke after N days*
(1–30) and *Never revoke*, preselected from the deployment override, then the agent override, then
the tenant agent default. The choice and day count are snapshotted for that one request and repeated
in the step-up summary. Agent-wide and deployment defaults are changed by an admin on the agent page
and audited. The separate *Other certificates* default applies to UI, REST and non-agent ACME
renewals. REST renewal bodies accept the same optional `predecessor` object (`choice`, `days`).

An agent predecessor is revoked or scheduled only after an accepted `deployed` report with a real
serial transition and exact deployment proof. With a configured TLS `check`, only a nonempty
`served_fingerprint` matching the stored certificate counts. Without `check`, the agent instead reads
the leaf back after its atomic write and reports `written_fingerprint`; the server accepts that only
for this check-less case. A served fingerprint always takes precedence when present, including a
v0.3.0 report that does not know `check_configured`; written proof is only the check-less fallback.
It never substitutes for a missing or wrong TLS fingerprint, and legacy agents with neither field
cause no predecessor action. The account, exact normalized order/deployment name sets and
server-recorded certificate age must all match.
Older never-deployed or discarded certificates of that exact deployment are included; every serial
currently served by any deployment of the agent is excluded. `failed` and `rolled_back` do nothing.
Missing, tied, duplicated or foreign-account mappings revoke and schedule nothing and are logged for
diagnosis. A delay starts at the accepted server deployment time, not at issuance or an agent-provided
timestamp. Repeated reports neither duplicate nor move plans.

A pending entry appears as **Revocation planned · date** on certificate lists/details and beside the
deployment. Use certificate status `planned` or the dashboard's seven-day count to review them. An
authorized operator can revoke now or cancel before execution; both need step-up and are audited.
REST exposes `revocation_planned_at` and `PUT`/`DELETE
/api/v1/certificates/{id}/revocation-plan`. Plans execute idempotently after restart and unseal;
revocation is committed before CRL signing, and the normal CRL scheduler publishes it. No report
fails merely because a CRL cannot yet be signed or a mapping is ambiguous.

When a hook fails, the last stderr lines are included as `output` in the agent log and in the
deployment's `last_error`, bounded to 1 KiB of valid UTF-8 without control characters. **Hooks must
not write secrets to stderr**, even with this filtering.

The systemd unit runs as root because configured owners and `systemctl reload` need it, but with
`ProtectSystem=strict`, `NoNewPrivileges=yes`, private `/tmp`, restricted address families and
`@system-service` system calls. Its base writable path is only the state directory. The drop-in
`10-paths.conf` lists what else it may write: `state_dir`, every entry of `paths`, and the optional
`sandbox.write` list. **Since v0.3.5 the agent keeps that file in step with `agent.yaml` for you**:
`setup`, `deployment add`, `deployment remove` and `sandbox sync` ([§12.7](#127-adding-a-host)) write
it, so editing it by hand is the exception. A file written by the agent looks like this:

```ini
# Written by myownpki-agent from agent.yaml (state_dir, paths, sandbox.write).
# Entries you add here by hand are kept; "myownpki-agent sandbox sync" shows them.
[Service]
ReadWritePaths=/var/lib/myownpki-agent /var/www/html /etc/nginx/myownpki /var/log/nginx
```

`paths` is what the **agent** may write (certificates, keys, webroot files). Directories that only a
**hook** writes go into the optional `sandbox:` block, which affects nothing but `ReadWritePaths`:

```yaml
sandbox:
  write: [/var/log/nginx]   # directories the hooks write; added to 10-paths.conf
  low_ports: true           # 20-low-ports.conf; unset: derived (see below)
```

`nginx -t` opens its log files, so a hook that runs nginx needs `/var/log/nginx` there;
`deployment add --recipe nginx` sets it. If `nginx -t` reports `Read-only file system` for its
temporary directories, add them too (`--sandbox-write`, for example the `/var/cache/nginx` and
`/var/lib/nginx` subdirectories). The agent refuses system roots such as `/`, `/etc`, `/var` or
`/home` as `--sandbox-write`, `--dir` or `--webroot` ([§12.7](#127-adding-a-host)). `config check`
prints the effective list and whether the drop-ins on disk match it.

**What the agent does with a file it finds.** An entry in `10-paths.conf` that `agent.yaml` does not
explain stays; the commands report it as `Kept in 10-paths.conf (agent.yaml does not explain them):
…`. `sandbox sync --adopt` records such entries under `sandbox.write`; `sandbox sync --prune`
drops them. Entries `agent.yaml` needs and the file lacks are appended (`Added to 10-paths.conf: …`).
A file that already holds everything is not rewritten, comments and other directives included. A
path with white space, quotes or `%` is refused before anything is written, because systemd would
split or expand it. If you do edit the file by hand, keep the `[Service]` section, run
`systemctl daemon-reload` and restart the agent.

Do not make `/etc`, `/var` or `/` writable. The sandbox prevents writes outside the allowed paths
and thereby contains filesystem mistakes in the agent. It is **not a security boundary against
code running as root in the agent process**: `systemctl reload` needs access to systemd over D-Bus,
and the same access would also allow `systemd-run`. The actual protection is that the agent accepts
no commands from the server and runs hooks only from the root-owned `agent.yaml`.

Standalone mode needs the packaged `agent-low-ports.conf` drop-in for `CAP_NET_BIND_SERVICE`.
The nginx test and reload hooks need it too, **also in webroot mode**: `nginx -t` opens the
configured listen sockets, so a listener on port 443 otherwise fails with `bind() ... Permission
denied`. The agent installs it as `20-low-ports.conf` when `sandbox.low_ports` is `true`, when the
enrollment **or any deployment** uses the standalone challenge, or when you pass `--low-ports` to
`setup` or `deployment add` (the recipe `nginx` does). It removes the file only when you set
`sandbox.low_ports: false` explicitly; otherwise it leaves the file as found, and a file that differs
from the packaged one is not overwritten. To install it by hand from the release archive:

```bash
sudo install -d -m 0755 /etc/systemd/system/myownpki-agent.service.d
sudo install -m 0644 deploy/systemd/agent-low-ports.conf \
  /etc/systemd/system/myownpki-agent.service.d/20-low-ports.conf
sudo systemctl daemon-reload
sudo systemctl restart myownpki-agent
```

Hooks run inside this sandbox. In v0.3.0, hooks using `sudo` or another user switch do not work
with `NoNewPrivileges=yes`.

CI first proves that `nginx -t` on port 443 fails without the low-port drop-in, then proves that it
succeeds with it. It also runs `systemd-analyze verify` and `systemd-analyze security myownpki-agent.service`. The full report and
measured overall exposure are documented in the **agent end-to-end** job summary for each run;
values can differ between systemd releases. No unmeasured local value is claimed here. The
**install** job separately downloads the served `.deb` from a real server, checks independent root
and package hashes, enrolls through `setup`, and updates an older enrolled agent on real systemd.

The optional top-level key `system_trust: {root_sha256: "<64 hex digits>"}` records that the root of this PKI was put
into the host's system trust store by `myownpki-agent trust install` or `setup --system-trust`
([§12.12](#1212-the-root-in-the-system-trust-store)). Absent means off. The running service ignores it, and an
agent older than 0.3.9 refuses it.

### 12.4 Firewall

| From | To | Port | Purpose |
|---|---|---|---|
| Agent host | Server | 8444/tcp | agent channel with mTLS |
| Agent host | Server | ACME HTTPS port (443 or the reverse proxy) | certificate orders |
| Server | Agent host | 80/tcp | http-01 for enrollment and orders |
| Agent host | the DNS server of a provider | 53/tcp | dns-01 with RFC 2136: the update and the SOA lookup |
| Agent host | the resolver (`resolver` or `/etc/resolv.conf`) | 53/udp, 53/tcp | dns-01: CNAME check, `propagation: resolver` |
| Agent host | the authoritative servers of the zone | 53/udp, 53/tcp | dns-01 with `propagation: authoritative` (default) |
| Agent host | `api.cloudflare.com` | 443/tcp, through `proxy:` if set | dns-01 with Cloudflare |

Nothing else needs to be opened on the host. Standalone port 80 is listened on only while a check
runs; the web server must answer it in webroot mode. The agent makes outbound connections; the
server never connects to an administrative agent port. The server-to-host port 80 row is not needed for a
deployment that uses dns-01 (the host still enrolls with http-01 or an approval); the four rows for
dns-01 are needed only for such deployments ([§12.11](#1211-dns-01-in-the-agent)).

### 12.5 Status and troubleshooting

```bash
/usr/local/bin/myownpki-agent config check
/usr/local/bin/myownpki-agent status
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
- **dns-01 fails:** `myownpki-agent config check` shows the state of each DNS credentials file; the
  error of the deployment names the provider and the problem and holds no secret
  ([§12.11](#1211-dns-01-in-the-agent)). A wildcard also needs the identical `*.` pattern in the agent's
  *Names it may order* and a domain with *Wildcards*.
- **Permission or sandbox errors:** `myownpki-agent config check` prints the effective `ReadWritePaths`
  and says whether the drop-ins match; if they differ, run `myownpki-agent sandbox sync` (§12.7). A
  hook that writes somewhere other than `paths` needs that directory in `sandbox.write` (nginx:
  `/var/log/nginx`). Hooks with `sudo` are unsupported.
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
sudo sh -c 'cd /var/lib/myownpki-agent && rm -f agent.json agent.key agent.crt pending.key enrollment.json acme-*.key acme-*.json'
sudo /usr/local/bin/myownpki-agent enroll --token-file /root/myownpki-join-token
sudo systemctl start myownpki-agent
```

The `acme-<directory-hash>` files must be removed together because the old ACME account belongs to
the revoked agent ID. Keep `deployments.json`, `deployment-journal.json`, `deploy-backup-*` and
`webroot-files.json`: they carry deployment history, rollback data and crash cleanup state. Delete
those only as part of a separate, manually verified reset of deployment state.

### 12.7 Adding a host

Four things take a new host from "nothing installed" to "certificate deployed": the *Add host*
assistant in the UI, the commands `deployment add|list|remove` and `sandbox sync` on the host, the
recipes ([§12.9](#129-recipes)) and, for a roll-out by a tool, the enrollment pass
([§12.8](#128-enrollment-passes)). They change nothing about the trust model: the agent still takes
no commands from the server, every path, hook and name comes from the root-owned `agent.yaml`, and
the UI only produces commands for **a person or a script on the host** to run.

**The Add host assistant.** *Agents → Add host* is the page `/hosts/add`. It is also a button on the
agent list and an entry in the *Agents* group of the menu, while agents are on and your role can read
them.

1. **Answers.** The host name (one exact, fully qualified, lower-case name that a domain of this PKI
   covers), the service (nginx, Postfix, Dovecot, Proxmox VE, or *certificate files only*), the http-01
   challenge (webroot with its directory, or standalone), up to four more certificate names (optional)
   and the agent package (`deb`, `rpm` or tarball with the architecture, or *already installed*).
   Nothing is stored for the assistant.
2. **Admission.** The page checks every name against the domains (a name with no domain, or a domain
   without http-01, is refused), shows the tenant's enrollment mode and a table of the three ways to be
   admitted:

   | Way | What it is | Approval after the host enrolled |
   |---|---|---|
   | Single-use token | Made now for the host and the extra names: works once, valid 15 minutes, its names become the names the agent may order. Creating it needs an **admin and a fresh second factor**. | none in `verified` and `auto`, once the host passed the check |
   | An existing enrollment pass | Offered when an active pass covers the host (shown by label and uses, never its secret) and the host has no agent. The host gets its own name only, so it is not offered with extra names. | none in `verified` and `auto`, once the host passed the check |
   | No secret | The host enrolls and waits in *Enrollment requests*. | one approval by an admin |

   In `manual` mode every way waits for an approval; in `auto` mode a host that passes the check is
   admitted whatever it brings. Extra certificate names need the token.
3. **Commands, shown once** (the answer to the form, `no-store`, never in a URL or on a later page): the
   token-file block (a here-document for a token, a `read -s` prompt for a pass, which the page never
   knows), the verified root and package download with `setup`, the `deployment add` block, and a last
   line, `/usr/local/bin/myownpki-agent deployment list`. Run them as root on the host. The `deployment
   add` block first makes the parent directory of the certificate files with `install -d -m 0755`, then
   runs, for example for nginx with a webroot:

   ```bash
   /usr/local/bin/myownpki-agent deployment add 'nginx' \
     --recipe nginx \
     --name 'proxy1.homelab.lan' \
     --challenge webroot --webroot '/var/www/acme' \
     --acme-directory 'https://pki.homelab.lan/acme/directory' \
     --restart
   ```

   The deployment is named after the service (`nginx`, `postfix`, `dovecot`, `proxmox`), or `files` for
   *certificate files only* (`--dir /etc/ssl/myownpki/<host> --key-mode 0600`, no hook). If `setup`
   ends with *Enrollment is pending*, the service stays disabled: after the approval run `systemctl
   enable --now myownpki-agent`.
4. **Progress.** `/hosts/add/<host>` follows the host and reloads itself every 10 seconds until the agent
   is online and every deployment is deployed:

   | Row | States |
   |---|---|
   | Host enrolled | waiting for the host, checking, waiting for your approval (with the source address, the secret it brought, the check result and the **Approve** and **Refuse** buttons), refused, expired, admitted, agent revoked |
   | Agent online | waiting for the first report, online (last seen, version), silent, disabled |
   | Certificate for deployment *name* | pending, deployed (serial, expiry, link to the certificate), failed or rolled back (the agent's last error, cut to 300 characters and shown as text) |

   The first visit counts as activity of your session; the automatic reloads, which use a separate
   `/status` route, do not keep it alive.

*Who may do what.* Anyone who can read the PKI tenant-wide (viewer and up) can open the assistant, get
the commands for *No secret* or *an existing pass* and watch the progress. Creating the single-use
token and approving or refusing an enrollment need an admin and a fresh second factor
(`agent.manage`); to everybody else those controls are not offered or answer `403`. The ordinary
*Enrollment requests* page keeps working as before.

**`deployment add NAME`** adds one deployment to `agent.yaml` and makes the systemd drop-ins match.
Linux and systemd only; run it as root, **also with `--dry-run`**.

| Flag | Meaning |
|---|---|
| `--recipe nginx`, `postfix`, `dovecot` or `proxmox` | Fills the defaults of [§12.9](#129-recipes). Every other flag overrides it. |
| `--profile nginx` or `file` | As in `agent.yaml`. Default: `nginx` with `--dir`, `file` with the file flags. |
| `--name FQDN` (repeat) | Certificate names, validated like `names:`; the first one is the SNI of the local check. Default: the host name of `agent.yaml`. |
| `--challenge webroot` or `standalone`, `--webroot DIR` | Default: what `enrollment:` uses. |
| `--dir DIR` | nginx profile: `fullchain.pem` and `privkey.pem` go here. |
| `--certificate`, `--chain`, `--fullchain`, `--key FILE` | file profile, as `files:`. |
| `--owner`, `--group`, `--key-mode` | As in `agent.yaml`; the key mode may not give rights to others. |
| `--hook NAME='CMD ARGS'` (repeat), `--test-hook NAME`, `--reload-hook NAME` | Define hooks and refer to them. The command is split on spaces and quotes, there is **no shell**, and the first element must be an absolute path. A command line that exists already is reused under its name, so deployments of one service share one reload and one rollback group. |
| `--check HOST:PORT` | Local TLS check. It is an **implicit-TLS** handshake, so STARTTLS ports (25, 143, 587) cannot be checked. |
| `--sandbox-write DIR` (repeat), `--low-ports` | Extra directories the hooks may write; `CAP_NET_BIND_SERVICE` for the hooks. Both are recorded in the `sandbox:` block of `agent.yaml`. |
| `--acme-directory URL` | Required when `agent.yaml` has none (`setup --acme-directory` writes it into a new file). |
| `--create-dirs` | Create missing directories instead of stopping. |
| `--dry-run` | Print a unified diff of `agent.yaml` and both drop-ins; write nothing. |
| `--restart` | Restart `myownpki-agent` afterwards. Without it the command prints `Apply it with: systemctl restart myownpki-agent`. |
| `--config FILE` | Another `agent.yaml`. |

Before it writes anything the command checks that `agent.yaml` parses and is valid now, that the name
is new, everything `config check` checks (names, targets under `paths`, hooks that exist, the key
mode), and that each directory it adds to `paths` is the parent of a target (for the nginx profile the
parent of `--dir`, which the agent creates) or a webroot, exists (or `--create-dirs`) and has no
symbolic link on its way. These system directories are refused for `--dir`, `--webroot`,
`--sandbox-write` and the parent of a target: `/`, `/etc`, `/usr`, `/var`, `/boot`, `/dev`, `/proc`,
`/sys`, `/run`, `/root`, `/home`, `/tmp`, `/bin`, `/sbin`, `/lib*`, `/opt`, `/srv`, `/mnt`, and
anything below `/proc`, `/sys` or `/dev`. A wide but legitimate directory such as `/etc/nginx` is
accepted with a warning that names a narrower one; `config check` shows the same list as warnings. A
hook that runs `nginx`, `apachectl`, `apache2ctl` or `haproxy` prints a hint when its log directory
(`--sandbox-write`) or `--low-ports` is missing.

It writes the two drop-ins first and `agent.yaml` second, so that a crash in between leaves a wider
sandbox, never a missing one; if the second write fails, the drop-ins are put back. The previous file
is kept as `agent.yaml.bak`. Comments and the order of keys in `agent.yaml` stay (blank lines inside a
block do not). A file with anchors, aliases, merge keys or several documents is refused. The command
runs `systemctl daemon-reload` when a drop-in changed and never restarts the agent unless you pass
`--restart`. On a host where the unit is not installed yet it writes the files and says so.

| You see | Because |
|---|---|
| `deployment add must run as root; nothing was changed` | Not root, also with `--dry-run` |
| `agent.yaml is not valid yet – run "myownpki-agent config check" and fix it first; nothing was changed` | The file fails the same check as `run` |
| `deployment "nginx" exists – pick another name or run "deployment remove nginx" first` | The name is taken |
| `--dir /etc: too broad – the agent may write only where "paths" allows; use a subdirectory such as /etc/ssl/myownpki` | A system directory |
| `/etc/ssl/myownpki does not exist – create it, or pass --create-dirs` | A directory it must add to `paths` is missing |
| `agent.yaml has no acme_directory – pass --acme-directory https://pki.homelab.lan/acme/directory` | Neither the file nor the flag has one |
| `hook "nginx-test": the first element must be an absolute path` | A hook command such as `nginx -t` |
| `agent.yaml uses anchors, aliases or several documents – edit it by hand and run config check` | The editor cannot keep such a file intact |
| `The unit is not installed (run setup first) – files written, systemctl skipped.` | Not an error: no `setup` ran on this host yet |

**`deployment list`** prints name, profile, names, targets, hooks and check of every deployment; it
only reads, so it also runs without root. **`deployment remove NAME`** removes the deployment from
`agent.yaml` (written first, the drop-ins second: a crash must never leave a deployment without its
sandbox) and recomputes the drop-ins. It keeps `paths` unless you pass `--prune-paths`, never touches
deployed files, certificates or the agent's state, and takes `--dry-run`, `--restart` and `--config`.
Delete the files by hand if you do not need them.

**`sandbox sync [--dry-run] [--adopt|--prune]`** recomputes `10-paths.conf` and `20-low-ports.conf`
from `agent.yaml` without changing a deployment. It is what a configuration tool runs after it has
rendered the file. An entry of `10-paths.conf` that `agent.yaml` does not explain is **kept** and
reported (`Kept in 10-paths.conf (agent.yaml does not explain them): /var/log/nginx`); `--adopt` writes
such entries under `sandbox.write` in `agent.yaml`, so that the file explains them, and `--prune` drops
them from the drop-in. The two exclude each other. `sandbox sync` has no `--restart`: run
`systemctl restart myownpki-agent` yourself.

**Existing hosts.** Nothing changes on a host until you run `setup` (the *Update* commands) or one of
the commands above. Then `setup` keeps a hand-made `ReadWritePaths` entry and an installed
`20-low-ports.conf`, says `Kept in 10-paths.conf …` and `Added to 10-paths.conf: …` for what it kept and
what it appended, and does not overwrite a `20-low-ports.conf` that differs from the packaged file. The
details are in [§9](#9-upgrading) and [§12.3](#123-agentyaml-and-deployment-profiles). To bring an old
host to the new model, look first, then let the file explain the entries:

```bash
/usr/local/bin/myownpki-agent sandbox sync --dry-run
```

```bash
/usr/local/bin/myownpki-agent sandbox sync --adopt
```

### 12.8 Enrollment passes

A single-use join token enrolls one host. For a roll-out by Salt, Ansible, a script or CI there is the
**enrollment pass**: one secret that lets a bounded number of hosts enroll **without anybody opening
the UI for each one**. It is a kind of join token (the same table, the same `--token-file`; the secret
starts with `mjp_` instead of `mjt_`); nothing changes in the agent or its protocol.

Create it under *Agents → Join tokens → New enrollment pass* (admin and a fresh second factor), or with
`POST /api/v1/agent-join-tokens` and `"kind": "pass"` from a signed-in session:

| Field | Rule |
|---|---|
| Label | Required, at most 64 characters. It says on the list and in the audit log what the pass is for. |
| Host names | 1 to 5, each an exact name or `*.suffix`. **A domain of this PKI must cover each one**; otherwise the creation is refused and names the pattern. |
| Hosts it may admit | 2 to 25, default 10. A larger fleet takes two passes. |
| Valid for | Up to 7 days, default 24 hours (the UI and the API take whole hours, 1 to 168). |

The secret appears once, in the answer to the form (or the `201` of the API), and only its SHA-256 is
stored. **What a use needs.** A host is admitted by a pass only when all of these hold:

- the pass is active: not revoked, not used up, not expired;
- the host name matches one of its names (`*.homelab.lan` matches `minion-01.homelab.lan` and names
  deeper below the suffix, never the bare suffix);
- the server's http-01 check of the host passed. This is required **in every mode** (in `auto` a passed
  check admits anyway; in `manual` everything waits for an admin), so a pass alone is never enough;
- the host has **no agent** that is not revoked (an active or a disabled one counts). A pass admits new
  hosts only; replacing a host stays a human act, with a single-use token or the approval queue.

A pass grants the host its **own name only**, not the pattern. Another name takes the single-use token
of the assistant or an admin on the agent page.

An enrollment that presents a valid pass takes one use, **also when it then waits in the queue**; a host
that enrolls again takes another. When the pass does not count, the enrollment is not lost: it waits in
*Enrollment requests* and `setup` prints the reason, for example `waiting for an admin to approve it in
the web UI (Agents) – the enrollment pass has no uses left (10 of 10) – ask an admin for a new one, a
passed check`. The reasons:

| Text | Cause |
|---|---|
| `the enrollment pass has no uses left (10 of 10) – ask an admin for a new one` | Used up |
| `the pass expired` / `the pass was revoked` | Expired, or revoked |
| `the pass is not for minion-01.homelab.lan` | The host name matches none of its names |
| `an agent for minion-01.homelab.lan exists – a pass admits new hosts only; ask an admin for a single-use token` | The host already has an agent |
| `unknown join token` | The secret is not one this server knows (a typo, another server, a withdrawn pass) |

*The list.* Each pass shows its state as `active 3 of 10`, `used up 10 of 10`, `expired …` or
`revoked …`, and below it the hosts it admitted or queued with where their enrollment stands.
**Revoke** (admin and second factor; `POST /api/v1/agent-join-tokens/{id}/revoke`, which answers `409`
for a pass that cannot admit anybody any more) ends its use at once. It does **not** touch the
enrollments and agents the pass already produced: they stay, listed with their state, and refusing or
disabling them is a separate, visible decision. A pass nobody used can also be withdrawn
(`DELETE /api/v1/agent-join-tokens/{id}`); a used one stays as a record.

*From automation.* An admin creates the pass in the UI with the second factor; the tool only consumes
it. **An API token can never create or revoke a pass**, whatever its role (`403`): that takes a person
with a fresh second factor, and tokens have roles, not scopes, so there is no narrower permission to
hand to a script. Give automation a **viewer** token that reads the result. A roll-out (with Salt, the
formula of [§12.10](#1210-rolling-out-with-salt) does steps 2 and 3 from a pillar):

1. Create the pass: label `salt rollout 2026-11`, names `*.homelab.lan`, 10 uses, 24 hours. Copy the
   secret.
2. Put it into the encrypted store of your tool. The tool writes `/root/myownpki-join-token` (mode
   **exactly 0600**) on a host only if the host has no `/var/lib/myownpki-agent/agent.crt` yet, then
   runs `myownpki-agent setup … --token-file /root/myownpki-join-token`. `setup` deletes the file when
   it newly gets admission; a host that stays pending keeps it.
3. Render `agent.yaml` (or run `deployment add`) and `sandbox sync`. Never both for one file.
4. Check with a viewer token:

   ```bash
   curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/agents?hostname=minion-01.homelab.lan"
   ```

   `GET /api/v1/agent-enrollments?hostname=…` shows the host while it waits, `GET
   /api/v1/agent-join-tokens` the pass with its uses and hosts, and `GET /api/v1/agent-install` the
   facts a script needs without a browser (server URL, ACME directory, the root with its SHA-256, the
   package files with their SHA-256; nothing in it is secret; `404` while the server has no packages).
5. Afterwards remove the pass from the store, and revoke it if it is not used up.

**The trade-off.** A pass admits actors without a person looking at each one. A leaked pass admits at
most as many more hosts as it has uses left, only for names that match, only if the server can fetch the
check file under that name (an attacker needs DNS or port 80 for it), never replaces an existing agent,
gives each host its own name only and dies at its expiry. Still, treat it like a key: short validity,
few uses, remove it after the roll-out. **If it leaks**, revoke it (second factor), read the list of
hosts it admitted, refuse the pending ones you do not know and disable or revoke the agents you do not
know.

*Audit.* `agent.token.create` (kind, maximum uses, names, expiry), `agent.token.revoke`, and the
`agent.enroll` entry of every enrollment, which names `token_id`, `token_kind`, the use (`3 of 10`), the
reason when the pass did not count, and the source address. The secret is in no entry and no log line.

### 12.9 Recipes

`deployment add --recipe NAME` fills the files, owner, hooks, local check and sandbox of a service; a
flag you pass wins, and `--dry-run` shows what the recipe expands to. **Only the nginx recipe rests on a
setup the CI job (the agent end-to-end test) has run; the `--recipe` command itself is new in this
release. The Postfix, Dovecot and Proxmox VE recipes are examples, written from the documentation of
each service and not yet run on a live host. Test them on a non-production host first**;
`deployment add` says so itself and lists what to verify.

| Recipe | Files | Owner, key mode | Hooks | Local check | Sandbox |
|---|---|---|---|---|---|
| `nginx` | nginx profile: `fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>` | root, `0600` | `nginx-test` = `/usr/sbin/nginx -t`, `nginx-reload` = `/usr/bin/systemctl reload nginx` | `127.0.0.1:443` | write `/var/log/nginx`, low ports |
| `postfix` | file profile: `/etc/ssl/myownpki/postfix/fullchain.pem` and `privkey.pem` | root:root, `0600` | `postfix-test` = `/usr/sbin/postfix check`, `postfix-reload` = `/usr/bin/systemctl reload postfix` | none | none |
| `dovecot` | file profile: `/etc/ssl/myownpki/dovecot/fullchain.pem` and `privkey.pem` | root:root, `0600` | `dovecot-test` = `/usr/bin/doveconf -n`, `dovecot-reload` = `/usr/bin/systemctl reload dovecot` | `127.0.0.1:993` | none |
| `proxmox` | file profile: `/etc/ssl/myownpki/pve/fullchain.pem` and `privkey.pem` | root:root, `0600` | `proxmox-install` as the reload hook, no test hook: `/usr/bin/pvenode cert set /etc/ssl/myownpki/pve/fullchain.pem /etc/ssl/myownpki/pve/privkey.pem --force 1 --restart 1` | `127.0.0.1:8006` | write `/etc/pve` |

The parent directory of the files must exist before the command (the assistant makes it for you):
`install -d -m 0755 /etc/ssl/myownpki` for nginx, `/etc/ssl/myownpki/postfix`, `…/dovecot` or
`…/pve` for the others, or pass `--create-dirs`. The service must be pointed at the files; the agent
does not edit its configuration:

- **Postfix**, `main.cf`, Postfix 3.4 and later: `smtpd_tls_chain_files =
  /etc/ssl/myownpki/postfix/privkey.pem, /etc/ssl/myownpki/postfix/fullchain.pem` (older:
  `smtpd_tls_cert_file` and `smtpd_tls_key_file`). The recipe has no local check, because the agent
  checks implicit TLS only; add `--check 127.0.0.1:465` when `master.cf` has a `submissions` listener.
- **Dovecot** 2.3: `ssl_cert = </etc/ssl/myownpki/dovecot/fullchain.pem` and
  `ssl_key = </etc/ssl/myownpki/dovecot/privkey.pem`; 2.4: `ssl_server_cert_file` and
  `ssl_server_key_file` (no `<`).
- **Proxmox VE**: the agent does **not** write into `/etc/pve`, a FUSE file system that takes neither
  `chown` nor `chmod`; `pvenode` validates the files, installs them and restarts `pveproxy`, and a
  rollback runs it again on the restored files. Run one agent per node.

To verify on a test host (and note what differed from this page):

| Recipe | Verify |
|---|---|
| Postfix | `postfix check` runs inside the sandbox without writing; no group is needed (the key is read before Postfix drops privileges); new connections use the new certificate after the reload |
| Dovecot | A reload makes new connections use the new certificate; which `doveconf` option is a syntax-only test on your version |
| Proxmox VE | The `pvenode cert set` syntax of your version; that `pvenode` works under the sandbox (it writes `/etc/pve`); `https://<node>:8006` serves the new certificate |

None of the three should need a group, as far as the documentation says: the daemons read their keys
as root. A service that reads its key as an unprivileged user takes `--group` and `--key-mode 0640`
(for example `ssl-cert` on Debian). That is a claim to verify on each host.

### 12.10 Rolling out with Salt

Since v0.3.6 the repository has a Salt formula, [`deploy/salt/myownpki/`](../deploy/salt/myownpki), that puts the pieces of
[§12.7](#127-adding-a-host) and [§12.8](#128-enrollment-passes) into one `state.apply myownpki`. It is
not part of the release archives: copy the directory `myownpki/` from the tag you install into a
`file_roots` directory of the master, or fetch it with gitfs at that tag. The page for administrators,
with the commands, is [Rolling out with Salt](https://der-felix.github.io/MyOwnPKI/hosts/salt/); the
formula's own [README](../deploy/salt/myownpki/README.md) lists every state and rule. In short:

- **Pillar `myownpki:agent`.** Required: `version`, `server`, `acme_directory`, `root_source`,
  `root_sha256` and `package.sha256` (a map of `amd64` and `arm64` to the SHA-256 of the package). Optional:
  `package.source` (default `salt://myownpki/files/{name}`) and `package.format` (`auto`, `deb`, `rpm`),
  `webroot`, `low_ports`, `system_trust`, `enrollment_pass`, `config_source`, `deployments` and `absent`. The hashes come
  from the authenticated admin UI, not from the files being rolled out.
- **Verified package.** Salt ignores `source_hash` for `salt://` sources, so the formula stages the package
  in `/var/cache/myownpki-agent`, compares its SHA-256 with the pillar (the state
  `myownpki-agent-package-verified` fails the run on a mismatch, on every apply) and installs only from
  that local file.
- **Enrollment.** `enrollment_pass` is written to `/root/myownpki-join-token` (0600, not shown in any
  output) only while `/var/lib/myownpki-agent/agent.crt` does not exist, and `setup --token-file` uses it.
  Without a pass the host waits for one approval and the next apply finishes the job. The formula never
  enables or starts the unit; `setup` does when the host is admitted, and the restart is
  `systemctl try-restart` only. A host that waited and is approved later keeps the pass file; delete it
  and take the pass out of the pillar after the roll-out.
- **Deployments.** `deployments` are applied with `deployment add`, guarded by `deployment list`; a
  changed option of an existing deployment is **not** applied (remove it through `absent` first).
  `config_source` (Salt renders the whole file, then `sandbox sync`) and `deployments` are mutually
  exclusive: one owner of `agent.yaml` ([§12.3](#123-agentyaml-and-deployment-profiles)). A `state_dir`
  other than `/var/lib/myownpki-agent` breaks the formula's `agent.crt` checks.
- **Updates.** A new package on an enrolled host runs `setup` again (the state
  `myownpki-agent-setup-update`), which is the update step of [§9](#9-upgrading). Update the server first.
- **System trust.** `system_trust: true` (a boolean, default `false`) adds the state
  `myownpki-agent-system-trust` after `setup`, which runs `trust install` ([§12.12](#1212-the-root-in-the-system-trust-store)).
  It refuses a value that is not a boolean, `true` on an `os_family` other than Debian and RedHat, and `true` with
  a `version` below 0.3.9. `false` or absent creates no state and removes nothing: `trust remove` is by hand.
- **Fails closed.** A missing required key, a missing hash for the minion's architecture, an unknown key,
  option or format, a pass that is not a string and similar mistakes render one failing state,
  `myownpki-agent-refused`, and nothing is installed. `state.show_highstate` prints the reason.

**What is tested.** The CI job `salt formula` renders every pillar in `deploy/salt/test/cases` and
applies it with `test=True` under Salt 3008.5. The maintainer also applied it for real to five enrolled
Debian amd64 hosts (agent 0.3.2 to 0.3.5, a second apply changed nothing). **Not tested live:** the
enrollment of a new host with an enrollment pass, `rpm` hosts, `arm64`, `config_source`, the gitfs
install and other Salt versions. Try the formula on one minion before you roll out.

### 12.11 dns-01 in the agent

Since v0.3.7 a deployment may prove its names with **dns-01** instead of http-01: the agent writes the TXT
record `_acme-challenge.<name>` into a DNS zone, waits until it is visible, lets the ACME server read it
and removes it again. The server only reads the record (through `acme.resolver`, [§10.7](#107-split-dns-and-the-network)),
so the server is unchanged. Use it for **wildcards** (`*.homelab.lan` can only be proven with dns-01, RFC 8555
§7.1.3), for a service **without port 80** and for a host **behind NAT**. It costs a credential that can
change a zone, so keep http-01 where it works. Enrollment of a host stays http-01 (or an approval); only the
certificates use dns-01. The page for administrators, with a worked example, is
[dns-01 and wildcard certificates](https://der-felix.github.io/MyOwnPKI/dns-01/).

**What the server must allow.** The ACME server decides; the agent never asks about policy, so a refusal comes
back as the server's own message. The domain that covers the name needs dns-01 among its challenges, and
for a wildcard *Wildcards* (which needs *Names below the domain too* and dns-01,
[§10.5](#105-domains-approvals-and-eab-keys)). The agent's *Names it may order* must cover every name of the
deployment, and **a wildcard is covered only by the identical pattern**: `*.homelab.lan` in the list covers
`www.homelab.lan` but not `homelab.lan`, and `homelab.lan` does not cover `*.homelab.lan`. An enrollment
pass grants the host name only, so add the pattern by hand. A deployment of `*.homelab.lan` and `homelab.lan`
is one certificate with two names; the agent writes two values at the one TXT name `_acme-challenge.homelab.lan`
and removes both.

**`agent.yaml`.** A deployment sets `challenge: dns-01` and `dns_provider: NAME`; `NAME` is a key of the
top-level map `dns_providers`, which holds no secret:

| Key of `dns_providers.NAME` | Default | Meaning |
|---|---|---|
| `type` | required | `rfc2136` or `cloudflare` |
| `credentials_file` | required | Absolute path of the credentials file |
| `nameserver` | required for `rfc2136` | `host` or `host:port` (port 53) of the DNS server that accepts the update; not for Cloudflare |
| `zone` | looked up | `rfc2136`: the zone to update. Without it the agent asks the nameserver for the SOA of the name and its parents |
| `ttl` | 120 | TTL of the record in seconds: 30 to 3600 for `rfc2136`, 120 to 3600 for Cloudflare |
| `resolver` | `/etc/resolv.conf` | `IP` or `IP:port` for the SOA, CNAME and propagation queries; the agent never falls back to public resolvers and fails when it has none |
| `propagation` | `authoritative` | `authoritative`, `resolver` or `wait` (below) |
| `propagation_wait` | 0 | A pause in seconds before the first check, 0 to 300 |
| `propagation_timeout` | 120 | Seconds the agent polls (every 2 seconds), 1 to 600 |

Unknown keys are errors and `config check` reports every problem at once. A wildcard name is allowed only with
dns-01; a dns-01 deployment takes no `webroot`; a provider no deployment uses is a warning. A provider
entry serves several deployments. `deployment add` writes an entry once, when its name is new and
`--dns-type` is given; it refuses a different definition of an existing name ("edit agent.yaml by hand"),
and `ttl`, `propagation*` and a changed `zone` are edited by hand. `check_name` is the SNI of the local TLS
check; without it the agent uses the first name that is not a wildcard, and a deployment of wildcards only
that has a `check` needs it.

**The credentials file.** A file of its own, never `agent.yaml`, a command line or an environment variable
(`agent run` removes every variable that starts with `LEGO_`, `CLOUDFLARE_`, `CF_` or `RFC2136_`, and
also `SSL_CERT_FILE` and `SSL_CERT_DIR`, logs their names and ignores them). The last two choose the
system roots on Linux, which the Cloudflare calls trust, so they would choose which CA may receive the API
token; the agent's own connections use the `ca_bundle` of `agent.yaml` and never read them. **Hooks inherit
the cleaned environment**: they see none of these variables, and a hook that talks TLS uses the system's
default trust. YAML with strict keys; an unknown key, an empty value, a repeated key, an
alias or a second document is an error:

| Provider | Keys |
|---|---|
| `rfc2136` | `tsig_key_name` and `tsig_secret` (base64, as in BIND's `key` statement) required; `tsig_algorithm` optional: `hmac-sha256` (default), `hmac-sha384`, `hmac-sha512`. `hmac-md5` and `hmac-sha1` are refused |
| `cloudflare` | `api_token` required (an API token, not the legacy global key); `zone_token` optional, a second token with *Zone / Zone / Read* only |

The agent opens the file without following a symbolic link and checks the **open** file: a regular file of at
most 4 KiB, mode 0600 or 0400 with no setuid, setgid or sticky bit, owned by root or the agent's user, in a
directory that group and others cannot write and that root or the agent's user owns. The path must be
absolute, without `..`, and **not** under `/home`, `/root` or `/run/user` (the unit hides them with
`ProtectHome=yes`), `state_dir`, `paths` or a deployment target. Use `/etc/myownpki-agent/dns/`; `/etc` is
readable under `ProtectSystem=strict`, so the systemd drop-ins do not change. The file is read **when an
issuance starts** and wiped from memory afterwards, so a rotated secret works at the next renewal without a
restart. A failing check names the state (`missing`, `wrong mode`, `wrong owner`, `unsafe directory`,
`symbolic link`, `not a regular file`, `too large`, `invalid`) and the path, never the content; no secret
reaches a log, an error, the report to the server or `agent status`. `myownpki-agent config check` prints a block
*dns providers* with the state of each file and exits 1 when a deployment uses a file that cannot be used.
`deployment add` shows the same problems as a **warning**, because a configuration tool may run it before the
secret file exists.

**RFC 2136 (BIND, Knot, PowerDNS).** One signed UPDATE message adds the TXT record and one removes exactly
this run's value, both **over TCP** to `nameserver`; the zone SOA lookup goes to the same server over TCP. The
agent accepts a success only when the answer's own TSIG verifies. The key needs to be allowed to add and
remove TXT records at `_acme-challenge.<name>`. In BIND, with `tsig-keygen -a hmac-sha256 acme-agent` for the key:

```
zone "homelab.lan" {
    type primary;
    file "db.homelab.lan";
    update-policy {
        grant acme-agent name _acme-challenge.homelab.lan. TXT;
    };
};
```

A certificate for `*.homelab.lan` and `homelab.lan` needs this one `grant`; every other name needs its own line
(`_acme-challenge.www.homelab.lan.`). `update-policy` and `allow-update` cannot be combined in one zone.
**This `update-policy` is not verified:** the BIND test of the CI job uses `allow-update`. Check it on a test
zone. TSIG signatures carry the time (the agent sends a tolerance of 300 seconds), so keep both clocks on NTP.
A CNAME from `_acme-challenge.<name>` to another zone is followed and the update goes to the target's zone,
so the key must be valid there; leave `zone` unset in that case, because with `zone` set a target outside
that zone is refused before any message is sent (`rfc2136: zone mismatch: …`).

**Cloudflare.** The agent looks the zone up by name, creates a TXT record and deletes it by its ID. The
token therefore needs *Zone / Zone / Read* and *Zone / DNS / Edit*, scoped to the **one zone**; these are the
permissions of the lego Cloudflare provider that the agent uses, so **check the names against Cloudflare's
current documentation**. `zone_token` may carry the read permission alone. The calls use the system trust
store (not `ca_bundle`), TLS 1.2 or newer and the `proxy:` of `agent.yaml` (never `HTTPS_PROXY`); error
answers are cut to their codes and short messages. The zone is found by an SOA lookup through `resolver`, so
that resolver must return the zone as Cloudflare hosts it.

**Propagation.** After it writes the record the agent checks that it is visible before it tells the ACME
server to look. `authoritative` (default): the TXT record is on every authoritative name server of the zone
(port 53), robust against negative caching. `resolver`: only the configured resolver, for hosts that cannot query the name
servers. `wait`: no query, only `propagation_wait`. `propagation_wait` is added once before the first check in
every mode. The ACME server's own read goes through `acme.resolver`, which must see the zone the agent writes.

**Cleanup.** The agent removes its record on success, failure, cancellation and timeout, and only this run's
value. Each removal gets 30 seconds and is not cancelled with the issuance. Once the issuance is cancelled
(the agent is stopping), all removals of one issuance share **12 seconds**, below the 30 seconds of the
unit's `TimeoutStopSec`, so that a hanging DNS server and two records no longer end in `SIGKILL` during the
second removal; a record that has no time left is not sent and counts as a failed removal. A cleanup failure
is logged as `dns-01 cleanup failed: a TXT record may be left behind; remove it by hand if it stays` (with
the reason), and it is reported in the deployment's *Last error*: `dns-01 cleanup failed: a TXT record may
remain at _acme-challenge.<name>; remove it by hand if it stays (the agent log has the details)`, with up to
three names and then `and N more`. That text carries no provider message and no secret. The issuance keeps
its result: a deployed deployment stays `deployed`, and when the issuance failed too, the notice stands in
front of the error. The next pass without a cleanup problem clears it. With Cloudflare the notice appears
only when the create request may have worked (a network error, an answer that is not the API's JSON, a 5xx or
a 2xx), because only then a record can exist that the agent cannot delete by ID; a create that was refused
with a 4xx wrote nothing and stays quiet.
`SIGKILL` or a power cut leaves a record, and the Cloudflare record IDs live in memory only, so remove such a
record by hand. It does not harm validation. The agent refuses a challenge for a name that is not one of the
deployment's names. `log_level: debug` shows lego's lines on the waiting and the checks.

**Renewal checks during an issuance.** An issuance holds the agent's pass lock for as long as it runs, and a
dns-01 one can wait up to `propagation_timeout` (15 minutes at most). The optional ARI lookup of a pass therefore does not queue
behind it: while an issuance runs, the agent skips the lookup (debug log: `skipping the ARI check: an issuance
is running`) and asks again at the next pass.

**When it fails.** The error is the deployment's *Last error* on the agent page and in `myownpki-agent
status`. Frequent texts: `credentials file …: wrong mode: is 0640, want 0600 or 0400` (the other states
likewise); `dns-01 needs a resolver of its own and /etc/resolv.conf has none` (set `resolver`);
`rfc2136: … NOTAUTH from …` (wrong key name, secret or algorithm, or `nameserver` is not authoritative);
`REFUSED from …: the server refuses this key to change this name` (fix `update-policy` or `allow-update`);
`the answer's TSIG time differs too much from this host's clock; check NTP`; `rfc2136: zone lookup: … has no
SOA record …` (point `nameserver` at the primary or set `zone`); `propagation: time limit exceeded: last
error: NS … did not return the expected TXT record` (try `propagation: resolver` or `wait`, check port 53);
`cloudflare: … [status code 403] …` (the token's zone or permissions); the server's `… is not in this agent's
allowed names`, `no domain covers …` and `_acme-challenge.… has no TXT record` (the server's resolver does not
see the zone). A failed validation counts against the failure limit of the ACME server
([§10.8](#108-sealed-server-rate-limits-audit)). The complete list is in
[Troubleshooting](https://der-felix.github.io/MyOwnPKI/troubleshooting/#dns-01-in-the-agent).

**Not supported.** GSS-TSIG (Kerberos, Active Directory DNS: run the ACME zone on BIND, Knot or PowerDNS, or
delegate `_acme-challenge` by CNAME), other DNS providers (use an ACME client with its DNS plugin), the legacy
Cloudflare global API key, DNS updates over HTTPS or TLS, TSIG with MD5 or SHA-1, more than one provider per
deployment, dns-01 for enrollment, a sweep of stale records, and dns-01 in the *Add host* assistant (it ends in
a pasted command and cannot place a secret file; run `deployment add` by hand).

**What is tested.** CI runs the agent's RFC 2136 code against an in-process DNS server and, in the job *ACME
conformance*, against a real BIND with a TSIG key (`propagation: resolver`); the Cloudflare code against a
stub; and the whole path, wildcard included, against the real ACME server of the repository. **Not tested
live:** the real Cloudflare API, a BIND `update-policy` on the maintainer's server, `propagation:
authoritative` against name servers on port 53, and the Salt formula's dns-01 deployments. Try it on one test
host before you rely on it.

An end-to-end check: add the deployment with `--dry-run`, then without it, restart the agent, press *Renew
now*; the deployment turns *deployed*; `openssl s_client -connect minion-01.homelab.lan:443 -servername
x.homelab.lan` shows both names; `dig +short TXT _acme-challenge.homelab.lan @192.0.2.53` prints nothing.
Put a wrong secret in the file and the renewal fails with a message that names the provider and holds no part
of the secret; correct the file and the next attempt works without a restart.

### 12.12 The root in the system trust store

Since v0.3.9 the agent can add the root of this PKI to the **system trust store** of its host, so that `curl`
and every other program there trust the PKI's certificates without a `--cacert` option. It is **opt-in and off
by default**, it is a command that root runs (or Salt runs), and it is **never part of `run`**: the running
service is confined by the unit's sandbox (§12.3) and cannot write `/etc/ssl`, `/etc/pki` or `/usr/local/share`.
Widening the unit's `ReadWritePaths` to those directories would give the always-running, network-facing process
write access to the host's trust anchors, so it is not done; the unit file and its drop-ins are unchanged.

**What it can do, and what it implies.** The agent can add the CA that issues its own certificates; it never
touches anything else. The root is the one the host already pinned at enrollment: `ca_bundle`, checked against
`--root-sha256` by `setup`. The option therefore makes no new trust decision, it only widens the scope of the same
one. After it, **every program on the host that reads the system store trusts that root for every name**; the
only limit is a name constraint on the intermediates (which works only where
the client enforces it). Firefox, Java and other programs with their own store are not affected.

**Hosts.** Debian-family and RedHat-family Linux. The family comes from `ID` and `ID_LIKE` in `/etc/os-release`
(or `/usr/lib/os-release`): `debian` selects the Debian family, `rhel`, `fedora` or `centos` the RedHat family.
Anything else, and a host without a readable `os-release`, is refused with the `ID` and `ID_LIKE` it reports, and
nothing is changed. The target and the command are fixed per family; nothing from `agent.yaml` reaches a path or
an argument:

| Family | File | Command (no shell) |
|---|---|---|
| Debian | `/usr/local/share/ca-certificates/myownpki-agent-root.crt` | `/usr/sbin/update-ca-certificates` |
| RedHat | `/etc/pki/ca-trust/source/anchors/myownpki-agent-root.pem` | `/usr/bin/update-ca-trust` |

The command runs with the environment `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LC_ALL=C` (no proxy and no
`SSL_CERT_*` variable), with the working directory `/`, with umask 022 whatever the caller's umask is (so the
bundle stays readable for everyone), and with a limit of 60 seconds. Its output is cleaned of control characters
and cut before it enters an error text.

**`trust install --root-sha256 HEX [--no-record] [--config FILE]`** (root only). `--root-sha256` is required
(exit code 2 without it). Before a byte is written it checks that: the caller is root; the host is of a supported
family; `ca_bundle` is a regular file (a symbolic link is refused) of at most 1 MiB with exactly one PEM
certificate and nothing else; that certificate is a self-signed CA; and its SHA-256 equals the value given. The
file written is made from the bytes that were checked, not read again. The anchors directory must exist (an error
names the missing CA certificates package otherwise), and neither it nor the target may be a symbolic link. The
file goes through a temporary file in the same directory with mode 0644 and a rename, then the command runs, then
`agent.yaml` gets the key `system_trust` (the previous file stays as `agent.yaml.bak`). `--no-record` leaves
`agent.yaml` alone, for a file that another tool renders.

- **A failed command is rolled back.** The previous state of the file is put back, or the file is removed, so
  "the file is there" means "the command succeeded". Because a failed `update-ca-certificates` may already have
  rewritten the bundle, the command then runs **once more**, best effort, and the error text says how that went
  ("the trust store was regenerated again" or "could not be regenerated again: …"). The first error is kept.
- **Running it again** is safe: with identical content nothing is written, but the command still runs once. That
  makes a file dropped in by hand effective, and it is cheap.
- **A different pin** than the recorded one replaces the key after the new value matched `ca_bundle` (a root
  renewal). `ca_bundle` is replaced only by `setup`, so run `setup` with the new root first.
- **An error after the install** (the key cannot be written) says that the root is installed and to run the
  command again after fixing `agent.yaml`.

**`trust status [--quiet] [--root-sha256 HEX] [--config FILE]`** reads and writes nothing and needs no root. It
compares the fixed file with the pin of `agent.yaml` (or the argument) and prints one line. It never reads
`ca_bundle`. **Exit code 0 only when the installed file is the pinned root**; "not installed", "differs", "not
configured", a pin that disagrees with the argument and an unsupported host all exit 1. `--quiet` prints nothing.

**`trust remove [--root-sha256 HEX] [--config FILE]`** (root only) needs a valid `agent.yaml` and a pin (the key,
or the argument; both given and different is an error). It deletes **only the fixed file, and only when it holds
the pinned root**; another content is refused. Then it runs the same command as `install` and removes the key
from `agent.yaml`. When the file is already gone it still runs the command, so a stale bundle is built again, and
exits 0. Without the anchors directory there is nothing to run. A failed command puts the file back and runs the
command once more.

**`setup --system-trust`** (with the `--root-sha256` that `setup` always needs) does the install after
enrollment, for an admitted and for a waiting host (the root does not depend on the approval) and never for a
denied or expired one. It checks the family before it writes any file ("no host files were changed"). If the
install fails, `setup` itself is done, and the message says to run `trust install` after fixing the cause.

**`agent.yaml`:**

```yaml
system_trust:
  root_sha256: "AA..."   # 64 hexadecimal digits, no colons; absent: off
```

The key is read by `config check` and the `trust` commands; the running service ignores it. **An agent older than
0.3.9 refuses the key** (unknown keys are errors) and does not start, so update the agents before you write it
(§9). `deploy/agent.example.yaml` does not list it, because `setup` compares that file with the installed one.

**`config check`** prints a line `system trust`: `off`; `installed: <file> holds the root with SHA-256 <hex>`;
`not installed (<file>); as root run: myownpki-agent trust install --root-sha256 <hex>`; or `differs: …`. Those
are information and exit 0. It exits 1 only when `system_trust` does not match the root in `ca_bundle` (the line then says
"pin differs from ca_bundle"), or the key cannot be read. **Limit:** the check reads `ca_bundle`, which `setup`
writes with mode 0600 for root, so as another user `config check` says that `ca_bundle` cannot be checked against
the pin, and exits 0. Run it as root for the full check.

**Salt.** The pillar key `myownpki:agent:system_trust` is a boolean. With `true` the formula adds the state
`myownpki-agent-system-trust` after `setup`: `trust install --root-sha256 <root_sha256>`, skipped (`unless`) when
`trust status --quiet --root-sha256 <root_sha256>` already exits 0, with no restart. With `config_source` the
state adds `--no-record`, because Salt owns `agent.yaml`. `false` and an absent key create no state, **and the
formula never removes the root**: set the key to `false`, then run `trust remove` on the host. The formula
refuses a value that is not a boolean, `true` on a minion whose `os_family` is not Debian or RedHat, and `true`
with a `version` below 0.3.9 (§12.10).

An end-to-end check on a Debian or RedHat agent host, as root: `trust install --root-sha256 <hex>` prints the
file and the command it ran; `trust status` exits 0; `config check` shows `system trust  installed: …`; a second
`install` changes nothing; a wrong hash is refused before any write; `curl https://<a host of the PKI>/` works
without `--cacert`; `systemctl show myownpki-agent -p ReadWritePaths` is as before; `trust remove`, then
`trust status` exits 1. This was tested with a fake runner and temporary directories in the program's tests, not
yet on a live host.

## 13. Monitoring and notifications

Since v0.3.3 the server watches itself. **Every minute** it checks the certificates, the CAs and
their CRLs, the seal state and the agents against the thresholds in §13.7 and keeps one **alert** per
condition. Since v0.3.4 it also looks at the TLS endpoints you entered, to see what each one really
serves ([chapter 14](#14-tls-scan)). The alerts are on the *Alerts* page, in the dashboard's *Needs attention* block and in
`GET /api/v1/alerts`. If you configure **e-mail** or a **webhook**, a change also goes out as a
message: **one digest** for everything that happened in that minute (not one mail per certificate), a
**reminder** every `repeat_every` while an alert stays open, and a last message when the problem is
gone. The checks and the messages **work while the server is sealed** – that is the point: the most
important alert is "the server is sealed", and a sealed server can't decrypt anything. So the
channels live in the configuration file and their secrets in files next to it, not in the database.

Without a channel nothing breaks: alerts still open and show in the UI, only nobody is told.
`myownpki config check` and the Alerts page say so.

### 13.1 Set up e-mail

1. Create the password file, if the mail server needs a login. The service user (`myownpki` with
   install.sh) must be able to read it, nobody else; root owns it, like `config.yaml`:

   ```bash
   sudo install -m 0640 -o root -g myownpki /dev/null /etc/myownpki/smtp-password
   ```

   ```bash
   sudo bash -c 'read -rsp "SMTP password: " p && printf "%s" "$p" > /etc/myownpki/smtp-password'
   ```

   The first command creates the empty file with owner and mode, the second fills it without the
   password showing up on the screen, in the shell history or in a process list. A trailing newline
   in the file is ignored. (Owner `myownpki` with mode `0600` works as well.) The file is read at
   each send, so a changed password needs no restart.

2. If the mail server's certificate comes from your own CA, give the server the root as an extra
   trusted root (public data, any readable PEM file will do – for example the root from the trust
   page, [chapter 11](#11-the-public-trust-page)):

   ```bash
   sudo curl -fsS -o /etc/myownpki/mail-ca.pem http://pki.homelab.lan/ca/root/1.pem
   ```

   (`root` and `1` are the name and generation of your root.) Compare its fingerprint with the admin
   UI before you rely on it (§10.4).

3. Add the channel to `/etc/myownpki/config.yaml`:

   ```yaml
   notify:
     email:
       smtp: mail.homelab.lan:587           # host:port
       security: starttls                   # starttls | tls | none
       username: pki@homelab.lan            # optional; with it password_file is required
       password_file: /etc/myownpki/smtp-password
       from: pki@homelab.lan
       to: ops@homelab.lan, lead@homelab.lan   # comma-separated, one message for all
       ca_file: /etc/myownpki/mail-ca.pem   # optional, added to the system roots
   ```

4. Check the file **as the service user** – a secret that only root can read passes as root and
   fails for the server:

   ```bash
   sudo -u myownpki /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

5. Restart the service (the channels are read at start) and **unseal it again** – every start is
   sealed (§9):

   ```bash
   sudo systemctl restart myownpki
   ```

6. Send a test message (§13.5).

| `security` | Usual port | What happens |
|---|---|---|
| `starttls` (default) | 587 | Connects in plain text and switches to TLS **before** the login. Refuses if the server doesn't offer STARTTLS. |
| `tls` | 465 | TLS from the first byte. |
| `none` | 25 | No encryption. **Only without `username`** – a password never travels in plain text, and `config check` refuses the combination. For an internal relay that accepts mail from the server's address. |

The server's certificate is always checked against the system roots (plus `ca_file`) and must carry
the host name used in `smtp` – with an IP address in `smtp` it needs that IP as a name. TLS 1.2 is
the minimum. The login is `PLAIN`, sent only inside TLS; a server that offers only `LOGIN` or
OAuth is not supported – use a relay for the server's address instead. The mail is plain text,
UTF-8, marked `Auto-Submitted: auto-generated`; `from` must be an address the mail server accepts.
One delivery has 20 seconds. E-mail **doesn't use the proxy variables** (§13.3): the mail server
must be reachable directly.

### 13.2 Set up a webhook

A webhook is one `POST` with a JSON body to a URL of yours – a small receiver, or a relay that turns
it into Slack, Teams, ntfy or a ticket.

1. Create the secret – the key that signs every call – and give the same value to the receiver:

   ```bash
   sudo install -m 0640 -o root -g myownpki /dev/null /etc/myownpki/webhook-secret
   ```

   ```bash
   openssl rand -hex 32 | sudo tee /etc/myownpki/webhook-secret >/dev/null
   ```

   ```bash
   sudo cat /etc/myownpki/webhook-secret
   ```

   The key is the text of the file (without surrounding white space), not the bytes behind the hex.

2. Add the channel to `config.yaml`:

   ```yaml
   notify:
     webhook:
       url: https://hooks.homelab.lan/myownpki
       secret_file: /etc/myownpki/webhook-secret   # required
       ca_file: /etc/myownpki/hooks-ca.pem         # optional, added to the system roots
   ```

3. Check, restart and unseal, test – as in §13.1, steps 4 to 6.

The URL must be `https://`; `http://` is accepted only for a loopback address (a relay on the same
host). It may not carry a user name or password – the request is signed instead. The receiver's
certificate is checked against the system roots plus `ca_file`. Any **2xx** answer is success; a
redirect is **not followed** (a redirect could carry the signed body somewhere else) and counts as a
failure, as does any other status. One call has 10 seconds. Errors in the log and in the UI name the
host, never the path or query – they may hold a token.

**What arrives.** `Content-Type: application/json`, `User-Agent: MyOwnPKI/<version>` and

```text
X-MyOwnPKI-Signature: sha256=<hex HMAC-SHA256 of the body, key = the secret>
```

```json
{
  "server": "pki.homelab.lan",
  "created": "2026-11-11T12:00:03Z",
  "events": [
    {
      "kind": "sealed",
      "subject": "Server sealed",
      "severity": "warning",
      "state": "opened",
      "since": "2026-11-11T11:50:01Z",
      "detail": "The server has been sealed since 2026-11-11 11:50 UTC – it signs nothing: …",
      "link": "https://pki.homelab.lan:9443/unseal"
    }
  ]
}
```

`state` is `opened`, `raised` (warning → critical), `reminder`, `resolved`, or `test` for a test
message. `since` is when the alert opened. `link` is left out when the server has no name to link
to (§13.6). Check the signature on the **raw body, before you parse it**, and compare in constant
time. A receiver in shell, for a body saved as `body.json` and the header value in `$header`:

```bash
expected="sha256=$(openssl dgst -sha256 -hmac "$(cat /etc/myownpki/webhook-secret)" < body.json | sed 's/^.* //')"
```

```bash
[ "$header" = "$expected" ] && echo valid || echo INVALID
```

The signature proves who sent the body, not when: the digest has `created`, but no timestamp is
signed separately, so a receiver that must reject replays should remember what it has seen.

**Through a proxy.** The webhook honors the standard `HTTPS_PROXY` and `NO_PROXY` variables of the
**server process**, read once at start. With systemd, put them in a drop-in:

```bash
sudo systemctl edit myownpki
```

```ini
[Service]
Environment=HTTPS_PROXY=http://proxy.homelab.lan:3128
Environment=NO_PROXY=localhost,127.0.0.1,.homelab.lan
```

Restart (and unseal) afterwards. `myownpki notify test` run in a shell doesn't see the unit's
`Environment=`; set the variables for that command too (§13.5).

### 13.3 In the container image

Every key is also an environment variable: `MYOWNPKI_` plus the path in upper case, `.` as `_`. A
variable wins over `config.yaml`. The secret files are files, so mount them **read-only** into the
container and make them readable for UID 65532, the user of the image:

```bash
sudo install -d -m 0750 -o 65532 -g 65532 secrets
```

```bash
sudo install -m 0400 -o 65532 -g 65532 /dev/null secrets/webhook-secret
```

```bash
openssl rand -hex 32 | sudo tee secrets/webhook-secret >/dev/null
```

Create `smtp-password` and copy the root PEM (`root-ca.pem`, mode `0444`) there the same way. Then
in `docker-compose.yml`:

```yaml
services:
  myownpki:
    # The server name in the message subject; the default is a random container ID.
    hostname: pki.homelab.lan
    environment:
      MYOWNPKI_NOTIFY_EMAIL_SMTP: mail.homelab.lan:587
      MYOWNPKI_NOTIFY_EMAIL_SECURITY: starttls
      MYOWNPKI_NOTIFY_EMAIL_USERNAME: pki@homelab.lan
      MYOWNPKI_NOTIFY_EMAIL_PASSWORD_FILE: /run/secrets/smtp-password
      MYOWNPKI_NOTIFY_EMAIL_FROM: pki@homelab.lan
      MYOWNPKI_NOTIFY_EMAIL_TO: ops@homelab.lan, lead@homelab.lan
      MYOWNPKI_NOTIFY_EMAIL_CA_FILE: /run/secrets/root-ca.pem
      MYOWNPKI_NOTIFY_WEBHOOK_URL: https://hooks.homelab.lan/myownpki
      MYOWNPKI_NOTIFY_WEBHOOK_SECRET_FILE: /run/secrets/webhook-secret
      HTTPS_PROXY: http://proxy.homelab.lan:3128
      NO_PROXY: localhost,127.0.0.1,.homelab.lan
    volumes:
      - ./secrets/smtp-password:/run/secrets/smtp-password:ro
      - ./secrets/webhook-secret:/run/secrets/webhook-secret:ro
      - ./secrets/root-ca.pem:/run/secrets/root-ca.pem:ro
```

The thresholds (§13.7) are `MYOWNPKI_MONITOR_EXPIRY_DAYS`, `MYOWNPKI_MONITOR_CA_EXPIRY_DAYS`,
`MYOWNPKI_MONITOR_SEALED_AFTER`, `MYOWNPKI_MONITOR_AGENT_SILENT_AFTER` and
`MYOWNPKI_MONITOR_REPEAT_EVERY`. Check and test with the same Compose file, so the same variables
and mounts apply:

```bash
docker compose run --rm myownpki config check
```

```bash
docker compose run --rm myownpki notify test
```

`config check` shows `(from MYOWNPKI_NOTIFY_…)` behind a value that came from a variable. A change
needs `docker compose up -d` (the container restarts sealed – unseal it).

### 13.4 Two things to know before you rely on it

- **A restart seals the server.** Changing the channels or thresholds means a restart, and a
  restart means an unseal in the browser. Do it when nobody waits for a certificate.
- **No message is sent while the server is down.** It tells you about its own sealed state, not about
  being off. For that, watch from outside: `myownpki healthcheck` or your monitoring system on
  `/healthz` (§4).

### 13.5 Test the channels

```bash
sudo -u myownpki /usr/local/bin/myownpki notify test --config /etc/myownpki/config.yaml
```

One test message goes through every configured channel, right now, with the server's configuration
and secret files; `--channel email` or `--channel webhook` limits it to one. Success:

```text
email    sent to ops@homelab.lan, lead@homelab.lan via mail.homelab.lan:587
webhook  sent to hooks.homelab.lan
```

A failure prints `email    FAILED: <reason>` (the reason names the host and what went wrong, never
a password or the webhook path) and the exit code is 1. The command needs neither a running server
nor an unsealed one and sends no alerts. Behind a proxy, give the variables to the command:

```bash
sudo -u myownpki env HTTPS_PROXY=http://proxy.homelab.lan:3128 /usr/local/bin/myownpki notify test --config /etc/myownpki/config.yaml
```

The e-mail subject of a test is `[MyOwnPKI] pki.homelab.lan: test message`; the webhook gets one
event with `"state": "test"` and `"severity": "info"`.

The same test from the running server:

- **UI:** *Alerts → Notifications → Send test message* (tenant admins). The page then shows one line
  per channel, success or the reason.
- **REST:** `POST /api/v1/notifications/test` with the token of a tenant admin:

  ```bash
  curl -sS --cacert root.pem -X POST -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/notifications/test
  ```

  ```json
  {"channels":[{"channel":"email","ok":true},{"channel":"webhook","ok":false,"error":"webhook hooks.homelab.lan answered 403 Forbidden"}]}
  ```

  A failing channel doesn't fail the call (`200`, `ok: false`). `409` means no channel is
  configured, `403` that the token isn't a tenant admin's, `429` that the last test was less than
  10 seconds ago (`Retry-After` says how long).

The UI and REST tests are limited to **one every 10 seconds** and audited as `notification.test`
(§13.9). `myownpki notify test` is neither limited nor audited – it runs on the machine, as the
service user.

**`config check`** shows what is in effect and reads the secret and CA files:

```text
Notifications (notify:)
  e-mail           mail.homelab.lan:587, starttls, 2 recipients
  webhook          hooks.homelab.lan, signed with HMAC-SHA256

Alert thresholds (monitor:)
  certificates     warning 14 days, critical 3 days before they end
  CA certificates  warning 90 days, critical 30 days before they end
  sealed server    alert after 10m
  silent agent     alert after 1h
  reminder         every 24h while an alert is open
```

The webhook appears by host only. A file that is missing, unreadable, empty (a password or secret)
or without a PEM certificate (`ca_file`) is an **error** and the exit code is 1, because every
message would fail:

```text
Error: notify.email.password_file /etc/myownpki/smtp-password: the file does not exist.
Error: notify.webhook.secret_file /etc/myownpki/webhook-secret: the file can't be read (permission denied) – the service user must be able to read it.
```

With no channel at all it only warns (exit 0): *no notification channel is configured – alerts are
shown in the UI, nobody is notified*. `config check` doesn't connect to anything; only a test shows
that the mail server or receiver accepts the message.

### 13.6 The alerts

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `cert_expiry` | a valid end-entity certificate ends soon and **no newer valid certificate covers the same names** | 14 days left | 3 days left, or expired |
| `ca_expiry` | the current certificate of an active CA ends soon | 90 days left | 30 days left, or expired |
| `crl` | the newest CRL of a CA generation is not current | half its lifetime has passed without a renewal, or none was ever published | past its next update |
| `sealed` | the server has been sealed longer than `sealed_after` | after 10 minutes | a CRL of an online CA is less than 24 hours from its next update |
| `agent_silent` | an active agent that reported before has not reported | after 1 hour | after 24 hours |
| `agent_certificate` | an active agent's own certificate has less than 48 hours left | – | always |
| `deploy_failed` | the last report of a deployment is `failed` or `rolled_back` | always | – |
| `scan_mismatch`, `scan_expiry`, `scan_unreachable`, `scan_chain` | the TLS scan finds that an endpoint you entered serves the wrong or an expiring certificate, is down, or sends an incomplete chain (v0.3.4; thresholds and what to do in [§14.5](#145-the-alerts)) | see §14.5 | see §14.5 |

Warning and critical thresholds are configurable where §13.7 lists a key. An alert changes its
severity while it is open (warning → critical sends a new message, critical → warning stays quiet)
and closes by itself at the next check once the cause is gone.

**`cert_expiry`** – a certificate runs out and nothing replaces it. "Replaces" means: another valid,
unrevoked certificate with the same set of names (DNS names and IPs, or the common name when there
are none) ends later. Agent identity certificates and revoked certificates never alert. An expired
certificate stays an alert for 30 days after its end, then it closes. What to do: issue the
replacement – with ACME the client renews on its own, so look at why it didn't (§10.9; for an
agent's deployment the agent page and `journalctl -u myownpki-agent`, §12.5, *Renew now*), by hand
issue a new certificate for the same names and deploy it. If the certificate isn't needed any more,
revoke it. The alert closes as soon as the replacement is **issued**; the server doesn't look at
what the host actually serves, so deploying it is still your check (a failed agent deployment is
`deploy_failed`).

**`ca_expiry`** – the CA's own certificate ends; everything below it stops validating that day. What
to do: renew the CA from its page under *Certificate authorities* well before the date, and give
the clients what they need if the renewal brings a new root (§10.4, chapter 11). The 90 days give
you time; the critical level at 30 days means the planned change was missed.

**`crl`** – clients that check revocation reject certificates below a CA whose CRL has expired
(RFC 5280 §5.1.2.5: `nextUpdate` is the time after which the CRL must not be relied on). *Warning*
means the renewal didn't happen: for an online CA the server renews its CRL itself, so the usual
cause is a sealed server – unseal it, or see the `sealed` alert. For a CA with an **offline root**
nobody renews it automatically: sign a new CRL on the offline root and upload it on the root's page
(*Upload the root's CRL*, §5). *Missing* means no CRL was ever published for that generation.

**`sealed`** – the server is sealed and signs nothing: no new certificates, no ACME orders, no
agent renewals, no CRLs. It opens after `sealed_after` so that the restart of an update, or a short
seal, doesn't wake anyone. It becomes **critical when a CRL of an online CA is less than 24 hours
from its next update** (or past it): a sealed server can't sign the replacement, and once the CRL
expires revocation checks fail for everything below that CA. How soon that happens depends on when
the last CRL was signed – with the default 7-day CRL of an intermediate (renewed after a third of
its life), roughly 3½ to 6 days after the seal; a CA with shorter CRLs gets there sooner. What to do: unseal it (*Unseal* in the banner, or `serve --unseal`, §4). An
instance admin is needed to unseal. If the server was sealed by mistake or after a restart, that's
all; if you don't know why it sealed, read the audit log first (§8).

**`agent_silent`** – an active agent has not reported for `agent_silent_after` (an agent reports
every five minutes, §12.5). An agent that never reported doesn't alert. What to do: on the host

```bash
systemctl status myownpki-agent
```

```bash
journalctl -u myownpki-agent -n 100 --no-pager
```

Typical causes: the host or service is down, the agent port (8444/tcp, §12.4) is blocked, the
server's agent listener certificate expired while sealed. A disabled or revoked agent doesn't alert.

**`agent_certificate`** – the agent's own 7-day certificate was not renewed at two thirds of its life
and ends in less than 48 hours. Without it the agent can't reach the server any more. What to do:
fix the connection as for `agent_silent` while the certificate is still valid; an agent whose
certificate expired enrolls again with the key of its last one (§12). The same event usually shows as
`agent_silent` first.

**`deploy_failed`** – the last report of a deployment is `failed` or `rolled_back`. The previous
certificate is still in place, but it keeps ageing. What to do: open the agent's page (the alert
links to it) for the error, then `journalctl -u myownpki-agent` and the rollback hints in §12.5. The
alert closes with the next successful report, or when the deployment is removed.

### 13.7 Thresholds

The defaults suit most installations. Set them in `config.yaml` (restart to apply):

```yaml
monitor:
  expiry_days: "14, 3"
  ca_expiry_days: "90, 30"
  sealed_after: 10m
  agent_silent_after: 1h
  repeat_every: 24h
```

| Key | Default | Allowed | Environment variable |
|---|---|---|---|
| `monitor.expiry_days` | `"14, 3"` | warning and critical days for end-entity certificates; warning 2–90, critical at least 1 and below warning | `MYOWNPKI_MONITOR_EXPIRY_DAYS` |
| `monitor.ca_expiry_days` | `"90, 30"` | the same for CA certificates; warning 2–365 | `MYOWNPKI_MONITOR_CA_EXPIRY_DAYS` |
| `monitor.sealed_after` | `10m` | 1m–1h | `MYOWNPKI_MONITOR_SEALED_AFTER` |
| `monitor.agent_silent_after` | `1h` | 10m–24h | `MYOWNPKI_MONITOR_AGENT_SILENT_AFTER` |
| `monitor.repeat_every` | `24h` | 1h–168h | `MYOWNPKI_MONITOR_REPEAT_EVERY` |

The keys of the TLS scan (`monitor.scan_*`) are in [§14.6](#146-settings).

Durations are written like `10m`, `1h` or `168h`. The server refuses to start, and `config check`
fails, with a message naming the key when a value is outside its range. Not configurable: the
24-hour CRL horizon of the critical `sealed` alert, the 24 hours after which a silent agent turns
critical, the 48 hours of `agent_certificate` and the 30 days an expired certificate stays an alert.

### 13.8 How messages behave

**One digest per minute at most.** After each check the server collects what changed since the last
message and sends it as one message per channel. A minute without a change sends nothing.

| State | When | In the e-mail |
|---|---|---|
| `opened` | a new alert (also: every alert that was open when a channel was first configured) | NEW |
| `raised` | warning → critical | NOW CRITICAL |
| `reminder` | still open `repeat_every` after its last message | STILL OPEN |
| `resolved` | the cause is gone, for an alert whose opening was reported | RESOLVED |

The subject counts them: `[MyOwnPKI] pki.homelab.lan: 2 new, 1 resolved`. The name is the host
name of the machine (or the container's `hostname:`). The body lists each alert with its severity,
what it is and what to do, and a link to the object in the web UI. Links need a name: they use the
first name of `admin.tls_names` (an IP if there is no name) and the port of `admin.listen`; without
`tls_names` there are no links. Names in the message come from certificates and are cleaned of
control characters.

```text
Subject: [MyOwnPKI] pki.homelab.lan: 1 new

MyOwnPKI on pki.homelab.lan, 2026-11-11 12:00 UTC

NEW

  [critical] www.homelab.lan
  Certificate www.homelab.lan (serial 04A1…, CA issuing) expires in 2 days (2026-11-13 09:00 UTC) and no newer certificate covers its names – renew it.
  https://pki.homelab.lan:9443/certificates/<id>

-- 
Sent by MyOwnPKI. The open alerts are on the dashboard.
```

**No channel, no marking.** While neither channel is configured, nothing is marked as notified. The
first message after you configure one lists **every alert that is open then**, as new.

**Delivery and retries.** Messages are queued in `system.db` and sent by the same minute job, so
they survive a restart. A failed delivery is tried again after **1 minute, 5 minutes, 30 minutes and
2 hours**; after the fifth failed attempt (about two and a half hours after the first) the message is
**dropped**. The log shows each step (JSON; `journalctl -u myownpki -o cat`):

| Log message | Level | Meaning |
|---|---|---|
| `notification failed – will retry` | warn | with `channel`, `attempt`, `next_attempt`, `error` |
| `notification sent` | info | after at least one failure, with the attempt that worked |
| `notification dropped after the last retry – the alerts are still on the dashboard` | error | gave up; with `channel` and the last `error` |
| `alert` | warn / info | an alert `opened`, `raised`, `lowered` or `resolved` – logged whether or not a channel exists |
| `no notification channel configured – alerts show only in the UI …` | info | at start |

```bash
journalctl -u myownpki -o cat | grep -E 'notification|"alert"'
```

Set up an alarm on **`notification dropped`** in your log system: it's the one case where the server
tried and nobody was told. A dropped message is not repeated – the alerts it carried count as
reported, so open ones come again with their next reminder (after `repeat_every`), but a `resolved`
message that was dropped is lost; the Alerts page still shows it for 7 days. Delivery and retries of
the two channels are independent: a broken webhook doesn't hold back the mail.

Alerts resolved more than 30 days ago and finished queue entries are deleted daily; the Alerts page
and API show the open ones and those resolved in the last 7 days.

### 13.9 Who sees and does what

| | Role | Notes |
|---|---|---|
| Alerts page, dashboard figure *Open alerts*, `GET /api/v1/alerts` | tenant-wide **viewer** or higher | `?state=open` or `resolved`. Alerts name certificates, CAs and hosts of the whole tenant, so a role limited to one CA gets 403, has no *Alerts* entry in the menu and no alert block on the dashboard. Works while sealed. |
| *Send test message*, `POST /api/v1/notifications/test` | tenant **admin** (permission `notification.test`) | No step-up – it changes nothing. One every 10 seconds. A refused attempt is audited as denied. |
| Channels and thresholds | whoever edits `config.yaml` or the environment, on the server | There is no setting in the UI. |

Each test is in the tenant audit log as `notification.test` with the result per channel (`ok`, or the
error text). The error text may name hosts, file paths and recipient addresses; it never holds a
password, the webhook secret, or the webhook's path or query.

### 13.10 When no message arrives

Work from the server outward:

1. **Is a channel configured?** `config check` (as the service user) shows the channels, or says
   *off*. The start of the log has `no notification channel configured` if not. Was the service
   restarted after the change?
2. **Do the files work?** `config check` names a missing, unreadable or empty password, secret or
   CA file. The service user must be able to read them (`sudo -u myownpki cat <file> >/dev/null`).
3. **Does a test arrive?** `myownpki notify test` (§13.5). If it says `sent` but no mail arrives,
   the problem is behind the server: spam filter, the relay's sender rules for `from`, a wrong `to`.
   Look at the mail server's log for the message from the server's address.
4. **Is there anything to report?** A message goes out only when an alert opened, rose, resolved or
   is due for a reminder. Look at the *Alerts* page. After an alert was reported, the next message is
   the reminder in `repeat_every`.
5. **Did it fail and get dropped?** `journalctl -u myownpki -o cat | grep notification`. The
   `error` says why.
6. **Is the monitoring running?** `journalctl -u myownpki -o cat | grep '"job failed"'` – a failing
   `monitor` job logs its error every minute.

| Error (from the test or the log) | Cause and fix |
|---|---|
| `x509: certificate signed by unknown authority` | the mail server's or receiver's certificate comes from a CA the server doesn't trust: set `ca_file` to its root (§13.1, §13.2) |
| `x509: certificate is valid for …, not …` | the host in `smtp` or `url` isn't a name in the certificate; use a name it carries |
| `the server does not offer STARTTLS – set notify.email.security to tls or none` | wrong `security` for that port: 465 needs `tls`, 25 often `none` |
| `authentication as <user>: 535 …` | wrong user or password in the file; or the server wants `LOGIN` or OAuth, which isn't supported |
| `MAIL FROM: 550 …`, `RCPT TO <address>: 550 …` | the relay refuses the sender or a recipient: allow the server's address, check `from` and `to` |
| `connection refused`, `i/o timeout`, `no such host` | name resolution or firewall from the server to the mail server or receiver; e-mail ignores the proxy |
| `webhook … answered 401` or `403` | the receiver rejects the signature: another secret, a body that was parsed and written out again before hashing, or the `sha256=` prefix left out when comparing |
| `webhook … answered 404`, `5xx` | wrong path, or the receiver itself fails; look at its log |
| `webhook … answered 301` or `302` | redirects aren't followed: use the final URL |
| `proxyconnect` or `Forbidden` from the proxy | `HTTPS_PROXY` points to a proxy that refuses the destination, or `NO_PROXY` should list it; the variables are read when the server starts |
| `secret file: … permission denied` | the service user can't read the file (§13.1, step 1) |

### 13.11 An end-to-end check

Do this once after setup, and again after changing a channel. It uses a real alert, so it proves the
whole chain: check, digest, queue, channel. **While the server is sealed it signs nothing** – no new
certificates, ACME orders, agent renewals or CRLs. The web UI keeps working, so you can unseal; but
choose a time when nobody waits for a certificate, and keep it short. You need an instance admin
account.

1. Note the time and seal the server: *Seal now* next to your user name in the UI, or
   `POST /api/v1/system/seal`. The UI shows the seal banner at once; nothing else happens yet.
2. After `sealed_after` (default **10 minutes**) plus up to a minute for the next check, **one
   message** arrives through every channel: `[MyOwnPKI] pki.homelab.lan: 1 new`, with *Server
   sealed* and a link to *Unseal*. The *Alerts* page shows an open `sealed` alert (warning – critical
   only if a CRL is due within a day), and the log has `"msg":"alert"` with `"state":"opened"`.
3. Unseal the server. Within about **one to two minutes** a second message follows: `1 resolved`,
   *Server sealed (open since …)*. The alert moves to *Resolved in the last 7 days*.

If step 2 doesn't happen after about twelve minutes, go through §13.10. If you only want to know that
the channels work, the test of §13.5 is enough and seals nothing.

## 14. TLS scan

Since v0.3.4 the server can check what a host **actually serves**. The alerts of
[chapter 13](#13-monitoring-and-notifications) know what this PKI issued, so `cert_expiry` closes as
soon as the replacement certificate is issued – it cannot tell you that the replacement never reached
the web server. The TLS scan closes that gap. You enter the TLS endpoints you rely on, for example
`proxy.homelab.lan:443`. The server connects to each one every 15 minutes, reads the certificate it
presents and compares it with what this PKI issued for that name. A host that keeps serving the old
certificate after a renewal, a service that is down, a certificate that runs out, a chain that lacks
the intermediate CA: each becomes an alert, with the same digest, reminder and resolve messages as in
chapter 13.

This is level 2 of the three ways to connect a host (level 1 is an ACME client alone, level 3 the
agent). An ACME client or anything else puts the certificate on the host, the scan only watches, and
nothing is installed there. The agent's own check (`check` in `agent.yaml`, §12.3) looks from the host
at the local service; the scan looks from the server, the way a client sees it.

### 14.1 What it does, and what it does not

A scan is **one TCP connection and one TLS handshake**, then the connection closes. The server sends
its ClientHello and what the handshake needs, nothing else: **no HTTP request, no data, no client
certificate**. TLS 1.2 and 1.3 are accepted. So a scan has no redirect to follow and no request that
could change anything on the host.

The handshake takes whatever certificate the endpoint presents, even a wrong one: that is the point,
because otherwise a wrong certificate would only show as "handshake failed" and you could not see what
is served. **Whether to trust it is decided afterwards, by the server itself.** It checks the served
certificate and the intermediates the endpoint sent against the root CAs of this PKI (key usage server
authentication). The result is the chain state: `trusted`, `incomplete` (it leads to this PKI only with
this PKI's own intermediates, so the endpoint forgot to send them) or `untrusted` (it does not lead
here). An expired certificate is checked as of its last valid second, so that expiry does not hide a
chain problem – expiry has its own alert. The host name is compared separately.

| The scan does | The scan does not |
|---|---|
| read the leaf certificate and the first 8 intermediates the endpoint sends | send an HTTP request, follow a redirect or log in |
| compare the leaf with the certificates this PKI issued for the name | present a client certificate; an endpoint that requires one is read only as far as the handshake allows (§14.10) |
| judge the chain against the CAs of this PKI | speak STARTTLS (ports 25, 143, 587 and similar), or check OCSP stapling, cipher suites or key sizes |
| run while the server is sealed | discover hosts: it scans only what an admin entered, never the names inside issued certificates |

What the host sees is an ordinary TLS client that connects and leaves after the handshake. A service
that logs every connection shows one line per scan; some services also log that the client sent no
request.

### 14.2 Requirements

- **Monitoring is on** (chapter 13). The scan needs no notification channel, but without one nobody
  is told.
- **A domain covers the host.** In *ACME → Domains* a domain must match the host name you enter: the
  domain's own name, or a name below it when the domain includes subdomains; an IP address must lie in
  one of the domain's IP ranges (§10.5). Creating a domain needs a fresh second factor, so an API
  token, or an admin without one, cannot widen the set of hosts the server may connect to. The rule
  is checked for the **host**, the address the server connects to; the SNI only chooses the name.
- **The address policy of that domain applies**: when the endpoint is added (for an IP address) and
  at **every scan** (for the addresses a name resolves to). It is *internal networks too* (the default)
  or *public only*. Some ranges are never scanned under either setting (§14.8).
- **The port is in `monitor.scan_ports`** (§14.6). The default list is the ports where TLS starts with
  the first byte: 443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883 and 9443.
- **The server can reach the host:** DNS (names are resolved by `acme.resolver` if you set it, which
  is what you want for split DNS, else by the system's resolver) and an outbound TCP connection to the
  port. The scan connects directly and **does not use the proxy variables** of §13.3.
- **Roles:** tenant admins add and remove endpoints, operators and admins scan now, viewers read
  (§14.9).

### 14.3 Set up

1. Check the configuration. `config check` shows the scan under *Alert thresholds*:

   ```bash
   sudo -u myownpki /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

   ```text
   TLS scan         every 15m, timeout 10s
   scan ports       443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443
   scan limits      100 endpoints, unreachable after 3 failed scans, mismatch after 1h
   ```

   The defaults need no change. The keys are in §14.6; a change needs a restart, and a restart leaves
   the server sealed, as always.

2. Make sure a domain covers the host (*ACME → Domains*, §10.5). The domain `homelab.lan` with
   subdomains covers `proxy.homelab.lan`.

3. Open *Endpoints* (menu *Overview*), fill in *Add an endpoint* and press *Add endpoint*:

   | Field | What to enter |
   |---|---|
   | Host | A fully qualified name such as `proxy.homelab.lan`, or an IP address (IPv6 without brackets). Lower case, no scheme, path, port or wildcard; a trailing dot is dropped. |
   | Port | One of the scan ports; `443` is prefilled. |
   | SNI (optional) | The name to send in the handshake and to expect the certificate for. Empty: a name is its own SNI; an **IP address sends none**, so give one when you enter an IP. Use it too for a host with several names behind one address: one endpoint per name. |

4. The first scan runs at the next dispatch, within 30 seconds. Reload the page after a minute: the
   state should read **OK**, with the SHA-256 fingerprint of the served certificate. Compare it with
   what the host really presents:

   ```bash
   openssl s_client -connect proxy.homelab.lan:443 -servername proxy.homelab.lan </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

   The fingerprint of an OK endpoint links to the certificate in the UI.

Adding is audited as `endpoint.create`, refusals too (§14.9). *Remove* ends the scans, and the alerts
of the endpoint resolve within a minute. *Scan now* scans at once (§14.4).

**Through the REST API.** The calls need an API token with the tenant role named in the table (*My
account → New API token*; the secret starts with `mop_` and is shown once). No second factor is needed
for these calls, because they grant no trust and change no certificate.

| Call | Role | Answer |
|---|---|---|
| `GET /api/v1/endpoints` | viewer | `200`, a list |
| `POST /api/v1/endpoints` | admin | `201` with the endpoint |
| `POST /api/v1/endpoints/{id}/scan` | operator | `202`, no body; the scan runs in the background |
| `DELETE /api/v1/endpoints/{id}` | admin | `204` |

```bash
export MYOWNPKI_TOKEN=mop_…
```

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" -H "Content-Type: application/json" -d '{"host": "proxy.homelab.lan", "port": 443}' https://pki.homelab.lan:9443/api/v1/endpoints
```

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/endpoints
```

```json
[
  {
    "id": "ep_01k9x3d5m7q2w8h4r6t0v1y2z3",
    "host": "proxy.homelab.lan",
    "port": 443,
    "sni": null,
    "name": "proxy.homelab.lan",
    "source": "manual",
    "created_at": "2026-11-12T09:00:00Z",
    "created_by": "admin",
    "state": "ok",
    "expiry_severity": null,
    "next_scan_at": "2026-11-12T09:16:12Z",
    "last_scan_at": "2026-11-12T09:01:04Z",
    "last_ok_at": "2026-11-12T09:01:04Z",
    "fail_streak": 0,
    "last_error_kind": null,
    "served": {
      "fingerprint": "6B1F…C0A2",
      "certificate_id": "crt_01k9x…",
      "serial": "04A1…",
      "subject": "CN=proxy.homelab.lan",
      "issuer": "CN=issuing",
      "not_before": "2026-11-10T08:00:00Z",
      "not_after": "2027-02-08T08:00:00Z",
      "chain_len": 2,
      "chain_state": "trusted",
      "tls_version": "TLS 1.3",
      "seen_count": 3,
      "seen_since": "2026-11-12T09:01:04Z"
    }
  }
]
```

The fingerprints and IDs in the example are shortened. `state` is one of the words of §14.4 in lower
case: `pending`, `ok`, `unmanaged`, `older`, `foreign`, `wrong_name`, `revoked`, `chain`, `unreachable`
or `refused`. `served` is `null` before the first successful scan, and `expiry_severity` is `warning` or
`critical` while the served certificate is within the expiry thresholds. `created_by` is only present for
roles that may add endpoints. `subject` and `issuer` are chosen by the remote host: treat them as
untrusted text in your own scripts. A refusal is `422` with the field and the rule (`errors[0].field` is
`/host`, `/port` or `/sni`), a malformed body `400` and a body over 4 KiB `413`; a duplicate, the limit
and a switched-off scan are `409`; *scan now* twice within 60 seconds is `429` with `Retry-After`. The
full description is in `api/openapi.yaml`.

### 14.4 The Endpoints page

The table has one row per endpoint:

| Column | Shows |
|---|---|
| Endpoint | `host:port`, and the SNI under it if one is set |
| State | one of the words below, with the fixed status colors |
| Last scan | how long ago, for example *5 minutes ago* (the exact time on hover); *Not yet* before the first scan |
| Certificate (SHA-256) | the first 16 characters of the served certificate's fingerprint (all of it on hover), linked to the certificate when this PKI issued it |
| Expires | the end of the served certificate, in the status color while it is within the `monitor.expiry_days` thresholds |
| Issuer | the issuer the served certificate names (the subject on hover). Chosen by the remote host: shown as plain text |
| Last error | the kind of the last failed scan (§14.10), `–` when the last scan worked |
| Added by | who added it – only for roles that may add endpoints |

*Scan now* (operators and admins) makes the endpoint due at once; the result shows within a minute. It
works once per endpoint and 60 seconds. *Remove* (admins) deletes the endpoint. Both are plain forms and
end on the page with a message.

The **state** is computed when the page loads, from the last scan and the certificates as they are now –
the page, the API and the alerts always show the same one. A renewal therefore changes the state of an
endpoint that still serves the old certificate at once, before the next scan; the alert waits for its
confirmation (§14.5).

| State on the page | Meaning | Alert | What to do |
|---|---|---|---|
| **Pending** – not scanned yet | The endpoint is new, or its first scans failed fewer times than `scan_unreachable_after` | – | Wait a minute. If it stays, read *Last error* and §14.10; check that scanning is not off. |
| **OK** | The served certificate is the one this PKI issued for the name (current, not superseded) and the chain is trusted | – | Nothing. |
| **Expiring** (warning or critical) | As OK, but the served certificate ends within the `monitor.expiry_days` thresholds | `scan_expiry` | The host does not renew. Fix the renewal: ACME client or agent (§10.9, §12.5). |
| **Not issued by this PKI** | This PKI never issued a certificate for this name, and the served one is not from this PKI | – | Nothing is wrong as far as this PKI can tell (a router with its own certificate, a service of another CA). Remove the endpoint if it has no meaning for you; set an SNI for an IP address. |
| **Wrong certificate** – an older certificate of this PKI | The endpoint serves a certificate of this PKI that a newer one has superseded (it may still be valid, or have ended) | `scan_mismatch` | The renewal did not reach the host: reload the service, or check the deployment (agent page, ACME client log, hook). |
| **Expired** – no newer certificate was issued | The endpoint serves a certificate of this PKI that has ended, and this PKI has issued nothing newer for the name. The color is that of the expiry alert. The state word in the API is `older`, as for a superseded certificate | `scan_expiry` (critical), unless `cert_expiry` already reports it | The certificate was never renewed. Issue one and deploy it (ACME client or agent, §10.9, §12.5). A certificate that was renewed but not deployed is *Wrong certificate* above. |
| **Wrong certificate** – not issued by this PKI | This PKI issued a certificate for the name, but the endpoint serves another CA's – often a self-signed default after a reinstall | `scan_mismatch` | Point the service at the certificate of this PKI. |
| **Wrong certificate** – not valid for this name | The served certificate is from this PKI but does not cover the name (another host's certificate, a wildcard of a different level) | `scan_mismatch` | Point the service at the certificate issued for this name. |
| **Wrong certificate** – revoked (critical) | The endpoint serves a revoked certificate of this PKI | `scan_mismatch`, critical | Replace it at once; clients that check revocation reject it. |
| **Chain problem** – the intermediate CA is not sent, or the chain does not lead to this PKI | The right certificate, but the chain is `incomplete` or `untrusted` | `scan_chain` | Configure the service with the full chain (`fullchain.pem`, not the leaf alone) from this PKI. |
| **Unreachable** – *N* scans failed | The last *N* scans failed; *N* has reached `scan_unreachable_after` | `scan_unreachable`, except for *client certificate required* | Read *Last error* and §14.10. A service that is only rebooting never gets here. |
| **Refused** – not scanned | No domain covers the host any more, or the address policy or the port list refuses it. Not an outage | – | *Last error* says which. Restore the domain or the port, or remove the endpoint. |

**Why a name this PKI never issued is "Not issued by this PKI" and not a mismatch.** The scan compares
what is served with what this PKI **issued** for the name. For a name nothing was issued for, there is
nothing to compare, and an alert about a certificate nobody here manages would be noise. You entered the
endpoint, so a dead service (`scan_unreachable`) or an expiring certificate (`scan_expiry`) on it still
alerts. An endpoint entered by IP address without an SNI is in this state too: the address says nothing
about a name. The page then asks you to add it again with an SNI.

**What "issued for the name" means.** The expected set is every certificate of this PKI that is valid
now (not revoked, not expired, already valid), is not an agent identity certificate, covers the name and
is **not superseded**: no other valid certificate with the same set of names ends later (the rule of
`cert_expiry`, §13.6). A wildcard certificate covers one label, as RFC 6125 says: `*.homelab.lan` covers
`proxy.homelab.lan`, not `a.b.homelab.lan` or `homelab.lan`. A wildcard and an exact certificate for the
same name are both current. The served leaf is recognized by its SHA-256 fingerprint.

### 14.5 The alerts

The scan adds four alert kinds to chapter 13. They are on the *Alerts* page (as *Wrong certificate
served*, *Served certificate expires*, *Endpoint unreachable* and *Chain problem*), count in the *Open
alerts* figure of the dashboard, are in `GET /api/v1/alerts`, and go out through the channels like any
other alert. The dashboard's *Needs attention* block does not list them. Each alert is named after
`host:port` and links to the *Endpoints* page. They follow the rules of §13.6: one alert per condition,
severity may rise, and it resolves by itself at the next evaluation – so a message that says *resolved*
follows within a minute of the next good scan, or of removing the endpoint.

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `scan_mismatch` | the state is *an older certificate* (a newer one exists), *not issued by this PKI* or *not valid for this name*, **two scans in a row saw the same certificate**, and the newest certificate for the name is at least `scan_mismatch_after` old (counted from its creation). *Expired* never opens it: there is no newer certificate to wait for | always | – |
| `scan_mismatch` (revoked) | the state is *revoked* and two scans in a row saw it; no waiting time | – | always |
| `scan_expiry` | the served certificate ends within `monitor.expiry_days` or has ended, unless that certificate has its own `cert_expiry` alert | 14 days left | 3 days left, or expired |
| `scan_unreachable` | `scan_unreachable_after` scans in a row failed with *dns*, *timed out*, *connection refused*, *could not connect*, *TLS handshake failed* or *no certificate* | from that failure on | down for 24 hours |
| `scan_chain` | the right certificate is served with an incomplete or untrusted chain, seen by two scans in a row, and it is a certificate of this PKI | always | – |

What the rules are for:

- **Two scans and a waiting time** keep a deployment that is half through quiet. A renewal creates the
  new certificate first, and the host picks it up some minutes later; `scan_mismatch_after` (default 1
  hour) is the time a deployment may take. The count of scans includes the time before the renewal: an
  endpoint that served the old certificate for weeks has been seen many times, so its alert opens at the
  first evaluation after the waiting time. A mismatch also needs a current certificate for the name: if
  there is none (the old one ran out and nothing replaced it), `cert_expiry` is the alert.
- **A failed scan keeps the last good data.** Below `scan_unreachable_after` failures the state stays what
  the last good scan said, so a host that reboots, or one failed scan, produces nothing. With the default
  interval of 15 minutes, three failures take about half an hour. The 24 hours until critical are
  counted from the last good scan (from the day the endpoint was added, if it never worked).
- **`scan_expiry` shares the thresholds of `cert_expiry`** (`monitor.expiry_days`): the question is the
  same – how long until clients refuse it. It is its own kind because it is about what is **served**: it
  is the only expiry alert for a certificate of another CA, or a superseded one, that is still in use.
- **Refusals are no outage.** An endpoint that the address policy or the port list refuses is shown as
  *Refused* and raises no alert.

The text of an alert holds only what the server wrote itself: the endpoint, serials, fingerprints, dates
and the kind of error. **The subject and issuer of a served certificate never go into an alert,** so an
e-mail or webhook carries nothing a remote host chose. An example:

```text
NEW

  [warning] proxy.homelab.lan:443
  proxy.homelab.lan:443 serves an older certificate of this PKI (serial 04A1…, ends 2026-11-13 09:00 UTC) instead of the newest one for proxy.homelab.lan (serial 07C2…, issued 2026-11-11 08:00 UTC) – the renewal did not reach it. Reload the service or check the deployment.
  https://pki.homelab.lan:9443/endpoints
```

**Scanning off.** With `monitor.scan_interval: off` no scan alert is produced and the open ones resolve.
The endpoints stay, you can still add and remove them, and the page says that scanning is off.

### 14.6 Settings

In `config.yaml` (restart to apply; `deploy/config.example.yaml` has them with comments):

```yaml
monitor:
  scan_interval: 15m
  scan_timeout: 10s
  scan_ports: "443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443"
  scan_max_endpoints: 100
  scan_unreachable_after: 3
  scan_mismatch_after: 1h
```

| Key | Default | Allowed | Environment variable |
|---|---|---|---|
| `monitor.scan_interval` | `15m` | `5m`–`24h`, or `off` to never connect | `MYOWNPKI_MONITOR_SCAN_INTERVAL` |
| `monitor.scan_timeout` | `10s` | `2s`–`30s`; resolve, connect and handshake of one scan together (judging the chain afterwards has its own 5 seconds, §14.7) | `MYOWNPKI_MONITOR_SCAN_TIMEOUT` |
| `monitor.scan_ports` | `443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443` | 1 to 32 different ports from 1 to 65535, comma-separated | `MYOWNPKI_MONITOR_SCAN_PORTS` |
| `monitor.scan_max_endpoints` | `100` | 1–500 | `MYOWNPKI_MONITOR_SCAN_MAX_ENDPOINTS` |
| `monitor.scan_unreachable_after` | `3` | 1–10 failed scans in a row | `MYOWNPKI_MONITOR_SCAN_UNREACHABLE_AFTER` |
| `monitor.scan_mismatch_after` | `1h` | `5m`–`24h` | `MYOWNPKI_MONITOR_SCAN_MISMATCH_AFTER` |

The thresholds of `scan_expiry` are `monitor.expiry_days` (§13.7). A value outside its range makes the
server refuse to start and `config check` fail, naming the key, as in §13.7. The port list is a decision
for whoever edits the configuration on the server: a tenant admin cannot turn the server into a port
scanner by adding endpoints on other ports. STARTTLS ports (25, 143, 587) are not supported, because they
need protocol bytes before the handshake. In a container set the variables in the Compose file (§13.3);
the defaults need none.

Each endpoint is scanned every `scan_interval` plus a random 0–10 %, so that 100 endpoints do not all fire
together after a restart. If the clock of the server steps back (a VM that booted with a wrong time and
then set it right), an endpoint whose next scan lies more than twice the interval ahead counts as due, so
a wrong clock does not leave endpoints silent. Not configurable: the 4 workers, the 30-second dispatch, the 60 seconds between
two *Scan now* of one endpoint and the 24 hours after which an unreachable endpoint turns critical.

### 14.7 What is stored, and the limits

Per endpoint the server keeps, in `pki.db`: host, port, SNI, who added it and when, the time of the next
and the last scan and of the last success, how many scans failed in a row, the **kind** of the last error
with a fixed short message, and about the served leaf: the SHA-256 fingerprint, serial, subject, issuer
(each clipped to 256 bytes, valid UTF-8, control characters replaced), start and end, how many
certificates the endpoint sent, the chain state, the TLS version, and how many scans in a row saw this
fingerprint and since when. **It never stores the certificate itself, a public key, the list of names or
the address a name resolved to** (that address goes to the log at debug level). There is no history, only
the last result. The data is part of `pki.db`, so backups carry it.

| Limit | Value |
|---|---|
| Endpoints | 100 (`scan_max_endpoints`, 1–500); the next one is refused with `409` |
| Scans at the same time | 4 workers; an endpoint that is being scanned is skipped; a backlog is worked off at the speed of the workers |
| One scan | `scan_timeout` (10 s) for resolve, connect and handshake; at most 4 addresses are tried, 3 seconds each; the leaf and 8 intermediates are looked at. Judging the chain against this PKI's CAs after the handshake has a budget of its own, **5 seconds**, so a slow handshake cannot leave it without time |
| Request body of *add* | 4 KiB |
| *Scan now* | once per endpoint and 60 seconds (kept in the database, so a restart does not reset it) |

Scans **work while the server is sealed**: nothing is decrypted, and the certificates the scan compares
with are public data in `pki.db`. A sealed server that still reports a deployment that lapsed is the
point. The log has one `scan` line when the outcome of an endpoint changes (reachable, failed with a
kind, the certificate changed) and nothing for a scan that found the same as before:

```bash
journalctl -u myownpki -o cat | grep '"msg":"scan"'
```

The remote host's own words are never stored, quoted or logged.

### 14.8 Which addresses are never scanned

The same guard decides where the server may connect for http-01 validation (§10.9), for the check of an
agent's enrollment (chapter 12) and for the scan. A name is resolved **once**, and the connection goes to
exactly the address that was checked – a DNS answer that changes between the check and the connect
cannot redirect it. Every address a name resolves to is checked; the allowed ones are tried in the
resolver's order.

**Never, under either policy:**

- unspecified (`0.0.0.0`, `::`), **loopback** (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`,
  `fe80::/10`) and multicast addresses, and an IPv6 address with a zone (`%eth0`);
- the reserved IPv4 ranges `0.0.0.0/8` and `240.0.0.0/4` (the latter includes the broadcast address);
- the IPv6 ranges that carry an IPv4 address inside, or translate to one: IPv4-compatible (`::/96`),
  NAT64 (`64:ff9b::/96` and `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001::/32`) and the
  IPv4-translated range (`::ffff:0:0:0/96`). A router or a client may translate such an address to the
  embedded IPv4 one, so `64:ff9b::7f00:1` or `::ffff:0:7f00:1` could reach `127.0.0.1` although it looks
  like a global address. The ranges are refused entirely, because no service of an internal PKI lives
  there. IPv4-mapped addresses (`::ffff:a.b.c.d`, a different range from the IPv4-translated one) are
  judged as the IPv4 address they carry;
- ranges that are not globally reachable and are not private networks either, so nothing of yours lives
  there: `192.0.0.0/24` (IETF protocol assignments), `198.18.0.0/15` (benchmarking), `192.88.99.0/24`
  (the retired 6to4 relay anycast), `fec0::/10` (the retired site-local range), `100::/64` (discard only)
  and `5f00::/16` (SRv6 segment identifiers).

The documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`) are not
on the list: they are allowed, because the examples and tests of this project use them as stand-ins for
public addresses. They are not routed on the internet, so a scan of one simply times out.

**Under the policy *public only*** a domain also refuses private networks (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and the carrier-grade NAT range `100.64.0.0/10`.
*Internal networks too*, the default, allows them.

So the server cannot scan its own `127.0.0.1`. Its LAN address is allowed: a bare handshake gives nothing
that any client on that network does not get anyway.

### 14.9 Who sees and does what

| | Role | Notes |
|---|---|---|
| *Endpoints* page, `GET /api/v1/endpoints` | tenant-wide **viewer** or higher (permission `pki.read`) | The endpoints name the hosts of the whole tenant, so a role limited to one CA gets 403 and has no *Endpoints* entry in the menu. Works while sealed. |
| *Scan now*, `POST /api/v1/endpoints/{id}/scan` | **operator** or admin (permission `endpoint.scan`) | An endpoint that is entered already adds no new target. Once per endpoint and 60 seconds. |
| *Add endpoint* and *Remove*, `POST /api/v1/endpoints`, `DELETE /api/v1/endpoints/{id}` | tenant **admin** (permission `endpoint.manage`) | It makes the server connect to hosts of your choosing, so it sits at the level of domains and agents. No second factor: it grants no trust and changes no certificate, so an API token may do it. A role limited to one CA cannot. |
| The scan settings | whoever edits `config.yaml` or the environment, on the server | There is no setting in the UI. |

The tenant audit log (*Administration → Audit log*) records `endpoint.create`, `endpoint.delete` and
`endpoint.scan` (scan now) with host and port. **A refusal is recorded too**, with the reason and the
result `denied` or `failure`: an attempt to point the server at `127.0.0.1`, or at a port outside the
list, is on record.

An endpoint ID that is not well-formed (1 to 64 letters, digits, `_` or `-`) is "not found", and that is
checked after the role: a viewer still gets 403 first. If such a request is denied or fails, the audit
entry names only the target type `endpoint`; what was asked for is in the details (`id`), cleaned of
control characters and clipped to 64 bytes, so a hostile ID cannot put text into the log. The scans
themselves are not audited, only the requests.

### 14.10 When something does not work

First look at *Last error* on the page, or `last_error_kind` in the API. It is always one of these words;
what the remote host said is never kept. Then try the same from the server:

```bash
openssl s_client -connect proxy.homelab.lan:443 -servername proxy.homelab.lan </dev/null
```

| Last error | Cause | Fix |
|---|---|---|
| `dns` | The name does not resolve from the server, or has no address | `getent hosts proxy.homelab.lan` on the server. With split DNS set `acme.resolver` to the server that knows the name (§10.7). |
| `timed out` | Nothing answered within `scan_timeout`: the host is down, or a firewall drops the packets | Check route and firewall from the server to the host and port. Raise `scan_timeout` (up to 30 s) only if the host really is slow. |
| `connection refused` | The host answers and nothing listens on that port | Start the service, or correct the port. |
| `could not connect` | Another network failure: no route, the network is unreachable, a reset | Same checks as for a timeout; with `log.level: debug` the log names the address that failed. |
| `TLS handshake failed` | The port does not speak TLS from the first byte (plain HTTP, SSH, a STARTTLS port), the service speaks only TLS 1.0 or 1.1, or no cipher suite matches | `openssl s_client` shows which. A STARTTLS service cannot be scanned: remove the endpoint. Enable TLS 1.2 on the service. |
| `no certificate` | The handshake worked, but the server presented no certificate | Rare; a service configured for anonymous or pre-shared keys. This scan cannot judge such a service. |
| `client certificate required` | The service demands a client certificate and the scan presents none (a TLS 1.2 server rejects it after its chain; with TLS 1.3 the scan still reads the certificate, so such a service can look fine) | The endpoint cannot be scanned. It shows as *Unreachable* and **raises no alert**. Remove it, or scan a listener without client authentication. |
| `refused by the address policy` | Every address of the name is in a range that is never scanned, or is private on a *public only* domain (§14.8) | Look at what the name resolves to; correct DNS, or change the domain's address setting. |
| `no domain covers the host` | The domain was removed or narrowed after the endpoint was added | Restore the domain (§10.5) or remove the endpoint. |
| `port is not in monitor.scan_ports` | The port list was changed after the endpoint was added | Put the port back (§14.6, restart) or remove the endpoint. |

Other symptoms:

| Symptom | Cause and fix |
|---|---|
| Adding is refused: `host: no domain covers this host – the host must lie in a domain of this PKI (Domains)` | No domain matches (§14.2). Create one, or let an existing one include subdomains. |
| `port: port 22 is not in the list of scannable ports (monitor.scan_ports: …)` | The port is not in the list (§14.6). |
| `host: this address range is never scanned …` | The IP address is in one of the ranges of §14.8. The message lists only the common ones (unspecified, loopback, link-local, multicast, reserved); the IPv6 forms that embed an IPv4 address and the non-global ranges are refused the same way. Use the host's name or another address. |
| `host: the address policy of the domain "homelab.lan" (public) does not allow this address` | A private address on a *public only* domain. |
| `host: …` about spaces, a scheme, brackets or a port | Enter a host name or IP address only; the port is its own field. `localhost` and single-label names fail because a fully qualified name is required. |
| `409`: `the limit of 100 endpoints is reached …` or `this endpoint is entered already` | Remove one or raise `scan_max_endpoints`; or the same host, port and SNI exist already. |
| *Scan now* is missing, or `409 scanning is switched off` | `monitor.scan_interval: off`. |
| *Scan now* answers `429` (*try again in N seconds*) | One request per endpoint and 60 seconds. |
| *That endpoint is gone already* on the page, or `404` from the API, for an endpoint that exists | The ID in the request is not well-formed (1 to 64 letters, digits, `_` or `-`), so it counts as "not found". Use the buttons of the page, or the `id` that `GET /api/v1/endpoints` returns. A caller without the role gets 403 first, never 404. |
| State *Not issued by this PKI*, but the name has a certificate here | The endpoint is an IP address without an SNI, or the certificate this PKI issued names something else (check *Certificates* for the names). Add the endpoint again with the SNI. |
| State *Wrong certificate* – *an older certificate* right after a renewal | The state shows at once; the alert waits `scan_mismatch_after`. Reload the service, then *Scan now*. |
| State *Expired* – *no newer certificate was issued* | The host serves a certificate of this PKI that has ended, and nothing newer exists for the name. Issue a new certificate and deploy it (§10.9, §12.5). |
| The state stays *Pending* | The first scans failed fewer than `scan_unreachable_after` times (see *Last error*), or scanning is off, or the server was started a moment ago. |
| No alert although the state is wrong | The two scans or the waiting time are not over yet (§14.5), the name has no current certificate here, or the endpoint is *Not issued by this PKI*. Then §13.10 for the messages. |

### 14.11 An end-to-end check

Do this once after setup, on a test host with a service that serves a certificate of this PKI for a name
you can renew; the names are examples. Set `monitor.scan_interval: 5m` for the test if you do not want to
wait, and use *Scan now* (once a minute per endpoint) to speed up the steps. You need an admin account
and a channel from chapter 13.

1. `config check` shows the *TLS scan* rows (§14.3). Restart the service and unseal it.
2. *Endpoints*: add `proxy.homelab.lan`, port 443. Within a minute the state is **OK**; compare the
   fingerprint with the `openssl s_client` command of §14.3.
3. **Older certificate.** On the host switch the service to a previous certificate of the same name (the
   agent's backup, or one issued earlier) and reload. The newer certificate must be older than
   `scan_mismatch_after`. After two scans and the next evaluation, one `scan_mismatch` alert (warning) is
   on *Alerts* and one message arrives.
4. **Fix.** Put the current certificate back and reload. After the next scan the alert resolves within a
   minute; the second message says *resolved*.
5. **Unreachable.** Stop the service. After `scan_unreachable_after` (3) failed scans: `scan_unreachable`.
   A restart within two scans, as a reboot does, produces nothing. Start it again: resolved.
6. **Not issued by this PKI.** Add an endpoint that serves a certificate of another CA for a name this PKI
   never issued: the state reads *Not issued by this PKI* and no `scan_mismatch` opens.
7. **Guard.** Adding `127.0.0.1` port 443 and `proxy.homelab.lan` port 22 is refused; both attempts are in
   the audit log. Seal the server: the *Last scan* column keeps moving.
8. Remove the test endpoints; their alerts resolve within a minute.

If step 3 produces no alert after about twelve minutes with `scan_interval: 5m`, go through §14.10 and
then §13.10.

## 15. Reports and analysis

Since v0.3.8 the web UI has two pages that answer "what is the state of the PKI, and why?": **Reports** (charts
of the expiry of the current week and the next 12 weeks, the issuances, the certificates per CA, the alert history and the agent
fleet) and **Analysis** (ten fixed rules that name what no alert covers). The dashboard shows two of the charts.
Everything is computed on the server from data it already holds. Nothing is sent to an outside service, nothing
new is stored (§15.5), and nothing needs to be configured.

The alerts of [chapter 13](#13-monitoring-and-notifications) say that something needs action now. These pages are
for looking, for example once a week. The analysis is advice: it raises no alert, sends no message and has no
dismiss button.

### 15.1 The Reports page

*Reports* is under *Overview*, between *Alerts* and *Analysis*. It has five sections, each a fold (`<details>`).
*Expiry* and *Authorities* are open, the rest closed; the state is not remembered. Each section has a sentence that
says what is counted, a chart with a summary sentence, and the same numbers as a table in a closed fold *Numbers*.
The page says when it was computed. **Weeks are ISO weeks in UTC** (Monday 00:00 to Sunday), labeled `W47`; empty
weeks are shown, not skipped. A section with nothing to count shows a sentence instead of a chart.

| Section | Chart | What is counted | Left out |
|---|---|---|---|
| Expiry | *Expiry timeline*: 13 weekly columns, the current week and 12 more; the first counts only certificates that end after the moment of the build | Every certificate that is not revoked and ends in that week, whatever its source | Revoked certificates; the identity certificates of agents |
| Issuances | *Issuances per week*: 12 weekly columns ending with the current week, stacked by source | Certificates with the source `issued`, by creation time | Imported and external certificates; the identity certificates of agents |
| Authorities | *Certificates per CA and status*: one horizontal bar per CA, stacked by valid, expiring (30 days), expired, revoked | The certificates of each CA; those without a CA of this server as *External certificates*, last | The identity certificates of agents; a CA without certificates that is not active |
| Alerts | *Alerts opened per week*: 5 weekly columns (the current week and four before), stacked by warning and critical, and the number of alerts open now | The alerts the server still keeps, counted in the week they opened, with the severity they have now | Anything older than the 30 days the server keeps resolved alerts |
| Agents | *Agents by state*, *Agent versions compared with the server*, *Deployments by state* | See below | Only shown while the agent listener is on |

**Expiry windows.** A column is *critical* when its week starts inside the critical expiry limit of the monitor, counted
from the moment of the build, and *warning* when it starts inside the warning limit (`monitor.expiry_days`, default 3
and 14 days, §13.7), else *later*. The current week starts at the moment of the build. The table has the window in
a *Window* column. The chart counts every certificate that ends, also one that a newer certificate with the same names
replaces already; `cert_expiry` (§13.6) opens only when nothing newer covers the names.

**Source classes** (issuances). The server records no field for how a certificate was requested, so the class comes from
the ACME orders: *ACME* when an order points at the certificate and the order's account has no agent link, *Agent* when
the account is an agent's, *UI and API* when no order points at it (the UI and the REST API are one engine call and cannot be
told apart).

**Agents.** *Agents by state* counts Active, Silent (warning), Silent (critical), Disabled and Revoked. Silent uses the
limits of the `agent_silent` alert (1 hour and 24 hours by default); an agent that never reported counts as Active, as in the
monitor. *Versions* and *Deployments* count the agents that are neither disabled nor revoked: versions as Current or newer,
Older and Unknown (not a release number, or a server that is a development build); deployments as Deployed, Pending,
Failed and Rolled back, without the removed ones.

**Dashboard.** For a role that may read the reports, the dashboard shows the *Expiry* and *Authorities* charts below the
table of certificates that expire in 30 days, each in an open fold, with a link *All reports*. If the report cannot be
built, the dashboard shows one warning line and the rest still works; the cause is in the server log.

### 15.2 The Analysis page

*Analysis* shows, from top to bottom: a summary line (for example *3 findings: 1 critical, 1 warning, 1 info; 2 rules
cannot be assessed.*), the **findings** as a table (*Severity*, *Rule*, *Subject* with a link to the page of the
certificate, CA, agent, domain or account, *What was seen*, *Why it matters*, *What to do*), the **rules** with state and
number of findings, and a short *How this works*. `?rule=<id>` limits the findings to one rule; an id that is no rule is a 400
page. The tables scroll sideways on a small screen. At most 200 findings per rule are kept; the rest is counted.

Every rule is in exactly one **state**: `ok`; `findings` (if part of its input could not be judged, the page adds
*N not assessed* and the reason); or `unknown`, when the input is missing. **`unknown` is not a problem and never a
finding**; the reason is shown. A finding states only what the data shows ("no scanned endpoint served this certificate in
the last 7 days", never "unused"). The thresholds are constants in `internal/analysis/rules.go`, not configuration, and
defaults to be judged on a real installation.

| Rule | Fires when | Thresholds | Severity | Unknown when |
|---|---|---|---|---|
| `orphaned_certificate` | A valid, current certificate (no valid one with the same names ends later) is old enough, no agent deployment in state `deployed` reports it, and no scanned endpoint that covers one of its names serves it, although at least one such endpoint was scanned and served something else | Certificate at least 14 days old; a witness is a covering endpoint scanned successfully in the last 7 days that has served another certificate for at least 7 days | info | The TLS scan is off; or, for certificates without a witness, the reason counts them (they are never judged one by one) |
| `duplicate_certificates` | Valid `issued` certificates with the identical set of names from at least two different sources (UI and API, an ACME account, an agent), or three or more from one source | Each has more than a third of its lifetime left, so the overlap of a renewal does not count | warning (two sources), info (one source) | The source of a certificate in a group is not known |
| `renewal_loop` | Certificates for the same set of names created within a short time, whatever their status now | 3 or more in 24 hours (warning), 6 or more in 24 hours (critical), 8 or more in 7 days (warning) | warning, critical | never |
| `expiry_wave` | One ISO week in which many valid certificates end | At least 10 certificates in the week and at least 30 percent of all valid certificates | warning | Fewer than 20 valid certificates |
| `weak_key` | A valid certificate with an RSA key under 2048 bits | RSA 2048 is not flagged | critical | The key size cannot be read |
| `weak_signature` | A valid certificate, or the certificate of a current intermediate CA, signed with SHA-1, MD5 or MD2 (ECDSA and DSA with SHA-1 count too) | The signature of a root is not judged | critical | The algorithm is not known to the program |
| `ca_cliff` | An issuing CA (active, key on this server) whose current certificate ends sooner than the default validity of the certificates it issues | The default is the longest `validity_days` of the CA's domains, 90 days if it has none; critical when less than 14 days are left or it has ended | warning, critical | The CA has no signed certificate yet |
| `outdated_agent` | An active agent whose version is older than the server's | A different major or minor version is a warning, only a patch behind is info | warning, info | The agent listener is off; the server is a development build; an agent version that is not a release number |
| `unused_acme_account` | A valid ACME account without agent link | At least 30 days old and no order in 90 days, or none ever | info | never |
| `unused_domain` | A domain for which no certificate of the tenant, of any status, has a name it covers | At least 30 days old | info | never |

The findings hold names that come from CSRs, ACME clients and agents, clipped to 120 characters in the API and
escaped in the page. The links go only to pages of the UI.

### 15.3 Who sees what

| | Role | Notes |
|---|---|---|
| *Reports* and *Analysis* pages, the dashboard charts, `GET /api/v1/reports`, `GET /api/v1/analysis` | tenant-wide **viewer** or higher (permission `pki.read`) | The pages name the CAs, hosts, accounts, agents and domains of the whole tenant, so a role limited to one CA gets 403 (the 403 page in the UI), has no menu entry and no dashboard charts. An API token follows its roles: tenant-wide reads, limited to one CA is 403. Works while sealed. |
| Anything that changes | nobody | There is no setting, button or write operation: the pages read and calculate. |

A request that fails the check reads no data: the permission is the first thing the report and analysis services
test, and the cache is not consulted before it.

### 15.4 The REST API

Both operations are in `api/openapi.yaml` (tag `monitoring`, `x-required-role: viewer`). Times are RFC 3339 in UTC, every
string is plain text, never HTML, and the answer has `Cache-Control: no-store`.

- `GET /api/v1/reports`: `generated_at` (whole seconds), `expiry.weeks[]` (`start`, `count`, `window` = `critical`,
  `warning` or `none`), `issuances.weeks[]` (`start`, `acme`, `agent`, `ui`), `authorities[]` (`id`, `name`, `valid`,
  `expiring`, `expired`, `revoked`), `alerts` (`retention_days`, `weeks[]` with `start`, `warning`, `critical`, and `open`)
  and `agents` (`null` while the agent listener is off). `valid` includes `expiring`; the certificates without a CA are
  the entry with an empty `id` and `name`, last.
- `GET /api/v1/analysis`: `generated_at`, `summary` (`critical`, `warning`, `info`, `unknown`: the last is the number of
  rules in state `unknown`), `rules[]` (`id`, `title`, `state`, `count`, `unknown_reason`) and `findings[]` (`key`, `rule`,
  `severity`, `subject`, `seen`, `why`, `recommendation`, `href`). `count` is every finding of the rule, `findings` at most
  200 per rule. `key` is `rule:` plus the subject's ID and stays the same between runs.
- `GET /api/v1/analysis?rule=<id>` returns one rule and a summary of that rule only. An unknown id is `400`
  (`bad-request`, field `rule`, the valid ids named, the input not echoed); the id is checked before anything is read, so
  a caller without the permission who sends a bad id also gets 400.

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/analysis | jq -c '.rules[] | {id, state}'
```

### 15.5 Cache, what is stored, and cost

- **One report and one analysis per tenant, shared by every caller who passes the permission check, built at most once
  a minute.** The check comes first; the cache has no key that comes from a request. A reload within the minute shows the
  same numbers (`generated_at` stays), and a build runs one at a time, so a burst of reloads cannot hammer the database.
- **Nothing is stored.** No table, no file and no setting holds a report or a finding; a restart starts with an empty
  cache. There is no history beyond what the monitor keeps: resolved alerts for 30 days.
- **Migration `pki.db` 0020** (`0020_report_indexes.sql`) adds two indexes: `certificates_created_at` on `certificates
  (created_at)` and the partial `acme_orders_certificate` on `acme_orders (certificate_id)` where it is not null. They
  serve the issuance chart. Nothing else changes in the database: no column, row or constraint.
- **Cost.** The expiry and issuance charts read the `not_after` and `created_at` of the certificates in their window
  through those indexes. The analysis reads the valid certificates and parses their DER once per build to find the key size
  and the signature algorithm; the list pages do not parse DER. The analysis walks the agents (one read per agent for its
  deployments), the ACME accounts, the domains and the stored result of the last TLS scan. It **never starts a scan** and opens
  no connection: the two packages import no network package, which a test checks.
- **No new dependency, no script.** `go.mod` and `THIRD_PARTY.md` did not change for these pages.

### 15.6 Charts without JavaScript

The charts are inline SVG written by the server and styled by the same style sheet as the rest of the UI. No script runs
on these pages, and the Content Security Policy (`script-src 'self'; style-src 'self'`, no inline code or style) is
unchanged. The project plan names Apache ECharts as an island; v0.3.8 does not use it. There is no JavaScript pipeline in the
repository and esbuild is not an approved dependency, and the HTML tooltip of ECharts is reported to write inline `style`
attributes, which that policy refuses (not verified for the current version). ECharts stays approved and unused; the
decision is recorded in PLAN §7 and PHASE3 §14.3.

What that means for you: no zoom or legend toggle, a bar has the browser's own tooltip (an SVG `<title>`). Accessibility:
every chart is a `<figure>` with a caption and a one-sentence summary; the SVG has a title and a description; the exact
numbers are a real table under it; every series has a text label and the second and third also a hatch pattern, so
color is never the only information; nothing animates. A test checks 3:1 contrast of the chart colors against the
background in the light, dark and OS-follow themes. Text that comes from data is cleaned of control characters, clipped
(18 characters on an axis, 48 in the table and tooltip) and escaped by the template.

### 15.7 When a number or a finding looks wrong

| Symptom | Cause and check |
|---|---|
| A new certificate, revocation or alert is not in the numbers | The report is built at most once a minute; look at *Computed at* and reload after a minute. |
| The expiry or authority numbers differ from *Certificates* | *Certificates* hides agent identity certificates by default; compare with its filters `valid`, `expired` and `revoked` and `?status=expiring`. The expiry chart counts every certificate that ends in the week, also one that a newer certificate replaces, and does not count revoked ones. |
| No *Agents* section in *Reports* | The agent listener is off (§12.1). |
| *Orphaned certificate* says `unknown` | The TLS scan is off (§14), or no scanned endpoint covers the certificates with a stable result from the last 7 days. Add the endpoint (§14.4). |
| *Expiry wave* says `unknown` | Fewer than 20 valid certificates. |
| *Outdated agent* says `unknown` | The agent listener is off, or the server runs a development build. |
| 403 on the page or the API | The role or the token is limited to one CA (§15.3). |
| 400 on `GET /api/v1/analysis?rule=…` | The id is not one of the ten; the message lists them. |
| Reports and Analysis are missing from the menu | The role cannot read the whole tenant. |

### 15.8 An end-to-end check

Do this after the update to v0.3.8, as an admin. It has not been run on a live installation at the time of writing.

1. `myownpki db status` shows `pki.db` 0020.
2. *Reports*: compare *Certificates per CA and status* with *Certificates* filtered by `status=valid`, `expired` and
   `revoked`, and the *Expiry timeline* with *Certificates* filtered by `status=expiring`: the totals should agree.
3. Issue one certificate in the UI and one with an ACME client. After a minute, reload *Reports*: the current week of
   *Issuances per week* shows one *UI and API* and one *ACME* (or *Agent*) certificate, and the *Numbers* table says the same.
4. Open both pages with the keyboard (Tab, Enter on a fold) and in the dark theme; the browser console shows no
   Content Security Policy violation.
5. *Analysis*: read each finding and judge it. With the TLS scan off, *Orphaned certificate* must say `unknown`.
6. `curl` both endpoints with a token of a viewer (200) and of a viewer limited to one CA (403).
