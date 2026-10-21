# Operations guide – MyOwnPKI v0.1

For the administrator who runs MyOwnPKI: installing it, the first start, daily work, backup and
restore, moving from `pki.sh`, and what to do when something is lost. Installing from a release or
with Docker is in the [README](../README.md); the full design is in [PLAN.md](PLAN.md).

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

1. Install the binary (release archive, package or Docker – see the README) and create a system
   user, for example `myownpki`, that owns the data directory (mode 0700).
2. Copy [`deploy/config.example.yaml`](../deploy/config.example.yaml) to the config path, set
   `data_dir`, and check it:

   ```bash
   myownpki config check --config /etc/myownpki/config.yaml
   ```

3. Decide who may reach the admin listener. Loopback is the default. For remote administration set
   `admin.listen: 0.0.0.0:9443` **and** `admin.allowed_networks` (for example
   `127.0.0.1, 192.168.10.0/24`). Keep `127.0.0.1` in the list: `myownpki healthcheck` connects
   through loopback. Never expose the admin listener to the internet.
4. Add the names you type into the browser to `admin.tls_names` (for example
   `pki.homelab.lan, 192.168.10.5`), or give your own certificate with `admin.tls_cert_file` /
   `admin.tls_key_file`.
5. The public listener must be reachable under the base URL that is baked into every certificate
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

1. `myownpki backup …` and `myownpki backup verify …`.
2. Replace the binary (or pull the new image), start the server – migrations run at start.
3. `myownpki db status` shows the versions; a newer database than the binary is refused, so going
   back means restoring the backup from step 1.
