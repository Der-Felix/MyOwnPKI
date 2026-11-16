---
title: Back up and restore
summary: What a backup holds, the daily timer, how to check a backup, copy it off the machine and restore it.
audience: Admins who run the server
order: 50
site: /guides/backup-and-restore/
sources:
  - docs/OPERATIONS.md
  - cmd/myownpki/backup.go
  - cmd/myownpki/passphrase.go
  - internal/backup/backup.go
  - internal/backup/restore.go
  - deploy/install.sh
---

## What a backup holds

A backup is the only way back after a disk failure, a bad update or a compromised server. It is also a copy of your CA
keys, so it needs care in both directions: it must exist, and it must not lie next to the secrets that open it.

| In the backup | Not in the backup |
|---|---|
| Every database: users, the audit logs, CAs, certificates and the encrypted keys | `config.yaml`: copy `/etc/myownpki/config.yaml` yourself |
| `auth.key`, only if it lives in the data directory | `auth.key` when `auth.key_file` points elsewhere; without it every user needs a second-factor reset after a restore |
| A `manifest.json` with a SHA-256 per file and the head of every audit chain | The unseal passphrase and the recovery key, on purpose |

The keys in a backup are encrypted. The backup alone cannot sign; the backup together with the passphrase or the recovery
key can. That is why the three belong in different places.

## The daily timer

The package installation sets up `myownpki-backup.timer` unless it was told not to. Once a day it makes a backup in
`/var/backups/myownpki/<UTC time>`, runs every restore check on it and only then deletes the oldest scheduled backups,
keeping the newest 14. It never deletes the backup made before an update, one that failed its check (named
`-unverified`) or anything else you put there. The dashboard warns when the newest backup is older than 48 hours.

```bash
systemctl list-timers myownpki-backup.timer
```

```bash
sudo journalctl -u myownpki-backup.service -o cat
```

Make a backup by hand before a larger change. The directory must not exist yet; a backup never overwrites anything.

```bash
sudo -u myownpki /usr/local/bin/myownpki backup /var/backups/myownpki/before-change
```

Check a backup without touching anything. Use the checkpoint key fingerprint that `init` showed you:

```bash
sudo -u myownpki /usr/local/bin/myownpki backup verify /var/backups/myownpki/before-change --checkpoint-key FINGERPRINT
```

## Keep a copy off the machine

`/var/backups/myownpki` is on the same disk as the data, so it does not survive that disk. Copy it to another machine
with whatever you already use. As an example with rsync, run by root because the directory is private:

```bash
sudo rsync -a /var/backups/myownpki/ backup-host.homelab.lan:/srv/backups/myownpki/
```

Keep the passphrase and the recovery key away from that machine.

## Restore

Practice this once on a spare host. A restored server that is unsealed does what the original does: it signs CRLs and runs
monitoring and scans. Install the same release there and do not run `init`. The restore needs the server stopped and an
empty or missing data directory. Run it as **root**, not as the service user: it builds a work copy next to the data
directory, where the service user cannot write. All checks run first and nothing is written if one fails.

```bash
sudo systemctl stop myownpki
```

```bash
sudo mv /var/lib/myownpki /var/lib/myownpki.old
```

```bash
sudo install -d -m 0700 -o myownpki -g myownpki /var/lib/myownpki
```

```bash
sudo /usr/local/bin/myownpki restore /path/to/backup --config /etc/myownpki/config.yaml --checkpoint-key FINGERPRINT
```

The restored files belong to root until you hand them back, then start the server:

```bash
sudo chown -R myownpki:myownpki /var/lib/myownpki
```

```bash
sudo systemctl start myownpki
```

## Unseal after a restore

Sign in and unseal with the passphrase that was **valid when the backup was taken**; after a change, the old passphrase
opens the old backup, so keep it with those backups. If you no longer know it, `myownpki passphrase reset` sets a new one
and proves you may with the recovery key. The recovery key is not a passphrase, so the unseal page and `serve --unseal` accept
only a passphrase. If both are lost, the CA keys cannot be recovered: you would create new CAs and issue again.

## Check it worked

```bash
sudo -u myownpki /usr/local/bin/myownpki ca list
```

```bash
sudo -u myownpki /usr/local/bin/myownpki audit verify --checkpoint-key FINGERPRINT
```

After the unseal `ca list` shows your authorities and `audit verify` prints `OK`. Certificates issued after the backup are
not in it.

## What to store apart

| Item | Where |
|---|---|
| Unseal passphrase, and the old ones with old backups | A password manager, not on the server and not in a script |
| Recovery key | On paper in a safe, not in the password manager and not with the backups |
| Backups | Another machine or disk |
| Checkpoint key fingerprint | Written down: `backup verify` and `restore` use it |

A guide never shows any of these secrets; they appear once, where they are created. The longer page walks through a full
restore drill and the failure cases.
