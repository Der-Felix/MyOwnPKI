---
title: "Backup and restore"
description: "What a backup holds, the daily timer, verifying a backup, copying it offsite, and a restore drill on a spare host step by step."
permalink: /guides/backup-and-restore/
sources:
  - docs/OPERATIONS.md (6, 6.1, 7, 8)
  - cmd/myownpki/backup.go
  - internal/backup/backup.go
  - internal/backup/restore.go
  - site/install.md
  - site/upgrade.md
---

A backup is the only way back after a disk failure, a bad update or a compromised server. It is also
a copy of your CA keys, so it needs care in both directions: it must exist, and it must not lie next
to the secrets that open it.

* TOC
{:toc}

## When to use this

- Right after the installation, to confirm that the daily backup works.
- Before an update or any larger change.
- Once now, and again after every major upgrade, to **rehearse a restore** on a spare machine. A backup
  you never restored is a hope.

## What is in a backup

`myownpki backup DIR` copies every database as one consistent copy while the server runs and writes a
`manifest.json` with a SHA-256 per file, the migration versions, the head of every audit chain and the
checkpoint key fingerprint.

| In the backup | Not in the backup |
|---|---|
| `system.db` (users, sessions, the key ring), the instance and tenant audit logs, `pki.db` (CAs, certificates, encrypted keys) | `config.yaml`. Copy `/etc/myownpki/config.yaml` yourself. |
| `auth.key`, **only if** it lives in the data directory | `auth.key` if `auth.key_file` points elsewhere. Back it up separately, or every user needs `user reset-2fa` after a restore. |
| | The passphrase and the recovery key, on purpose |

The CA and certificate keys in the backup are **encrypted with the root key**. The backup alone cannot
sign. The backup **plus the passphrase or the recovery key** can. That is why the three belong in
three different places (see the last section).

## 1. The daily timer

`install.sh` installs and enables `myownpki-backup.timer` (unless you passed `--no-backup-timer`).
Once a day, at a random time in the first hour after midnight, it runs `myownpki backup scheduled`:

1. a backup into `/var/backups/myownpki/<UTC time>`, for example `20261025T003512Z`;
2. every restore check on it;
3. only if the check passed, **prune**: the newest 14 scheduled backups stay, older ones go.

Prune never touches the backup that `install.sh` makes before an update (`<time>-v<old version>`), a
timer backup that failed its check (`<time>-unverified`), a directory that is not a complete backup,
or anything else you put there. See the table in
[operations guide §6.1]({{ '/reference/operations/' | relative_url }}#61-daily-backups-with-the-systemd-timer).

```bash
systemctl list-timers myownpki-backup.timer
```

```bash
journalctl -u myownpki-backup.service -o cat
```

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup prune /var/backups/myownpki --keep 14 --dry-run
```

Another number: `install.sh --backup-keep 30`. The dashboard warns when the newest timer backup is
older than 48 hours or when an `-unverified` directory exists.

## 2. A backup by hand, and its check

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup /var/backups/myownpki/before-change --config /etc/myownpki/config.yaml
```

`DIR` must not exist; a backup never overwrites anything. The command prints the audit heads, the
checkpoint key and whether `auth.key` is included. In a container:

```bash
docker compose run --rm -v "$PWD/backup:/backup" myownpki backup /backup/before-change
```

Check a backup without touching anything. The timer's own check does not pin the checkpoint key, so do
this yourself with the fingerprint you wrote down at `init`:

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup verify /var/backups/myownpki/before-change --checkpoint-key <fingerprint>
```

## 3. Copy it offsite

`/var/backups/myownpki` is on the same disk as the data directory, so it does not survive that disk.
Copy it to another machine with whatever you already use. As an example with rsync, run by root
because the directory is mode 0700:

```bash
sudo rsync -a /var/backups/myownpki/ backup-host.homelab.lan:/srv/backups/myownpki/
```

Without `--delete`, rsync keeps on the target what the timer has pruned here, so prune there on your
own schedule. Keep the passphrase and the recovery key away from that machine.

## 4. Restore drill on a spare host

Use a machine that is **not** your production network if you can. A restored server that is unsealed
does what the original does: it signs CRLs and runs monitoring and scans.

1. Install the **same release** on the spare host, but do not run `init`. `install.sh` writes a
   configuration and creates an empty data directory ([Installation]({{ '/install/' | relative_url }}#option-a-linux-with-systemd)).
   Put your saved `config.yaml` in place if you need the same settings.
2. Copy one backup directory to the spare host, for example into `/srv/restore-test/`, and give it to
   the service user (the service user cannot read `/root`):

   ```bash
   chown -R myownpki:myownpki /srv/restore-test
   ```

3. Check it, with the fingerprint from `init`:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki backup verify /srv/restore-test/20261025T003512Z --checkpoint-key <fingerprint>
   ```

4. Restore. The data directory must be empty or missing, and the server stopped. All checks run first
   (hashes, database integrity, audit chains and heads, the certificate name index) and nothing is
   written if one fails. Run it as root: `restore` builds a work copy next to the data directory
   (`/var/lib`), where the service user cannot write. Then give the restored files to the service user:

   ```bash
   /usr/local/bin/myownpki restore /srv/restore-test/20261025T003512Z --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
   ```

   ```bash
   chown -R myownpki:myownpki /var/lib/myownpki
   ```

5. Start the server:

   ```bash
   systemctl start myownpki
   ```

6. Sign in, then **unseal with the passphrase that was valid when the backup was taken**. If you changed
   the passphrase since, the old one opens this backup. If you do not know it, set a new one with the
   recovery key (`myownpki passphrase reset`) and unseal with that. The UI and `serve --unseal` take only
   a passphrase, never the recovery key itself.
7. Check the result:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki ca list --config /etc/myownpki/config.yaml
   ```

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki audit verify --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
   ```

8. Write down how long it took and what was missing. Then stop the service and clear the spare host.

## Check it worked

- `backup verify` ends with "The backup passed every check of a restore."
- `restore` ends with "Restored into … Start the server and unseal it …".
- After the unseal, `ca list` shows your authorities and `audit verify` prints `OK`.
- Certificates issued **after** the backup are not in it. Their serial numbers are still in the
  certificates themselves.

## When it fails

- **`… is not empty – restore only into an empty data directory`:** stop the server and move the old
  data directory away first.
- **A check fails:** nothing was restored. Try an older backup; the journal of the timer names the
  problem.
- **The unseal is refused:** you are using the wrong passphrase for this backup. Try the old one, or run
  `myownpki passphrase reset` with the recovery key and unseal with the new passphrase
  ([operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key)).
- **Everyone is asked for a new second factor:** `auth.key` was not in the backup. Put the old file where
  the configuration names it, or run `user reset-2fa` for each user
  ([operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong)).
- More: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#installation-and-updates) and
  [Upgrade]({{ '/upgrade/' | relative_url }}#roll-back).

## What to store apart

| Item | Where | Why |
|---|---|---|
| Unseal passphrase | A password manager. Not on the server, not in a script. | Opens the CA keys. Keep the old one with old backups. |
| Recovery key | On paper, in a safe. Not in the password manager, not on the backup disk. | The second way in. |
| Backups | Another machine or disk | They are the keys, encrypted. |
| Checkpoint key fingerprint | Written down | Needed for `backup verify` and `restore`. |
| `config.yaml`, and `auth.key` if outside the data directory | With your configuration backup | Not part of the backup. |

Check once a year that you can unseal and that the paper is readable.

## Next steps

- Practice the failure cases: [When things go wrong]({{ '/guides/when-things-go-wrong/' | relative_url }}).
- Read about the audit log that every backup and restore writes to: [The audit log]({{ '/guides/audit-log/' | relative_url }}).
- Put the habit in a calendar: [Best practices]({{ '/best-practices/' | relative_url }}#back-up-daily-copy-it-away-and-restore-it-once).
