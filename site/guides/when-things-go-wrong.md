---
title: "When things go wrong"
description: "A runbook: sealed server after a reboot, lost passphrase, lost recovery key, full disk, a wrongly issued certificate, a compromised intermediate and a restore. Each with symptom, action, check and source."
permalink: /guides/when-things-go-wrong/
sources:
  - docs/OPERATIONS.md (1, 4, 6, 6.1, 7, 8, 13.6)
  - "docs/PLAN.md (5, 14: Keys and unseal, Revocation and CRLs)"
  - internal/ca/revoke.go
  - internal/ca/offline.go
  - legacy/lib/operations.sh
  - site/troubleshooting.md
  - site/upgrade.md
---

Read this page once on a quiet day. Each case lists the symptom, what to do first, how to check it and
where the product documents it. Only steps the product supports are here; where it has no answer, the
page says so.

* TOC
{:toc}

## When to use this

Something is lost, wrong or suspicious. If no case below fits, start with the alerts and
`journalctl -u myownpki -o cat | tail -n 50`.

## Sealed after a reboot

**Symptom.** A banner says the server is sealed. New certificates, ACME orders and agent renewals fail.
A `sealed` alert opens after 10 minutes. The server starts sealed after **every** restart.

**Do.** An instance admin chooses *Unseal* in the banner and types the passphrase. If you run the server
in a terminal, `myownpki serve --unseal` asks for it there. Wrong attempts are slowed: three free, then one
minute, doubling up to an hour, and every attempt is audited.

**Check.** The banner is gone and the `sealed` alert closes at the next check. A long seal matters: a
sealed server signs no CRLs, and once a CRL expires, clients that check revocation reject everything
below that CA.

**Source.** [Operations guide §4]({{ '/reference/operations/' | relative_url }}#4-running-the-server),
[Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts).

## Lost passphrase

**Symptom.** Nobody knows the unseal passphrase, so the server cannot be unsealed.

**Do.** Reset it with the **recovery key**. The command asks for the key and then for a new passphrase
(at least 16 characters, twice):

```bash
runuser -u myownpki -- /usr/local/bin/myownpki passphrase reset --config /etc/myownpki/config.yaml
```

**Check.** Unseal with the new passphrase. The audit log has the reset. A backup taken before the change
unseals only with the **old** passphrase (or after another `passphrase reset` with the recovery key), so
keep the old one with those backups until they have aged out.

**If you also lost the recovery key.** The CA keys cannot be recovered, from a backup either. Create new
CAs, issue new certificates and retire the old CAs.

**Source.** [Operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key)
and [§8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).

## Lost recovery key

**Symptom.** The paper is gone or unreadable, but the passphrase still works.

**Do.** Nothing is lost as long as the passphrase is known. A command to **rotate** the recovery key is
planned and does not exist in this release, so you cannot make a new one yet. What you can do is protect
the remaining way in: the passphrase in a password manager that is backed up, and the backups elsewhere.

**Check.** Unseal with the passphrase now. **Source.** [Operations guide §1]({{ '/reference/operations/' | relative_url }}#1-what-runs-and-where).

## Disk full

**Symptom.** Backups fail (`systemctl --failed`, the journal of `myownpki-backup.service`), an update
stops with `backup failed – nothing changed`, or the dashboard warns about an old backup.

**Do.** Free space first. The backups in `/var/backups/myownpki` are on the same disk as the data
directory. Copy them to another machine, then see what the timer's prune would remove:

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup prune /var/backups/myownpki --keep 7 --dry-run
```

Run it again without `--dry-run` to apply it. Prune deletes only complete scheduled backups. It never
touches `<time>-<old version>` (taken before an update) or `-unverified` directories; delete those
yourself when you no longer need them.

**Check.** Run a backup by hand, then `backup verify` and `audit verify` as in
[Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}):

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup /var/backups/myownpki/after-cleanup --config /etc/myownpki/config.yaml
```

**Not documented.** What the server does when the *data* disk itself is full is not described in the
product documentation. Treat it as an incident: free space, then run the checks.

**Source.** [Operations guide §6.1]({{ '/reference/operations/' | relative_url }}#61-daily-backups-with-the-systemd-timer),
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#installation-and-updates).

## A wrongly issued certificate

**Symptom.** A certificate exists for a name or a person that should not have it.

**Do.**

1. Open the certificate and choose *Revoke*. You need the role *operator* or *admin* and a fresh second
   factor. Choose a reason: *unspecified*, *keyCompromise*, *affiliationChanged*, *superseded*,
   *cessationOfOperation* or *privilegeWithdrawn*.
2. If anyone else may hold the key, use *keyCompromise*. The key is then blocked for every later request.
3. Revocations are stored at once, even while sealed. The CRL is signed right after, or at the next
   unseal; until then the dashboard says "N revocation(s) not yet published".
4. If an ACME client or agent keeps asking for the name, fix the domain or its approval, otherwise it will
   be issued again ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).

**Check.** The certificate shows as revoked, and the CRL lists its serial:

```bash
curl -sS http://pki.homelab.lan/crl/issuing/1.crl | openssl crl -inform DER -noout -text
```

**Source.** [Operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong),
[Renew and revoke]({{ '/guides/renew-and-revoke/' | relative_url }}).

## A compromised intermediate

**Symptom.** The key of an intermediate may be in someone else's hands.

**Do.**

1. **If someone may be on the server,** choose *Seal* at once (this removes every key from memory), take
   the server off the network, run `audit verify`, and plan a restore onto a clean machine.
2. **Revoke the intermediate.** Below an *online* root: *Manage → Revoke* on the CA, reason *cACompromise*
   or *keyCompromise*. That blocks its key for every new certificate and CA. Below an *offline* root the UI
   refuses: revoke it **at the root**, then create a new root CRL and upload it on the root's page
   (*Upload the root's CRL*). The product documents this flow, but not the exact `pki.sh` subcommand for
   a CA that MyOwnPKI created. `pki.sh revoke NAME --reason keyCompromise` handles an intermediate that
   exists in that `pki` directory. Then create the CRL:

   ```bash
   ./pki.sh crl --ca root
   ```

3. **Replace it.** Create a new intermediate with a new key and a new name
   ([Sign with an offline root]({{ '/guides/offline-root/' | relative_url }}),
   [CA lifecycle]({{ '/guides/ca-lifecycle/' | relative_url }})). Point your ACME domains at it. Re-issue
   what ACME clients and agents do not renew themselves.
4. **Communicate.** Tell the owners of hosts and your users which CA is revoked, when, and which new
   certificates to expect. Clients that check revocation reject the old chain once they fetch the new
   CRL; a client may keep a cached CRL until its next update, and some clients never check. The root's CRL
   lifetime therefore matters.
5. **Find what it signed** in the certificate list and in the tenant audit log (`certificate.issue`).

**Check.** The CA shows as revoked in *Certificate authorities* and in `ca show`. The root's CRL lists the
intermediate's serial. A certificate below the new CA verifies against the root.

**Source.** [Operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).

## A restore

**Symptom.** The data directory is lost, damaged or must be rolled back, for example after an update that
migrated the databases.

**Do.** Stop the server, move the old data directory away, restore into an empty one, start and unseal
with the passphrase valid when the backup was taken:

```bash
systemctl stop myownpki
mv /var/lib/myownpki /var/lib/myownpki.failed
install -d -m 0700 -o myownpki -g myownpki /var/lib/myownpki
```

Run `restore` as root: it builds a work copy next to the data directory (`/var/lib`), where the service
user cannot write. Then give the restored files to the service user:

```bash
/usr/local/bin/myownpki restore /var/backups/myownpki/<time> --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
```

```bash
chown -R myownpki:myownpki /var/lib/myownpki
```

```bash
systemctl start myownpki
```

**Check.** `ca list` shows your authorities; `audit verify` prints `OK`. Certificates issued after the
backup are not in it. Everyone needs a new second factor only if `auth.key` was not in the backup.

**Source.** [Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}),
[Upgrade]({{ '/upgrade/' | relative_url }}#roll-back).

## Check it worked

For every case above: the server is unsealed, `healthcheck` exits 0, `audit verify` prints `OK`, and a
test certificate can be issued. Locked-out users, lost phones and a lost `auth.key` are in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in) and the
[operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).

## Next steps

- Rehearse the restore: [Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}).
- Know who can do what: [Users, roles, second factor]({{ '/guides/users-roles-2fa/' | relative_url }}).
- Set up alerts so that you hear about it first: [Monitoring]({{ '/monitoring/' | relative_url }}).
