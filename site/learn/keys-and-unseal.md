---
title: "Keys and unsealing"
description: "How the CA keys are protected in MyOwnPKI: passphrase, recovery key, the sealed and unsealed server, what a restart does, what a backup contains and exactly what you can recover when something is lost."
permalink: /learn/keys-and-unseal/
sources:
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - internal/keys/keyring.go
  - internal/keys/crypto.go
  - internal/backup/backup.go
  - internal/ca/revoke.go
---

The private key of a CA is the most valuable file in a PKI: whoever has it can sign certificates that all
your clients accept. MyOwnPKI keeps the keys of **online** CAs in its database, encrypted. This page says
what that encryption rests on, how the server behaves with and without the keys in memory, and what you can
get back when something is lost. The key of an **offline root** is not here at all; the server holds only
that root's certificate.

* TOC
{:toc}

## From passphrase to key

```text
unseal passphrase --Argon2id--> key-encryption key --> master key of the key ring --> one data key per private key --> CA key
recovery key ----------------------------------------> master key of the key ring (a second wrap of the same key)
```

(The plan calls the master key the "root key". It has nothing to do with the root CA.)

- The **unseal passphrase** has at least 16 characters. Argon2id turns it into a key, and that key wraps the
  master key. The settings are 4 passes, 256 MiB of memory and 4 lanes, which is why unsealing takes a
  moment and needs the memory free. An unseal refuses weaker settings.
- The **recovery key** is 256 random bits, shown once at `init` as 9 groups of 6 characters. It wraps the
  same master key a second time, so it is a second way in, not a second copy of the keys.
- Everything is encrypted with AES-256-GCM, bound to its purpose, so a ciphertext moved to another row does
  not decrypt.
- **Changing the passphrase** rewrites one row (the wrapped master key). The CA keys are not touched.

## Sealed and unsealed

The server **starts sealed** after every start and every restart: the master key is not in memory, so
nothing can be signed. An instance admin unseals it in the UI (the banner) or with `serve --unseal`. Only
the master key is held while unsealed; the data keys and the CA key are decrypted for each signature and
cleared afterwards. *Seal* removes the key from memory at once, which is the emergency stop. A normal
stop with SIGTERM seals too.

| | Sealed | Unsealed |
|---|---|---|
| Web UI, sign-in | Works | Works |
| Serving CRLs and CA certificates | Works | Works |
| Monitoring and notifications | Work, and the `sealed` alert opens after 10 minutes | Work |
| ACME accounts, orders, challenges | Work | Work |
| ACME finalize | The order stays `processing` and is issued at the unseal | Issued |
| New certificates, agent renewals | Not possible | Possible |
| Revoking | The revocation is stored at once; the CRL is signed at the unseal | Stored and published |
| Renewing a CRL | Not possible; `sealed` turns critical when a CRL of an online CA is less than 24 hours from its next update | Done by the server |

Wrong passphrases are slowed down: three failures are free, then the wait starts at one minute and doubles
up to an hour. Every attempt is audited and costs the memory of one derivation, so they run one at a time.
Because of all this, plan for an unseal after every restart and every update, and run monitoring.

## What a backup contains

`myownpki backup` copies every database consistently, also while the server runs: the instance database
(users, sessions and the key ring with the wrapped master key), the tenant databases (CAs, certificates,
encrypted keys) and the audit logs, plus `auth.key` when it lies in the data directory, and a
`manifest.json` with a hash for each file. It does **not** copy `config.yaml`; keep that in your own backup.

The backup holds the keys, but encrypted. It cannot sign on its own. **Backup plus the passphrase or the
recovery key can.** That is why the three belong in three different places.

## What can I recover?

| What you have | What you can do | What you cannot do |
|---|---|---|
| Passphrase and the data directory or a backup | Everything: unseal, sign, restore | |
| Recovery key, passphrase lost | `myownpki passphrase reset` sets a new passphrase, proven with the recovery key. Nothing is lost. | Open old backups with the new passphrase: they open with the passphrase of their time, or with the recovery key |
| Passphrase, recovery key lost | Everything works. Keep going. | Make a new recovery key: a command to rotate it is planned and not in this release. Until then the passphrase is your only way in. |
| **Neither** | Nothing that signs. A server that is still unsealed keeps signing until the next restart or seal. Create new CAs, issue new certificates, retire the old CAs. | Get the CA keys back, from the server or from any backup: there is no back door. Set a new passphrase: that needs the old one or the recovery key. |
| A backup, but neither secret | Nothing: the backup cannot sign. | |
| A backup and one secret | Restore into an empty data directory and unseal with the passphrase that was valid at the time of the backup (or set a new one with `passphrase reset` and the recovery key, then unseal with that) | Find what was issued or revoked after the backup: it is not in it |
| Only the offline root's key is lost | The server and the intermediates are fine | Sign new intermediates or the root's CRL. When the last root CRL expires, clients that check revocation reject certificates below it (the `crl` alert). |
| `auth.key` lost | The CA keys are untouched. Run `user reset-2fa NAME --new-auth-key`, then `user reset-2fa` for every user | Keep the existing second-factor secrets |

Test it once: restore a backup on another machine and unseal it. Instructions are in the
[operations guide §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore).

## Next steps

- Create the secrets and write them down: [Installation]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key).
- Change or reset the passphrase: [operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key).
- Something is lost: [operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).
- Habits: [Best practices]({{ '/best-practices/' | relative_url }}#keep-the-passphrase-and-the-recovery-key-apart),
  [know what a sealed server means]({{ '/best-practices/' | relative_url }}#know-what-a-sealed-server-means).
- Back up before every update: [Upgrade]({{ '/upgrade/' | relative_url }}#back-up-first).
- Get told when the server is sealed: [Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts).
- Where the root's key may live: [Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }}).
