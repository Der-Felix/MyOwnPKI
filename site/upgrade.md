---
title: "Upgrade"
description: "Update MyOwnPKI safely: back up, run install.sh or pull the new image, unseal, update the agents, and roll back if needed. Notes for every release since 0.2."
permalink: /upgrade/
---

Updating is a routine: **read the notes, back up, install, unseal, check, update the agents**.
`install.sh` does the risky part for you and puts the old version back when the new one does not come
up. The complete text is in the
[operations guide §9]({{ '/reference/operations/' | relative_url }}#9-upgrading); what changed in each
release is in the [release notes]({{ '/reference/changelog/' | relative_url }}).

* TOC
{:toc}

## The routine

1. Read the [notes for the releases you skip](#notes-per-release), and the release notes for
   anything marked as changed.
2. [Back up](#back-up-first) and keep a copy off the machine.
3. Update the server: [`install.sh`](#with-installsh) for a systemd installation,
   [the new image](#with-a-container) for a container.
4. **Unseal.** Every start leaves the server sealed.
5. [Check](#after-the-update) that the right version runs and nothing is waiting.
6. [Update the agents](#update-the-agents), after the server, never before.

Choose a quiet moment. While the server is sealed it signs nothing: no new certificates, no ACME
orders, no agent renewals and no CRLs. For a few minutes that does not matter; it matters if you
leave it sealed for days.

## Back up first

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup /var/backups/myownpki/before-update --config /etc/myownpki/config.yaml
```

The backup runs while the server is up and writes a directory with a `manifest.json`. Check it
without touching anything, with the checkpoint fingerprint from `init`:

```bash
runuser -u myownpki -- /usr/local/bin/myownpki backup verify /var/backups/myownpki/before-update --checkpoint-key <fingerprint>
```

Then copy the directory to another machine. A backup on the same disk does not survive the disk. The
backup contains the CA keys, **encrypted** with the root key: it cannot sign without the
passphrase or the recovery key, so keep the two apart from it.

`install.sh` also takes a backup and verifies it before it replaces the binary
(`/var/backups/myownpki/<time>-<old version>`), and the daily timer keeps 14 more. Those are for the
rollback below; your own copy is for the case that the disk fails.

In a container:

```bash
docker compose run --rm -v "$PWD/backup:/backup" myownpki backup /backup/before-update
```

`./backup` must be writable for UID 65532.

## With install.sh

Download the `install.sh` of the **new** release, check it, and run it as root, exactly as for the
first installation:

```bash
v={{ site.data.release.version }}
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install.sh"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
sha256sum --check --ignore-missing checksums.txt
```

```bash
sudo bash install.sh
```

Behind a proxy use `sudo --preserve-env=https_proxy,http_proxy,no_proxy bash install.sh`
([why]({{ '/install/' | relative_url }}#behind-a-proxy)). On an initialized instance with a different
binary it updates:

1. It runs `myownpki config check` of your configuration with the **new** binary. If that fails,
   nothing changes.
2. It makes a backup with the running version into `/var/backups/myownpki/<time>-<old version>` and
   verifies it.
3. It installs the new binary (the old one stays as `/usr/local/bin/myownpki.previous`), restarts the
   service, runs the health check for up to 30 seconds and checks that the **running** service is the
   new binary.
4. If one of these checks fails, the old binary and the old agent packages come back, the service
   restarts, and the script ends with an error. An update counts as done only when the new version
   runs.

Your configuration and the drop-ins stay as they are. The old update backups are never deleted by
the timer; remove them yourself when the new version has run well for a while.

## With a container

Pin the new version in `docker-compose.yml`, then:

```bash
docker compose pull
```

```bash
docker compose up -d
```

The migrations run at start. New settings arrive as `MYOWNPKI_*` variables (see the release
notes); a variable the new version does not know makes the start fail, which is also how a
rollback to an older version breaks (see below).

## After the update

The server is sealed. Open the UI and unseal it. Then check:

```bash
/usr/local/bin/myownpki --version
```

```bash
runuser -u myownpki -- /usr/local/bin/myownpki db status --config /etc/myownpki/config.yaml
```

```bash
journalctl -u myownpki -o cat | tail -n 30
```

- The version and the migration state are what you expected.
- The dashboard shows no new warning, and the *Alerts* page (since 0.3.3) lists nothing you did not
  expect. A server that stays sealed for more than 10 minutes opens a `sealed` alert by design.
- A certificate can still be issued, and a CRL is current.

**What a sealed server means.** The UI works, and CRLs and CA certificates are still served, so
clients keep validating. Nothing can be signed: ACME clients can create orders but the *finalize* waits
and is issued at the unseal; agents cannot renew; an online CA's CRL is not renewed. CRLs live for days,
so a short seal is harmless and a long one is not: clients that check revocation reject certificates
below a CA whose CRL has expired. Since 0.3.3 the `sealed` alert becomes critical when a CRL is less
than 24 hours from its next update.

## Notes per release

You can skip releases: CI upgrades an instance from 0.1.0 to the current build on every change. Read
every row between your version and the new one, newest first. Always back up first.

| From → to | Database | What to do |
|---|---|---|
| 0.3.3 → 0.3.4 (2026-11-12) | `pki.db` 0018 adds the table for the TLS scan's endpoints (additive) | Nothing to configure: the [TLS scan]({{ '/tls-scan/' | relative_url }}) connects nowhere until an admin enters an endpoint, and the new `monitor.scan_*` keys have defaults (`monitor.scan_interval: off` switches it off). Admins get the new permission `endpoint.manage`, operators and admins `endpoint.scan`. **Behavior change:** the address guard shared by http-01 validation, the agent enrollment check and the scan now refuses more ranges outright: the IPv6 forms that embed or translate to an IPv4 address (NAT64, IPv4-compatible, 6to4, Teredo, IPv4-translated), addresses with a zone and some non-global ranges such as `192.0.0.0/24` and `198.18.0.0/15` ([full list]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned); the documentation ranges stay allowed). A service that really lives there can no longer be an http-01 target or an enrollment host. Going back means restoring the backup, because 0.3.3 refuses the newer `pki.db`. |
| 0.3.2 → 0.3.3 (2026-11-12) | `system.db` 0014 adds the tables for alerts and queued notifications (additive) | No configuration change. Alerts start one minute after the start; nobody is told until you configure `notify:` ([Monitoring]({{ '/monitoring/' | relative_url }})); the first message then lists every alert that is open. Expect a `sealed` alert if you leave the updated server sealed for more than 10 minutes, and `agent_silent` for agents that stopped reporting. **Containers:** add the `MYOWNPKI_NOTIFY_*` variables and mount the secret files read-only; the image now sets `MYOWNPKI_AGENT_PACKAGE_DIR`. Alerts need a tenant-wide role (viewer or higher): a role limited to one CA no longer sees the Alerts page. |
| 0.3.1 → 0.3.2 (2026-10-29) | None | No configuration change. **Update the server first.** A 0.3.1 server answered every `/agent-packages/` download with 404, so guided installation and package updates need the server at 0.3.2. |
| 0.3.0 → 0.3.1 (2026-10-28) | `system.db` 0013; `pki.db` 0014 to 0017, all additive | Existing certificates and revocations are unchanged. Open *Administration → Tenant settings* and review the two predecessor defaults (agent: revoke immediately after a confirmed deployment; other certificates: after seven days). `install.sh` now publishes the agent packages. **Update the server before the agents.** |
| 0.2.2 → 0.3.0 (2026-10-25) | `system.db` 0011; `pki.db` 0011 to 0013 | The agent listener is off until you set `agent.*` (see [Adding hosts]({{ '/hosts/' | relative_url }})). Enrollment mode is a tenant setting; the default is `verified`. |
| 0.2.1 → 0.2.2 (2026-10-24) | `system.db` 0010 | `install.sh` now also installs the daily backup timer and enables it once (`--no-backup-timer` keeps it off). The drop-in `public-port-80.conf` stays and works as before. The **trust page** appears at `/` of the public listener; switch it off in *Tenant settings* if you do not want it. This `install.sh` installs 0.2.2 and later only. Containers: back up, pull, start. |
| 0.2.0 → 0.2.1 (2026-10-24) | None | The server is unchanged; `install.sh` is new. Without Docker you can update as before, or run `install.sh` once: it keeps an existing `config.yaml` and `/var/lib/myownpki`. |
| 0.1.0 → 0.2.0 (2026-10-23) | `pki.db` adds the domains and ACME tables; `system.db` adds the ACME rate limits | ACME stays off until you set `acme.base_url`; read [chapter 10]({{ '/reference/operations/' | relative_url }}#10-acme-server) first. Going back to 0.1 means restoring the backup **and** removing every `MYOWNPKI_ACME_*` variable: 0.1 refuses unknown variables and would not start. The unseal now refuses key-derivation parameters below t=4, 256 MiB, p=4; every release stored exactly those, so installations are not affected. |

## Update the agents

Update the server first. Mixed operation is supported: 0.3.0 agents keep working against a newer
server, and the server does not revoke certificates because an older agent does not send a newer
report field. There is **no automatic agent update and no command from the server**: an agent changes
only when an admin installs a new package on the host.

The agent list in the UI marks agents that are older than the server (only older ones; it never
suggests a downgrade). For such an agent, an admin opens the update link on its page and confirms with
a fresh second factor. The server then shows the verified commands for the host's installed package
format and architecture, with no join token: download the root and compare its SHA-256, download the
package and `checksums.txt`, check the package against the value shown in the UI, install it, and run
`myownpki-agent setup`. Run them as root **on the agent host**. The update keeps `agent.yaml` and
restarts the service.

On many hosts the same commands go into your configuration management; see
[Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}).

## Roll back

**`install.sh` rolls back for you** when the new binary does not come up healthy: the old binary and
agent packages return, and the script ends with an error that names the backup. If the old version is
not healthy either, the new one may already have migrated the databases. Then restore the backup that
was taken before the update:

```bash
systemctl stop myownpki
```

```bash
mv /var/lib/myownpki /var/lib/myownpki.failed
```

```bash
install -d -m 0700 -o myownpki -g myownpki /var/lib/myownpki
```

```bash
runuser -u myownpki -- /usr/local/bin/myownpki restore /var/backups/myownpki/<time>-<old version> --config /etc/myownpki/config.yaml --checkpoint-key <fingerprint>
```

```bash
systemctl start myownpki
```

Restore runs all its checks first and writes nothing if one fails. Start the server, then unseal with
the passphrase that was valid when the backup was taken. Certificates issued after the backup are not
in it.

**By hand or with a container**, going back always means restoring the backup from the start of the
update. A database that is newer than the binary is refused, and so is an unknown `MYOWNPKI_*`
variable of a newer version.

A rollback of the binary alone (`mv /usr/local/bin/myownpki.previous /usr/local/bin/myownpki`)
works only if no migration ran, which `myownpki db status` shows.
