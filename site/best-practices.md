---
title: "Best practices"
description: "A short, opinionated list of habits for running a MyOwnPKI: offline root, narrow CAs, short certificates, backups you have restored, least-privilege tokens and monitoring from day one."
permalink: /best-practices/
---

These are habits, not rules of the program. Each has the reason in one sentence and a pointer to the
page that shows how. Where a number is a recommendation rather than a default of the software, it says
so.

* TOC
{:toc}

## CAs and keys

### Keep the root offline

A root is the anchor every client trusts; if its key leaks you must touch every client, so keep that
key on a machine that is not on the network and let online **intermediates** do the daily signing.
The root signs only the intermediates and its CRL, and the engine refuses to issue end-entity
certificates with it. How: [first CA]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate), and for the offline root's CRL the
[alerts]({{ '/monitoring/' | relative_url }}#the-alerts) page. Put the date on which the root's CRL must be signed
again into a calendar: nothing renews it by itself.

### One CA per purpose

Separate intermediates for web servers, for people and clients, and for the agents, because a problem
with one purpose then costs you one CA and not everything. The agent CA is a good example: it is an
intermediate with the EKU limit *clientAuth only* that signs nothing but agent client certificates.
How: [Adding hosts]({{ '/hosts/' | relative_url }}#what-the-server-needs-first).

### Narrow every CA with name constraints

Give an intermediate name constraints for your own names (for example the DNS suffix `.homelab.lan` and your
address ranges), so that even a stolen intermediate key cannot sign `www.example.com`. The engine
enforces the constraints before it signs, instead of relying on clients. Keep the EKU limit
and `pathlen:0` of intermediates that should not have sub-CAs. How:
[operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys) and
the CA pages in the UI.

### Say in domains who may get what

An ACME **domain** states which CA signs, which names exist below it, which challenges are allowed,
whether wildcards are allowed (dns-01 only, off by default), the validity, and whether a new account
needs approval. Keep the approval level at *approved accounts*, the default, unless the whole network is
trusted, and give clients that you trust an EAB key instead of opening the domain. How:
[operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).

### Protect the keys, and give them an end date

Online CA keys lie encrypted in the database and are in memory only while the server is unsealed. The
rest is up to you: a CA must end before the CA above it, and short leaf lifetimes limit what a leaked key is
worth. ACME domains default to 90-day certificates, and the agent's own certificates last 7 days.
(Recommendation, not a default: choose a root lifetime you can live with for a decade or two, an
intermediate lifetime of a few years, and let leaf certificates be as short as automation allows.) How:
[operations guide §1]({{ '/reference/operations/' | relative_url }}#1-what-runs-and-where).

### Choose the public base URL once

Every certificate contains the address of its CRL and of its issuer, built from the CA's base URL
(for example `http://pki.homelab.lan`), and it can never change for that CA. Use a DNS name you control,
never an address, and keep the port plain HTTP. How: [Installation]({{ '/install/' | relative_url }}#what-runs-where).

## Secrets and recovery

### Keep the passphrase and the recovery key apart

Anyone with a backup and one of the two can sign as your CAs, and nobody can help you if both are lost, so
keep the passphrase, the recovery key and the backups in three different places and never store the passphrase on the
server. Test once a year that you can unseal and that the paper is readable. How:
[The passphrase and the recovery key]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key).

### Back up daily, copy it away, and restore it once

The timer writes and verifies a backup every night, but a backup on the same disk does not survive the
disk, and a backup you never restored is a hope. Copy `/var/backups/myownpki` to another machine, run
`backup verify` with the checkpoint fingerprint, and **restore onto a spare machine** at least once, and
again after a major upgrade. Remember `auth.key` if it lives outside the data directory. How:
[operations guide §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore) and
[Upgrade]({{ '/upgrade/' | relative_url }}#back-up-first).

### Know what a sealed server means

A sealed server serves CRLs and CA certificates but signs nothing, including new CRLs. A short seal after
a restart is fine; a long one ends in certificates that clients reject once a CRL has expired. Unseal
promptly after every restart and update, and let monitoring wake you if you forget. How:
[Upgrade]({{ '/upgrade/' | relative_url }}#after-the-update) and [Monitoring]({{ '/monitoring/' | relative_url }}).

## People and tokens

### Use a second factor and the smallest role

Every user signs in with a password and an authenticator app (TOTP), and sensitive actions (revoking, key
downloads, CA operations, user management) ask again with a fresh code. Give people the role that fits:
*viewer* for looking, *operator* for issuing and renewing, *admin* for the tenant, and the instance admin
only to those who unseal. A role can be limited to one CA. How:
[operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong) and
[Security]({{ '/reference/security/' | relative_url }}).

### Give every script its own API token with the least role

An API token carries roles its owner has (never more) and ends within a year; it never satisfies the
fresh second factor, so it cannot revoke, download keys or manage CAs, users or agents. Create one
token per use, the *viewer* role for anything that only reads, a short validity, and delete the token
when the script is gone. How: [REST API]({{ '/reference/api/' | relative_url }}).

An API token can **never** create an agent join token or an enrollment pass, even with the admin role,
and a token with the admin role is more than a script needs. Give a roll-out tool a *viewer* token to
check the result and let a person with the second factor make the pass (below).

### Keep the admin listener private

The web UI and API belong on an admin network, never on the internet: set `admin.listen` and
`admin.allowed_networks` deliberately and give the listener a certificate from your own CA
(`admin.tls_issuer`) so nobody learns to click through certificate warnings. The public listener on
plain HTTP is meant for everyone and holds nothing secret. How:
[Installation]({{ '/install/' | relative_url }}#ports-and-firewall).

## Running it

### Automate renewal, and keep certificates short

Renew by ACME client or agent, never by calendar reminder. Automation is what makes short lifetimes
possible, and short lifetimes make revocation a rare event instead of your only defense. Clients with ARI
renew when the server says so. How: [Adding hosts]({{ '/hosts/' | relative_url }}).

### Turn monitoring on from day one

Alerts exist from the first start, but they only wake you if a channel is configured. Set up e-mail or a
webhook, send a test, run the end-to-end check once, and watch `/healthz` from outside, because a server
that is down tells nobody. How: [Monitoring]({{ '/monitoring/' | relative_url }}).

### Scan the endpoints you rely on

An alert that a certificate was renewed does not tell you that the web server picked it up. Enter the
services whose outage you would notice first, such as the reverse proxy, the mail server and the
directory, as endpoints, and the server tells you when one still serves an old certificate, runs out, is
down or sends an incomplete chain. Give an IP address an SNI, keep `monitor.scan_interval` at its default,
and start with a handful of endpoints. How: [TLS scan]({{ '/tls-scan/' | relative_url }}).

### Keep time right

Validity periods, CRL update times, the second factor and ACME all compare clocks. Run NTP on the server
and on every host with a certificate; a host that is off by hours gets certificates that look
not yet valid or already expired.

### Upgrade as a routine

Pin the container version, read the notes, back up, update the server before the agents, unseal, and
check. Small steps are easier to roll back than a jump over six releases. How:
[Upgrade]({{ '/upgrade/' | relative_url }}).

### Verify the audit log now and then

The audit log is hash-chained and signed. `myownpki audit verify` with the checkpoint fingerprint shows that it is the log you had; without the
fingerprint it still finds damage but cannot prove the log was not replaced. How:
[operations guide §4]({{ '/reference/operations/' | relative_url }}#4-running-the-server).

## Agents

### Prefer webroot to standalone when a web server runs

Standalone binds port 80 and needs a capability for it; with webroot the web server you already have answers
the challenge and the agent only writes a file. Always set a `check`, so that the agent compares what the
host serves with what it deployed. How: [agent.yaml]({{ '/hosts/' | relative_url }}#agentyaml).

### Keep paths and hooks small

`paths` is the only place where the agent may write apart from its state directory; the agent derives the
drop-in `10-paths.conf` from it (v0.3.5 and later), so the two cannot drift apart. Hooks are
argument lists with absolute paths: no
shell, no `sudo`, and no secrets in their stderr. How:
[The systemd sandbox]({{ '/hosts/' | relative_url }}#the-systemd-sandbox-and-paths).

### Keep an enrollment pass short, small and temporary

A pass lets hosts enroll without a person looking at each one. Make it for the roll-out only: a validity of
a day or less, as many uses as you have hosts, names no wider than needed. It grants each host its own name
only, and only after the server's http-01 check passed, but a leaked pass still admits as many more hosts as
it has uses left. Keep it in an encrypted store, remove it after the roll-out and **revoke it** if it is not
used up; if it ever leaks, revoke it at once and read the list of hosts it admitted. How:
[the enrollment pass]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs).

### Let the agent write the sandbox, and try unverified recipes on a test host

`deployment add` and `sandbox sync` keep `agent.yaml` and the systemd drop-ins in step, so use them instead
of editing `10-paths.conf` by hand. The Postfix, Dovecot and Proxmox VE recipes are unverified examples: run
them on a non-production host first. How: [Recipes]({{ '/recipes/' | relative_url }}).

### Know what happens to the old certificate

After a confirmed deployment the tenant default revokes the **previous** certificate of an agent at once
(other certificates after seven days). That is right when the agent is trusted; review both defaults in *Tenant settings*
once and use *Never revoke* where a second host shares the certificate. How:
[Adding hosts]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).
