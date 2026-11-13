---
title: "FAQ"
description: "Short answers to the questions a homelab operator asks first: domains, Let's Encrypt, browser warnings, ports, sealing, wildcards, OCSP, the agent, lost passphrases, upgrades and what is production ready."
permalink: /faq/
sources:
  - README.md
  - CHANGELOG.md
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - deploy/config.example.yaml
  - presets/
  - internal/authz/authz.go
  - site/install.md
  - site/upgrade.md
  - site/hosts.md
  - site/best-practices.md
---

Short answers, each with a link to the page that holds the detail. They describe release
{{ site.data.release.version }}. Where something is planned but not built, the answer says so and
points to the release plan instead of promising it. Words you do not know are in the
[glossary]({{ '/glossary/' | relative_url }}).

* TOC
{:toc}

## Basics

### What is MyOwnPKI?

A self-hosted PKI: a certificate authority engine, an ACME server, a web UI with a REST API, monitoring
and an optional agent for Linux hosts that gets and deploys certificates. It issues certificates from
CAs that you own, for your own hosts, users and devices. The page [Choose your setup]({{ '/choose/' | relative_url }})
compares the ways to run it. New to PKI? Start with
[What is a certificate authority?]({{ '/learn/what-is-a-ca/' | relative_url }}).

### Do I need a public domain name?

No. A name that only your own DNS knows, such as `pki.homelab.lan`, is enough. What you need is one
stable name for the server that every client resolves, because its address is written into every
certificate (the CRL and the issuer's certificate). Certificates for hosts can use internal names
too; with split DNS the server's validator reads your internal zone through `acme.resolver`
([operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network)).
See [Before you start]({{ '/install/' | relative_url }}#before-you-start).
More: [Split DNS and the network for validation]({{ '/guides/split-dns/' | relative_url }}).

### Can I use it to get certificates from Let's Encrypt?

Not today. MyOwnPKI is the ACME **server** of your own CAs; it does not request certificates from public
CAs. An ACME client for Let's Encrypt is on the roadmap, not in the current release, so use certbot,
acme.sh or lego for public names. Release plan:
[docs/PLAN.md §10.1]({{ site.repository_url }}/blob/main/docs/PLAN.md).

### Can I use its certificates on the public internet?

Only for clients that trust your root. Browsers and operating systems trust the public CAs they ship
with, and your root is not among them. That is the difference between a private and a public CA, and it
is why you hand your own root to your own devices ([the trust page]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page)).
Background: [How trust works]({{ '/learn/trust/' | relative_url }}).

### Is it production ready?

Not yet, and the project says so. It is before version 1.0: the plan still has releases, a quality
round and a beta ahead, and the release notes state that a minor version before 1.0 may change the API,
the configuration and the database schema. What exists is released and has tests; the
[release notes]({{ '/reference/changelog/' | relative_url }}) say what the maintainer ran on live hosts and what was not
tested live. Decide by what a failure costs you: keep the root offline, back up daily and before every
update, and read the notes of each release before you update
([Best practices]({{ '/best-practices/' | relative_url }})).

## Installation and operation

### Can I run it without Docker?

Yes. On a Linux machine with systemd, `install.sh` installs it as a hardened service and is the
recommended way; the container is the alternative. Download the script and the checksum file, check
them and run it as root; never pipe it into a shell.
See [Option A]({{ '/install/' | relative_url }}#option-a-linux-with-systemd).

### Does it run on a Raspberry Pi?

The releases contain Linux arm64 archives and a container image for arm64, and `install.sh` supports
arm64, so a Pi that runs a **64-bit** operating system can run it. No 32-bit build is listed. The
docs record no test on a Pi. Unsealing derives the key with Argon2id, which needs about 256 MiB of
free memory for a moment ([Before you start]({{ '/install/' | relative_url }}#before-you-start)).

### Does it run on Windows or macOS?

Release archives exist for windows/amd64, darwin/arm64 (Apple silicon) and freebsd/amd64, and the
operations guide names a Windows configuration path. This site, however, describes only two ways to run
the server: the systemd service and the container. For another operating system you install the binary
by hand and write your own service definition
([operations guide §2.2]({{ '/reference/operations/' | relative_url }}#22-with-docker-or-by-hand)); there is no installer for
it. The agent is Linux only. Windows and macOS as **clients** are fine: the trust page has guides for both.

### Which ports does it use?

The admin listener (web UI and API) on 9443, the public listener (CRLs, CA certificates, trust page)
on 8080 or 80, the ACME listener only if you set `acme.base_url` (443 with its own TLS, or a local port
behind your proxy), and the agent listener on 8444 only if you enable it. The server also connects out
to port 80 of your hosts for http-01. The table with who needs to reach what is in
[Ports and firewall]({{ '/install/' | relative_url }}#ports-and-firewall).

### Do I have to open anything to the internet?

No. The admin listener must never face the internet, and the other listeners only need to be reachable
by your own clients and hosts. `admin.allowed_networks` limits the admin listener to your admin
networks before the TLS handshake
([operations guide §2.3]({{ '/reference/operations/' | relative_url }}#23-settings-to-decide)).

### What happens after a reboot or an update?

The server starts **sealed**: the CA keys are encrypted and are decrypted into memory only when an
instance admin enters the passphrase (*Unseal* in the banner, or `serve --unseal` at the terminal). While
sealed the UI works and CRLs and CA certificates are served, but nothing is signed: no new certificates,
no ACME finalize, no agent renewals, no CRL renewal. A `sealed` alert opens after 10 minutes and turns
critical before a CRL runs out. See [Know what a sealed server means]({{ '/best-practices/' | relative_url }}#know-what-a-sealed-server-means).
Background: [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}).

### Can it unseal itself after a restart?

No. Unsealing needs the passphrase every time. An automatic unseal (TPM, a key service or a key file) is
only named as a possible later option in the plan. The price of the current design is that the server
waits for you after every restart; the gain is that a stolen disk or backup holds no usable key
([Installation]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key)).

### Where is the data, and what do I back up?

Everything is below `/var/lib/myownpki` (databases, the audit log, the encrypted keys). `myownpki backup`
makes a consistent copy while the server runs, and with `install.sh` a daily timer keeps 14 of them in
`/var/backups/myownpki`. That directory is on the same disk, so copy it elsewhere, and keep the
passphrase and the recovery key away from the copy.
See [Where everything is]({{ '/install/' | relative_url }}#where-everything-is) and
[operations guide §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore).

### Can I change the public base URL later?

No, not for a CA that has issued certificates: the URL is written into every certificate, and clients
fetch the CRL and the issuer's certificate from it. Choose a name you control and keep, not an IP address
and not a machine name ([Installation]({{ '/install/' | relative_url }}#what-runs-where)).

### Can several people use it?

Yes. Users have a role in the tenant (viewer, operator or admin), optionally limited to one CA, and every
user needs a second factor. Instance admins manage users and unseal the server. The server has one
tenant, `default`; a tenant UI comes later. Sign-in is by local users: there is no single sign-on
(OIDC) yet. See [Use a second factor and the smallest role]({{ '/best-practices/' | relative_url }}#use-a-second-factor-and-the-smallest-role),
the guide [Users, roles, second factor and API tokens]({{ '/guides/users-roles-2fa/' | relative_url }})
and the [glossary entry for roles]({{ '/glossary/' | relative_url }}#role).

### How do I know that it is healthy?

`myownpki healthcheck` asks the server's own health endpoint (it says nothing about the seal state on
purpose). Since v0.3.3 the server also reports problems itself: a sealed server, a CRL that gets old, expiring
certificates and silent agents, by e-mail or webhook. Set that up on day one
([Monitoring]({{ '/monitoring/' | relative_url }})).

## Certificates and ACME

### What kinds of certificates can I issue?

Twelve built-in presets: `server`, `wildcard`, `server-client`, `client`, `user`, `smime`, `vpn-server`,
`vpn-client`, `codesign`, `timestamp`, `ocsp` and `custom`. A preset fixes the key usage, extended key
usage, required names and default validity. The extensions of a certificate always come from the
preset, never from the request. The list is on the *Presets* page of the UI.

### How long are the certificates valid?

ACME certificates default to 90 days (a domain can set another value). Presets have their own defaults for
issuance in the UI and API, for example 397 days for `server`, and every CA has a maximum validity that
caps both. Short lifetimes are cheap when something renews them for you
([operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys),
[Lifetimes in best practices]({{ '/best-practices/' | relative_url }}#automate-renewal-and-keep-certificates-short)).
Background: [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).

### Can I bring my own root?

Yes. *Certificate authorities → Import offline root* takes the root's certificate (never its key), shows
the fingerprint so you can compare it, and you create intermediates below it that the root signs
offline. A directory made by the old `pki.sh` suite can be imported with its history
([Moving from pki.sh]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish)).
Guides: [Sign with an offline root]({{ '/guides/offline-root/' | relative_url }}) and [Move from the old Bash suite]({{ '/guides/import-from-pki-sh/' | relative_url }}).

### Is there OCSP?

No. Revocation is published as CRLs on the public listener, and each certificate carries the address of
its CRL. An OCSP responder is planned after version 1.0. The `ocsp` preset only issues certificates for
a responder; it does not start one. Whether a client checks a CRL at all is up to the client.
The `crl` alert tells you when a CRL is not renewed in time
([Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts)).

### Does it issue wildcard certificates?

Yes, in two ways. In the UI and API the `wildcard` preset issues `*.homelab.lan` plus the base name. Over
ACME a domain may allow wildcards; they are off by default and proven by **dns-01** only. The agent does
this since v0.3.7: a deployment with `challenge: dns-01` writes the TXT record through RFC 2136 (BIND, Knot,
PowerDNS with a TSIG key) or the Cloudflare API; see
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). An ACME client such as certbot, lego or
acme.sh with a DNS plug-in of its own works too, also for providers the agent does not have. A wildcard covers
exactly one label, so `*.homelab.lan` does not cover `a.b.homelab.lan`. See
[operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).

### Which ACME clients work?

Any client that speaks RFC 8555. The operations guide shows commands for certbot, lego and acme.sh, and
configuration for Caddy and Traefik, including the root as trust anchor and EAB keys. http-01 and dns-01
are supported; tls-alpn-01 is not, and is planned for after 1.0. See
[operations guide §10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients).
Guides: [certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}), [acme.sh]({{ '/guides/acme-sh/' | relative_url }}), [Traefik and Caddy]({{ '/guides/traefik-caddy/' | relative_url }}). Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### My ACME client says my account waits for approval. Why?

The default approval level of a domain is *approved accounts*: a new account waits in *ACME → Accounts*
until an admin approves it, unless it brings an EAB key. Approve only accounts you expect, and compare
the contact and the address with the machine that registered. Other levels are *open* and *new names*.
See [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys) and
the [table of client errors]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).
Guide: [Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}).

### What is an EAB key and when do I need one?

An external account binding key lets one client skip the approval queue. An admin creates it under
*ACME → EAB keys* and gives the key ID and the MAC key (shown once) to the client; it binds one account and
expires, by default after 7 days. Use it for clients you trust and want to onboard without a click.
See the [glossary]({{ '/glossary/' | relative_url }}#eab-external-account-binding).

### Does ACME work when my names exist only in my internal DNS?

Yes, if the server can resolve them. Set `acme.resolver` to the DNS server that knows your internal names.
For http-01 the server must also reach port 80 of the client; for dns-01 the TXT record has to be in the
zone that resolver reads. See
[operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).

### Can I issue a certificate for an IP address?

Yes. The certificate may carry IP addresses as subject alternative names, and an ACME domain lists the
IP ranges that may appear in certificates (http-01 only). Some ranges are never validated, such as
loopback and link-local addresses ([§14.8]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned)).

### Who makes the private key?

By default the host makes it and sends only a certificate request, so the key never leaves the host. The
server can generate a key for you, a setting that an admin can switch off per tenant; such a key is stored
encrypted, and exporting it needs a fresh second factor and is audited.
See [the first certificate]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).

## Trust and clients

### Why does my browser warn about the certificate?

The browser does not trust the root that signed it. Your own root is not in any browser's list until you
put it there. For the admin UI there is a second reason: before you give the listener a certificate from
your CA (`admin.tls_issuer`) it uses a self-signed bootstrap certificate whose fingerprint you compare once
([operations guide §2.4]({{ '/reference/operations/' | relative_url }}#24-certificates-the-server-issues-itself-tls_issuer)).
See [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in).
Guide: [When things go wrong]({{ '/guides/when-things-go-wrong/' | relative_url }}).

### How do I make my devices trust the root?

Open the trust page at `/` of the public listener, for example `http://pki.homelab.lan/`. It lists every
root with its SHA-256 fingerprint, offers DER and PEM downloads and two Windows helper scripts, and has
guides for Windows, macOS, iPhone and iPad, Android, Linux and Firefox. On iOS the root needs one more
switch under *Certificate Trust Settings*.
See [operations guide chapter 11]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page).
Guide: [Make clients trust your root]({{ '/guides/trust-the-root/' | relative_url }}).

### Is it safe to download the root over plain HTTP?

Only if you compare the fingerprint with one you got another way, such as the admin UI or a printout.
The page is plain HTTP on purpose, because it has to work before anything trusts your PKI, so someone in
the network path could change it; the fingerprint is the check. The Windows helper scripts refuse to
import without that comparison. See [Security]({{ '/reference/security/' | relative_url }}#what-it-does-not-protect).

### Do clients trust the root or the intermediate?

The root is the trust anchor you install. The intermediate signs the certificates, and the server must
send it together with its own certificate, which is what the *fullchain* download contains. A server that
sends only its own certificate shows up in a TLS scan as an *incomplete* chain.
See [the glossary]({{ '/glossary/' | relative_url }}#chain) and [TLS scan]({{ '/tls-scan/' | relative_url }}#what-the-states-mean).
Background: [How trust works]({{ '/learn/trust/' | relative_url }}) and [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

### Can I revoke the root?

Not in the way you revoke a leaf. A root signs itself, so nobody above it can revoke it; clients stop
trusting it only when you remove it from their trust stores. That is why the plan warns about an online
root and why the intermediates carry the daily work. For a leaked intermediate, the root revokes it.
See [Keep the root offline]({{ '/best-practices/' | relative_url }}#keep-the-root-offline) and
[operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).
Background: [Revocation]({{ '/learn/revocation/' | relative_url }}).

## Agent and hosts

### Do I need the agent?

No. It is optional. A host that already runs an ACME client needs nothing else, and you can add the TLS
scan so that the server also checks what the host really serves. The agent adds deployment, reload with
rollback and a view of what is installed. The three levels are compared in
[Which level for which host]({{ '/hosts/' | relative_url }}#which-level-for-which-host).

### Which systems does the agent run on?

Linux with systemd. It ships as `.deb`, `.rpm` and tarball for amd64 and arm64, with deployment profiles
for nginx and for plain files, and recipes for nginx, Postfix, Dovecot and Proxmox VE (only the nginx recipe
rests on a setup the project has run). Live tests so far used Debian amd64. Windows, macOS and FreeBSD
are build and test targets only; those hosts use an ACME client.
See [Adding hosts]({{ '/hosts/' | relative_url }}) and [Recipes]({{ '/recipes/' | relative_url }}).

### Does the agent take commands from the server?

No. It receives desired state, runs only hooks written in its own root-owned `agent.yaml`, and writes
only below the paths listed there. It connects out to the server over mutual TLS; the server never
connects to an administrative agent port. See [Security]({{ '/reference/security/' | relative_url }}#what-protects-what).

### Can I use the agent on a host without port 80 or behind NAT?

Yes, for the certificates, since v0.3.7. A deployment with `challenge: dns-01` proves its names through a
DNS TXT record, so it needs no port 80 and no connection from the server to the host; it also gets
wildcards. See [dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). The agent still
**enrolls** with http-01 or with an approval: a host without port 80 enrolls with a join token and one
approval in the UI. For a DNS provider the agent does not have (only RFC 2136 and Cloudflare are built in),
use an ACME client with a DNS plug-in
([operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network)).

### Which DNS providers can the agent use for dns-01?

Two: **RFC 2136** (dynamic updates with a TSIG key, as BIND, Knot and PowerDNS offer) and **Cloudflare** (an
API token). Not supported: Active Directory DNS (it needs GSS-TSIG), other providers and the legacy Cloudflare
global API key. The secret lives in a root-only file of its own, never in `agent.yaml`. See
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}).

### How do I roll the agent out to many hosts?

With the Salt formula and an enrollment pass: an admin creates the pass once with a second factor, and
`state.apply myownpki` installs, enrolls and configures every minion. Ansible or a script can use the pass
the same way, but the project ships only the Salt formula. Run it on one host first.
See [Rolling out agents with Salt]({{ '/hosts/salt/' | relative_url }}) and
[the enrollment pass]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs).

### What happens to the old certificate after a renewal?

The tenant setting decides. The default for agent deployments is to revoke the predecessor immediately
after the new certificate is confirmed as deployed, and for other certificates after seven days. A
revocation happens only after an accepted report with proof that the new certificate is the one being
served. Review both defaults in *Administration → Tenant settings*.
See [Renewal and what the agent reports]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).

### Does the agent update itself?

No. There is no self-update and no remote command. An update is a new package and `setup` again on the
host; the *Agents* page shows the verified commands, and with Salt it is a change of `version` and the
package hash in the pillar. Update the server first. See
[Update the agents]({{ '/upgrade/' | relative_url }}#update-the-agents).

## Security and recovery

### Where are the keys?

Online CA keys are in `pki.db` in the data directory, **encrypted**: AES-256-GCM under a root key that is
wrapped with a key derived from your passphrase (Argon2id), and again with the recovery key. They are
decrypted into memory only while the server is unsealed. The key of an offline root is not on the server at
all. Host keys made by an agent or by `openssl` stay on the host. See
[What protects what]({{ '/reference/security/' | relative_url }}#what-protects-what).

### What if I lose the unseal passphrase?

Run `myownpki passphrase reset` with the **recovery key**; nothing is lost. A backup taken earlier unseals
only with the passphrase that was valid then (or after a `passphrase reset` with the recovery key), so keep
the old passphrase with those backups until they age out.
See [operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key).
Background: [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}).

### What if I lose the passphrase and the recovery key?

The CA keys cannot be recovered: there is no support, no back door and no recovery from a backup. You
create new CAs, issue new certificates and retire the old CAs; every client has to learn the new root.
This is why the passphrase, the recovery key and the backups belong in three different places.
See [The passphrase and the recovery key]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key).

### What if someone gets onto the server?

*Seal* the server at once, which removes all keys from memory, take it off the network, check the audit
log with `audit verify` and restore onto a clean machine. Whoever has a backup plus the passphrase or the
recovery key can sign as your CAs, so a stolen backup alone is not enough, but the three secrets must not
sit together. See [operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).
Background: [Revocation]({{ '/learn/revocation/' | relative_url }}).

### Can the audit log be trusted?

Every action and every refusal is recorded in a hash chain with signed checkpoints, and
`myownpki audit verify` walks it. With the checkpoint key fingerprint written down at `init` it can also
show that the log is the one you had and not a replacement. Single entries cannot be deleted or changed,
which matters if the log holds personal data such as user names and addresses.
See [Verify the audit log now and then]({{ '/best-practices/' | relative_url }}#verify-the-audit-log-now-and-then).
Guide: [The audit log]({{ '/guides/audit-log/' | relative_url }}).

### I lost my phone. How do I sign in again?

A person with access to the server console runs `myownpki user reset-2fa NAME`, which needs the unseal
passphrase or the recovery key, and the user confirms a new authenticator at the next sign-in. A user who
is only locked out after too many wrong passwords waits 15 minutes, or an instance admin unlocks them.
See [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in).
Guide: [When things go wrong]({{ '/guides/when-things-go-wrong/' | relative_url }}).

## Updates and releases

### How do I upgrade?

Read the notes of every release you skip, make a backup, run the `install.sh` of the new release (or pull
the new image), unseal, check the version, then update the agents. `install.sh` backs up and verifies first,
and puts the old binary back if the new one does not become healthy.
See [Upgrade]({{ '/upgrade/' | relative_url }}#the-routine).

### Can I go back to the old version?

`install.sh` rolls back by itself when the new version does not start. Later, going back means restoring the
backup taken before the update, because a database that is newer than the binary is refused. Certificates
issued after that backup are not in it. See [Roll back]({{ '/upgrade/' | relative_url }}#roll-back).

### Is the REST API stable?

Not before 1.0. The release notes say that a minor version may change the API, the configuration and the
database schema, and each release says how to upgrade. The API is described in `api/openapi.yaml`
(OpenAPI 3.1), and pinning your scripts to a version and reading the notes before an update is the safe
way. See [REST API]({{ '/reference/api/' | relative_url }}).

### How do I know a download is genuine?

Every release is built by a workflow from a tag. `checksums.txt` is signed keyless with cosign (Sigstore),
each archive has an SBOM, and the builds are reproducible. `install.sh` checks the SHA-256 of what it
downloads, and the signature too when cosign is installed.
See [Verify a download]({{ '/reference/security/' | relative_url }}#verify-a-download).

### What comes next?

The plan lists dns-01 in the agent (v0.3.7), charts and an analysis page (v0.3.8), a public trust portal
(v0.3.9), a preview before issuance and versioned settings (v0.3.10), Apache and HAProxy profiles and
guides inside the UI (v0.3.11), then a quality round and a beta before 1.0. The order is firmer than the
numbers. Release plan: [docs/PLAN.md §10.1]({{ site.repository_url }}/blob/main/docs/PLAN.md).
