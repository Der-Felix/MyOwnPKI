---
title: "MyOwnPKI documentation"
description: "Install, run and automate MyOwnPKI: a self-hosted certificate authority with an ACME server, a web UI, a REST API and an optional agent."
permalink: /
---

MyOwnPKI is a self-hosted public key infrastructure. It runs your own certificate authorities, hands
out certificates to the clients that ask for them by ACME (the protocol of Let's Encrypt), and
shows you in a web UI what is issued, what expires soon and what needs your attention. It is one
Go program that runs as a systemd service or as a container.

Current release: **{{ site.data.release.version }}**, {{ site.data.release.date }}
([release notes]({{ '/reference/changelog/' | relative_url }})). Before version 1.0 a minor version
may change the API, the configuration or the database schema; the
[upgrade notes]({{ '/upgrade/' | relative_url }}) say what to do.

## From zero to a first certificate

1. **Install the server** with `install.sh` on a Linux machine with systemd, or start the container
   image with Docker Compose, then run `init` once.
   See [Installation]({{ '/install/' | relative_url }}).
2. **Unseal the server and create the first CA.** Sign in to the web UI, unseal, then create an
   intermediate below an offline root. For a first try, `init --with-ca` creates a root and an
   intermediate for you.
   See [The first CA and the first certificate]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).
3. **Get a certificate.** Point an ACME client such as certbot, acme.sh or Caddy at the ACME server
   (switched on with `acme.base_url`, see the
   [operations guide §10]({{ '/reference/operations/' | relative_url }}#10-acme-server)), or choose
   *Agents → Add host* in the web UI to put the agent on a host.
   See [Adding hosts]({{ '/hosts/' | relative_url }}).

Not sure which way fits your network? [Choose your setup]({{ '/choose/' | relative_url }}) compares
the server installs, the three ways to connect a host and the ways to roll out the agent.

> **Warning:** Read the part about the unseal passphrase and the recovery key on the
> [installation page]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key) before you
> create your first authority. Without one of the two, the keys of your CAs cannot be recovered,
> and nobody can help you get them back.
{: .warning}

## What is in it

The parts, and who talks to whom:

<div class="diagram">
{% include_relative assets/overview.svg %}
<p class="diagram-caption">Clients at the top, the server in the middle, what the server sends out at the bottom. An arrow points from the side that connects to the side that answers.</p>
</div>

- **CA engine:** root and intermediate authorities, presets for server, client, mail and other
  certificates, name constraints, CRLs, and an offline root that signs on another machine.
- **ACME server** (RFC 8555) for certbot, acme.sh, lego, Traefik, Caddy and other clients. Clients
  renew by themselves; nobody copies certificates by hand any more.
- **Web UI and REST API** with roles, a second factor for every user, and a hash-chained audit log.
  The API is described in an OpenAPI file.
- **Agent** (`myownpki-agent`, Linux, optional): gets a certificate by ACME, writes it for nginx or
  into plain files, reloads the service and rolls back when the reload fails. An *Add host*
  assistant takes a new host from its name to a deployed certificate, the
  [Salt formula]({{ '/hosts/salt/' | relative_url }}) rolls the agent out to many hosts, and
  [recipes]({{ '/recipes/' | relative_url }}) cover nginx, Postfix, Dovecot and Proxmox VE (the last
  three are unverified examples).
- **Monitoring:** the server checks itself every minute and tells you by e-mail or webhook when a
  certificate or a CA is about to expire, a CRL goes stale, the server is sealed or an agent is
  silent.
- **TLS scan:** the server connects to the endpoints you enter, reads the certificate each one really
  serves and alerts when it is not the one this PKI issued, for example after a renewal that never
  reached the web server.
- **Reports and analysis:** charts of the expiry of the current week and the next 12 weeks, the issuances by source, the
  certificates per CA, the alert history and the agent fleet, and ten rules that point out what no alert
  covers, such as a weak key, a renewal loop or a certificate that no scanned endpoint serves. The server draws the charts
  itself; no script runs in the browser.
- **Backup and restore**, a daily backup timer, and an import of the old `pki.sh` Bash suite.

## Who it is for

You run services on an internal network, such as a homelab, a lab or a small company, and want
TLS certificates that browsers and tools trust without paying for a public CA or clicking
through warnings. You are comfortable with a Linux shell and with systemd or containers. You do not
need to be a PKI expert: the pages explain the few PKI ideas that matter where they come up.

## Three ways to connect a host

You choose per host how much MyOwnPKI does for you. The agent is optional.

| Level | On the host | What the server knows |
|---|---|---|
| 1. ACME only | An ACME client you already run: certbot, acme.sh, lego, Traefik, Caddy | Issuances and renewals |
| 2. ACME and scan | The same client | Also whether the certificate is really served (a [TLS scan]({{ '/tls-scan/' | relative_url }}) from the server) |
| 3. Agent | `myownpki-agent` (Linux), which uses ACME inside | Everything: inventory, deployment, reload, rollback, a local TLS check |

Level 1 is enough for hosts that already renew by ACME. Add level 2 for the hosts you cannot afford
to find out about from a user: nothing is installed, you enter the endpoint on the server. Take
level 3 when you want the server to see what is deployed where and to renew on a button.
[Choose your setup]({{ '/choose/' | relative_url }}) helps you decide, and
[Adding hosts]({{ '/hosts/' | relative_url }}) shows how to set up each level.

## Start here

| I want to | Go to |
|---|---|
| Decide how to set it all up | [Choose your setup]({{ '/choose/' | relative_url }}) |
| Understand how a CA, trust, ACME and revocation work | [Learn]({{ '/learn/' | relative_url }}) |
| Do one task: issue, renew, revoke, trust the root, back up | [Guides]({{ '/guides/' | relative_url }}) |
| Find a quick answer or look up a term | [FAQ]({{ '/faq/' | relative_url }}), [Glossary]({{ '/glossary/' | relative_url }}) |
| See what the web UI looks like | [A tour of the web UI]({{ '/tour/' | relative_url }}) |
| Install the server | [Installation]({{ '/install/' | relative_url }}) |
| Update to a new release | [Upgrade]({{ '/upgrade/' | relative_url }}) |
| Get certificates onto a host, with or without the agent | [Adding hosts]({{ '/hosts/' | relative_url }}) |
| Set up nginx, Postfix, Dovecot or Proxmox VE with the agent | [Recipes]({{ '/recipes/' | relative_url }}) |
| Roll the agent out with the Salt formula | [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}) |
| Be told when something expires or breaks | [Monitoring]({{ '/monitoring/' | relative_url }}) |
| Check that a host really serves the certificate it should | [TLS scan]({{ '/tls-scan/' | relative_url }}) |
| See the state of the PKI in charts and what looks odd | [Reports and analysis]({{ '/reports/' | relative_url }}) |
| Know what to do and what to avoid | [Best practices]({{ '/best-practices/' | relative_url }}) |
| Fix something that does not work | [Troubleshooting]({{ '/troubleshooting/' | relative_url }}) |
| Look up a command, a key or an API call | [Reference]({{ '/reference/' | relative_url }}) |

## About this site

The pages here are guides for the tasks you do. The complete operator's book, the example
configuration and the release notes are part of the repository and shown unchanged under
[Reference]({{ '/reference/' | relative_url }}). The source of the project is on
[GitHub]({{ site.repository_url }}); problems with these pages are welcome as
[issues]({{ site.repository_url }}/issues).
