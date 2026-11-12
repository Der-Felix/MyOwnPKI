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

## What is in it

- **CA engine:** root and intermediate authorities, presets for server, client, mail and other
  certificates, name constraints, CRLs, and an offline root that signs on another machine.
- **ACME server** (RFC 8555) for certbot, acme.sh, lego, Traefik, Caddy and other clients. Clients
  renew by themselves; nobody copies certificates by hand any more.
- **Web UI and REST API** with roles, a second factor for every user, and a hash-chained audit log.
  The API is described in an OpenAPI file.
- **Agent** (`myownpki-agent`, Linux): optional. It gets a certificate by ACME, writes it for nginx
  or into plain files, reloads the service and rolls back when the reload fails.
- **Monitoring:** the server checks itself every minute and tells you by e-mail or webhook when a
  certificate or a CA is about to expire, a CRL goes stale, the server is sealed or an agent is
  silent.
- **Backup and restore**, a daily backup timer, and an import of the old `pki.sh` Bash suite.

## Who it is for

You run services on an internal network, such as a homelab, a lab or a small company, and want
TLS certificates that browsers and tools trust without paying for a public CA or clicking
through warnings. You are comfortable with a Linux shell and with systemd or containers. You do not
need to be a PKI expert: the pages explain the few PKI ideas that matter where they come up.

## Three ways to connect a host

You choose per host how much MyOwnPKI does for you. The agent is optional.

| Level | On the host | What the server knows | State |
|---|---|---|---|
| 1. ACME only | An ACME client you already run: certbot, acme.sh, lego, Traefik, Caddy | Issuances and renewals | Available |
| 2. ACME and scan | The same client | Also whether the certificate is really served (a TLS scan from the server) | Planned (v0.3.4) |
| 3. Agent | `myownpki-agent`, which uses ACME inside | Everything: inventory, deployment, reload, rollback, a local TLS check | Available for Linux |

Level 1 is enough for hosts that already renew by ACME. Take level 3 when you want the server to
see what is deployed where and to renew on a button. How to set up each level is on
[Adding hosts]({{ '/hosts/' | relative_url }}).

## Start here

| I want to | Go to |
|---|---|
| Install the server | [Installation]({{ '/install/' | relative_url }}) |
| Update to a new release | [Upgrade]({{ '/upgrade/' | relative_url }}) |
| Get certificates onto a host, with or without the agent | [Adding hosts]({{ '/hosts/' | relative_url }}) |
| Roll the agent out with Salt | [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}) |
| Be told when something expires or breaks | [Monitoring]({{ '/monitoring/' | relative_url }}) |
| Know what to do and what to avoid | [Best practices]({{ '/best-practices/' | relative_url }}) |
| Fix something that does not work | [Troubleshooting]({{ '/troubleshooting/' | relative_url }}) |
| Look up a command, a key or an API call | [Reference]({{ '/reference/' | relative_url }}) |

> **Warning:** Read the part about the unseal passphrase and the recovery key on the
> [installation page]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key) before you
> create your first authority. Without one of the two, the keys of your CAs cannot be recovered,
> and nobody can help you get them back.
{: .warning}

## About this site

The pages here are guides for the tasks you do. The complete operator's book, the example
configuration and the release notes are part of the repository and shown unchanged under
[Reference]({{ '/reference/' | relative_url }}). The source of the project is on
[GitHub]({{ site.repository_url }}); problems with these pages are welcome as
[issues]({{ site.repository_url }}/issues).
