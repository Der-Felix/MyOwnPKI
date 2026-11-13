---
title: "Guides"
description: "Task guides for MyOwnPKI: issue and renew certificates, connect ACME clients, make clients trust your root, back up and restore, manage users, and recover when something goes wrong."
permalink: /guides/
---

The pages under Installation and Adding hosts take you from nothing to a running setup. These guides are for
the tasks that come after: one task per page, with the steps, a check that it worked, and what to do when it
does not. Each one links to the [operations guide]({{ '/reference/operations/' | relative_url }}) for the
complete details. If you want to know why something works the way it does, the
[Learn]({{ '/learn/' | relative_url }}) pages explain the idea behind it.

## Get certificates

| I want to | Guide |
|---|---|
| Issue my first certificate in the web UI | [Issue a first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }}) |
| Let certbot get and renew certificates | [Certbot with MyOwnPKI]({{ '/guides/certbot/' | relative_url }}) |
| Use acme.sh | [acme.sh with MyOwnPKI]({{ '/guides/acme-sh/' | relative_url }}) |
| Use lego | [lego with MyOwnPKI]({{ '/guides/lego/' | relative_url }}) |
| Use Traefik or Caddy | [Traefik and Caddy as ACME clients]({{ '/guides/traefik-caddy/' | relative_url }}) |
| Say which names a client may ask for, approve them, or create an EAB key | [Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}) |
| Understand why validation fails on my network | [Split DNS and the network for validation]({{ '/guides/split-dns/' | relative_url }}) |
| Renew or revoke a certificate | [Renew and revoke certificates]({{ '/guides/renew-and-revoke/' | relative_url }}) |
| Run the server behind nginx or another proxy | [Put MyOwnPKI behind a reverse proxy]({{ '/guides/reverse-proxies/' | relative_url }}) |

## Trust and authorities

| I want to | Guide |
|---|---|
| Make laptops, phones and servers trust my root | [Make clients trust your root]({{ '/guides/trust-the-root/' | relative_url }}) |
| Create a root and an intermediate, or replace one | [CA lifecycle: create, renew, replace]({{ '/guides/ca-lifecycle/' | relative_url }}) |
| Keep the root key on a machine that is offline | [Sign with an offline root]({{ '/guides/offline-root/' | relative_url }}) |
| Move over from the old Bash suite | [Move from the old Bash suite]({{ '/guides/import-from-pki-sh/' | relative_url }}) |

## Run it

| I want to | Guide |
|---|---|
| Back up, and prove that a restore works | [Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}) |
| Add people, set roles and a second factor, create API tokens | [Users, roles, second factor and API tokens]({{ '/guides/users-roles-2fa/' | relative_url }}) |
| See who did what, and check that the log was not changed | [The audit log]({{ '/guides/audit-log/' | relative_url }}) |
| Know what to do when the server is sealed, a secret is lost or a CA is compromised | [When things go wrong]({{ '/guides/when-things-go-wrong/' | relative_url }}) |

## More

| I want to | Page |
|---|---|
| Find a quick answer | [FAQ]({{ '/faq/' | relative_url }}) |
| Look up a term | [Glossary]({{ '/glossary/' | relative_url }}) |
| See what the screens look like | [A tour of the web UI]({{ '/tour/' | relative_url }}) |
| Fix an error message | [Troubleshooting]({{ '/troubleshooting/' | relative_url }}) |
