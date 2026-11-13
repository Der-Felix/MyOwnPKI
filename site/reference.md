---
title: "Reference"
description: "The operator's book, the configuration file, the command line, the REST API, the release notes, the security notes and the contribution rules of MyOwnPKI."
permalink: /reference/
---

The guides on this site are written for tasks. This is the material you look things up in. Three of
the pages are the files of the repository, shown unchanged: when a file changes on `main`, the page
is built again.

| Page | What it is | Source in the repository |
|---|---|---|
| [Operations guide]({{ '/reference/operations/' | relative_url }}) | The operator's book: what runs where, install, `init`, running, backup and restore, passphrase and recovery key, when something is lost, upgrading, the ACME server, the trust page, the agent, monitoring, the TLS scan, reports and analysis | `docs/OPERATIONS.md` |
| [Configuration file]({{ '/reference/configuration/' | relative_url }}) | Every key of `config.yaml` with its default and a comment | `deploy/config.example.yaml` |
| [Command line]({{ '/reference/cli/' | relative_url }}) | The commands of `myownpki` and `myownpki-agent` | `cmd/` |
| [REST API]({{ '/reference/api/' | relative_url }}) | How to call the API, how to make a token, what a token cannot do | `api/openapi.yaml` |
| [Release notes]({{ '/reference/changelog/' | relative_url }}) | What changed in every release, with the upgrade notes | `CHANGELOG.md` |
| [Security]({{ '/reference/security/' | relative_url }}) | What protects what, how to report a vulnerability, how to verify a download | `SECURITY.md`, `docs/PLAN.md` |
| [Contributing]({{ '/reference/contributing/' | relative_url }}) | How to change the code or these pages | `CONTRIBUTING.md` |

## The operations guide by chapter

1. [What runs and where]({{ '/reference/operations/' | relative_url }}#1-what-runs-and-where): listeners, files and the secrets of `init`
2. [Install and configure]({{ '/reference/operations/' | relative_url }}#2-install-and-configure): `install.sh`, containers, settings, certificates the server issues itself
3. [First start: init]({{ '/reference/operations/' | relative_url }}#3-first-start-init)
4. [Running the server]({{ '/reference/operations/' | relative_url }}#4-running-the-server): seal, health checks, logs, the audit log
5. [Moving from pki.sh]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish)
6. [Backup and restore]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore), with the [daily timer]({{ '/reference/operations/' | relative_url }}#61-daily-backups-with-the-systemd-timer)
7. [Passphrase and recovery key]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key)
8. [When something is lost or wrong]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong)
9. [Upgrading]({{ '/reference/operations/' | relative_url }}#9-upgrading)
10. [ACME server]({{ '/reference/operations/' | relative_url }}#10-acme-server): proxies, domains, EAB keys, clients, split DNS, errors
11. [The public trust page]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page)
12. [Agent]({{ '/reference/operations/' | relative_url }}#12-agent): server setup, installation, `agent.yaml`, firewall, status
13. [Monitoring and notifications]({{ '/reference/operations/' | relative_url }}#13-monitoring-and-notifications)
14. [TLS scan]({{ '/reference/operations/' | relative_url }}#14-tls-scan)
15. [Reports and analysis]({{ '/reference/operations/' | relative_url }}#15-reports-and-analysis): charts, the ten analysis rules, who sees them, the API

## More in the repository

- [Project plan and decisions](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md): the
  architecture, the decisions (ADRs) and the roadmap.
- [OpenAPI description](https://github.com/Der-Felix/MyOwnPKI/blob/main/api/openapi.yaml) of the REST API.
- [`legacy/`](https://github.com/Der-Felix/MyOwnPKI/tree/main/legacy): the original Bash suite `pki.sh`,
  still the tool for an offline root.
- [Third-party software](https://github.com/Der-Felix/MyOwnPKI/blob/main/THIRD_PARTY.md) and the
  [Apache License 2.0](https://github.com/Der-Felix/MyOwnPKI/blob/main/LICENSE).
