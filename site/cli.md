---
title: "Command line"
description: "The commands of myownpki, the server, and myownpki-agent, with their options and where each is explained."
permalink: /reference/cli/
---

MyOwnPKI has three programs. `myownpki` is the server and its administration commands.
`myownpki-agent` is the agent for Linux hosts. `myownpki-ctl` is reserved for a command-line client of
the REST API; in this release it only prints its version. Every program takes `--version`. Run `myownpki`
without a command to see its usage.

Exit codes of `myownpki`: **0** success, **1** the command failed, **2** wrong usage.

* TOC
{:toc}

## myownpki

Almost every command reads the configuration. The file is chosen by `--config FILE`, then by the
environment variable `MYOWNPKI_CONFIG`, then by the default `/etc/myownpki/config.yaml` (on Windows
`%ProgramData%\MyOwnPKI\config.yaml`). Run the commands that open the data directory as the service
user, for example `runuser -u myownpki -- /usr/local/bin/myownpki …`.

| Command | What it does | Details |
|---|---|---|
| `serve` with `--unseal` | Runs the server. It starts sealed. With `--unseal` it asks for the passphrase on this terminal once the listeners run. | [Operations §4]({{ '/reference/operations/' | relative_url }}#4-running-the-server) |
| `serve --dev --listen 127.0.0.1:9443` | The UI prototype with sample data, no TLS, no login, loopback only. For looking at the UI, never for real use. | |
| `init` with `--stdin` or `--demo`, `--with-ca --ca-base-url URL`, `--admin-user NAME`, `--recovery-key-file FILE`, `--otpauth-file FILE` | Creates the instance: passphrase, recovery key, first admin, second factor. `--stdin` is for automation. `--demo` generates every secret into one file and marks the instance as a demo. `--with-ca` creates an online root and an intermediate for testing. | [Operations §3]({{ '/reference/operations/' | relative_url }}#3-first-start-init) |
| `config check` | Checks the configuration, prints what is in effect, and reads the secret and CA files of `notify:`. | [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#config-check-messages) |
| `healthcheck --timeout 5s` | Asks `/healthz` of the admin listener on this machine. Exit code 0 means healthy. A sealed server is healthy. | [Operations §4]({{ '/reference/operations/' | relative_url }}#health-checks-and-monitoring) |
| `db status`, `db migrate` | Shows the migration state; runs the migrations (they also run at start). | [Operations §9]({{ '/reference/operations/' | relative_url }}#9-upgrading) |
| `ca list`, `ca show NAME` | Lists the authorities, or shows one. | |
| `backup DIR` | A consistent copy of every database into the new directory `DIR`, while the server runs. | [Operations §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore) |
| `backup verify DIR --checkpoint-key FP` | Runs every restore check on a backup and writes nothing. | |
| `backup scheduled DIR --keep N` | The timer's run: backup into `DIR/<UTC time>`, verify, then prune. | [Operations §6.1]({{ '/reference/operations/' | relative_url }}#61-daily-backups-with-the-systemd-timer) |
| `backup prune DIR --keep N --dry-run` | Keeps the newest `N` scheduled backups and deletes older complete ones; never touches anything else. `--dry-run` only shows what would go. | |
| `restore DIR --checkpoint-key FP` | Restores into an empty or missing data directory, with the server stopped. Runs every check first. | |
| `audit verify` with `--scope S`, `--expect-head SEQ:HASH`, `--checkpoint-key FP` | Verifies the hash chain and the signatures of the audit logs. | [Operations §4]({{ '/reference/operations/' | relative_url }}#4-running-the-server) |
| `import legacy DIR` with `--dry-run`, `--base-url URL`, `--root-key offline` or `online` | Imports a `pki.sh` directory. Use `--dry-run` first. | [Operations §5]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish) |
| `user unlock NAME` | Unlocks a user who is locked out. | [Operations §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong) |
| `user reset-2fa NAME` with `--recovery-key`, `--new-auth-key`, `--otpauth-file PATH` | Gives a user a new second-factor secret. Reads the unseal passphrase, or with `--recovery-key` the recovery key, from standard input. | |
| `passphrase change`, `passphrase reset` | A new passphrase, proven with the current one; or, if it is lost, proven with the recovery key. | [Operations §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key) |
| `notify test` with `--channel email` or `--channel webhook` | Sends a test message through the configured channels. | [Monitoring]({{ '/monitoring/' | relative_url }}#test-the-channels) |

## myownpki-agent

The configuration is `/etc/myownpki-agent/agent.yaml` by default. `--config FILE` or the environment
variable `MYOWNPKI_AGENT_CONFIG` change it. The agent ignores `HTTPS_PROXY` and `HTTP_PROXY`.

| Command | What it does |
|---|---|
| `setup --server URL --ca-bundle FILE --root-sha256 HEX` with `--token-file FILE`, `--package-format deb`, `rpm` or `tarball`, `--webroot DIR`, `--hostname FQDN`, `--low-ports` | Writes the configuration, the systemd unit and its drop-ins, enrolls the host, and only then enables and starts the service. Run as root. Every option is explained in [Adding hosts]({{ '/hosts/' | relative_url }}#manual-installation-from-a-package). |
| `enroll --token-file FILE` | Enrolls this host once. `setup` calls it for you. |
| `run` | The service. systemd starts it. |
| `status` | The agent's identity, the enrollment state and every deployment with its last error. |
| `config check` | Checks `agent.yaml` and names every problem. |

## myownpki-ctl

`myownpki-ctl --version` prints the version. The command-line client for the
[REST API]({{ '/reference/api/' | relative_url }}) and the offline mode for root ceremonies are not
implemented yet; use `curl` with an API token, or `pki.sh` for an offline root.
