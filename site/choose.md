---
title: "Choose your setup"
description: "Decide how to run the MyOwnPKI server (systemd or container), how each host gets its certificates (ACME client, ACME client plus TLS scan, or the agent) and how to roll the agent out (Add host assistant, packages, Salt formula)."
permalink: /choose/
---

Three decisions, in this order: where the **server** runs, how each **host** gets its certificates,
and, if you use the agent, how you **roll it out**. Each part has a table; every row links to
the page that holds the details. This page compares, it does not repeat the steps.

* TOC
{:toc}

## 1. The server

Both ways install the same program. Both need a stable DNS name for the server (it is written into
every certificate), the right time, and about 256 MiB of free memory for a moment when you unseal.
See [Before you start]({{ '/install/' | relative_url }}#before-you-start).

| | systemd service (`install.sh`) | Container |
|---|---|---|
| You need | A Linux machine with systemd (Debian, Ubuntu and other systemd distributions), amd64 or arm64. Root, and the standard tools the [installation page]({{ '/install/' | relative_url }}#option-a-linux-with-systemd) lists. | Docker with Compose. The image `ghcr.io/der-felix/myownpki` exists for linux/amd64 and linux/arm64. The files `docker-compose.yml` and `docker/config.yaml` from the `deploy/` directory of the release. |
| What it sets up | Downloads the archive of its own version and checks it against `checksums.txt` (and the signature, if cosign is installed). Creates the user `myownpki`, installs the binary, a hardened systemd unit and a daily backup timer, and publishes the agent packages. Writes `config.yaml` only if there is none. Enables the service but does not start it. | Runs the image as the non-root user 65532 with a read-only root file system and no extra capabilities. The configuration file is mounted read-only. You run `init` with `docker compose run`. |
| Where the data lives | `/var/lib/myownpki`; configuration in `/etc/myownpki/config.yaml`; backups in `/var/backups/myownpki` | The named volume `myownpki-data`, mounted at `/var/lib/myownpki`; configuration in `docker/config.yaml` next to the compose file |
| Backups | A daily timer, 14 backups kept by default | No timer. Run the `backup` command from cron or a timer of your own. |
| Updates | Run the `install.sh` of the new release. It makes a backup, installs, checks the health and puts the old version back if the new one does not run. | Pin the new image version in the compose file, then `docker compose pull` and `docker compose up -d`. |
| Pick it when | The CA gets a machine or VM of its own, and you want the hardened unit, the backup timer and an update that rolls itself back. | You already run containers, or the machine has no systemd, and you are fine with scheduling backups yourself. |
| Details | [Option A]({{ '/install/' | relative_url }}#option-a-linux-with-systemd), [update with install.sh]({{ '/upgrade/' | relative_url }}#with-installsh) | [Option B]({{ '/install/' | relative_url }}#option-b-container), [update a container]({{ '/upgrade/' | relative_url }}#with-a-container) |
{: .stack .stack-server}

The server starts **sealed** after every start and every update: you unseal it in the web UI. Read
[the passphrase and the recovery key]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key)
before you run `init`.

The releases also contain archives of the server for macOS (arm64), FreeBSD (amd64) and Windows
(amd64). This site describes only the two ways above.

## 2. Getting certificates onto hosts

You choose per host, and you can mix the levels. The ACME server is off until you set
`acme.base_url`; the agent also needs its own listener. The tables on
[the start page]({{ '/' | relative_url }}#three-ways-to-connect-a-host) and on
[Adding hosts]({{ '/hosts/' | relative_url }}#which-level-for-which-host) show the same levels from
other sides.

| Level | What you do, and what the server knows | Pick it when |
|---|---|---|
| **1. ACME client only** | Run an ACME client you already have (certbot, acme.sh, lego, Traefik, Caddy, win-acme, cert-manager) against the ACME server. The project tests certbot, acme.sh and lego in CI; the others are documented, not tested. The server knows issuances and renewals. [Operations guide §10]({{ '/reference/operations/' | relative_url }}#10-acme-server) | The host already renews by ACME, or it is not a Linux host. |
| **2. ACME client and TLS scan** | The same client, and you enter the host's TLS endpoint on the server. The server connects regularly (every 15 minutes by default) and compares what it serves with what this PKI issued. Nothing is installed on the host. [TLS scan]({{ '/tls-scan/' | relative_url }}) | You do not want to hear about a renewal that never reached the web server from a user. |
| **3. Agent** | Install `myownpki-agent` (Linux with systemd). It gets the certificate by ACME, writes the files, tests, reloads the service and rolls back if that fails. The server also knows what is deployed, its serial and expiry, and whether the host is alive. [Adding hosts]({{ '/hosts/' | relative_url }}) | Linux hosts with nginx or plain files that you want to manage from one place, or that should renew on a button. |
{: .stack .stack-levels}

The agent asks more of the server than the other two levels: an agent CA, the agent listener, port
8444 open to the hosts and an ACME domain that covers the host names. The list is under
[What the server needs first]({{ '/hosts/' | relative_url }}#what-the-server-needs-first). The
[recipes]({{ '/recipes/' | relative_url }}) set up nginx, Postfix, Dovecot and Proxmox VE with the
agent.

## 3. Rolling out the agent

Skip this part if you use ACME clients only. All four ways end in the same command,
`myownpki-agent setup`. In all of them the server must be able to reach port 80 of the host under its
name: in the default enrollment mode the server fetches a check file from there before it admits the host. Whether a
person has to approve the host depends on the enrollment mode and on the token or pass the host
presents: see [Admission]({{ '/hosts/' | relative_url }}#admission-token-check-approval).

| Way | Who it is for, and the effort | What needs a person, and what is tested |
|---|---|---|
| **Add host assistant** in the web UI (*Agents → Add host*). [Details]({{ '/hosts/' | relative_url }}#add-host-the-guided-installation) | One host or a handful. The UI asks a few questions and shows the commands to run as root on the host, then follows the host until the certificate is deployed. Little effort per host, but you run the commands on each one. | An admin with a fresh second factor makes a single-use token (valid 15 minutes), or approves the host once in the UI. Tested: no live test of the assistant is recorded in the [release notes]({{ '/reference/changelog/' | relative_url }}). |
| **Packages by hand**: `.deb`, `.rpm` or `.tar.gz` for amd64 and arm64, then `myownpki-agent setup`. [Details]({{ '/hosts/' | relative_url }}#manual-installation-from-a-package) | Scripts, or hosts where you do not want the assistant. You check the download and give `setup` the server address and the SHA-256 of the root yourself. More typing, the same checks. | The same as above: a token or pass in a file, or one approval in the UI. Tested: the recorded live tests (of the Salt formula) used enrolled Debian amd64 hosts; `rpm` and `arm64` hosts were not tested live. |
| **`install-agent.sh`**, deprecated. [Details]({{ '/reference/operations/' | relative_url }}#122-guided-and-verified-installation) | Not for new installs. It is a compatibility wrapper from v0.3.1 that checks a release archive, installs the binary and calls `setup`, and it will be removed in a later release. Use a package or the tarball with `setup` instead. | The same as above. |
| **Salt formula** with an enrollment pass. [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}) | Many Linux hosts that Salt manages. You prepare the master once (the formula, the root, the packages and their hashes from the admin UI); then one `state.apply myownpki` installs, enrolls and configures every minion. | An admin creates the pass once, with a fresh second factor (an API token can never do that); no click per host. Without a pass, each host waits for one approval. Tested: CI renders and applies the test pillars with `test=True`; the formula was live tested on five enrolled Debian amd64 hosts. **Not tested live:** enrolling a new host with a pass, `rpm`, `arm64`, `config_source`, the gitfs install and other Salt versions. |
{: .stack .stack-rollout}

Ansible, a script or CI can enroll hosts with an enrollment pass in the same way
([the pass]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs)); this project ships
only the Salt formula. Run any roll-out on **one host** first.

> **Note:** The recipes for **Postfix, Dovecot and Proxmox VE** are unverified examples: they were
> not run on a live host. Only the nginx recipe rests on a setup the project has run. Try the others
> on a non-production host first, as [Recipes]({{ '/recipes/' | relative_url }}) says.
{: .note}

## If you are unsure

A **homelab with a few hosts**: run the server as a systemd service (or as a container if you
already run Docker), let the ACME clients you already have renew the certificates, and enter the
hosts that matter in the [TLS scan]({{ '/tls-scan/' | relative_url }}). Add the agent later, one host
at a time with the assistant, where you want deployment and rollback handled for you. Set up
[monitoring]({{ '/monitoring/' | relative_url }}) from the start.

**Many Linux hosts**: use the agent and roll it out with the
[Salt formula]({{ '/hosts/salt/' | relative_url }}) and an enrollment pass, after you have run it on
one host.
