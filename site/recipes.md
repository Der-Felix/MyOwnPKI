---
title: "Recipes"
description: "Ready-made agent deployments for nginx, Postfix, Dovecot and Proxmox VE: what each sets, the commands the Add host assistant generates, where the files go and what to verify. The Postfix, Dovecot and Proxmox VE recipes are unverified examples."
permalink: /recipes/
---

A **recipe** is a set of defaults for `myownpki-agent deployment add --recipe NAME`: where the
certificate files go, who owns them, which hooks test and reload the service, which local TLS port the
agent checks afterwards and what the systemd sandbox must allow. You can use a recipe from the
[Add host assistant]({{ '/hosts/' | relative_url }}#add-host-the-guided-installation) (choose the
service) or by hand on a host that has an agent. Any flag you pass overrides the recipe, and
`--dry-run` shows what it expands to before it writes anything.

> **Warning: unverified examples.** Only the **nginx** recipe rests on a setup the project has run: the
> agent end-to-end tests deploy to a real nginx under real systemd, with the nginx hooks and the
> low-port capability. The **Postfix**, **Dovecot** and **Proxmox VE** recipes are examples, written from the
> documentation of each service and **not yet run on a live host**. `deployment add` says so itself
> when you use them. Try them on a **non-production host first**, check each point under *What to
> verify*, and expect to change a path, a group or a hook. If something differs from this page, please
> tell us in an [issue]({{ site.repository_url }}/issues).
{: .warning}

* TOC
{:toc}

## Overview

| Recipe | Files | Owner and key mode | Hooks | Local check | Sandbox |
|---|---|---|---|---|---|
| `nginx` | `fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>` | root, `0600` | test `/usr/sbin/nginx -t`, reload `/usr/bin/systemctl reload nginx` | `127.0.0.1:443` | write `/var/log/nginx`, low ports |
| `postfix` (example) | `/etc/ssl/myownpki/postfix/fullchain.pem` and `privkey.pem` | root:root, `0600` | test `/usr/sbin/postfix check`, reload `/usr/bin/systemctl reload postfix` | none | none |
| `dovecot` (example) | `/etc/ssl/myownpki/dovecot/fullchain.pem` and `privkey.pem` | root:root, `0600` | test `/usr/bin/doveconf -n`, reload `/usr/bin/systemctl reload dovecot` | `127.0.0.1:993` | none |
| `proxmox` (example) | `/etc/ssl/myownpki/pve/fullchain.pem` and `privkey.pem` | root:root, `0600` | install and restart `/usr/bin/pvenode cert set …` (no separate test) | `127.0.0.1:8006` | write `/etc/pve` |

The deployment is named after the service in the assistant (`nginx`, `postfix`, `dovecot`, `proxmox`).
By hand you choose the name; for the nginx recipe it is also the last part of the directory. The check
is an **implicit-TLS** handshake, so a STARTTLS port (25, 143, 587) cannot be checked.

## Before you start

The host needs an enrolled agent (v0.3.5 or later) and an `acme_directory`. The assistant does both
for a new host. On a host that already has an agent, make the parent directory of the files first, or
pass `--create-dirs`, and add the deployment:

```bash
sudo install -d -m 0755 /etc/ssl/myownpki/postfix
```

```bash
sudo /usr/local/bin/myownpki-agent deployment add postfix --recipe postfix --name mail.homelab.lan --webroot /var/www/acme --dry-run
```

The dry run prints a diff of `agent.yaml` and both systemd drop-ins, and for an example recipe the
words *example recipe, test on a non-production host* and a list of what to verify. When the diff is
what you expect, run it again without `--dry-run`, add `--restart`, or restart the agent yourself.
Undo it with `deployment remove postfix`.

**A wildcard, or a host without port 80.** Every recipe works with `--challenge dns-01` (agent 0.3.7):
replace `--webroot …` with the dns-01 flags, and add `--check-name` when every name is a wildcard and the
recipe has a check. The recipe still decides the files, hooks and sandbox; only the way the names are
proven changes. The flags, the credentials file and the DNS settings are on
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). The assistant does not generate dns-01
commands; run `deployment add` by hand.

## nginx

The recipe the others follow. The assistant generates this block for `minion-01.homelab.lan`, service
nginx and the webroot challenge (replace the names, the webroot and the ACME directory with yours):

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki'
/usr/local/bin/myownpki-agent deployment add 'nginx' \
  --recipe nginx \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

Point the server block at the files, and let nginx answer the challenge on port 80:

```nginx
server {
    listen 80;
    server_name minion-01.homelab.lan;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
}

server {
    listen 443 ssl;
    server_name minion-01.homelab.lan;
    ssl_certificate     /etc/ssl/myownpki/nginx/fullchain.pem;
    ssl_certificate_key /etc/ssl/myownpki/nginx/privkey.pem;
}
```

**Why the sandbox entries.** `nginx -t` opens its log files, so `/var/log/nginx` must be writable
(`sandbox.write`), and it opens the listen sockets, so a listener on 443 needs `20-low-ports.conf`,
also in webroot mode. The recipe sets both. If `nginx -t` still says `Read-only file system` for a
temporary directory, add it with `--sandbox-write`.

**What to verify.** The agent page shows the deployment as `deployed`; `openssl s_client -connect
minion-01.homelab.lan:443 -servername minion-01.homelab.lan </dev/null` shows its serial. The
`deployment add --recipe nginx` command itself is new in this release and has not run on a live host yet either.

## Postfix (example, not verified)

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki/postfix'
/usr/local/bin/myownpki-agent deployment add 'postfix' \
  --recipe postfix \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

Point Postfix at the two files in `main.cf`. With Postfix 3.4 and later:

```text
smtpd_tls_chain_files = /etc/ssl/myownpki/postfix/privkey.pem, /etc/ssl/myownpki/postfix/fullchain.pem
```

The key comes first. Older versions use `smtpd_tls_cert_file` and `smtpd_tls_key_file` instead. Reload
Postfix once yourself to load the setting.

The recipe sets **no local check**, because the check is an implicit-TLS handshake and port 25 is
STARTTLS. If `master.cf` has a `submissions` listener on 465 (implicit TLS), add
`--check 127.0.0.1:465`.

**What to verify.**

- `postfix check`, the test hook, runs inside the agent's sandbox without needing to write anything.
- No group is needed for the key: Postfix reads it as root before it drops privileges. If your setup
  reads the key as another user, pass `--group` and `--key-mode 0640`.
- After a renewal, a new connection gets the new certificate:
  `openssl s_client -starttls smtp -connect mail.homelab.lan:25 </dev/null`.

## Dovecot (example, not verified)

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki/dovecot'
/usr/local/bin/myownpki-agent deployment add 'dovecot' \
  --recipe dovecot \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

Point Dovecot at the files. Dovecot 2.3 (`conf.d/10-ssl.conf`), note the `<`:

```text
ssl_cert = </etc/ssl/myownpki/dovecot/fullchain.pem
ssl_key = </etc/ssl/myownpki/dovecot/privkey.pem
```

Dovecot 2.4 uses `ssl_server_cert_file` and `ssl_server_key_file`, without the `<`.

The local check is `127.0.0.1:993`, the implicit-TLS IMAP port; change it with `--check` if your
installation does not listen there.

**What to verify.**

- A reload (`systemctl reload dovecot`) makes **new** connections use the new certificate.
- Which `doveconf` option is a pure syntax test on your version. The recipe's test hook is
  `doveconf -n`, which reads and prints the active configuration; replace it with
  `--test-hook` and a `--hook` of your own if you know a better one.
- The key mode: root-owned `0600` works if Dovecot reads it as root at start.

## Proxmox VE (example, not verified)

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki/pve'
/usr/local/bin/myownpki-agent deployment add 'proxmox' \
  --recipe proxmox \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

The agent does **not** write into `/etc/pve`: that is a FUSE file system which takes neither `chown`
nor `chmod`. It writes the files to `/etc/ssl/myownpki/pve` and runs one hook that does the rest:

```text
/usr/bin/pvenode cert set /etc/ssl/myownpki/pve/fullchain.pem /etc/ssl/myownpki/pve/privkey.pem --force 1 --restart 1
```

`pvenode` validates the files, installs them as the node's certificate and restarts `pveproxy`. After a
failed deployment the agent rolls back by running it again on the restored files. The sandbox gets
write access to `/etc/pve` for that hook. The local check is `127.0.0.1:8006`, the web interface.

Run **one agent per node**: the certificate belongs to the node, and a cluster shares `/etc/pve`.

**What to verify.**

- The `pvenode cert set` syntax of **your** Proxmox VE version (`pvenode cert set --help`).
- That `pvenode` works under the agent's sandbox; it writes below `/etc/pve`.
- That `https://<node>:8006` serves the new certificate afterwards, and that the web interface comes
  back (`systemctl status pveproxy`).

## When you have tried one

Write down every difference from this page: a different path, a missing group, a hook that needs
another directory in `sandbox.write`. Open an [issue]({{ site.repository_url }}/issues) with the
service version and the `deployment add` output, so that the recipe and this page can be corrected.
Other services work the same way without a recipe; see `deployment add` in
[Adding hosts]({{ '/hosts/' | relative_url }}#adding-a-deployment-deployment-add).
