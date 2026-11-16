---
title: "Recipes"
description: "Ready-made agent deployments for nginx, Apache, HAProxy, Postfix, Dovecot and Proxmox VE: what each sets, the commands the Add host assistant generates, where the files go and what to verify. Every recipe except nginx is an unverified example."
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
> low-port capability. The **Apache** (`apache2`, `httpd`), **HAProxy**, **Postfix**, **Dovecot** and
> **Proxmox VE** recipes are examples, written from the documentation of each service and **not yet run
> on a live host**. `deployment add` says so itself when you use them. Try them on a **non-production
> host first**, check each point under *What to verify*, and expect to change a path, a group or a
> hook. If something differs from this page, please tell us in an
> [issue]({{ site.repository_url }}/issues).
>
> The `apache2` and `haproxy` recipes also run in the project's CI against the Apache and HAProxy
> packages of the CI runner, started by the test with a private configuration. That proves the files,
> the test hook and the rollback against the real programs. It is not a live host: the real systemd
> unit, the sandbox of the unit, the Red Hat layout and SELinux are not covered.
{: .warning}

* TOC
{:toc}

## Overview

| Recipe | Files | Owner and key mode | Hooks | Local check | Sandbox |
|---|---|---|---|---|---|
| `nginx` | `fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>` | root, `0600` | test `/usr/sbin/nginx -t`, reload `/usr/bin/systemctl reload nginx` | `127.0.0.1:443` | write `/var/log/nginx`, low ports |
| `apache2` (example) | `fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>` | root, `0600` | test `/usr/sbin/apache2ctl configtest`, reload `/usr/bin/systemctl reload apache2` | `127.0.0.1:443` | write `/var/log/apache2` |
| `httpd` (example) | `fullchain.pem` and `privkey.pem` in `/etc/ssl/myownpki/<deployment name>` | root, `0600` | test `/usr/sbin/httpd -t`, reload `/usr/bin/systemctl reload httpd` | `127.0.0.1:443` | write `/var/log/httpd` |
| `haproxy` (example) | one file `/etc/ssl/myownpki/haproxy/<deployment name>.pem` with the certificate chain and the private key | root:root, `0600` | test `/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg`, reload `/usr/bin/systemctl reload haproxy` | `127.0.0.1:443` | none |
| `postfix` (example) | `/etc/ssl/myownpki/postfix/fullchain.pem` and `privkey.pem` | root:root, `0600` | test `/usr/sbin/postfix check`, reload `/usr/bin/systemctl reload postfix` | none | none |
| `dovecot` (example) | `/etc/ssl/myownpki/dovecot/fullchain.pem` and `privkey.pem` | root:root, `0600` | test `/usr/bin/doveconf -n`, reload `/usr/bin/systemctl reload dovecot` | `127.0.0.1:993` | none |
| `proxmox` (example) | `/etc/ssl/myownpki/pve/fullchain.pem` and `privkey.pem` | root:root, `0600` | install and restart `/usr/bin/pvenode cert set …` (no separate test) | `127.0.0.1:8006` | write `/etc/pve` |

The deployment is named after the service in the assistant (`nginx`, `apache2`, `httpd`, `haproxy`,
`postfix`, `dovecot`, `proxmox`). By hand you choose the name. In every recipe path `{name}` stands for
that deployment name, so a name is a path segment and may hold only lower case letters, digits and `-`.
The nginx, `apache2` and `httpd` recipes use it as the last part of the directory, the `haproxy` recipe
as the file name, which is why two HAProxy deployments never write to the same file. The check is an
**implicit-TLS** handshake, so a STARTTLS port (25, 143, 587) cannot be checked.

## Before you start

The host needs an enrolled agent (v0.3.5 or later; **0.3.11 or later for `haproxy`**, see
[the combined file](#the-combined-file)) and an `acme_directory`. The assistant does both for a new host. On a host that already has an agent, make the parent directory of the files first, or
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

## Apache (example, not verified)

Two recipes, named after the unit they reload: **`apache2`** for Debian and Ubuntu and **`httpd`** for
the Red Hat family. They differ in the test command, the unit and the log directory (the table above).
The assistant lists them as *Apache (Debian, Ubuntu; example recipe)* and *Apache httpd (Red Hat family;
example recipe)*. This is what it generates for `apache2` (for `httpd`, replace the two names):

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki'
/usr/local/bin/myownpki-agent deployment add 'apache2' \
  --recipe apache2 \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

The recipe writes `fullchain.pem` and `privkey.pem` to `/etc/ssl/myownpki/apache2` (`httpd`:
`/etc/ssl/myownpki/httpd`). It **never edits the Apache configuration**; the lines in your virtual host are
yours. Enable `mod_ssl` (`a2enmod ssl` on Debian and Ubuntu, `dnf install mod_ssl` on the Red Hat family) and
point the virtual host at the files. The chain belongs in the first file, since Apache 2.4.8:

```text
SSLCertificateFile    /etc/ssl/myownpki/apache2/fullchain.pem
SSLCertificateKeyFile /etc/ssl/myownpki/apache2/privkey.pem
```

All deployments of one Apache recipe share one test hook and one reload hook, so they are one reload and
one rollback group: a failed test of one deployment rolls the others of that service back as well. The
agent runs the hooks with the argument vector of the table; no shell and no value from the server is
part of them.

**What the test hook covers.** `apache2ctl configtest` and `httpd -t` check that the files exist and that
the directives parse. It is **not known** to check that the key matches the certificate. The agent checks
the pair itself before it writes anything, so the gap is a file that is corrupted afterwards. The project's
CI runs the real `apache2ctl configtest` against a deliberately mismatched key, and a pass with a
corrupted staged key through the agent, and prints what it saw in the job summary; this page does not claim more than the recipe's notes,
which say *not known* until that answer is written down.

**What to verify** (on a test host, as `deployment add --dry-run` also tells you):

- `apache2ctl configtest` (or `httpd -t`) passes after you pointed the virtual host at the files. A
  *Renew now* in the UI (or `openssl s_client -connect <host>:443 -servername <name> </dev/null`) shows
  the new serial, and the agent reports `deployed`.
- What the test hook says when `privkey.pem` is corrupted by hand, and whether the rollback restores the
  old pair. A reload with a broken key can take Apache down; the open question is whether a failed
  graceful reload leaves the old process serving.
- The local check connects to `127.0.0.1:443` with the certificate's first name as SNI. When Apache
  listens elsewhere, set `--check HOST:PORT`, or delete the `check:` line of the deployment in
  `agent.yaml`: a check that fails on a valid setup rolls back every renewal.
- **Red Hat family and SELinux** (enforcing by default): `ls -Z /etc/ssl/myownpki`; if `httpd` cannot read
  the files, run `restorecon -R /etc/ssl/myownpki`. The recipe does not touch labels.
- No group is needed for the key while the root-run Apache master reads it before it drops privileges;
  add a group such as `ssl-cert` (and `--group`, `--key-mode 0640`) only if something else reads the key.
- `journalctl -u myownpki-agent` shows no `Read-only file system` or `Permission denied` from a hook.
  The recipe makes `/var/log/apache2` (`/var/log/httpd`) writable, because Apache opens its error log even for a
  check and fails with `AH00091` when it cannot; it sets no low-ports entry, because a check-only command is not
  expected to bind a port. If the log says otherwise, pass `--sandbox-write` or `--low-ports`.

## HAProxy (example, not verified)

HAProxy takes the certificate chain **and** the private key from one PEM file. The `haproxy` recipe
writes exactly that, one file per deployment, with the file profile's `combined` target (see
[the combined file](#the-combined-file)). This is what the assistant generates, as *HAProxy (example
recipe)*:

```bash
( set -euo pipefail
install -d -m 0755 '/etc/ssl/myownpki/haproxy'
/usr/local/bin/myownpki-agent deployment add 'haproxy' \
  --recipe haproxy \
  --name 'minion-01.homelab.lan' \
  --challenge webroot --webroot '/var/www/acme' \
  --acme-directory 'https://pki.homelab.lan/acme/directory' \
  --restart
 )
```

The assistant names the deployment `haproxy`, so the file is `/etc/ssl/myownpki/haproxy/haproxy.pem`. By hand
you name the deployment, and the file follows: `deployment add www --recipe haproxy …` writes
`/etc/ssl/myownpki/haproxy/www.pem`, and a second deployment `api` writes `api.pem` next to it. Both
are one reload group. The recipe **never edits `haproxy.cfg`**; point a `bind` line at the file, or at the
directory to take every file in it:

```text
bind :443 ssl crt /etc/ssl/myownpki/haproxy/www.pem
bind :443 ssl crt /etc/ssl/myownpki/haproxy/
```

A `crt-list` is your own file. The file is owned by root:root with mode `0600`, because the key is in it.

**The test hook names one configuration file.** `haproxy -c -f /etc/haproxy/haproxy.cfg` checks that file
only. When the service reads more (for example `-f /etc/haproxy/conf.d`), give the deployment a test hook
of your own with `--hook` and `--test-hook`; the recipe cannot know. The check parses the configuration
and loads the certificate files; it is expected to bind no port, so the recipe adds no sandbox directory
and no low-ports entry.

**What to verify** (on a test host):

- `haproxy -c -f /etc/haproxy/haproxy.cfg` refuses a broken file. The project's CI asks the real HAProxy
  this and records the answer in the job summary; the recipe's notes say *verify* until it is written down.
- With `crt` set to the **directory**, HAProxy ignores the agent's temporary `.myownpki-*` file while it
  is being written. This is also something CI asks and records. An agent that is killed during a write
  leaves such a file behind; the agent removes leftovers of its own naming scheme when it starts, and
  you can look for them with `ls -a /etc/ssl/myownpki/haproxy`.
- Two deployments (two names) both serve their own certificate after a reload, with the directory form
  and with one `crt` per file.
- `systemctl show myownpki-agent -p ReadWritePaths` shows no log directory for HAProxy, and
  `journalctl -u myownpki-agent` has no `Read-only file system` from the hooks.
- The local check connects to `127.0.0.1:443` with the first name as SNI. With `accept-proxy` or a `bind`
  to another address, set `--check HOST:PORT` or delete the `check:` line.

## The combined file

`files.combined` is a target of the **file profile** for services that want the certificate chain and
the private key in one PEM file (HAProxy). It is written as `--combined FILE` or as `combined:` under
`files:` in `agent.yaml`:

```yaml
    files:
      combined: /etc/ssl/myownpki/haproxy/www.pem
```

- The file holds the certificate first, then the chain, then the private key. The key mode of the
  deployment (default `0600`, never rights for others) and its owner and group apply to the whole file,
  never the `0644` of a certificate.
- `combined` is used **alone**. It cannot be combined with `certificate`, `chain`, `fullchain` or `key`,
  and `deployment add` and the configuration check refuse the mix. Like every target it must lie under
  `paths` and may not be the target of another deployment, `state_dir` or `ca_bundle`.
- It is written with one atomic rename, so the certificate and the key never disagree on disk. The
  key is held in memory only while the file is built and is not logged. A failed test hook, a failed
  reload or a failed check restores the previous file; a first installation removes it again.
- **An agent older than 0.3.11 refuses a configuration that contains `combined`** (the parsing is
  strict). Update the agents **first**, then add a HAProxy deployment ([Upgrade]({{ '/upgrade/' | relative_url }})).
- Every other recipe and every host without the key is unaffected.

HAProxy can also read a key from a file next to the certificate (the global option `ssl-load-extra-files`).
The recipe does not use that form, and it was not tried.

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
