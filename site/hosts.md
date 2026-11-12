---
title: "Adding hosts"
description: "Get certificates onto your hosts with ACME clients or with the MyOwnPKI agent: the Add host assistant, enrollment passes, deployment add, packages, agent.yaml, the systemd sandbox, ports and removal."
permalink: /hosts/
---

A host gets its certificate in one of two ways. Either it runs an **ACME client** that talks to the
ACME server of MyOwnPKI, or it runs the **agent**, which uses ACME inside and adds deployment,
reload, rollback and reporting. This page covers both and then the agent in detail. Ready-made
settings for nginx, Postfix, Dovecot and Proxmox VE are on [Recipes]({{ '/recipes/' | relative_url }}).
Rolling the agent out to many machines is done with the Salt formula (since v0.3.6); it has its own page:
[Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}).

* TOC
{:toc}

## Which level for which host

| | ACME client (level 1) | Agent (level 3) |
|---|---|---|
| On the host | certbot, acme.sh, lego, Traefik, Caddy, win-acme, cert-manager | `myownpki-agent`, a systemd service (Linux) |
| Who renews | The client, by its own schedule or with ARI | The agent, at two thirds of the lifetime, or on *Renew now* in the UI |
| Deployment and reload | You configure the client | The agent writes the files, tests, reloads, and **rolls back** on failure |
| The server knows | Issuances and renewals | Also what is deployed, the serial, expiry, errors, and whether the host is alive |
| Good for | Hosts that already run an ACME client; other operating systems | Linux hosts with nginx or plain files that should be managed from one place |

Level 1 needs no agent at all: point the client at the ACME directory and trust your root
([operations guide §10]({{ '/reference/operations/' | relative_url }}#10-acme-server)). To have the
server also check what such a host really serves (level 2), enter it as an endpoint: see
[TLS scan]({{ '/tls-scan/' | relative_url }}). The rest of this page is about the agent.

## What the server needs first

The agent needs more than ACME. Check this once on the server
([operations guide §12.1]({{ '/reference/operations/' | relative_url }}#121-agent-ca-and-server)):

1. **ACME works**, and a **domain** (*ACME → Domains*) covers every host name the agent may order,
   for example `homelab.lan`. The same domain is used to prove that a host controls its name when it
   enrolls.
2. **An agent CA:** an intermediate directly below the root with the EKU limit **clientAuth only**,
   named for example `agent-ca`. It signs only the agents' 7-day client certificates. Do not
   create it below an intermediate with `pathlen: 0`.
3. **The agent listener** in `/etc/myownpki/config.yaml`:

   ```yaml
   agent:
     base_url: https://pki.homelab.lan:8444
     listen: ":8444"
     tls_issuer: issuing   # issues the listener's server certificate
     ca: agent-ca          # signs and authenticates agent client certificates
   ```

   Check the file, restart and unseal; the server issues the listener certificate once it is unsealed.
   `config check` and the start verify the agent CA and its EKU limit.
4. **Port 8444/tcp** from the agent hosts to the server is open.
5. **The package files** are available: `install.sh` published them in `/var/lib/myownpki/agent-dist`
   (`agent.package_dir`); the container image has them in `/opt/myownpki/agent-dist`.

## Add host: the guided installation

The default way, from a new host name to a deployed certificate. In the UI choose *Agents → Add host*
(or the button on the agent list) and go through four steps:

1. **Your answers.** The **exact host name** (an FQDN that resolves to the host and is covered by a
   domain), the **service** (nginx, Postfix, Dovecot, Proxmox VE, or *certificate files only*), how the
   host answers the enrollment check, **standalone** (the agent listens on port 80 for a moment) or
   **webroot** (a web server already answers port 80 and the agent writes a file into a directory it
   serves), up to four more certificate names (optional), and the package: `deb`, `rpm`, tarball with
   the architecture, or *already installed*. The Postfix, Dovecot and Proxmox VE choices are marked
   *example recipe*: see [Recipes]({{ '/recipes/' | relative_url }}).
2. **Admission.** The page checks every name against your domains (a name no domain covers, or a
   domain without http-01, is refused), names the tenant's enrollment mode, and lists the ways to get
   the host admitted with the approval each one still needs: a **single-use token** for this host
   (admin and a fresh second factor), **an existing enrollment pass** that covers the host (shown by
   label and uses, never its secret), or **no secret** (one approval in the UI).
3. **Commands, shown once.** The answer is the page with the commands; it is not cached and shows a
   token only now. Run the blocks as root **on the target host**, not on the PKI server:
   the token file (a here-document for a token, a prompt for a pass), the verified root and package
   download, the installation and `myownpki-agent setup`, then `deployment add`, and a last line,
   `myownpki-agent deployment list`.
4. **Progress.** `Add host: <name>` follows the host and reloads itself every 10 seconds: *Host
   enrolled* (waiting for the host, checking, **waiting for your approval** with *Approve* and
   *Refuse* for an admin, admitted), *Agent online* (first report, last seen, silent) and one row per
   deployment (pending, deployed with serial and expiry, failed or rolled back with the agent's last
   error). The page stops reloading when the certificate is deployed.

The result page shows, once, the **independent values** from the authenticated UI: the root
certificate's SHA-256 and the package's SHA-256. These are what you compare against, because the
downloaded files cannot vouch for themselves. The commands download the root over HTTP and check its
fingerprint, download the package and `checksums.txt` over HTTPS with that root, check the package,
install it and run `setup`. A single-use token is valid for exactly this host name (and the extra
names), **once**, for **15 minutes**; it goes to `/root/myownpki-join-token` with mode 0600 and never
on a command line. If it has expired or was used, start the assistant again: there is no way to show
it a second time.

Anyone who can read the PKI (viewer and up) can open the assistant and watch the progress, and can get
the commands for *no secret* or an existing pass. Making a token, and approving or refusing an
enrollment, need an admin with a fresh second factor.

The older page *Agents → Install agent* is still there. It does the same for the install and `setup`
part, without the service and the progress page.

What happens at `setup`: it validates everything before it changes the host, then writes
`/etc/myownpki-agent/agent.yaml` (an existing customized file is kept), the unit
`/etc/systemd/system/myownpki-agent.service` and the drop-in `10-paths.conf` (with `20-low-ports.conf`
for standalone mode), and enrolls **before** it enables or starts anything. `deployment add` then adds
the deployment to `agent.yaml` and the sandbox, and `--restart` restarts the agent so that it asks for the
first certificate.

### Admission: token, check, approval

The server admits an agent according to the tenant's enrollment mode (*Administration → Tenant
settings*):

| Mode | Valid join token | Control of the name proven (http-01) | Result |
|---|---|---|---|
| `verified` (default) | yes | yes | admitted |
| `verified` | only one of the two | | waits for an admin |
| `auto` | yes, or the check passed | | admitted |
| `manual` | any | any | waits for an admin |

An **enrollment pass** (below) is the exception: it admits only together with a passed check, in
`verified` and in `auto`, and never in `manual`.

Changing the mode needs a **fresh second factor**, because `auto` admits a host without a person, and an
API token can never do it. In the UI the form asks for the code and then saves; over the REST API a
`PUT /api/v1/settings` with a different `agent_enrollment` answers `403` (`step-up-required` for a
session without a fresh code, `forbidden` for a token). Saving other settings, or the same mode, needs
no code.

A token is valid when it is unused, not expired, and its name patterns match the host. A token is
marked used even when the agent then waits in the queue. A **waiting** agent leaves the service
disabled and prints `systemctl enable --now myownpki-agent` for use after approval; an admin approves
it under *Enrollment requests* (fresh second factor), then run `setup` again, which polls the pending
request, or enable the service. The queue shows which of the two proofs failed.

Without a token you can still enroll: the agent lands in *Enrollment requests* and waits. The
alternative flow *Agents → Join tokens → Create token* makes a token for exact names or patterns such
as `*.apps.homelab.lan`, with a validity of your choice; it is still **single-use**. Store its secret
in a file with mode 0600 and never in `agent.yaml` or on a command line.

### The enrollment pass for roll-outs

A single-use token enrolls one host, and a person creates it with the second factor. To enroll many
hosts from Salt, Ansible, a script or CI **without anybody opening the UI for each one**, an admin
creates an **enrollment pass** once, in *Agents → Join tokens → New enrollment pass*, again with the
second factor:

| Field | Rule |
|---|---|
| Label | Required: what the pass is for (it is on the list and in the audit log) |
| Host names | 1 to 5, each an exact name or `*.suffix`, each covered by a domain of this PKI |
| Hosts it may admit | 2 to 25 (default 10); a larger fleet takes two passes |
| Valid for | Up to 7 days (default 24 hours) |

The pass is shown **once**; the server keeps only its hash. A host is admitted by a pass only when the
pass is active (not revoked, used up or expired), the host name matches, **the http-01 check passed**
and the host has **no agent yet**. The host gets **its own name only**, not the pattern. Every
enrollment that presents a valid pass takes one use, also when it then waits in the queue. The list
shows `active 3 of 10`, `used up`, `expired` or `revoked`, and the hosts each pass admitted. *Revoke*
ends its use at once; hosts it already admitted stay, listed, for you to refuse or disable.

On the host the pass goes into the token file, exactly like a token, and `setup --token-file` uses it:

```bash
sudo /usr/local/bin/myownpki-agent setup \
  --server https://pki.homelab.lan:8444 \
  --ca-bundle root.pem \
  --root-sha256 AA:BB:CC:... \
  --token-file /root/myownpki-join-token \
  --webroot /var/www/html
```

With Salt you do not run this yourself: the formula keeps the pass in the pillar, writes the token file only
while the host has no agent certificate and calls `setup --token-file` (see
[Rolling out with Salt]({{ '/hosts/salt/' | relative_url }})).

When the pass does not count, the host is not lost: it waits in *Enrollment requests* and `setup` prints
why (see [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#agents-and-enrollment)).

> **Warning:** A pass admits hosts without a person looking at each one. A leaked pass admits at most as
> many more hosts as it has uses left, for names that match, only if the server can reach port 80 under
> that name, for at most its validity. Keep it in an encrypted store, make it short and small, remove it
> after the roll-out and **revoke it at once if it leaks**; then read the list of hosts it admitted and
> refuse or disable the ones you do not know.
{: .warning}

An API token can **never** create or revoke a pass, whatever its role: that takes a person with a fresh
second factor. Give automation a **viewer** token to read the result (`GET /api/v1/agents?hostname=…`,
`GET /api/v1/agent-enrollments?hostname=…`, `GET /api/v1/agent-join-tokens` and
`GET /api/v1/agent-install`), as in [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}).

## Manual installation from a package

Use this when you cannot use the guided page, or when you install by script. Check the downloads
exactly as the guided page does.

```bash
v={{ site.data.release.version }}
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/myownpki-agent_${v}_linux_amd64.deb"
sha256sum --check --ignore-missing checksums.txt
```

Packages exist as `myownpki-agent_<version>_linux_<amd64|arm64>.deb`, `.rpm` and `.tar.gz`. With
[cosign](https://github.com/sigstore/cosign/releases) check `checksums.txt` first, as in the
[README](https://github.com/Der-Felix/MyOwnPKI#verify-a-download). Install the package:

```bash
sudo apt-get install ./myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
```

```bash
sudo dnf install ./myownpki-agent_{{ site.data.release.version }}_linux_amd64.rpm
```

A package puts the binary at `/usr/local/bin/myownpki-agent`, a pristine
`/etc/myownpki-agent/agent.yaml` (kept on upgrades) and unit examples in
`/usr/share/myownpki-agent/examples`. It has **no maintainer scripts** and never enables or starts the
service. For a tarball, verify it, unpack it and install the binary as
`/usr/local/bin/myownpki-agent`. All three formats run the same `setup`.

The root certificate is the independent trust anchor. Get `root.pem` (the trust page of the public
listener, or the guided page), then compare its SHA-256 over the **DER** form with the value in the
admin UI:

```bash
openssl x509 -in root.pem -outform DER | sha256sum
```

Then run `setup` as root. With a web server that already answers port 80, use webroot:

```bash
sudo /usr/local/bin/myownpki-agent setup \
  --server https://pki.homelab.lan:8444 \
  --ca-bundle root.pem \
  --root-sha256 AA:BB:CC:... \
  --package-format deb \
  --token-file /root/myownpki-join-token \
  --webroot /var/www/html
```

| `setup` option | Meaning |
|---|---|
| `--server URL` | The agent listener, `https://host[:port]`, without a path (required) |
| `--ca-bundle FILE` | The root certificate in PEM form. It must be one self-signed CA whose SHA-256 matches `--root-sha256`. |
| `--root-sha256 HEX` | The expected SHA-256 of the root's DER form (required; colons allowed) |
| `--token-file FILE` | A regular file with mode exactly 0600 that holds the join token or the enrollment pass. Deleted only when this run newly gets admitted. |
| `--package-format` | `deb`, `rpm` or `tarball` (default); recorded and reported so the UI can suggest the right update |
| `--webroot DIR` | An existing directory your web server serves on port 80. Without it, enrollment uses standalone http-01. |
| `--hostname FQDN` | The name to prove. Default: the host's fully qualified name. |
| `--acme-directory URL` | The ACME directory, `https://…/acme/directory`. It is written into a **new** `agent.yaml`, so that the first deployment needs no hand edit. An existing file is kept as it is. |
| `--low-ports` | Install the capability drop-in for ports below 1024 even in webroot mode |
| `--config FILE` | Another `agent.yaml` path. Default `$MYOWNPKI_AGENT_CONFIG`, then `/etc/myownpki-agent/agent.yaml`. |

`setup` is safe to run again: an already enrolled host keeps its configuration and the service is
restarted. It also keeps what you added to the systemd drop-ins by hand (see
[The systemd sandbox and paths](#the-systemd-sandbox-and-paths)).

## Adding a deployment: deployment add

`deployment add` writes a deployment into `agent.yaml` **and** makes the systemd sandbox allow what it
needs, in one step. That replaces the two hand edits that used to be required and that showed up only
as `Read-only file system` after the first failed renewal. Run it as root on the host (also with
`--dry-run`); it needs agent v0.3.5. Look at the change first:

```bash
sudo /usr/local/bin/myownpki-agent deployment add proxy --recipe nginx --name minion-01.homelab.lan --webroot /var/www/html --acme-directory https://pki.homelab.lan/acme/directory --create-dirs --dry-run
```

`--dry-run` prints a diff of `agent.yaml` and both drop-ins and writes nothing. Run the same line
without it, then restart the agent (or add `--restart`):

```bash
sudo systemctl restart myownpki-agent
```

| Flag | Meaning |
|---|---|
| `--recipe nginx`, `postfix`, `dovecot` or `proxmox` | Defaults for the service, see [Recipes]({{ '/recipes/' | relative_url }}). Every other flag overrides them. |
| `--name FQDN` (repeat) | Certificate names. Default: the host name of `agent.yaml`. |
| `--profile nginx` or `file`, `--dir DIR`, `--certificate`, `--chain`, `--fullchain`, `--key FILE` | Where the files go: `--dir` for the nginx profile, the file flags for the file profile |
| `--challenge webroot` or `standalone`, `--webroot DIR` | Default: what the enrollment uses |
| `--owner`, `--group`, `--key-mode` | Local ownership and mode of the key (no rights for others) |
| `--hook NAME='CMD ARGS'` (repeat), `--test-hook NAME`, `--reload-hook NAME` | Hooks: no shell, the first element is an absolute path. An identical command line is reused, so deployments of one service share one reload and one rollback group. |
| `--check HOST:PORT` | The local TLS check; implicit TLS only, so a STARTTLS port (25, 143, 587) cannot be checked |
| `--sandbox-write DIR` (repeat), `--low-ports` | Directories the hooks may write (nginx: `/var/log/nginx`), and ports below 1024 for the hooks |
| `--acme-directory URL` | Needed when `agent.yaml` has no `acme_directory` yet |
| `--create-dirs`, `--restart`, `--dry-run`, `--config FILE` | Create missing directories; restart the agent afterwards; show the diff only; another file |

It checks the result with the same rules as `config check` **before** it writes a byte, refuses a
name that exists, and refuses system directories such as `/`, `/etc`, `/var` or `/home` for `--dir`,
`--webroot` and `--sandbox-write` (a wide one such as `/etc/nginx` only gets a warning that names a
narrower directory). It keeps the previous file as `agent.yaml.bak`, keeps your comments, reloads
systemd (`daemon-reload`) and prints the restart command; it never restarts the agent by surprise.

```bash
sudo /usr/local/bin/myownpki-agent deployment list
```

lists name, profile, names, targets, hooks and check (it also runs without root).
`deployment remove NAME` takes a deployment out again and recomputes the drop-ins; it keeps `paths`
unless you pass `--prune-paths`, and it never touches deployed files or the agent's state.

Use **one owner** for `agent.yaml`: either an admin with `deployment add`, or a configuration tool that
renders the whole file and then runs `sandbox sync`. A rendered file overwrites what `add` wrote. The
[Salt formula]({{ '/hosts/salt/' | relative_url }}) offers both and refuses to mix them: the pillar has
either `deployments` (it calls `deployment add`) or `config_source` (it renders the file and runs
`sandbox sync`).

## agent.yaml

The file is `/etc/myownpki-agent/agent.yaml`; the state (key, certificate, deployment history) is in
`/var/lib/myownpki-agent` (mode 0700). After every edit:

```bash
myownpki-agent config check
```

```bash
systemctl restart myownpki-agent
```

`config check` names every problem at once and prints the effective sandbox. A first file from `setup`
has no deployments; you add them with `deployment add` (above) or by hand. This is what an nginx host
looks like after that, and the file `deployment add --recipe nginx` produces is similar:

```yaml
server: "https://pki.homelab.lan:8444"
ca_bundle: "/etc/myownpki-agent/root.pem"
hostname: "minion-01.homelab.lan"
state_dir: "/var/lib/myownpki-agent"
log_level: "info"
acme_directory: "https://pki.homelab.lan/acme/directory"
enrollment:
  challenge: webroot
  webroot: "/var/www/html"
hooks:
  nginx-test: ["/usr/sbin/nginx", "-t"]
  nginx-reload: ["/usr/bin/systemctl", "reload", "nginx"]
paths: ["/var/www/html", "/etc/nginx/myownpki"]
deployments:
  - name: web
    profile: nginx
    names: ["minion-01.homelab.lan"]
    challenge: webroot
    webroot: "/var/www/html"
    dir: "/etc/nginx/myownpki/web"
    test_hook: nginx-test
    reload_hook: nginx-reload
    check: "127.0.0.1:443"
```

The agent writes `fullchain.pem` and `privkey.pem` into `dir`; reference those two files in the
nginx server block.

| Key | Meaning |
|---|---|
| `server`, `ca_bundle`, `hostname` | The agent listener, the root PEM (absolute path), the FQDN proven at enrollment |
| `acme_directory` | The ACME directory URL, `https://…/acme/directory`; required as soon as there is a deployment |
| `proxy` | An `http://` or `https://` proxy for both connections. The agent **ignores** `HTTPS_PROXY` and `HTTP_PROXY`; only this key sets a proxy. |
| `state_dir`, `log_level` | State directory (absolute) and `debug`, `info`, `warn` or `error` |
| `enrollment.challenge` | `standalone` or `webroot` for the enrollment check; `enrollment.webroot` is the directory for `webroot` |
| `hooks` | Named commands. Each is a list; the first element is an absolute path. No shell, no `sudo`. |
| `paths` | The only directories the agent may write to, apart from its state: web roots and the parents of deployment targets |
| `sandbox.write` | Directories that only **hooks** write (nginx: `/var/log/nginx`); they go into the drop-in `10-paths.conf`, not into `paths`. The agent itself does not get them. |
| `sandbox.low_ports` | `true`: install `20-low-ports.conf`; `false`: remove it; unset: install it for any standalone challenge, otherwise leave it as found |
| `deployments[].name` | Lower-case letters, digits and `-`, unique |
| `deployments[].profile` | `nginx` (writes `fullchain.pem` and `privkey.pem` into `dir`) or `file` (explicit target files) |
| `deployments[].names` | 1 to 100 DNS names for the certificate. Each must be covered by the agent's *Names it may order* on the server. |
| `deployments[].challenge`, `webroot` | `standalone` or `webroot` for the ACME http-01 of this certificate; the webroot lies below `paths` |
| `deployments[].files` | For `file`: `key` and `certificate` or `fullchain`, optionally `chain` |
| `deployments[].owner`, `group`, `key_mode` | Local ownership and an octal mode without rights for others (for example `"0600"` or `"0640"`) |
| `deployments[].test_hook`, `reload_hook` | Names from `hooks`: run before the reload (for example `nginx -t`) and the reload itself |
| `deployments[].check` | `host:port` of the local TLS endpoint. After the reload the agent connects with SNI and compares the served certificate with the deployed one. |

For files you manage yourself, use the `file` profile:

```yaml
  - name: web
    profile: file
    names: ["minion-01.homelab.lan"]
    challenge: webroot
    webroot: "/var/www/html"
    files:
      fullchain: "/etc/nginx/myownpki/web.fullchain.pem"
      key: "/etc/nginx/myownpki/web.key"
    key_mode: "0600"
    test_hook: nginx-test
    reload_hook: nginx-reload
    check: "127.0.0.1:443"
```

Deployments that share a non-empty reload hook are staged, tested, reloaded and, on failure, rolled
back **together**. A first-time failure removes the new files. If a rollback itself fails, both errors
are reported and the agent does not retry in a loop.

> **Warning:** A hook must not write secrets to stderr. The last lines of a failed hook's stderr go
> into the agent log and into the deployment's `last_error` on the server, filtered and cut to 1 KiB,
> but still.
{: .warning}

## The systemd sandbox and paths

The unit runs as root, because setting owners and `systemctl reload` need it, but under
`ProtectSystem=strict`, `NoNewPrivileges=yes`, a private `/tmp`, restricted address families and the
`@system-service` system calls. Only the state directory is writable. Everything else must be
allowed twice: in `paths` of `agent.yaml` (what the **agent** may write) and in the drop-in
`/etc/systemd/system/myownpki-agent.service.d/10-paths.conf` (what systemd lets the unit write).

Since v0.3.5 the agent writes that drop-in for you. `setup`, `deployment add`, `deployment remove` and
`sandbox sync` derive it from `agent.yaml`: the state directory, every entry of `paths`, and the
directories of the optional `sandbox.write` list, which are the ones only a **hook** writes (nginx opens
its log files, so `/var/log/nginx`):

```yaml
sandbox:
  write: [/var/log/nginx]
  low_ports: true
```

The drop-in then looks like this, and you do not have to touch it:

```ini
[Service]
ReadWritePaths=/var/lib/myownpki-agent /var/www/html /etc/nginx/myownpki /var/log/nginx
```

What the agent does with a drop-in that already exists:

- An entry it cannot explain from `agent.yaml`, for example a `/var/log/nginx` you added by hand, is
  **kept**, and the command says `Kept in 10-paths.conf (agent.yaml does not explain them): …`.
  `sandbox sync --adopt` writes such entries into `sandbox.write`, so that `agent.yaml` explains them;
  `sandbox sync --prune` removes them from the drop-in.
- An entry that `agent.yaml` needs and the file lacks is appended (`Added to 10-paths.conf: …`).
- A file that already holds everything is not rewritten. A path with white space, quotes or `%` is
  refused before anything is written, because systemd would split or expand it.

```bash
sudo /usr/local/bin/myownpki-agent sandbox sync --dry-run
```

shows what would change in both drop-ins; `sandbox sync` without `--dry-run` writes it, and you then
restart the agent. `config check` prints the effective list and whether the drop-ins on disk match it.
If `nginx -t` says `Read-only file system` for a temporary directory, add that directory with
`--sandbox-write` (for example below `/var/cache/nginx` or `/var/lib/nginx`). Never make `/etc`, `/var`
or `/` writable; the commands refuse it.

If you do edit `10-paths.conf` by hand, run `systemctl daemon-reload` and restart the agent afterwards.
**Updating a host from v0.3.4 or earlier:** run `setup` once (the *Update* commands of the agent page).
It keeps a hand-made `/var/log/nginx` and an installed `20-low-ports.conf`; earlier versions rewrote the
first and removed the second.

The sandbox contains mistakes; it is not a boundary against code that runs as root in the agent. The
real protection is that the agent takes **no commands from the server** and runs only hooks from the
root-owned `agent.yaml`.

### Ports below 1024

Standalone mode binds port 80, and the nginx hooks open the listen sockets of nginx (`nginx -t` with a
listener on 443 fails with `bind() … Permission denied` otherwise). Both need the drop-in
`20-low-ports.conf` with `CAP_NET_BIND_SERVICE`, **also in webroot mode** for the nginx hooks. The
agent installs it when `sandbox.low_ports` is `true`, when the enrollment **or any deployment** uses the
standalone challenge, or when you pass `--low-ports` to `setup` or `deployment add` (the nginx recipe
does). It removes the file only for an explicit `sandbox.low_ports: false`, and it does not overwrite a
file that differs from the packaged one. You can also install it by hand from the package examples:

```bash
sudo install -d -m 0755 /etc/systemd/system/myownpki-agent.service.d
```

```bash
sudo install -m 0644 /usr/share/myownpki-agent/examples/agent-low-ports.conf /etc/systemd/system/myownpki-agent.service.d/20-low-ports.conf
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart myownpki-agent
```

## Ports and firewall

| From | To | Port | Purpose |
|---|---|---|---|
| Agent host | Server | 8444/tcp | The agent channel, mutual TLS |
| Agent host | Server | The ACME HTTPS port (443 or your reverse proxy) | Certificate orders |
| **Server** | **Agent host** | **80/tcp** | **http-01** for enrollment and for every order |

The agent only makes outbound connections; the server never connects to an administrative port on the
agent. But http-01 means the **server** fetches `/.well-known/acme-challenge/…` from port 80 of the
host, so that port must be open from the server to the host, a firewall on the host (nftables, ufw)
included, and the name must resolve to the host from the point of view of the server
(`acme.resolver`). In webroot mode the web server on port 80 must answer the challenge directory; in
standalone mode port 80 is bound only while a check runs.

## Renewal, "Renew now" and what the agent reports

The agent renews at two thirds of the certificate's lifetime, or earlier if the server's ARI window
asks for it. On the agent's page in the UI *Renew now* (operator and admin) wakes the agent through a
bounded long-poll and it runs its normal ACME path, with a new key. Failures back off instead of retrying
continuously.

The agent reports every five minutes (with jitter) and right after each deployment pass: last seen,
version, installed package format, and for each deployment the state (`deployed`, `failed`,
`rolled_back` or `pending`), serial, expiry and last error. An agent is **silent** after three missed
reports. Reports and watches are rate-limited per agent to 60 and 120 calls per 10 minutes, far above
normal use.

> **Note:** After a successful renewal the old certificate is revoked according to the tenant's
> predecessor setting. The default for agent deployments is *immediately after the deployment is
> confirmed*, and for other certificates *after seven days*. A revocation happens only after an
> accepted `deployed` report with proof that the new certificate is the one being served. Review both
> defaults in *Administration → Tenant settings*.
{: .note}

Look at one host:

```bash
myownpki-agent status
```

```bash
journalctl -u myownpki-agent -n 100 --no-pager
```

## Removing a host

- **Disable** (the agent's page) is reversible: the agent is cut off at its next call.
- **Revoke agent** is permanent for that agent ID. Its client certificates go onto the agent CA's CRL.
  **Certificates already deployed stay valid**; revoke those separately, if you mean to.

To enroll the same host as a new agent, create a new join token (or use the guided page), stop the
service and remove the old identity, the ACME account files together, and keep the deployment history:

```bash
sudo systemctl stop myownpki-agent
```

```bash
sudo sh -c 'cd /var/lib/myownpki-agent && rm -f agent.json agent.key agent.crt pending.key enrollment.json acme-*.key acme-*.json'
```

```bash
sudo /usr/local/bin/myownpki-agent enroll --token-file /root/myownpki-join-token
```

```bash
sudo systemctl start myownpki-agent
```

Keep `deployments.json`, `deployment-journal.json`, `deploy-backup-*` and `webroot-files.json`; they hold
deployment history, rollback data and crash cleanup. To uninstall an agent for good, disable and
stop the service, remove the unit and its `.service.d` directory under `/etc/systemd/system`, remove
the package, and delete `/etc/myownpki-agent`, `/var/lib/myownpki-agent` and the certificate files it
deployed. Nothing does this for you.
