---
title: "Adding hosts"
description: "Get certificates onto your hosts with ACME clients or with the MyOwnPKI agent: guided installation, packages, agent.yaml, the systemd sandbox, ports and removal."
permalink: /hosts/
---

A host gets its certificate in one of two ways. Either it runs an **ACME client** that talks to the
ACME server of MyOwnPKI, or it runs the **agent**, which uses ACME inside and adds deployment,
reload, rollback and reporting. This page covers both and then the agent in detail. Rolling the
agent out to many machines with Salt is on its own page:
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
([operations guide §10]({{ '/reference/operations/' | relative_url }}#10-acme-server)). The rest of this
page is about the agent.

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

## Guided installation from the web UI

The default way. In the UI choose *Agents → Install agent* and fill in:

- the **exact host name** (an FQDN that resolves to the host and is covered by a domain),
- the Linux architecture (amd64 or arm64),
- the package format (`deb`, `rpm` or tarball),
- how the host answers the enrollment check: **standalone** (the agent listens on port 80 for a
  moment) or **webroot** (a web server already answers port 80 and the agent writes a file into a
  directory it serves).

Confirm with a fresh second factor. The result page shows, once:

- **independent values** from the authenticated UI: the root certificate's SHA-256 and the
  package's SHA-256. These are what you compare against, because the downloaded files cannot vouch
  for themselves;
- an optional **join token**, valid for exactly this host name, **once**, and for **15 minutes**. It
  is shown only on this page. The page gives a here-document that writes it to
  `/root/myownpki-join-token` with mode 0600; the token never goes on a command line;
- the **commands**: download the root over HTTP, check its fingerprint, download the package and
  `checksums.txt` over HTTPS with that root, check the package, install it, and run
  `myownpki-agent setup`.

Run the commands as root **on the target host**, not on the PKI server. If the token has expired or
was used, create the page again; there is no way to show it a second time.

What happens at `setup`: it validates everything before it changes the host, then writes
`/etc/myownpki-agent/agent.yaml` (an existing customized file is kept), the unit
`/etc/systemd/system/myownpki-agent.service` and the drop-in `10-paths.conf` (with `20-low-ports.conf`
for standalone mode), and enrolls **before** it enables or starts anything.

### Admission: token, check, approval

The server admits an agent according to the tenant's enrollment mode (*Administration → Tenant
settings*):

| Mode | Valid join token | Control of the name proven (http-01) | Result |
|---|---|---|---|
| `verified` (default) | yes | yes | admitted |
| `verified` | only one of the two | | waits for an admin |
| `auto` | yes, or the check passed | | admitted |
| `manual` | any | any | waits for an admin |

A token is valid when it is unused, not expired, and its name patterns match the host. A token is
marked used even when the agent then waits in the queue. A **waiting** agent leaves the service
disabled and prints `systemctl enable --now myownpki-agent` for use after approval; an admin approves
it under *Enrollment requests* (fresh second factor), then run `setup` again, which polls the pending
request, or enable the service. The queue shows which of the two proofs failed.

Without a token you can still enroll: the agent lands in *Enrollment requests* and waits. The
alternative flow *Agents → Join tokens → Create token* makes a token for exact names or patterns such
as `*.apps.homelab.lan`, with a validity of your choice; it is still **single-use**. Store its secret
in a file with mode 0600 and never in `agent.yaml` or on a command line.

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
| `--token-file FILE` | A regular file with mode exactly 0600 that holds the join token. Deleted only when this run newly gets admitted. |
| `--package-format` | `deb`, `rpm` or `tarball` (default); recorded and reported so the UI can suggest the right update |
| `--webroot DIR` | An existing directory your web server serves on port 80. Without it, enrollment uses standalone http-01. |
| `--hostname FQDN` | The name to prove. Default: the host's fully qualified name. |
| `--low-ports` | Install the capability drop-in for ports below 1024 even in webroot mode |
| `--config FILE` | Another `agent.yaml` path. Default `$MYOWNPKI_AGENT_CONFIG`, then `/etc/myownpki-agent/agent.yaml`. |

`setup` is safe to run again: an already enrolled host keeps its configuration and the service is
restarted.

## agent.yaml

The file is `/etc/myownpki-agent/agent.yaml`; the state (key, certificate, deployment history) is in
`/var/lib/myownpki-agent` (mode 0700). After every edit:

```bash
myownpki-agent config check
```

```bash
systemctl restart myownpki-agent
```

`config check` names every problem at once. A first file from `setup` has no deployments; you add
them. This one keeps an nginx host up to date:

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
`@system-service` system calls. Only the state directory is writable. Everything else the agent
writes must be listed twice: in `paths` of `agent.yaml` and in the drop-in
`/etc/systemd/system/myownpki-agent.service.d/10-paths.conf`. `setup` writes the drop-in for the
paths it knows. Whenever you add or change `paths`, make the drop-in hold **exactly the state
directory, the web roots and the parent directories of your deployments**, then:

```ini
[Service]
ReadWritePaths=/var/lib/myownpki-agent /var/www/html /etc/nginx/myownpki /var/log/nginx
```

```bash
systemctl daemon-reload
```

```bash
systemctl restart myownpki-agent
```

When a hook runs nginx, add `/var/log/nginx` too, because `nginx -t` opens its log files. If
`nginx -t` says `Read-only file system` for a temporary directory, add that directory (for example
below `/var/cache/nginx` or `/var/lib/nginx`). Never make `/etc`, `/var` or `/` writable.

The sandbox contains mistakes; it is not a boundary against code that runs as root in the agent. The
real protection is that the agent takes **no commands from the server** and runs only hooks from the
root-owned `agent.yaml`.

### Ports below 1024

Standalone mode binds port 80, and the nginx hooks open the listen sockets of nginx (`nginx -t` with a
listener on 443 fails with `bind() … Permission denied` otherwise). Both need the drop-in
`20-low-ports.conf` with `CAP_NET_BIND_SERVICE`, **also in webroot mode** for the nginx hooks.
`setup --low-ports` installs it. It is also in the package examples:

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
