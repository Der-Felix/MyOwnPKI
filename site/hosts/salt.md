---
title: "Rolling out agents with Salt"
description: "Install and enroll the MyOwnPKI agent on Salt minions with plain Salt commands and a state file you adapt, until the Salt formula ships."
permalink: /hosts/salt/
---

This page shows how to roll the agent out to many hosts with **plain Salt**: `cmd.run` for a first
test, a state file for the fleet, and the checks that tell you it worked. It is written for
Salt, but the steps are the same for any tool that runs commands as root on a host.

> **Note:** A **Salt formula** for this is planned for v0.3.6 (`deploy/salt/` in the repository). It
> will install the agent with a checksum check, render `agent.yaml` from pillar and run the
> enrollment. Everything below is an **example to adapt**, written with the commands the
> product has today. Nothing here is a released formula, and the sketch has not been run against your
> Salt version: try it on one minion first.
{: .note}

* TOC
{:toc}

## What the agent needs from a configuration tool

On every host, as root, in this order:

1. install the agent package, after a check against a hash you got independently;
2. place the root certificate and, optionally, a customized `agent.yaml`;
3. run `myownpki-agent setup`, which enrolls the host and then enables and starts the service;
4. keep `agent.yaml` and the `10-paths.conf` drop-in in step when you change them.

How the pieces work is on [Adding hosts]({{ '/hosts/' | relative_url }}); this page only adds Salt.

## The limit of v0.3.4: who creates the join token

Enrollment can use a **join token**, but creating one (and approving a waiting enrollment) is an
action of the permission `agent.manage`. That permission needs a **fresh second factor** from a
person, and an **API token never satisfies that**: the API answers a token's attempt to create a join
token with `403`. So with v0.3.4 a script or Salt cannot create join tokens by itself. An automation
path for this, with a documented least-privilege API token, is planned for v0.3.5.

That leaves two patterns that work today:

| Pattern | How | Secrets in Salt | Work for a person |
|---|---|---|---|
| **A. Enroll without a token** (the one used below) | Salt runs `setup` without `--token-file`. The host proves it controls its name (http-01) and lands in *Enrollment requests*. | None | Approve each host once in the UI, with the second factor |
| **B. One token per host** | A person creates a token for each host in the UI (*Agents → Install agent*, valid 15 minutes; or *Agents → Join tokens*, valid as long as you choose). Salt puts it into `/root/myownpki-join-token` with mode 0600 and passes `--token-file`. | A single-use token per host, short-lived | Create one token per host with the second factor; no approval needed in the default mode |

Join tokens are single-use, also when the name is a pattern such as `*.homelab.lan`: one token enrolls
one host. Pattern A needs one approval per host, pattern B one token per host, so for a fleet pattern A is
simpler and keeps the secrets out of Salt. A tenant in `auto` enrollment mode admits a host whose check
passed without any approval, but that is a weaker setting (switching to it needs the second factor and
cannot be scripted with an API token); see
[Adding hosts]({{ '/hosts/' | relative_url }}#admission-token-check-approval).

## Preconditions

- The server side is ready: the agent listener, an agent CA, ACME with a domain that covers the host
  names, and port 8444 open ([Adding hosts]({{ '/hosts/' | relative_url }}#what-the-server-needs-first)).
- Each minion's FQDN, for example `minion-01.homelab.lan`, resolves to the host (also from the server,
  with `acme.resolver`), and the **server can reach port 80 of the host**. The enrollment check is the
  server fetching a file from there.
- You have two independent values from the **authenticated admin UI**: the root's SHA-256 (for example
  from *Agents → Install agent*) and the SHA-256 of the package you roll out. Do not take them from a
  download or from `checksums.txt` alone.

## On the Salt master: stage the files once

Verify the release as described on the [installation page]({{ '/install/' | relative_url }}) and in the
README, then put the package and the root into the file server, for example `/srv/salt/myownpki/`:

```text
/srv/salt/myownpki/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
/srv/salt/myownpki/root.pem
```

The `.deb` comes from the release (or from the agent listener of your server); the root PEM from the
trust page of the public listener. Compare the SHA-256 of both with the UI before you use them.

## Try it with cmd.run on one minion

A good first run, with the commands visible. Two things matter in `cmd.run`:

- **Use the absolute path** `/usr/local/bin/myownpki-agent`. The `PATH` of the minion's root environment
  often has no `/usr/local/bin`, and `salt 'minion-01.homelab.lan' cmd.run 'myownpki-agent status'`
  answers `command not found` although the agent is installed.
- **Raise the timeout** with `-t`. `setup` waits for the enrollment, up to two minutes, and the CLI gives
  up after five seconds by default.

Copy the files to the minion and check the package against the UI value:

```bash
salt 'minion-01.homelab.lan' cp.get_file salt://myownpki/root.pem /root/myownpki-root.pem
```

```bash
salt 'minion-01.homelab.lan' cp.get_file salt://myownpki/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
```

```bash
salt 'minion-01.homelab.lan' cmd.run "printf '%s  %s\n' '<package SHA-256 from the UI>' /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb | sha256sum --check -"
```

Install it and enroll (pattern A):

```bash
salt 'minion-01.homelab.lan' cmd.run 'apt-get install -y /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb'
```

```bash
salt -t 180 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 --ca-bundle /root/myownpki-root.pem --root-sha256 <root SHA-256 from the UI> --package-format deb --webroot /var/www/html'
```

Without `--webroot`, `setup` uses standalone http-01 on port 80 and installs the low-ports drop-in. If the
host runs nginx, use the webroot form, and pass `--low-ports` when nginx listens on port 443 (see
[ports below 1024]({{ '/hosts/' | relative_url }}#ports-below-1024)).

`setup` talks to your PKI server directly and ignores `HTTPS_PROXY`, so it needs no proxy. Downloads
from outside, such as the release from GitHub or a package mirror, may need one. `cmd.run` does not read
your shell's variables, so give the proxy through the `env` argument:

```bash
salt 'minion-01.homelab.lan' cmd.run 'apt-get update' env='{"http_proxy": "http://proxy.homelab.lan:3128", "https_proxy": "http://proxy.homelab.lan:3128"}'
```

Pattern A ends with *Enrollment is pending* and a disabled service. Approve the host under *Agents →
Enrollment requests* in the UI. Then run the same `setup` command again: it polls the request,
enables and starts the service. For pattern B, the token file must exist first:

```bash
salt 'minion-01.homelab.lan' state.single file.managed name=/root/myownpki-join-token source=salt://myownpki/tokens/minion-01.homelab.lan mode=0600 show_changes=False
```

and `setup` gets `--token-file /root/myownpki-join-token`. Do not put the token on a command line or
into a Salt pillar that other minions can read; the agent refuses a token file whose mode is not exactly
0600, and deletes it after a successful admission. A token in the master's file server stays there, so
delete it after use.

## The state file for the fleet

This sketch does the whole job idempotently. **It is an example to adapt**: names, hashes and
paths are placeholders, it has no Jinja on purpose, and `unless` and `creates` make it safe to run on
every highstate.

```yaml
# /srv/salt/myownpki/agent.sls
# EXAMPLE - adapt it. This is not the formula planned for v0.3.6.
# Fill in the values in <angle brackets> from the admin UI.

myownpki-agent-package:
  file.managed:
    - name: /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
    - source: salt://myownpki/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
    - source_hash: sha256=<package SHA-256 from the UI>
    - mode: '0600'

myownpki-agent-installed:
  cmd.run:
    - name: apt-get install -y /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
    - unless: |
        test "$(/usr/local/bin/myownpki-agent --version | awk '{print $2}')" = {{ site.data.release.version }}
    - require:
      - file: myownpki-agent-package

myownpki-agent-root:
  file.managed:
    - name: /root/myownpki-root.pem
    - source: salt://myownpki/root.pem
    - mode: '0600'

# Your agent.yaml, with deployments. setup keeps a customized file.
myownpki-agent-config:
  file.managed:
    - name: /etc/myownpki-agent/agent.yaml
    - source: salt://myownpki/agent.yaml
    - mode: '0644'
    - makedirs: True
    - require:
      - cmd: myownpki-agent-installed

# Exactly: the state directory, plus every entry of paths: in agent.yaml,
# and /var/log/nginx when a hook runs nginx.
myownpki-agent-paths:
  file.managed:
    - name: /etc/systemd/system/myownpki-agent.service.d/10-paths.conf
    - contents: |
        [Service]
        ReadWritePaths=/var/lib/myownpki-agent /var/www/html /etc/nginx/myownpki /var/log/nginx
    - makedirs: True
    - mode: '0644'

myownpki-agent-setup:
  cmd.run:
    - name: >-
        /usr/local/bin/myownpki-agent setup
        --server https://pki.homelab.lan:8444
        --ca-bundle /root/myownpki-root.pem
        --root-sha256 <root SHA-256 from the UI>
        --package-format deb
        --webroot /var/www/html
        --low-ports
    - creates: /var/lib/myownpki-agent/agent.crt
    - timeout: 180
    - require:
      - file: myownpki-agent-root
      - file: myownpki-agent-config
      - file: myownpki-agent-paths

# After a change of agent.yaml or the drop-in on an enrolled host.
myownpki-agent-restart:
  cmd.run:
    - name: systemctl daemon-reload && systemctl try-restart myownpki-agent
    - onchanges:
      - file: myownpki-agent-config
      - file: myownpki-agent-paths
```

How it behaves:

- `salt://myownpki/agent.yaml` is your own file with the host's `hostname`, `deployments` and `paths`
  (see [agent.yaml]({{ '/hosts/' | relative_url }}#agentyaml)); it needs one file per host, or a
  template if you use one. `setup` keeps it and writes the drop-in for the paths it contains.
- The `creates:` line makes `setup` run until the host has its agent certificate. On pattern A the
  first run ends with a pending enrollment; the next highstate after the approval polls it again,
  enables the service and starts it. There is deliberately **no `service.running`** state: a service
  that is not enrolled yet must stay disabled, and `setup` enables it on admission.
- The `unless:` line compares the installed version, so a new release is installed by changing the
  version in the state, the staged package and the hash together. Update the server first
  ([Upgrade]({{ '/upgrade/' | relative_url }}#update-the-agents)).
- arm64 hosts need the arm64 package; use a second state or a grain-based target.
- Apply it on one minion first: `salt -t 300 'minion-01.homelab.lan' state.apply myownpki.agent`.

## Check the fleet

From the master. The `minion-*` target is an example; use your own:

```bash
salt 'minion-*' cmd.run '/usr/local/bin/myownpki-agent --version'
```

```bash
salt 'minion-*' cmd.run '/usr/local/bin/myownpki-agent config check'
```

```bash
salt 'minion-*' cmd.run 'systemctl is-active myownpki-agent'
```

```bash
salt 'minion-*' cmd.run '/usr/local/bin/myownpki-agent status'
```

`status` shows the agent ID and the validity of its certificate once enrolled, `not enrolled` otherwise,
and the state of each deployment, including the last error. From the server's point of view, read the
agent list with a **read-only API token**. Create it in the UI under *My account → New API token* with
the role *viewer* and a short validity (a token ends within one year, and creating one needs a fresh
second factor), then:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/agents
```

Each entry has `hostname`, `status`, `version`, `package_format`, `last_seen_at`, `silent` and the
`deployments` with their `state`, `serial` and `not_after`. A viewer token may also read `GET
/api/v1/agent-enrollments` (the queue of waiting hosts) and `GET /api/v1/alerts`. It cannot approve
anything. Alerts for silent agents and failed deployments are described under
[Monitoring]({{ '/monitoring/' | relative_url }}).

If something does not work, start with
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#agents-and-enrollment): `command not found`,
an expired token, a silent agent and `permission denied` writing certificates are the usual four.
