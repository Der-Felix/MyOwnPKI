---
title: "Rolling out agents with Salt"
description: "Install and enroll the MyOwnPKI agent on Salt minions with plain Salt commands, an enrollment pass and a state file you adapt, until the Salt formula ships."
permalink: /hosts/salt/
---

This page shows how to roll the agent out to many hosts with **plain Salt**: `cmd.run` for a first
test, a state file for the fleet that enrolls the hosts with an **enrollment pass**, and the checks that
tell you it worked. It is written for Salt, but the steps are the same for any tool that runs commands
as root on a host.

> **Note:** A **Salt formula** for this is planned for v0.3.6 (`deploy/salt/` in the repository). It
> will install the agent with a checksum check, render `agent.yaml` from pillar and run the
> enrollment, using the pass and the commands described here. Everything below is an **example to
> adapt**, written with the commands the product has today. Nothing here is a released formula, and
> the sketch has not been run against your Salt version: try it on one minion first.
{: .note}

* TOC
{:toc}

## What the agent needs from a configuration tool

On every host, as root, in this order:

1. install the agent package, after a check against a hash you got independently;
2. place the root certificate and the enrollment pass (or nothing, see below);
3. run `myownpki-agent setup`, which enrolls the host and then enables and starts the service;
4. render your `agent.yaml` with the deployments, or run `deployment add`, and let
   `myownpki-agent sandbox sync` bring the systemd drop-ins in step with it.

How the pieces work is on [Adding hosts]({{ '/hosts/' | relative_url }}); this page only adds Salt.

## Who creates the secret: the enrollment pass

Enrollment can use a secret, but **creating** one (and approving a waiting enrollment) is an action of
the permission `agent.manage`. That needs a **fresh second factor** from a person, and an **API token
never satisfies that**, whatever its role: the API answers a token's attempt to create a join token or a
pass with `403`. So Salt cannot create the secret itself, and there is no "narrow" API token to give it
for that. What it can do is **use** a secret a person made once for the roll-out:

| Pattern | How | Secrets in Salt | Work for a person |
|---|---|---|---|
| **A. Enroll without a secret** | Salt runs `setup` without `--token-file`. The host proves it controls its name (http-01) and lands in *Enrollment requests*. | None | Approve each host once in the UI, with the second factor |
| **B. An enrollment pass** (the one used below) | An admin creates a pass in the UI with the second factor. Salt puts it into `/root/myownpki-join-token` (mode 0600) for the time of the roll-out and passes `--token-file`. | One pass, bounded by uses, names and time | One pass per roll-out; no click per host |
| **C. One token per host** | A person creates a single-use token for each host (*Agents → Add host*, valid 15 minutes). | A single-use token per host | One token per host with the second factor |

Pattern A is right for a handful of hosts and for replacing a host: nothing secret is in Salt and
nothing can leak. Pattern B is for a fleet.

An **enrollment pass** admits up to the number of hosts you set (2 to 25, default 10), whose name
matches one of 1 to 5 names or `*.suffix` patterns, for at most 7 days (default 24 hours). It admits a
host only after the **server's http-01 check of that host passed**, in `verified` and in `auto` mode
(never in `manual`), it gives the host **its own name only**, and it refuses a host that already has an
agent. Each enrollment takes one use, also when it then waits in the queue. Details, limits and the
refusal texts are on [Adding hosts]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs).

> **Warning:** A pass admits hosts without a person looking at each one, and in the pillar it lies on
> every minion the pillar targets. A leaked pass admits at most as many more hosts as it has uses left,
> for names that match and only if the server can reach port 80 under that name, for at most its
> validity. Make it short and small (a day, as many uses as you have hosts), target the pillar at the
> hosts of the roll-out, **remove the pass from the pillar afterwards**, and revoke it at once if it
> leaks. Revoking does not remove the hosts it admitted: they are listed on the pass, so you can refuse
> or disable the ones you do not know.
{: .warning}

A tenant in `auto` enrollment mode admits a host whose check passed without any approval, but that is
a weaker setting (switching to it needs the second factor and cannot be scripted with an API token); see
[Adding hosts]({{ '/hosts/' | relative_url }}#admission-token-check-approval).

## Preconditions

- The server side is ready: the agent listener, an agent CA, ACME with a domain that covers the host
  names, and port 8444 open ([Adding hosts]({{ '/hosts/' | relative_url }}#what-the-server-needs-first)).
- Each minion's FQDN, for example `minion-01.homelab.lan`, resolves to the host (also from the server,
  with `acme.resolver`), and the **server can reach port 80 of the host**. The enrollment check is the
  server fetching a file from there.
- You have two independent values from the **authenticated admin UI**: the root's SHA-256 (for example
  from *Agents → Add host*) and the SHA-256 of the package you roll out. Do not take them from a
  download or from `checksums.txt` alone. A viewer API token can read both: `GET /api/v1/agent-install`.
- For pattern B: the pass, created by an admin with the second factor under *Agents → Join tokens → New
  enrollment pass*, for example label `salt rollout 2026-11`, names `*.homelab.lan`, 3 uses, 1 hour.

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
salt -t 180 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 --ca-bundle /root/myownpki-root.pem --root-sha256 <root SHA-256 from the UI> --package-format deb --webroot /var/www/html --acme-directory https://pki.homelab.lan/acme/directory'
```

Without `--webroot`, `setup` uses standalone http-01 on port 80 and installs the low-ports drop-in. If the
host runs nginx, use the webroot form, and pass `--low-ports` when nginx listens on port 443 (see
[ports below 1024]({{ '/hosts/' | relative_url }}#ports-below-1024)). `--acme-directory` goes into the new
`agent.yaml`, so that the first `deployment add` needs no hand edit.

`setup` talks to your PKI server directly and ignores `HTTPS_PROXY`, so it needs no proxy. Downloads
from outside, such as the release from GitHub or a package mirror, may need one. `cmd.run` does not read
your shell's variables, so give the proxy through the `env` argument:

```bash
salt 'minion-01.homelab.lan' cmd.run 'apt-get update' env='{"http_proxy": "http://proxy.homelab.lan:3128", "https_proxy": "http://proxy.homelab.lan:3128"}'
```

Pattern A ends with *Enrollment is pending* and a disabled service. Approve the host under *Agents →
Enrollment requests* in the UI. Then run the same `setup` command again: it polls the request,
enables and starts the service.

**Pattern B** needs the pass in the token file first. For the test, write it from the pillar, not from the
command line (a `cmd.run` argument shows up in the process list and the job cache):

```bash
salt 'minion-01.homelab.lan' state.single file.managed name=/root/myownpki-join-token contents_pillar=myownpki:enrollment_pass mode=0600 show_changes=False
```

and `setup` gets `--token-file /root/myownpki-join-token`. The agent refuses a token file whose mode is
not exactly 0600, and deletes it after a successful admission; a host that stays pending keeps it. Do
not put the pass on a command line or into a pillar other minions can read. Afterwards remove it from
the pillar.

Then add the deployment on the minion, first as a dry run, and look at the diff:

```bash
salt 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent deployment add proxy --recipe nginx --name minion-01.homelab.lan --webroot /var/www/html --create-dirs --dry-run'
```

```bash
salt 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent deployment add proxy --recipe nginx --name minion-01.homelab.lan --webroot /var/www/html --create-dirs --restart'
```

## The state file for the fleet

This sketch does the whole job idempotently with pattern B. **It is an example to adapt**: names,
hashes and paths are placeholders, it has no Jinja on purpose, and `unless`, `onchanges` and `creates`
make it safe to run on every highstate. It follows the rule of **one owner of `agent.yaml`**: Salt
renders the whole file and runs `sandbox sync`; nobody runs `deployment add` on these hosts.

```yaml
# /srv/salt/myownpki/agent.sls
# EXAMPLE - adapt it. This is not the formula planned for v0.3.6.
# Fill in the values in <angle brackets> from the admin UI. The pass comes from
# an encrypted pillar (myownpki:enrollment_pass) that targets only the hosts of
# the roll-out; remove it from the pillar when the roll-out is done.

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

# The pass, only until the host has its agent certificate. setup deletes the
# file when it gets the host admitted.
myownpki-agent-pass:
  file.managed:
    - name: /root/myownpki-join-token
    - contents_pillar: myownpki:enrollment_pass
    - mode: '0600'
    - show_changes: False
    - unless: test -e /var/lib/myownpki-agent/agent.crt

# Your agent.yaml, with deployments and, for nginx hooks, the sandbox block:
#   sandbox:
#     write: [/var/log/nginx]
#     low_ports: true
# setup keeps a customized file.
myownpki-agent-config:
  file.managed:
    - name: /etc/myownpki-agent/agent.yaml
    - source: salt://myownpki/agent.yaml
    - mode: '0644'
    - makedirs: True
    - require:
      - cmd: myownpki-agent-installed

myownpki-agent-setup:
  cmd.run:
    - name: >-
        /usr/local/bin/myownpki-agent setup
        --server https://pki.homelab.lan:8444
        --ca-bundle /root/myownpki-root.pem
        --root-sha256 <root SHA-256 from the UI>
        --package-format deb
        --webroot /var/www/html
        --token-file /root/myownpki-join-token
    - creates: /var/lib/myownpki-agent/agent.crt
    - timeout: 180
    - require:
      - file: myownpki-agent-root
      - file: myownpki-agent-pass
      - file: myownpki-agent-config

# After a change of agent.yaml on an enrolled host: recompute the drop-ins.
myownpki-agent-sandbox:
  cmd.run:
    - name: /usr/local/bin/myownpki-agent sandbox sync
    - onchanges:
      - file: myownpki-agent-config
    - require:
      - cmd: myownpki-agent-setup

myownpki-agent-restart:
  cmd.run:
    - name: systemctl try-restart myownpki-agent
    - onchanges:
      - file: myownpki-agent-config
    - require:
      - cmd: myownpki-agent-sandbox
```

How it behaves:

- `salt://myownpki/agent.yaml` is your own file with the host's `hostname`, `deployments`, `paths`,
  `acme_directory` and the `sandbox:` block (see [agent.yaml]({{ '/hosts/' | relative_url }}#agentyaml));
  it needs one file per host, or a template if you use one. `setup` keeps it and writes the drop-ins
  for what it contains; `sandbox sync` does the same on later changes, keeps entries it cannot explain
  and tells you about them.
- The `creates:` line makes `setup` run until the host has its agent certificate, and the `unless:` of
  the pass state stops writing the pass from then on. On pattern A the first run ends with a pending
  enrollment; the next highstate after the approval polls it again, enables the service and starts it.
  There is deliberately **no `service.running`** state: a service that is not enrolled yet must stay
  disabled, and `setup` enables it on admission.
- A host the pass refuses (used up, expired, not for that name, or it already has an agent) waits in
  the queue and `setup` prints the reason; fix the cause or approve the host in the UI.
- The `unless:` of the package state compares the installed version, so a new release is installed by
  changing the version in the state, the staged package and the hash together. Update the server first
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
and the state of each deployment, including the last error. `config check` also says whether the
drop-ins match `agent.yaml`. From the server's point of view, read the result with a **read-only API
token**. Create it in the UI under *My account → New API token* with the role *viewer* and a short
validity (a token ends within one year, and creating one needs a fresh second factor), then:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/agents?hostname=minion-01.homelab.lan"
```

The `hostname` filter returns the agents of exactly that host name, so a script can ask for one host.
Each entry has `hostname`, `status`, `version`, `package_format`, `last_seen_at`, `silent` and the
`deployments` with their `state`, `serial` and `not_after`. A viewer token may also read
`GET /api/v1/agent-enrollments?hostname=…` (the queue of waiting hosts), `GET /api/v1/agent-join-tokens`
(the pass with its uses and the hosts it admitted, never its secret), `GET /api/v1/agent-install` (the
facts a script needs to install the agent: server URL, ACME directory, the root with its SHA-256 and
the package files with theirs) and `GET /api/v1/alerts`. It cannot create or approve anything.

When the roll-out is done, take the pass out of the pillar and, if it still has uses left, revoke it in
the UI (second factor). Alerts for silent agents and failed deployments are described under
[Monitoring]({{ '/monitoring/' | relative_url }}).

If something does not work, start with
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#agents-and-enrollment): `command not found`,
an expired or used-up pass, a silent agent and `permission denied` writing certificates are the usual
four.
