---
title: "Rolling out agents with Salt"
description: "Install, enroll and configure the MyOwnPKI agent on Salt minions with the Salt formula: a pillar, one state.apply, an enrollment pass for the roll-out, updates and the checks that show it worked."
permalink: /hosts/salt/
---

This page shows how to roll the agent out to many hosts with the **Salt formula** that ships in the
repository (`deploy/salt/myownpki/`, since v0.3.6). A minion that gets the pillar installs the agent
package after a checksum check, enrolls with an **enrollment pass** and adds its deployments, all from
one `state.apply myownpki`. The page also shows the plain `cmd.run` commands for a first test, and the
checks that tell you it worked.

> **Note:** The formula is tested in CI, but not against your installation. The CI job renders every test
> pillar and applies it with `test=True` under Salt 3008.5. **Not tested:** a real apply that installs the
> package and enrolls an agent against a server, other Salt versions, and the installation of an `rpm`
> package. Run it on **one minion** first, and read the formula before you roll it out: it runs as root on
> every minion that gets the pillar.
{: .note}

* TOC
{:toc}

## What the formula does

On every minion that gets the pillar, in this order:

1. **Package.** It stages the agent package from the Salt file server (or an `https://` URL) in
   `/var/cache/myownpki-agent/`, **checks its SHA-256 against the value from your admin UI** and installs
   it only from that local, verified file. If the hash differs, the run fails and installs nothing.
2. **Root.** It stages the root certificate. `myownpki-agent setup` compares its SHA-256 with the value in
   your pillar and refuses a root that differs.
3. **Pass.** If the pillar has an enrollment pass, it writes it to `/root/myownpki-join-token` (mode
   0600) while the host has no agent certificate.
4. **Enrollment.** It runs `myownpki-agent setup` until the host has its agent certificate
   (`/var/lib/myownpki-agent/agent.crt`). `setup` enables and starts the service when the host is admitted.
   Once the certificate exists, the formula deletes the pass file, also on a host that was approved later.
5. **Deployments.** It runs `deployment add` for each deployment in the pillar that the agent does not
   have yet, and `deployment remove` for each name in `absent`. Or, in the other mode, it renders a
   complete `agent.yaml` from your file and runs `sandbox sync`.
6. **Restart.** If the configuration changed, it runs `systemctl try-restart myownpki-agent`: a running
   agent restarts, a stopped one stays stopped.

The formula **never enables or starts the service itself**. A host that is not admitted yet stays
disabled. Linux with systemd only; `deb` for the Debian family, `rpm` for Red Hat and SUSE families,
`amd64` and `arm64`. The server (`install.sh`, backups) is not managed by it.

How the pieces work is on [Adding hosts]({{ '/hosts/' | relative_url }}); this page only adds Salt.

## Who creates the secret: the enrollment pass

Enrollment can use a secret, but **creating** one (and approving a waiting enrollment) is an action of
the permission `agent.manage`. That needs a **fresh second factor** from a person, and an **API token
never satisfies that**, whatever its role: the API answers a token's attempt to create a join token or a
pass with `403`. So Salt cannot create the secret itself, and there is no "narrow" API token to give it
for that. What it can do is **use** a secret a person made once for the roll-out:

| Pattern | How | Secrets in Salt | Work for a person |
|---|---|---|---|
| **A. Enroll without a secret** | No `enrollment_pass` in the pillar. The host proves it controls its name (http-01) and lands in *Enrollment requests*. | None | Approve each host once in the UI, with the second factor |
| **B. An enrollment pass** | An admin creates a pass in the UI with the second factor. The pillar holds it for the time of the roll-out; the formula writes it to `/root/myownpki-join-token` (mode 0600) and passes `--token-file`. | One pass, bounded by uses, names and time | One pass per roll-out; no click per host |
| **C. One token per host** | A person creates a single-use token for each host (*Agents → Add host*, valid 15 minutes). | A single-use token per host | One token per host with the second factor |

Pattern A is right for a handful of hosts and for replacing a host: nothing secret is in Salt and
nothing can leak. Pattern B is for a fleet. The formula supports A and B (the pass is one pillar key);
pattern C is not a pillar setting, because the token is valid 15 minutes.

An **enrollment pass** admits up to the number of hosts you set (2 to 25, default 10), whose name
matches one of 1 to 5 names or `*.suffix` patterns, for at most 7 days (default 24 hours). It admits a
host only after the **server's http-01 check of that host passed**, in `verified` and in `auto` mode
(never in `manual`), it gives the host **its own name only**, and it refuses a host that already has an
agent. Each enrollment takes one use, also when it then waits in the queue. Details, limits and the
refusal texts are on [Adding hosts]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs).

> **Warning:** A pass admits hosts without a person looking at each one, and in the pillar it lies on
> every minion the pillar targets. A leaked pass admits at most as many more hosts as it has uses left,
> for names that match and only if the server can reach port 80 under that name, for at most its
> validity. Make it short and small (a day, as many uses as you have hosts), keep it in an encrypted
> pillar, target the pillar at the hosts of the roll-out, **remove the pass from the pillar afterwards**,
> and revoke it at once if it leaks. Revoking does not remove the hosts it admitted: they are listed on
> the pass, so you can refuse or disable the ones you do not know.
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
- The **server is updated first** ([Upgrade]({{ '/upgrade/' | relative_url }}#update-the-agents)): the
  server must be at the release you roll out, or newer.
- You have two independent values from the **authenticated admin UI**: the root's SHA-256 (for example
  from *Agents → Add host*) and the SHA-256 of each package you roll out. Do not take them from a
  download or from `checksums.txt` alone, and not from the files you are about to roll out. A viewer API
  token can read both: `GET /api/v1/agent-install`.
- For pattern B: the pass, created by an admin with the second factor under *Agents → Join tokens → New
  enrollment pass*, for example label `salt rollout 2026-11`, names `*.homelab.lan`, 3 uses, 1 hour.

## Install the formula on the Salt master

The formula is a directory, `myownpki/`, and its name matters: the states refer to it. It is not a
release asset; take it from the repository at the tag of the release you install. Either copy it into a
`file_roots` directory of the master (here `/srv/salt/`):

```bash
git clone --depth 1 --branch v{{ site.data.release.version }} https://github.com/Der-Felix/MyOwnPKI.git
```

```bash
cp -r MyOwnPKI/deploy/salt/myownpki /srv/salt/
```

Or let the master fetch it with gitfs (needs `pygit2` or `GitPython` on the master). `root` makes the
repository's `deploy/salt` the root of the file server, and `base` pins the tag:

```yaml
fileserver_backend: [gitfs, roots]
gitfs_remotes:
  - https://github.com/Der-Felix/MyOwnPKI.git:
    - root: deploy/salt
    - base: v{{ site.data.release.version }}
```

Pin a tag and not `main`, so the states do not change under you.

## Stage the root and the packages

Verify the release as described on the [installation page]({{ '/install/' | relative_url }}) and in the
README. Then put the root and the packages where the pillar points (these are the defaults, in the
`files/` directory of the formula):

```text
/srv/salt/myownpki/files/root.pem
/srv/salt/myownpki/files/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
/srv/salt/myownpki/files/myownpki-agent_{{ site.data.release.version }}_linux_arm64.rpm
```

The package comes from the release (or from the agent listener of your server); the root PEM from the
trust page of the public listener. Only the architectures and formats you roll out are needed. The name
is `myownpki-agent_<version>_linux_<arch>.<deb|rpm>`. The formula checks both again on the minion, against
the hashes in your pillar, which you took from the UI.

## The pillar

The pillar path is `myownpki:agent`. Put it in a pillar file, for example `/srv/pillar/myownpki.sls`, and
give it to the hosts of the roll-out only:

```yaml
# /srv/pillar/top.sls
base:
  'minion-01.homelab.lan':
    - myownpki
```

A **minimal pillar** (pattern A: the host waits for one approval; no deployment yet):

```yaml
myownpki:
  agent:
    version: "{{ site.data.release.version }}"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://myownpki/files/root.pem
    root_sha256: "<SHA-256 of the root from the admin UI>"
    package:
      sha256:
        amd64: "<SHA-256 of the amd64 package from the admin UI>"
```

A **full pillar** (pattern B, with a webroot and a deployment). Quote the hashes and `key_mode`: YAML reads
an unquoted `0640` as a number.

```yaml
myownpki:
  agent:
    version: "{{ site.data.release.version }}"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://myownpki/files/root.pem
    root_sha256: "<SHA-256 of the root from the admin UI>"
    package:
      sha256:
        amd64: "<SHA-256 of the amd64 package>"
        arm64: "<SHA-256 of the arm64 package>"
      source: salt://myownpki/files/{name}
      format: auto
    webroot: /var/www/html
    low_ports: false
    enrollment_pass: "<enrollment pass from the admin UI>"
    deployments:
      proxy:
        recipe: nginx
        name: minion-01.homelab.lan
        webroot: /var/www/html
        create_dirs: true
    absent: []
```

The repository has the same file with comments: `deploy/salt/myownpki/pillar.example`. The keys:

| Key | Required | Meaning |
|---|---|---|
| `version` | yes | The release to install, for example `{{ site.data.release.version }}`. Part of the package file name |
| `server` | yes | The agent listener, `https://pki.homelab.lan:8444` (https, no path) |
| `acme_directory` | yes | The ACME directory URL (https); `setup --acme-directory` writes it into a new `agent.yaml` |
| `root_source`, `root_sha256` | yes | `salt://` source of the root PEM and its SHA-256 from the admin UI (64 hexadecimal digits, colons allowed) |
| `package.sha256` | yes | Map `amd64` / `arm64` to the SHA-256 of the package. The entry for the minion's architecture must exist |
| `package.source` | no | Default `salt://myownpki/files/{name}`. `{name}` is the package file name. An `https://` URL is allowed because the hash is checked |
| `package.format` | no | `auto` (default: `deb` for the Debian family, `rpm` for Red Hat and SUSE), `deb` or `rpm` |
| `webroot` | no | An existing directory for the enrollment check (http-01). Unset: standalone on port 80 |
| `low_ports` | no | `true` passes `--low-ports` to `setup`, needed when nginx listens on port 443 |
| `enrollment_pass` | no | The pass, as a string. Used only while the host has no agent certificate. Unset: pattern A |
| `config_source` | no | A `salt://` source for a complete `agent.yaml`. Not together with `deployments` or `absent` |
| `deployments` | no | Map of deployment name to options, applied with `deployment add` |
| `absent` | no | List of deployment names to remove with `deployment remove` |

The options of a deployment are the flags of `myownpki-agent deployment add` with `-` written as `_`:
`recipe`, `profile`, `challenge`, `webroot`, `dir`, `certificate`, `chain`, `fullchain`, `key`, `owner`,
`group`, `key_mode`, `test_hook`, `reload_hook`, `check`, `acme_directory` (strings), `name`, `hook`,
`sandbox_write` (a string or a list; the flag is repeated) and `low_ports`, `create_dirs`, `restart`
(`true` or `false`). Leave `restart` unset: the formula restarts the agent itself with `try-restart`,
and `restart: true` would start an agent that still waits for approval. The recipes are on
[Recipes]({{ '/recipes/' | relative_url }}).

**One owner of `agent.yaml`.** Either `deployments` (the formula calls `deployment add`) or `config_source`
(Salt renders the whole file and runs `sandbox sync`). Both together are refused. The agent's state
directory must stay `/var/lib/myownpki-agent`: the formula looks for `agent.crt` there, and a
`config_source` that sets another `state_dir` breaks that check.

## Apply it to one minion

First look at what would happen. `test=True` changes nothing:

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki test=True
```

If the pillar is not usable, the result is one failing state, `myownpki-agent-refused`. `test=True` shows
only a generic text for it; the reason is in the name of the state, which `state.show_highstate` prints
([When the formula refuses](#when-the-formula-refuses-or-fails) below):

```bash
salt 'minion-01.homelab.lan' state.show_highstate
```

Then the first real apply. Use `-t 300`: `setup` waits up to two minutes for the enrollment, and the `salt`
command gives up after five seconds by default.

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki
```

With a pass in the pillar the output of the state `myownpki-agent-setup` ends with
`Agent <id> is enrolled; myownpki-agent is enabled and running.` Check the host:

```bash
salt 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent status'
```

The agent shows its ID and the validity of its certificate, and each deployment with its state. The
agent's page in the UI (*Agents*) shows the deployed certificate, its serial and expiry once it is issued.

### The second apply changes nothing

Run it again:

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki --state-output=changes
```

Every state is already in place, so none reports a change: the package state compares versions, the pass is
written only while `agent.crt` does not exist, `setup` runs only without it, and `deployment add` runs only
when `deployment list` does not show the name. The summary at the end has no `changed=` count. This is the
test that the roll-out is idempotent; do it before you add more minions.

### A host without a pass waits for one approval

Without `enrollment_pass`, `setup` ends with `Enrollment is pending: …` and the service stays disabled. The
run is not an error: the deployments are added to `agent.yaml` anyway, and the formula does not start the
agent. The host is in *Agents → Enrollment requests* with the result of its check. An admin approves it
(second factor). Then **apply again**; that is the whole step:

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki
```

`setup` runs again because there is still no agent certificate, polls the request, and now enables and
starts the service. A scheduled highstate does the same on its next run.

If a pass is in the pillar and the host still waits, the pass did not count: used up, expired, revoked,
not for this name, or the host already has an agent. `setup` prints the reason in the same output; see
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#add-host-passes-and-deployment-add).

### Take the pass out of the pillar afterwards

When the hosts of the roll-out are enrolled, delete `enrollment_pass` from the pillar. A host that still
waits for an approval needs it until it is admitted, so remove it when the last one is done. The formula
writes the pass file only while a host has no agent certificate. `setup` deletes the file when it admits
the host in that run; the state `myownpki-agent-pass-absent` deletes it as soon as the host has its agent
certificate, so a host that waited and was approved later, or whose pass you took out of the pillar while
it waited, is cleaned up by the next apply. A host that still waits keeps the file, because the next
`setup` needs it. To check:

```bash
salt 'minion-*' cmd.run 'test -e /root/myownpki-join-token && echo present || echo absent'
```

If the pass still has uses left, revoke it in the UI (*Agents → Join tokens*, second factor).

## Update the agents

Update the server first ([Upgrade]({{ '/upgrade/' | relative_url }}#update-the-agents)). Then, in the
pillar, change `version` and the `package.sha256` entries to the new release's values (from the admin UI),
and put the new package files on the master. Apply to one minion first:

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki
```

On an enrolled host the formula stages and verifies the new package, installs it, and then runs `setup`
again (the state `myownpki-agent-setup-update`). That is the documented update step: `setup` refreshes
the unit and the systemd drop-ins and restarts the agent, and it keeps your `agent.yaml`. A host that is
not enrolled yet is enrolled as usual.

## Change or remove a deployment

A deployment is added once. If its name already exists in `deployment list`, the formula does nothing for
it, so **changing an option of an existing deployment in the pillar has no effect**. To change one,
put its name in `absent` and apply, then add it back with the new options:

```yaml
    deployments: {}
    absent:
      - proxy
```

Apply (the formula runs `deployment remove proxy`, which keeps `paths` and never touches deployed files):

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki
```

Then put the deployment back into `deployments`, take the name out of `absent`, and apply again. A name
in both lists is refused. With `config_source` you change the file instead: edit `agent.yaml` on the
master and apply; the formula runs `sandbox sync` and restarts the agent when it changed.

## When the formula refuses or fails

The formula **fails closed**: it checks the pillar before it does anything. A pillar it cannot use renders
one failing state, `myownpki-agent-refused`, and nothing is installed. Read the reason with
`state.show_highstate` (above); `state.apply` shows it too. The usual ones:

| Message (shortened) | What to do |
|---|---|
| `missing required pillar key myownpki:agent:<key>` | Set the key. Required: `version`, `server`, `acme_directory`, `root_source`, `root_sha256`, `package:sha256` |
| `unknown pillar key myownpki:agent:<key>` | A typo, or a key the formula does not have. Unknown keys are refused so that a mistake is not silently ignored |
| `missing myownpki:agent:package:sha256:<arch> for this minion` | The pillar has no hash for this minion's architecture (`amd64`, or `arm64` for `aarch64`) |
| `myownpki:agent:package:sha256:<arch> must be 64 hexadecimal digits` | Quote the value; check that it is the SHA-256 and not a file name |
| `cannot derive the package format from os_family …` or `unknown package.format` | Set `package.format` to `deb` or `rpm` |
| `unsupported architecture …` | Only `amd64` and `arm64` packages exist |
| `config_source and deployments/absent are mutually exclusive` | Choose one owner of `agent.yaml` |
| `deployment "<name>": unknown option "<x>"` | Use the flags of `deployment add`, with `_` for `-` (the message lists them) |
| `deployment "<name>": option "key_mode" must be a non-empty string` | Quote it: `"0640"` |
| `deployment "<name>" is in deployments and in absent` | Remove the name from one of them |
| `enrollment_pass must be a string` | Quote the value in the pillar |

Failures at run time:

| What you see | Meaning and fix |
|---|---|
| The state `myownpki-agent-package-verified` fails with `SHA-256 of … does not match package.sha256.<arch>; not installing` | The staged file is not the package the pillar names. Wrong file on the master, a stale file, or a changed one. Compare with the UI, replace the file, apply again. The check runs on every apply, so a file swapped later is caught too. |
| `setup` prints `root certificate SHA-256 mismatch` | `root_sha256` is not the SHA-256 of the DER form of that root. Compare with the UI |
| `setup` prints `Enrollment is pending: …` | Pattern A, or the pass did not count. Approve the host, then apply again |
| `read token file: permissions must be exactly 0600` | Something else changed the file. The formula writes it with mode 0600; check for a conflicting state |
| `command not found` for `myownpki-agent` | Use the absolute path `/usr/local/bin/myownpki-agent` in your own `cmd.run` |
| A second apply shows `setup` running again | The host has no agent certificate yet (still pending), or `state_dir` is not the default |
| Nothing from the pillar arrives on the minion | Check the pillar top file and `salt 'minion-01.homelab.lan' saltutil.refresh_pillar` |

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

Alerts for silent agents and failed deployments are described under
[Monitoring]({{ '/monitoring/' | relative_url }}).

## Try the steps by hand with cmd.run

The formula does what these commands do. Run them on one minion when you want to see each step, or when
you do not use the formula. Two things matter in `cmd.run`:

- **Use the absolute path** `/usr/local/bin/myownpki-agent`. The `PATH` of the minion's root environment
  often has no `/usr/local/bin`, and `salt 'minion-01.homelab.lan' cmd.run 'myownpki-agent status'`
  answers `command not found` although the agent is installed.
- **Raise the timeout** with `-t`. `setup` waits for the enrollment, up to two minutes, and the CLI gives
  up after five seconds by default.

Copy the files to the minion and check the package against the UI value:

```bash
salt 'minion-01.homelab.lan' cp.get_file salt://myownpki/files/root.pem /root/myownpki-root.pem
```

```bash
salt 'minion-01.homelab.lan' cp.get_file salt://myownpki/files/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb /root/myownpki-agent_{{ site.data.release.version }}_linux_amd64.deb
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
salt 'minion-01.homelab.lan' state.single file.managed name=/root/myownpki-join-token contents_pillar=myownpki:agent:enrollment_pass mode=0600 show_changes=False
```

and `setup` gets `--token-file /root/myownpki-join-token`. The agent refuses a token file whose mode is
not exactly 0600, and deletes it after a successful admission; a host that stays pending keeps it. Do
not put the pass on a command line or into a pillar other minions can read.

Then add the deployment on the minion, first as a dry run, and look at the diff:

```bash
salt 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent deployment add proxy --recipe nginx --name minion-01.homelab.lan --webroot /var/www/html --create-dirs --dry-run'
```

```bash
salt 'minion-01.homelab.lan' cmd.run '/usr/local/bin/myownpki-agent deployment add proxy --recipe nginx --name minion-01.homelab.lan --webroot /var/www/html --create-dirs --restart'
```

If something does not work, start with
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#agents-and-enrollment): `command not found`,
an expired or used-up pass, a silent agent and `permission denied` writing certificates are the usual
four.
