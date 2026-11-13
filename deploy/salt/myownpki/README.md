# Salt formula for the MyOwnPKI agent

This formula installs the MyOwnPKI agent on Linux minions, enrolls them and adds their
deployments, so that `state.apply myownpki` replaces a hand-copied state file. It follows the
rules in `docs/PHASE3.md` section 12; the page for administrators is
[Rolling out agents with Salt](https://der-felix.github.io/MyOwnPKI/hosts/salt/).

It does, in this order, on every minion that gets the pillar:

1. stages the agent package from the file server (or an `https://` URL) into
   `/var/cache/myownpki-agent/` (root-owned, mode 0755: only root can replace a file there),
   **checks its SHA-256 against the value from your admin UI** and only then installs it
   **from that local file** (`pkg.installed` with `sources`);
2. stages the root certificate; `myownpki-agent setup` compares its SHA-256 with `root_sha256` and
   refuses a root that differs;
3. writes the enrollment pass to `/root/myownpki-join-token` (mode 0600) while the host has no
   agent certificate (`/var/lib/myownpki-agent/agent.crt`);
4. runs `myownpki-agent setup` until that certificate exists, then removes the pass file (also
   when the pass left the pillar);
5. adds the deployments with `deployment add` and removes the ones in `absent` with
   `deployment remove`, **or** renders a complete `agent.yaml` (`config_source`) and runs
   `sandbox sync`;
6. runs `systemctl try-restart myownpki-agent` when the configuration changed.

It never uses `service.running` and never enables the unit: `setup` enables and starts the agent
when the host is admitted, a host that still waits for approval stays disabled. A host without a
pass waits for one approval in the UI (*Agents → Enrollment requests*); the next `state.apply`
polls the request and finishes the job.

Linux with systemd only. Packages are `deb` (Debian family) or `rpm` (RedHat and Suse family) for
`amd64` and `arm64`. The server (`install.sh`, backup) is not managed here.

## Install the formula

Copy the directory `myownpki/` (the name matters) into a `file_roots` directory of the Salt
master, for example `/srv/salt/myownpki/`. Or use gitfs, with the tag of the release you install;
`root` makes the repository's `deploy/salt` the root of the file server:

```yaml
fileserver_backend: [gitfs, roots]
gitfs_remotes:
  - https://github.com/Der-Felix/MyOwnPKI.git:
    - root: deploy/salt
    - base: v0.3.6
```

Put the root certificate and the packages where `root_source` and `package.source` point, by
default `/srv/salt/myownpki/files/root.pem` and
`/srv/salt/myownpki/files/myownpki-agent_<version>_linux_<arch>.<deb|rpm>`. Get both, and their
SHA-256, from the **authenticated admin UI** (*Agents → Add host*) or with a viewer API token from
`GET /api/v1/agent-install`. Do not take the hashes from the files you are about to roll out.

Give the pillar to the hosts of the roll-out only (see `pillar.example`) and apply:

```bash
salt -t 300 'minion-01.homelab.lan' state.apply myownpki
```

Use `-t 300`: `setup` waits up to two minutes for the enrollment, and `salt` gives up after five
seconds by default.

## Pillar `myownpki:agent`

Defaults are in `defaults.yaml` and merged with the pillar in `map.jinja`. A value of `null` means
"not set".

| Key | Required | Default | Meaning |
|---|---|---|---|
| `version` | yes | none | The release to install, for example `0.3.6`. Part of the package file name |
| `server` | yes | none | Agent listener, `https://pki.homelab.lan:8444` (https, no path) |
| `acme_directory` | yes | none | ACME directory URL (https); `setup --acme-directory` writes it into a new `agent.yaml` |
| `root_source` | yes | none | `salt://` source of the root certificate (PEM) |
| `root_sha256` | yes | none | SHA-256 of the root from the admin UI, 64 hexadecimal digits (colons allowed); passed to `setup --root-sha256` |
| `package.sha256` | yes | `{}` | Map `amd64` / `arm64` to the SHA-256 of the package. The entry for the minion's architecture must exist (grain `osarch`: `amd64`, `x86_64` -> `amd64`; `arm64`, `aarch64` -> `arm64`) |
| `package.source` | no | `salt://myownpki/files/{name}` | `{name}` is `myownpki-agent_<version>_linux_<arch>.<deb\|rpm>`. `salt://` or `https://` only |
| `package.format` | no | `auto` | `auto` (deb for `os_family` Debian, rpm for RedHat and Suse), `deb` or `rpm` |
| `webroot` | no | unset | Existing directory for the enrollment check (http-01). Unset: standalone on port 80 |
| `low_ports` | no | `false` | `true` passes `--low-ports` to `setup` |
| `enrollment_pass` | no | unset | The pass, a string. Only used while `/var/lib/myownpki-agent/agent.crt` does not exist. An empty string counts as unset |
| `config_source` | no | unset | `salt://` source of a complete `agent.yaml` |
| `deployments` | no | `{}` | Map deployment name -> options, applied with `deployment add` |
| `absent` | no | `[]` | List of deployment names to remove with `deployment remove` |

Deployment names are lower case letters, digits and hyphens, as in `agent.yaml`. The options are
the flags of `myownpki-agent deployment add`, with `-` written as `_`:

| Kind | Options |
|---|---|
| string | `recipe`, `profile`, `challenge`, `webroot`, `dir`, `certificate`, `chain`, `fullchain`, `key`, `owner`, `group`, `key_mode`, `test_hook`, `reload_hook`, `check`, `check_name`, `acme_directory`, `dns_provider`, `dns_type`, `dns_credentials`, `dns_nameserver`, `dns_zone`, `dns_resolver` |
| string or list of strings (flag repeated) | `name`, `hook` (`NAME=/abs/command args`), `sandbox_write` |
| `true` / `false` | `low_ports`, `create_dirs`, `restart` |

`dry_run` and `config` are not options. Quote values such as `key_mode: "0640"`: YAML reads an
unquoted `0640` as a number. Leave `restart` unset: the formula runs `systemctl try-restart` when a
deployment changed, which restarts a running agent and never starts a stopped one (`restart: true`
would start an agent that still waits for approval).

### dns-01 deployments

A deployment with `challenge: dns-01` proves its names through a TXT record instead of port 80. It is
the only way to get a wildcard (`*.homelab.lan`), and it works on a host without port 80. It needs
no `webroot`, and `deployment add` adds no `paths` entry and no low-ports drop-in for it. The
seven options below are the flags `--check-name` and `--dns-*` of `deployment add`:

| Option | Flag | Meaning |
|---|---|---|
| `dns_provider` | `--dns-provider` | Required with dns-01. The name of the provider entry in `dns_providers` of `agent.yaml`, for example `homelab-dns`. Deployments that share a provider repeat the options or name only the provider |
| `dns_type` | `--dns-type` | Defines a new provider entry: `rfc2136` (BIND, Knot, PowerDNS with TSIG) or `cloudflare` |
| `dns_credentials` | `--dns-credentials` | Absolute path of the credentials file, for example `/etc/myownpki-agent/dns/homelab.yaml`. Never under `/home`, `/root` or `/run/user` |
| `dns_nameserver` | `--dns-nameserver` | `rfc2136` only, required: the DNS server that accepts the update, `host` or `host:port` |
| `dns_zone` | `--dns-zone` | `rfc2136` only, optional: the zone to update (default: found by an SOA lookup) |
| `dns_resolver` | `--dns-resolver` | Optional: `IP` or `IP:port` used for SOA, CNAME and propagation queries |
| `check_name` | `--check-name` | The server name (SNI) of the local TLS check; needed when every name is a wildcard and the deployment has a `check` (the nginx recipe has one) |

The provider entry is written once, when its name is new and `dns_type` is given. A repeated
`deployment add` with the same values changes nothing; a **different** definition for an existing name
is refused (`edit agent.yaml by hand`), and so is a change of an existing deployment, as above.
`ttl`, `propagation` and the other settings of a provider are not options: edit `dns_providers` in
`agent.yaml` by hand (then use `absent` and `deployments` or `config_source` for the rest).

```yaml
myownpki:
  agent:
    deployments:
      wild:
        recipe: nginx
        name: ["*.homelab.lan", homelab.lan]
        challenge: dns-01
        check_name: www.homelab.lan
        dns_provider: homelab-dns
        dns_type: rfc2136
        dns_credentials: /etc/myownpki-agent/dns/homelab.yaml
        dns_nameserver: 192.0.2.53
```

The formula renders `--name '*.homelab.lan'` with the quotes a shell needs.

**The credentials file is a secret and the formula does not manage it.** It holds a TSIG key or an API
token, and the agent refuses it unless it is a regular file of mode 0600 or 0400 that root or the agent's
user owns, in a directory that only root writes. Place it with `file.managed` in the host's own state
(a different state file than this formula), with the content from an encrypted pillar:

```yaml
/etc/myownpki-agent/dns:
  file.directory:
    - user: root
    - group: root
    - mode: "0750"
    - makedirs: True

/etc/myownpki-agent/dns/homelab.yaml:
  file.managed:
    - user: root
    - group: root
    - mode: "0600"
    - show_changes: False
    - contents_pillar: homelab_dns:credentials
    - require:
      - file: /etc/myownpki-agent/dns
```

`show_changes: False` keeps the content out of the Salt output. The order does not
matter: Salt may run `deployment add` before the file exists. A missing or wrongly protected file is then
a **warning** on the command's output, never an error, and the agent reads the file when an issuance
starts, so a file that arrives later works at the next renewal without a restart.
`myownpki-agent config check` shows its state (ok, missing, wrong mode, wrong owner) and never its content.

Minimal pillar (the host waits for one approval; no deployment yet):

```yaml
myownpki:
  agent:
    version: "0.3.6"
    server: https://pki.homelab.lan:8444
    acme_directory: https://pki.homelab.lan/acme/directory
    root_source: salt://myownpki/files/root.pem
    root_sha256: "<SHA-256 of the root from the admin UI>"
    package:
      sha256:
        amd64: "<SHA-256 of the amd64 package>"
```

Full example: `pillar.example` (pass, webroot, deployments, `absent`, the alternative `config_source`).

## States

| State ID | What |
|---|---|
| `myownpki-agent-cache` | `/var/cache/myownpki-agent`, root-owned, mode 0755 |
| `myownpki-agent-package-file` | stages the package; for an `https://` source Salt checks `source_hash` |
| `myownpki-agent-package-verified` | fails, with the reason, when the staged file does not match `package.sha256`. Runs on every apply, so a file swapped later is caught |
| `myownpki-agent-package` | `pkg.installed` from the verified local file |
| `myownpki-agent-root` | stages the root certificate |
| `myownpki-agent-pass` | the pass as a file (only with `enrollment_pass`, only until the agent certificate exists) |
| `myownpki-agent-pass-absent` | removes `/root/myownpki-join-token` once the agent certificate exists, with or without `enrollment_pass` in the pillar. Never before: a host that still waits needs the file for the next `setup` |
| `myownpki-agent-config` | `config_source` mode: `/etc/myownpki-agent/agent.yaml` |
| `myownpki-agent-setup-update` | package changed on an enrolled host: `setup` again (refreshes the unit and drop-ins, restarts the agent), as the update instructions say |
| `myownpki-agent-setup` | enrollment; `creates` the agent certificate; timeout 180 seconds |
| `myownpki-agent-deployment-<name>`, `myownpki-agent-deployment-absent-<name>` | `deployment add` / `deployment remove` |
| `myownpki-agent-sandbox` | `config_source` mode: `sandbox sync` when the file changed |
| `myownpki-agent-restart` | `systemctl try-restart myownpki-agent` when the file or a deployment changed |
| `myownpki-agent-refused` | only when the pillar is refused (below); the only state then |

Salt ignores `source_hash` for `salt://` sources, so the formula does not rely on it: the explicit
check in `myownpki-agent-package-verified` is what protects the install, for both kinds of source.

## Rules

**Idempotence.** A second `state.apply` changes nothing: files compare their content, the package
state compares the version of the file with the installed one, the pass is written `unless` the
agent certificate exists, `setup` runs `creates` that certificate, `deployment add` runs `unless`
`deployment list` already shows the name, `deployment remove` runs `onlyif` it does. A **changed
option of an existing deployment is not applied** (the state sees the name and stops): put the
name in `absent`, remove it from `deployments`, apply, then add it again. Or use `config_source`.

**Default state directory.** The pass state and `setup` look for `/var/lib/myownpki-agent/agent.crt`.
A `config_source` that sets another `state_dir` makes those checks look in the wrong place.

**One owner of `agent.yaml`.** Either an admin and `deployment add`, or Salt rendering the whole
file. `config_source` together with `deployments` (or `absent`) is refused.

**Secrets.** The pass is the only secret. It is read from the pillar by Salt
(`contents_pillar`), written with `show_changes: False` and mode 0600, and passed to `setup` as
the file (`--token-file`), never as a value: it is on no command line, in no state name and in no
highstate output. Keep it in an encrypted pillar, target the pillar at the hosts of the roll-out,
and remove it afterwards. `setup` deletes the file only when it admits the host in that very run, so
`myownpki-agent-pass-absent` removes it as soon as the agent certificate exists (a host approved
later, or a pass taken out of the pillar). A host that still waits keeps the file. A pass admits
hosts without a person looking at each one: make it small and short-lived (see the page above).

**Fail closed.** The pillar is checked before anything happens. If it is not usable, the render
produces one failing state, `myownpki-agent-refused`, and nothing is installed. The reason is in
the name of the state: `state.apply` shows it, `test=True` shows only a generic text, so read it
with `salt-call state.show_highstate`. Refused: a missing required key; a missing hash for the
minion's architecture or an unsupported architecture; `enrollment_pass` that is not a string; an
unknown `package.format` or an `os_family` that `auto` cannot map; `config_source` together with
`deployments` or `absent`; an unknown deployment option or a value of the wrong type; `challenge: dns-01` without
`dns_provider` or with `webroot`; a `dns_*` option next to another challenge; a wildcard name without
dns-01; a name in both `deployments` and `absent`; an unknown key (a typo) anywhere in the pillar.

**Updating the agent.** Update the server first. Then change `version` and `package.sha256` (and
stage the new package). On enrolled hosts the formula installs the package and runs `setup` again;
a host that is not enrolled yet is enrolled as usual.

## Tested, and not tested

`scripts/ci/salt-test.sh` runs in the CI job `salt formula` against **Salt 3008.5** (LTS, onedir
for Linux x86_64, Apache-2.0). It renders every pillar in `deploy/salt/test/cases` with
`state.show_highstate` (Debian amd64 with a pass and deployments, Debian amd64 with two dns-01
deployments, RedHat arm64 with `config_source`, a minimal pillar, an `https://` package source, and
every refusal), checks which
states exist and which do not, checks that the pass appears nowhere in the output, and runs
`state.apply test=True` for the cases that a Debian runner can apply. `bash scripts/ci/salt-test.sh
--self-test` runs the checks that need no Salt (fixture hashes, YAML, example names).

Tested live by the maintainer: a real `state.apply` on five enrolled Debian amd64 hosts upgraded the
agent from 0.3.2 to 0.3.5 (package staged and checked, installed from the local file, `setup` run once
by `myownpki-agent-setup-update`, `agent.yaml`, certificate serial and deployments unchanged), and a
second apply changed nothing. Four of the hosts had `20-low-ports.conf` and needed `low_ports: true`.

Not tested live: the enrollment of a new host with an enrollment pass (`--token-file`, the removal of the
pass file, a host that waits for approval), `rpm` hosts, `arm64`, `config_source`, the gitfs install and
other Salt versions. CI does not apply for real either: no package is installed and no agent is enrolled.
