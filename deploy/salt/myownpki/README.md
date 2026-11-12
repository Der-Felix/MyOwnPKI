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
4. runs `myownpki-agent setup` until that certificate exists;
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
| string | `recipe`, `profile`, `challenge`, `webroot`, `dir`, `certificate`, `chain`, `fullchain`, `key`, `owner`, `group`, `key_mode`, `test_hook`, `reload_hook`, `check`, `acme_directory` |
| string or list of strings (flag repeated) | `name`, `hook` (`NAME=/abs/command args`), `sandbox_write` |
| `true` / `false` | `low_ports`, `create_dirs`, `restart` |

`dry_run` and `config` are not options. Quote values such as `key_mode: "0640"`: YAML reads an
unquoted `0640` as a number. Leave `restart` unset: the formula runs `systemctl try-restart` when a
deployment changed, which restarts a running agent and never starts a stopped one (`restart: true`
would start an agent that still waits for approval).

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
and remove it afterwards. `setup` deletes the file when the host is admitted; a host that waits
keeps it. A pass admits hosts without a person looking at each one: make it small and short-lived
(see the page above).

**Fail closed.** The pillar is checked before anything happens. If it is not usable, the render
produces one failing state, `myownpki-agent-refused`, and nothing is installed. The reason is in
the name of the state: `state.apply` shows it, `test=True` shows only a generic text, so read it
with `salt-call state.show_highstate`. Refused: a missing required key; a missing hash for the
minion's architecture or an unsupported architecture; `enrollment_pass` that is not a string; an
unknown `package.format` or an `os_family` that `auto` cannot map; `config_source` together with
`deployments` or `absent`; an unknown deployment option or a value of the wrong type; a name in
both `deployments` and `absent`; an unknown key (a typo) anywhere in the pillar.

**Updating the agent.** Update the server first. Then change `version` and `package.sha256` (and
stage the new package). On enrolled hosts the formula installs the package and runs `setup` again;
a host that is not enrolled yet is enrolled as usual.

## Tested, and not tested

`scripts/ci/salt-test.sh` runs in the CI job `salt formula` against **Salt 3008.5** (LTS, onedir
for Linux x86_64, Apache-2.0). It renders every pillar in `deploy/salt/test/cases` with
`state.show_highstate` (Debian amd64 with a pass and deployments, RedHat arm64 with
`config_source`, a minimal pillar, an `https://` package source, and every refusal), checks which
states exist and which do not, checks that the pass appears nowhere in the output, and runs
`state.apply test=True` for the cases that a Debian runner can apply. `bash scripts/ci/salt-test.sh
--self-test` runs the checks that need no Salt (fixture hashes, YAML, example names).

Not tested: other Salt versions, a real `state.apply` (no package is installed, no agent is
enrolled), `pkg.installed` for rpm (the runner has no `rpm`), and anything against a real server.
The live test on a minion is the owner's.
