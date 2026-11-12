---
title: "Troubleshooting"
description: "Symptom, likely cause, fix: install.sh and updates, sealed server and sign-in, ACME and http-01, agents and enrollment, Add host, enrollment passes and deployment add, the Salt formula, notifications, the TLS scan, containers and config check messages."
permalink: /troubleshooting/
---

Find your symptom in the table of the matching area (use your browser's search, or the contents
below). Every table reads **Symptom → Likely cause → Fix**. The messages are the ones the programs
print; where a message has a variable part, it is shown as `…`.

Two commands answer most questions before you start:

```bash
journalctl -u myownpki -o cat | tail -n 50
```

```bash
journalctl -u myownpki-agent -n 100 --no-pager
```

The server logs JSON (set `log.format: text` to read it on a console). It never logs secrets.

* TOC
{:toc}

## Installation and updates

| Symptom | Likely cause | Fix |
|---|---|---|
| `install.sh: run it as root (sudo bash install.sh)` | Not run as root | Run `sudo bash install.sh …` |
| The download fails (`curl: (6)` or `(7)`) under `sudo` although `curl` works in your shell | Behind a proxy: `sudo` drops `https_proxy` | `sudo --preserve-env=https_proxy,http_proxy,no_proxy bash install.sh …` ([Installation]({{ '/install/' | relative_url }}#behind-a-proxy)) |
| `install.sh: neither curl nor wget found – install one, or use --archive` | A minimal system | Install `curl`, or download the archive elsewhere and use `--archive` with `checksums.txt` next to it |
| `SHA-256 of … does not match checksums.txt – nothing installed` | A damaged or replaced download, or `checksums.txt` of another release | Download again from the release page; do not continue until it matches |
| `the Sigstore signature of checksums.txt is not valid for v… – nothing installed` | cosign is installed and the signature does not match the tag | Check that `--version` and the `checksums.txt` belong to the same release; do not install |
| `the release has no signature bundle – nothing installed` | `checksums.txt.sigstore.json` is missing and cosign is installed | Download the `.sigstore.json` file of the release; with `--archive` put it next to the archive |
| `the new binary does not run here – is … on a noexec mount?` | `/tmp` is mounted `noexec` | `TMPDIR=/var/tmp sudo --preserve-env=TMPDIR bash install.sh …` (or another directory that allows running programs) |
| `… exists but is not owned by myownpki – check it by hand` | The data or backup directory was created by someone else | Fix the owner (`chown -R myownpki:myownpki`) or move the directory away |
| `… has data_dir …; the unit and install.sh use /var/lib/myownpki` | `data_dir` in the existing config is another directory | Change one of them; for another data directory see `StateDirectory=` in [Installation]({{ '/install/' | relative_url }}) and the operations guide §2.1 |
| `… does not pass config check of … – nothing changed` | The new version rejects your configuration | Run the command it names, fix what it lists, run `install.sh` again. Nothing was changed. |
| `backup failed – nothing changed` or `backup verify failed for …` | The pre-update backup does not work (disk full, wrong owner) | Fix the cause first; an update without a backup is refused |
| `rolled back to …, which is healthy again; see journalctl -u myownpki` | The new version did not come up healthy; the old one is back | Read `journalctl -u myownpki`, fix the cause (often the configuration), try again |
| `rolled back to …, but it is not healthy either` | The new version already migrated the databases | Restore the backup it names ([Upgrade]({{ '/upgrade/' | relative_url }}#roll-back)) |
| `the archive has no … – this install.sh needs v0.2.2 or later` | An old archive with the new script | Use the `install.sh` that belongs to the archive's release |
| After an update the UI works but nothing can be issued | The server is sealed after the restart | Unseal in the browser ([below](#server-and-sign-in)) |

## Server and sign-in

| Symptom | Likely cause | Fix |
|---|---|---|
| A banner says the server is sealed; certificate requests are refused; ACME orders stay *processing* | **The server starts sealed** after every restart. It serves CRLs and CA certificates but signs nothing. | An instance admin unseals it: *Unseal* in the banner, or `myownpki serve --unseal` at the terminal. Wrong passphrases are slowed down (three free, then a minute, doubling up to an hour). |
| Clients warn about an expired CRL | The server stayed sealed longer than the CRL lives, so it could not sign a new one | Unseal. A `crl` alert says the same ([Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts)). |
| `crl` alert: the CRL of the **root** expired | A root that is offline cannot renew its CRL; nobody does it automatically | Sign a new CRL on the offline root (with `pki.sh`) and upload it on the root's page, *Upload the root's CRL* ([operations guide §5]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish)). Put the next date in a calendar. |
| The browser cannot connect to port 9443, or the connection is closed before the TLS handshake | `admin.allowed_networks` does not contain your address (it is checked before TLS), or `admin.listen` is `127.0.0.1` | Add your network (keep `127.0.0.1` in the list), restart, unseal |
| The browser warns about the certificate of the admin UI | The bootstrap certificate is self-signed | Compare the fingerprint with the `fingerprint_sha256` value in the log (`journalctl -u myownpki -o cat`), or give the listener a certificate from your CA with `admin.tls_issuer` ([operations guide §2.4]({{ '/reference/operations/' | relative_url }}#24-certificates-the-server-issues-itself-tls_issuer)) |
| The fingerprint of the admin certificate changed unexpectedly | A renewal 30 days before expiry, new names, or something else | Do not sign in until you know why; look for "new admin TLS certificate" in the log |
| A user is locked out (too many wrong passwords) | The lockout | Wait 15 minutes, or an instance admin clicks *Unlock now*, or `myownpki user unlock NAME` |
| A user lost the phone | The authenticator is gone | At the server: `myownpki user reset-2fa NAME` (needs the unseal passphrase or `--recovery-key`) |
| Every user needs a new second factor after a restore | `auth.key` was not in the backup (it lives outside the data directory) | `myownpki user reset-2fa NAME --new-auth-key`, then `reset-2fa` for every other user |
| The passphrase is lost | | `myownpki passphrase reset` with the **recovery key**. If both are lost, the CA keys cannot be recovered: create new CAs ([operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong)). |
| `systemctl start myownpki` fails at once | The configuration is invalid | `sudo -u myownpki /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml` |
| The server refuses to start: unknown `MYOWNPKI_…` variable | A typo or a variable of another version; unknown variables are errors | Remove or correct it; the message lists the known names |
| `myownpki healthcheck` prints `unhealthy: …` | The server is not running, or `127.0.0.1` is not in `admin.allowed_networks`, or the listener serves another certificate than the file | Follow the hint in the message; keep loopback in the allow list |

### `config check` messages

`myownpki config check` lists every problem at once. The common ones:

| Message | Meaning |
|---|---|
| `config file … does not exist (choose one with --config or MYOWNPKI_CONFIG)` | Wrong path. Default `/etc/myownpki/config.yaml` |
| `data_dir: required …` / `data_dir: must be an absolute path, got "…"` | Set an absolute `data_dir` |
| `admin.listen: want IP:port or :port, got "…"` | Write an address such as `0.0.0.0:9443` |
| `admin.tls_cert_file and admin.tls_key_file: set both or neither` | One of the pair is missing |
| `admin.tls_issuer and admin.tls_cert_file: set one of them …` | They exclude each other |
| `admin.tls_issuer needs admin.tls_names: …` | The issued certificate needs the names you type into the browser |
| `public.listen: "…" collides with admin.listen "…"` | Two listeners on one port |
| `admin.allowed_networks: "…" is not an IP or CIDR` / `has host bits set – did you mean …?` | Write networks as `192.0.2.0/24` |
| `auth.passkey_origin: … passkeys need https` / `… need a host name, not an IP address` | Passkeys are bound to a host name |
| `acme.base_url: … must be https:// …` | ACME clients talk TLS only |
| `acme.tls_issuer needs acme.base_url: …` | Set the URL whose host is the name in the certificate |
| `agent.ca and agent.tls_issuer: the agent CA signs only agents' client certificates …` | Name another CA as `agent.tls_issuer` |
| `… needs agent.base_url: without it the agent listener is off` | You set `agent.*` keys without `agent.base_url` |
| `key "dev": dev mode is a command-line flag …` | `serve --dev` is not a config key |
| `Error: notify.email.password_file …: the file does not exist.` / `… can't be read (permission denied) …` | A secret file is missing or the service user cannot read it ([Notifications](#notifications)) |
| `CA root is a root – name the issuing intermediate in admin.tls_issuer …` | A listener certificate must come from an intermediate, not the root |

## ACME and http-01

For http-01 the **server** connects to **port 80 of the host** and fetches a file. Most failures are
on that path. From the PKI server:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://nas.homelab.lan/.well-known/acme-challenge/test
```

A `404` from the host's web server means the route works. A timeout or `Connection refused` is a
firewall, a closed port or a wrong address.

| The client says | Likely cause | Fix |
|---|---|---|
| `connection: … could not be reached` | Port 80 of the host is closed for the PKI server, a host firewall (**nftables**, ufw, firewalld) drops it, or nothing listens | On the host: `ss -ltnp 'sport = :80'` and `nft list ruleset`. Allow tcp/80 from the PKI server. The server log (level info) has the address it tried. |
| The same, but the name does not point at the host | The DNS name does not resolve to the host from the point of view of the **server** (split DNS, a public record) | Set `acme.resolver` to the DNS server that knows your internal names; test with `dig @192.0.2.53 nas.homelab.lan` |
| It works from your laptop, not from the server | A **proxy or load balancer** in front of the host answers port 80 with a redirect or does not pass `/.well-known/acme-challenge/` | The validator follows redirects only to names of the same order and ports 80 and 443. Pass the challenge path through, or use dns-01. |
| `connection: … address policy … refuses` | The name resolves to a range that is never reached (loopback, link-local and others; [full list]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned)), or to a private address on a *public only* domain | Fix DNS, or the domain's address setting |
| `incorrectResponse: … answered with status 404` | The web server does not serve `/.well-known/acme-challenge/` | Use the client's webroot or standalone mode correctly |
| `rejectedIdentifier: no domain covers …` | **The name is not allowed:** no ACME domain covers it, or it is a wildcard on a domain without wildcards | *ACME → Domains*: add the domain, or enable wildcards (dns-01) |
| `unauthorized: account … waits for approval` | The domain's approval level is *approved accounts* | Approve the account (*ACME → Accounts*) or give the client an EAB key |
| `dns: … has no TXT record` | The TXT record went to another zone than the resolver reads | With split DNS use the **internal** zone |
| `rateLimited` | A limit of the tenant settings | Wait for `Retry-After` or raise the limit |
| TLS error, unknown authority | The client does not trust your root | Install the root ([trust page]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page)) or point the client at it (`REQUESTS_CA_BUNDLE`, `LEGO_CA_CERTIFICATES`, `--ca-bundle`) |
| `unauthorized: the ACME server is reachable only through its reverse proxy` (403) | The proxy's address is not in `acme.trusted_proxies` | Add it (with Docker the network, for example `172.16.0.0/12`) |
| A certificate for "MyOwnPKI ACME (bootstrap)" | With `acme.tls_issuer`: the server was not unsealed since the start, or the certificate expired while sealed | Unseal; the next unseal issues the certificate |
| An order stays *processing* | The server is sealed: finalize waits and is issued at the unseal | Unseal |

The full table is
[operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).

## Agents and enrollment

| Symptom | Likely cause | Fix |
|---|---|---|
| `myownpki-agent: command not found`, from `salt … cmd.run`, `sudo` or cron | The program is in `/usr/local/bin`, and root's `PATH` for that caller does not contain it (common with Salt's `cmd.run` and with `sudo` on Red Hat-like systems) | Call it by its **absolute path**: `/usr/local/bin/myownpki-agent …` |
| The enrollment waits: "waiting for an admin to approve it in the web UI (Agents) – …" | No valid join token, or the check failed; the text says which | Approve it in *Enrollment requests*, then run `setup` again (it polls) or `systemctl enable --now myownpki-agent` |
| …"the join token expired" / "the join token was used already" / "unknown join token" / "the join token is not for …" | A guided token is valid **15 minutes**, **once**, and only for the exact host name; the token was already used, or the name differs | Create a new token (*Agents → Add host*, or *Join tokens*) and write the file again. A token is also used up when the agent then waits in the queue. For a pass see [the table below](#add-host-passes-and-deployment-add). |
| `read token file: permissions must be exactly 0600` / `not a regular file` / `token file is empty` | The token file has the wrong mode or content | `chmod 0600` the regular file; a file written by Salt needs `mode: '0600'` (the [Salt formula]({{ '/hosts/salt/' | relative_url }}) writes it that way) |
| `no domain covers … – an admin of the PKI must add one` | The host name is not under an ACME domain | *ACME → Domains*: add or extend the domain |
| `root certificate SHA-256 mismatch: got …` | The value given to `--root-sha256` is not the SHA-256 of the **DER** form of this root | Compare with the authenticated UI: the SHA-256 of `openssl x509 -in root.pem -outform DER`, as `sha256sum` prints it |
| `root file must contain exactly one PEM CERTIFICATE and no trailing data` | `--ca-bundle` holds a chain or extra text | Give only the root certificate |
| `--webroot must name an existing directory` | The directory does not exist | Create it, or use standalone |
| The agent is listed as **silent** in the UI (and an `agent_silent` alert) | Three reports (15 minutes) are missing: the service is down, the host cannot reach `server` on 8444, the agent's proxy is wrong, the clock is far off, or the server's agent listener certificate expired while sealed | On the host: `systemctl status myownpki-agent`, `journalctl -u myownpki-agent -n 100`, `myownpki-agent status`, and test `openssl s_client -connect pki.homelab.lan:8444 -CAfile root.pem </dev/null`. The agent **ignores** `HTTPS_PROXY`; set `proxy:` in `agent.yaml` if it needs one. Check `timedatectl`. |
| TLS or host name errors to the server | `ca_bundle` is not the root of the listener's chain, or `server` is not a DNS name in the listener's certificate, or the listener still has its bootstrap certificate | Compare `ca_bundle` with the root; use the name from `agent.base_url`; unseal the server |
| **`permission denied`** when the agent writes a certificate, a key or a webroot file | The systemd sandbox: the directory is not in `ReadWritePaths` of the unit | Add the directory to `paths` in `agent.yaml` (`deployment add` does it for you), then `myownpki-agent sandbox sync` to bring `10-paths.conf` in step, and restart ([next tables](#deployments-and-nginx)) |
| Standalone: `challenge standalone: port :80 is in use or not allowed (…) – with a web server on port 80 use challenge: webroot` | A web server holds port 80, or the service may not bind a port below 1024 | Use `challenge: webroot`, or stop what holds the port (`ss -ltnp 'sport = :80'`) and install `20-low-ports.conf` (`setup --low-ports`) |
| `myownpki-agent config check` lists problems | See the messages below | Fix them, then restart the service |
| `paths: "…": an absolute path without ..` / `… not under one of paths – the agent writes only there` | A target or webroot is outside `paths` | Add its directory to `paths` |
| `… is not under hooks` / `hooks: …: a command line whose first element is an absolute path` | A deployment names a hook that does not exist, or a hook is not an absolute-path argument list | Define it under `hooks:` like `["/usr/sbin/nginx", "-t"]` |
| `deployments[0].name: lower case letters, digits and '-', e.g. proxy` | Invalid name | Rename |
| `acme_directory: the https URL of the ACME directory …` | Missing with deployments | Set `https://pki.homelab.lan/acme/directory` |
| Name refused when ordering | The agent may order only the names under *Names it may order* | Add the exact name or a `*.suffix` pattern on the agent's page |
| `agent … is revoked – it can't enroll again` | The agent was revoked or disabled | Create a new agent identity ([Adding hosts]({{ '/hosts/' | relative_url }}#removing-a-host)) |
| Rate limited | More than 60 reports or 120 watches per 10 minutes from one agent | Look for a second process or a broken loop on the host |

## Add host, passes and deployment add

Since v0.3.5. The commands print the messages below themselves; the progress page of the *Add host*
assistant shows the stages. See [Adding hosts]({{ '/hosts/' | relative_url }}) for how they work.

| Symptom or message | Likely cause | Fix |
|---|---|---|
| `Kept in 10-paths.conf (agent.yaml does not explain them): /var/log/nginx` | **Not an error.** The drop-in has an entry that `agent.yaml` does not explain, for example one you added by hand. `setup`, `deployment add` and `sandbox sync` keep it. | `myownpki-agent sandbox sync --adopt` records it under `sandbox.write`, so that `agent.yaml` explains it; `--prune` removes it from the drop-in |
| `Added to 10-paths.conf: …` | **Not an error.** The drop-in lacked a directory that `agent.yaml` needs; it was appended. | Restart the agent (`systemctl restart myownpki-agent`) |
| `waiting for an admin to approve it in the web UI (Agents) – the enrollment pass has no uses left (10 of 10) – ask an admin for a new one, …` | The pass is **used up**; every enrollment that presented it took a use, also one that then waited | An admin creates a new pass, or approves this host under *Enrollment requests* |
| … `the pass expired` / `the pass was revoked` | The pass is past its validity (at most 7 days), or an admin revoked it | A new pass, or approve the host in the UI |
| … `the pass is not for minion-01.homelab.lan` | The host name matches none of the names of the pass | Use a pass for that name, or approve the host in the UI |
| … `an agent for minion-01.homelab.lan exists – a pass admits new hosts only; ask an admin for a single-use token` | The host already has an agent (an active or a disabled one), and a pass never replaces a host | An admin creates a single-use token for it (*Agents → Add host*), or approves the request after reading the reason; to start over, revoke the old agent ([Removing a host]({{ '/hosts/' | relative_url }}#removing-a-host)) |
| … `unknown join token` | The secret is not one this server knows: a typo, a token of another server, or one that was withdrawn | Check the file `/root/myownpki-join-token`; create a new one |
| Creating a pass is refused: `names: no domain covers … – an admin of the PKI must add one first (Domains)` | A name of the pass is not under an ACME domain | *ACME → Domains*: add the domain first |
| `403` when a script creates or revokes a pass | **By design:** an API token never satisfies the second factor, whatever its role | An admin does it in the UI; give the script a viewer token that reads |
| Add host: *Host enrolled* stays **waiting for the host** | Nothing has arrived. The commands were not run, ran on the wrong host, or the host cannot reach `server` on 8444. | Run the blocks as root on the host; `journalctl -u myownpki-agent -n 100` and `systemctl status myownpki-agent`; test port 8444 |
| Add host: **checking** for longer than a minute | The server cannot fetch the check file from the host: DNS, port 80, the webroot | [ACME and http-01](#acme-and-http-01); the same path is used |
| Add host: **waiting for your approval** | The host has no valid secret, or the check failed; the row names which, with the source address | An admin with a fresh second factor presses *Approve* if the host is expected, *Refuse* if not |
| Add host: **refused** or **expired** | An admin refused it, or nobody decided in time | Run `setup` on the host again (a new token if the first one was used) |
| Add host: **waiting for the first report** | The agent is admitted but has not reported yet; `deployment add` was not run, or the service is disabled | `systemctl enable --now myownpki-agent`; run the `deployment add` block |
| Add host: **silent** | Three reports are missing | As for a silent agent ([Agents and enrollment](#agents-and-enrollment)) |
| Add host: a deployment is **failed** or **rolled back** | The test or reload hook failed; the row shows the agent's last error | Read the error; [Deployments and nginx](#deployments-and-nginx); fix, then *Renew now* |
| Add host: the page does not reload any more | It stops when the agent is online and every deployment is deployed | Nothing to fix: the certificate is in place |
| `deployment add must run as root; nothing was changed` | Not root (also with `--dry-run`) | `sudo` |
| `agent.yaml is not valid yet – run "myownpki-agent config check" and fix it first; nothing was changed` | The existing file fails the checks of `run` | Fix what `config check` lists, then add the deployment |
| `deployment "nginx" exists – pick another name or run "deployment remove nginx" first` | A deployment of that name is in `agent.yaml` | Choose another name, or remove the old one |
| `--dir /etc: too broad – the agent may write only where "paths" allows; use a subdirectory such as /etc/ssl/myownpki` | `--dir`, `--webroot` or `--sandbox-write` names a system directory (`/`, `/etc`, `/var`, `/home` and others) | Use a subdirectory |
| `/etc/ssl/myownpki does not exist – create it, or pass --create-dirs` | The directory the agent must add to `paths` is missing | `install -d -m 0755 DIR`, or `--create-dirs` |
| `agent.yaml has no acme_directory – pass --acme-directory https://pki.homelab.lan/acme/directory` | A deployment needs an ACME directory and neither the file nor the flag has one | Add `--acme-directory` (or set `acme_directory`) |
| `hook "nginx-test": the first element must be an absolute path` | A `--hook` command such as `nginx -t` | `--hook nginx-test='/usr/sbin/nginx -t'` |
| `agent.yaml uses anchors, aliases or several documents – edit it by hand and run config check` | The editor cannot change such a file without damaging it | Edit the file by hand |
| `The unit is not installed (run setup first) – files written, systemctl skipped.` | **Not an error:** `deployment add` ran before `setup` | Run `setup`; it keeps the file |
| `hint: hook "nginx-test" runs nginx, which writes its log files …` | A hook runs nginx and `sandbox.write` has no log directory | `--sandbox-write /var/log/nginx`, or use `--recipe nginx` |
| A STARTTLS port as `--check` never succeeds | The check is an implicit-TLS handshake | Use an implicit-TLS port (443, 465, 993, 8006) or leave `--check` out |

## Salt formula

Since v0.3.6. The page [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}) has the full list of
refusals and what they mean.

| Symptom or message | Likely cause | Fix |
|---|---|---|
| The only state is `myownpki-agent-refused` (`test=True` shows a generic text) | The formula checked the pillar and cannot use it; it installs nothing then | `salt 'minion-01.homelab.lan' state.show_highstate` prints the reason in the name of the state; fix the pillar |
| `unknown pillar key myownpki:agent:…` | A typo, or a key the formula does not have | Compare with `pillar.example` in `deploy/salt/myownpki/` |
| `config_source and deployments/absent are mutually exclusive` | The pillar sets both owners of `agent.yaml` | Keep `deployments` (and `absent`) or `config_source` |
| `myownpki-agent-package-verified` fails: `SHA-256 of … does not match package.sha256.<arch>; not installing` | The package file on the master is not the one whose hash is in the pillar | Compare with the admin UI, replace the file, apply again. Nothing was installed |
| `setup` prints `Enrollment is pending: …` and the service is disabled | No pass in the pillar, or the pass did not count (the text says why) | An admin approves the host (*Agents → Enrollment requests*); then `state.apply myownpki` again. The formula never starts the service itself |
| A changed option of a deployment has no effect | The formula adds a deployment only when its name is not in `deployment list` | Put the name in `absent`, apply, then add it back with the new options; or use `config_source` |
| `/root/myownpki-join-token` is still on a host that is enrolled | The host waited and was approved later; `setup` deletes the file only when it admits the host in that run | `rm -f /root/myownpki-join-token`; remove `enrollment_pass` from the pillar |
| `agent.crt` checks fail or `setup` runs on every apply | A `config_source` sets a `state_dir` other than `/var/lib/myownpki-agent` | Keep the default state directory |

## Deployments and nginx

| Symptom | Likely cause | Fix |
|---|---|---|
| A deployment shows `rolled_back` or `failed`; `myownpki-agent status` prints `deployment …: rolled_back (…)` | The new certificate was written, but the test or reload hook failed (for example `nginx -t` found an error). The agent **put the old files and certificate back** and reloaded; the service is as before, only the renewal did not happen. `failed` means the step did not finish at all. | Read the error on the agent's page, in `myownpki-agent status` and in `journalctl -u myownpki-agent` (the last stderr lines of the hook are in it). Fix the cause, then *Renew now*. Failures back off instead of retrying in a loop. A `deploy_failed` alert stays open until a report succeeds. |
| `nginx -t` fails with `bind() … Permission denied` on port 443 under the agent | The hooks run inside the sandbox, and `nginx -t` opens the listen sockets | Install the low-ports drop-in (`setup --low-ports`) even in webroot mode |
| `nginx -t` fails with `Read-only file system` | nginx writes to a directory that is not in `ReadWritePaths` (its logs, or temporary directories below `/var/cache/nginx` or `/var/lib/nginx`) | Add `/var/log/nginx` and the directories it names to `sandbox.write` in `agent.yaml` (`deployment add --sandbox-write DIR`, or `--recipe nginx`), run `myownpki-agent sandbox sync` and restart. A hand-made entry in `10-paths.conf` is kept; `sandbox sync --adopt` records it. |
| A new `paths` entry still gives `permission denied` | `paths` was edited by hand and `10-paths.conf` was not brought in step, or `daemon-reload` was not run | `myownpki-agent config check` says whether the drop-ins match; `myownpki-agent sandbox sync` writes them. Then `systemctl restart myownpki-agent`. See what systemd applies with `systemctl show myownpki-agent -p ReadWritePaths`. |
| A hook with `sudo` does nothing | `NoNewPrivileges=yes` | The agent runs as root already; remove `sudo` |
| The renewed certificate is on disk but the site serves the old one | A `check` is set and no reload happened, or nginx does not use the agent's files | Check that the server block points to the `fullchain.pem` and `privkey.pem` in `dir`; look at `check` |

## Notifications

Work from the server outward ([operations guide §13.10]({{ '/reference/operations/' | relative_url }}#1310-when-no-message-arrives)):
Is a channel configured (`config check`)? Can the service user read the files? Does
`myownpki notify test` arrive? Is there an alert to report? Did a delivery fail and get dropped
(search `journalctl -u myownpki -o cat` for `notification`)?

| Symptom or error | Cause and fix |
|---|---|
| No e-mail arrives and `notify test` says it was sent | The problem is behind the server: spam filter, the relay's rules for `from`, a wrong `to`. Look at the mail server's log. |
| `x509: certificate signed by unknown authority` | The mail server's or receiver's certificate is not from a CA the server trusts: set `ca_file` to **this PKI's root** (a PEM file the service user can read) |
| `x509: certificate is valid for …, not …` | The host in `smtp` or `url` is not a name in the certificate; use a name it carries |
| `the server does not offer STARTTLS – set notify.email.security to tls or none` | Wrong `security` for the port: 465 needs `tls`, 25 often `none` |
| `authentication as …: 535 …` | Wrong user or password in the file, or the server wants `LOGIN` or OAuth, which is not supported (use a relay) |
| `MAIL FROM: 550 …`, `RCPT TO …: 550 …` | The relay refuses the sender or a recipient: allow the server's address, check `from` and `to` |
| `connection refused`, `i/o timeout`, `no such host` | Name resolution or firewall from the server to the mail server or receiver. E-mail **ignores the proxy**. |
| `secret file: … permission denied`, `Error: notify….: the file can't be read (permission denied)` | The service user cannot read the file. `sudo install -m 0640 -o root -g myownpki …`, and check as the service user: `sudo -u myownpki cat FILE >/dev/null` |
| `config check` passes as root but fails for the service | Run it as the service user: `sudo -u myownpki /usr/local/bin/myownpki config check …` |
| Webhook: `answered 401` or `403` | **The receiver rejects the signature:** another secret, a body that was parsed and written out again before hashing, or `sha256=` left out when comparing. Hash the **raw body** with the text of the secret file as key. |
| Webhook: `answered 404` or `5xx` | Wrong path, or the receiver fails |
| Webhook: `answered 301` or `302` | Redirects are not followed: use the final URL |
| `proxyconnect` or `Forbidden` from a proxy (webhook) | `HTTPS_PROXY` points to a proxy that refuses the destination, or `NO_PROXY` should list it. The variables are read when the server starts. |
| Messages stop after a change of channel | The server was restarted and is sealed again; the checks run while sealed, but unseal anyway |
| `notification dropped after the last retry – the alerts are still on the dashboard` in the log | Five delivery attempts failed over about two and a half hours. Fix the channel; open alerts come again at the next reminder, a dropped *resolved* message is lost. |

## TLS scan

Start with the *Last error* column of the *Endpoints* page (or `last_error_kind` in the API); it is
always one of the words below. Then try the same from the server
([operations guide §14.10]({{ '/reference/operations/' | relative_url }}#1410-when-something-does-not-work)):

```bash
openssl s_client -connect proxy.homelab.lan:443 -servername proxy.homelab.lan </dev/null
```

| Symptom or error | Likely cause | Fix |
|---|---|---|
| `dns` | The name does not resolve from the server, or has no address | `getent hosts NAME` on the server. With split DNS set `acme.resolver` to the server that knows the name. |
| `timed out` | Nothing answered within `scan_timeout`: the host is down, or a firewall drops the packets | Check route and firewall from the server to the host and port. Raise `scan_timeout` (up to 30 s) only if the host really is slow. |
| `connection refused` | The host answers and nothing listens on that port | Start the service, or correct the port |
| `could not connect` | Another network failure: no route, network unreachable, a reset | The same checks as for a timeout; `log.level: debug` names the address that failed |
| `TLS handshake failed` | The port is not TLS from the first byte (plain HTTP, SSH, a STARTTLS port), or the service speaks only TLS 1.0 or 1.1, or no cipher suite matches | `openssl s_client` shows which. A STARTTLS service cannot be scanned: remove the endpoint. Enable TLS 1.2 on the service. |
| `no certificate` | The handshake worked, but the server presented none | Rare (anonymous or pre-shared keys); the scan cannot judge such a service |
| `client certificate required` | The service demands a client certificate and the scan presents none | The endpoint cannot be scanned and raises no alert: remove it, or scan a listener without client authentication |
| `refused by the address policy` | Every address of the name is in a range that is never scanned, or private on a *public only* domain | Look at what the name resolves to; correct DNS or the domain's address setting |
| `no domain covers the host` | The domain was removed or narrowed after the endpoint was added | Restore the domain or remove the endpoint |
| `port is not in monitor.scan_ports` | The port list was changed after the endpoint was added | Put the port back (restart) or remove the endpoint |
| Adding is refused: `no domain covers this host` | No domain matches the host | Create a domain for it, or let an existing one include subdomains |
| Adding is refused: `port … is not in the list of scannable ports` | The port is not in `monitor.scan_ports` | Use a listed port, or extend the list in `config.yaml` and restart |
| Adding is refused: `this address range is never scanned` | The IP address is loopback, link-local, multicast, reserved, an IPv6 form that embeds or translates to an IPv4 address, or in a non-global range ([full list]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned)) | Use the host's name or another address |
| *Scan now* is missing, or answers `409` | `monitor.scan_interval: off` | Set an interval and restart |
| *Scan now* answers `429` | One request per endpoint and 60 seconds | Wait for the time in `Retry-After` |
| *Not issued by this PKI*, but the name has a certificate here | The endpoint is an IP address without an SNI, or the certificate names something else | Add the endpoint again with the SNI |
| *Wrong certificate* right after a renewal, but no alert | The state shows at once; the alert waits for two scans and `scan_mismatch_after` (1 hour) | Reload the service on the host, then *Scan now* |
| *Expired*, no newer certificate was issued | The host serves a certificate of this PKI that has ended, and nothing newer exists for the name | Issue a new certificate and deploy it |
| `404` or *gone already* for *Scan now* or *Remove* of an endpoint that exists | The endpoint ID in the request is not well-formed (1 to 64 letters, digits, `_` or `-`). A caller without the role gets 403 first | Use the page's buttons or the `id` from `GET /api/v1/endpoints` |
| The state stays *Pending* | The first scans failed fewer than `scan_unreachable_after` times, or scanning is off | Read *Last error* |

## Containers

| Symptom | Likely cause | Fix |
|---|---|---|
| Permission denied on `/var/lib/myownpki` in the container, or the container exits at start | A **bind-mounted** data directory is not owned by UID 65532 (a named volume takes the image's owner) | `sudo install -d -m 0700 -o 65532 -g 65532 ./data`, or use the named volume. The same for `./backup`. |
| The container is `unhealthy` | `myownpki healthcheck` fails: the server is not up yet (start period 30 s), `127.0.0.1` is not in `admin.allowed_networks`, or the configuration is invalid | `docker compose logs myownpki`; `docker compose exec myownpki /usr/local/bin/myownpki healthcheck` prints the reason. Keep `127.0.0.1` in `admin.allowed_networks`. A **sealed** server is healthy. |
| The container exits at start with an `unknown environment variable` error | A typo, or a variable the image's version does not know | Fix or remove it |
| Cannot reach the UI from another machine | The port is published on `127.0.0.1` only | Publish it on the host address and set `admin.allowed_networks` (with `127.0.0.1` and the Docker network) |
| The agent packages are not served | `agent.package_dir` does not point at `/opt/myownpki/agent-dist` | Use image 0.3.3 or later, which sets `MYOWNPKI_AGENT_PACKAGE_DIR`; or set the variable |
| A config change has no effect | `docker/config.yaml` is mounted read-only and read at start | `docker compose up -d` recreates the container; then unseal |

Still stuck? Open an
[issue]({{ site.repository_url }}/issues) with the exact message and the output of
`myownpki --version`. For anything that looks like a vulnerability, follow
[SECURITY.md]({{ site.repository_url }}/blob/main/SECURITY.md) instead.
