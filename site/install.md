---
title: "Installation"
description: "Install MyOwnPKI as a systemd service with install.sh or as a container, run init, unseal the server and issue the first certificate."
permalink: /install/
---

This page takes you from an empty machine to a running server, the first authority and the first
certificate. There are two ways to install: a **systemd service** with `install.sh` (recommended
on Linux) and a **container**. The complete reference is the
[operations guide]({{ '/reference/operations/' | relative_url }}#2-install-and-configure).

* TOC
{:toc}

## What runs where

One program, several listeners. Which of them you open to whom is the main decision of an
installation.

| Part | What it does | Default | Who needs to reach it |
|---|---|---|---|
| Admin listener | Web UI and REST API, HTTPS only | `127.0.0.1:9443` (`0.0.0.0:9443` with `install.sh`) | Administrators only. Never the internet. |
| Public listener | CRLs, CA certificates and the trust page over plain HTTP, no login | `:8080` (`:80` with `--public-port-80`) | Every client that checks revocation or loads a CA certificate |
| ACME listener | The ACME server | Off until `acme.base_url` is set; `127.0.0.1:8081` behind a proxy, `:443` with its own TLS | ACME clients, or only your reverse proxy |
| Agent listener | The agents of your hosts, mutual TLS | Off until `agent.base_url` is set; `:8444` | The hosts that run `myownpki-agent` |
| Data directory | Databases, audit log, keys (encrypted), bootstrap certificates | `/var/lib/myownpki` | The service user only (mode 0700) |
| Configuration | One YAML file; every key also exists as a `MYOWNPKI_*` variable | `/etc/myownpki/config.yaml` | root, and read access for the service user |

The public listener speaks **plain HTTP on purpose**. Every certificate contains the address of its
CRL and of its issuer's certificate, and clients fetch those before they trust anything. Do not
redirect that port to HTTPS.

> **Note:** The address on which the public listener is reached, the *base URL* (for example
> `http://pki.homelab.lan`), is written into every certificate that a CA issues and can never be
> changed for that CA. Pick a stable DNS name that you control, not an IP address and not a name
> of the machine.
{: .note}

## Before you start

- A Linux machine with systemd (Debian, Ubuntu and other systemd distributions, amd64 or arm64),
  or a host with Docker and Compose. Unsealing derives the key with Argon2id, which uses 256 MiB of
  memory for a moment, so keep at least that much free.
- A DNS name for the server, for example `pki.homelab.lan`, that every client resolves.
- The time must be right. Certificates, CRLs and the second factor all depend on it, so run NTP
  or systemd-timesyncd on the server.
- Decide where the three secrets of the next section will be kept before you run `init`.
- Optional: [cosign](https://github.com/sigstore/cosign/releases) on the machine. With it
  `install.sh` also checks the Sigstore signature of the release.

## Option A: Linux with systemd

`install.sh` installs MyOwnPKI as a hardened systemd service with one command. Do not pipe it from
the internet into a shell: download it with the checksum file, check it, then run it.

```bash
v={{ site.data.release.version }}
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install.sh"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt.sigstore.json"
sha256sum --check --ignore-missing checksums.txt
```

Then run it as root. `--tls-names` lists the names you will type into the browser:

```bash
sudo bash install.sh --tls-names "pki.homelab.lan, 192.0.2.5"
```

The script downloads the release archive of its own version, checks its SHA-256 against
`checksums.txt` (and the signature of `checksums.txt` when cosign is installed), and stops before it
installs anything if one check fails. It then:

- creates the system user `myownpki` (no login shell) and `/var/lib/myownpki` (mode 0700);
- installs `/usr/local/bin/myownpki`, the unit `/etc/systemd/system/myownpki.service` and the
  daily backup timer;
- publishes the agent packages of the same release (`.deb`, `.rpm`, tarballs for amd64 and arm64,
  each checked against `checksums.txt`) in `/var/lib/myownpki/agent-dist`, so you can install
  agents later without internet on the hosts;
- writes `/etc/myownpki/config.yaml` **only if there is none**. An existing configuration is never
  changed;
- enables the service and **does not start it**, then prints the next steps.

Run it again and it changes nothing that is already in place ("Changes: none"). A newer release
makes it an update, which is described on the [Upgrade page]({{ '/upgrade/' | relative_url }}).

### Options

| Option | Meaning |
|---|---|
| `--version V` | Install another release than the one the script belongs to |
| `--archive FILE` | Install from a local `myownpki_<version>_linux_<arch>.tar.gz`, with `checksums.txt` next to it (and `checksums.txt.sigstore.json` if you have it). For machines without internet. |
| `--tls-names LIST` | Names and addresses in the admin certificate. Default: `hostname -f` and the machine's addresses. |
| `--admin-listen ADDR` | Admin listener. Default `0.0.0.0:9443`. |
| `--allowed-networks LIST` | Who may connect to the admin listener. Default: `127.0.0.1` and the /24 of each own IPv4 address. |
| `--public-port-80` | Public listener on `:80` without a reverse proxy (installs the `low-ports.conf` drop-in). Default `:8080`. |
| `--acme URL` | ACME with its own TLS, for example `https://pki.homelab.lan/acme`. Sets `acme.base_url`, the listener port (443 if the URL has none) and `acme.tls_issuer`. |
| `--acme-ca NAME` | The CA that issues the ACME listener's certificate. Default `issuing`. Give the name of your own intermediate. |
| `--backup-keep N` | How many daily backups the timer keeps. Default 14. |
| `--no-backup-timer` | Switch the daily backup timer off. |
| `-h`, `--help` | The same list on the terminal |

The options about the configuration (`--tls-names`, `--admin-listen`, `--allowed-networks`,
`--public-port-80`, `--acme`) apply only when `install.sh` creates `config.yaml`. With an existing
file it tells you which values to set by hand. The drop-ins are installed either way.

> **Note:** `install.sh` must run as root and needs `systemctl`, `tar`, `sha256sum`, `install`,
> `getent`, `useradd`, `runuser`, `awk`, `cmp`, `stat` and `curl` or `wget`. If it says the new
> binary does not run, `/tmp` may be mounted `noexec`: run it with `TMPDIR` set to another
> directory.
{: .note}

### Behind a proxy

`curl` takes the proxy from `https_proxy`, but `sudo` drops most of the environment. Keep the
variables explicitly, for the downloads and for the script:

```bash
export https_proxy=http://proxy.homelab.lan:3128
```

```bash
sudo --preserve-env=https_proxy,http_proxy,no_proxy bash install.sh --tls-names "pki.homelab.lan, 192.0.2.5"
```

Without `--preserve-env` the script fails with a download error although `curl` works in your shell.
The server itself does not use these variables, except for webhooks (see
[Monitoring]({{ '/monitoring/' | relative_url }})).

### Ports and firewall

| Direction | Port | Open to |
|---|---|---|
| In | 9443/tcp (admin) | Your admin networks only |
| In | 8080/tcp, or 80/tcp with `--public-port-80` or a reverse proxy (public) | Every client |
| In | 443/tcp with `--acme` (ACME with its own TLS), or the port of your reverse proxy | Your ACME clients |
| In | 8444/tcp (agents) | The hosts with an agent |
| Out | 80/tcp to your hosts | ACME http-01 and agent enrollment: the **server** connects to the host to fetch a challenge file |
| Out | 25, 465 or 587/tcp, and HTTPS | Mail server and webhook receiver, if you use them |

Ports below 1024 (`:80`, `:443`) without a reverse proxy need the drop-in
`myownpki.service.d/low-ports.conf`. It gives the service exactly one capability, binding such a
port. `install.sh` installs it when you use `--public-port-80` or `--acme`. If a host firewall
(nftables, ufw, firewalld) is active, open these ports there too; the symptoms of a closed port
are in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

### Where everything is

| Path | What |
|---|---|
| `/usr/local/bin/myownpki` | The binary. After an update the old one is `myownpki.previous`. |
| `/etc/systemd/system/myownpki.service` and `myownpki.service.d/` | The unit with a strict sandbox, and its drop-ins |
| `/etc/myownpki/config.yaml` | The configuration, owner root, group `myownpki`, mode 0640 |
| `/var/lib/myownpki` | The data directory, owned by `myownpki`, mode 0700 |
| `/var/lib/myownpki/agent-dist` | The agent packages of this release |
| `/var/backups/myownpki` | Backups of the daily timer and of updates, mode 0700 |
| `myownpki-backup.service`, `myownpki-backup.timer` | The daily backup |

The service runs as the user `myownpki`. Run every `myownpki` command that reads the data
directory as that user, with `runuser -u myownpki -- /usr/local/bin/myownpki …`.

### Own TLS certificate or ACME without a proxy

By default the admin listener uses a self-signed bootstrap certificate whose fingerprint you compare
once. Better: give it a certificate from your own CA so that browsers that trust your root show no
warning. With `admin.tls_issuer: issuing` in the configuration the server issues and renews this
certificate itself while it is unsealed; see
[operations guide §2.4]({{ '/reference/operations/' | relative_url }}#24-certificates-the-server-issues-itself-tls_issuer).
For ACME without a reverse proxy see `--acme` above and
[§10.10]({{ '/reference/operations/' | relative_url }}#1010-without-a-reverse-proxy-acme-with-its-own-tls).

## Option B: container

The image is `ghcr.io/der-felix/myownpki` for linux/amd64 and linux/arm64. It is distroless and runs
as the non-root user **UID 65532**. Each stable release is tagged with its version
(`:{{ site.data.release.version }}`) and with `:latest`. Pin the version you tested: `:latest` moves with every
stable release, and updating a CA should be a decision, not a pull. Pre-releases get only their version tag.

You need two files from the `deploy/` directory of the release,
[`docker-compose.yml` and `docker/config.yaml`](https://github.com/Der-Felix/MyOwnPKI/tree/v{{ site.data.release.version }}/deploy).
Put them next to each other as `docker-compose.yml` and `docker/config.yaml`.

```yaml
services:
  myownpki:
    image: ghcr.io/der-felix/myownpki:{{ site.data.release.version }}
    restart: unless-stopped
    volumes:
      - myownpki-data:/var/lib/myownpki
      - ./docker/config.yaml:/etc/myownpki/config.yaml:ro
    ports:
      - "127.0.0.1:9443:9443"   # admin UI and API: this host only
      - "8080:8080"             # CRLs and CA certificates: every client
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    stop_grace_period: 30s

volumes:
  myownpki-data:
```

How the container differs from the service:

- **Configuration:** `docker/config.yaml` is mounted **read-only**. Set `admin.tls_names` to the names
  you type into the browser. Every key is also a `MYOWNPKI_*` variable (`MYOWNPKI_` plus the path in
  upper case, `.` as `_`, for example `MYOWNPKI_ADMIN_TLS_NAMES`); a variable wins over the file, and an
  unknown variable is an error. Check the result with `docker compose run --rm myownpki config check`.
- **Volume:** the named volume `myownpki-data` takes over the owner (65532) and mode (0700) of the
  image. A **bind mount** does not: create the directory first with
  `sudo install -d -m 0700 -o 65532 -g 65532 ./data`, or the container cannot write to it.
- **Admin access from other machines:** publish the port on the host address you need and set
  `admin.allowed_networks` to your admin networks. Keep `127.0.0.1` in the list (the health check
  connects through loopback) and the Docker network (for example `172.16.0.0/12`), because
  connections arrive from Docker's gateway address.
- **Health check:** the image runs `myownpki healthcheck` every 30 seconds. It asks `/healthz` of the
  admin listener on loopback and pins the certificate the server serves. A **sealed** server is
  healthy: it cannot sign, but it is up. Monitoring tells you about the seal state (see
  [Monitoring]({{ '/monitoring/' | relative_url }})).
- **Agent packages:** the image carries the agent packages in `/opt/myownpki/agent-dist` and sets
  `MYOWNPKI_AGENT_PACKAGE_DIR` to it. If you enable the agent listener, also publish port 8444.
- **No systemd extras:** the backup timer of `install.sh` does not exist here. Back up with the
  `backup` command ([Upgrade]({{ '/upgrade/' | relative_url }}#back-up-first)) from cron or a timer of your own.

## The passphrase and the recovery key

`init`, the next step, creates the secrets on which everything rests. Know what each one is
before you create it.

> **Warning:** The **unseal passphrase** (or the **recovery key**) decrypts every CA key. Without
> one of the two, the CA keys are gone for good: there is no support, no back door and no recovery
> from a backup. And whoever has a backup **plus** the passphrase or the recovery key can sign as
> your CAs.
{: .warning}

| Secret | What it protects | Where to keep it |
|---|---|---|
| Unseal passphrase (at least 16 characters) | All CA keys. You type it after every start of the server. | A password manager. Not on the server, not in a script, not in an environment variable, not next to the backups. |
| Recovery key (9 groups of 6 characters, shown once) | The same as the passphrase: the second way in, if the passphrase is lost | On paper, in a safe or another place that is not your password manager and not the backup disk |
| Admin password and authenticator (TOTP) | Sign-in to the UI and API | The admin's password manager and phone |
| Checkpoint key fingerprint (shown at the end of `init`) | Lets you prove later that the audit log is the one you had | Write it down; you need it for `backup verify` and `restore` |
| Backups | Everything, but encrypted: they cannot sign without the passphrase | A third place: a backup disk or another machine |

Keep the passphrase, the recovery key and the backups in **three different places**. Once a year,
unseal with the passphrase and check that the paper with the recovery key is readable. The commands to
change a passphrase or use the recovery key are in
[operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key).

## Initialize and start

Run `init` once, at a terminal, as the service user:

```bash
runuser -u myownpki -- /usr/local/bin/myownpki init --config /etc/myownpki/config.yaml
```

In a container:

```bash
docker compose run --rm -it myownpki init
```

It asks for the unseal passphrase (twice), the name and password of the first admin, shows the
**recovery key** and asks you to type two groups of it again, shows the setup for the authenticator
app and wants one code, and ends with recovery codes and the **checkpoint key fingerprint**. Write
the recovery key and the fingerprint down now.

Then start the server:

```bash
systemctl start myownpki
```

```bash
docker compose up -d
```

The server starts **sealed**. It serves the UI, CRLs and CA certificates, but it can sign nothing
until an instance admin unseals it. The log names the SHA-256 fingerprint of the admin certificate;
compare it with what your browser shows the first time:

```bash
journalctl -u myownpki -o cat | grep fingerprint_sha256
```

```bash
docker compose logs myownpki | grep fingerprint_sha256
```

Open `https://pki.homelab.lan:9443/`, sign in with your password and authenticator code, and use
**Unseal** in the banner. A restart seals the server again, so you unseal after every restart and
every update.

For automation without a terminal, `init --stdin` is described in the
[operations guide §3]({{ '/reference/operations/' | relative_url }}#3-first-start-init).

## The first CA and the first certificate

**A root and an intermediate.** The root CA is the anchor that every client trusts; it signs only
other CAs and CRLs. The intermediate signs the certificates you issue. If the intermediate is ever
compromised you replace it; replacing a root means touching every client.

- **Recommended: an offline root.** The key of the root never lies on the server. You create the root
  elsewhere (the original Bash suite `pki.sh` in `legacy/` of the repository is made for this), import
  its certificate in *Certificate authorities*, and create the intermediate below it with *New
  intermediate*. Because the root is offline, the UI gives you a signing request for it; you sign it
  there and upload the certificate. The root also signs its CRL offline, and you upload it on the
  root's page. How often you must do that is in
  [Best practices]({{ '/best-practices/' | relative_url }}#keep-the-root-offline).
- **For trying it out: `init --with-ca`.** It creates an online root and an intermediate (named
  `root` and `issuing`) in one go, for testing and for homelabs that accept an online root:
  `init --with-ca --ca-base-url http://pki.homelab.lan`. The base URL cannot be changed later.

Give your clients the root: the **trust page** at `http://pki.homelab.lan/` (the public listener)
shows every root with its SHA-256 fingerprint, downloads and a guide for Windows, macOS, iOS,
Android, Linux and Firefox. Always compare the fingerprint with the one in the admin UI, because the
page comes over plain HTTP.

**The first certificate.** On the host that will use it, make a key and a request. The key never
leaves that host:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout www.homelab.lan.key -out www.homelab.lan.csr -subj "/CN=www.homelab.lan" -addext "subjectAltName=DNS:www.homelab.lan"
```

In the UI choose *Issue certificate*, the preset *server*, paste the request and issue. Download the
*fullchain* and save it next to the key. The server alternatively makes the key itself, if the tenant
allows that. For many certificates you do not want to do this by hand: let ACME clients or the agent
ask ([Adding hosts]({{ '/hosts/' | relative_url }})).

Check the result against your root:

```bash
openssl verify -CAfile root.pem -untrusted www.homelab.lan.fullchain.pem www.homelab.lan.fullchain.pem
```

## Verify the installation

Go through this once after the installation. Each line should be true.

1. The service runs:

   ```bash
   systemctl is-active myownpki
   ```

2. The health check passes (exit code 0):

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki healthcheck --config /etc/myownpki/config.yaml
   ```

3. The configuration is valid and shows what is in effect:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

4. The public listener answers from a client machine (200 is the trust page; 404 means you switched
   it off, which is fine). Use the port you chose: 80 behind a proxy or with `--public-port-80`,
   otherwise `:8080`:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' http://pki.homelab.lan/
   ```

5. The admin UI opens over HTTPS, the fingerprint matched, you could sign in with the second factor,
   and the server is unsealed (no banner).
6. Your authorities are listed:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki ca list --config /etc/myownpki/config.yaml
   ```

7. A certificate you issued carries working revocation and issuer addresses. Print them, then fetch
   each URL from a client:

   ```bash
   openssl x509 -in www.homelab.lan.fullchain.pem -noout -ext crlDistributionPoints,authorityInfoAccess
   ```

8. The backup works: the timer is listed, one run succeeds and passes its own check:

   ```bash
   systemctl list-timers myownpki-backup.timer
   ```

   ```bash
   systemctl start myownpki-backup.service
   ```

   ```bash
   journalctl -u myownpki-backup.service -o cat
   ```

9. You have written down the passphrase location, the recovery key and the checkpoint fingerprint,
   and you know who may unseal the server.
10. A notification channel is configured and a test message arrived
    ([Monitoring]({{ '/monitoring/' | relative_url }})).

## Next steps

- Set up monitoring and notifications: [Monitoring]({{ '/monitoring/' | relative_url }}).
- Connect hosts: [Adding hosts]({{ '/hosts/' | relative_url }}).
- Read the short list of habits that matter: [Best practices]({{ '/best-practices/' | relative_url }}).
- Practice a restore on another machine before you need one:
  [operations guide §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore).
