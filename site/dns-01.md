---
title: "dns-01 and wildcard certificates with the agent"
description: "Since v0.3.7 the agent can prove names through a DNS TXT record: wildcard certificates, hosts without port 80, hosts behind NAT. RFC 2136 with a TSIG key (BIND, Knot, PowerDNS) or Cloudflare with an API token; the credentials file, DNS server settings, propagation, firewall, a worked example and what to do when it fails."
permalink: /dns-01/
---

Until v0.3.6 the agent proved a name only with **http-01**: the ACME server fetched a file from port 80 of
the host. Since v0.3.7 a deployment can use **dns-01** instead. The agent publishes a TXT record
`_acme-challenge.<name>` in your DNS zone, waits until it is visible, lets the ACME server read it, and
removes it again. The server still only **reads** the record (see
[ACME explained]({{ '/learn/acme/' | relative_url }}#the-challenge-dns-01)); the agent is the client that writes it.

This page is the administrator's view. The reference text is
[operations guide §12.11]({{ '/reference/operations/' | relative_url }}#1211-dns-01-in-the-agent).

> **Status:** new in v0.3.7. CI runs the agent's RFC 2136 code against an in-process DNS server and against
> a real BIND (TSIG key, `propagation: resolver`), and the Cloudflare code against a stub. **Not yet tested
> live:** the real Cloudflare API, a BIND `update-policy` on the maintainer's server, and the default
> `propagation: authoritative` on port 53. Try it on one test host before you rely on it. If something differs
> from this page, please tell us in an [issue]({{ site.repository_url }}/issues).
{: .note}

* TOC
{:toc}

## When to use it

| Situation | http-01 (default) | dns-01 |
|---|---|---|
| A **wildcard** name such as `*.homelab.lan` | Not possible: RFC 8555 §7.1.3 leaves wildcards to dns-01 | The only way |
| A service on a port other than 80, with **no port 80** reachable from the PKI server | The check fails | Works: no port is involved |
| A host **behind NAT** or a firewall you do not control | The server must reach the host's port 80 | Works: the agent only makes outbound connections |
| A normal host with nginx on port 80 | Works, and needs no DNS credentials | Not worth the secret |

dns-01 costs you one thing: a **credential that can change your DNS zone**. Everything below is about keeping
that credential small and out of the wrong places. If http-01 works for a host, keep it.

The challenge is chosen **per deployment**. A host can have one deployment on http-01 and another on
dns-01. Enrollment of a new host stays on http-01 (a host without port 80 enrolls with a join token and one
approval, see [Adding hosts]({{ '/hosts/' | relative_url }}#admission-token-check-approval); its certificates can then use dns-01).

## What you need

1. A **domain on the server** that allows dns-01, and for a wildcard also *Wildcards* (see
   [the server side](#the-server-side-domain-and-the-agents-names)).
2. The agent's **names** include the exact names the deployment orders, wildcard pattern included.
3. A DNS server the agent may **update**: BIND, Knot or PowerDNS with a TSIG key (RFC 2136), or a zone at
   **Cloudflare** with an API token.
4. A **credentials file** on the host, readable by root only.
5. The PKI server's `acme.resolver` can **see the zone** the agent writes. The server reads
   `_acme-challenge.<name>` through that resolver; with split DNS it must be the internal one
   ([Split DNS]({{ '/guides/split-dns/' | relative_url }})).
6. Agent v0.3.7 on the host. Update it before you add a dns-01 deployment
   ([Upgrade]({{ '/upgrade/' | relative_url }}#notes-per-release)).

## The server side: domain and the agent's names

The ACME server decides what the agent may order. The agent never asks about policy, so a refusal comes back
as the server's own message. Two settings matter, and both are made in the UI:

- **The domain.** Under *ACME → Domains*, the domain that covers the name must allow **dns-01**. For a
  wildcard it must also have *Wildcards* ticked, which needs *Names below the domain too* and dns-01
  ([Domains and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }})).
- **The agent's names.** On the agent's page, *Names it may order* must hold every name of the deployment.
  **A wildcard is covered only by the identical pattern.** `*.homelab.lan` in the list covers
  `www.homelab.lan` but not `homelab.lan` itself, and the entry `homelab.lan` does not cover `*.homelab.lan`. For a
  certificate with both names, add both entries. An enrollment pass grants the host name only, so for a
  wildcard you always add the pattern yourself.

A wildcard `*.homelab.lan` covers one label: `www.homelab.lan`, not `a.b.homelab.lan`. A deployment that asks
for `*.homelab.lan` **and** `homelab.lan` gets one certificate with two names; the agent writes two values
at the same TXT name `_acme-challenge.homelab.lan` and removes both afterwards.

## The credentials file

The secret (a TSIG key or an API token) lives in a file of its own, **never** in `agent.yaml`: that file is
shared and often kept in version control. It is also never put on a command line
(it would show in the process list and the shell history) or in an environment variable. The agent removes
every variable that starts with `LEGO_`, `CLOUDFLARE_`, `CF_` or `RFC2136_` when it starts, logs their
**names** and ignores them. It also removes `SSL_CERT_FILE` and `SSL_CERT_DIR`: on Linux they choose which
certificate authorities the system trusts, and the Cloudflare calls use that trust, so they would choose who
may receive the API token. The agent's own connections (to the PKI server and to the ACME server) trust the
`ca_bundle` of `agent.yaml` and never read them. **Hooks inherit the cleaned environment**: a test or reload
hook sees none of these variables, and a hook that talks TLS uses the system's default trust.

A file per provider entry, for example `/etc/myownpki-agent/dns/homelab.yaml`. It is YAML with a fixed set of
keys; an unknown key, an empty value, a repeated key or a second YAML document is an error.

**RFC 2136:**

```yaml
tsig_key_name: acme-agent
tsig_algorithm: hmac-sha256
tsig_secret: bm90LWEtcmVhbC1zZWNyZXQtanVzdC1hbi1leGFtcGxl
```

| Key | Meaning |
|---|---|
| `tsig_key_name` | Required. The name of the key on the DNS server, the same as in its `key` statement. |
| `tsig_secret` | Required. Base64, exactly as the secret in BIND's `key` statement. |
| `tsig_algorithm` | Optional: `hmac-sha256` (default), `hmac-sha384` or `hmac-sha512`. `hmac-md5` and `hmac-sha1` are refused. |

**Cloudflare:**

```yaml
api_token: example-token-replace-me
```

| Key | Meaning |
|---|---|
| `api_token` | Required. A Cloudflare API **token** (not the legacy global API key, which is not supported). |
| `zone_token` | Optional. Only if you split the permissions: a second token that may only read zones. See [the token scope](#cloudflare). |

The agent opens the file without following a symbolic link and checks the **open** file. A file that fails
a check is not read at all, and the message names the problem and the path, never the content:

| Rule | State shown by `config check` |
|---|---|
| A regular file (no directory, device or pipe), at most 4 KiB | `not a regular file`, `too large` |
| Mode **0600** or **0400**, no setuid, setgid or sticky bit | `wrong mode` |
| Owned by **root** or the agent's user | `wrong owner` |
| The directory that holds it is owned by root or the agent's user and **not writable by group or others** (anyone who can write the directory can replace the file) | `unsafe directory` |
| Not a symbolic link: set `credentials_file` to the real file | `symbolic link` |
| Valid YAML with the keys above | `invalid` |

The **path** has rules too, checked when `agent.yaml` is read: absolute, no `..`, and **not** under `/home`,
`/root` or `/run/user` (the agent's systemd unit hides them with `ProtectHome=yes`), not under `state_dir` or
`paths`, and not a deployment target (the agent writes there, a secret file must not be there). Use
`/etc/myownpki-agent/dns/`. The unit can read `/etc`, and the file is only read, so no change of the systemd
sandbox is needed.

Create it like this:

```bash
install -d -m 0750 -o root -g root /etc/myownpki-agent/dns
```

```bash
install -m 0600 -o root -g root /dev/null /etc/myownpki-agent/dns/homelab.yaml
```

Then put the content in with an editor (as root), so the secret never appears in a command line.

The agent reads the file **when an issuance starts** and clears it from memory afterwards. A rotated secret
works at the next renewal without a restart.

## The DNS server settings

### RFC 2136 with a TSIG key (BIND, Knot, PowerDNS)

RFC 2136 is the standard way to change a zone over the network ("dynamic update"). A **TSIG** key signs each
update so the server knows who sends it. The agent sends one signed update to add the record and one to remove
it, **over TCP**, and accepts the answer only if its own TSIG signature verifies: an unsigned "success" from
somebody in the path counts as a failure.

Create a key on the DNS server. BIND ships a tool for it:

```bash
tsig-keygen -a hmac-sha256 acme-agent
```

It prints a `key` statement with the secret. The name (`acme-agent`) goes into `tsig_key_name`, the secret
into `tsig_secret`.

Give that key the **least** it needs. The agent only adds and removes TXT records at
`_acme-challenge.<name>`, so a BIND `update-policy` can say exactly that:

```
key "acme-agent" {
    algorithm hmac-sha256;
    secret "…the secret that goes into tsig_secret…";
};

zone "homelab.lan" {
    type primary;
    file "db.homelab.lan";
    update-policy {
        grant acme-agent name _acme-challenge.homelab.lan. TXT;
    };
};
```

A `name` rule matches that one name. A certificate for `*.homelab.lan` and `homelab.lan` needs only this one
line, because both names use `_acme-challenge.homelab.lan`. For every other name of a deployment, add its own
`grant` line (for example `_acme-challenge.www.homelab.lan.`). A zone cannot have both `update-policy` and
`allow-update`. (`type primary` is BIND 9.16 and newer; older versions say `type master`.) Reload with `rndc reload`, and make sure the directory of the zone file is writable by the
`named` user, because dynamic updates write a journal next to it.

> **Not verified:** this `update-policy` is the narrowest form that the agent's updates need, written from
> the BIND documentation. The CI test against BIND uses `allow-update` with the same kind of key, not
> `update-policy`. Check the line on a test zone first and compare with the documentation of your BIND version.
> Knot and PowerDNS have their own ways to restrict a key; the agent only needs to be allowed to add and
> remove TXT records at the names above.
{: .note}

What the agent needs to know, in the `dns_providers` entry of `agent.yaml`:

- `nameserver`: the DNS server that **accepts the update** (the primary, not a secondary). `host` or
  `host:port`, port 53 by default.
- `zone`: optional. Without it the agent asks the nameserver for the **SOA** record of the name and its
  parents and updates the zone that answers. Set it if the nameserver is not authoritative for the name, or
  to save the lookup.
- **Time.** TSIG signatures carry the time, and a server refuses a signature that is too far off (the agent
  sends a tolerance of 300 seconds, BIND's default). Keep the clocks of the host and the DNS server on NTP.

**CNAME delegation works.** If `_acme-challenge.homelab.lan` is a CNAME to a name in another zone, the agent
follows it and sends the update to the zone of the target, so the key must be valid **there**. Leave `zone`
unset in that case: with `zone` set, a target outside that zone is refused before any message is sent
(`rfc2136: zone mismatch: …`).

### Cloudflare

Create an API **token** at Cloudflare. The agent's calls are:
look up the zone by name, create a TXT record in it, delete that record by its ID. For that the token needs

- **Zone / Zone / Read**, and
- **Zone / DNS / Edit**,

and scope the token to **the one zone**, not to all zones of the account. These are the permissions that the
Cloudflare provider of the lego library (which the agent uses) documents; **check the names against Cloudflare's
current documentation**, because their dashboard changes.

If you want even less on the host that holds the DNS-edit token, split it: `zone_token` (only *Zone / Zone /
Read*, can be shared by hosts) and `api_token` (*Zone / DNS / Edit* on the one zone). With no `zone_token` the
`api_token` does both.

The Cloudflare calls use the system's trust store (not `ca_bundle`, which is for your private root), TLS 1.2
or newer, and the `proxy:` of `agent.yaml` if you set one. A host without the `ca-certificates` package cannot
verify Cloudflare's certificate. The agent never reads `HTTPS_PROXY`.

The zone is found by an SOA lookup through the resolver of the entry, so that resolver must see the zone under
its public name. With split DNS (the same name inside and at Cloudflare), set `resolver` to a resolver that
answers for the public zone.

## agent.yaml: dns_providers

`deployment add` writes the entry for you (see [the example](#step-by-step-a-wildcard-certificate)). The
entry holds no secret, only where to send updates and the path of the credentials file:

```yaml
dns_providers:
  homelab-dns:
    type: rfc2136
    credentials_file: /etc/myownpki-agent/dns/homelab.yaml
    nameserver: 192.0.2.53
```

| Key | Default | Meaning |
|---|---|---|
| `type` | required | `rfc2136` or `cloudflare` |
| `credentials_file` | required | Absolute path, see [the credentials file](#the-credentials-file) |
| `nameserver` | required for `rfc2136` | `host` or `host:port` of the DNS server that accepts the update. Not for Cloudflare. |
| `zone` | looked up | `rfc2136` only: the zone to update |
| `ttl` | 120 | TTL of the TXT record in seconds: 30 to 3600 for `rfc2136`, 120 to 3600 for Cloudflare |
| `resolver` | `/etc/resolv.conf` | `IP` or `IP:port` used for the SOA, CNAME and propagation queries |
| `propagation` | `authoritative` | How the agent waits for the record, see [below](#propagation-how-the-agent-waits) |
| `propagation_wait` | 0 | A pause in seconds before the first check, 0 to 300 |
| `propagation_timeout` | 120 | How long the agent polls, in seconds, 1 to 600 |

A deployment then says `challenge: dns-01` and `dns_provider: homelab-dns`; several deployments can share one
entry. A name with `*.` is allowed **only** with dns-01, and a dns-01 deployment takes no `webroot`. Unknown
keys are errors, and `config check` reports every problem at once. A provider that no deployment uses is a
warning.

`ttl`, `resolver`, the propagation keys and `zone` for an existing name are changed **by hand** in
`agent.yaml`; `deployment add` writes a new entry once and refuses a different definition for an existing
name (it says "edit agent.yaml by hand").

The agent never falls back to public resolvers. Without `resolver` it uses the servers of `/etc/resolv.conf`,
and if that file has none the issuance fails with a message that says so, because a silent fallback would send
the names of your internal network to the internet.

A deployment of only wildcard names that has a local TLS `check` also needs `check_name` (a concrete host
name used as SNI, for example `www.homelab.lan`): `*.homelab.lan` is not a name a server can be asked for. Without
`check_name` the agent uses the first name that is not a wildcard.

## Propagation: how the agent waits

After it writes the record, the agent checks that the record is visible **before** it tells the ACME server to
look. It polls every 2 seconds until `propagation_timeout`. Telling the server too early costs a failed
validation (and counts against the [rate limits]({{ '/reference/operations/' | relative_url }}#108-sealed-server-rate-limits-audit));
waiting a little too long costs nothing.

| `propagation` | The agent waits until | Use it when |
|---|---|---|
| `authoritative` (default) | The TXT record is on **every authoritative name server** of the zone. It asks the resolver for the zone's name servers and then each of them on **port 53**. | The agent can query the name servers directly. This is robust against caches: it does not depend on what a resolver remembers from an earlier "no such record". |
| `resolver` | The configured **resolver** returns the record. | The host cannot reach the authoritative servers on port 53 (a firewall, a DNS design where only the resolver is reachable). A resolver that cached "no record" can make this slow; keep `ttl` low. |
| `wait` | Nothing is queried. It only sleeps `propagation_wait` seconds. | Neither check is possible. You must set `propagation_wait` long enough for your DNS to publish the change. |

`propagation_wait` is added once before the first check in **every** mode, which helps with a secondary that
needs a moment to receive a zone transfer.

While an issuance runs, the agent does not queue the optional ARI check of another deployment behind it (a
dns-01 issuance can wait up to `propagation_timeout`): it skips that check for this pass and asks again at the
next one, so an early-renewal hint of the ACME server may arrive one pass later.

## Firewall

The agent only makes outbound connections.

| From | To | Port | When |
|---|---|---|---|
| Agent host | the DNS server in `nameserver` | **53/tcp** | RFC 2136: updates and the SOA lookup (both over TCP) |
| Agent host | the resolver | 53/udp, and 53/tcp for large answers | the CNAME check and `propagation: resolver` |
| Agent host | the authoritative servers of the zone | 53/udp and 53/tcp | `propagation: authoritative` only |
| Agent host | `api.cloudflare.com` | 443/tcp, through `proxy:` if it is set | Cloudflare |
| Agent host | Server | 8444/tcp, and the ACME HTTPS port | as for every agent |

For dns-01 the **server does not need to reach the host at all**: port 80 can stay closed. The server needs
its `acme.resolver` to reach your DNS, which it needs for dns-01 from any client.

## Step by step: a wildcard certificate

The names are examples. Use a test host first.

1. **Server.** *ACME → Domains*: `homelab.lan` with *Names below the domain too*, *Wildcards* and dns-01
   ticked. On the agent's page, *Names it may order*: add `*.homelab.lan` and `homelab.lan`.
2. **DNS server.** Create the TSIG key and the `update-policy` ([above](#rfc-2136-with-a-tsig-key-bind-knot-powerdns)).
3. **Host.** Create `/etc/myownpki-agent/dns/homelab.yaml` as in [the credentials file](#the-credentials-file):
   root, mode 0600.
4. **Check the file.** `config check` shows the state of each credentials file:

   ```bash
   myownpki-agent config check
   ```

   With the new entry in `agent.yaml` (step 5) it prints a block like this, and nothing of the content:

   ```
     dns providers
       homelab-dns  rfc2136  /etc/myownpki-agent/dns/homelab.yaml: ok
   ```

   If the file has the wrong mode, the line says `wrong mode: is 0640, want 0600 or 0400`, the command exits
   with 1 and ends with `The configuration is valid, but 1 DNS credentials file(s) used by a deployment cannot
   be used`.
5. **Add the deployment**, first with `--dry-run` (add `--acme-directory URL` if `agent.yaml` has none):

   ```bash
   sudo /usr/local/bin/myownpki-agent deployment add wild --recipe nginx --name '*.homelab.lan' --name homelab.lan --challenge dns-01 --dns-provider homelab-dns --dns-type rfc2136 --dns-nameserver 192.0.2.53 --dns-credentials /etc/myownpki-agent/dns/homelab.yaml --check-name www.homelab.lan --dry-run
   ```

   The diff shows the new `dns_providers` entry and the deployment. Run the same line without `--dry-run`, then:

   ```bash
   sudo systemctl restart myownpki-agent
   ```

   `deployment add` checks the credentials file too, but only as a **warning** (a configuration tool may run
   it before the secret file exists), and the warning names the state and the path, never a value.
6. **Renew now.** On the agent's page the deployment is pending; press *Renew now*, or wait. The deployment
   turns *deployed*.
7. **Verify.** Both names are in the certificate:

   ```bash
   openssl s_client -connect minion-01.homelab.lan:443 -servername x.homelab.lan </dev/null | openssl x509 -noout -ext subjectAltName
   ```

   and the agent removed its records:

   ```bash
   dig +short TXT _acme-challenge.homelab.lan @192.0.2.53
   ```

   The second command should print nothing. To see the waiting and the checks, set `log_level: debug` in
   `agent.yaml` for one run and read `journalctl -u myownpki-agent`.

### The flags

`deployment add` has these flags for dns-01 (the other flags are in
[Adding hosts]({{ '/hosts/' | relative_url }}#adding-a-deployment-deployment-add)):

| Flag | Meaning |
|---|---|
| `--challenge dns-01` | Use dns-01. Needed for a wildcard name. No `--webroot`. |
| `--dns-provider NAME` | Required with dns-01: the entry of `dns_providers`, for example `homelab-dns` |
| `--dns-type rfc2136` or `cloudflare` | Defines a **new** entry. Without it the entry must already exist. |
| `--dns-credentials FILE` | The absolute path of the credentials file (required for a new entry) |
| `--dns-nameserver HOST[:PORT]` | `rfc2136`: the DNS server that accepts the update (required for a new entry) |
| `--dns-zone ZONE` | `rfc2136`: the zone to update (default: looked up) |
| `--dns-resolver IP[:PORT]` | The resolver for SOA, CNAME and propagation queries |
| `--check-name NAME` | The SNI of the local TLS check; needed when every name is a wildcard and there is a `check` |

A second deployment on the same provider repeats the flags, or gives only `--dns-provider`: the same
definition changes nothing, a **different** one is refused.

### With Cloudflare

The same, with a token file and no nameserver:

```bash
sudo /usr/local/bin/myownpki-agent deployment add wild --recipe nginx --name '*.example.com' --name example.com --challenge dns-01 --dns-provider cloudflare-example --dns-type cloudflare --dns-credentials /etc/myownpki-agent/dns/cloudflare.yaml --check-name www.example.com --dry-run
```

If the host needs a proxy to reach the internet, set `proxy:` in `agent.yaml`. Check afterwards that the zone
in Cloudflare has no `_acme-challenge` TXT record left.

## When it fails

The deployment shows the error as its *Last error* on the agent's page and in `myownpki-agent status`;
`journalctl -u myownpki-agent -n 100 --no-pager` has more. None of these messages contains a secret. Failed
validations count against the failure limit of the ACME server, so fix the cause before you press *Renew now*
again.

| Message (variable parts as `…`) | Cause | Fix |
|---|---|---|
| `credentials file …: missing: no such file` | The file is not where `credentials_file` says | Create it, or correct the path |
| `credentials file …: wrong mode: is 0640, want 0600 or 0400` | The mode is too open | `chmod 0600` |
| `credentials file …: wrong owner: owned by uid …, want root or the agent's user` | Another user owns it | `chown root:root` |
| `credentials file …: unsafe directory: directory … has mode … and can be written by group or others` | Someone else could replace the file | `chmod 0750` the directory, owned by root |
| `credentials file …: invalid: unknown key "…"; a … file has …` (or `tsig_secret: not valid base64`, `… the value is empty`) | The content does not fit the provider type | Compare with [the credentials file](#the-credentials-file) |
| `credentials_file: "…" is under /home, which the agent's systemd unit hides (ProtectHome=yes)` | A path under `/home`, `/root` or `/run/user` | Use `/etc/myownpki-agent/dns/` |
| `a wildcard needs challenge: dns-01 (RFC 8555 §7.1.3)` | A `*.` name on http-01 | Use `--challenge dns-01` |
| `dns_provider: "…" is not under dns_providers` | The deployment names an entry that does not exist | Add it with `--dns-type`, or fix the name |
| `check_name: every name is a wildcard, so the TLS check needs a concrete name` | Only wildcards and a `check` | Add `--check-name www.homelab.lan` |
| `dns-01 needs a resolver of its own and /etc/resolv.conf has none: set resolver: <IP> under dns_providers` | No resolver to ask, and the agent never uses public ones | Set `resolver` |
| `rfc2136: adding the TXT record: NOTAUTH from …: the server does not accept the TSIG key or its secret, or is not authoritative for the zone` | A wrong key name or secret, or `nameserver` is not authoritative | Compare `tsig_key_name`, `tsig_secret` and the algorithm with the server's `key` statement |
| `… REFUSED from …: the server refuses this key to change this name (check its update policy and allow-update)` | The key may not change `_acme-challenge.<name>` | Fix `update-policy` or `allow-update` |
| `… NOTZONE from …: the name is not inside the zone being updated` | `zone` is wrong | Correct or remove `zone` |
| `rfc2136: zone mismatch: … is not inside the configured zone …` | `zone` is set, and the name (or a CNAME target) is elsewhere | Leave `zone` unset |
| `rfc2136: zone lookup: … has no SOA record for … or a parent` | The nameserver is not authoritative for the name | Point `nameserver` at the primary, or set `zone` |
| `rfc2136: … the TXT record at …: dial tcp …` (timeout, refused) | The agent cannot reach the nameserver on 53/tcp | Firewall, address, `named` listening |
| `the answer's TSIG time differs too much from this host's clock; check NTP` | The clocks differ by more than the TSIG window | Fix NTP on both machines |
| `the answer's TSIG signature is wrong: not from the server that holds this key, or the secret differs` or `the answer is not signed (TSIG record missing)` | The secret differs, or something answers in the server's place | Check the secret and the path to the DNS server |
| `propagation: time limit exceeded: last error: NS … did not return the expected TXT record` | The record is not visible to the check in `propagation_timeout` seconds. The update may have gone to a server the others do not copy from, or a secondary lags, or port 53 to the name servers is blocked | `dig TXT _acme-challenge.<name> @<each NS>` from the host. Use `propagation: resolver` or `wait`, or raise `propagation_wait` and `propagation_timeout` |
| `propagation: time limit exceeded: last error: initial recursive nameserver: …` or `authoritative nameservers: …` | The resolver does not answer, or the name servers are unreachable | Set `resolver`, check port 53 |
| `cloudflare: could not find zone for domain …` or `failed to find zone …: [status code 403] …` or `zone could not be found` | The resolver does not return the zone's SOA, or the token may not read the zone, or the zone is not in this account | Set `resolver` to one that sees the public zone; check the token's zone and its *Zone / Read* permission |
| `cloudflare: failed to create TXT record: [status code 403] …` | The token lacks *DNS / Edit* on this zone | Fix the token |
| `cloudflare: HTTP status … with an answer that is not the Cloudflare API's JSON; is a proxy or a captive portal in the way?` | A proxy or portal answers instead of the API | Check `proxy:` and the route to `api.cloudflare.com` |
| `dns-01: the ACME server asked for a record for a name that is not one of this deployment's names; refused` | The server asked for a name that the deployment never ordered. The agent refuses. | This should not happen with your own server; check the server and `names` |
| `… is not in this agent's allowed names` (the server's `rejectedIdentifier`) | *Names it may order* lacks the name, or for a wildcard lacks the identical `*.` pattern | Add it on the agent's page |
| `no domain covers *.homelab.lan – an admin of the PKI must add one` | No domain covers the name, or the domain has no *Wildcards*, or dns-01 is not allowed | *ACME → Domains*, see [the server side](#the-server-side-domain-and-the-agents-names) |
| `_acme-challenge.… has no TXT record`, or `no TXT record of … holds the digest of the key authorization` | The agent believed the record was visible, but **the server's resolver** does not see it | `acme.resolver` must read the zone the agent writes; with split DNS point it at the internal server ([Split DNS]({{ '/guides/split-dns/' | relative_url }})). A resolver with a cached "no record" needs `propagation_wait` |

**A leftover record.** The agent removes its TXT record on success, on failure, when the issuance is cancelled
and on a timeout. Each removal gets 30 seconds while the issuance runs. While the agent is stopping, **all
removals of one issuance share 12 seconds** (below the 30 seconds that systemd allows for stopping), so that
systemd does not have to kill the agent in the middle of the second record; a record that has no time left is
not sent and counts as a failed removal. If a removal fails, or the agent is killed (`SIGKILL`, a power cut), a
record can stay. It does no harm to validation, but it is untidy.

A failed removal does not fail the issuance. The deployment stays *deployed*, because the certificate is good,
and its *Last error* (on the agent's page and in `myownpki-agent status`) names the records that may remain:
`dns-01 cleanup failed: a TXT record may remain at _acme-challenge.<name>; remove it by hand if it stays (the
agent log has the details)`. It lists up to three names and then says `and N more`. The text has no provider
message and no secret; the reason is in the agent log, with the line `dns-01 cleanup failed: a TXT record may be
left behind; remove it by hand if it stays`, the provider, the name and the reason. If the issuance itself
failed too, the notice comes first, in front of the error. The next pass without a cleanup problem clears the
text. Remove the record in your DNS.

With **Cloudflare** the agent tells you only when the request that created the record may have worked: the
connection broke, the answer was not the API's JSON, or the status was 5xx or 2xx. Then no record ID is known
and the agent cannot delete by ID, so it names `_acme-challenge.<name>`. A create that Cloudflare refused with a
4xx (a token without permission, for example) wrote nothing and gives no notice. A killed agent writes
nothing, and for Cloudflare the agent knows record IDs only in memory, so a leftover record there is always
removed by hand.

## What is not supported

- **GSS-TSIG and Active Directory DNS.** Windows DNS in an Active Directory zone accepts only secure (GSS-TSIG)
  updates, which the agent does not speak. Run the zone used for ACME on BIND, Knot or PowerDNS, or delegate
  `_acme-challenge.<zone>` by CNAME to such a zone.
- **Other DNS providers.** Only RFC 2136 and Cloudflare are built in. For another provider, use an ACME client
  with its DNS plug-in ([certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}),
  [acme.sh]({{ '/guides/acme-sh/' | relative_url }})); they work against this server like any ACME client.
- **The legacy Cloudflare global API key.** Use a token.
- **DNS updates over HTTPS or TLS**, MD5 and SHA-1 TSIG keys, and more than one provider per deployment.
- **dns-01 for enrollment.** A new host still proves its name with http-01 or is approved by an admin.
- **The Add host assistant** does not offer dns-01: it ends in a pasted command and cannot place a secret file.
  Run `deployment add` by hand afterwards (or let [Salt]({{ '/hosts/salt/' | relative_url }}#dns-01-deployments) do it).
- **A sweep of old records.** Nothing removes a record that an earlier, killed run left.

## Next steps

- Several hosts: [Rolling out with Salt]({{ '/hosts/salt/' | relative_url }}#dns-01-deployments) places the credentials file with `file.managed`.
- Keep the token small and the file private: [Best practices]({{ '/best-practices/' | relative_url }}#keep-the-dns-credential-small).
- What the server needs to see the record: [Split DNS]({{ '/guides/split-dns/' | relative_url }}).
- More errors: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#dns-01-in-the-agent).
