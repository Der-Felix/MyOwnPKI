---
title: "Split DNS and the network for validation"
description: "Make ACME validation work in a network with internal names: the resolver of the validator, port 80 for http-01, the address guard and what to check when a validation fails."
permalink: /guides/split-dns/
sources:
  - docs/OPERATIONS.md
  - site/troubleshooting.md
---

## When to use this

Use this page when ACME clients get `connection: … could not be reached`, when a name such as
`nas.homelab.lan` exists only in your internal DNS, or when you plan the firewall for the first domain.
The key fact: the **validator**, the part of MyOwnPKI that checks a challenge, runs on the PKI server and
**connects to the client**, not the other way round. So the name must resolve, and the port must be open,
**from the point of view of the server**.

* TOC
{:toc}

## Before you start

- You know the DNS server that knows your internal names, for example `192.0.2.53`.
- You can run commands on the PKI server, and on a client host.
- A domain covers the name ([Domains and approvals]({{ '/guides/domains-and-approvals/' | relative_url }})).

## Steps

1. **Point the validator at your internal DNS.** `acme.resolver` is the DNS server the validator asks. Empty
   means the system resolver. In `/etc/myownpki/config.yaml`:

   ```yaml
   acme:
     resolver: 192.0.2.53
   ```

   The key also exists as the variable `MYOWNPKI_ACME_RESOLVER`. Check the file and restart:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

   ```bash
   systemctl restart myownpki
   ```

2. **Test the name from the PKI server**, against the same DNS server:

   ```bash
   dig @192.0.2.53 nas.homelab.lan
   ```

   The answer must be the address of the client. Without the right resolver the name does not resolve,
   or it resolves to a public address.

3. **http-01: open port 80** of the client for the PKI server (a firewall on the host included:
   nftables, ufw, firewalld). The server fetches `/.well-known/acme-challenge/…` from there. Test from
   the PKI server:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' http://nas.homelab.lan/.well-known/acme-challenge/test
   ```

   A `404` from the client's web server means the route works. A timeout or `Connection refused` is a
   firewall, a closed port or the wrong address. On the client, see what listens:

   ```bash
   ss -ltnp 'sport = :80'
   ```

4. **Redirects.** The validator follows a redirect only to names of the same order and only to ports 80
   and 443. A load balancer or proxy in front of the client must pass `/.well-known/acme-challenge/`
   through, or you use dns-01.
5. **dns-01** (the server reads a TXT record): the record `_acme-challenge.<name>` must be in the zone
   that `acme.resolver` reads. With split DNS that is the **internal** zone: point the client's DNS plug-in
   (for example certbot-dns-rfc2136) at the internal DNS server. A zone at a provider works the same way
   with the provider's plug-in, as long as the resolver can see that zone. The agent does dns-01 too since
   v0.3.7: with RFC 2136 it writes the record into the **internal** zone itself ([dns-01 and wildcard
   certificates]({{ '/dns-01/' | relative_url }})), and `acme.resolver` must read that zone.
6. **Choose the address policy of the domain.** On the domain page, *Addresses http-01 may reach* is either
   *internal networks too (homelab)*, the default, or *public addresses only*. The next section says
   what both refuse.

## The address guard

The same guard decides where the server may connect for http-01 validation, for the check of an agent's
enrollment and for the TLS scan. A name is resolved **once** and the connection goes to exactly the address
that was checked, so a DNS answer that changes between check and connect cannot redirect it. Every address
that a name resolves to is checked.

**Never reached, under either policy**, among others: loopback (`127.0.0.0/8`, `::1`), link-local
(`169.254.0.0/16`, `fe80::/10`), multicast, unspecified addresses, the reserved IPv4 ranges, and the IPv6
ranges that carry an IPv4 address inside (NAT64, 6to4, Teredo and others). So the server cannot validate
its own `127.0.0.1`; its LAN address is allowed. The documentation ranges such as `192.0.2.0/24` are allowed,
because examples and tests use them.

The complete list is in
[operations guide §14.8]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned).
Under *public addresses only* a domain also refuses the private networks (`10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `fc00::/7`) and `100.64.0.0/10`.

## Check it worked

Run the client again ([Certbot]({{ '/guides/certbot/' | relative_url }}) or another). *ACME → Orders* lists the
order as *valid*. If it fails, the client's message only names the kind of problem, never what the target
answered; the addresses are in the server log at level info:

```bash
journalctl -u myownpki -n 100 --no-pager
```

## When it fails

| The client says | Usually | Check |
|---|---|---|
| `connection: … could not be reached` | Port 80 of the client is closed for the PKI server, or the name resolves elsewhere | Steps 1 to 3; the log has the address |
| `connection: … address policy … refuses` | The name resolves to a range that is never reached, or to a private address on a *public addresses only* domain | The address guard above; the domain's setting |
| `incorrectResponse: … answered with status 404` | The client's web server does not serve `/.well-known/acme-challenge/` | The client's mode: standalone or webroot |
| `dns: … has no TXT record` | The TXT record is in another zone than the resolver reads | Step 5 |
| `rateLimited` | Over a limit of the tenant settings (failed validations per name: 5 per hour by default) | Wait for `Retry-After`, or raise the limit |

The complete table is
[§10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails); the same causes with more
examples are in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Keep the ports in order: the firewall table in [Installation]({{ '/install/' | relative_url }}#ports-and-firewall).
- Background and the other ACME rules (sealed server, rate limits, audit):
  [§10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network) and
  [§10.8]({{ '/reference/operations/' | relative_url }}#108-sealed-server-rate-limits-audit).
- Wildcard certificates (dns-01): see Learn for the concept ([ACME explained]({{ '/learn/acme/' | relative_url }}#the-challenge-dns-01)).
  With ACME clients use their DNS plug-ins; the agent does it since v0.3.7:
  [dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}).
