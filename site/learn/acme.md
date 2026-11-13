---
title: "ACME explained"
description: "How ACME (RFC 8555) works: accounts, orders, authorizations, challenges (http-01 in full, dns-01), finalize and renewal, and how the MyOwnPKI ACME server differs: domains, approvals, EAB keys, policy and rate limits."
permalink: /learn/acme/
sources:
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - CHANGELOG.md
  - internal/acme/server.go
  - internal/acme/order.go
  - internal/acme/validate.go
  - internal/acme/ari.go
  - internal/ca/domains.go
  - .claude/skills/myownpki/references/pki-rules.md
---

Without automation, a certificate is a file somebody copies to a host and forgets until it expires.
**ACME** (Automatic Certificate Management Environment, RFC 8555) is the protocol that replaces this:
a program on the host asks a CA for a certificate, proves it controls the name, and renews on its own.
Let's Encrypt made it common; MyOwnPKI has a server for it, so certbot, acme.sh, lego, Traefik, Caddy and
others can use your CA.

* TOC
{:toc}

## The objects

| Object | What it is |
|---|---|
| Account | A key pair the client makes, registered at the server. Every request is a signed message (JWS) with a one-time nonce against replay. |
| Order | "I want a certificate for these names." |
| Authorization | One per name in an order: the server wants proof for that name. |
| Challenge | A way to give the proof. The client picks one the server offers. |
| Finalize | The client sends a CSR once every authorization is valid; the server issues the certificate. |

The flow: the client reads the **directory** (the list of the server's URLs), creates an account, creates an
order, solves a challenge for each name, calls finalize with a CSR, and downloads the certificate. The CSR
is made on the host, so the private key stays there.

## The challenge http-01

The proof is that the client controls what `http://<name>/` answers.

1. The server gives the client a **token**. The client computes the **key authorization**: the token, a dot,
   and the thumbprint of its account key. Only the holder of the account key can compute it.
2. The client publishes that string at `/.well-known/acme-challenge/<token>` on port 80 of the host, either
   with a tiny web server of its own (standalone) or in a directory the existing web server serves
   (webroot).
3. The client tells the server it is ready. The server fetches the URL and compares the answer.

```text
GET http://nas.homelab.lan/.well-known/acme-challenge/q7Tn3wZk0aXr4Lm9PbVd2YhCe8SgFuJo5NiKx1AtRQe
200 OK
q7Tn3wZk0aXr4Lm9PbVd2YhCe8SgFuJo5NiKx1AtRQe.hV6c1bYdKQ2sWmN8zXrP0uLgEoFtAj3iDyCvB5nMxRw
```

(Example values.) It works for any host whose port 80 the CA can reach. It cannot prove a wildcard name,
which RFC 8555 §7.1.3 leaves to dns-01. For IP addresses (RFC 8738) MyOwnPKI offers http-01 only.

## The challenge dns-01

The proof is that the client can write to the DNS zone. It publishes a TXT record at
`_acme-challenge.<name>` holding a hash of the key authorization (RFC 8555 §8.4). The server reads the
record. It needs no access to the host and no open port, and it is the **only** way to prove a wildcard
name (RFC 8555 §7.1.3). A CNAME from `_acme-challenge` to another zone lets a client with limited DNS
rights do the work.

MyOwnPKI's server only **reads** the record, through the resolver in `acme.resolver`, which should be your
internal DNS if you use split DNS. The **client** sets the record, for example with certbot's
`dns-rfc2136` or `dns-cloudflare` plug-in.

> **Note:** Since v0.3.7 the **MyOwnPKI agent does dns-01 too**. A deployment with `challenge: dns-01` writes
> the TXT record itself, through RFC 2136 (BIND, Knot, PowerDNS with a TSIG key) or the Cloudflare API, waits
> until it is visible and removes it afterwards. That is how an agent gets a wildcard certificate or a
> certificate for a host without port 80. The setup, the credentials file and the errors are on
> [dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). Earlier agents (up to v0.3.6) prove names
> with http-01 only; for other DNS providers, use an ACME client with a DNS plug-in.
{: .note}

The server does not support tls-alpn-01. It is planned for after v1.0.

## Renewal

There is no special renewal step: a client creates a new order for the same names. When it should do so
is up to the client. Clients that support **ARI** (ACME renewal information, RFC 9773, for example lego and
Caddy) ask the server. MyOwnPKI answers with a window that opens at about two thirds of the lifetime
(for 90 days: between day 60 and 63, a little different for each certificate) and lasts a tenth of the lifetime (9 days); a revoked certificate gets a window in the
past, so its client renews at once. Clients without ARI use their own rule (certbot: 30 days before
expiry). The agent renews at two thirds of the lifetime, or earlier if ARI asks for it.

## How the MyOwnPKI server differs

| Topic | In MyOwnPKI |
|---|---|
| Who may get what | Only names covered by a **domain** (*ACME → Domains*). A domain fixes the signing CA, the names below it, the allowed challenges, whether wildcards are allowed (off by default), the preset, the validity (90 days by default), and which addresses http-01 may reach. A name outside every domain is refused with `rejectedIdentifier`. |
| Constraints of the CA | The domain's CA must be an online intermediate whose name constraints permit the domain. A root is refused. |
| Approval | *Open*: any account that passes the challenge. *Approved accounts* (the default): a new account waits for an admin, or brings an EAB key. *New names*: the first certificate for a name waits. Approval per order is not offered, because standard clients stop waiting. |
| EAB keys | **External account binding**: an admin creates a key ID and a MAC key (shown once), the client presents them at registration and skips the queue. A key binds one account and expires after 7 days by default. |
| Rate limits (per hour) | 300 new orders per account, 5 failed validations per name, 10 new accounts per client address (IPv6 per /64). Over a limit the client gets `429` with `Retry-After`. They are set in the tenant settings. |
| Validation | The server resolves a name once and connects to exactly the address it checked. It refuses loopback, link-local and other ranges, reaches only ports 80 and 443, and never tells the client what the target answered. |
| Pending work | A pending order or authorization expires after 24 hours. |
| Sealed server | Accounts, orders and challenges work, but finalize waits and the certificate is issued at the unseal. |
| TLS | By default behind a reverse proxy that ends TLS; with `acme.tls_issuer` the server can serve its own TLS. |

All of it goes through the same policy engine as the UI, so a rule such as a name constraint holds for
ACME as well. Every account, order, validation, approval and issuance is in the audit log.

## Next steps

- Connect a client: [operations guide §10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)
  and [Recipes]({{ '/recipes/' | relative_url }}).
- Make the domains, approvals and EAB keys: [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).
- Split DNS and the network: [operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).
- A client fails: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01) and
  [operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails).
- Hosts without ACME knowledge: [Adding hosts]({{ '/hosts/' | relative_url }}).
- What the challenge result depends on: [Name constraints]({{ '/learn/name-constraints/' | relative_url }}) and
  [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).
