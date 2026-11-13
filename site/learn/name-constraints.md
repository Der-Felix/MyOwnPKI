---
title: "Name constraints"
description: "What name constraints are, why a private CA should carry them, how MyOwnPKI applies them before signing, what happens when a name is outside, and where client support varies."
permalink: /learn/name-constraints/
sources:
  - internal/ca/constraints.go
  - internal/ca/profile.go
  - internal/ca/lifecycle.go
  - internal/ca/offline.go
  - internal/ca/domains.go
  - internal/ca/engine.go
  - docs/PLAN.md
  - docs/OPERATIONS.md
  - .claude/skills/myownpki/references/pki-rules.md
---

A CA certificate normally says nothing about *which* names the CA may vouch for. A client that trusts it
believes it for `www.example.com` as much as for `nas.homelab.lan`. **Name constraints** change that: they
are an extension in a CA certificate that limits the names in every certificate below it.

* TOC
{:toc}

## Why a private CA should use them

Your root sits in the trust stores of your devices. If the key of an intermediate leaks, whoever has it
can sign a certificate for your bank, and your devices accept it. If the intermediate is constrained to
`homelab.lan` and `192.0.2.0/24`, the same stolen key can sign only names inside those limits, and a
certificate for any other name fails validation on a client that enforces constraints. The constraint is
a seat belt, not a lock: it limits the damage of a leak. It does not prevent one.

## What the extension says (RFC 5280 §4.2.1.10)

It holds **permitted** and **excluded** subtrees for four name types:

| Type | Example value | Covers |
|---|---|---|
| DNS | `homelab.lan` | `homelab.lan` and every name below it |
| DNS | `.homelab.lan` | only the names below it (a common form for DNS that RFC 5280 does not define; MyOwnPKI accepts both) |
| IP address | `192.0.2.0/24`, `fd00::/8` | addresses in the range, IPv4 and IPv6 |
| E-mail | `homelab.lan`, `.homelab.lan` or `admin@homelab.lan` | mailboxes at a host, below a domain, or one mailbox |
| URI | `homelab.lan` | the host of the URI |

A name must be inside a permitted subtree (when the type has one) and outside every excluded one. RFC
5280 says a conforming CA marks the extension **critical**, which tells a client that does not understand
it to reject the certificate rather than ignore the limit.

## How MyOwnPKI applies them

- **Where you set them.** On an **intermediate**, when you create it; MyOwnPKI offers no constraints for
  a root it creates. The constraints become part of the CA certificate, so changing them needs a new
  certificate. For an intermediate below an offline root they are in the extension file that the root
  signs with, and the upload is refused if the signed certificate differs from the order.
- **Critical by default**, with a per-CA switch to write the extension non-critical for old clients that
  mishandle it. The switch exists for compatibility; RFC 5280 asks for critical.
- **Enforced before signing.** Every request is checked against the constraints of **every CA in the
  chain** up to the root, including wildcard names (`*.homelab.lan` is inside `homelab.lan`, but not
  inside `a.homelab.lan`) and excluded names that a wildcard would cover. After signing, the certificate is
  verified against the chain once more, including the CA certificates' constraints, so a gap in the first
  check becomes an error, not a certificate.
- **ACME domains.** A domain is refused when the names it would issue lie outside the CA's constraints.
- **Name checks.** If a certificate has no DNS SAN and its CN looks like a host name (it contains a dot),
  clients may read the CN as a name, and some constraint checks do too. MyOwnPKI then checks the CN against
  the DNS constraints as well, and the message offers two ways out: a CN without dots, or a DNS SAN.
- **Warnings.** Creating an intermediate with DNS constraints that reach outside its parent's gives a
  warning, because those extra names could never validate.

## What happens when a name is outside

The request is refused before the key is used, and the refusal is audited. The message names the name, the
CA and the permitted names:

```text
dns "www.example.com" is outside the name constraints of CA "issuing" (permitted: homelab.lan)
```

An excluded name says "is excluded by the name constraints of CA" instead. If a certificate that violates
the constraints reaches a client anyway, for example one signed with a stolen key, a client that enforces
constraints rejects it. OpenSSL reports it like this:

```text
error 47 at 0 depth lookup: permitted subtree violation
```

Look at what a CA certificate carries:

```bash
openssl x509 -in issuing.pem -noout -ext nameConstraints
```

## How clients treat them

What is certain from the standard: a client must reject a certificate with a **critical** extension it
does not implement, and may ignore a non-critical one. So a client without name constraint support either
fails closed (critical) or silently drops the protection (non-critical).

What varies: current versions of OpenSSL, Go and the major browsers and operating systems enforce
constraints, but old systems, some embedded devices and some special-purpose clients do not, or handle
them badly. How a client treats constraints placed on a root, or a name only in the CN, also differs. For
that reason the constraint belongs on the intermediate, and you should test it with the clients you
rely on, for example against a throw-away test CA that carries the same constraints. Name constraints
do not replace keeping the keys safe and the root offline.

They limit nothing but names. The kinds of use a CA may sign are limited by an **EKU limit** on the
CA, and whether it may have sub-CAs by the **path length**. The agent CA is an example of an EKU limit:
an intermediate directly below the root that may sign *clientAuth* certificates only.

## Next steps

- Choose the values when you create an intermediate: [Best practices]({{ '/best-practices/' | relative_url }}#narrow-every-ca-with-name-constraints).
- The agent CA and its EKU limit: [Adding hosts]({{ '/hosts/' | relative_url }}#what-the-server-needs-first).
- Domains must fit the CA: [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).
- The risk they reduce: [How trust works]({{ '/learn/trust/' | relative_url }}).
- Create a CA below an offline root: [Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }}).
- A request is refused: [Troubleshooting]({{ '/troubleshooting/' | relative_url }}).
