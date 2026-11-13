---
title: "Learn"
description: "Concept pages on public key infrastructure: what a certificate authority is, root and intermediate CAs, certificate fields, trust, revocation, ACME, name constraints, key protection and lifetimes, each with what MyOwnPKI does."
permalink: /learn/
---

The guides on this site tell you what to type. These pages tell you **why**. Each one explains a piece of
PKI in plain words, names the standard it comes from where that matters, and then says what MyOwnPKI does
about it. They are written for someone who runs a homelab or a small network and wants to understand the
certificates, not only issue them. Where a statement is about this product it holds for the current
release; features of later releases are marked as not built.

## Questions and pages

| Question | Page |
|---|---|
| What does a certificate authority do, and what does a certificate prove and not prove? | [What is a certificate authority?]({{ '/learn/what-is-a-ca/' | relative_url }}) |
| Why a root and an intermediate, why is the root offline, and what if one of them is lost or expires? | [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}) |
| What is in a certificate, which fields matter, what do the presets set, and how do I read `openssl x509 -text`? | [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}) |
| How does a client decide to trust a certificate, and what does a browser warning mean? | [How trust works]({{ '/learn/trust/' | relative_url }}) |
| How can I limit a CA to my own names, and what happens to a name outside? | [Name constraints]({{ '/learn/name-constraints/' | relative_url }}) |
| How does a certificate stop working before its end date, and does the server do OCSP? | [Revocation]({{ '/learn/revocation/' | relative_url }}) |
| How long should certificates and CAs live, and who renews them? | [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}) |
| How does a host get a certificate by itself, and how is this ACME server different? | [ACME explained]({{ '/learn/acme/' | relative_url }}) |
| How are the CA keys protected, what is a sealed server, and what can I recover if I lose a secret? | [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}) |

## Reading order for a newcomer

1. [What is a certificate authority?]({{ '/learn/what-is-a-ca/' | relative_url }}): the idea.
2. [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}): the structure you
   are about to build.
3. [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}): what the CA writes.
4. [How trust works]({{ '/learn/trust/' | relative_url }}): why clients need your root.
5. [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}): what you must keep safe, before
   you install.
6. [Name constraints]({{ '/learn/name-constraints/' | relative_url }}) and
   [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}): how to set the limits.
7. [ACME explained]({{ '/learn/acme/' | relative_url }}) and [Revocation]({{ '/learn/revocation/' | relative_url }}):
   how certificates are obtained, and withdrawn.

Then follow the guides: [Installation]({{ '/install/' | relative_url }}), [Adding hosts]({{ '/hosts/' | relative_url }})
and [Best practices]({{ '/best-practices/' | relative_url }}).

## Where the facts come from

The numbers for MyOwnPKI (lifetimes, limits, defaults) are those of the
[operations guide]({{ '/reference/operations/' | relative_url }}) and of the code of the current release.
General PKI statements follow the standards they name (RFC 5280, RFC 8555 and others). If a page here ever
disagrees with the operations guide, the operations guide is right.
