---
title: "What is a certificate authority?"
description: "What a certificate authority does, what a certificate proves and what it does not, and which parts of that work MyOwnPKI takes over."
permalink: /learn/what-is-a-ca/
sources:
  - internal/ca/engine.go
  - internal/ca/build.go
  - internal/ca/preset/preset.go
  - docs/PLAN.md
  - docs/OPERATIONS.md
  - .claude/skills/myownpki/references/pki-rules.md
---

When a browser opens `https://nas.homelab.lan/`, it must be sure of two things: that the connection
is encrypted, and that the other end really is `nas.homelab.lan` and not someone in between. Encryption
alone does not give the second part. A **certificate authority** (CA) does.

* TOC
{:toc}

## The problem a CA solves

A public key is just a number. Nothing in it says who owns it. A **certificate** is a short document in
which a CA states: "this public key belongs to these names". The CA signs the document with its own
private key. A client that already trusts the CA can check the signature and then believe the statement.

So trust is handed on in one direction. You trust the CA once, and every certificate it signs is
trusted without any further decision. The format of the document is X.509, and the rules for using it on
the internet are in RFC 5280.

## What a certificate contains

For a server certificate the parts that matter are the **names** it is valid for, the **public key**, the
**validity period**, what the key may be **used for**, who **issued** it, and the CA's **signature**
over all of that. Each field is explained on
[Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

## What it proves

| The client checks | What that proves |
|---|---|
| The signature verifies with the CA's public key | The CA made exactly this certificate, and nobody changed it afterwards |
| The CA is one the client trusts, directly or through a chain | The statement comes from someone the client decided to believe ([How trust works]({{ '/learn/trust/' | relative_url }})) |
| The host name is in the certificate's names | The CA said this key belongs to that name |
| The current time is inside the validity period | The statement has not run out |
| During the TLS handshake the server signs with the private key that belongs to the certificate's public key | The server in front of you holds that key |

The last row matters. A certificate is public: anyone can copy it. Only the holder of the **private key**
can complete the handshake. That is why the key should never leave the host that uses it. With MyOwnPKI
a host sends a certificate signing request (CSR), which contains the public key and is signed with the
private key, so the CA never needs to see the private key. The agent works this way on every host. The
server can also generate a key for you, but a tenant can switch that off.

## What it does not prove

- **That the site is honest or safe.** A certificate says who holds the key, not what they do with it.
- **That the certificate is still good.** A key can leak before the certificate expires. The client only
  learns that if it checks revocation ([Revocation]({{ '/learn/revocation/' | relative_url }})).
- **That the CA checked carefully.** A certificate is worth what the CA's checks were worth. A public CA
  proves control of a domain. A private CA checks whatever you told it to check.
- **That the CA is limited to your names.** Unless the CA carries name constraints, a client that trusts
  it believes it for every name ([Name constraints]({{ '/learn/name-constraints/' | relative_url }})).
- **Anything about the traffic.** Encryption comes from the TLS session that the key helps to set up, not
  from the certificate itself.

## What a CA does

1. It receives a request: the public key and the names wanted.
2. It decides whether to grant it, by its own rules.
3. It builds the certificate from a fixed profile and signs it.
4. It publishes where clients find its own certificate and its list of revoked certificates.
5. It revokes a certificate when asked, and keeps that list up to date.
6. It protects its signing key. If that key leaks, everything it signed is in doubt.

## What MyOwnPKI adds

| Concern | What the server does |
|---|---|
| Checking the request | Verifies the CSR signature, applies the key policy, checks every name, the name constraints of every CA up to the root, and the validity. The CSR's names and subject are treated as a wish list; its extensions are never read. |
| What the certificate may do | Key usage, extended key usage and basic constraints come from a **preset** and the CA, never from the request. |
| A second check | After signing, the certificate is parsed and verified against the chain before it is stored. |
| Who may ask | A signed-in person with a role, an ACME client within a **domain** policy, or an agent that proved control of its host name or was approved by an admin ([ACME]({{ '/learn/acme/' | relative_url }})). All paths go through the same engine. |
| Structure | A root and intermediates, with an optional offline root ([Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }})). |
| Key protection | CA keys lie encrypted in the database; the server starts sealed ([Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }})). |
| Revocation | CRLs per CA, served over plain HTTP. There is no OCSP responder in this release. |
| Record | Every issuance, revocation and CA change goes into a hash-chained audit log. The entry is queued in the same database transaction as the change, so a change is never stored without it. |

## Next steps

- Build your own: [Installation]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).
- Read the fields of the certificate you just made: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).
- See why there are two levels of CA: [Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }}).
- Habits that follow from this page: [Best practices]({{ '/best-practices/' | relative_url }}).
