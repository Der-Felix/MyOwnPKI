---
title: "Glossary"
description: "Plain definitions of the PKI, ACME and MyOwnPKI terms used in this documentation, in alphabetical order, each with a link to the page that explains it in the product."
permalink: /glossary/
sources:
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - README.md
  - CHANGELOG.md
  - internal/authz/authz.go
  - presets/README.md
---

Every term is defined as this product uses it. Where a term comes from a standard, the definition
follows it: X.509 certificates and CRLs are RFC 5280, ACME is RFC 8555, ACME renewal information is
RFC 9773. The links lead to the page that shows the term in use.

[A](#a) · [B](#b) · [C](#c) · [D](#d) · [E](#e) · [F](#f) · [G](#g) · [H](#h) · [I](#i) · [J](#j) ·
[K](#k) · [L](#l) · [N](#n) · [O](#o) · [P](#p) · [R](#r) · [S](#s) · [T](#t) · [V](#v) · [W](#w)

## A

### Account

An ACME client's identity at the server: a key pair that the client creates (RFC 8555), under which it
places orders. On this server a new account waits for an admin's approval under the default approval
level, or comes with an [EAB](#eab-external-account-binding) key. Use one account per host.
See [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### ACME

Automatic Certificate Management Environment, RFC 8555: the protocol with which a client asks a CA for
certificates and proves that it controls the names. MyOwnPKI is an ACME **server** for your own CAs and
supports the [http-01](#http-01) and [dns-01](#dns-01) challenges. It is not an ACME client for public CAs.
See [operations guide chapter 10]({{ '/reference/operations/' | relative_url }}#10-acme-server).

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### Agent

`myownpki-agent`, an optional program for a Linux host. It enrolls, gets certificates over ACME, writes the
files, runs the [hooks](#hook) you configured, reloads the service, rolls back on failure and reports to the
server. It takes no commands from the server. See [Adding hosts]({{ '/hosts/' | relative_url }}).

### AIA (authority information access)

A certificate extension that says where to fetch the issuer's certificate (RFC 5280 §4.2.2.1). MyOwnPKI
writes an address on the [public listener](#public-listener) into it, built from the [base URL](#base-url),
the CA's name and its [generation](#generation).
See [What runs where]({{ '/install/' | relative_url }}#what-runs-where).

### Alert

One condition that the server watches, such as an expiring certificate, a [CRL](#crl) that is not renewed, a
server that stays [sealed](#seal-and-unseal) or a silent agent. An alert is *warning* or *critical*, shows on
the Alerts page, and closes by itself when the cause is gone; e-mail and webhook messages are optional.
See [Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts).

### API token

A secret starting with `mop_` that a script uses instead of a sign-in. It carries a [role](#role) its owner
has, never more, ends within one year, and can never satisfy a [step-up](#step-up). See
[REST API]({{ '/reference/api/' | relative_url }}#make-an-api-token).

### ARI (ACME renewal information)

RFC 9773: the server tells the client when to renew. Here the window opens at about two thirds of the
lifetime and lasts nine days; a revoked certificate gets a window in the past, so its client renews at once.
Clients without ARI use their own rule. See
[operations guide §10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients).

Background: [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).

### Audit log

The record of every action and every refusal, kept as a [hash chain](#hash-chain) with signed
[checkpoints](#checkpoint). There is an instance log (sign-ins, users, unseal) and a tenant log.
`myownpki audit verify` checks it. See
[Verify the audit log]({{ '/best-practices/' | relative_url }}#verify-the-audit-log-now-and-then).

### Authorization

In ACME (RFC 8555), the server's record that an [account](#account) may get certificates for one name,
proven by completing one [challenge](#challenge). An [order](#order) lists one authorization per name.

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

## B

### Backup

A consistent copy of every database that `myownpki backup` writes while the server runs, with a manifest of
hashes. It contains the CA keys, **encrypted**: a backup alone cannot sign, but a backup together with the
[passphrase](#passphrase) or the [recovery key](#recovery-key) can. See
[operations guide §6]({{ '/reference/operations/' | relative_url }}#6-backup-and-restore).

### Base URL

The public address of the server, for example `http://pki.homelab.lan`, that is written into every
certificate a CA issues (the [CRL](#crl) and [AIA](#aia-authority-information-access) addresses). It cannot be
changed for a CA afterwards, so choose a stable DNS name. See
[What runs where]({{ '/install/' | relative_url }}#what-runs-where).

### Basic constraints

A certificate extension (RFC 5280 §4.2.1.9) that says whether the certificate belongs to a CA (`CA:TRUE`) and,
for a CA, its [path length](#path-length). CA certificates here carry it as critical; certificates for
servers and users say `CA:FALSE`.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

### Bootstrap certificate

The self-signed certificate that the admin listener serves until it can get one from your CA
(`admin.tls_issuer`). You compare its [fingerprint](#fingerprint) with the one in the log once. The ACME
listener serves a bootstrap certificate too when its own TLS has no issued certificate yet. See
[operations guide §2.4]({{ '/reference/operations/' | relative_url }}#24-certificates-the-server-issues-itself-tls_issuer).

## C

### CA (certificate authority)

An entity that signs certificates. In MyOwnPKI a CA is a [root](#root-ca) or an
[intermediate](#intermediate-ca) with a name that never changes, a key (online and encrypted, or offline),
a maximum validity and one or more [generations](#generation). See
[First CA and first certificate]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).

Background: [What is a certificate authority?]({{ '/learn/what-is-a-ca/' | relative_url }}).

### Chain

The path from a certificate through its intermediates to a root. A server should send its own certificate
and the intermediates (the *fullchain* download); the client already holds the root. The
[TLS scan](#tls-scan) reports a chain as *trusted*, *incomplete* (intermediates missing) or *untrusted*. See
[What the states mean]({{ '/tls-scan/' | relative_url }}#what-the-states-mean).

Background: [How trust works]({{ '/learn/trust/' | relative_url }}).

### Challenge

A test that the ACME server gives to prove control of a name. This server knows [http-01](#http-01) and
[dns-01](#dns-01). The [validator](#validator) runs it.

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### Checkpoint

A signed entry in the [audit log](#audit-log): Ed25519, made at unseal, before seal, daily and every 1000
entries, with a key derived from the root key. Pinning its fingerprint with `audit verify --checkpoint-key`
shows that the log is the one you had. Write the fingerprint down at `init`.

### CN (common name)

An attribute of a certificate's subject name. Modern clients match a host name against the
[SAN](#san-subject-alternative-name), not the CN, so the SAN must hold every name. Some presets derive the CN
from the first SAN.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

### CRL

Certificate revocation list (RFC 5280 §5): a list, signed by a CA, of the serial numbers it has revoked, with a
number and a next-update time after which it must not be relied on. MyOwnPKI publishes one CRL per CA
[generation](#generation) over plain HTTP on the [public listener](#public-listener), renews it after a third
of its life, and writes its address into every certificate. The CRL of an [offline root](#offline-root) is
signed offline and uploaded. See [Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts).

Background: [Revocation]({{ '/learn/revocation/' | relative_url }}).

### CSR

Certificate signing request (PKCS #10): a public key and a wish list of names, signed with the private key, so
the key itself never leaves the host. The server takes only the names from a CSR; extensions are never copied
from it, they come from the [preset](#preset). See
[the first certificate]({{ '/install/' | relative_url }}#the-first-ca-and-the-first-certificate).

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

## D

### Deployment

In the agent, one certificate setup on a host: the names, the challenge mode, where the files go (profile
`nginx` or `file`), the test and reload [hooks](#hook) and an optional local TLS check. `myownpki-agent
deployment add` writes it. See [Adding a deployment]({{ '/hosts/' | relative_url }}#adding-a-deployment-deployment-add).

### dns-01

The ACME challenge in which the client puts a TXT record at `_acme-challenge.<name>` (RFC 8555 §8.4). The server
only reads it, through `acme.resolver`. It is the only challenge that proves a [wildcard](#wildcard-certificate).
The agent can do it since v0.3.7, through [RFC 2136](#rfc-2136) or Cloudflare; see
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). For split DNS see
[operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### Domain

An ACME domain is a rule under *ACME → Domains*: which names below it may be ordered, which CA signs, which
challenges and wildcards are allowed, the approval level, the [preset](#preset) and validity, and which
addresses the server may connect to. Without a domain that covers a name, ACME, agent enrollment and the
[TLS scan](#tls-scan) refuse it. See
[operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).

## E

### EAB (external account binding)

RFC 8555 §7.3.4: a key ID and a MAC key that the CA gives out of band, so that a new
[account](#account) is bound to something the CA already knows. Here an admin creates the key under *ACME → EAB
keys*; it shows once, binds one account, expires (7 days by default) and lets the client skip the approval
queue.

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

### EKU (extended key usage)

A certificate extension (RFC 5280 §4.2.1.12) that lists what the certificate may be used for, such as
`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping` or `OCSPSigning`. A CA can carry an
EKU limit that narrows what everything below it may do; the agent CA must be limited to `clientAuth`.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

### Enrollment

How a host becomes an [agent](#agent): it makes a key and a [CSR](#csr), proves control of its name (the server
fetches a check file by http-01), and is admitted according to the tenant's enrollment mode: `verified` (the
default), `auto` or `manual`. See [Admission]({{ '/hosts/' | relative_url }}#admission-token-check-approval).

### Enrollment pass

A [join token](#join-token) for a bounded number of hosts (2 to 25), for names that match a pattern, valid up to
7 days, so that automation can enroll hosts without a person opening the UI for each. An admin creates it with a
fresh second factor; an API token never can. See
[the enrollment pass]({{ '/hosts/' | relative_url }}#the-enrollment-pass-for-roll-outs).

## F

### Fingerprint

A hash, usually SHA-256, of a certificate's DER encoding, written as hex. You compare a fingerprint of a root you
got over an untrusted path with one from a trusted source. The trust page also shows a SHA-1 value, only for the
Windows certificate dialog.

Background: [How trust works]({{ '/learn/trust/' | relative_url }}).

## G

### Generation

Each key of a CA with its certificate is one generation. Renewing a CA with a new key starts the next one, and
the old generation keeps its URL and its [CRL](#crl), so older certificates still validate.

## H

### Hash chain

A log in which every entry's hash includes the hash of the entry before it, so changing or removing an entry
breaks every later link. The [audit log](#audit-log) is one.

### Hook

A command named under `hooks:` in the agent's local `agent.yaml`, such as `nginx -t` or a service reload, that a
[deployment](#deployment) runs. Only hooks from that root-owned file ever run; the server cannot add one. See
[agent.yaml]({{ '/hosts/' | relative_url }}#agentyaml).

### http-01

The ACME challenge in which the server fetches a token over HTTP from port 80 of the name, at
`/.well-known/acme-challenge/` (RFC 8555 §8.3). The server must be able to reach that port. See
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

## I

### Instance admin

A user who may [unseal](#seal-and-unseal) and seal the server and manage users. That role alone gives no rights in
the PKI of a tenant. See [Role](#role).

### Intermediate CA

A CA that a root (or another intermediate) has signed and that issues the certificates you use. Keeping the
daily signing here and the root offline means a leaked intermediate is replaced, not every client. Narrow it
with [name constraints](#name-constraints), an [EKU](#eku-extended-key-usage) limit and a
[path length](#path-length). See
[Best practices]({{ '/best-practices/' | relative_url }}#narrow-every-ca-with-name-constraints).

Background: [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

## J

### Join token

A single-use secret, starting with `mjt_`, that lets one host [enroll](#enrollment). It is tied to a host name or
a pattern. The guided one expires after 15 minutes. See
[Admission]({{ '/hosts/' | relative_url }}#admission-token-check-approval).

## K

### Key usage

A certificate extension (RFC 5280 §4.2.1.3) with the basic operations the key may do, such as
`digitalSignature`, `keyEncipherment`, `keyCertSign` and `cRLSign`. It is always critical here. The
[preset](#preset) sets it for end-entity certificates; CA certificates also get `keyCertSign` and `cRLSign`.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

## L

### Leaf certificate

A certificate that is not a CA: the one for a server, a user or a device (an end-entity certificate, `CA:FALSE`).
The engine refuses to issue one from a root. See [Which certificates can I issue]({{ '/faq/' | relative_url }}#what-kinds-of-certificates-can-i-issue).

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

## N

### Name constraints

A CA certificate extension (RFC 5280 §4.2.1.10) that limits the names of every certificate below it to permitted
subtrees, such as a DNS suffix or an address range. Clients enforce it, and MyOwnPKI checks it before it signs.
It makes a stolen intermediate key much less useful. See
[Best practices]({{ '/best-practices/' | relative_url }}#narrow-every-ca-with-name-constraints).

Background: [Name constraints]({{ '/learn/name-constraints/' | relative_url }}).

## O

### OCSP

Online Certificate Status Protocol (RFC 6960): a client asks a responder about one certificate. MyOwnPKI has no
OCSP responder; it publishes [CRLs](#crl). An OCSP responder is planned after version 1.0, and the `ocsp` preset
only issues a certificate for one.

Background: [Revocation]({{ '/learn/revocation/' | relative_url }}).

### Offline root

A root whose private key is not on the server; the server holds only its certificate. An intermediate below it
is made by taking a CSR and an extension file to the machine that has the key, signing exactly that file, and
uploading the result. The root's CRL is signed there too and uploaded. See
[Keep the root offline]({{ '/best-practices/' | relative_url }}#keep-the-root-offline).

Background: [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

### Order

In ACME (RFC 8555), a client's request for a certificate for a set of names. It has one
[authorization](#authorization) per name, ends with the client's [CSR](#csr) (*finalize*), and is *pending*,
*ready*, *processing*, *valid* or *invalid*. While the server is sealed, a finalized order stays *processing*.
The UI lists them under *ACME → Orders*.

Background: [ACME explained]({{ '/learn/acme/' | relative_url }}).

## P

### Passphrase

The unseal passphrase, at least 16 characters, that you set at `init`. A key derived from it with Argon2id
decrypts the root key that protects every CA key. It is not your sign-in password, and it is not stored on the
server. See [Installation]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key).

Background: [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}).

### Path length

The `pathlen` value in [basic constraints](#basic-constraints) (RFC 5280 §4.2.1.9): how many intermediate CAs may
follow below this CA. `pathlen:0` means it can issue only end-entity certificates. The agent CA must sit directly
below the root, not below a CA with `pathlen:0`.

Background: [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

### PKI

Public key infrastructure: the CAs, the rules, the software and the procedures that issue, distribute, check and
revoke certificates. MyOwnPKI runs one for your own network.

### Policy

What the server checks before every signature, whatever the client claims: the key, the names, the preset's
rules, the [name constraints](#name-constraints) and EKU limits of every CA up to the root, and the validity. For
ACME, the [domain](#domain) adds its own rules. A refusal is written to the [audit log](#audit-log).

### Predecessor

The earlier certificate that a renewal replaces. The tenant settings decide whether it is revoked, with the
reason `superseded`: for agent deployments by default right after the new certificate is confirmed as deployed,
for other certificates by default after seven days. See
[Renewal and what the agent reports]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).

### Preset

A built-in profile for a kind of certificate: key usage, extended key usage, required names, default validity.
There are twelve, for example `server`, `client`, `smime` and `wildcard`. The extensions of a certificate always
come from the preset, never from the [CSR](#csr).

### Public listener

The plain-HTTP listener without a login that serves the CRLs, the CA certificates and the trust page. It speaks
HTTP on purpose, because clients fetch from it before they trust anything. See
[What runs where]({{ '/install/' | relative_url }}#what-runs-where).

## R

### Recovery key

A second secret that can open the CA keys, created once at `init` and shown once (nine groups of six
characters). It protects the same root key as the [passphrase](#passphrase), and `myownpki passphrase reset`
uses it to set a new passphrase when the old one is lost. In this release the UI and `serve --unseal` accept
only the passphrase, so you unseal with the new one afterwards. Keep it on paper, apart from the passphrase
and the backups. See
[operations guide §7]({{ '/reference/operations/' | relative_url }}#7-passphrase-and-recovery-key).

Background: [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}).

### Revocation

Declaring a certificate invalid before its end date, with an RFC 5280 reason such as `keyCompromise` or
`superseded`. It is final (there is no hold) and shows in the next [CRL](#crl). `keyCompromise` also blocks that
key for every later request. See
[operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong).

Background: [Revocation]({{ '/learn/revocation/' | relative_url }}).

### RFC 2136

The standard for dynamic DNS updates: a client sends a signed message that adds or removes records in a zone.
The agent uses it for [dns-01](#dns-01), signed with a [TSIG](#tsig) key, against BIND, Knot or PowerDNS. See
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}).

### Role

What a user may do in a tenant, optionally limited to one CA. *Viewer* reads; *operator* also issues, renews,
revokes, downloads server-made keys, scans endpoints and renews agent deployments; *admin* also manages CAs, ACME
approvals, domains, agents, settings and reads the audit log. Revoking, key export and the admin actions need a
fresh [step-up](#step-up).

### Root CA

A self-signed CA certificate that clients trust directly, so it is the starting point of every chain. Here a root
signs only other CAs and CRLs. Nobody above it can revoke it: clients stop trusting it only when you remove it
from their [trust stores](#trust-store). See [Keep the root offline]({{ '/best-practices/' | relative_url }}#keep-the-root-offline).

Background: [Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

## S

### SAN (subject alternative name)

A certificate extension (RFC 5280 §4.2.1.6) with the names the certificate is valid for: DNS names, IP addresses,
e-mail addresses and URIs. TLS clients match the host name against the SAN. The `server` preset requires at least
one DNS or IP name.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

### Sandbox

The systemd restrictions under which the server and the agent run. The agent's writable paths are listed in the
drop-in `10-paths.conf`, which `setup`, `deployment add` and `sandbox sync` keep in step with `agent.yaml`. See
[The systemd sandbox and paths]({{ '/hosts/' | relative_url }}#the-systemd-sandbox-and-paths).

### Seal and unseal

The server starts **sealed**: the CA keys are encrypted and cannot be used. An instance admin **unseals** it with
the [passphrase](#passphrase) (a lost one is replaced with the [recovery key](#recovery-key)), which decrypts
the root key into memory.
*Seal* removes it again. While sealed the server serves CRLs and CA certificates but signs nothing, so a long seal
lets the CRLs run out. See
[Know what a sealed server means]({{ '/best-practices/' | relative_url }}#know-what-a-sealed-server-means).

Background: [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}).

### Serial number

A number that identifies a certificate among those of one issuer. MyOwnPKI uses a random 159-bit serial, unique per
CA, and a [CRL](#crl) lists revoked certificates by serial number.

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).

### Split DNS

Names that resolve one way inside your network and another way, or not at all, outside. The ACME server's
[validator](#validator) uses `acme.resolver` to ask the DNS server that knows your internal names. See
[operations guide §10.7]({{ '/reference/operations/' | relative_url }}#107-split-dns-and-the-network).

### Standalone and webroot

The two ways the agent answers [http-01](#http-01). *Standalone*: the agent listens on port 80 for the moment of
the check, which needs the low-ports drop-in. *Webroot*: it writes the token into a directory that your web server
already serves. Webroot is recommended when a web server runs. See
[Best practices]({{ '/best-practices/' | relative_url }}#prefer-webroot-to-standalone-when-a-web-server-runs).

### Step-up

A fresh second-factor check that sensitive actions ask for even in a signed-in session: revoking, downloading
keys, CA operations, user and agent management, changing the agent enrollment mode. A confirmation stays valid for
5 minutes by default (a tenant admin can choose 5, 10, 15, 30 or 60). An [API token](#api-token) can never do it.
See [operations guide §4]({{ '/reference/operations/' | relative_url }}#step-up-confirmation-lifetime).

## T

### Tenant

The unit that holds its own CAs, certificates, domains, settings and audit log. The server has one tenant,
`default`; a tenant UI comes later.

### TLS scan

The server connects to endpoints an admin entered, does one TLS handshake, and compares the certificate that is
served with the ones this PKI issued. It raises alerts for a wrong, expiring or incomplete certificate and for an
endpoint that is down. It sends no request and runs while sealed. See [TLS scan]({{ '/tls-scan/' | relative_url }}).

### TOTP

Time-based one-time password (RFC 6238): the six-digit code from an authenticator app. It is the second factor of
every user here, set up at `init` or confirmed at a new user's first sign-in, with recovery codes as a spare. See
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in).

### Trust page

The page at `/` of the [public listener](#public-listener) where every root can be downloaded (DER and PEM), with
its SHA-256 fingerprint, two Windows helper scripts and guides for Windows, macOS, iOS, Android, Linux and Firefox.
It can be switched off in the tenant settings. See
[operations guide chapter 11]({{ '/reference/operations/' | relative_url }}#11-the-public-trust-page).

### Trust store

The set of root certificates that a system or an application trusts: the operating system's store, or the one of
Firefox and Java. A certificate is accepted only if its [chain](#chain) ends at a root in the store, which is why
your own root must be added to every client. See
[Trusting your root on the clients]({{ '/reference/operations/' | relative_url }}#104-trusting-your-root-on-the-clients).

Background: [How trust works]({{ '/learn/trust/' | relative_url }}).

### TSIG

A shared secret that signs DNS messages (RFC 8945), so a DNS server knows who sends an update and the sender
knows the answer is genuine. The agent's [RFC 2136](#rfc-2136) provider needs a key name and a base64 secret
in its root-only credentials file, and accepts `hmac-sha256`, `hmac-sha384` and `hmac-sha512`. See
[dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}#rfc-2136-with-a-tsig-key-bind-knot-powerdns).

## V

### Validator

The part of the ACME server that checks a [challenge](#challenge). It resolves the name once and connects to
exactly the address it checked, never to loopback, link-local and other ranges that are refused, and tells the
client only the kind of failure. See
[operations guide §14.8]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned).

### Validity period

The time between `notBefore` and `notAfter` in which a certificate is valid. ACME certificates default to 90 days,
the presets have their own defaults, and each CA has a maximum validity that caps both. Short lifetimes are
practical when renewal is automatic.

Background: [Lifetimes and renewal]({{ '/learn/lifetimes/' | relative_url }}).

## W

### Wildcard certificate

A certificate for `*.homelab.lan`: it covers exactly one label below the name (`nas.homelab.lan`, not
`a.b.homelab.lan` and not `homelab.lan` itself). Here it comes from the `wildcard` preset, or over ACME from a
[domain](#domain) that allows wildcards (off by default), proven by [dns-01](#dns-01).

Background: [Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}).
