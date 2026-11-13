---
title: "Lifetimes and renewal"
description: "Why certificates should be short-lived, which lifetimes MyOwnPKI uses by default, when clients and the agent renew, what the monitor alerts on, and how to plan the lifetimes of the CAs."
permalink: /learn/lifetimes/
sources:
  - presets/*.yaml
  - internal/ca/profile.go
  - internal/ca/validity.go
  - internal/ca/domains.go
  - internal/acme/ari.go
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - .claude/skills/myownpki/references/pki-rules.md
---

Every certificate has an end date. The only question is how far away it is. This page gives the reasons
for short lifetimes, the numbers MyOwnPKI uses, and the order in which the CAs and the certificates under
them must end.

* TOC
{:toc}

## Why short

- **A leaked key stops being useful by itself.** Revocation is unreliable ([Revocation]({{ '/learn/revocation/' | relative_url }})),
  expiry is not. A certificate that ends in 90 days limits the harm of a leak to 90 days at most.
- **Names and keys change.** A host is renamed, a service is retired. Short lifetimes clean up after you.
- **It forces automation**, and automation is the thing that works: a renewal that runs every 60 days
  is tested every 60 days. A manual yearly task is forgotten.

The price is that **renewal must never fail silently**. That is what monitoring is for (below).

Public CAs are being pushed the same way. Under CA/Browser Forum ballot SC-081 their certificates are
capped at 200 days from 2026-03-15, 100 days from 2027-03-15 and 47 days from 2029-03-15. This does not bind
a private CA, but it shows where clients and tools are going.

## The numbers in MyOwnPKI

| What | Default | Where it is set |
|---|---|---|
| Certificate by UI or API | The preset's days: 397 for server, wildcard and server-client; 730 for client, user, smime and VPN; 1095 for codesign; 1825 for timestamp; 365 for ocsp and custom. A default above the CA's maximum is shortened to it. | The preset, or an explicit request |
| Certificate by ACME | **90 days** | The domain |
| Longest leaf a CA allows | 397 days; allowed 1 to 3650 | *Max validity* of the CA |
| Agent client certificate | 7 days | Fixed |
| Listener certificates that the server issues itself | 90 days at most, renewed at two thirds | `admin.tls_issuer`, `acme.tls_issuer` |
| EAB key | 7 days | EAB key creation |
| Root CA | 7300 days (20 years) | CA creation |
| Intermediate CA | 3650 days (10 years), never beyond its parent | CA creation |
| CRL | 7 days intermediate, 30 days online root, 180 days offline root; allowed 1 to 366 | CA settings |

With the default maximum of 397 days, the presets with 730 days or more therefore get 397 days unless you
raise the maximum of the CA. The 397 days of the server preset are just under the 398 days that were the
limit for public certificates before SC-081. Two rules decide the actual lifetime:

- An **explicit request is never changed silently**: it is accepted, or refused with the reason. A
  **default** is adapted: it is shortened to the CA's maximum and to the end of the CA certificate, and a
  note says so.
- **A CA never issues beyond its own end.** A certificate cannot outlive the CA that signed it.

`notBefore` is set 5 minutes back, so a client whose clock is slightly behind accepts a new certificate.
Keep the time right on the server and on the clients.

## Who renews, and when

| Renewed by | Moment |
|---|---|
| The agent | At two thirds of the lifetime, or earlier if the server's ARI window asks for it. *Renew now* in the UI starts it at once. |
| ACME clients with ARI (lego, Caddy) | When the server's window says: it opens at about two thirds of the lifetime, 9 days wide for 90 days |
| certbot | 30 days before expiry |
| The server, for its own listener certificates | At two thirds, and at once when the names change or the certificate is revoked |
| You, for a certificate you issued in the UI and installed by hand | By a reminder, or because the monitor told you |

After a renewal the old certificate is revoked according to the tenant's predecessor setting (the agent
default is after the new one is confirmed deployed; other certificates after seven days).

## What the monitor tells you

Every minute the server checks the following. The defaults are configurable under `monitor.*`.

| Alert | Opens | Meaning |
|---|---|---|
| `cert_expiry` | 14 days (warning) and 3 days (critical) before the end, when no newer valid certificate covers the same names | A renewal did not happen |
| `ca_expiry` | 90 days and 30 days before a CA's certificate ends | Everything below it stops validating on that day |
| `crl` | Half of a CRL's life passed without renewal, or past `nextUpdate` | A sealed server or an offline root CRL that was not renewed |
| `agent_certificate` | An agent's 7-day certificate has less than 48 hours left | The agent cannot reach the server any more |

The alert `cert_expiry` closes when the replacement is **issued**, not when it is deployed. To check what a
host really serves, use the [TLS scan]({{ '/tls-scan/' | relative_url }}).

## Planning the CA lifetimes

The rule is simple: **each level ends after the level below it.** Leaf, then intermediate, then root.

- **The root lives longest.** Replacing it touches every client, so you want to do that rarely. The default is
  20 years. A common recommendation, not a default: 10 years or more.
- **An intermediate lives shorter**, because it is online and exposed to more risk. The default is 10 years.
  A few years, if you are willing to renew it on a schedule, is a common recommendation (not a default).
- **Renew an intermediate well before its end.** A renewal makes a **new key**, the next generation of the
  same CA name. Certificates issued before keep chaining to the old generation until they end, and new ones
  come from the new generation. The `ca_expiry` alert starts 90 days ahead; use that time. If you
  renew a **root**, clients need the new root before the old one ends.
- **Leaf certificates are the shortest**, as short as your automation allows.
- A leaf cannot be longer than the time left on its CA. An intermediate that ends in 60 days issues
  default certificates that end in 60 days at most.

## Next steps

- Check the habit list: [Best practices]({{ '/best-practices/' | relative_url }}#protect-the-keys-and-give-them-an-end-date)
  and [automate renewal]({{ '/best-practices/' | relative_url }}#automate-renewal-and-keep-certificates-short).
- Set up the alerts: [Monitoring]({{ '/monitoring/' | relative_url }}#thresholds).
- Renewal from the host side: [Adding hosts]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).
- ACME renewal and ARI: [ACME explained]({{ '/learn/acme/' | relative_url }}).
- Renewing a CA: [Root and intermediate]({{ '/learn/root-and-intermediate/' | relative_url }}).
- Domain lifetimes: [operations guide §10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys).
