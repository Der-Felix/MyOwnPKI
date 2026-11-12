---
title: "TLS scan"
description: "How the MyOwnPKI server checks what a host really serves: add an endpoint, read its state, what each alert means, and what to do when a scan fails."
permalink: /tls-scan/
---

Since v0.3.4 the server can check what a host **actually serves**. The alerts in
[Monitoring]({{ '/monitoring/' | relative_url }}) know what this PKI issued, so a `cert_expiry` alert
closes as soon as the replacement certificate is issued. It cannot tell you that the replacement never
reached the web server. The TLS scan closes that gap: you enter the TLS endpoints you rely on, for
example `proxy.homelab.lan:443`, and the server connects to each one every 15 minutes, reads the
certificate it presents and compares it with what this PKI issued for that name.

This is level 2 of the [three ways to connect a host]({{ '/' | relative_url }}#three-ways-to-connect-a-host):
an ACME client, or anything else, puts the certificate on the host, and the scan only watches. Nothing
is installed there. This is the condensed version of
[operations guide chapter 14]({{ '/reference/operations/' | relative_url }}#14-tls-scan).

* TOC
{:toc}

## What a scan does

A scan is **one TCP connection and one TLS handshake**, then the connection closes. The server sends no
HTTP request, no data and no client certificate, so there is nothing to redirect and nothing on the host
changes. It works while the server is sealed.

The handshake takes whatever certificate the endpoint presents, even a wrong one, because the point is to
see what is served. **Whether to trust it is decided afterwards, by the server:** it checks the chain
against the CAs of this PKI. The chain is `trusted`, `incomplete` (the endpoint does not send the
intermediate CA) or `untrusted` (it does not lead to this PKI).

The scan does not speak STARTTLS (ports 25, 143, 587), does not look at ciphers, key sizes or OCSP
stapling, and never discovers hosts: it scans what an admin entered.

## Before you start

- **A domain covers the host.** In *ACME → Domains* a domain must match the host name (the domain's own
  name, or a name below it when the domain includes subdomains), or contain the IP address in its IP
  ranges. The domain's address policy applies at every scan. Creating a domain needs a fresh second
  factor, so an API token cannot widen the set of hosts the server may connect to.
- **The port is one the server allows.** The default list is 443, 465, 636, 853, 993, 995, 5061, 6514,
  8443, 8883 and 9443 (`monitor.scan_ports`).
- **The server can reach the host**: DNS (it uses `acme.resolver` if you set one, which suits split DNS)
  and an outbound TCP connection to the port. The scan does not use the proxy variables.
- **Your role:** tenant admins add and remove endpoints, operators and admins scan now, viewers read.

## Add an endpoint

Open *Endpoints* in the menu, fill in *Add an endpoint* and press *Add endpoint*:

| Field | What to enter |
|---|---|
| Host | A fully qualified name such as `proxy.homelab.lan`, or an IP address (IPv6 without brackets). No scheme, port or wildcard. |
| Port | One of the scan ports; `443` is prefilled. |
| SNI (optional) | The name to send and to expect the certificate for. An **IP address sends none**, so give one when you enter an IP. |

The first scan runs within a minute. The state should read **OK**; compare the shown fingerprint with
what the host presents:

```bash
openssl s_client -connect proxy.homelab.lan:443 -servername proxy.homelab.lan </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

The same with an API token of the role *admin* (no second factor is needed for these calls):

```bash
export MYOWNPKI_TOKEN=mop_…
```

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" -H "Content-Type: application/json" -d '{"host": "proxy.homelab.lan", "port": 443}' https://pki.homelab.lan:9443/api/v1/endpoints
```

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/endpoints
```

`POST /api/v1/endpoints/{id}/scan` (role *operator*) scans now, once per endpoint and 60 seconds, and
`DELETE /api/v1/endpoints/{id}` (role *admin*) removes it. A refusal is `422` with the field and the
rule. The list shows the same states as the page; see [REST API]({{ '/reference/api/' | relative_url }}).

## What the states mean

| State on the page | What it means | What to do |
|---|---|---|
| **OK** | The served certificate is the one this PKI issued for the name, and the chain is trusted | Nothing |
| **Expiring** | As OK, but the served certificate ends soon | The host does not renew: fix the ACME client or the agent |
| **Not issued by this PKI** | This PKI never issued a certificate for the name, and the served one is not from here | Nothing is wrong as far as this PKI can tell. An IP address without SNI is always here: add it again with an SNI |
| **Wrong certificate**, an older certificate | The host still serves a superseded certificate of this PKI | The renewal did not reach it: reload the service, check the deployment |
| **Wrong certificate**, not issued by this PKI | This PKI issued a certificate for the name, but another CA's is served | Point the service at the certificate of this PKI |
| **Wrong certificate**, not valid for this name | A certificate of this PKI that does not cover the name | Point the service at the right one |
| **Wrong certificate**, revoked | The host serves a revoked certificate | Replace it at once |
| **Chain problem** | The right certificate, but the intermediate CA is not sent, or the chain does not lead here | Configure the service with the full chain (`fullchain.pem`) |
| **Unreachable** | The last scans failed | Read *Last error* below |
| **Refused** | No domain covers the host any more, or the address policy or port list refuses it. Not an outage | Restore the domain or the port, or remove the endpoint |
| **Pending** | Not scanned yet | Wait a minute |

A name this PKI never issued has nothing to compare with, so it raises no mismatch; an unreachable
service or an expiring certificate on it still alerts. The state is computed when you open the page, from
the last scan and the certificates as they are now.

## The alerts

Four alert kinds join those in [Monitoring]({{ '/monitoring/' | relative_url }}#the-alerts). They have
the same digest, reminder and *resolved* messages, and they never carry the subject or issuer of the
served certificate.

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `scan_mismatch` | the host serves an older, a foreign or a wrong-name certificate; **two scans in a row** saw it and the newest certificate for the name is at least `scan_mismatch_after` (1 hour) old | always | a revoked certificate, after two scans |
| `scan_expiry` | the served certificate ends within the `monitor.expiry_days` thresholds, or has ended | 14 days | 3 days, or expired |
| `scan_unreachable` | `scan_unreachable_after` (3) scans in a row failed | from then on | down for 24 hours |
| `scan_chain` | the right certificate with an incomplete or untrusted chain, seen by two scans | always | – |

The two scans and the waiting time keep a deployment that is half through quiet, and a host that only
reboots produces nothing. A failed scan keeps the last good data.

## Settings

In `config.yaml`; restart to apply. Every key is also `MYOWNPKI_MONITOR_SCAN_…` in a container.

| Key | Default | Allowed |
|---|---|---|
| `monitor.scan_interval` | `15m` | `5m` to `24h`, or `off` to never connect |
| `monitor.scan_timeout` | `10s` | `2s` to `30s` |
| `monitor.scan_ports` | `443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443` | 1 to 32 ports |
| `monitor.scan_max_endpoints` | `100` | 1 to 500 |
| `monitor.scan_unreachable_after` | `3` | 1 to 10 failed scans |
| `monitor.scan_mismatch_after` | `1h` | `5m` to `24h` |

`config check` shows them under *Alert thresholds*.

## What is stored, and what is never scanned

Per endpoint the server keeps only metadata of the last result: fingerprint, serial, subject and issuer
(clipped to 256 bytes), dates, chain state and TLS version. It never stores the certificate, a key, the
names in it or the address a name resolved to. Subject and issuer are chosen by the remote host and are
shown as plain text.

The server **never connects** to loopback, link-local, multicast, unspecified or reserved addresses, nor
to the IPv6 ranges that embed an IPv4 address (NAT64, IPv4-compatible, 6to4, Teredo). A domain set to
*public only* also refuses private networks and `100.64.0.0/10`. A name is resolved once and the
connection goes to the address that was checked. The same guard applies to http-01 validation and the
agent enrollment check. Attempts, refused ones too, are in the audit log as `endpoint.create`,
`endpoint.delete` and `endpoint.scan`.

## When it does not work

*Last error* on the page, or `last_error_kind` in the API, is one of these words:

| Last error | Likely cause | Fix |
|---|---|---|
| `dns` | The name does not resolve from the server | `getent hosts` on the server; with split DNS set `acme.resolver` |
| `timed out` | The host is down or a firewall drops the packets | Check route and firewall from the server |
| `connection refused` | Nothing listens on the port | Start the service or correct the port |
| `could not connect` | No route, network unreachable, a reset | As for a timeout |
| `TLS handshake failed` | The port is not TLS from the first byte (plain HTTP, a STARTTLS port), or the service speaks only TLS 1.0 or 1.1 | `openssl s_client` shows which; remove a STARTTLS endpoint |
| `no certificate` | The server presented no certificate | Rare; the scan cannot judge such a service |
| `client certificate required` | The service demands a client certificate | It cannot be scanned and raises no alert: remove the endpoint |
| `refused by the address policy` | Every address of the name is in a refused range | Look at what the name resolves to |
| `no domain covers the host` | The domain was removed or narrowed | Restore the domain or remove the endpoint |
| `port is not in monitor.scan_ports` | The port list was changed | Put the port back or remove the endpoint |

More symptoms, the refusals when adding an endpoint and an end-to-end check are in
[operations guide §14.10 and §14.11]({{ '/reference/operations/' | relative_url }}#1410-when-something-does-not-work).
Other scan problems are in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#tls-scan).
