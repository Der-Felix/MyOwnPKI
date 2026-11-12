---
title: "REST API"
description: "How to call the MyOwnPKI REST API: the base URL, API tokens, conventions, and what a token can and cannot do."
permalink: /reference/api/
---

Everything the web UI does goes through the REST API of the admin listener, with the same permission
checks. The description of every operation is the OpenAPI 3.1 file
[`api/openapi.yaml`](https://github.com/Der-Felix/MyOwnPKI/blob/main/api/openapi.yaml) in the
repository. This page explains how to call it and what to expect.

* TOC
{:toc}

## Where it is

The API is served only on the **admin listener**, over HTTPS, under `/api/v1`:

```text
https://pki.homelab.lan:9443/api/v1
```

It is not on the public listener, and not on the ACME listener. The ACME protocol itself (RFC 8555) is
not part of this API. The listener's own `GET /healthz` is the health check.

## Make an API token

Sign in to the UI and open *My account*. Under *New API token* give a name, a **role** with its scope
(the tenant, or one CA), and a validity. Creating a token needs a fresh second factor. The secret
starts with `mop_` and is shown **once**.

- A token carries roles its owner has, **never more**, and ends within one year.
- You can list your own tokens, and revoke one; it stops working at once.
- Give each script its own token with the smallest role. For anything that only reads, use *viewer*.

Call the API with the token in a header. Pass the root as the trust anchor:

```bash
export MYOWNPKI_TOKEN=mop_…
```

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/system/status
```

## What a token cannot do

An API token **never satisfies the fresh second factor** that some operations require, because no
code can make a token fresh. Such a request answers `403` with the problem type `forbidden`. This covers:

- revoking certificates, and downloading or exporting private keys;
- creating, renewing, retiring and revoking CAs, and uploading a root's CRL;
- managing users;
- managing agents: creating join tokens, approving or denying enrollments, disabling or revoking an
  agent. (Reading them is allowed.)
- creating other API tokens.

Issuing and renewing certificates, reading CAs, certificates, agents, alerts and the audit log, and
sending the test notification are allowed for the right role. A sign-in session in the browser can do
everything its roles allow, after the step-up.

## Conventions

- JSON with `snake_case` fields. Times are RFC 3339 in UTC. Serial numbers and fingerprints are
  upper-case hex without separators.
- A request with a body must send `Content-Type: application/json` (else `415`). Unknown fields and
  trailing data are refused (`400`). Bodies are limited to 128 KiB (`413`).
- Errors are `application/problem+json` (RFC 9457). The `type` is a URN such as
  `urn:myownpki:problem:forbidden`. Every response has an `X-Request-ID`, repeated in problems as
  `request_id`; quote it when you report a problem.
- Lists are paged with a cursor: `limit` (at most 100) and `cursor`; the answer has `next_cursor`.
- What you may not read answers `404`, like an unknown ID, so nobody can probe what exists. What you may
  read but not change answers `403`.
- A browser session sends the cookie `__Host-myownpki_session` and an `X-CSRF-Token` header on
  changing requests. A token needs neither.
- While the server is sealed, operations that sign answer `503`; reading works.

## Operation groups

| Group | Examples | Minimum role |
|---|---|---|
| system | `GET /system/status`, `POST /system/unseal`, `POST /system/seal` | signed in; unseal and seal need an instance admin |
| auth, users | sign-in, step-up, `GET /users`, own password and second factor | varies |
| tokens | `GET /tokens`, `POST /tokens`, `DELETE /tokens/{tokenId}` | signed in |
| settings | `GET /settings`, `PUT /settings` | viewer reads, admin changes |
| domains, acme | `GET /domains`, ACME accounts and their predecessor policies | viewer / admin |
| cas | `GET /cas`, `POST /cas`, `/cas/{caId}/certificate`, `/cas/{caId}/crl` | viewer reads, admin changes |
| certificates | `GET /certificates`, `/certificates/{id}/download/{format}`, `…/renew`, `…/revoke` | viewer reads; operator issues, renews and revokes (revoking needs the second factor) |
| imports | legacy `pki.sh` import, external certificates | admin |
| audit | `GET /audit`, `POST /audit/verify` | per operation, see the OpenAPI file |
| agents | `GET /agents`, `/agent-enrollments`, `/agent-join-tokens`, `…/deployments/{name}/renew` | viewer reads, operator renews, admin manages |
| monitoring | `GET /alerts`, `POST /notifications/test` | viewer reads, admin tests |

The OpenAPI file has the exact paths, parameters and the role each operation needs (`x-required-role`),
and marks operations that need a fresh second factor (`x-step-up: true`).

## Examples

The open alerts:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/alerts?state=open"
```

The admitted agents and their deployments:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/agents
```

The first 20 certificates:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/certificates?limit=20"
```

A test message through the notification channels (the token needs the tenant *admin* role):

```bash
curl -sS --cacert root.pem -X POST -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/notifications/test
```
