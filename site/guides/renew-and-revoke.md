---
title: "Renew and revoke certificates"
description: "How renewal works for ACME clients, the agent and the web UI, how to revoke a certificate in the UI or over ACME, when the CRL lists it, and how to check that with openssl."
permalink: /guides/renew-and-revoke/
sources:
  - docs/OPERATIONS.md
  - api/openapi.yaml
  - internal/web/app_certactions.go
  - internal/web/pages/certificates/detail.templ
  - internal/ca/revoke.go
  - internal/ca/crl.go
  - internal/server/server.go
  - internal/publish/publish.go
  - internal/authz/authz.go
---

## When to use this

Use this page to know **who renews what** and to take a certificate out of service. Renewal is a new
certificate with a new key for the same names; revocation is final and puts the serial number on the
CRL of the issuing CA, the list that clients check.

* TOC
{:toc}

## Renewal: who does it

| Path | Who renews and when | What you do |
|---|---|---|
| ACME client | The client. With ARI (lego, Caddy) the server names a window: it opens at about two thirds of the lifetime (day 60 to 63 of 90) and lasts nine days. certbot renews 30 days before expiry. | Nothing on the server |
| Agent | The agent, at two thirds of the lifetime or earlier if the ARI window asks. *Renew now* on the agent's page (operator and admin) wakes it. | Nothing; the agent deploys, tests and reloads |
| Web UI | You, with *Renew* on the certificate page (operator and admin) | Download and install the new files yourself |

**In the UI** the successor gets the same CA, preset, subject and names, and **always a new key**. If
the server holds the key you choose the algorithm of the new one; if the original came from a request,
you paste a new request made on the device. The form also asks what happens to the old certificate
(below). Over the API: `POST /api/v1/certificates/{id}/renew` (role *operator*; an API token may do it).

**What happens to the old certificate** is the *predecessor* rule. For an ACME client a completed order
replaces an older valid order of **the same account** with the identical set of names. The tenant's
*Other certificates* default then applies: at once, after 1 to 30 days, or never; the factory
value is seven days. For the agent the default is at once, after the new certificate is confirmed as
deployed and served. An admin can change the defaults in *Administration → Tenant settings* and
override them per ACME account or agent ([§10.6]({{ '/reference/operations/' | relative_url }}#106-connecting-clients)).
**Use one account per host**: hosts that share an account and the same names retire each other's
certificates. A test order counts too: a `certbot renew --dry-run` or an `acme.sh --renew --force` is a real
renewal for this rule.

## Steps: revoke in the UI

1. Open the certificate (*Certificates*) and press *Revoke now*. You need the role *operator* or *admin*
   at the issuing CA, and a **fresh second factor** (step 4).
2. Choose the reason. The UI offers `superseded`, `cessationOfOperation`, `keyCompromise`,
   `affiliationChanged`, `privilegeWithdrawn` and `unspecified`. There is no `certificateHold`: a
   revocation cannot be undone.
3. For `keyCompromise` you may enter *Compromised since* (`YYYY-MM-DD` or an RFC 3339 time). The key is
   then blocked for every later request.
4. Tick the confirmation and press *Revoke*. If your second factor is not fresh, the UI now sends you to the
   step-up page and carries out the revocation after you confirm. The message says "Revoked. The CRL of …
   lists it now."

*Plan revocation* on the same page revokes as `superseded` after 1 to 30 days; *Cancel planned
revocation* withdraws the plan before it runs. A planned revocation shows as "Revocation planned" in
the lists.

**Over the API** the operation is `POST /api/v1/certificates/{id}/revoke` with a body of `reason` and an
optional `invalidity_date`. It needs the second factor too, and an **API token never has it**, so a script with a
token gets `403` ([REST API]({{ '/reference/api/' | relative_url }}#what-a-token-cannot-do)). Revoke from the UI, or from the ACME client.

**From an ACME client**, with the account that ordered the certificate (the certificate's own key
may revoke it as well, for example after a leak, without the account):

```bash
certbot revoke --cert-path /etc/letsencrypt/live/nas.homelab.lan/cert.pem
```

```bash
lego certificates revoke --server https://pki.homelab.lan/acme/directory --path /var/lib/lego --email admin@homelab.lan --cert.name nas.homelab.lan --reason 4 --keep
```

Revoking an **agent** (*Revoke agent*) does not revoke the certificates it deployed; revoke those separately.
Certificates stored as *external* were not issued here and cannot be revoked here.

## When the CRL lists it

- **At once.** A revocation signs a new CRL of the issuing CA in the same step while the server is unsealed.
  While it is **sealed**, the revocation is stored and audited, and the CRL is signed at the next
  unseal; only then clients see it ([§10.8]({{ '/reference/operations/' | relative_url }}#108-sealed-server-rate-limits-audit)).
- **Caches.** The public listener lets a CRL be cached for 15 minutes, so a client or proxy may still
  hold the old list for that long.
- **Regular renewal.** Every 15 minutes the server checks all CRLs of its online CAs and signs a new one when a
  third of its lifetime has passed. The default lifetime is 7 days for an intermediate and 30 days for an
  online root. An **offline root** signs its CRL on the offline machine (180 days by default) and you upload it.
- **How long an entry stays.** After the certificate expires, the serial remains on the CRL until its
  expiry plus the CA's CRL lifetime, so that a regular CRL has listed it.
- A CRL that is not renewed is an alert (`crl`), see [Monitoring]({{ '/monitoring/' | relative_url }}).

## Check it worked

The address of the CRL is in the certificate, and the serial number is in the certificate:

```bash
openssl x509 -in nas.homelab.lan-fullchain.pem -noout -serial -ext crlDistributionPoints
```

Fetch the CRL (it is DER) and print it:

```bash
curl -o issuing.crl http://pki.homelab.lan/crl/issuing/1.crl
```

```bash
openssl crl -inform DER -in issuing.crl -noout -text
```

Look for the serial under *Revoked Certificates*, with its revocation date and reason. *Last Update*,
*Next Update* and *CRL Number* show when it was signed. Or let OpenSSL decide: it needs the CRL as PEM and
fails with "certificate revoked" for a listed serial:

```bash
openssl crl -inform DER -in issuing.crl -out issuing.crl.pem
```

```bash
openssl verify -crl_check -CAfile root.pem -untrusted nas.homelab.lan-chain.pem -CRLfile issuing.crl.pem nas.homelab.lan.pem
```

## When it fails

| What you see | Usually | What to do |
|---|---|---|
| No *Revoke now* link | Your role is *viewer*, or the certificate is revoked already | Ask for *operator* at the issuing CA |
| The UI sends you to a second-factor page | Revocation needs a fresh second factor | Confirm with your authenticator |
| API answers 403 | A token never satisfies the second factor | Use the UI |
| "Revoked and stored. The CRL is signed when the server is unsealed" | The server is sealed | Unseal; check the CRL afterwards |
| The serial is not on the CRL you fetched | A cached copy, or the wrong CA or generation | Wait up to 15 minutes, fetch the URL from the certificate |
| `openssl verify` says "unable to get certificate CRL" | The CRL is not the one of this certificate's issuer | Use the URL from `crlDistributionPoints` |

More in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}).

## Next steps

- Keep CRLs fresh: [Monitoring]({{ '/monitoring/' | relative_url }}); the offline root's CRL is on the
  schedule of [Best practices]({{ '/best-practices/' | relative_url }}#keep-the-root-offline).
- Renewal of agents and what the agent reports: [Adding hosts]({{ '/hosts/' | relative_url }}#renewal-renew-now-and-what-the-agent-reports).
- Clients: [certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}).
