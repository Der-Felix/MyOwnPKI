---
title: "Preview a certificate before you issue it"
description: "See what the policy would do with a request before anything is signed: the Review step of the issue wizard and POST /certificates/preview show the verdict, the reasons, the checks, the names, the key, the validity, the extensions, the chain and the URLs."
permalink: /guides/preview-a-certificate/
sources:
  - docs/OPERATIONS.md
  - docs/PHASE3.md
  - internal/ca/plan.go
  - internal/ca/engine.go
  - internal/web/app_issue.go
  - internal/web/app_issue_plan.go
  - internal/web/pages/certificates/plan.templ
  - internal/httpapi/pki.go
  - internal/httpapi/preview.go
  - api/openapi.yaml
---

## When to use this

Use the preview when you want to know **what a request would produce, and whether the policy would refuse it,
before a certificate exists**: you are unsure which names a CA's constraints allow, you want to see the
validity a CA caps, or a script should find out whether a request is acceptable without issuing it. Since
v0.3.10 the *Review* step of the issue wizard shows the preview, and the REST API has
`POST /api/v1/certificates/preview`.

Nothing is signed, nothing is stored, no key and no serial number are drawn and no audit entry is written, not
even for a refusal. Submitting a refused request for real does write a `certificate.issue` entry marked as
denied; the preview does not.

* TOC
{:toc}

## Before you start

- You may issue on the CA. The preview needs exactly the permission that issuing needs: *operator* or *admin* on
  that CA or on the whole tenant. A *viewer* gets `403` from the API, and a role that may not read the CA at all
  gets `404`, as for issuing. It needs no second factor, so an API token works.
- The wizard needs an online intermediate to sign with ([Issue a first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }})).
- A sealed server previews too (see [what you see](#what-you-see)): the policy is decided, and the page says that
  issuing is possible after an unseal.

## Steps: in the wizard

1. Open *Certificates → New certificate* and go through **Preset**, **Key** and **Names** as before.
2. Press *Next* on the Names step. The **Review** step opens with the preview. Read it from
   the top: the verdict, then the checks, then what would be issued.
3. If the verdict is *Allowed*, press *Issue certificate*. The engine checks everything again at that moment.
4. If the verdict is *Refused*, the *Issue certificate* button is disabled; *Back* still works. Change what the reasons
   name (the preset, the names, the key or the validity) and come back to the Review step.

The preview is made again every time the Review step opens, and again after a submit that was refused, so it
always matches the form you are about to send.

## What you see

The sections of the Review step, from the top:

| Section | What it says |
|---|---|
| **Review** | The verdict, *Allowed* or *Refused*, one message line per reason, a warning when the server is sealed, and "Prepared at hh:mm UTC". It says that this is a forecast, not a promise |
| **Policy checks** | One row per check with the result *Passed*, *Refused* or *Refused, stopped here*, and the problems of that check |
| **What would be issued** | The preset, the subject, the names, the key and where it comes from, *Not before*, *Not after*, the validity in days, the key usage, the extended key usage and the names left out of a CSR |
| **Extensions** | Every extension with its OID, whether it is critical, and what it says. They come from the preset and the issuing CA, never from the request |
| **Who signs** | The issuing CA, its key generation and the longest validity it allows, the CA certificate URL (AIA) and the CRL URL (CDP) that would be written into the certificate |
| **Chain** | The CA certificates from the issuing CA up to the root, each with its SHA-256 (in two lines of 16 bytes, to compare line by line) and its expiry |
| **Notes and warnings** | Defaults that changed the request (a validity cut down, a base domain added) and compatibility warnings that would not stop the issuance |

A refused plan shows only what it got to know: no validity, usages, extensions or URLs. Everything on the page,
including names that come from a CSR, is escaped; the text of the CSR itself is never shown, only what the engine
derived from it.

### The checks table: collected, and stopped here

The policy runs ten checks in a fixed order:

| Check | Kind | What it tests |
|---|---|---|
| Preset | gate | The preset exists |
| Issuing CA | gate | The CA exists, is active and online, and is not a root |
| CA certificates valid now | gate | Every CA certificate up to the root is valid at this moment |
| Key | gate | The CSR parses and is signed correctly, the key passes the key policy and is not blocked; or the server may generate the key |
| Key usages | gate | Custom key usages, where the preset allows them |
| Subject and names | collected | The names and the rules of the preset |
| Name constraints | collected | The name constraints of every CA up to the root |
| Extended key usage limits | collected | The EKU limits of every CA up to the root |
| Validity | collected | The requested or default lifetime |
| Certificate to renew | collected | Only for a renewal; it passes for a new request |

The difference matters when you fix a refusal:

- A **collected** check reports every problem it finds, and all collected checks run before the request is
  refused. If *Subject and names* and *Validity* both fail, you see both.
- A **gate** ends the plan at its first problem, as it ends an issuance. The row says *Refused, stopped here*,
  and the page says where the checks stopped. The checks after it did not run, so **more reasons can appear once
  you fix a gate**. That is not a bug of the preview: issuance would stop at the same place.

The reasons at the top are these problems in this order, and they are the same reasons a refused issuance gives.

### The dates

*Not before* is **this moment minus 5 minutes**, a clock-skew allowance, not the time you press the button.
A certificate that is issued a few minutes later has a later *Not before*.

## Steps: through the REST API

`POST /api/v1/certificates/preview` takes exactly the body of `POST /api/v1/certificates` and answers with the
plan. First find the ID of the CA:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" https://pki.homelab.lan:9443/api/v1/cas
```

Build the body from a CSR (the key stays on its host; see [Issue a first certificate]({{ '/guides/first-certificate-ui/' | relative_url }})):

```bash
jq -n --arg ca "<CA ID>" --rawfile csr www.homelab.lan.csr '{ca_id: $ca, preset: "server", csr_pem: $csr, validity_days: 30}' > preview.json
```

Send it:

```bash
curl -sS --cacert root.pem -X POST -H "Authorization: Bearer $MYOWNPKI_TOKEN" -H "Content-Type: application/json" --data @preview.json https://pki.homelab.lan:9443/api/v1/certificates/preview
```

Read the verdict and the reasons:

```bash
curl -sS --cacert root.pem -X POST -H "Authorization: Bearer $MYOWNPKI_TOKEN" -H "Content-Type: application/json" --data @preview.json https://pki.homelab.lan:9443/api/v1/certificates/preview | jq '{allowed, reasons, stopped_at}'
```

What to expect:

- **A refusal is HTTP 200 with `allowed: false`** and `reasons` listing every reason. Issuing the same request
  answers `422`. The preview never answers `422`: "would this be refused?" has a legitimate answer. A malformed
  body (`400`), a missing or invalid token (`401`), a role that may not issue (`403`), a CA you may not read
  (`404`), a body over the size limit (`413`) and a missing JSON content type (`415`) are answered as for issuing.
- `sealed` is `true` on a sealed server, and `allowed` still says what the policy decides. Issuing would fail
  with `503` until an instance admin unseals the server.
- `checks` is the table above: each entry has a `name`, a `title`, `collected`, `passed` and `problems`.
  `stopped_at` names the gate where the plan ended, or is `null` when every check ran.
- Parts the plan did not reach are `null` (`ca`, `preset`, `subject`, `key`, `validity`, `aia_url`, `cdp_url`) or
  empty lists. A refused plan has no `validity`, no usages, no `extensions` and no URLs.
- The response has no serial number, no `ca_id` and no CSR. Names and reasons may contain text from your request
  or CSR: a client that shows them must escape them.
- `generated_at` is the moment of the preview.

## What the preview does not promise

- **The state can change before you submit.** The CA may be retired, a domain or setting may change, the clock moves
  on. Issuing runs every check again; if the policy then refuses, you get the refusal as before. Nothing is kept
  between the preview and the issuance, and there is no preview ID.
- **It covers one path at a time.** The wizard and the REST API build their request differently today, and each
  preview shows what **its own path** really does:

  | | Issue wizard | REST API |
  |---|---|---|
  | Tenant subject defaults (O, OU, L, ST, C from *Tenant settings*) | Not applied | Applied where neither the request nor the CSR gives the field |
  | Names in a CSR | Ignored: the names of the *Names* step are used (the step starts from the CSR's names) | Used, unless the body says `use_csr_sans: false` |

  So the same CSR can give a different certificate in the two paths, and the preview of each path says so. To
  know what a script would get, preview through the REST API. Which behavior should win is open.
- **It is not an ACME dry run.** ACME has no preview, and neither renewals nor agent issuance have one in this
  release. `POST /api/v1/csr/inspect` still only parses a CSR and says what it asks for.
- **It has no rate limit of its own.** Give a script its own token with the smallest role.

## Check it worked

1. Preview a request the policy accepts. Then issue it and compare: the names, the validity (minutes apart), the
   extensions and the URLs are the ones the preview showed; only the serial number and the key identifier are new.

   ```bash
   openssl x509 -in www.homelab.lan.pem -noout -subject -dates -ext subjectAltName,keyUsage,extendedKeyUsage,crlDistributionPoints,authorityInfoAccess
   ```

2. Preview a request the policy refuses, for example a name outside the CA's name constraints. The review names
   the reason and the *Issue certificate* button is disabled. *Certificates* shows no new row, and the audit log has no
   `certificate.issue` entry, not even a denied one.

## When it fails

| What you see | Usually | What to do |
|---|---|---|
| The review says "The preview could not be computed. The checks run when you issue." | The engine could not make a plan (an invalid earlier step, or an internal error; the server log has the details) | Issuing stays possible and the engine decides then. Go *Back* and check the earlier steps |
| *Refused, stopped here* on a gate | The first problem of a gate ended the plan | Fix it; the checks after it run next time and may name more |
| *Refused* with a name-constraint or EKU reason | The CA, or a CA above it, does not allow the name or the usage | Change the name, or use a CA whose constraints cover it ([Name constraints]({{ '/learn/name-constraints/' | relative_url }})) |
| `403` from the API | The role is *viewer*, or it may not issue on that CA | Ask for *operator* on the CA |
| `404` from the API | The CA ID is unknown, or your role may not read that CA | List the CAs with `GET /cas` |
| `allowed: true`, but issuing is refused a moment later | The state changed between the two (see above) | Preview again |
| `allowed: true`, but issuing answers `503` | The server is sealed (`sealed: true`) | An instance admin unseals it |

More in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}).

## Next steps

- Issue the certificate: [Issue a first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }}).
- Undoing an issuance is revoking it: [Renew and revoke certificates]({{ '/guides/renew-and-revoke/' | relative_url }}).
- Undo a change to a domain or a setting: [History and restore of settings]({{ '/guides/settings-history/' | relative_url }}).
- The complete description, the permissions and the problem types:
  [operations guide §16]({{ '/reference/operations/' | relative_url }}#16-certificate-preview-and-settings-history).
