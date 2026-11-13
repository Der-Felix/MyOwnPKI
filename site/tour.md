---
title: "A tour of the web UI"
description: "A walk through the screens of the MyOwnPKI web UI: sign-in, unseal, dashboard, reports, analysis, authorities, certificates, the issue wizard, the ACME pages, users, the audit log, legacy import, offline signing and the public trust portal, with the role each one needs."
permalink: /tour/
sources:
  - docs/screenshots/
  - docs/OPERATIONS.md
  - docs/PLAN.md
  - internal/authz/authz.go
  - internal/web/app.go
  - internal/web/app_admin.go
  - internal/web/app_acme.go
  - internal/web/app_pki.go
  - internal/web/app_reports.go
  - internal/web/app_analysis.go
  - internal/web/app_caactions.go
  - internal/web/app_issue.go
  - internal/acme/admin.go
  - internal/publish/trust.go
  - internal/web/pages/trust/trust.templ
  - internal/tools/screenshots/main.go
---

This page shows what each screen is for, what you can do there and which role it needs, so that you
know where to look before you have an instance in front of you. The pictures come from a demo instance
(`myownpki init --demo`) with sample certificates under `homelab.example`, taken in an earlier release.
The pictures of *Reports* and *Analysis* are from v0.3.8 and come from a demo instance with extra sample
data (agents, alerts, endpoints). The two pictures of the *trust portal* are from v0.3.9. Your menu can have more entries than these pictures, for example
*Agents*, *Alerts* and *Endpoints*; an entry is hidden when your role cannot use it. There is a light and a
dark theme.

The roles are the ones of the [glossary]({{ '/glossary/' | relative_url }}#role): *viewer* reads,
*operator* also issues, revokes and exports keys, *admin* also manages CAs, ACME approvals, agents and
settings, and an *instance admin* unseals the server and manages users. Actions that change what the PKI
trusts or reveal a key ask for a fresh second factor first (a
[step-up]({{ '/glossary/' | relative_url }}#step-up)). The guides linked in each section go deeper.

* TOC
{:toc}

## Sign in

![The sign-in page: user name and password, nothing else]({{ '/assets/screens/tour-login.png' | relative_url }})

The sign-in page asks for the user name and the password. It shows nothing about the instance. After the
password it asks for the code of the authenticator app (or a recovery code). Every user has a second
factor. Ten wrong passwords lock the account for 15 minutes; an instance admin can unlock it, or
`myownpki user unlock NAME` at the server.

**Role:** none; this is where roles start. **More:**
[Users, roles, second factor and API tokens]({{ '/guides/users-roles-2fa/' | relative_url }}) and
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#server-and-sign-in).

## Unseal

![The unseal page: the time of the seal, the state of the CRLs and a field for the passphrase]({{ '/assets/screens/tour-unseal.png' | relative_url }})

The server starts sealed after every start. While it is sealed the UI works and the CRLs and CA
certificates are served, but nothing is signed. A banner on every page says so and links here. The page
shows since when the server has been sealed and which CRLs are missing or about to run out, and asks for
the unseal passphrase. It is not your sign-in password. Wrong passphrases are slowed down, and every
attempt is audited.

**Role:** instance admin. Everybody else sees a message that an instance admin must unseal.
**More:** [Keys and unsealing]({{ '/learn/keys-and-unseal/' | relative_url }}) and
[Know what a sealed server means]({{ '/best-practices/' | relative_url }}#know-what-a-sealed-server-means).

## Dashboard

![The dashboard: figures for certificates, a block of things that need attention and the certificates that expire in 30 days]({{ '/assets/screens/tour-dashboard.png' | relative_url }})

The first page after sign-in. The figures count certificates (all, valid, expiring within 30 days,
expired, revoked) and CAs. *Needs attention* lists what waits for you: ACME accounts and new names that
wait for approval, a CA that waits for its signature from the offline root, a CRL that is missing or
about to expire. Below it are the certificates that expire in the next 30 days. When monitoring is
configured, open alerts show here as well. For a role that may read the reports, two charts follow the
table (*Expiry* and *Authorities*), each in a fold that can be closed.

**Role:** viewer or higher; the charts need a tenant-wide role. **More:**
[Monitoring]({{ '/monitoring/' | relative_url }}) and
[Reports and analysis]({{ '/reports/' | relative_url }}#the-dashboard-charts).

## Reports

![The Reports page: the expiry timeline and the certificates per CA and status, with the issuances, alerts and agents sections closed]({{ '/assets/screens/tour-reports.png' | relative_url }})

Five sections, each a fold with a chart, a sentence that says what is counted and a table of the exact
numbers: *Expiry* (certificates that end in the current week and each of the next 12 weeks, colored by the warning and critical
windows of the monitor), *Issuances* (the last 12 weeks by source: ACME, agent, UI and API), *Authorities*
(certificates per CA by status), *Alerts* (opened per week, the last five weeks) and *Agents* (state,
version and deployments, only with the agent listener on). The page says when it was computed; the
numbers are refreshed at most once a minute. The charts are plain SVG: no script runs on the page.

**Role:** viewer or higher with a tenant-wide role; a role limited to one CA gets a 403 page and no menu
entry. **More:** [Reports and analysis]({{ '/reports/' | relative_url }}).

## Analysis

![The Analysis page: a summary line, the findings with what was seen, why it matters and what to do, and the state of each of the ten rules]({{ '/assets/screens/tour-analysis.png' | relative_url }})

What ten fixed rules found in the data the server holds: an orphaned certificate, duplicates, a renewal
loop, an expiry wave, a weak key or signature, a CA that ends before its certificates, an outdated agent,
an unused ACME account or domain. Each finding says what was seen, why it matters and what to do, and its
subject links to the page of the certificate, CA, agent, domain or account. Under the findings the *Rules*
table shows the state of every rule. A rule that lacks the data to judge says *unknown* with the reason,
which is not a problem. The analysis is advice only: it raises no alert and nothing can be dismissed.

**Role:** the same as *Reports*. **More:** [Reports and analysis]({{ '/reports/' | relative_url }}#the-analysis-page).

## Certificate authorities

![The list of CAs: an intermediate that waits for a signature, an issuing intermediate, an offline root and an online root]({{ '/assets/screens/tour-authorities.png' | relative_url }})

Every CA with its type (root or intermediate), status, subject, key algorithm, where the key lives
(*Encrypted on this server* or *Offline*), when it ends, its maximum validity and how many certificates
it has signed. *New CA* creates a root or an intermediate; *Import offline root* adds a root whose key
stays elsewhere. A CA's own page shows its details and holds the actions for it, such as renewing and retiring it.

**Role:** viewer or higher to read. Creating, importing, renewing, retiring and revoking CAs, and
uploading a root's CRL, need **admin** and a fresh second factor.
**More:** [CA lifecycle]({{ '/guides/ca-lifecycle/' | relative_url }}),
[Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}) and
[Keep the root offline]({{ '/best-practices/' | relative_url }}#keep-the-root-offline).

## Certificates

![The certificate list with filters for name or serial, status, issuing CA and preset]({{ '/assets/screens/tour-certificates.png' | relative_url }})

The end-entity certificates of the tenant, newest first, with common name, status (valid, expiring soon,
expired, revoked), end date, preset, issuing CA and serial number. Filter by name or serial, status,
CA and preset; the search box in the header does the same. *New certificate* opens the issue wizard.

**Role:** viewer or higher. **More:**
[Issue a first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }}) and
[Renew and revoke certificates]({{ '/guides/renew-and-revoke/' | relative_url }}).

## Certificate detail

![The page of one certificate: subject, issuer, serial number, SHA-256 fingerprint, validity, names and the actions]({{ '/assets/screens/tour-certificate-detail.png' | relative_url }})

One certificate with its subject, issuer, serial number, SHA-256 fingerprint, validity, key algorithm,
preset, who requested it and its subject alternative names. The tabs *Extensions* and *Chain* show the
extensions and the chain up to the root. The actions are *Renew*, the downloads (fullchain, certificate,
chain, DER), *Export with key* and *Revoke*. A key that the server generated is stored encrypted, and the
export needs a fresh second factor and can delete the key from the server afterwards.

**Role:** viewer or higher to read. Renewing needs **operator** or admin; revoking and exporting a key need
operator or admin and a fresh second factor. **More:**
[Reading a certificate]({{ '/learn/certificate-anatomy/' | relative_url }}),
[Revocation]({{ '/learn/revocation/' | relative_url }}) and
[Renew and revoke certificates]({{ '/guides/renew-and-revoke/' | relative_url }}).

## Issue wizard

![Step 1 of the issue wizard: a list of presets with their use and default validity]({{ '/assets/screens/tour-issue-wizard.png' | relative_url }})

Four steps: **Preset**, **Key**, **Names**, **Review**. Nothing is issued before the last one. The preset
decides key usage, extended key usage, which names are required and the default validity. In the key step
you paste a CSR (the default; the key stays on the host that made it) or let the server generate the key
if your tenant allows that. The last step is the review. Before it signs, the engine checks the request
against the policy and the CA's name constraints.

**Role:** operator or admin, and only for the CAs your role covers. **More:**
[Issue a first certificate in the web UI]({{ '/guides/first-certificate-ui/' | relative_url }}) and
[Name constraints]({{ '/learn/name-constraints/' | relative_url }}).

## ACME accounts

![ACME accounts: a table of accounts that wait for approval and a form to approve one]({{ '/assets/screens/tour-acme-accounts.png' | relative_url }})

The ACME clients that have registered an account. Under the approval level *approved accounts* (the default
of a domain) a new account waits here until an admin approves it, unless it brought an EAB key. The page
tells you to compare the contact and the address with the machine that registered. Approved and closed
accounts are listed below. An account's page also holds the renewal policy for the old certificate.

**Role:** viewer or higher, with a tenant-wide role, to read. Approving needs **admin** and a fresh second
factor. **More:** [Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}) and
[ACME explained]({{ '/learn/acme/' | relative_url }}).

## ACME new names

![ACME new names: a name that waits for a decision, a form to decide and a form to approve a name in advance]({{ '/assets/screens/tour-acme-names.png' | relative_url }})

Under the approval level *new names*, the first certificate for a name waits here; once you approve it,
every later order for that name passes. The first order is refused with *unauthorized … is a new name … waits
for approval*; the client does not wait, so run it again after you approved the name. You can also approve a
name in advance, for a host that has not asked yet, as `dns:nas.homelab.lan` or `ip:192.0.2.10`.

**Role:** the same as for accounts: read with a tenant-wide viewer role, decide with **admin** and a fresh
second factor. **More:**
[Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}).

## ACME orders

![ACME orders: the names, status, account and result of each order]({{ '/assets/screens/tour-acme-orders.png' | relative_url }})

The newest 200 orders: what clients asked for and what came of it. A *valid* order links to its
certificate; an *invalid* one says why, in the words of the validator, for example that the client's web
server answered with status 404 or that the order expired before its challenges were solved. This is the
first place to look when a client reports a failure.

**Role:** viewer or higher with a tenant-wide role. **More:**
[operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails),
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01) and
[Split DNS and the network for validation]({{ '/guides/split-dns/' | relative_url }}).

## Users and roles

![Users and roles: a list of users with status, roles, second factor and creation date]({{ '/assets/screens/tour-users.png' | relative_url }})

Every user with status (active, disabled, locked), roles (an instance admin, or a role in the tenant,
optionally for one CA) and second factor. *New user* creates one; a user's page gives and removes roles,
unlocks a locked account and disables or enables the user. Users are never deleted, only disabled, because
their ID is in the audit log. A lost authenticator is reset at the server with `myownpki user reset-2fa`;
the UI cannot do that yet.

**Role:** instance admin. The entry is hidden for everyone else, and changes need a fresh second factor.
**More:** [Users, roles, second factor and API tokens]({{ '/guides/users-roles-2fa/' | relative_url }}).

## Audit log

![The audit log: entries with number, time, actor, action, target, result, address and details]({{ '/assets/screens/tour-audit-log.png' | relative_url }})

Every change and every refusal, in a hash chain with signed checkpoints. The first filter chooses the log:
the instance log (sign-ins, users, unseal) or the tenant log (certificates, CAs, ACME, agents). The other
filters are the start of an action name and the result (success, failure, denied). The page shows what
happened; `myownpki audit verify` proves the chain is intact.

**Role:** the tenant log needs a tenant **admin**; the instance log needs an instance admin. A viewer or
operator has no *Audit log* entry. **More:** [The audit log]({{ '/guides/audit-log/' | relative_url }}).

## Legacy import

![Legacy import: an upload field for the archive, a dry run option, the base URL and the root key choice]({{ '/assets/screens/tour-legacy-import.png' | relative_url }})

Imports a directory made by the old Bash suite `pki.sh` (pack it with `tar czf pki.tar.gz pki/`): every CA,
certificate, revocation with time and reason, and the CRL numbering. *Dry run* is on by default and writes
only the report. The root becomes an offline root unless you choose to import its key. The same import is
`myownpki import legacy` at the command line.

**Role:** admin with a fresh second factor; the entry is hidden for other roles. **More:**
[Move from the old Bash suite]({{ '/guides/import-from-pki-sh/' | relative_url }}) and
[operations guide §5]({{ '/reference/operations/' | relative_url }}#5-moving-from-pkish).

## Offline signing

![Offline signing: the request, the extension file and the signing instructions for an intermediate below an offline root]({{ '/assets/screens/tour-offline-signing.png' | relative_url }})

An intermediate below an offline root waits for a signature. Step 1 gives you a CSR and an extension file;
you take both to the machine that holds the root key and sign with exactly that extension file, never with
the extensions of the request. Step 2 shows the command. Step 3 takes the signed certificate back, and the
server checks it against the order (key, subject, `CA:TRUE`, key usage, path length, name constraints, EKU,
parent signature) before it activates the CA.

**Role:** admin, on the CA's page, with a fresh second factor for the upload. **More:**
[Sign with an offline root]({{ '/guides/offline-root/' | relative_url }}) and
[Root and intermediate CAs]({{ '/learn/root-and-intermediate/' | relative_url }}).

## The trust portal

![The trust portal for Windows: a warning, the roots with their SHA-256 fingerprints, the list of systems and the Windows steps]({{ '/assets/screens/tour-portal-windows.png' | relative_url }})

![The trust portal for iPhone and iPad: the same page with the profile download and the four steps]({{ '/assets/screens/tour-portal-ios.png' | relative_url }})

This is not a page of the admin UI. It is the page at `/` of the **public listener**, which anybody on the
network may open without signing in, and the one you send people to so that their devices trust your root.
Both pictures show it with the system chosen in the address (`/?os=windows` and `/?os=ios`); without that
the page guesses the system from the browser. The warning comes first on purpose: the page is plain HTTP, so
nothing on it proves itself, and the fingerprint must be compared with a value from another source. Below the
fingerprints come the list of systems and the steps for the chosen one: PowerShell and the Windows helpers, or
the configuration profile and the *Certificate Trust Settings* step on an iPhone. The pictures come from the demo
instance of v0.3.9, whose two roots are both listed.

**Role:** none; it is public. An admin finds the address and a *Message for your users* on the root's page under
*Certificate authorities*, and can switch the portal off in *Tenant settings*. **More:**
[The trust portal]({{ '/trust-portal/' | relative_url }}) and
[Make clients trust your root]({{ '/guides/trust-the-root/' | relative_url }}).

## Pages without a picture here

- **Alerts** lists what the server watches and works while sealed. Viewer or higher, tenant-wide.
  [Monitoring]({{ '/monitoring/' | relative_url }}).
- **Endpoints** lists the TLS endpoints the server scans. Viewer reads, operator and admin scan now,
  admin adds and removes. [TLS scan]({{ '/tls-scan/' | relative_url }}).
- **Agents** and **Add host** manage hosts that run the agent. Reading is viewer or higher; adding a host,
  join tokens and approvals need admin and a fresh second factor. [Adding hosts]({{ '/hosts/' | relative_url }}).
- **Domains** and **EAB keys** hold the ACME rules and the keys that skip approval; creating either needs
  admin and a fresh second factor. [Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}).
- **Presets** shows what each kind of certificate gets, read-only.
- **Tenant settings** holds the step-up lifetime, the ACME rate limits, whether the server may generate
  keys, the default subject fields, the trust portal switch, the predecessor defaults and the agent
  enrollment mode. Viewers and operators read, an admin changes, and a
  different enrollment mode needs a fresh second factor.
  [operations guide §4]({{ '/reference/operations/' | relative_url }}#step-up-confirmation-lifetime).
