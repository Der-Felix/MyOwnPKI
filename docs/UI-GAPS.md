# UI gaps: inventory of the web UI at v0.3.8

A list for the maintainer: what is missing or awkward in the web UI, page by page, with a priority and a
one-line proposal. It is based on screenshots of the real UI, not on a guess about what a UI might want. Nothing
here is built; each item is a candidate for a later release (docs/PHASE3.md §14, step 50, decision D13).

## How this was made

- **Command:** `task screenshots -- -inventory` (equivalent: `go run ./internal/tools/screenshots -inventory`;
  `-only <name prefix,...>` shoots a few pages, `-width` and `-height` change the window). The images, the HTML of
  every page and `manifest.txt` (page, route, HTTP status) go to `.tmp/ui-inventory/`, which is gitignored. Nothing
  from there is committed.
- **Date and version:** 2026-11-13, branch `release/v0.3.8`, tool commit `7c59ac2`. The demo instance reports
  server version 0.3.8 (a fixed value; the analysis compares agent versions with it).
- **Browser:** Microsoft Edge 157.0.4341.46, headless, 1400 x 1500 px, light and dark, scrollbars hidden.
- **Demo data:** the seeded demo instance plus the inventory seeds (`internal/tools/screenshots/seed.go`): three
  agents (one silent, one outdated with a failed deployment) and one enrollment that waits, deployments, alerts
  with a five-week history, five TLS endpoints in every state, about 45 certificates issued over twelve weeks, one wave
  that ends in a single week, one renewal loop, two sources for one name, a weak key, an unused domain and an unused
  ACME account. Reports and Analysis are switched on. Some oddities are artifacts of the seeds and are not listed
  as gaps: every alert says "today", the agent deployments name hosts the agent may not order for, the demo banner.
- **What I looked at:** 32 of the 54 light images (every page that a candidate or a ranked item names), the new
  names image of the normal run, and the dark images of the dashboard and the reports only: the other dark images
  exist but were not opened, so the dark theme is checked on two pages. The narrow layout was checked at 390 px on
  the certificates and audit pages (Edge may lay out a headless window wider than 390 px, so only the menu, which
  I also read from the CSS, is a finding). Rows marked "not reviewed" were not opened.
- **Not shot, read from source instead:** `/login/code` (needs a sign-in in progress), the file downloads
  (`/certificates/{id}/download/{format}`, `/authorities/{id}/certificate`), the two htmx fragments
  (`/hosts/add/{host}/status`, `/agents/{id}/deployments`) and `/admin/import/{id}` (the report of a finished legacy
  import; the demo has none). `/step-up` answers 400 without a pending action; the page with a pending action was
  read from `internal/web/app_auth.go`. The steps after the first of the wizards (POST pages) were not shot.
- **Limits:** contrast was looked at, not measured. Keyboard use was not tried; the source has a skip link
  (`internal/web/layout/app.templ:83`) and a global `:focus-visible` rule (`web/styles/base.css:68`). Empty instances
  (no agents, no ACME, no alerts) were not reviewed: the inventory only has pages with data. Hostile names were not
  tried here (step 47 tests them for the findings).

## The candidates of the plan

| Candidate | What exists | Gap | Priority and size |
|---|---|---|---|
| Global search | A search field in every header (`internal/web/layout/app.templ:110`) that goes to `/certificates?q=`: name, serial or SAN of certificates | It finds certificates only: not agents, hosts, ACME accounts or orders, domains, endpoints, audit entries. The placeholder says so | could, M. A results page that groups hits by kind |
| Host view | The agent page `/agents/{id}` shows deployments and the names the agent may order; `/endpoints` shows what a host serves; certificates are searched by name | No page joins the pieces for one host name: agent, deployments, certificates for its names, the scanned endpoint, open alerts. The deployment shows a serial, not a link to the certificate | should, M. `/hosts/{name}` read-only, from the services the analysis already loads; first step: link serials and names |
| Chain view | Tab *Chain* on the certificate page (`/certificates/{id}/chain`): role, subject, expiry, status for leaf, issuing CA, root | A plain three-row table: no fingerprints, no CRL or OCSP address, no note which CA generation signed. `/authorities` is a flat list without parent and child | could, S. Add the parent column or indentation to the authorities list; fingerprint and CRL address to the chain tab |
| CSV export | Nothing: no list can be exported, the REST API answers JSON only (`api/openapi.yaml` has no CSV) | An admin who needs the expiry list for a ticket or a spreadsheet copies by hand | should, S to M. `?format=csv` on the certificate list, the findings and the audit log. Cells that start with `=`, `+`, `-` or `@` need a guard: names are attacker input |
| Audit log filters | Log (tenant or instance), "action begins with", result (`internal/web/app_admin.go:376`); paging by "Older entries" | No time range, no actor, no target (so no history of one certificate or agent), no search in the details, no link from a certificate or agent to its entries. `audit verify` exists in the API (`/audit/verify`) and the CLI, not in the UI | should, M. A target filter plus a "History" link on certificate, agent, CA and domain pages; could: time range |
| Notification settings | The alerts page explains what is checked and has a test button when a notifier is wired (`POST /alerts/test`) | `notify.email`, `notify.webhook` and the `monitor.*` thresholds are in `config.yaml` only; *Tenant settings* has none of them | could, L. Not a UI-only change: SMTP and webhook secrets in the database need an ADR decision |

## Ranked list of the gaps

Should (an admin trips over it):

1. **Small-screen navigation.** At 760 px and below only seven links stay: Dashboard, Alerts, Reports, Analysis, All
   certificates, Certificate authorities, Appearance (`Primary` in `internal/web/layout/app.templ:11-57`,
   `web/styles/layouts.css:341`). Agents, Domains, ACME, Endpoints, Users, Audit log and Tenant settings cannot be
   reached from the menu on a phone. Proposal: show every link in a wrapped or collapsible list, or let *Agents* and
   *Domains* be primary. S.
2. **Wide tables are clipped.** At 1400 px the content column is 1136 px wide. The authorities table cuts *Signed*,
   the endpoints table cuts *Added by* (and probably its actions), the audit table cuts *Details*. They scroll
   sideways (`.table-wrap`, `web/styles/components.css:262`) with no visible cue. Proposal: let the long columns wrap
   or drop (Issuer, Added by), and add a scroll hint. S.
3. **Checkbox labels wrap in the label column.** On every form with a checkbox (revoke, manage CA, domain, tenant
   settings, install agent, export) the label sits in the narrow left column: "I understand that this can't / be
   undone" breaks into lines with a large gap. Proposal: one CSS rule that spans checkbox rows over both columns. S.
4. **The issue wizard offers the agent CA.** Step 1 lists `agent-ca` as the issuing CA and preselects it, because it
   is first in the list, for a server certificate. The filter is `canIssueAt` only (`internal/web/app_issue.go:37`);
   the domain form already filters by name constraints and EKU limit (its hint says so). Proposal: filter by the
   preset's EKU against `CAInfo.EKULimit` and prefer the CA that was used last. S.
5. **The certificate page says nothing about where a certificate is used.** No source (UI, ACME account, agent,
   import), no agent deployment, no scanned endpoint, no link to the certificate it replaces or that replaced it
   (the table has `renewal_of`), no audit history. Proposal: a "Used by and history" block; it is the base of the host
   view. M.
6. **The authority page shows 20 certificates without saying so.** `Issued certificates` is cut at 20
   (`internal/web/app_pki.go:675`), and there is no link to the rest although `/certificates?ca=<id>` exists.
   Proposal: a title "Newest 20 of N" and the link. S.
7. **The dashboard's "Needs attention" is not capped.** Every open alert is a full-width row (six rows in the
   inventory, 30 in a bad week), plus the ACME and CA notes. Proposal: show the five most severe, then "and N more"
   with a link to *Alerts*. S.
8. **Two date formats.** The ACME pages (accounts, orders, new names) show the stored text `2026-11-13T09:32:39Z`;
   the rest of the UI shows `2026-11-13 09:44 UTC` (`internal/web/app_acme.go` passes the database string through).
   Proposal: `view.DateTime` everywhere. S.
9. **Certificate list: only "newest first".** No sort by expiry or name, no filter by source (ACME, UI, agent,
   imported), no visible count of matches, paging forward only. An imported certificate has empty *Preset* and *Issuing CA*
   cells. Proposal: `sort=expiry` first, then the source filter (the report's source classes D6 already exist). M.
10. **The revoke page shows a serial, not the name.** It does not say what the certificate is for, where it is
    deployed, or that a fresh second factor follows (the export page says it). Proposal: name, expiry, deployments
    and the second-factor line on `/certificates/{id}/revoke` and on the CA revoke form. S.
11. **Wide analysis and endpoint cells break names.** Analysis: `ci-runner.homel/ab.example` in the *Subject* column,
    a raw `acc_01m...` id for an unused ACME account. Endpoints: the *Issuer* column is one to five characters wide
    (`CN=Hom/elab/Issuin/g CA`). Proposal: a fixed minimum width for subject and issuer, and the account contact
    instead of its id. S.
12. **Reports sections: the code and the plan disagree.** The plan says all sections open (D12); the page opens
    *Expiry* and *Authorities* and closes *Issuances*, *Alerts* and *Agents* (`internal/web/app_reports.go:22`). A
    closed section hides data on first sight. Decision for the maintainer: open all, or change D12. S.

Could (nice, no pain yet):

13. **Reports charts use about 40% of the width**; the x axis shows every second week (W46, W48, ...); the label
    `External certificates` is cut to `External certific...`. Proposal: let the SVG use the column width (viewBox)
    and show every week label at that size. S.
14. **Install agent and Add host overlap.** Two entry points for the same job, worded differently ("Exact host FQDN" /
    "Host name", "Enrollment http-01: standalone" / "http-01 challenge: webroot ..."). The command blocks have no copy
    control that I could see, and their long lines scroll sideways. Proposal: one wizard, one wording; a copy button
    only if it works without inline script (CSP). M.
15. **The agent page.** A deployment's first cell mixes the profile, the names and a sentence about names the agent may
    not order; the serial is not a link to the certificate; no list filter or search for many agents. S.
16. **Settings is one flat form** with more than 20 fields and no headings (subject defaults, ACME limits, trust page,
    agents, step-up, predecessor). Proposal: headings, later tabs. S.
17. **Alerts:** the *What to do* column is one long blue link sentence; no filter by severity or kind; no way to silence
    one (a decision, since the monitor is the one place that alarms). S.
18. **ACME lists show opaque ids** (`acc_01m...`, `ord_01m...`) for accounts and orders; no marker for an account that
    belongs to an agent, no order count or last order per account; orders have no filter and stop at the newest 200.
    S to M.
19. **Step-up.** After *Revoke* the user lands on `/step-up`; the pending action lives in memory for five minutes
    (`internal/web/app_stepup.go:18`), so a server restart or a slow code loses it. Without a pending action the page
    is titled "Start again" and offers only the dashboard. Proposal: say "valid for 5 minutes" on the page and link
    back to the page the action came from. S.
20. **Renew and plan-revocation pages use the word "predecessor"** for the old certificate and "Revoke after N days" with
    little context; neither page names the names or the expiry of the certificate. Proposal: the sentence "Replaces
    web.example (ends 2027-12-15)". S.
21. **Manage CA mixes routine and destructive actions** (limits, CRL, renew, retire, revoke) on one long page with no
    count of the certificates that a retire or revoke affects. Proposal: a danger zone with the count. S.
22. **Domains list and page:** no number of certificates, orders or agents per domain; *Delete domain* says open orders
    fail but not how many. S.
23. **The "Design system" page is in the Administration menu** (`/design`, registered for everyone who is signed in).
    It is a developer gallery; check that it is meant for production. S.
24. **The sealed dashboard keeps "Issue certificate"** next to the banner "Signing is off". Probably the form can
    not succeed then (guess; not tried). S.
25. **Wizard clarity:** the first step of the issue wizard shows 12 presets and puts the CA choice below them, out of
    sight on a small window; the step names (1. Preset, 2. Key, 3. Names, 4. Review) look like links but I did not
    check that they are (guess). Steps 2 to 4 were not shot. S.

## Page by page

Priority and size: S small, M medium, L large. "Seen" says what the light and dark images showed. Numbers in
brackets refer to the ranked list above.

| Page and route | Seen | Missing or awkward | Candidate fix |
|---|---|---|---|
| Sign-in `/login` | not reviewed | | |
| Unseal `/unseal` | not reviewed | | |
| Step-up `/step-up` | 400, "Start again" without a pending action | [19] | text and back link, S |
| Dashboard `/` (also sealed) | counters, alerts, expiring table, expiry chart; light and dark fine | [7], [24]; the chart repeats the table above it and starts below the fold | cap alerts; put the chart beside the counters, S |
| Alerts `/alerts` | open and resolved tables | [17] | link only the verb, filters, S |
| Reports `/reports` | expiry and authorities charts; three sections closed | [12], [13]; the closed sections were read from the HTML only | open all; wider charts, S |
| Analysis `/analysis` | eight findings, rule list | [11]; six columns are tight at 1400 px; "unknown" for orphaned certificates reads clearly | wider subject, S |
| Endpoints `/endpoints` | five endpoints in four states | [2], [11]; no actions column visible at 1400 px | wrap issuer, S |
| Certificates `/certificates` (+ `?status=expiring`) | list with filters | [9]; `Hide agent certificates` is checked by default, which is right but easy to miss | sort, source filter, M |
| Issue wizard `/certificates/new` | step 1 | [4], [25] | filter CAs, S |
| Certificate `/certificates/{id}` | properties, SANs, actions *Renew*, *Revoke now*, *Plan revocation* | [5]; the right half and the lower page are empty | used-by block, M |
| Certificate, Extensions and Chain tabs | chain: three rows | chain candidate above; the extensions tab was not reviewed | S |
| Renew, Export, Revoke, Plan revocation | forms | [3], [10], [20]; Export says "needs a fresh second factor", Revoke does not | text, S |
| Authorities `/authorities` | flat list of five CAs | [2]; no parent, no CRL state | parent column, S |
| Authority `/authorities/{id}` | properties, name constraints, CRL, generations, 20 certificates | [6]; the CRL address breaks inside a word | link, S |
| Manage CA `/authorities/{id}/manage` | five forms | [3], [21] | danger zone, S |
| New CA, Import root, Offline signing | not reviewed | | |
| Domains `/domains`, `/domains/{id}` | list of two; page with settings and delete | [3], [22]; the domain page's CA hint is good | counts, S |
| Presets `/presets`, `/presets/{name}` | not reviewed | | |
| Agents `/agents` | three agents, silent and outdated marked | [15]; no filter | filter, S |
| Agent `/agents/{id}` | host data, deployments, names, predecessor forms | [3], [15]; long page with three forms | link serials, S |
| Update agent `/agents/{id}/update` | independent values and commands | [14] | copy button, S |
| Install agent `/agents/install`, Add host `/hosts/add` and progress | forms; progress with three stages and approve or refuse | [14]; the progress page refreshes itself, which is good | one wizard, M |
| Enrollment requests, Join tokens | not reviewed | | |
| ACME accounts, one account, new names, EAB keys, orders | accounts and orders seen; new names seen in the normal shots | [8], [18]; the new names text now says what the client does (this step) | S |
| Users and roles, one user, new user | list seen | the list is clear; the second factor column is useful | |
| Tenant settings `/admin/settings` | one flat form | [3], [16]; no notification settings (see the candidates) | headings, S |
| Audit log `/admin/audit` (tenant and instance) | table with filter row | [2]; see the candidates | target filter, M |
| Legacy import, Appearance, My account, Design system | account seen: three password prompts for three actions, API tokens, passkeys note | [23]; the repeated "Current password" is deliberate | |

## Follow-ups outside this file

- `site/guides/when-things-go-wrong.md:115` still says "If an ACME client or agent keeps asking for the name"; the
  corrected sentence is on the new names page and in `site/tour.md`. Agents do not hit that refusal (their names are
  admitted at enrollment), so the line is only about ACME clients.
- Step 51 adds the `reports` and `analysis` shots to `shots`: the README demo has no Reports or Analysis, so that step
  needs the same two services; the seeds of this tool show how.
