---
title: "History and restore of settings"
description: "See who changed a domain or a tenant setting and when, compare versions, restore an old version as a new one, and stop two admins from overwriting each other, in the web UI and through the REST API."
permalink: /guides/settings-history/
sources:
  - docs/OPERATIONS.md
  - docs/PHASE3.md
  - internal/settingsver/snapshot.go
  - internal/ca/restore.go
  - internal/tenant/restore.go
  - internal/web/app_history.go
  - internal/web/app_versions.go
  - internal/httpapi/history.go
  - api/openapi.yaml
---

## When to use this

Since v0.3.10 every change to a **domain** and to the **tenant settings** is kept as a version: who made it, when,
the full state afterward and an optional reason. Use this page when a change had an effect you did not want and you
want the old state back, when you want to know who changed a rule and why, or when two people work on the same
settings and one must not overwrite the other.

Restoring is a change like any other: it needs the same permission and the same second factor as the change it
undoes, and it is recorded as a **new** version. Undoing an issuance is a different thing: revoke the certificate
([Renew and revoke certificates]({{ '/guides/renew-and-revoke/' | relative_url }})).

* TOC
{:toc}

## What is versioned, and what is not

| Versioned | What a version holds |
|---|---|
| **Domains** (*ACME → Domains*) | Every field: the name, the CA (by its ID, so renaming a CA is no change), subdomains, wildcards, challenge types, approval, preset, validity in days, address policy and IP ranges |
| **Tenant settings** (*Administration → Tenant settings*) | Server-side key generation, the subject defaults (O, OU, L, ST, C), the three ACME rate limits, the trust portal switch, the agent enrollment mode, the second-factor lifetime and the two predecessor defaults |

**Not versioned**, on purpose:

| What | Why |
|---|---|
| Presets | They are files embedded in the binary; nobody edits them. A certificate stores the preset's name |
| CA limits (CRL lifetime, maximum validity), a CA's identity and name constraints | Names and constraints are baked into issued certificates and can never be restored. The limits are a candidate for a later release |
| Per-account ACME overrides, agent names and per-agent predecessor overrides | State of one object, not a rule |
| EAB keys, join tokens, enrollment passes, API tokens | Secrets or runtime state |
| The configuration file, with the notification channels and their passwords | It is not in a database |

A version can **never hold a secret**: a snapshot is a closed list of fields, and two tests fail when a column or
a field is added that nobody has classified as a setting or as not one.

## The baseline

An object that was never changed since the upgrade has no versions (its `ETag` is `"0"`, its *History* tab says
"No changes recorded yet"). The **first change** first stores the state *before* the change as version 1, "State
before the history began", by "system, before history", and then your change as version 2. So the very first
mistake can be undone too. Changes made before v0.3.10 are not in the history; the [audit log]({{ '/guides/audit-log/' | relative_url }})
keeps them as text.

## Steps: read the history in the web UI

1. Open the domain (*ACME → Domains*, then the domain) or *Administration → Tenant settings*. A tab row with
   **Settings** and **History** sits under the title. You see it only if you may read the history (see
   [who may do what](#who-may-do-what)).
2. Open **History**. The table lists the versions, newest first: *Version*, *When* (UTC, with a relative hint, such as
   how long ago), *Who* (the name and the kind of actor), *Change* (*Created*, *Changed*, *Deleted*, *Restored* or
   *State before the history began*), *Reason*, *Restored from* and *Changed settings*. The current version is marked.
   *Older versions* continues the list.
3. Open a version. The page shows the version's facts and a table **Settings that differ**, with the columns
   *Setting*, *Before* and *After*. A list such as the challenge types shows one value per line, marked *added* or
   *removed*, so you never depend on a color. Two links switch what the version is compared with:
   - **The previous version** (the default): *What this version changed.*
   - **The current state**: *What restoring this version would change now.*

## Steps: restore a version

1. Open the version you want back, and switch the comparison to **The current state**. Read the table: it is
   what the restore would change.
2. Under **Restore this version** read the sentence "Restoring would change: …". Write a reason if you like
   (at most 200 characters) and press *Restore this version*.
3. For a domain, and for a change of the agent enrollment mode, the page asks for a **fresh second factor**, like
   any other change of that kind. Confirm it.
4. The page of the history returns with "Domain restored from version 2 as version 4." (or "Settings restored …").
   Version 2 is unchanged; the history has a new version 4 with *Restored from* version 2.

### Dry run: why a restore is offered or refused

When a restore would be refused, the version page shows no form. It says "This version can't be restored now:" and
lists the reasons. They come from the same checks as the restore itself, without writing anything and without asking for
the second factor.

A restore runs the **ordinary** change, so everything a normal change refuses is refused here, with the same
reasons: a CA that is retired or gone, a CA whose key is offline, name constraints or an EKU limit that do not
allow the domain, a validity above the CA's maximum, a preset that no longer exists, a domain name that another
domain has taken now. Two more refusals are specific to a restore:

- **The state is already current.** "The current state already equals this version."
- **The version cannot be read.** A snapshot written by a release this server does not know, or one whose data
  does not match its stored hash. The other versions are not affected.

### Deleted domains

A deleted domain keeps its history. *ACME → Domains* has a link **Deleted domains** (for those who may read the
history). The table lists the domain, its CA ("no longer exists" if the CA is gone), when it was deleted, by whom,
the reason and the version of the deletion; *Restore* opens that version. Restoring brings the domain back **under
its old ID** with the settings it had, if the name is still free and its CA still accepts it. Certificates that
were issued meanwhile were never touched by any of this.

## Steps: two admins, one object

Every edit form of a domain and of the tenant settings carries the version it was built from (a hidden field,
`base_version`) and an optional **Reason (optional)** field. The save is refused if somebody saved a newer version
meanwhile:

- You see a page titled **Changed meanwhile** (HTTP 409): "This object was changed by *name* at *time* after you
  opened this page. Reload the history and look again. Nothing was saved." Its link goes to the History
  (*Back to the history*), or to the page itself if you may not read the history. Only a reader of the history is told the
  name; anybody else sees "somebody else".
- Nothing was saved. The page does not show what you typed, so copy it first if you want to enter it again.
- Open the History, look at what the other admin changed, open the object again and make your change.

The check covers the **whole object**: two admins who change different fields of one domain still conflict. A form
without the hidden field (a page that was open before the upgrade) is not checked, and the last writer wins, as
before; a field with a value that is not a number is refused with "This form is out of date – open the page again
and repeat the change." The version survives the second-factor detour.

## Who may do what

| Action | What it needs |
|---|---|
| **Read** the history, a version, its diff, the deleted domains | The audit right **tenant-wide**: the role *admin* on the whole tenant. The history names users, like the audit log. For a domain you also need read access to its CA (otherwise `404`). An admin of one CA only, an operator and a viewer see no tab; the API answers `403` (or `404` for a domain whose CA you may not read) |
| **Restore a domain** that exists | What changing it needs: *admin* with *manage CAs* on its CA, **and a fresh second factor**, and also the audit right on the whole tenant, because a restore is made from the history: an admin of one CA may change the domain but gets `403` on a restore. Moving it back to another CA needs that CA as well. An API token never satisfies the second factor (`forbidden`) |
| **Restore a deleted domain** | What creating a domain needs (*admin* on the tenant, a fresh second factor, never a token) and the audit right on the whole tenant |
| **Restore the tenant settings** | *Admin* (*manage the tenant*) with the audit right on the whole tenant. No second factor, **unless** the version has another agent enrollment mode: then *change the agent enrollment mode* and a fresh second factor, never a token |
| **Edit** with a reason or with a stale version | As before; the new fields change nothing about who may edit |

No new permission exists: restoring policy is not easier than changing it.

## Steps: through the REST API

The ETag is the version number, quoted. `GET /domains/{id}` and `GET /settings` send it as the `ETag` header, and so
do the answers of `POST` and `PATCH /domains` and `PUT /settings`; `"0"` means no history yet.

| Endpoint | What it does |
|---|---|
| `GET /domains/{domainId}/versions` | The history of a domain, newest first, also of a deleted one. `limit` 1 to 100 (default 50), `before` and `next_before` page through it |
| `GET /domains/{domainId}/versions/{version}` | One version with its full state, the diff (`against=previous`, the default, `current`, or a version number; `0` means nothing), `restorable` and `restore_problems` |
| `POST /domains/{domainId}/versions/{version}/restore` | Restore as a new version. Body `{}` or `{"reason": "…"}` |
| `GET /domains/deleted` | Deleted domains that can be restored |
| `GET /settings/versions`, `GET /settings/versions/{version}`, `POST /settings/versions/{version}/restore` | The same for the tenant settings |

- **`If-Match`** accepts exactly one quoted number, such as `"7"`, or its weak form `W/"7"` (a proxy that compresses
  the answer, nginx with gzip, makes a weak tag of a strong one, and a client sends it back as it got it), which counts
  as `"7"`. It is **optional** on `PATCH` and `DELETE /domains/{id}` and on `PUT /settings`: without it the last writer
  wins, as before. `*`, a list or a value that is not a number is `400`. When it is not the current version the answer
  is `412` with the problem type `urn:myownpki:problem:precondition-failed`, nothing is written, and the problem names
  `current_version` and `changed_at`, and `changed_by` for a caller with the audit right on the whole tenant.
- It is **required** on a restore: `428` (`precondition-required`) without it, `412` when it is not the newest
  version. A permission problem is answered first, so a token that may not restore hears `forbidden`, not `428`.
- `reason` (at most 200 characters, no control or invisible formatting characters) is a write-only field of the `POST`, `PATCH` and `PUT`
  bodies and of the restore body. `DELETE` has no body, so a delete through the API has no reason.
- A restore answers `200` with the object as it is now and the new `ETag`. Refusals: `422` with the reasons
  (the same as for a normal change; also an invalid argument of the history, which is a `422`, not a `500`), `409` for the identical state or a version that cannot be read, `404` for an
  unknown version or an object you may not read, `403` for a role that is too low, a missing second factor
  (`step-up-required`) or a token (`forbidden`).

A domain restore needs a session with a fresh second factor, so the example uses the tenant settings, which a token
with the *admin* role may restore as long as the enrollment mode stays the same. List the versions:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/settings/versions?limit=10" | jq -c '.items[] | {version, change, actor_name, changed_keys}'
```

Ask what restoring version 3 would change now, and whether it is allowed:

```bash
curl -sS --cacert root.pem -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/settings/versions/3?against=current" | jq '{restorable, restore_problems, diff}'
```

Read the newest version number, the `ETag` of the list:

```bash
curl -sS --cacert root.pem -D - -o /dev/null -H "Authorization: Bearer $MYOWNPKI_TOKEN" "https://pki.homelab.lan:9443/api/v1/settings/versions?limit=1"
```

Restore version 3, if the newest version is still 7:

```bash
curl -sS --cacert root.pem -X POST -H "Authorization: Bearer $MYOWNPKI_TOKEN" -H "Content-Type: application/json" -H 'If-Match: "7"' --data '{"reason":"back to the old ACME limits"}' https://pki.homelab.lan:9443/api/v1/settings/versions/3/restore
```

## What is written to the audit log

The entries of the changes gain two details, `version` and `snapshot_sha256` (the SHA-256 of the stored state, the same
value the version row holds): `domain.create`, `domain.update`, `domain.delete` and `tenant.settings`. A restore writes
`domain.restore` or `tenant.settings_restore` with `version`, `restored_from`, the changed keys and the hash. A refused
restore is audited too, with the error (a refused domain restore also names `restored_from`). The **reason stays out of the audit log**: it is free text, kept only with the
version. The change, its version and its audit entry are written in one transaction: if one fails, none is kept.

## Retention and size

Everything is kept; there is no pruning and no limit in v0.3.10. The history cannot be edited or deleted: the tables
refuse an `UPDATE` or a `DELETE` of a version, even by hand. A snapshot is small (the plan estimates about 0.5 KiB,
so 1,000 changes are about 0.5 MB). The history lives in `pki.db` (domains) and `system.db` (tenant settings), so
every backup carries it and a restore of a backup brings it back with the data. The name of the actor in a version is personal
data in a table that cannot be edited: like the audit log, it cannot be scrubbed later. To keep a snapshot small, a domain
has at most 256 IP ranges (more is refused with `422`). An older domain with more ranges can still be deleted, but an
update is refused until its list is trimmed; its history keeps only the first 256 ranges, and so would a restore of it.

## Check it worked

1. Change a test domain, for example its validity, and save with a reason. *History* shows version 1 ("State before
   the history began") and version 2 with your name and the reason.
2. Open version 1, compare with *The current state*, and restore it. Confirm the second factor. The history has
   version 3, *Restored* from version 1; version 1 and 2 are unchanged. The audit log has `domain.restore`.
3. Open the domain in two browser windows, save in the first, then in the second: the second shows *Changed
   meanwhile* and saves nothing.

## When it fails

| What you see | Usually | What to do |
|---|---|---|
| No *History* tab | Your role may not read the history: you are not *admin* on the whole tenant | Ask for the tenant-wide admin role |
| *Changed meanwhile* | Somebody saved a newer version | Read the History, open the object again, repeat your change |
| "This version can't be restored now:" with reasons | The same checks as a normal change refuse the old state (retired CA, missing preset, taken name, constraints) | Fix the cause (for example use another CA in a normal change), or restore nothing |
| "The current state already equals this version." / `409` | There is nothing to restore | Pick another version |
| "Version cannot be read" / `409` | A version of an unknown schema, or a damaged row | The other versions work; see the [operations guide §16]({{ '/reference/operations/' | relative_url }}#16-certificate-preview-and-settings-history) |
| `412 precondition-failed` | `If-Match` is not the current version | Read the object (or the history) again and send the new `ETag` |
| `428 precondition-required` | A restore without `If-Match` | Send the `ETag` of the newest version |
| `403` `step-up-required` | The restore needs a fresh second factor | Confirm it in the UI; a token can never do it |

More in [Troubleshooting]({{ '/troubleshooting/' | relative_url }}).

## Next steps

- Look at a certificate before it is issued: [Preview a certificate]({{ '/guides/preview-a-certificate/' | relative_url }}).
- Decide who may order what: [Domains, approvals and EAB keys]({{ '/guides/domains-and-approvals/' | relative_url }}).
- See the entries of every change: [The audit log]({{ '/guides/audit-log/' | relative_url }}).
- Back up the history with the rest: [Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}).
