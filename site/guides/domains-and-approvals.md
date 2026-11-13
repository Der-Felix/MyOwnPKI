---
title: "Domains, approvals and EAB keys"
description: "Decide which names the ACME server issues for and who may order: add a domain, set the approval level, approve accounts and names, create an EAB key."
permalink: /guides/domains-and-approvals/
sources:
  - docs/OPERATIONS.md
  - docs/NIGHTLOG.md
  - internal/web/app_domains.go
  - internal/web/app_acme.go
  - internal/acme/admin.go
  - api/openapi.yaml
---

## When to use this

The ACME server issues for a name only when a **domain** covers it. Use this page to add the first
domain, to choose who may order for it, and to deal with what waits for a decision: new accounts, new
names and clients that bring an EAB key. An ACME client that gets `rejectedIdentifier` or "waits for
approval" is a reason to be here. Everything below needs the role *admin* with a **fresh second factor**
(`ca.manage` on the tenant), and the ACME server must be on (`acme.base_url` is set, see
[Reverse proxies]({{ '/guides/reverse-proxies/' | relative_url }})).

* TOC
{:toc}

## Steps: add a domain

1. Open *ACME → Domains* and press *New domain*.
2. Fill in the form. The important fields:

   | Field | What to choose |
   |---|---|
   | Domain | Lower case, at least two labels, for example `homelab.lan` |
   | Signing CA | An online intermediate whose name constraints permit the domain and whose EKU limit allows serverAuth |
   | Names below the domain too | Tick it for `nas.homelab.lan` under `homelab.lan` |
   | Wildcards | `*.homelab.lan`, proven by dns-01 only; off by default |
   | http-01, dns-01 | The challenges that prove control. http-01: the server fetches a file from the client's port 80. dns-01: it reads a TXT record |
   | Approval | Who may order, see the next section |
   | Preset and validity | The profile of the certificates; empty validity means 90 days, never beyond the CA's maximum |
   | Addresses http-01 may reach | *internal networks too (homelab)*, or *public addresses only* ([Split DNS]({{ '/guides/split-dns/' | relative_url }})) |
   | IP ranges | Which IP addresses may appear in certificates, for example `192.0.2.0/24` (http-01 only) |

3. Press *Create domain*. The domain page lets you change every setting later (*Save*) or delete the domain
   (*Delete domain*): certificates already issued stay valid, open ACME orders for its names fail.

The REST API has `POST /api/v1/domains`; like the UI it needs the second factor, so an API token cannot
create a domain.

## Who may order: the approval level

| Level | What happens | Use it for |
|---|---|---|
| *open* | Any account that passes the challenge gets a certificate | A closed lab network |
| *approved accounts* (default) | A new account waits until an admin approves it, or it brings an EAB key | Most homelabs |
| *new names* | The first certificate for each name waits for an admin; later orders for it pass | Hosts you want to know about before they get a certificate |

Narrow the rest with the CA: its name constraints limit the names whatever you tick here.

## Steps: approve accounts and names

![The ACME accounts page: one account waiting for approval with its contact and source address, and an Approve account form]({{ '/assets/screens/acme-accounts.png' | relative_url }})

1. **Accounts.** A client that registers under *approved accounts* appears under *Waiting for approval*,
   and the dashboard says that accounts wait. Compare the contact and the address (*From*) with the machine
   you expect, choose the account, press *Approve account*, and confirm the second factor. The client
   gets its certificate on the next run.
2. **New names.** Under *new names* the first order for a name is refused with "… is a new name for domain
   … and waits for approval", and the name appears on *ACME → New names*. Choose the name under *Decide*,
   then *approve* or *refuse*, and save. Run the client again after the approval; the order is not kept
   for it.

   ![The New names page: a waiting name, a Decide form and a form to approve a name in advance]({{ '/assets/screens/acme-names.png' | relative_url }})

3. **In advance.** *Approve in advance* takes a name nobody has asked for yet, written as
   `dns:nas.homelab.lan` or `ip:192.0.2.10`, for example before a new host gets its first certificate.
4. **See what clients asked for.** *ACME → Orders* lists the newest 200 orders with their names, status
   and result: a link to the certificate, or the reason it failed.

   ![The ACME orders page: a valid order with a link to its certificate and two invalid orders with their reasons]({{ '/assets/screens/acme-orders.png' | relative_url }})

The pages offer *Approve* for accounts and *approve* or *refuse* for names. There is no button to reject
an account; an account that you do not approve simply never orders. Account and name approvals, and
EAB keys, are done in the UI: the OpenAPI file has no operation for them.

## Steps: create an EAB key

An EAB key (external account binding) lets one client skip the approval queue: it signs its first
registration with the key.

1. Open *ACME → EAB keys*, enter a **label** (the host that will use it), and the **days** the key may stay
   unused (1 to 90, default 7). Press *Create key*. The server must be unsealed.
2. The next page shows the **key ID** and the **MAC key** once, with command lines for lego and certbot. It
   is not shown again and cannot be recovered: hand it over like a password.
3. Give both values to the client ([Certbot]({{ '/guides/certbot/' | relative_url }}),
   [acme.sh]({{ '/guides/acme-sh/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }})).
4. The list shows each key as *unused*, *expired* or *used by* an account. A key binds **one** account.

**Revoking an EAB key.** Version 0.3.6 has no button or REST operation to withdraw an EAB key. An unused
key expires after the days you chose, so keep that number small. A key that was used is spent: it has bound
its account. Whoever approves accounts decides what that account may order, through the domain's approval
level.

## Check it worked

Run the client again. In the UI, *ACME → Orders* shows the order as *valid* with a link to the certificate,
and *ACME → Accounts* lists the account as *approved*. The audit log has every account, order,
validation, approval, EAB key, issuance and revocation under the actor `acme:<account>`.

## When it fails

| The client says | Usually | What to do |
|---|---|---|
| `rejectedIdentifier: no domain covers …` | No domain for the name, or a wildcard on a domain without wildcards | Add the domain or tick *Wildcards* |
| `unauthorized: account … waits for approval` | Approval level *approved accounts* | Approve the account, or use an EAB key |
| `unauthorized: … is a new name for domain … and waits for approval` | Approval level *new names* | Decide the name under *ACME → New names*, then run the client again |
| Creating an EAB key is refused | The server is sealed | Unseal it first ([Installation]({{ '/install/' | relative_url }}#initialize-and-start)) |
| An approval sends you to a second-factor page | Approvals need a fresh second factor | Confirm with your authenticator |

The full table is in [operations guide §10.9]({{ '/reference/operations/' | relative_url }}#109-when-a-client-fails);
the details of the settings are in
[§10.5]({{ '/reference/operations/' | relative_url }}#105-domains-approvals-and-eab-keys). More in
[Troubleshooting]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01).

## Next steps

- Get a certificate: [Certbot]({{ '/guides/certbot/' | relative_url }}).
- Check that the validator can reach your hosts: [Split DNS]({{ '/guides/split-dns/' | relative_url }}).
- Limit who may do what in the tenant: [Best practices]({{ '/best-practices/' | relative_url }}#say-in-domains-who-may-get-what).
- dns-01 for wildcards works with ACME clients, and with the MyOwnPKI agent since v0.3.7: [dns-01 and wildcard certificates]({{ '/dns-01/' | relative_url }}). The agent's *Names it may order* must hold the identical `*.` pattern.
