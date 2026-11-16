# Security policy

MyOwnPKI is a certificate authority, so security reports matter even at this early stage.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/Der-Felix/MyOwnPKI/security/advisories/new)**

Helpful details:

- the affected component (server, web UI, API, ACME, agent, the legacy `pki.sh` suite) and commit or version
- steps to reproduce, or a proof of concept
- the impact you see (for example: a certificate issued outside policy, a key readable without
  unseal, an authentication bypass)

You will get an answer through the advisory. We aim to acknowledge reports within 14 days
(best effort): this is a spare-time project maintained by one person, but reports are taken
seriously and handled before other work. Once a fix is available, the advisory is published and you are credited,
unless you prefer not to be.

## Supported versions

MyOwnPKI is pre-1.0 (the beta, the 0.9 series, see [docs/PLAN.md](docs/PLAN.md) and the
[changelog](CHANGELOG.md)). Security fixes go to the **latest release** and to the `main` branch;
earlier releases get no backport, so the answer to a report is "update to the next release". Before
1.0 a minor version may change the API, the configuration and the database schema; the release
notes say how to upgrade.

| Version | Security fixes |
|---|---|
| the latest 0.9.x release | yes |
| `main` | yes |
| earlier releases | no, please update |

The parsers that read data from outside (CSRs, ACME requests, uploads, REST bodies, the legacy
archive) are fuzzed in CI, see [CONTRIBUTING.md](CONTRIBUTING.md). A crash found there is fixed in
the open, except when it is reachable without authentication in a released version: then it is
handled like a report through the channel above.

The legacy Bash suite in [`legacy/`](legacy/README.md) is supported as an offline root CA tool;
reports for it are welcome through the same channel.

## Scope

In scope: everything in this repository – including issuance policy (a certificate issued with
names, key usages or validity the policy does not allow), key handling, authentication and
authorization, the ACME server and the agent protocol. Explicitly in scope:

- **privilege escalation** between roles, for example from viewer or operator to administrator
- **any break of tenant separation**: reading or changing data, keys or certificates of another
  tenant, or issuing for its names

Out of scope: findings that need an already compromised host or an administrator account of the
**same instance** (an administrator can change the configuration by design), and reports from
automated scanners without a demonstrated impact.
