---
title: "Test the beta"
description: "What the MyOwnPKI beta is, what is frozen, a checklist for testers, what is known not to work yet, how to report a problem, and what never to post."
permalink: /beta/
---

The beta is the last stretch before version 1.0. Its releases are ordinary ones (0.9.0, 0.9.1 and so
on): `install.sh`, the container tag `latest` and the Salt formula behave as for every release. What
changes is the rule for the code: the **feature set is frozen**, and only fixes follow. Version 1.0.0
comes when no open finding is one that the maintainer rates a blocker. Your part is to try it and to
say what broke.

* TOC
{:toc}

## What is frozen

Nothing new is added during the beta: no feature, page, setting, REST field or command. What is
accepted are fixes, documentation, tests, security hardening that only narrows what is accepted, and
dependency security updates. A wish is welcome and gets the label `post-1.0`; it is looked at after
1.0, not built before. The full rules are on the
[Contributing]({{ '/reference/contributing/' | relative_url }}#the-feature-freeze-of-the-beta) page.

> **Warning:** A beta can still have defects that lose data or stop a start. Test on a machine you can
> throw away, or keep the production instance you have and install the beta next to it. If you do
> update an instance that matters, [back it up]({{ '/upgrade/' | relative_url }}#back-up-first) first
> and copy the backup off the machine.
{: .warning}

## Install the beta

Use the newest 0.9.x release; the [release notes]({{ '/reference/changelog/' | relative_url }}) say
which one it is.

- **A Linux machine with systemd:** [Installation]({{ '/install/' | relative_url }}#option-a-linux-with-systemd).
  The script installs the release it belongs to; `--version 0.9.0` (or a later 0.9.x) names another one.
- **A container:** [Installation]({{ '/install/' | relative_url }}), with the tag of the release, for example
  `ghcr.io/der-felix/myownpki:0.9.0`.
- **Only to look around:** the [demo]({{ '/demo/' | relative_url }}) starts a throwaway instance with
  Docker and removes it again.

Afterwards, print the version, so you can say what you ran:

```bash
myownpki --version
```

## The tester checklist

You do not need all of it. Every item you try helps, and so does the note "this item worked": say it
in the [feedback form](#how-to-report), with the version.

1. **Install** with `install.sh`, run `init`, write down the passphrase, the recovery key and the
   checkpoint fingerprint, unseal, and create the first CA
   ([Installation]({{ '/install/' | relative_url }})). Was anything unclear or in the wrong order?
2. **Issue a certificate by ACME** with certbot, with lego and with Caddy
   ([certbot]({{ '/guides/certbot/' | relative_url }}), [lego]({{ '/guides/lego/' | relative_url }}),
   [Traefik and Caddy]({{ '/guides/traefik-caddy/' | relative_url }})). Renew once.
3. **The agent on a Debian or Ubuntu host,** from the package: *Agents → Add host*, approve the
   enrollment, check that the certificate is deployed and that *Renew now* works
   ([Adding hosts]({{ '/hosts/' | relative_url }})).
4. **A backup and its check.** Make a backup, then verify it with the fingerprint of the backup key
   that `init` or the first backup printed:

   ```bash
   runuser -u myownpki -- /usr/local/bin/myownpki backup verify /var/backups/myownpki/before-test --backup-key <fingerprint>
   ```

5. **A restore into an empty directory** on another machine or in a scratch directory, then start,
   unseal and look at the certificates
   ([Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }})).
6. **Update from 0.3.12.** Install 0.3.12 first, issue a certificate, then update to the beta as the
   [Upgrade]({{ '/upgrade/' | relative_url }}) page says. Do certificates, CRLs, agents and the audit log
   look the same afterwards? What did `db status` say before and after?
7. **The trust portal on a phone.** Open the public address of the server on an iPhone or an Android
   phone, install the root from the page and open a site with a certificate of yours
   ([The trust portal]({{ '/trust-portal/' | relative_url }})).
8. **The demo,** if you have Docker ([Demo]({{ '/demo/' | relative_url }})).
9. **Break something on purpose:** a wrong passphrase, a revoked certificate, a name the policy
   refuses, a stopped agent. Is the message clear?

## Known limitations

These are known, and they are not defects to report again. They are the reason for the beta.

- **The maintainer's own live tests are not finished.** The recipes `apache2`, `httpd` and `haproxy`
  (example recipes, run in CI against Ubuntu packages only), the guides in the web UI, the flags in
  the certbot guide, the agent act of the demo, and the container image with its Debian 13 base have
  not been run on the maintainer's hosts yet. The release notes of each 0.9.x release say what is
  still open.
- **Apache.** `apache2ctl configtest` and `httpd -t` do not notice a key that does not match its
  certificate; the agent's own check of the pair before it writes is the guard. A failed reload can
  stop Apache, and the rollback does not start it again: after a `rolled_back` result, look at
  `systemctl status apache2`. On a host where Apache has not been started since the boot, the test
  hook fails because `/run/apache2` does not exist yet. The recipes are described on
  [Recipes]({{ '/recipes/' | relative_url }}).
- **Fuzzing covers the data that comes from outside** (CSRs, ACME requests, uploads, REST bodies, the
  legacy archive), not the files an administrator writes: the server configuration, `agent.yaml`,
  DNS credentials and the agent's state.
- **The agent runs on Linux only.** Agents for Windows and FreeBSD come later. The upgrade
  tests run on Linux amd64; the server archives for macOS, Windows and FreeBSD exist, but nobody has
  run an update on them.
- **Old agents show a warning.** The analysis page flags every 0.3.x agent as `outdated_agent`,
  because its minor version differs from the server's. It is a warning, the agent keeps working.
  Update the server first and the agents afterwards; a new agent against an old server is not
  promised to work.
- **The first steps page** cannot see a backup or the devices that trust the root, and does not test
  the public address from outside.

## How to report

Use the forms on GitHub; they ask for what is needed to find the problem.

- **A bug:** [report a bug](https://github.com/Der-Felix/MyOwnPKI/issues/new?template=bug.yml). Give the
  version (`myownpki --version`), how it is installed, what you expected, what happened, and for a
  problem after an update the output of `myownpki db status`.
- **Feedback or the result of the checklist:**
  [send feedback](https://github.com/Der-Felix/MyOwnPKI/issues/new?template=feedback.yml).
- **A security problem is not reported in public.** A certificate issued outside policy, a key that
  can be read, a login bypass: use the private
  [advisory](https://github.com/Der-Felix/MyOwnPKI/security/advisories/new) described in
  [Security]({{ '/reference/security/' | relative_url }}). When in doubt, use it: it can be
  turned into a public issue later, the other way round does not work.

The maintainer reads every report and sorts it:

| What it is | What happens |
|---|---|
| **Blocker:** data lost or a start refused after an update, a restore that loses data, an old agent that stops working, a certificate issued outside policy | fixed in the next 0.9.x at once; 1.0 waits |
| **Major:** a wrong result with a workaround, a broken page, a guide command that fails | fixed in the next 0.9.x if small, otherwise listed as a known limitation of 1.0 |
| **Minor:** text, layout, a mistake in the documentation | fixed when cheap |
| **Wish:** a feature or a setting | label `post-1.0`, not built in the beta |

## Never post these

An issue is public, and so is its history after you edit it. **Never paste, attach or describe the
content of:**

- a private key or a key file, the recovery key, the unseal passphrase;
- an API token (`mop_…`), a join token (`mjt_…`) or an enrollment pass (`mjp_…`), a session cookie;
- a backup file or a whole backup directory, `auth.key`, `init-demo-secrets.txt`;
- a TOTP secret, an `otpauth://` link or the QR code that holds it;
- DNS credentials (a TSIG secret, a Cloudflare token), or an `agent.yaml` that contains credentials;
- the private material of a CA, a root or intermediate key, even from a test instance.

Before you paste a log, read it once and search it. This finds the usual cases; it does not replace
reading:

```bash
grep -nE 'mop_|mjt_|mjp_|otpauth://|PRIVATE KEY|passphrase|secret|token' myownpki.log
```

If you posted one by mistake, treat it as leaked: delete the text, and then change what it protected
(revoke the token, change the passphrase with `myownpki passphrase change`; a leaked CA key means the CA
is replaced). Deleting the post is not enough, because others may already
have copied it.
