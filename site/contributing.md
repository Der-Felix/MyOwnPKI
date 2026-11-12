---
title: "Contributing"
description: "How to change the code or the pages of the MyOwnPKI documentation site."
permalink: /reference/contributing/
---

Contributions are welcome. A certificate authority sets a high bar for correctness and security, but the
rules are short. The authoritative text is
[CONTRIBUTING.md](https://github.com/Der-Felix/MyOwnPKI/blob/main/CONTRIBUTING.md); this page is a summary.

* TOC
{:toc}

## The short version

- **Security problems are not reported as issues.** Follow
  [SECURITY.md](https://github.com/Der-Felix/MyOwnPKI/blob/main/SECURITY.md).
- For anything larger than a small fix, open an issue first. Read the
  [project plan](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md): the architecture decisions
  (ADRs) are deliberate trade-offs, and a change that conflicts with one starts as a discussion.
- Code, comments, UI text, documentation and commit messages are in **English** with US spelling.
- Builds are pure Go. New dependencies need approval first; only permissive licenses.
- Commits follow Conventional Commits, for example `docs(site): explain the Salt rollout`. Each commit
  builds and passes `task check`.

## Fixing a page on this site

Every page has an *Edit this page on GitHub* link in its footer. The hand-written pages are Markdown files
in the `site/` directory. The operations guide, the release notes and the configuration example are
**generated** from `docs/OPERATIONS.md`, `CHANGELOG.md` and `deploy/config.example.yaml`; edit those files,
not a copy.

Conventions for the pages:

- Examples use only the names `homelab.lan`, `pki.homelab.lan`, `minion-01.homelab.lan` and the address
  range `192.0.2.0/24`. Never put real host names, internal addresses or secrets into a page.
- Links between pages use the `relative_url` filter, so they work under the base URL of the project site.
  Headings get automatic anchors (lower case, spaces become hyphens).
- A note or warning is a block quote that starts with **Note:** or **Warning:**, followed by the line
  `{: .note}` or `{: .warning}`.
- Commands go in code blocks, one command per block where it makes sense, with no prompt character so that
  they can be copied.
- No JavaScript, no web fonts and nothing loaded from other hosts.

## How the site is built

A workflow, `.github/workflows/pages.yml`, builds the site with GitHub's own Jekyll action; no software
is installed on your machine and there is no local preview. To see your change, push a branch and open a pull
request: the **build** job generates the reference pages, checks every link and anchor, builds the site
and checks the HTML. Nothing is published from a pull request. After the merge to `main` the site is
deployed to GitHub Pages.
