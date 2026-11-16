---
title: "Guides in the UI"
description: "What the Help group of the web UI shows (First steps and six short guides), what it never does, the small text format the guides are written in, and how a guide is added."
permalink: /guides/guides-in-the-ui/
sources:
  - docs/OPERATIONS.md
  - docs/PHASE3.md
  - internal/guides/guides.go
  - internal/guides/parse.go
  - internal/guides/registry.go
  - internal/guides/guides_test.go
  - internal/web/app_guides.go
  - internal/web/app_firststeps.go
  - internal/web/firststeps.go
---

## When to use this

Since v0.3.11 the web UI has a **Help** group in the navigation. It answers two questions a new admin has after
`myownpki init`: *what does this instance still need?* and *how do I do the next thing?* This page says what is
there, what it never does, and, for a contributor, how a guide is written and added. The guides in the UI are short
texts for **this** instance; the pages of this site are the longer versions, and each guide links to its one.

* TOC
{:toc}

## First steps

*Help → First steps* is a read-only checklist, computed again on every request from what the instance already
knows. The rows, in order: unseal the server, create a certificate authority, the public base URL and CRL of the
CAs, add a domain, turn on ACME, issue a first certificate, add a host with an agent (optional), back up the
instance, trust the root on your devices, and set up notifications (optional). Each row is in one of four states:

| State | Meaning |
|---|---|
| Done | The instance has what the row asks for |
| Open | It does not; the row says what to do and links to the page that does it, and to the guide |
| Not detected | The server cannot know: whether a backup runs (the daily timer belongs to the host), which devices trust the root, whether a notification channel exists |
| Not available to your role | The signed-in role does not read that part of the instance. A role limited to one CA sees the rows it may see and this state for the tenant-wide ones, never an error |

The page **writes nothing and keeps nothing**: there is no "done" flag, no dismiss button, no redirect after
sign-in and nothing new in the databases. The buttons are links to the existing pages, and those pages keep their own
permissions and their own second factor. The row about the public base URL uses what the dashboard already knows
about CA base URLs and CRLs; it does not test whether a client can reach the address.

On a new instance, while there is no CA or no certificate (or, with ACME on, no domain), the dashboard also shows
one information message with a link to *First steps*. It disappears when the data exists. `myownpki init` ends with
the line "Next: sign in and open Help, First steps."

## The guides

*Help → Guides* lists six short guides. Every signed-in user can read them.

| Guide | What it covers | Longer version |
|---|---|---|
| Build a certificate authority | A root and an online intermediate in the UI, which fields matter and what can never be changed afterwards | [CA lifecycle]({{ '/guides/ca-lifecycle/' | relative_url }}) |
| Keep the root offline | Why the root key stays off the server, importing the root, having an intermediate signed elsewhere | [Sign with an offline root]({{ '/guides/offline-root/' | relative_url }}) |
| Connect certbot | The ACME directory of the instance, trusting the root, a first certificate with http-01 | [Certbot with MyOwnPKI]({{ '/guides/certbot/' | relative_url }}) |
| Install the agent and add a host | The Add host assistant, enrollment, a recipe with `--dry-run`, the rollback | [Adding hosts]({{ '/hosts/' | relative_url }}) |
| Back up and restore | What a backup holds, the daily timer, checking a backup, a restore | [Backup and restore]({{ '/guides/backup-and-restore/' | relative_url }}) |
| Using these guides | How to read them | this page |

A guide is complete without the longer page, so an installation without internet access loses nothing it needs.
Where a command needs the ACME directory or the name of a CA, the guide shows the value of this instance, or a marked
example such as `https://pki.homelab.lan/acme/directory` while there is none. A role that does not read the whole
tenant always sees the example for the directory.

**What a guide never does.** It shows text. It does not run a command, change anything on the server, or show a
secret: a passphrase, a recovery key, a token and an EAB secret exist only where they are created, once. The values in
a command come from the configuration and from the engine, never from the request. The guides are meant to be run on
a host that you choose, by you; **they have not yet been run on a live installation**, so correct any difference you
find and tell us in an [issue]({{ site.repository_url }}/issues).

## The format

The guides are not rendered by a Markdown library. They are written in a small, closed subset of Markdown, embedded in
the program and parsed into typed blocks that the page escapes. Whatever the parser does not know is an error when the
program is tested, so nothing unexpected can reach a page.

| Allowed | Notes |
|---|---|
| Front matter | `title`, `summary`, `audience`, `order`, `site` (the permalink of the longer page on this site) and `sources` (the repository files the text was checked against) |
| Headings `##` and `###` | Each gets an id for links inside the guide |
| Paragraphs, lists (`-` and `1.`), tables | |
| Fenced code blocks | With a language: `bash`, `powershell`, `yaml`, `json`, `ini` or `text` |
| Notes | `> **Note:**` and `> **Warning:**` |
| Inline | `**bold**`, `*italic*`, `` `code` `` and `[text](link)` |
| Placeholders | `{acme_directory}` and `{ca_name}`, in code only; filled after parsing from the configuration and the engine, never from the request |

Not allowed: raw HTML, images, scripts, `javascript:` links and every other construct. Links lead only to a page of
the UI (the paths must exist), to another guide, to a heading of the same guide, or to this site and the project's
repository. A guide file is at most 32 KiB and 200 blocks, and there are at most eight guides.

## How a guide is added

A guide is one file, `internal/guides/content/<slug>.md`, with a slug of lower case letters, digits and `-`. The program
embeds the directory, so nothing else needs to change: no route, no table, no template. Adding a file is a code change
and goes through the tests of the package `internal/guides`, which refuse the change when:

- the file does not parse in the subset above, or a link leaves the allowed targets;
- the `site` permalink is not a page of this site, or a file in `sources` does not exist;
- the text contains something that looks like a secret: an IPv4 address, a fingerprint, PEM material, a token or a
  `password:` style assignment;
- a command in a `bash` block starts with anything other than `myownpki`, `myownpki-agent`, `certbot`, `sudo`, `curl`,
  `openssl`, `systemctl`, `install`, `docker` or `./pki.sh` (the offline root tool), or pipes into a shell, as
  `curl … | sh` does. This is the **command-prefix test**: a guide shows commands the reader decides to run, from a
  short list of programs.

The commands of a guide are written from this site and from the code (`--help` of the program), and the `sources` list
is how the next reader knows what to check when the code changes.
