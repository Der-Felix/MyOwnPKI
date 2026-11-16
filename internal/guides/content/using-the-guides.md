---
title: Using these guides
summary: What the guides in this help area are, what they never do and how to read them.
audience: Everyone who signs in
order: 900
site: /guides/
sources:
  - internal/guides/guides.go
  - docs/PHASE3.md
---

## What the guides are

A guide is a short text that ships inside the program. It is written for this instance: where a command
needs the address of the ACME directory or the name of a CA, the guide shows the value of this instance,
or a clearly marked example while the instance has none.

Every guide is complete without the longer page on the documentation site. The link at the end of each guide
leads to that longer version, which you need only when you want more detail.

## What the guides never do

A guide only shows text. It does not run a command, it changes nothing on the server and it does not show a
secret. A passphrase, a recovery key, a token or an EAB secret exists only where it is created, once, and
never in a guide.

> **Note:** Anyone who is signed in can read the guides. A link in a guide leads to a page that checks your
> role itself, so a page can still refuse you.

## Where to start

- The [list of guides](/guides) shows every guide with a one-line summary.

## Reading the commands

Commands run on the host that the guide names. This is the shape of one:

```bash
openssl s_client -connect pki.homelab.lan:443 -servername pki.homelab.lan
```

| Part | Meaning |
|---|---|
| `pki.homelab.lan` | An example name; use the name of your own server |
| `-servername` | The name the client asks for (SNI) |

A value of this instance is filled in for you. The next command reads the ACME directory of this instance; on an
instance that has none, it shows the example address instead.

```bash
curl --silent {acme_directory}
```
