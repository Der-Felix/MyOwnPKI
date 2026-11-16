---
title: "Fixture guide"
summary: Every construct of the subset once.
audience: Tests
order: 7
site: /guides/certbot/
sources:
  - internal/guides/guides.go
  - docs/PHASE3.md
---

## First section

A paragraph with **bold**, *italic*, `code with {ca_name}` and a [link to the CA list](/authorities).
The second line continues the paragraph; a < b & c stays text.

### A subsection

1. Step one with a [guide link](/guides/other#second-section).
2. Step two continues
  on an indented line.

- Bullet with [the site](https://der-felix.github.io/MyOwnPKI/guides/certbot/) and [the repository](https://github.com/Der-Felix/MyOwnPKI).
- Bullet with an [anchor](#first-section) and a [query](/certificates?status=expiring).

> **Note:** A note over
> two lines, with `code`.

> **Warning:** A warning.

```bash
curl --silent {acme_directory}
sudo systemctl status myownpki   # <b>not html</b> & more
```

| Name | Meaning |
|:---|---|
| `a|b` | A pipe inside code does not split the cell |
| **bold** | [Certificates](/certificates) |

## Second section

Last paragraph.
