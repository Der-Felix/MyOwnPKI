---
title: "Security"
description: "What protects what in MyOwnPKI, where the threat model lives, how to verify a download and how to report a vulnerability."
permalink: /reference/security/
---

A certificate authority is a high-value target, so the design is conservative. This page is a map: what
the main protections are, where the details and the reasons are written down, and how to report a
problem. It does not replace the
[security chapter of the project plan](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md#5-security),
which is the source for the threat model and the decisions behind them.

* TOC
{:toc}

## Report a vulnerability

Please report vulnerabilities **privately**, never as a public issue or pull request. The process is
in [SECURITY.md](https://github.com/Der-Felix/MyOwnPKI/blob/main/SECURITY.md).

## What protects what

| Area | What the product does |
|---|---|
| CA keys | Online CA keys lie encrypted in the database. A key-encryption key is derived from the unseal passphrase with Argon2id and exists only in memory. The server **starts sealed** and signs only after an instance admin unseals it. *Seal* removes all keys from memory at once. An unseal refuses weak key-derivation parameters. |
| The root | Can be offline. A root signs only intermediate CAs and CRLs; the engine refuses to issue end-entity certificates with it. |
| Backups | Contain the CA keys, encrypted. A backup alone cannot sign; a backup plus the passphrase or the recovery key can. |
| Certificate content | Extensions come from the preset and the policy, **never from the CSR**. CSRs, uploads and ACME payloads are treated as attacker input. Name constraints are enforced before signing, not only by clients. |
| People | A second factor (authenticator or passkey) is mandatory. Sensitive actions ask for a fresh code (step-up): revoking, downloading keys, CA operations, user management, agent management. Wrong passwords lock the account for 15 minutes. |
| Roles | *viewer*, *operator* and *admin* per tenant or per CA; instance admins unseal and manage users. |
| API tokens | Never more than their owner has, one year at most, and they can never satisfy step-up. |
| Audit log | Every action is logged in a hash chain with signed checkpoints. `myownpki audit verify` checks it; with the checkpoint key fingerprint from `init` it can prove that the log is the one you had. |
| Listeners | The admin listener checks the allowed networks before TLS and serves only HTTPS. The public listener holds only public data. Cookies are `HttpOnly; Secure; SameSite=Strict`, with CSRF tokens and a strict content security policy without inline scripts. |
| ACME | The validator resolves a name once and connects to exactly the checked address (no DNS rebinding), never to the ranges the address guard refuses (loopback, link-local and more; [list]({{ '/reference/operations/' | relative_url }}#148-which-addresses-are-never-scanned)), only to ports 80 and 443, and never tells the client what the target answered. New accounts can wait for approval. |
| Agents | The agent takes **no commands** from the server, runs only hooks from its root-owned `agent.yaml`, writes only below its `paths`, and runs in a systemd sandbox. Its certificates last 7 days. Enrollment proves control of the host name. |
| Releases | Built by a workflow from a tag, signed keyless with cosign (Sigstore), with an SBOM per archive. Builds are reproducible. Dependencies are pinned; workflows use pinned actions and a read-only token. |
| Logs | Never contain secrets. Errors name hosts, never passwords or webhook paths. |

The reasons for each are in the plan and in the
[operations guide]({{ '/reference/operations/' | relative_url }}); the rules the code is reviewed against are in
the repository.

## What it does not protect

- **The passphrase, the recovery key and a backup together.** Whoever holds a backup and one of the two
  can sign as your CAs. Keep them apart
  ([Installation]({{ '/install/' | relative_url }}#the-passphrase-and-the-recovery-key)).
- **A server that is unsealed and compromised.** While it is unsealed, the decrypted keys are in its memory.
  If you suspect someone on the server: seal it at once, take it off the network, run
  `audit verify`, and restore onto a clean machine
  ([operations guide §8]({{ '/reference/operations/' | relative_url }}#8-when-something-is-lost-or-wrong)).
- **A lost passphrase and recovery key.** There is no recovery; create new CAs.
- **Clients that trust the wrong root.** Always compare the root's SHA-256 with the admin UI, because the
  trust page is served over plain HTTP so that it works before anything trusts your PKI.

## Verify a download

Every release is signed keyless with cosign: the signature proves the files come from the release workflow
at that tag. Check `checksums.txt`, then the files against it. The commands are in the
[README](https://github.com/Der-Felix/MyOwnPKI#verify-a-download); `install.sh` does the same for the
archive it downloads when cosign is installed. The image is signed too:

```bash
cosign verify ghcr.io/der-felix/myownpki:{{ site.data.release.version }} \
  --certificate-identity "https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml@refs/tags/v{{ site.data.release.version }}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## More

- [Third-party software and licenses](https://github.com/Der-Felix/MyOwnPKI/blob/main/THIRD_PARTY.md)
- [Project plan](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md): the architecture decisions (ADRs)
- [Best practices]({{ '/best-practices/' | relative_url }}) for running it
