# Releasing MyOwnPKI

The owner's checklist for a release, written for v0.1.0. Only the owner pushes, tags and
publishes. Pushing a `v*` tag starts [`.github/workflows/release.yml`](../.github/workflows/release.yml):
it runs the tests, builds the archives, SBOMs and the container image with GoReleaser
([`.goreleaser.yaml`](../.goreleaser.yaml)), signs the checksum file and the image keyless with
cosign, pushes the image to GHCR and creates a **draft** release. Nothing on the release page is
visible until you click *Publish*.

## Once: GitHub settings

- **Description** (repository page → ⚙ next to *About*): for example *Self-hosted PKI – CA engine,
  web UI and REST API; replaces a Bash PKI. ACME server next.* Website: empty for now.
- **Topics:** `pki`, `certificate-authority`, `x509`, `self-hosted`, `homelab`, `golang`, `crl`.
- **Tag protection for `v*`:** *Settings → Rules → Rulesets → New ruleset → New tag ruleset*;
  name `release tags`, enforcement *Active*, target *Include by pattern* `v*`; rules *Restrict
  creations*, *Restrict updates*, *Restrict deletions*; add yourself (*Repository admin*) to the
  bypass list. Then only you can create or move a release tag.
- Optional: *Settings → General → Releases → Enable release immutability* – a published release
  can't be changed afterwards (the draft still can).
- *Settings → Actions → General → Workflow permissions* stays at *Read repository contents*: the
  release job asks for its three permissions itself.

## Before the tag

1. Check the branch: read the report at the top of `docs/NIGHTLOG.md`, test in the browser,
   run `task check`.
2. `CHANGELOG.md`: the date in `## [0.1.0] - 2026-10-22` must be the day you push the tag –
   change it if not and commit (`docs: date of v0.1.0`). The release notes are taken from this
   section; the workflow stops if it is missing.
3. Merge into main and push:

   ```bash
   git switch main
   ```

   ```bash
   git merge --ff-only night/v0.1
   ```

   ```bash
   git push origin main
   ```

4. Wait until CI on main is green (*Actions → CI*). Don't tag a red main.

## Rehearsal: v0.1.0-rc.1

Before the real tag, run the whole pipeline once with a release candidate – it is the first time
the workflow, the image build and the signatures run for real:

```bash
git tag -a v0.1.0-rc.1 -m "MyOwnPKI v0.1.0-rc.1"
```

```bash
git push origin v0.1.0-rc.1
```

- The release notes come from the `## [0.1.0]` section (a pre-release tag without its own section
  takes the one of its base version).
- GoReleaser marks the draft as **Pre-release** by itself (the `-rc.1` in the tag), and the image
  gets the tag `0.1.0-rc.1`.
- Check the draft and the image exactly as in "Check the draft" below, with `v0.1.0-rc.1` in the
  cosign identities and `0.1.0-rc.1` as the image tag.

Then remove the rehearsal completely – draft, tag and image version – as in "If something is
wrong" (with `v0.1.0-rc.1` instead of `v0.1.0`), and don't publish it. Only then tag v0.1.0.

## The tag

```bash
git tag -a v0.1.0 -m "MyOwnPKI v0.1.0"
```

```bash
git push origin v0.1.0
```

The workflow refuses a tag whose commit is not on main. It takes about 10–15 minutes.

## Check the draft

On *Releases*, the draft **MyOwnPKI v0.1.0** should have:

- 5 archives (`myownpki_0.1.0_linux_amd64.tar.gz`, `…_linux_arm64.tar.gz`, `…_darwin_arm64.tar.gz`,
  `…_freebsd_amd64.tar.gz`, `…_windows_amd64.zip`) and 5 SBOMs (`*.sbom.json`);
- `checksums.txt` and `checksums.txt.sigstore.json`;
- the release notes from CHANGELOG.md.

Download `checksums.txt`, `checksums.txt.sigstore.json` and one archive, and check them as the
README says (cosign from <https://github.com/sigstore/cosign/releases>):

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml@refs/tags/v0.1.0" --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

```bash
sha256sum --check --ignore-missing checksums.txt
```

The image is already in GHCR – as a **private** package (GHCR's default for a new package):

```bash
cosign verify ghcr.io/der-felix/myownpki:0.1.0 --certificate-identity "https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml@refs/tags/v0.1.0" --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
docker run --rm ghcr.io/der-felix/myownpki:0.1.0 --version
```

## Publish

1. Package visibility: profile → *Packages* → `myownpki` → *Package settings* → *Change
   visibility* → *Public*; under *Manage Actions access* the repository `MyOwnPKI` should be
   listed (the image label links it).
2. On the draft: *Edit* → check that *Set as the latest release* is ticked → *Publish release*.

## If something is wrong

Before publishing, everything can be undone:

1. Delete the draft (*Edit → Delete*).
2. Delete the tag on GitHub and locally (with tag protection, as the bypass user):

   ```bash
   git push --delete origin v0.1.0
   ```

   ```bash
   git tag -d v0.1.0
   ```

3. Delete the image version in GHCR (*Package settings → Manage versions*). If it is the
   package's only version (after the rehearsal), GHCR deletes the whole package instead – that's
   fine, the next release creates it again (private, see "Publish").
4. Fix on a branch, merge, wait for green CI, tag again.

After publishing, don't move a tag: fix forward with v0.1.1.
