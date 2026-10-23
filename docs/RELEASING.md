# Releasing MyOwnPKI

The owner's checklist for a release, the way v0.1.0 went: a rehearsal with a release candidate,
check it, remove it completely, then the real tag, check the draft, publish. Only the owner pushes,
tags and publishes. Pushing a `v*` tag starts
[`.github/workflows/release.yml`](../.github/workflows/release.yml): it runs the tests, builds the
archives, SBOMs and the container image with GoReleaser ([`.goreleaser.yaml`](../.goreleaser.yaml)),
signs the checksum file and the image keyless with cosign, pushes the image to GHCR and creates a
**draft** release. Nothing on the release page is visible until it is published.

## Set the version

Every command below uses the variable `VERSION` and works unchanged in Git Bash and in Windows
PowerShell 5.1: the commands write `"${VERSION}"` in double quotes, which both shells expand.
Commands that differ between the shells are marked. Set the version once per shell window:

```bash
VERSION=0.2.0
```

```powershell
$VERSION = "0.2.0"
```

The sections "Check the draft" and "Remove a draft" are used twice – for the release candidate
and for the real release. They use a second variable, `RELEASE`, set where they are needed.

The commands need the GitHub CLI `gh`, signed in (`gh auth status`), git, cosign
(<https://github.com/sigstore/cosign/releases>) and Docker.

If `gh` fails with a proxy or name-resolution error because a proxy in between can't resolve
`api.github.com`, let it bypass the proxy for GitHub in this shell window:

```bash
export NO_PROXY=github.com,api.github.com
```

```powershell
$env:NO_PROXY = "github.com,api.github.com"
```

## Once: GitHub settings

- **Description** (repository page → ⚙ next to *About*): for example *Self-hosted PKI – CA engine,
  ACME server, web UI and REST API; replaces a Bash PKI.* Update it when the scope grows.
- **Topics:** `pki`, `certificate-authority`, `x509`, `self-hosted`, `homelab`, `golang`, `crl`,
  `acme`.
- **Tag protection for `v*`:** *Settings → Rules → Rulesets → New ruleset → New tag ruleset*;
  name `release tags`, enforcement *Active*, target *Include by pattern* `v*`; rules *Restrict
  creations*, *Restrict updates*, *Restrict deletions*; add yourself (*Repository admin*) to the
  bypass list. Then only you can create, move or delete a release tag.
- Optional: *Settings → General → Releases → Enable release immutability* – a published release
  can't be changed afterwards (the draft still can).
- *Settings → Actions → General → Workflow permissions* stays at *Read repository contents*: the
  release job asks for its three permissions itself.
- The GHCR package `myownpki` is **public** since v0.1.0; new versions take the package's
  visibility. (Only for the very first release: profile → *Packages* → `myownpki` → *Package
  settings* → *Change visibility* → *Public*; under *Manage Actions access* the repository
  `MyOwnPKI` should be listed.)
- For removing image versions, `gh` needs the package scopes once:

  ```bash
  gh auth refresh -h github.com -s read:packages,delete:packages
  ```

## Before the tag

1. Check the branch: read the report at the top of `docs/NIGHTLOG.md` (after a night run), test in
   the browser, run `task check`.
2. `CHANGELOG.md`: the section `## [<version>] - <date>` must carry the day you push the tag –
   change it if not and commit (`docs: date of v<version>`). The release notes are taken from this
   section; the workflow stops if it is missing. What the workflow will take (Git Bash – the same
   awk line as in release.yml):

   ```bash
   awk -v head="## [${VERSION}]" 'index($0, head) == 1 { p = 1; next } p && /^## \[/ { exit } p && /^\[[^]]*\]: / { next } p' CHANGELOG.md
   ```

3. `deploy/install.sh`: `DEFAULT_VERSION=<version>` – the version `install.sh` installs without
   `--version`. The workflow stops if it differs from the tag (for a candidate: from its base
   version). Check it (Git Bash, or `Select-String` in PowerShell):

   ```bash
   grep "^DEFAULT_VERSION=" deploy/install.sh
   ```

4. Merge into main – through the pull request once its CI is green – and bring the local main up
   to date, so the tags below land on the merged commit:

   ```bash
   git switch main
   ```

   ```bash
   git pull --ff-only origin main
   ```

5. Wait until CI on main is green (*Actions → CI*). Don't tag a red main.

## Rehearsal: the release candidate

Run the whole pipeline once with a release candidate before the real tag – the workflow, the image
build and the signatures can only be tried for real:

```bash
git tag -a "v${VERSION}-rc.1" -m "MyOwnPKI v${VERSION}-rc.1"
```

```bash
git push origin "v${VERSION}-rc.1"
```

The workflow (*Actions → Release*) takes about 10–15 minutes. The release notes come from the
`## [<version>]` section (a pre-release tag without its own section takes the one of its base
version); GoReleaser marks the draft as **Pre-release** by itself, and the image gets the tag
`<version>-rc.1`.

Then check the candidate – set `RELEASE` and go through "Check the draft":

```bash
RELEASE="${VERSION}-rc.1"
```

```powershell
$RELEASE = "${VERSION}-rc.1"
```

Then remove it completely, with the same `RELEASE`, as in "Remove a draft" – draft, tag and image
versions – and don't publish it. A second rehearsal would be `-rc.2`.

## The tag

```bash
git tag -a "v${VERSION}" -m "MyOwnPKI v${VERSION}"
```

```bash
git push origin "v${VERSION}"
```

The workflow refuses a tag whose commit is not on main. When it is done, check the draft:

```bash
RELEASE="${VERSION}"
```

```powershell
$RELEASE = "${VERSION}"
```

## Check the draft

The draft, its assets and the pre-release mark:

```bash
gh release view "v${RELEASE}" --json name,isDraft,isPrerelease,assets --jq "{name, isDraft, isPrerelease, assets: [.assets[].name]}"
```

- `isDraft` true; `isPrerelease` true for a candidate, false for the real release.
- 13 assets: 5 archives (`myownpki_<release>_linux_amd64.tar.gz`, `…_linux_arm64.tar.gz`,
  `…_darwin_arm64.tar.gz`, `…_freebsd_amd64.tar.gz`, `…_windows_amd64.zip`), 5 SBOMs
  (`*.sbom.json`), `install.sh`, `checksums.txt` and `checksums.txt.sigstore.json`. The archives
  also hold `deploy/install.sh` and the systemd unit with its drop-in.

The release notes – **the text must not be empty**: the length is more than 0, and the text starts
with the first lines of the version's CHANGELOG section, without a list of commits:

```bash
gh release view "v${RELEASE}" --json body --jq ".body | length"
```

```bash
gh release view "v${RELEASE}" --json body --jq ".body"
```

An empty text means GoReleaser skipped its changelog step, the one that reads the notes (the
v0.1.0 draft had this, with `changelog: disable: true`): fill the text in by hand and fix the
config before the next tag.

Download the checksum file, its signature and one archive into a new directory, and check them as
the README says:

```bash
gh release download "v${RELEASE}" --dir "release-${RELEASE}" --pattern "checksums.txt*" --pattern "myownpki_${RELEASE}_windows_amd64.zip"
```

```bash
cd "release-${RELEASE}"
```

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml@refs/tags/v${RELEASE}" --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

The archive against the checksum file – Git Bash:

```bash
sha256sum --check --ignore-missing checksums.txt
```

PowerShell (compare the two values; `Get-FileHash` prints upper case):

```powershell
Get-FileHash "myownpki_${RELEASE}_windows_amd64.zip"
```

```powershell
Select-String "windows_amd64" checksums.txt
```

```bash
cd ..
```

The image is already in GHCR:

```bash
cosign verify "ghcr.io/der-felix/myownpki:${RELEASE}" --certificate-identity "https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml@refs/tags/v${RELEASE}" --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
docker pull "ghcr.io/der-felix/myownpki:${RELEASE}"
```

```bash
docker run --rm "ghcr.io/der-felix/myownpki:${RELEASE}" --version
```

It prints `myownpki v<release> (commit …)`.

## Publish

Only the real release, after "Check the draft" with `RELEASE` = `VERSION`:

```bash
gh release edit "v${VERSION}" --draft=false --latest
```

```bash
gh release view "v${VERSION}" --json isDraft,isPrerelease,url
```

Both marks are false, and the URL is the release page. (In the browser instead: the draft → *Edit*
→ *Set as the latest release* ticked → *Publish release*.)

## Remove a draft

For the rehearsal after its check, and for a real release with a problem – as long as it is not
published. `RELEASE` says which one.

1. The draft release:

   ```bash
   gh release delete "v${RELEASE}" --yes
   ```

2. The tag on GitHub and locally (with tag protection, as the bypass user):

   ```bash
   git push --delete origin "v${RELEASE}"
   ```

   ```bash
   git tag -d "v${RELEASE}"
   ```

3. The image versions in GHCR. One run pushes several versions: the tagged image index
   (`<release>`), its untagged platform images (linux/amd64, linux/arm64) and the signature
   (tag `sha256-<digest>.sig`). List all versions with their time and tags:

   ```bash
   gh api "/user/packages/container/myownpki/versions?per_page=100" --jq ".[] | {id, created_at, tags: .metadata.container.tags}"
   ```

   Delete every version created by this run – the tagged `<release>` and the versions with the
   same `created_at` minute – one id at a time (replace `123456789`). **Never** delete versions
   of an earlier release.

   ```bash
   gh api --method DELETE "/user/packages/container/myownpki/versions/123456789"
   ```

   List again to check. (Through the browser instead: *Package settings → Manage versions*.)

4. A real release with a problem: fix on a branch, merge, wait for green CI, tag again.

After publishing, don't move or delete a tag: fix forward with the next patch version.
