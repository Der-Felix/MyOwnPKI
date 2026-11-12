#!/usr/bin/env bash
# Prepares the sources of the documentation site (site/, built by
# .github/workflows/pages.yml with GitHub's Jekyll action).
#
# The operations guide, the release notes and the example configuration live
# in the repository where they are maintained (docs/OPERATIONS.md,
# CHANGELOG.md, deploy/config.example.yaml). This script does not copy them by
# hand into the site: it writes generated pages into site/reference/ (not
# committed, .gitignore) with a front-matter block in front, the whole text
# wrapped in {% raw %} so Liquid never touches it, and every relative link
# rewritten so it works on the site:
#
#   a link to docs/OPERATIONS.md, CHANGELOG.md or deploy/config.example.yaml
#                          -> the matching page of the site (with its anchor)
#   a link to another directory or file of the repository
#                          -> the GitHub page of it (tree/main or blob/main)
#   a link to something that does not exist, or outside the repository
#                          -> an error: nothing is guessed
#
# It also writes site/_data/release.yml (version and date of the newest
# numbered release in CHANGELOG.md) for the footer and the home page.
#
#   site-prepare.sh              generate site/reference/ and site/_data/release.yml
#   site-prepare.sh --check      generate into a temporary directory and verify
#                                the result; changes nothing in the repository
#   site-prepare.sh --self-test  table of cases for the link rewriting and an
#                                end-to-end run on a small fixture
#   site-prepare.sh --clean      remove what the default mode generates
#
# Needs only bash, awk, sed, grep and mktemp. The link rewriting skips fenced
# code blocks and does not look into inline code; the sources have none that
# looks like a link.
set -euo pipefail

self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
root=${SITE_PREPARE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$root"

REPO_URL=https://github.com/Der-Felix/MyOwnPKI
SITE_DIR=site

die() {
  echo "site-prepare: $*" >&2
  exit 1
}

# read_baseurl SITE: the baseurl of _config.yml without a trailing slash.
read_baseurl() {
  local v
  v=$(sed -n 's/^baseurl:[[:space:]]*//p' "$1/_config.yml" | head -n 1)
  v=${v%%#*}
  v=${v//\"/}
  v=${v//\'/}
  v=${v//[[:space:]]/}
  printf '%s' "${v%/}"
}

# latest_release CHANGELOG: "VERSION DATE" of the first numbered release.
latest_release() {
  sed -n 's/^## \[\([0-9][0-9A-Za-z.+-]*\)\] - \([0-9][0-9-]*\).*$/\1 \2/p' "$1" | head -n 1
}

# strip_h1: drops a first line "# Title" and the blank line after it; the
# layout prints the title of the page itself.
strip_h1() {
  awk 'NR == 1 && /^# / { skip = 1; next } skip && /^$/ { skip = 0; next } { skip = 0; print }'
}

# rewrite_links SRCDIR BASEURL: stdin to stdout. SRCDIR is the directory of
# the source file in the repository ("docs"), so ../README.md is README.md.
rewrite_links() {
  awk -v srcdir="$1" -v base="$2" -v repo="$REPO_URL" '
    function normalize(path,   n, parts, i, k, stack, out) {
      n = split(path, parts, "/")
      k = 0
      for (i = 1; i <= n; i++) {
        if (parts[i] == "" || parts[i] == ".") continue
        if (parts[i] == "..") { if (k == 0) return ""; k--; continue }
        stack[++k] = parts[i]
      }
      out = ""
      for (i = 1; i <= k; i++) out = out (i > 1 ? "/" : "") stack[i]
      return out
    }
    function fail(msg) { bad = bad "site-prepare: line " NR ": " msg "\n" }
    function map(target,   hash, path, frag, resolved) {
      hash = index(target, "#")
      if (hash) { path = substr(target, 1, hash - 1); frag = substr(target, hash) } else { path = target; frag = "" }
      if (path == "") return target
      if (path ~ /^[A-Za-z][A-Za-z0-9+.-]*:/ || path ~ /^\//) return target
      if (path !~ "^[A-Za-z0-9._/-]+$") { fail("unsupported characters in the link " target); return target }
      resolved = normalize(srcdir == "" ? path : srcdir "/" path)
      if (resolved == "") { fail("the link " target " leaves the repository"); return target }
      if (resolved == "docs/OPERATIONS.md") return base "/reference/operations/" frag
      if (resolved == "CHANGELOG.md") return base "/reference/changelog/" frag
      if (resolved == "deploy/config.example.yaml") return base "/reference/configuration/" frag
      if (system("test -d \"" resolved "\"") == 0) return repo "/tree/main/" resolved frag
      if (system("test -f \"" resolved "\"") == 0) return repo "/blob/main/" resolved frag
      fail("the link " target " points to " resolved ", which does not exist")
      return target
    }
    /^[ \t]*(```|~~~)/ { fence = !fence; print; next }
    fence { print; next }
    {
      rest = $0
      out = ""
      while (match(rest, /\]\([^)]*\)/)) {
        inner = substr(rest, RSTART + 2, RLENGTH - 3)
        sp = index(inner, " ")
        if (sp) { t = substr(inner, 1, sp - 1); tail = substr(inner, sp) } else { t = inner; tail = "" }
        out = out substr(rest, 1, RSTART - 1) "](" map(t) tail ")"
        rest = substr(rest, RSTART + RLENGTH)
      }
      print out rest
    }
    END { if (bad != "") { printf "%s", bad > "/dev/stderr"; exit 3 } }
  '
}

# leftover_links FILE: prints every link target in FILE (outside code fences)
# that is neither an anchor nor an absolute URL nor below the base URL.
leftover_links() {
  awk -v base="$2" '
    /^[ \t]*(```|~~~)/ { fence = !fence; next }
    fence { next }
    {
      rest = $0
      while (match(rest, /\]\([^)]*\)/)) {
        t = substr(rest, RSTART + 2, RLENGTH - 3)
        sub(/ .*$/, "", t)
        if (t !~ /^#/ && t !~ /^[A-Za-z][A-Za-z0-9+.-]*:/ && index(t, base "/") != 1) print FILENAME ":" NR ": " t
        rest = substr(rest, RSTART + RLENGTH)
      }
    }
  ' "$1"
}

# front_matter TITLE PERMALINK EDIT_PATH DESCRIPTION
front_matter() {
  printf -- '---\nlayout: default\ntitle: "%s"\ndescription: "%s"\npermalink: %s\nedit_path: %s\ngenerated: true\n---\n' \
    "$1" "$4" "$2" "$3"
}

# require_plain FILE: the text goes into a raw block and a code fence.
require_plain() {
  [ -f "$1" ] || die "$1 is missing"
  [ -s "$1" ] || die "$1 is empty"
  if grep -Eq '\{%-?[[:space:]]*endraw' "$1"; then
    die "$1 contains an endraw tag, which would end the raw block of the page"
  fi
}

# generate SITE: writes SITE/reference/*.md and SITE/_data/release.yml.
generate() {
  local site=$1 base release version date out
  [ -f "$site/_config.yml" ] || die "$site/_config.yml is missing"
  base=$(read_baseurl "$site")
  case $base in
    '' | /*) ;;
    *) die "baseurl in $site/_config.yml must start with a slash: $base" ;;
  esac

  require_plain docs/OPERATIONS.md
  require_plain CHANGELOG.md
  require_plain deploy/config.example.yaml
  if grep -Eq '^[[:space:]]*(```|~~~)' deploy/config.example.yaml; then
    die "deploy/config.example.yaml contains a code fence; the example page would break"
  fi

  release=$(latest_release CHANGELOG.md)
  [ -n "$release" ] || die "CHANGELOG.md has no numbered release (## [X.Y.Z] - DATE)"
  version=${release%% *}
  date=${release#* }

  out=$site/reference
  rm -rf "$out"
  mkdir -p "$out" "$site/_data"
  printf '# Generated by scripts/ci/site-prepare.sh from CHANGELOG.md. Do not edit.\nversion: "%s"\ndate: "%s"\n' \
    "$version" "$date" >"$site/_data/release.yml"

  {
    front_matter 'Operations guide' /reference/operations/ docs/OPERATIONS.md \
      'The operator book of MyOwnPKI: install, first start, backup and restore, upgrades, the ACME server, the agent and monitoring.'
    printf 'This is the complete operations guide, `docs/OPERATIONS.md` of the repository, unchanged. The\n'
    printf 'task-oriented pages [Installation](%s/install/), [Upgrade](%s/upgrade/) and\n' "$base" "$base"
    printf '[Adding hosts](%s/hosts/) link into it.\n\n' "$base"
    printf '%s\n' '{% raw %}' '**Contents**' '' '* TOC' '{:toc}' ''
    strip_h1 <docs/OPERATIONS.md | rewrite_links docs "$base"
    printf '\n%s\n' '{% endraw %}'
  } >"$out/operations.md"

  {
    front_matter 'Release notes' /reference/changelog/ CHANGELOG.md \
      'What changed in every release of MyOwnPKI, with the upgrade notes.'
    printf 'This is `CHANGELOG.md` of the repository. The upgrade notes of each release are summarized on\n'
    printf 'the [Upgrade](%s/upgrade/) page.\n\n' "$base"
    printf '%s\n' '{% raw %}'
    strip_h1 <CHANGELOG.md | rewrite_links . "$base"
    printf '\n%s\n' '{% endraw %}'
  } >"$out/changelog.md"

  {
    front_matter 'Configuration file' /reference/configuration/ deploy/config.example.yaml \
      'The example configuration of the MyOwnPKI server with every key explained.'
    printf 'This is `deploy/config.example.yaml` of the repository: every key of `/etc/myownpki/config.yaml`\n'
    printf 'with its default and a comment. Every key can also be set as a `MYOWNPKI_*` environment\n'
    printf 'variable. Check a file with `myownpki config check`. The installation page\n'
    printf '([Installation](%s/install/)) explains which values `install.sh` sets for you.\n\n' "$base"
    printf '%s\n' '{% raw %}' '```yaml'
    cat deploy/config.example.yaml
    printf '%s\n' '```' '{% endraw %}'
  } >"$out/configuration.md"
}

fail_count=0
problem() {
  echo "site-prepare: $*" >&2
  fail_count=$((fail_count + 1))
}

# verify SITE: checks what generate wrote.
verify() {
  local site=$1 base f raws endraws left version shipped
  base=$(read_baseurl "$site")
  for f in operations changelog configuration; do
    if [ ! -s "$site/reference/$f.md" ]; then
      problem "$site/reference/$f.md is missing or empty"
      continue
    fi
    f=$site/reference/$f.md
    [ "$(head -n 1 "$f")" = '---' ] || problem "$f does not start with front matter"
    grep -q '^permalink: /reference/' "$f" || problem "$f has no permalink"
    raws=$(grep -c '^{% raw %}$' "$f" || true)
    endraws=$(grep -c '^{% endraw %}$' "$f" || true)
    if [ "$raws" -ne 1 ] || [ "$endraws" -ne 1 ]; then
      problem "$f: want exactly one raw block, found $raws start and $endraws end tags"
    fi
    left=$(leftover_links "$f" "$base")
    [ -z "$left" ] || problem "links that would not work on the site:
$left"
  done
  if grep -Eq '^version: "[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?"$' "$site/_data/release.yml" 2>/dev/null; then
    version=$(sed -n 's/^version: "\(.*\)"$/\1/p' "$site/_data/release.yml")
    # A different number is a warning, not an error: the changelog is edited
    # for a release before install.sh is.
    shipped=$(sed -n 's/^DEFAULT_VERSION=\(.*\)$/\1/p' deploy/install.sh 2>/dev/null | head -n 1 || true)
    if [ -n "$shipped" ] && [ "$shipped" != "$version" ]; then
      echo "::warning::CHANGELOG.md says $version, deploy/install.sh installs $shipped"
    fi
  else
    problem "$site/_data/release.yml has no valid version"
  fi
  [ "$fail_count" -eq 0 ] || exit 1
}

self_test() {
  local failures=0 got
  fx=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-site-prepare.XXXXXX")
  trap 'rm -rf "$fx"' EXIT

  expect() { # expect NAME WANT INPUT [SRCDIR]
    local name=$1 want=$2 input=$3 dir=${4:-docs}
    got=$(cd "$fx" && printf '%s\n' "$input" | rewrite_links "$dir" /MyOwnPKI 2>/dev/null) || got="FAILED"
    if [ "$got" != "$want" ]; then
      echo "site-prepare self-test FAILED: $name:" >&2
      echo "  got:  $got" >&2
      echo "  want: $want" >&2
      failures=$((failures + 1))
    fi
  }

  mkdir -p "$fx/docs" "$fx/deploy" "$fx/site" "$fx/scripts"
  : >"$fx/README.md"
  : >"$fx/docs/PLAN.md"
  : >"$fx/docs/OPERATIONS.md"
  : >"$fx/CHANGELOG.md"
  : >"$fx/deploy/config.example.yaml"

  expect 'README of the root' '[README](https://github.com/Der-Felix/MyOwnPKI/blob/main/README.md)' '[README](../README.md)'
  expect 'sibling document' '[PLAN](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md)' '[PLAN](PLAN.md)'
  expect 'sibling with ./' '[PLAN](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md#5-security)' '[PLAN](./PLAN.md#5-security)'
  expect 'the example configuration' '[c](/MyOwnPKI/reference/configuration/)' '[c](../deploy/config.example.yaml)'
  expect 'the operations guide with an anchor' '[o](/MyOwnPKI/reference/operations/#12-agent)' '[o](OPERATIONS.md#12-agent)'
  expect 'the changelog' '[l](/MyOwnPKI/reference/changelog/)' '[l](../CHANGELOG.md)'
  expect 'a directory' '[d](https://github.com/Der-Felix/MyOwnPKI/tree/main/deploy)' '[d](../deploy/)'
  expect 'an anchor stays' 'see [x](#section)' 'see [x](#section)'
  expect 'a mailto stays' '[x](mailto:a@homelab.lan)' '[x](mailto:a@homelab.lan)'
  expect 'two links in one line' 'a [x](#a) b [y](https://github.com/Der-Felix/MyOwnPKI/blob/main/README.md) c' 'a [x](#a) b [y](../README.md) c'
  expect 'a title stays' '[x](https://github.com/Der-Felix/MyOwnPKI/blob/main/README.md "the readme")' '[x](../README.md "the readme")'
  expect 'a fenced block stays' "$(printf '%s\n%s\n%s' '```' '[x](../README.md)' '```')" "$(printf '%s\n%s\n%s' '```' '[x](../README.md)' '```')"
  expect 'from the root directory' '[d](https://github.com/Der-Felix/MyOwnPKI/blob/main/docs/PLAN.md)' '[d](docs/PLAN.md)' .
  expect 'a missing file fails' FAILED '[x](../nowhere.md)'
  expect 'a link out of the repository fails' FAILED '[x](../../etc/passwd)'
  expect 'odd characters fail' FAILED '[x](../README.md?x=$(id))'

  # The whole run on a fixture.
  {
    printf '# Operations guide - test\n\nSee [the README](../README.md) and [the plan](PLAN.md#x).\n\n'
    printf '## 1. First\n\nText with {{ braces }} and a [link](#1-first).\n'
  } >"$fx/docs/OPERATIONS.md"
  printf '# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2030-01-02\n\nText.\n\n## [1.2.2] - 2029-12-31\n' >"$fx/CHANGELOG.md"
  printf 'data_dir: /var/lib/myownpki\n' >"$fx/deploy/config.example.yaml"
  printf 'title: t\nbaseurl: "/MyOwnPKI"\n' >"$fx/site/_config.yml"
  if ! (cd "$fx" && SITE_PREPARE_ROOT="$fx" bash "$self" >/dev/null 2>"$fx/err.txt"); then
    echo 'site-prepare self-test FAILED: the run on the fixture failed:' >&2
    cat "$fx/err.txt" >&2
    failures=$((failures + 1))
  else
    grep -q '^version: "1.2.3"$' "$fx/site/_data/release.yml" || { echo 'site-prepare self-test FAILED: wrong version' >&2; failures=$((failures + 1)); }
    grep -q '^date: "2030-01-02"$' "$fx/site/_data/release.yml" || { echo 'site-prepare self-test FAILED: wrong date' >&2; failures=$((failures + 1)); }
    grep -q '^permalink: /reference/operations/$' "$fx/site/reference/operations.md" || { echo 'site-prepare self-test FAILED: no permalink' >&2; failures=$((failures + 1)); }
    grep -q 'blob/main/README.md' "$fx/site/reference/operations.md" || { echo 'site-prepare self-test FAILED: README link' >&2; failures=$((failures + 1)); }
    grep -q '^# Operations guide' "$fx/site/reference/operations.md" && { echo 'site-prepare self-test FAILED: the first heading was kept' >&2; failures=$((failures + 1)); }
    grep -q 'Text with {{ braces }}' "$fx/site/reference/operations.md" || { echo 'site-prepare self-test FAILED: text changed' >&2; failures=$((failures + 1)); }
    grep -q '^```yaml$' "$fx/site/reference/configuration.md" || { echo 'site-prepare self-test FAILED: no yaml block' >&2; failures=$((failures + 1)); }
    (cd "$fx" && SITE_PREPARE_ROOT="$fx" bash "$self" --check >/dev/null 2>&1) || { echo 'site-prepare self-test FAILED: --check on the fixture' >&2; failures=$((failures + 1)); }
  fi

  # A source that would end the raw block is refused.
  printf '# C\n\n## [1.0.0] - 2030-01-01\n\n{%% endraw %%}\n' >"$fx/CHANGELOG.md"
  if (cd "$fx" && SITE_PREPARE_ROOT="$fx" bash "$self" >/dev/null 2>&1); then
    echo 'site-prepare self-test FAILED: an endraw tag was accepted' >&2
    failures=$((failures + 1))
  fi
  # A broken link in the guide stops the run.
  printf '# C\n\n## [1.0.0] - 2030-01-01\n' >"$fx/CHANGELOG.md"
  printf '# O\n\n[x](MISSING.md)\n' >"$fx/docs/OPERATIONS.md"
  if (cd "$fx" && SITE_PREPARE_ROOT="$fx" bash "$self" >/dev/null 2>&1); then
    echo 'site-prepare self-test FAILED: a link to a missing file was accepted' >&2
    failures=$((failures + 1))
  fi

  if [ "$failures" -ne 0 ]; then
    echo "site-prepare self-test: $failures failure(s)" >&2
    exit 1
  fi
  echo 'site-prepare self-test: all cases passed'
}

case ${1:-} in
  '')
    generate "$SITE_DIR"
    verify "$SITE_DIR"
    echo "site-prepare: wrote $SITE_DIR/reference/ and $SITE_DIR/_data/release.yml"
    ;;
  --check)
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-site-prepare.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    cp "$SITE_DIR/_config.yml" "$tmp/_config.yml"
    generate "$tmp"
    verify "$tmp"
    echo 'site-prepare: the generated pages are well-formed'
    ;;
  --self-test) self_test ;;
  --clean)
    rm -rf "$SITE_DIR/reference" "$SITE_DIR/_data/release.yml"
    ;;
  -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo 'usage: site-prepare.sh [--check | --self-test | --clean]' >&2
    exit 2
    ;;
esac
