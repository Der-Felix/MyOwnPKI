#!/usr/bin/env bash
# Checks the prepared sources of the documentation site (site/) before Jekyll
# builds them. Jekyll itself does not complain about a link to a page that does
# not exist, so this does (.github/workflows/pages.yml, build job).
#
#   site-check.sh              check site/ (run scripts/ci/site-prepare.sh first)
#   site-check.sh --built DIR  check the HTML Jekyll wrote into DIR (after the build)
#   site-check.sh --self-test  table of good and bad fixtures
#
# What it checks, in every page (*.md below site/):
# - the page has front matter with a title and a permalink;
# - every Markdown link [text](target) and reference definition, every
#   href="..." of raw HTML, outside code fences and inline code:
#     {{ '/path/' | relative_url }}#anchor   the page or file must exist, and
#                                            so must the anchor
#     {% link file.md %}#anchor              same
#     /BASEURL/path/#anchor                  same (what site-prepare.sh writes)
#     #anchor                                a heading of the same page
#     https://..., mailto:..., {{ site.repository_url }}...
#                                            counted, not fetched
#     anything else                          an error: a plain relative link
#                                            such as (page.md) breaks under the
#                                            base URL of a project site
# - anchors are the ids kramdown makes (GFM style): the heading in lower case,
#   everything except letters, digits, "_", "-" and spaces removed, spaces
#   replaced by "-", a repeated heading gets "-1", "-2". An explicit {#id} and
#   id="..." in raw HTML count too. Only ASCII letters are understood; the
#   dashes and the ellipsis of the headings in the operations guide are
#   dropped like kramdown does.
# - every url of _data/nav.yml and every relative_url of _layouts/*.html exists;
# - nothing is loaded from another host: no <script>, <iframe>, @import,
#   url(http...), or <link>/<img> with an http(s) address in the layouts, the
#   style sheets and the pages.
#
# With --built DIR it checks what Jekyll made, after the build: every page of the
# sources exists as HTML, no Liquid is left in the output, every href and src
# that stays on the site starts with the base URL and points to a file, every
# #fragment is an id="..." of the target page (so the anchors are checked against
# what kramdown really produced), and nothing loads from another host.
#
# Limits, on purpose: it does not run Liquid (a link built from variables is
# an error, not guessed), does not follow external links (no network), does not
# look at links inside indented code blocks, and does not know headings that
# kramdown creates from Setext underlines. The real test is the Jekyll build
# of the same workflow. Needs only bash, awk, sed, grep and find.
set -euo pipefail

self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
cd "$(dirname "$0")/../.."

dir=${SITE_CHECK_DIR:-site}
errors=0
err() {
  echo "site-check: $*" >&2
  errors=$((errors + 1))
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

# scan FILE: tab-separated records on stdout:
#   H <id>               an anchor of the page
#   L <line> <target>    a link
scan() {
  LC_ALL=C awk '
    NR == 1 && $0 == "---" { infm = 1; next }
    infm { if ($0 == "---") infm = 0; next }
    /^[ \t]*(```|~~~)/ { fence = !fence; next }
    fence { next }
    {
      line = $0
      if (line ~ /^#+[ \t]/) {
        match(line, /^#+/)
        if (RLENGTH <= 6) {
          text = substr(line, RLENGTH + 1)
          sub(/^[ \t]+/, "", text)
          sub(/[ \t]+#+[ \t]*$/, "", text)
          sub(/[ \t]+$/, "", text)
          if (match(text, /\{#[A-Za-z0-9_:.-]+\}[ \t]*$/)) {
            id = substr(text, RSTART + 2, RLENGTH - 3)
            sub(/\}[ \t]*$/, "", id)
          } else {
            id = tolower(text)
            gsub(/[\200-\377]/, "", id)
            gsub(/[^a-z0-9_ -]/, "", id)
            gsub(/ /, "-", id)
          }
          seen[id]++
          if (seen[id] > 1) id = id "-" (seen[id] - 1)
          printf "H\t%s\n", id
        }
      }
      rest = line
      while (match(rest, /id="[^"]*"/)) {
        printf "H\t%s\n", substr(rest, RSTART + 4, RLENGTH - 5)
        rest = substr(rest, RSTART + RLENGTH)
      }
      plain = line
      gsub(/`[^`]*`/, "", plain)
      rest = plain
      while (match(rest, /\]\([^)]*\)/)) {
        t = substr(rest, RSTART + 2, RLENGTH - 3)
        sub(/[ \t]+"[^"]*"$/, "", t)
        printf "L\t%d\t%s\n", NR, t
        rest = substr(rest, RSTART + RLENGTH)
      }
      rest = plain
      while (match(rest, /href="[^"]*"/)) {
        printf "L\t%d\t%s\n", NR, substr(rest, RSTART + 6, RLENGTH - 7)
        rest = substr(rest, RSTART + RLENGTH)
      }
      if (match(plain, /^[ ]?[ ]?[ ]?\[[^]]+\]:[ \t]*[^ \t]+/)) {
        d = substr(plain, RSTART, RLENGTH)
        sub(/^[^]]*\]:[ \t]*/, "", d)
        printf "L\t%d\t%s\n", NR, d
      }
    }
  ' "$1"
}

# front_value FILE KEY: a value from the front matter.
front_value() {
  awk -v key="$2" '
    NR == 1 { if ($0 != "---") exit; next }
    $0 == "---" { exit }
    index($0, key ":") == 1 { v = substr($0, length(key) + 2); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); gsub(/^"|"$/, "", v); print v; exit }
  ' "$1"
}

work=
cleanup() { [ -z "$work" ] || rm -rf "$work"; }

# resolve_path SITEPATH: prints the file that answers it (a page's .md or a
# static file), or nothing.
resolve_path() {
  local p=$1 f
  [ "${p#/}" != "$p" ] || return 0
  f=$(awk -F'\t' -v p="$p" '$1 == p { print $2; exit }' "$work/permalinks.tsv")
  if [ -z "$f" ] && [ "${p%/}" = "$p" ]; then
    f=$(awk -F'\t' -v p="$p/" '$1 == p { print $2; exit }' "$work/permalinks.tsv")
  fi
  if [ -z "$f" ] && [ "$p" != / ] && [ -f "$dir$p" ] && [ ! -d "$dir$p" ]; then
    f=$dir$p
  fi
  printf '%s' "$f"
}

# check_anchor FILE FRAGMENT
has_anchor() {
  awk -F'\t' -v f="$1" -v a="$2" '$1 == f && $2 == a { found = 1; exit } END { exit !found }' "$work/anchors.tsv"
}

checked=0
external=0

# check_link FILE LINE TARGET
check_link() {
  local file=$1 line=$2 t=$3 target='' frag='' path='' resolved='' re_rel re_link
  re_rel="^\\{\\{[[:space:]]*['\"]([^'\"]*)['\"][[:space:]]*\\|[[:space:]]*relative_url[[:space:]]*\\}\\}(#.*)?$"
  re_link="^\\{%[[:space:]]*link[[:space:]]+([^[:space:]%]+)[[:space:]]*%\\}(#.*)?$"
  t=${t#"${t%%[![:space:]]*}"}
  t=${t%"${t##*[![:space:]]}"}
  t=${t#<}
  t=${t%>}
  [ -n "$t" ] || { err "$file:$line: empty link target"; return; }
  checked=$((checked + 1))
  case $t in
    http://* | https://* | mailto:* | tel:* | '{{ site.repository_url }}'*)
      external=$((external + 1))
      return
      ;;
    '#'*)
      frag=${t#\#}
      target=$file
      ;;
    *)
      if [[ $t =~ $re_rel ]]; then
        path=${BASH_REMATCH[1]}
        frag=${BASH_REMATCH[2]#\#}
        resolved=$(resolve_path "$path")
        [ -n "$resolved" ] || { err "$file:$line: relative_url target $path does not exist"; return; }
        target=$resolved
      elif [[ $t =~ $re_link ]]; then
        path=${BASH_REMATCH[1]}
        frag=${BASH_REMATCH[2]#\#}
        [ -f "$dir/$path" ] || { err "$file:$line: {% link %} target $path does not exist"; return; }
        target=$dir/$path
      elif [ -n "$base" ] && [ "${t#"$base"/}" != "$t" ]; then
        path=${t#"$base"}
        frag=
        case $path in *'#'*) frag=${path#*#}; path=${path%%#*} ;; esac
        resolved=$(resolve_path "$path")
        [ -n "$resolved" ] || { err "$file:$line: $t does not exist"; return; }
        target=$resolved
      else
        err "$file:$line: '$t' is not a link that works under the base URL; write {{ '/page/' | relative_url }}"
        return
      fi
      ;;
  esac
  if [ -n "$frag" ]; then
    case $target in
      *.md)
        has_anchor "$target" "$frag" || err "$file:$line: no heading with the anchor #$frag in $target"
        ;;
    esac
  fi
}

check_site() {
  local f t line id url base pages=0 anchors links
  [ -d "$dir" ] || { echo "site-check: $dir does not exist" >&2; return 1; }
  [ -f "$dir/_config.yml" ] || { echo "site-check: $dir/_config.yml is missing" >&2; return 1; }
  base=$(read_baseurl "$dir")
  work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-site-check.XXXXXX")
  : >"$work/permalinks.tsv"
  : >"$work/anchors.tsv"
  : >"$work/links.tsv"

  # Pages and their permalinks.
  while IFS= read -r f; do
    pages=$((pages + 1))
    if [ "$(head -n 1 "$f")" != '---' ]; then
      err "$f: no front matter; Jekyll would copy the file instead of building a page"
      continue
    fi
    [ -n "$(front_value "$f" title)" ] || err "$f: no title in the front matter"
    id=$(front_value "$f" permalink)
    if [ -z "$id" ]; then
      err "$f: no permalink in the front matter"
    else
      if awk -F'\t' -v p="$id" '$1 == p { found = 1 } END { exit !found }' "$work/permalinks.tsv"; then
        err "$f: the permalink $id is used twice"
      fi
      printf '%s\t%s\n' "$id" "$f" >>"$work/permalinks.tsv"
    fi
    scan "$f" | while IFS=$'\t' read -r kind a b; do
      if [ "$kind" = H ]; then
        printf '%s\t%s\n' "$f" "$a" >>"$work/anchors.tsv"
      else
        printf '%s\t%s\t%s\n' "$f" "$a" "$b" >>"$work/links.tsv"
      fi
    done
  done < <(find "$dir" \( -name _site -o -name .jekyll-cache -o -name node_modules \) -prune -o -name '*.md' -print | sort)
  [ "$pages" -gt 0 ] || err "no pages found below $dir"

  while IFS=$'\t' read -r f line t; do
    check_link "$f" "$line" "$t"
  done <"$work/links.tsv"

  # The navigation and the layouts.
  if [ -f "$dir/_data/nav.yml" ]; then
    while IFS= read -r url; do
      checked=$((checked + 1))
      [ -n "$(resolve_path "$url")" ] || err "$dir/_data/nav.yml: $url is not the permalink of a page"
    done < <(sed -n "s/^[[:space:]-]*url:[[:space:]]*\"\{0,1\}\([^\" ]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$dir/_data/nav.yml")
  else
    err "$dir/_data/nav.yml is missing"
  fi
  for f in "$dir"/_layouts/*.html; do
    [ -f "$f" ] || { err "$dir/_layouts has no layout"; break; }
    while IFS= read -r url; do
      checked=$((checked + 1))
      [ -n "$(resolve_path "$url")" ] || err "$f: relative_url target $url does not exist"
    done < <(sed -n "s/.*['\"]\\(\\/[^'\"]*\\)['\"][[:space:]]*|[[:space:]]*relative_url.*/\\1/p" "$f")
  done

  # Nothing from other hosts.
  while IFS= read -r f; do
    if grep -nEi "<script|<iframe|<object|<embed|@import|url\\([\"']?(https?:)?//|<link[^>]*(href|src)=[\"'](https?:)?//|<img[^>]*src=[\"'](https?:)?//|<source[^>]*src=[\"'](https?:)?//" "$f" >"$work/external.txt"; then
      while IFS= read -r line; do
        err "$f:$line (loads or runs something from outside the site)"
      done <"$work/external.txt"
    fi
  done < <(find "$dir" \( -name _site -o -name .jekyll-cache \) -prune -o \( -name '*.md' -o -name '*.html' -o -name '*.css' \) -print | sort)

  anchors=$(wc -l <"$work/anchors.tsv" | tr -d ' ')
  links=$(wc -l <"$work/links.tsv" | tr -d ' ')
  echo "site-check: $pages pages, $anchors anchors, $links links in the pages ($external external, not fetched), $checked targets checked"
  [ "$errors" -eq 0 ]
}

# check_built OUT: checks the HTML that Jekyll wrote (run after the build).
# Here the anchors are the real ones: every id="..." of the output.
check_built() {
  local out=$1 base f p rel href path frag target pages=0 links=0 ext=0 line
  [ -d "$out" ] || { echo "site-check: $out does not exist; build the site first" >&2; return 1; }
  base=$(read_baseurl "$dir")
  work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-site-check.XXXXXX")

  # Every page of the sources was built, and the style sheet is there.
  while IFS= read -r f; do
    p=$(front_value "$f" permalink)
    [ -n "$p" ] || continue
    pages=$((pages + 1))
    case $p in
      */) rel=$out${p}index.html ;;
      *) rel=$out$p ;;
    esac
    [ -f "$rel" ] || err "$f: $p was not built ($rel is missing)"
  done < <(find "$dir" \( -name _site -o -name .jekyll-cache \) -prune -o -name '*.md' -print | sort)
  [ -f "$out/assets/site.css" ] || err "$out/assets/site.css is missing"

  # The ids of every page.
  : >"$work/ids.tsv"
  while IFS= read -r f; do
    grep -oE ' id="[^"]*"' "$f" | sed 's/^ id="//; s/"$//' | while IFS= read -r p; do
      printf '%s\t%s\n' "$f" "$p"
    done >>"$work/ids.tsv" || true
  done < <(find "$out" -name '*.html' | sort)

  while IFS= read -r f; do
    if grep -nE '\{\{|\{%' "$f" >"$work/liquid.txt"; then
      while IFS= read -r line; do
        err "$f:${line%%:*}: Liquid left in the output (a tag that was not rendered)"
      done <"$work/liquid.txt"
    fi
    if grep -nEi '<script|<iframe|<object|<embed|@import|<link[^>]*(href|src)="(https?:)?//|<img[^>]*src="(https?:)?//' "$f" >"$work/external.txt"; then
      while IFS= read -r line; do
        err "$f:${line%%:*}: loads or runs something from outside the site"
      done <"$work/external.txt"
    fi
    while IFS= read -r href; do
      links=$((links + 1))
      href=${href#*=\"}
      href=${href%\"}
      case $href in
        http://* | https://* | mailto:* | tel:*)
          ext=$((ext + 1))
          continue
          ;;
        '#'*) target=$f; frag=${href#\#} ;;
        /*)
          if [ -z "$base" ] || [ "${href#"$base"/}" = "$href" ]; then
            err "$f: '$href' is a link without the base URL $base"
            continue
          fi
          path=${href#"$base"}
          frag=
          case $path in *'#'*) frag=${path#*#}; path=${path%%#*} ;; esac
          case $path in
            */) target=$out${path}index.html ;;
            *) target=$out$path ;;
          esac
          if [ ! -f "$target" ]; then
            err "$f: '$href' does not exist in the output"
            continue
          fi
          ;;
        *)
          err "$f: '$href' is a relative link; the pages must use absolute paths with the base URL"
          continue
          ;;
      esac
      if [ -n "$frag" ] && [ "${target%.html}" != "$target" ]; then
        awk -F'\t' -v f="$target" -v a="$frag" '$1 == f && $2 == a { found = 1; exit } END { exit !found }' "$work/ids.tsv" ||
          err "$f: '$href' - no element with id=\"$frag\" in $target"
      fi
    done < <(grep -oE '(href|src)="[^"]*"' "$f")
  done < <(find "$out" -name '*.html' | sort)

  echo "site-check: $pages pages built, $links links in the HTML ($ext external, not fetched) checked"
  [ "$errors" -eq 0 ]
}

self_test() {
  local failures=0
  fx=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-site-check-test.XXXXXX")
  trap 'rm -rf "$fx"' EXIT

  make_fixture() {
    rm -rf "$fx/site"
    mkdir -p "$fx/site/_layouts" "$fx/site/_data" "$fx/site/assets"
    printf 'title: t\nbaseurl: "/MyOwnPKI"\n' >"$fx/site/_config.yml"
    printf '<html><head><link rel="stylesheet" href="{{ '"'"'/assets/site.css'"'"' | relative_url }}"></head><body>{{ content }}</body></html>\n' >"$fx/site/_layouts/default.html"
    printf -- '- title: Home\n  url: /\n- title: A\n  url: /a/\n  children:\n    - title: B\n      url: /a/b/\n' >"$fx/site/_data/nav.yml"
    : >"$fx/site/assets/site.css"
    printf -- '---\ntitle: "Home"\npermalink: /\n---\nSee [a]({{ '"'"'/a/'"'"' | relative_url }}#section-one) and [b]({{ '"'"'/a/b/'"'"' | relative_url }}).\n' >"$fx/site/index.md"
    {
      printf -- '---\ntitle: "A"\npermalink: /a/\n---\n'
      printf '## Section one\n\n## 2.1 With install.sh \342\200\223 the default\n\n### Added\n\n### Added\n\n## 13. `code` Thing\n\n'
      printf 'Links: [same](#section-one), [dup](#added-1), [dash](#21-with-installsh--the-default), [code](#13-code-thing),\n'
      printf '[ext](https://example.org/x), [abs](/MyOwnPKI/a/b/#top), [link]({%% link index.md %%}), [css]({{ '"'"'/assets/site.css'"'"' | relative_url }}).\n\n'
      printf '```text\n[ignored](missing.md)\n```\n\nand `[ignored](missing.md)` in code.\n'
    } >"$fx/site/a.md"
    printf -- '---\ntitle: "B"\npermalink: /a/b/\n---\n<h2 id="top">Top</h2>\n' >"$fx/site/b.md"
  }

  run_check() { SITE_CHECK_DIR="$fx/site" bash "$self" >"$fx/out.txt" 2>&1; }

  expect_pass() {
    if ! run_check; then
      echo "site-check self-test FAILED: $1 was rejected:" >&2
      cat "$fx/out.txt" >&2
      failures=$((failures + 1))
    fi
  }
  expect_fail() { # expect_fail NAME PATTERN
    if run_check; then
      echo "site-check self-test FAILED: $1 was accepted" >&2
      failures=$((failures + 1))
    elif ! grep -q -- "$2" "$fx/out.txt"; then
      echo "site-check self-test FAILED: $1 failed with another message than '$2':" >&2
      cat "$fx/out.txt" >&2
      failures=$((failures + 1))
    fi
  }

  make_fixture
  expect_pass 'the good fixture'

  make_fixture
  printf '[x]({{ '"'"'/nowhere/'"'"' | relative_url }})\n' >>"$fx/site/b.md"
  expect_fail 'a missing page' 'nowhere'

  make_fixture
  printf '[x]({{ '"'"'/a/'"'"' | relative_url }}#no-such-heading)\n' >>"$fx/site/b.md"
  expect_fail 'a missing anchor' 'no-such-heading'

  make_fixture
  printf '[x](#no-such-heading)\n' >>"$fx/site/b.md"
  expect_fail 'a missing local anchor' 'no-such-heading'

  make_fixture
  printf '[x](a.md)\n' >>"$fx/site/b.md"
  expect_fail 'a plain relative link' 'relative_url'

  make_fixture
  printf '[x]({%% link missing.md %%})\n' >>"$fx/site/b.md"
  expect_fail 'a missing link tag target' 'missing.md'

  make_fixture
  printf '[x](/MyOwnPKI/gone/)\n' >>"$fx/site/b.md"
  expect_fail 'a missing absolute target' 'gone'

  make_fixture
  printf '[x]({{ '"'"'/assets/missing.css'"'"' | relative_url }})\n' >>"$fx/site/b.md"
  expect_fail 'a missing asset' 'missing.css'

  make_fixture
  printf -- '- title: C\n  url: /c/\n' >>"$fx/site/_data/nav.yml"
  expect_fail 'a navigation entry without a page' '/c/'

  make_fixture
  printf '<script src="https://cdn.example.org/x.js"></script>\n' >>"$fx/site/_layouts/default.html"
  expect_fail 'a script' 'outside the site'

  make_fixture
  printf '@import url(https://fonts.example.org/f.css);\n' >>"$fx/site/assets/site.css"
  expect_fail 'an import in the style sheet' 'outside the site'

  make_fixture
  printf -- '---\ntitle: "Dup"\npermalink: /a/b/\n---\n' >"$fx/site/c.md"
  expect_fail 'a repeated permalink' 'used twice'

  make_fixture
  printf 'no front matter\n' >"$fx/site/c.md"
  expect_fail 'a page without front matter' 'front matter'

  make_fixture
  printf -- '---\npermalink: /c/\n---\n' >"$fx/site/c.md"
  expect_fail 'a page without a title' 'no title'

  make_fixture
  printf '[x]({{ page.url | relative_url }})\n' >>"$fx/site/b.md"
  expect_fail 'a link built from a variable' 'relative_url'

  # The built HTML.
  make_built() {
    rm -rf "$fx/out"
    mkdir -p "$fx/out/a/b" "$fx/out/assets"
    : >"$fx/out/assets/site.css"
    printf '<h1 id="home">Home</h1><a href="/MyOwnPKI/a/#section-one">a</a> <a href="/MyOwnPKI/">home</a>\n' >"$fx/out/index.html"
    printf '<link rel="stylesheet" href="/MyOwnPKI/assets/site.css"><h2 id="section-one">One</h2><a href="#section-one">up</a> <a href="https://example.org/">x</a> <a href="/MyOwnPKI/a/b/#top">b</a>\n' >"$fx/out/a/index.html"
    printf '<h2 id="top">Top</h2>\n' >"$fx/out/a/b/index.html"
  }
  run_built() { SITE_CHECK_DIR="$fx/site" bash "$self" --built "$fx/out" >"$fx/out.txt" 2>&1; }
  expect_built_fail() { # NAME PATTERN
    if run_built; then
      echo "site-check self-test FAILED: built output with $1 was accepted" >&2
      failures=$((failures + 1))
    elif ! grep -q -- "$2" "$fx/out.txt"; then
      echo "site-check self-test FAILED: built output with $1 failed with another message than '$2':" >&2
      cat "$fx/out.txt" >&2
      failures=$((failures + 1))
    fi
  }

  make_fixture
  make_built
  if ! run_built; then
    echo 'site-check self-test FAILED: the good built output was rejected:' >&2
    cat "$fx/out.txt" >&2
    failures=$((failures + 1))
  fi

  make_built
  printf '<a href="/MyOwnPKI/a/#nothing">x</a>\n' >>"$fx/out/index.html"
  expect_built_fail 'a missing id' 'nothing'

  make_built
  printf '<a href="/a/">x</a>\n' >>"$fx/out/index.html"
  expect_built_fail 'a link without the base URL' 'base URL'

  make_built
  printf '<a href="a/">x</a>\n' >>"$fx/out/index.html"
  expect_built_fail 'a relative link' 'relative link'

  make_built
  printf '<a href="/MyOwnPKI/gone/">x</a>\n' >>"$fx/out/index.html"
  expect_built_fail 'a link to a page that is not there' 'gone'

  make_built
  printf '<script src="/MyOwnPKI/x.js"></script>\n' >>"$fx/out/index.html"
  expect_built_fail 'a script' 'outside the site'

  make_built
  printf '<p>{{ site.data.release.version }}</p>\n' >>"$fx/out/index.html"
  expect_built_fail 'Liquid left over' 'Liquid'

  make_built
  rm "$fx/out/a/b/index.html"
  expect_built_fail 'a page that was not built' 'was not built'

  if [ "$failures" -ne 0 ]; then
    echo "site-check self-test: $failures failure(s)" >&2
    exit 1
  fi
  echo 'site-check self-test: all cases passed'
}

case ${1:-} in
  '')
    trap cleanup EXIT
    check_site
    ;;
  --built)
    [ $# -eq 2 ] || { echo 'usage: site-check.sh --built DIR' >&2; exit 2; }
    trap cleanup EXIT
    check_built "$2"
    ;;
  --self-test) self_test ;;
  *)
    echo 'usage: site-check.sh [--built DIR | --self-test]' >&2
    exit 2
    ;;
esac
