#!/usr/bin/env bash
# Coverage report for `task cover`: reads the profile of
#   go test -json -coverpkg=./cmd/...,./internal/... -coverprofile=coverage.out ...
# and prints one line per package. -coverpkg credits an integration test to the package it
# exercises; the merged profile of several test binaries lists a block once per binary, so
# the blocks are merged here first (a block counts as covered when any binary ran it).
# Generated code and test helpers are left out: *_templ.go, internal/gen, internal/store/{pkidb,
# systemdb,auditdb}, internal/tools, internal/testinstance, internal/testutil.
#
# Usage: bash scripts/ci/cover-summary.sh [summary | func [N] | merge | progress | --self-test]
#   summary      (default) table: package, statements, covered, percent, then the total and the
#                number of skipped tests (read from the go test -json file)
#   func [N]     the N functions (default 40) with the most uncovered statements: "13 of 38"
#   merge        the merged and filtered profile on stdout (input of go tool cover -html)
#   progress     reads go test -json on stdin and prints one line per finished package
#   --self-test  runs summary and func on the small profile in scripts/ci/testdata and compares
#                them with the golden files there
#
# Environment: COVER_PROFILE (default coverage.out), COVER_JSON (default coverage.json),
# COVER_MODULE (default: the module line of go.mod).
set -euo pipefail
cd "$(dirname "$0")/../.."

profile=${COVER_PROFILE:-coverage.out}
testjson=${COVER_JSON:-coverage.json}
module=${COVER_MODULE:-$(awk '$1 == "module" { print $2; exit }' go.mod)}
tab=$(printf '\t')

work=
cleanup() {
  [ -z "$work" ] || rm -rf "$work"
}
trap cleanup EXIT

need_profile() {
  if [ ! -f "$profile" ]; then
    echo "cover: $profile not found; run 'task cover' first" >&2
    exit 1
  fi
}

# Merged and filtered profile on stdout: one line per block, counts summed over the test binaries.
merge_profile() {
  awk -v module="$module" '
    function excluded(rel) {
      if (rel ~ /_templ[.]go$/) return 1
      if (rel ~ /^internal[/]gen[/]/) return 1
      if (rel ~ /^internal[/]store[/](pkidb|systemdb|auditdb)[/]/) return 1
      if (rel ~ /^internal[/](tools|testinstance|testutil)[/]/) return 1
      return 0
    }
    { sub(/\r$/, "") }
    /^mode:/ { if (mode == "") mode = $0; next }
    NF != 3 { next }
    {
      rel = substr($1, 1, index($1, ":") - 1)
      if (index(rel, module "/") == 1) rel = substr(rel, length(module) + 2)
      if (excluded(rel)) next
      key = $1 " " $2
      if (!(key in count)) order[++n] = key
      count[key] += $3
    }
    END {
      print (mode == "" ? "mode: set" : mode)
      for (i = 1; i <= n; i++) print order[i], count[order[i]]
    }
  ' "$1"
}

# Table of the merged profile ($1) per package, sorted by name, with the total.
package_table() {
  awk -v module="$module" '
    {
      if ($1 ~ /^mode:/) next
      file = substr($1, 1, index($1, ":") - 1)
      if (index(file, module "/") == 1) file = substr(file, length(module) + 2)
      pkg = file
      if (sub(/[/][^/]*$/, "", pkg) == 0) pkg = "."
      if (!(pkg in stmts)) names[++n] = pkg
      stmts[pkg] += $2
      if ($3 > 0) covered[pkg] += $2
      total += $2
      if ($3 > 0) totalcovered += $2
    }
    END {
      for (i = 2; i <= n; i++) {
        v = names[i]
        for (j = i - 1; j >= 1 && names[j] > v; j--) names[j + 1] = names[j]
        names[j + 1] = v
      }
      width = 7
      for (i = 1; i <= n; i++) if (length(names[i]) > width) width = length(names[i])
      row = "%-" width "s %10s %9s %8s\n"
      line = "%-" width "s %10d %9d %7.1f%%\n"
      printf row, "package", "stmts", "covered", "percent"
      for (i = 1; i <= n; i++) {
        p = names[i]
        printf line, p, stmts[p], covered[p], (stmts[p] > 0 ? 100 * covered[p] / stmts[p] : 0)
      }
      printf line, "total", total, totalcovered, (total > 0 ? 100 * totalcovered / total : 0)
    }
  ' "$1"
}

# "N tests skipped in M packages" from the go test -json file, so a Windows number is never read as a Linux one.
skipped_line() {
  if [ ! -f "$testjson" ]; then
    echo "skipped tests: unknown ($testjson not found; the numbers above come from a profile only)"
    return
  fi
  awk '
    /"Action":"skip"/ && /"Test":"/ {
      skipped++
      if (match($0, /"Package":"[^"]*"/)) {
        p = substr($0, RSTART + 11, RLENGTH - 12)
        if (!(p in seen)) { seen[p] = 1; packages++ }
      }
    }
    END {
      printf "%d tests skipped in %d packages (a skipped test covers nothing; a number from one machine is not the number of another)\n", skipped, packages
    }
  ' "$testjson"
}

# Progress of `go test -json` on stdin: one line per finished package.
progress() {
  awk '
    function field(name,   s) {
      if (!match($0, "\"" name "\":\"?[^,}\"]*")) return ""
      s = substr($0, RSTART, RLENGTH)
      sub(/^"[A-Za-z]+":"?/, "", s)
      return s
    }
    /"Action":"(pass|fail)"/ {
      test = field("Test")
      pkg = field("Package")
      action = field("Action")
      if (test != "") { if (action == "fail") printf "--- FAIL  %s %s\n", pkg, test; fflush(); next }
      printf "%-5s %s  %ss\n", (action == "pass" ? "ok" : "FAIL"), pkg, field("Elapsed")
      fflush()
    }
  '
}

# Functions ranked by uncovered statements. $1 merged profile, $2 the output of go tool cover -func.
rank_functions() {
  awk -v module="$module" -v tab="$tab" '
    FNR == NR {
      n = split($0, part, tab)
      if (n < 3 || part[1] !~ /:[0-9]+:$/) next
      loc = part[1]
      sub(/:$/, "", loc)
      line = loc
      sub(/^.*:/, "", line)
      sub(/:[0-9]+$/, "", loc)
      funcs[loc]++
      fline[loc, funcs[loc]] = line + 0
      fname[loc, funcs[loc]] = part[2]
      next
    }
    /^mode:/ { next }
    {
      file = substr($1, 1, index($1, ":") - 1)
      split(substr($1, index($1, ":") + 1), pos, /[.,]/)
      start = pos[1] + 0
      best = 0
      for (i = 1; i <= funcs[file]; i++) if (fline[file, i] <= start && (best == 0 || fline[file, i] >= fline[file, best])) best = i
      if (best == 0) next
      total[file, best] += $2
      if ($3 == 0) uncovered[file, best] += $2
      seen[file, best] = 1
    }
    END {
      for (key in seen) {
        split(key, k, SUBSEP)
        file = k[1]
        i = k[2]
        if (uncovered[key] + 0 == 0) continue
        shown = file
        if (index(shown, module "/") == 1) shown = substr(shown, length(module) + 2)
        printf "%d%s%d%s%s%s%s:%d\n", uncovered[key], tab, total[key], tab, fname[file, i], tab, shown, fline[file, i]
      }
    }
  ' "$2" "$1" | LC_ALL=C sort -t "$tab" -k1,1nr -k2,2nr -k4,4 |
    awk -F "$tab" '{ printf "%5d of %-5d %5.1f%%  %-28s %s\n", $1, $2, 100 * ($2 - $1) / $2, $3, $4 }'
}

case ${1:-summary} in
  summary)
    need_profile
    work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-cover.XXXXXX")
    merge_profile "$profile" >"$work/merged.out"
    package_table "$work/merged.out"
    echo
    skipped_line
    ;;
  func)
    need_profile
    work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-cover.XXXXXX")
    merge_profile "$profile" >"$work/merged.out"
    if ! command -v go >/dev/null 2>&1; then
      echo 'cover: go not found in PATH; "func" needs go tool cover' >&2
      exit 2
    fi
    go tool cover -func="$work/merged.out" >"$work/func.txt"
    printf '%5s    %-5s %6s  %-28s %s\n' uncov stmts covered function location
    rank_functions "$work/merged.out" "$work/func.txt" | head -n "${2:-40}"
    ;;
  merge)
    need_profile
    merge_profile "$profile"
    ;;
  progress)
    progress
    ;;
  --self-test)
    data=scripts/ci/testdata
    work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-cover.XXXXXX")
    module=example.test/mod
    export COVER_MODULE=$module
    COVER_PROFILE=$data/cover-profile.txt COVER_JSON=$data/cover-test.json bash "$0" summary >"$work/summary.txt"
    merge_profile "$data/cover-profile.txt" >"$work/merged.out"
    rank_functions "$work/merged.out" "$data/cover-func.txt" >"$work/rank.txt"
    status=0
    diff -u "$data/cover-summary.golden" "$work/summary.txt" || status=1
    diff -u "$data/cover-rank.golden" "$work/rank.txt" || status=1
    if [ "$status" -ne 0 ]; then
      echo 'cover-summary self-test: output differs from the golden files in scripts/ci/testdata' >&2
      exit 1
    fi
    echo 'cover-summary self-test: summary and function ranking match the golden files'
    ;;
  -h | --help)
    sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "cover-summary: unknown mode: $1" >&2
    exit 2
    ;;
esac
