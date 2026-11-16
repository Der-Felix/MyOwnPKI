#!/usr/bin/env bash
# Runs every fuzz target of scripts/ci/fuzz-targets.txt, one `go test -fuzz` per target.
#
# Usage: bash scripts/ci/fuzz.sh [--check | --self-test]
#   (no option)  check the list against the tree, then fuzz every target for $FUZZTIME
#   --check      only compare the list with the `func Fuzz…` declarations in the tree
#   --self-test  prove that --check rejects a missing, an invented and a malformed entry
#
# Environment:
#   FUZZTIME   time per target, a Go duration or an execution count (default 10s; 30m before a release)
#   FUZZ_ONLY  fuzz this one target only (a name from the list, for example FuzzParseJWK)
#
# Exit status: 0 all targets passed, 1 a target failed or the list does not match the tree,
# 2 the environment is wrong (no Go, a bad FUZZTIME, an unknown FUZZ_ONLY). Stops at the first failing
# target and then prints every new file under testdata/fuzz, so a crash in CI is readable in the log.
set -euo pipefail
cd "$(dirname "$0")/../.."

list_file=${FUZZ_LIST_FILE:-scripts/ci/fuzz-targets.txt}
root=${FUZZ_ROOT:-.}
fuzztime=${FUZZTIME:-10s}
only=${FUZZ_ONLY:-}
mode=run

case ${1:-} in
  '') ;;
  --check) mode=check ;;
  --self-test) mode=self-test ;;
  -h | --help)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "fuzz: unknown option: $1" >&2
    exit 2
    ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-fuzz.XXXXXX")
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

problems=0
problem() {
  echo "fuzz: $*" >&2
  problems=$((problems + 1))
}

# The list, parsed into three parallel arrays (indexes match).
list_pkg=()
list_target=()
list_extra=()

parse_list() {
  local n=0 line pkg target extra flag
  list_pkg=()
  list_target=()
  list_extra=()
  if [ ! -f "$list_file" ]; then
    problem "target list $list_file not found"
    return
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line%$'\r'}
    pkg='' target='' extra=''
    read -r pkg target extra <<<"$line" || true
    case $pkg in '' | '#'*) continue ;; esac
    case $pkg in
      . | ./*) ;;
      *)
        problem "$list_file:$n: the package '$pkg' must be a path inside the module such as ./internal/ca"
        continue
        ;;
    esac
    if [ -z "$target" ]; then
      problem "$list_file:$n: line has no target; the form is '<package> <target> [extra go test flags]'"
      continue
    fi
    case $target in
      Fuzz[A-Za-z0-9_]*) ;;
      *)
        problem "$list_file:$n: '$target' is not a fuzz target name (Fuzz followed by letters, digits or _)"
        continue
        ;;
    esac
    case $target in *[!A-Za-z0-9_]*)
      problem "$list_file:$n: '$target' is not a fuzz target name (Fuzz followed by letters, digits or _)"
      continue
      ;;
    esac
    if [ -n "$extra" ]; then
      case $extra in *[!-A-Za-z0-9=._\ ]*)
        problem "$list_file:$n: the extra flags '$extra' contain a character outside -A-Za-z0-9=._ and space"
        continue
        ;;
      esac
      for flag in $extra; do
        case $flag in
          -fuzz | -fuzz=* | -fuzztime | -fuzztime=* | -run | -run=*)
            problem "$list_file:$n: the script sets $flag itself; remove it from the line"
            continue 2
            ;;
        esac
      done
    fi
    list_pkg+=("$pkg")
    list_target+=("$target")
    list_extra+=("$extra")
  done <"$list_file"
}

# "<package> <target>" for every `func Fuzz…` in a _test.go file below $root, sorted.
tree_pairs() {
  (
    cd "$root"
    grep -rEH --include='*_test.go' \
      --exclude-dir=.git --exclude-dir=.claude --exclude-dir=.tools --exclude-dir=node_modules \
      --exclude-dir=bin --exclude-dir=dist --exclude-dir=testdata \
      '^func Fuzz[A-Za-z0-9_]*\(' . || true
  ) | sed -E 's#^(.*)/[^/]*_test\.go:func (Fuzz[A-Za-z0-9_]*)\(.*$#\1 \2#' | LC_ALL=C sort -u
}

# Compares the list with the tree; every difference is one reported problem.
check_list() {
  local i
  parse_list
  : >"$work/list.txt"
  for i in "${!list_pkg[@]}"; do
    printf '%s %s\n' "${list_pkg[$i]}" "${list_target[$i]}" >>"$work/list.txt"
  done
  LC_ALL=C sort "$work/list.txt" >"$work/list.sorted"
  LC_ALL=C sort -u "$work/list.txt" >"$work/list.unique"
  tree_pairs >"$work/tree.sorted"

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    problem "listed twice in $list_file: $line"
  done < <(LC_ALL=C uniq -d "$work/list.sorted")

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    problem "listed in $list_file but not found in the tree (not written yet, renamed, or in another package): $line"
  done < <(LC_ALL=C comm -23 "$work/list.unique" "$work/tree.sorted")

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    problem "func $line... exists in a _test.go file but is missing from $list_file; add a line '$line'"
  done < <(LC_ALL=C comm -13 "$work/list.unique" "$work/tree.sorted")
}

self_test() {
  local tree=$work/selftest/tree rc
  mkdir -p "$tree/internal/a" "$tree/internal/b"
  printf 'package a\n\nfunc FuzzA(f *testing.F) {}\n\nfunc FuzzB(f *testing.F) {}\n' >"$tree/internal/a/a_test.go"
  printf 'package b\n\nfunc FuzzC(f *testing.F) {}\n' >"$tree/internal/b/b_test.go"
  # A seed file must not count as a target.
  mkdir -p "$tree/internal/b/testdata/fuzz/FuzzC"
  printf 'func FuzzNotATarget(f *testing.F) {}\n' >"$tree/internal/b/testdata/x_test.go"

  local good=$work/selftest/good.txt
  printf '# comment\n\n./internal/a FuzzA\n./internal/a FuzzB -parallel 2\n./internal/b FuzzC\n' >"$good"

  expect() { # expect pass|fail <list file> <text the output must contain>
    local want=$1 file=$2 text=${3:-}
    rc=0
    FUZZ_LIST_FILE=$file FUZZ_ROOT=$tree bash "$0" --check >"$work/selftest/out.txt" 2>&1 || rc=$?
    if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
      cat "$work/selftest/out.txt" >&2
      echo "fuzz self-test: a correct list was refused" >&2
      exit 1
    fi
    if [ "$want" = fail ]; then
      if [ "$rc" -eq 0 ]; then
        echo "fuzz self-test: accepted a wrong list ($text)" >&2
        exit 1
      fi
      if ! grep -Fq -- "$text" "$work/selftest/out.txt"; then
        cat "$work/selftest/out.txt" >&2
        echo "fuzz self-test: the refusal does not name '$text'" >&2
        exit 1
      fi
    fi
  }

  expect pass "$good"

  grep -v 'FuzzB' "$good" >"$work/selftest/no-b.txt"
  expect fail "$work/selftest/no-b.txt" 'missing from'

  { cat "$good"; echo './internal/b FuzzInvented'; } >"$work/selftest/invented.txt"
  expect fail "$work/selftest/invented.txt" 'FuzzInvented'

  sed 's#^./internal/b FuzzC#./internal/a FuzzC#' "$good" >"$work/selftest/wrong-pkg.txt"
  expect fail "$work/selftest/wrong-pkg.txt" './internal/a FuzzC'

  { cat "$good"; echo './internal/a FuzzA'; } >"$work/selftest/twice.txt"
  expect fail "$work/selftest/twice.txt" 'listed twice'

  { cat "$good"; echo './internal/b'; } >"$work/selftest/short.txt"
  expect fail "$work/selftest/short.txt" 'no target'

  sed 's#FuzzA#FuzzA -fuzztime 1h#' "$good" >"$work/selftest/own-flag.txt"
  expect fail "$work/selftest/own-flag.txt" 'sets -fuzztime itself'

  echo 'fuzz self-test: a missing, an invented, a misplaced, a duplicate and a malformed entry are rejected'
}

if [ "$mode" = self-test ]; then
  self_test
  exit 0
fi

if [ -n "$only" ] && [ "$mode" = run ]; then
  check_list 2>/dev/null # one target: differences of the others do not matter here
else
  check_list
fi
if [ "$mode" = check ]; then
  if [ "$problems" -ne 0 ]; then
    exit 1
  fi
  echo "fuzz: ${#list_target[@]} targets listed, all found in the tree, none missing from the list"
  exit 0
fi

# --- run ---

if ! command -v go >/dev/null 2>&1; then
  echo "fuzz: go not found in PATH; fuzzing needs the Go toolchain of go.mod (Go 1.18 or newer for go test -fuzz)" >&2
  exit 2
fi
if ! go help testflag 2>/dev/null | grep -q -e '-fuzztime'; then
  echo "fuzz: this Go toolchain ($(go version 2>/dev/null || echo unknown)) does not know 'go test -fuzz'; use the Go version of go.mod" >&2
  exit 2
fi
if ! [[ $fuzztime =~ ^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h)|[0-9]+x)$ ]]; then
  echo "fuzz: FUZZTIME='$fuzztime' is not a duration with a unit (10s, 2m, 1h) or a count (5000x)" >&2
  exit 2
fi

selected=()
if [ -n "$only" ]; then
  # One target: the other targets may be missing from the tree (still being written); only this one must exist.
  for i in "${!list_target[@]}"; do
    if [ "${list_target[$i]}" = "$only" ]; then
      selected+=("$i")
    fi
  done
  if [ "${#selected[@]}" -eq 0 ]; then
    echo "fuzz: FUZZ_ONLY=$only is not in $list_file; the targets are:" >&2
    printf '  %s\n' "${list_target[@]}" >&2
    exit 2
  fi
  if ! grep -Fqx -- "${list_pkg[${selected[0]}]} $only" "$work/tree.sorted"; then
    echo "fuzz: $only is listed for ${list_pkg[${selected[0]}]} but no 'func $only' exists there yet" >&2
    exit 1
  fi
  problems=0
elif [ "$problems" -ne 0 ]; then
  echo "fuzz: the list and the tree differ (see above); fix that first, or run one target with FUZZ_ONLY=<target>" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::error title=fuzz target list::the list and the tree differ; see the log"
  fi
  exit 1
else
  for i in "${!list_target[@]}"; do
    selected+=("$i")
  done
fi

export CGO_ENABLED=0

list_inputs() {
  find "$root" \( -name .git -o -name node_modules -o -name .tools \) -prune -o \
    -path '*/testdata/fuzz/*' -type f -print | LC_ALL=C sort
}

# Prints the corpus files the run added or changed since the snapshot in $work/inputs.before.
report_new_inputs() {
  local f shown=0
  list_inputs >"$work/inputs.after"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    shown=$((shown + 1))
    echo "--- new fuzz input: $f"
    head -c 16384 "$f"
    echo
    echo "--- end of $f"
  done < <(LC_ALL=C comm -13 "$work/inputs.before" "$work/inputs.after")
  if [ "$shown" -gt 0 ]; then
    echo "To keep it as a regression input, save this text as the same path (testdata/fuzz/<target>/<name>) in the package"
    echo "and run: go test <package> -run '^<target>\$'. Do not commit it before the fix (docs/PHASE3.md section 18.5, D3)."
  fi
}

passed=0
failed=
summary=()
for i in "${selected[@]}"; do
  pkg=${list_pkg[$i]}
  target=${list_target[$i]}
  extra=${list_extra[$i]}
  flags=()
  if [ -n "$extra" ]; then
    read -ra flags <<<"$extra"
  fi
  list_inputs >"$work/inputs.before"
  printf '\n>>> fuzz %s %s for %s%s\n' "$pkg" "$target" "$fuzztime" "${extra:+ ($extra)}"
  started=$(date +%s)
  rc=0
  (cd "$root" && go test "$pkg" -run '^$' -fuzz "^${target}$" -fuzztime "$fuzztime" ${flags[@]+"${flags[@]}"}) || rc=$?
  took="$(($(date +%s) - started))s"
  if [ "$rc" -eq 0 ]; then
    passed=$((passed + 1))
    summary+=("$(printf '%-6s %-28s %-22s %s' PASS "$target" "$pkg" "$took")")
  else
    failed="$pkg $target"
    summary+=("$(printf '%-6s %-28s %-22s %s' FAIL "$target" "$pkg" "$took")")
    echo
    echo "fuzz: $target in $pkg failed (go test exit status $rc) after $took"
    report_new_inputs
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      echo "::error title=fuzz $target::$target in $pkg failed; the crashing input is printed in the log"
    fi
    break
  fi
done

printf '\n%-6s %-28s %-22s %s\n' Status Target Package Time
printf '%s\n' "${summary[@]}"
if [ -n "$failed" ]; then
  printf '\nfuzz: stopped at the first failure (%s); %d of %d targets passed before it\n' "$failed" "$passed" "${#selected[@]}"
  exit 1
fi
printf '\nfuzz: %d targets passed (%s each)\n' "$passed" "$fuzztime"
