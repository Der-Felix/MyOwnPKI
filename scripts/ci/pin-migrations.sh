#!/usr/bin/env bash
# Pins of the released migration files (PHASE3 §19.5, step 107).
#
# internal/store/testdata/released-migrations.txt lists every migration file a
# release shipped: kind, version, name, SHA-256 and the release that shipped it
# first. TestReleasedMigrationsAreFrozen (internal/store) fails when such a file
# changes, disappears or is renamed. The hash is the one the migration runner
# stores in the database: SHA-256 of the file with LF line endings.
#
#   pin-migrations.sh --print [TAG...]     print the list recomputed from git tags
#                                          (default: every release tag vX.Y.Z)
#   pin-migrations.sh --check [TAG...]     compare the pin file with those tags;
#                                          needs the tags (git fetch --tags)
#   pin-migrations.sh --add-tree VERSION   release commit: append the files of the
#                                          working tree that are not pinned yet,
#                                          with first release VERSION (vX.Y.Z)
#   pin-migrations.sh --self-test          run the above in a throwaway repository
#
# --print and --check also stop when one tag changed a file an earlier tag already
# shipped: that is exactly what the pin file is there to prevent.
#
# Environment (for the self-test): PIN_ROOT (repository root), PIN_FILE and
# PIN_SCHEMA_DIR (default internal/store/schema).
set -euo pipefail

script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
root=${PIN_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$root"
pin_file=${PIN_FILE:-internal/store/testdata/released-migrations.txt}
schema_dir=${PIN_SCHEMA_DIR:-internal/store/schema}

die() {
  echo "pin-migrations: $*" >&2
  exit 1
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# File name -> "kind version name"; empty when it is not a migration file.
# Same pattern as internal/store/migrate (NNNN_lower_case_name.sql).
parse_path() {
  printf '%s\n' "$1" | sed -nE "s|^${schema_dir}/([a-z]+)/([0-9]{4})_([a-z0-9_]+)\\.sql\$|\\1 \\2 \\3|p"
}

# The release tags in version order.
default_tags() {
  git tag --list 'v[0-9]*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' |
    sort -t. -k1.2,1n -k2,2n -k3,3n
}

# "kind version name sha tag" for every migration file of one tag.
tag_lines() {
  local tag=$1 path parsed sum
  git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null || die "tag $tag does not exist (git fetch --tags)"
  while IFS= read -r path; do
    parsed=$(parse_path "$path")
    [ -n "$parsed" ] || continue
    sum=$(git show "$tag:$path" | tr -d '\r' | sha256_stdin)
    printf '%s %s %s\n' "$parsed" "$sum" "$tag"
  done < <(git ls-tree -r --name-only "$tag" -- "$schema_dir")
}

# The pinned list of the given tags (first release of every file), sorted.
# Fails when a later tag shipped different content under the same version.
compute() {
  local tag all rc=0
  all=$(mktemp "${TMPDIR:-/tmp}/pin-migrations.XXXXXX")
  for tag in "$@"; do
    tag_lines "$tag" >>"$all" || { rm -f "$all"; return 1; }
  done
  awk '
    {
      key = $1 " " $2
      if (!(key in first)) { first[key] = $0; tag[key] = $5; order[++n] = key; next }
      split(first[key], f, " ")
      if (f[3] != $3 || f[4] != $4) {
        printf "pin-migrations: %s %s_%s.sql of %s differs from the file shipped in %s\n", $1, $2, f[3], $5, tag[key] > "/dev/stderr"
        bad = 1
      }
    }
    END {
      for (i = 1; i <= n; i++) print first[order[i]]
      exit bad
    }' "$all" >"$all.out" || rc=1
  [ "$rc" -ne 0 ] || sort -k1,1 -k2,2 "$all.out" || rc=1
  rm -f "$all" "$all.out"
  return "$rc"
}

pin_entries() {
  [ -f "$pin_file" ] || die "$pin_file does not exist"
  grep -Ev '^[[:space:]]*(#|$)' "$pin_file" || true
}

header() {
  cat <<'EOF'
# Released migration files (PHASE3 section 19.5, step 107). Never edit by hand:
# bash scripts/ci/pin-migrations.sh --print | --check | --add-tree vX.Y.Z
# Columns: kind, version, name, SHA-256 (LF line endings, as the migration runner
# stores it), first release. A released file is never changed, renamed or removed;
# a defect is fixed by a new migration (docs/RELEASING.md).
EOF
}

tags_or_default() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$@"
  else
    default_tags
  fi
}

cmd_print() {
  local list=() t
  while IFS= read -r t; do list+=("$t"); done < <(tags_or_default "$@")
  [ "${#list[@]}" -gt 0 ] || die "no release tags (git fetch --tags)"
  compute "${list[@]}"
}

cmd_check() {
  local list=() t expected pinned tags
  while IFS= read -r t; do list+=("$t"); done < <(tags_or_default "$@")
  [ "${#list[@]}" -gt 0 ] || die "no release tags (git fetch --tags)"
  set -- "${list[@]}"
  expected=$(compute "$@") || exit 1
  tags=" $* "
  # Only the pins of the tags that are looked at: newer ones are not in git yet.
  pinned=$(pin_entries | awk -v tags="$tags" 'index(tags, " " $5 " ") > 0' | sort -k1,1 -k2,2)
  if [ "$expected" != "$pinned" ]; then
    diff <(printf '%s\n' "$pinned") <(printf '%s\n' "$expected") >&2 || true
    die "$pin_file does not match the release tags (< pinned, > in git); a released migration was changed, or a release was not pinned"
  fi
  echo "pin-migrations: $(printf '%s\n' "$expected" | wc -l | tr -d ' ') released migration files match $pin_file"
}

cmd_add_tree() {
  [ "$#" -eq 1 ] || die "--add-tree needs the release version (vX.Y.Z)"
  local version=$1 path parsed sum new tmp
  printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "$version is not a release version vX.Y.Z"
  new=$(mktemp "${TMPDIR:-/tmp}/pin-migrations.XXXXXX")
  pin_entries >"$new"
  while IFS= read -r path; do
    parsed=$(parse_path "$path")
    [ -n "$parsed" ] || continue
    sum=$(tr -d '\r' <"$path" | sha256_stdin)
    if grep -q "^${parsed% *} " "$new"; then
      grep -q "^${parsed} ${sum} " "$new" || { rm -f "$new"; die "$path differs from its pin: a released migration must not change"; }
      continue
    fi
    printf '%s %s %s\n' "$parsed" "$sum" "$version" >>"$new"
  done < <(find "$schema_dir" -type f -name '*.sql' | LC_ALL=C sort)
  tmp=$(mktemp "${TMPDIR:-/tmp}/pin-migrations.XXXXXX")
  { header; sort -k1,1 -k2,2 "$new"; } >"$tmp"
  mv "$tmp" "$pin_file"
  rm -f "$new"
  echo "pin-migrations: $pin_file now has $(pin_entries | wc -l | tr -d ' ') entries"
}

cmd_self_test() {
  local work out
  work=$(mktemp -d "${TMPDIR:-/tmp}/pin-migrations-test.XXXXXX")
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$work'" EXIT
  git init -q "$work/repo"
  (
    cd "$work/repo"
    git config user.email test@example.invalid
    git config user.name test
    git config commit.gpgsign false
    git config tag.gpgsign false
    git config core.autocrlf false
    mkdir -p internal/store/schema/pki internal/store/schema/audit
    printf 'CREATE TABLE a (x);\r\n' >internal/store/schema/pki/0001_init.sql
    printf 'CREATE TABLE b (x);\n' >internal/store/schema/audit/0001_init.sql
    git add -A
    git commit -q -m one
    git tag v0.1.0
    printf 'CREATE TABLE c (x);\n' >internal/store/schema/pki/0002_more.sql
    git add -A
    git commit -q -m two
    git tag v0.2.0
    git tag v0.2.0-rc.1
  )
  export PIN_ROOT="$work/repo" PIN_FILE="$work/pins.txt"
  out=$(bash "$script" --print)
  expect() {
    [ "$out" = "$1" ] || { printf 'self-test: unexpected output\n%s\n' "$out" >&2; exit 1; }
  }
  local sum_b sum_a sum_c
  sum_b=$(printf 'CREATE TABLE b (x);\n' | sha256_stdin)
  sum_a=$(printf 'CREATE TABLE a (x);\n' | sha256_stdin)
  sum_c=$(printf 'CREATE TABLE c (x);\n' | sha256_stdin)
  expect "audit 0001 init $sum_b v0.1.0
pki 0001 init $sum_a v0.1.0
pki 0002 more $sum_c v0.2.0"
  # The CRLF file hashes like its LF text, as the migration runner does.
  bash "$script" --print >"$work/list.txt"
  { header; cat "$work/list.txt"; } >"$PIN_FILE"
  bash "$script" --check >/dev/null || { echo 'self-test: --check rejected a matching pin file' >&2; exit 1; }
  # --check against one tag looks at the pins of that tag only.
  bash "$script" --check v0.1.0 >/dev/null || { echo 'self-test: --check v0.1.0 failed' >&2; exit 1; }
  # A missing pin is found.
  grep -v ' v0.2.0$' "$PIN_FILE" >"$work/short.txt"
  if PIN_FILE="$work/short.txt" bash "$script" --check >/dev/null 2>&1; then
    echo 'self-test: a missing pin was accepted' >&2
    exit 1
  fi
  # A file edited in a later tag stops --print.
  (
    cd "$work/repo"
    printf 'CREATE TABLE a (x, y);\n' >internal/store/schema/pki/0001_init.sql
    git add -A
    git commit -q -m edit
    git tag v0.3.0
  )
  if bash "$script" --print >/dev/null 2>&1; then
    echo 'self-test: an edited released file was accepted' >&2
    exit 1
  fi
  # --add-tree pins a new file; the edited one is refused.
  (
    cd "$work/repo"
    git reset -q --hard v0.2.0
    printf 'CREATE TABLE d (x);\n' >internal/store/schema/pki/0003_new.sql
  )
  bash "$script" --add-tree v0.4.0 >/dev/null
  grep -q '^pki 0003 new .* v0.4.0$' "$PIN_FILE" || { echo 'self-test: --add-tree did not pin the new file' >&2; exit 1; }
  printf 'CREATE TABLE a (x, z);\n' >"$work/repo/internal/store/schema/pki/0001_init.sql"
  if bash "$script" --add-tree v0.4.0 >/dev/null 2>&1; then
    echo 'self-test: --add-tree accepted an edited released file' >&2
    exit 1
  fi
  echo 'pin-migrations self-test: ok'
}

case ${1:-} in
  --print) shift; cmd_print "$@" ;;
  --check) shift; cmd_check "$@" ;;
  --add-tree) shift; cmd_add_tree "$@" ;;
  --self-test) cmd_self_test ;;
  *) sed -n '2,/^set -euo/{/^#/s/^# {0,1}//p}' "$0" >&2; exit 2 ;;
esac
