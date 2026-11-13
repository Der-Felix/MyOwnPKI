#!/usr/bin/env bash
# Tests the Salt formula in deploy/salt/myownpki (docs/PHASE3.md section 12).
#
#   salt-test.sh [CASE...]    Needs salt-call and jq on PATH. Renders every pillar in
#                             deploy/salt/test/cases (or only the named CASEs, file names
#                             without .sls) with state.show_highstate, checks which states
#                             exist or must not exist, and (on Linux, as root) runs
#                             state.apply test=True for the cases marked "apply". A refusal
#                             case must produce exactly one failing state with the reason.
#   salt-test.sh --self-test  Checks that need no Salt: the fixtures' hashes match the
#                             pillars, pillar.example and the pillars parse (when a
#                             Python with PyYAML exists), no real host names or
#                             addresses, ShellCheck on this script.
#
# A case file is a pillar with directives in comment lines at the top:
#   # grain: os_family=Debian      grains of the test minion (repeat)
#   # mode: apply|render           default apply; render skips state.apply
#   # present: STATE-ID            must be in the result (repeat)
#   # absent: STATE-ID             must not be in the result (repeat)
#   # contains: TEXT               must appear in the rendered highstate
#   # not-contains: TEXT           must not appear in any output
#   # refused: TEXT                a refusal case: the only state is
#                                  myownpki-agent-refused and its name has TEXT
set -euo pipefail
cd "$(dirname "$0")/../.."
repo=$PWD
formula=deploy/salt/myownpki
testdir=deploy/salt/test
refused_id=myownpki-agent-refused

failures=0
fail() {
  echo "salt-test: FAILED: $*" >&2
  failures=$((failures + 1))
}

native() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

# directive FILE KEY: the values of "# KEY: value" lines, one per line.
directive() {
  sed -n "s/^# $2: //p" "$1"
}

# yaml_python: a Python with PyYAML (system, or the one in the Salt onedir), or nothing.
yaml_python() {
  local candidate salt_call
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -I -c 'import yaml' >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  if salt_call=$(command -v salt-call 2>/dev/null); then
    candidate=$(dirname "$salt_call")/bin/python3
    if [ -x "$candidate" ] && "$candidate" -I -c 'import yaml' >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  fi
  return 1
}

# yaml_parses FILE: succeeds when the file is valid YAML (needs yaml_python).
yaml_parses() {
  "$1" -I -c 'import sys, yaml
with open(sys.argv[1], encoding="utf-8") as f:
    list(yaml.safe_load_all(f))' "$2"
}

# check_names FILE: only example names and addresses (homelab.lan, 192.0.2.x) and a few
# documentation hosts; anything else could be a real host.
check_names() {
  local file=$1 host
  while IFS= read -r host; do
    [ -n "$host" ] || continue
    host=${host#*//}
    host=${host%%:*}
    case $host in
      homelab.lan | *.homelab.lan | 192.0.2.* | docs.saltproject.io | github.com | der-felix.github.io | packages.broadcom.com | example.com) ;;
      *) fail "$file: host name \"$host\" is not an example name (use homelab.lan or 192.0.2.x)" ;;
    esac
  done < <(grep -oE 'https?://[^/[:space:]"'"'"')>,;`]+' "$file" || true)
  while IFS= read -r host; do
    [ -n "$host" ] || continue
    case $host in
      homelab.lan | *.homelab.lan) ;;
      *) fail "$file: \"$host\" is not an example name (use homelab.lan)" ;;
    esac
  done < <(grep -oE '[A-Za-z0-9._-]+\.lan([^A-Za-z0-9_-]|$)' "$file" | sed -E 's/[^A-Za-z0-9_-]$//' || true)
  while IFS= read -r host; do
    [ -n "$host" ] || continue
    case $host in
      192.0.2.*) ;;
      *) fail "$file: address $host is not a documentation address (use 192.0.2.x)" ;;
    esac
  done < <(grep -oE '(^|[^0-9.])[0-9]{1,3}(\.[0-9]{1,3}){3}([^0-9.]|$)' "$file" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true)
}

self_test() {
  local f file key case_file want got py unknown line
  local deb rpm

  for f in init.sls agent.sls map.jinja defaults.yaml pillar.example README.md; do
    [ -f "$formula/$f" ] || fail "$formula/$f is missing"
  done
  for f in files/myownpki-agent_0.3.6_linux_amd64.deb files/myownpki-agent_0.3.6_linux_arm64.rpm files/myownpki-agent_0.3.9_linux_amd64.deb files/myownpki-agent_0.3.9_linux_arm64.rpm files/root.pem files/agent.yaml minion.tmpl; do
    [ -f "$testdir/$f" ] || fail "$testdir/$f is missing"
  done
  # The 0.3.9 fixtures (the cases with system_trust need agent 0.3.9) are copies of the 0.3.6 ones, so the hashes in the pillars stay the same.
  cmp -s "$testdir/files/myownpki-agent_0.3.6_linux_amd64.deb" "$testdir/files/myownpki-agent_0.3.9_linux_amd64.deb" || fail "the 0.3.9 deb fixture differs from the 0.3.6 one"
  cmp -s "$testdir/files/myownpki-agent_0.3.6_linux_arm64.rpm" "$testdir/files/myownpki-agent_0.3.9_linux_arm64.rpm" || fail "the 0.3.9 rpm fixture differs from the 0.3.6 one"
  [ "$failures" -eq 0 ] || return 1

  deb=$(sha256sum "$testdir/files/myownpki-agent_0.3.6_linux_amd64.deb" | cut -d' ' -f1)
  rpm=$(sha256sum "$testdir/files/myownpki-agent_0.3.6_linux_arm64.rpm" | cut -d' ' -f1)

  for case_file in "$testdir"/cases/*.sls; do
    # The hashes in the pillars are the real hashes of the fixtures.
    for want in "amd64 $deb" "arm64 $rpm"; do
      key=${want%% *}
      want=${want#* }
      while IFS= read -r got; do
        [ "$got" = "$want" ] || fail "$case_file: package.sha256.$key is $got, the fixture has $want"
      done < <(sed -nE "s/^[[:space:]]+$key:[[:space:]]*\"?([0-9a-fA-F]{64})\"?[[:space:]]*\$/\\1/p" "$case_file")
    done
    # Fixtures the pillars point to exist.
    while IFS= read -r got; do
      [ -f "$testdir/files/$got" ] || fail "$case_file: salt://test/files/$got does not exist"
    done < <(grep -oE 'salt://test/files/[A-Za-z0-9._-]+' "$case_file" | sed 's#salt://test/files/##' || true)
    # Directives: known keys only, a grain pair, and either a refusal or expectations.
    unknown=$(grep -E '^# [a-z-]+: ' "$case_file" | grep -vE '^# (grain|mode|present|absent|contains|not-contains|refused): ' || true)
    [ -z "$unknown" ] || fail "$case_file: unknown directive: $unknown"
    line=$(directive "$case_file" grain)
    grep -q '^os_family=' <<<"$line" || fail "$case_file: no os_family grain"
    grep -q '^osarch=' <<<"$line" || fail "$case_file: no osarch grain"
    if [ -z "$(directive "$case_file" refused)" ] && [ -z "$(directive "$case_file" present)" ]; then
      fail "$case_file: neither refused nor present directives"
    fi
    line=$(directive "$case_file" mode)
    case $line in '' | apply | render) ;; *) fail "$case_file: mode must be apply or render" ;; esac
    check_names "$case_file"
  done

  # Every pillar key is in defaults.yaml, pillar.example and the README.
  while IFS= read -r key; do
    grep -qE "^[[:space:]#]*$key:" "$formula/pillar.example" || fail "pillar.example does not mention $key"
    [ "$key" = package ] || grep -qF "\`$key\`" "$formula/README.md" || fail "README.md does not mention \`$key\`"
  done < <(sed -nE 's/^  ([a-z_0-9]+):.*/\1/p' "$formula/defaults.yaml")
  # Every deployment option of map.jinja is in the README (the flags of "deployment add").
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    grep -qF "\`$key\`" "$formula/README.md" || fail "README.md does not mention the deployment option \`$key\`"
  done < <(sed -nE "s/^\\{% set opts_(string|list|bool) = \\[(.*)\\] %\\}\$/\\2/p" "$formula/map.jinja" | tr -d "' " | tr ',' '\n')
  for key in package.sha256 package.source package.format; do
    grep -qF "\`$key\`" "$formula/README.md" || fail "README.md does not mention \`$key\`"
  done

  for file in "$formula/pillar.example" "$formula/README.md" "$testdir/minion.tmpl" "$testdir/files/agent.yaml"; do
    check_names "$file"
  done
  if grep -qE 'mjp_[A-Za-z0-9_-]{43}' "$formula/pillar.example" "$formula/README.md"; then
    fail "pillar.example or README.md contains something that looks like a real pass"
  fi

  if py=$(yaml_python); then
    for file in "$formula/pillar.example" "$formula/defaults.yaml" "$testdir/files/agent.yaml" "$testdir"/cases/*.sls; do
      yaml_parses "$py" "$file" || fail "$file is not valid YAML"
    done
  else
    echo "salt-test self-test: SKIP the YAML parse (no Python with PyYAML; the full run renders every pillar)" >&2
  fi

  # The pinned Salt in ci.yml: the README names the same version.
  if grep -q 'SALT_VERSION:' .github/workflows/ci.yml; then
    want=$(sed -nE 's/^[[:space:]]+SALT_VERSION:[[:space:]]*"([^"]+)".*/\1/p' .github/workflows/ci.yml)
    grep -qF "$want" "$formula/README.md" || fail "README.md does not name the tested Salt version $want"
    sed -nE 's/^[[:space:]]+SALT_SHA256:[[:space:]]*"([^"]+)".*/\1/p' .github/workflows/ci.yml | grep -qE '^[0-9a-f]{64}$' ||
      fail "SALT_SHA256 in ci.yml is not a SHA-256"
  fi

  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --severity=warning --external-sources "$0" || fail "shellcheck found problems in $0"
  else
    echo "salt-test self-test: SKIP ShellCheck (not installed)" >&2
  fi

  if [ "$failures" -ne 0 ]; then
    echo "salt-test self-test: $failures failure(s)" >&2
    return 1
  fi
  echo "salt-test self-test: all checks passed"
}

# --- the full run ---------------------------------------------------------------------------

has_id() { # has_id FILE ID: the state ID is a key of a show_highstate result
  jq -e --arg id "$2" '.local | type == "object" and has($id)' "$1" >/dev/null 2>&1
}

applied_id() { # applied_id FILE ID: a state.apply result has a state with this ID
  jq -e --arg id "$2" '.local | type == "object" and any(keys[]; contains("_|-" + $id + "_|-"))' "$1" >/dev/null 2>&1
}

run_case() {
  local case_file=$1 name work cfg mode want text secret rc render apply
  name=$(basename "$case_file" .sls)
  work=$tmp/$name
  mkdir -p "$work/cache" "$work/log" "$work/pillar" "$work/top"
  cp "$case_file" "$work/pillar/myownpki.sls"
  printf "base:\n  '*':\n    - myownpki\n" >"$work/pillar/top.sls"
  printf "base:\n  '*':\n    - myownpki\n" >"$work/top/top.sls"
  cfg=$work/minion
  {
    sed -e "s#@WORK@#$(native "$work")#g" \
      -e "s#@TOP@#$(native "$work/top")#g" \
      -e "s#@PILLAR@#$(native "$work/pillar")#g" \
      -e "s#@FORMULAS@#$(native "$repo/deploy/salt")#g" \
      "$testdir/minion.tmpl"
    echo 'grains:'
    directive "$case_file" grain | while IFS= read -r want; do
      printf '  %s: %s\n' "${want%%=*}" "${want#*=}"
    done
  } >"$cfg"

  run_salt() { salt-call --local -c "$(native "$work")" --out=json --no-color --log-level=quiet --retcode-passthrough "$@"; }

  render=$work/highstate.json
  rc=0
  run_salt state.show_highstate >"$render" 2>"$work/render.err" || rc=$?
  if [ "$rc" -ne 0 ] || ! jq -e '.local | type == "object"' "$render" >/dev/null 2>&1; then
    fail "$name: state.show_highstate did not render (exit $rc)"
    head -c 3000 "$render" "$work/render.err" >&2 || true
    return
  fi

  if [ -n "$(directive "$case_file" refused)" ]; then
    if [ "$(jq '.local | length' "$render")" != 1 ] || ! has_id "$render" "$refused_id"; then
      fail "$name: a refusal must render exactly the state $refused_id"
    fi
    if has_id "$render" myownpki-agent-pass-absent; then
      fail "$name: a refusal must not remove the pass file (myownpki-agent-pass-absent)"
    fi
    text=$(jq -r --arg id "$refused_id" '.local[$id].test[]? | objects | .name // empty' "$render")
    want=$(directive "$case_file" refused)
    case $text in
      *"$want"*) ;;
      *) fail "$name: the reason \"$text\" does not contain \"$want\"" ;;
    esac
  else
    while IFS= read -r want; do
      has_id "$render" "$want" || fail "$name: state $want is missing"
    done < <(directive "$case_file" present)
    if has_id "$render" "$refused_id"; then
      fail "$name: refused: $(jq -r --arg id "$refused_id" '.local[$id].test[]? | objects | .name // empty' "$render")"
    fi
  fi
  while IFS= read -r want; do
    if has_id "$render" "$want"; then fail "$name: state $want must not exist"; fi
  done < <(directive "$case_file" absent)
  while IFS= read -r want; do
    grep -qF -- "$want" "$render" || fail "$name: the highstate does not contain \"$want\""
  done < <(directive "$case_file" contains)

  mode=$(directive "$case_file" mode)
  apply=$work/apply.json
  if [ "${mode:-apply}" = apply ] || [ -n "$(directive "$case_file" refused)" ]; then
    if [ "$can_apply" = true ]; then
      rc=0
      run_salt state.apply myownpki test=True >"$apply" 2>"$work/apply.err" || rc=$?
      if [ -n "$(directive "$case_file" refused)" ]; then
        if [ "$rc" -eq 0 ] || ! applied_id "$apply" "$refused_id"; then
          fail "$name: state.apply must fail with the state $refused_id (exit $rc)"
        fi
      else
        if [ "$rc" -ne 0 ] || ! jq -e '.local | type == "object" and all(.[]; (type != "object") or (.result != false))' "$apply" >/dev/null 2>&1; then
          fail "$name: state.apply test=True failed (exit $rc)"
          head -c 6000 "$apply" "$work/apply.err" >&2 || true
        fi
        while IFS= read -r want; do
          applied_id "$apply" "$want" || fail "$name: state.apply has no state $want"
        done < <(directive "$case_file" present)
        while IFS= read -r want; do
          if applied_id "$apply" "$want"; then fail "$name: state.apply must not have the state $want"; fi
        done < <(directive "$case_file" absent)
      fi
    fi
  fi

  # The pass never shows up in any output, and nothing a case forbids does.
  while IFS= read -r secret; do
    if grep -rqF -- "$secret" "$work"/*.json "$work"/*.err 2>/dev/null; then
      fail "$name: \"$secret\" appears in the output"
    fi
  done < <(directive "$case_file" not-contains)
  echo "salt-test: $name done"
}

full_run() {
  local case_file name cases
  command -v salt-call >/dev/null 2>&1 || { echo 'salt-test: salt-call is not on PATH' >&2; return 2; }
  command -v jq >/dev/null 2>&1 || { echo 'salt-test: jq is not on PATH' >&2; return 2; }
  salt-call --version

  can_apply=true
  if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ]; then
    can_apply=false
    echo 'salt-test: NOTE state.apply test=True is skipped (it needs Linux and root); only the rendering is checked' >&2
  fi

  tmp=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-salt-test.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT

  if py=$(yaml_python); then
    for case_file in "$formula/pillar.example" "$formula/defaults.yaml"; do
      yaml_parses "$py" "$case_file" || fail "$case_file is not valid YAML"
    done
  fi
  cases=()
  if [ "$#" -eq 0 ]; then
    cases=("$testdir"/cases/*.sls)
  else
    for name in "$@"; do
      [ -f "$testdir/cases/$name.sls" ] || { echo "salt-test: no case $name" >&2; return 2; }
      cases+=("$testdir/cases/$name.sls")
    done
  fi
  for case_file in "${cases[@]}"; do
    run_case "$case_file"
  done

  if [ "$failures" -ne 0 ]; then
    echo "salt-test: $failures failure(s)" >&2
    return 1
  fi
  echo 'salt-test: all cases passed'
}

can_apply=false
tmp=
py=
case ${1:-} in
  --self-test) self_test ;;
  -*)
    echo 'usage: salt-test.sh [--self-test | CASE...]' >&2
    exit 2
    ;;
  *) full_run "$@" ;;
esac
