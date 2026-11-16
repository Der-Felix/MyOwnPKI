#!/usr/bin/env bash
# The upgrade test (PHASE3 §19.5, steps 109 to 112): installations made by OLD
# release binaries keep working after an update to the binary of this tree.
#
#   bash test/upgrade/run.sh [options] [VERSION...]
#
# For each start version (default: every version of scripts/upgrade/releases.txt;
# UPGRADE_ONLY="0.3.5 0.3.12" or the arguments narrow it) the harness
#   1. fetches the release archives (scripts/upgrade/fetch.sh, SHA-256 pinned) and unpacks them,
#   2. makes an instance with the OLD binary (`init --demo --with-ca`, `serve`, the REST API:
#      two certificates, one revoked, a domain rule, an ACME issuance with lego, settings, an
#      agent, an enrollment pass, an audit entry) and a backup,
#   3. updates in place: the NEW binary (built from this tree) on the same data directory and
#      the same, unchanged config.yaml,
#   4. checks A1 to A10 of PHASE3 §19.5 (test/upgrade/assert.sh, profiles.sh says what a version has).
#
# Linux amd64 only: the release archives are Linux builds. On another machine use
# --old-bin for a smoke run with a binary you have (see below).
#
# Options:
#   --dry-run            print what would run for each version, touch nothing
#   --self-test          test the harness itself (parsers, config files, profiles, TOTP); no server
#   --print-matrix SET   print the versions of SET (pr or all), one line, for a CI matrix
#   --list               the versions of releases.txt
#   --offline            no downloads (same as UPGRADE_OFFLINE=1); a missing file is a SKIP line
#   --keep               keep the work directory of a passing run
#   --new-bin FILE       the server binary of this tree (default: go build)
#   --new-agent-bin FILE the agent binary of this tree (default: go build)
#   --old-bin FILE --as VERSION [--old-agent-bin FILE]
#                        smoke run: FILE is "the old release" with the capabilities of VERSION
#                        (with the same binary as new and old the migration steps A1 and A2 are not
#                        meaningful and say so). Nothing is downloaded.
#
# Environment: UPGRADE_WORK (default .tools/upgrade/work), UPGRADE_CACHE, UPGRADE_OFFLINE,
# UPGRADE_ONLY, LEGO_BIN (default .tools/lego; task acme:lego builds it), UPGRADE_HOST_IP (an address
# of this host that is not loopback, for http-01), UPGRADE_AGENT_WAIT (seconds to wait for the old
# agent's next report, default 420), UPGRADE_SKIP_ACME=1, UPGRADE_SKIP_AGENT=1.
#
# Exit status: 0 every check passed or was skipped with a reason, 1 a check failed,
# 2 usage. Every SKIP is printed in the table at the end: a skip is not a pass.
set -euo pipefail

# Git for Windows turns an argument that looks like a POSIX path into a Windows path (good for the
# files we pass to native binaries) but would also rewrite -subj "/CN=x": keep that one as it is.
export MSYS2_ARG_CONV_EXCL='/CN='

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE=$ROOT/test/upgrade
SELF=$HERE/run.sh

# shellcheck source=scripts/upgrade/lib.sh
. "$ROOT/scripts/upgrade/lib.sh"
# demo.sh (sourced: only its functions) brings the TOTP code, the sign-in and the API helper that
# the demo check already exercises; lib.sh and instance.sh override what differs.
# shellcheck source=deploy/demo/demo.sh
. "$ROOT/deploy/demo/demo.sh"
rm -rf "$tmp"
# shellcheck source=test/upgrade/lib.sh
. "$HERE/lib.sh"
# shellcheck source=test/upgrade/profiles.sh
. "$HERE/profiles.sh"
# shellcheck source=test/upgrade/instance.sh
. "$HERE/instance.sh"
# shellcheck source=test/upgrade/populate.sh
. "$HERE/populate.sh"
# shellcheck source=test/upgrade/assert.sh
. "$HERE/assert.sh"
trap - EXIT

# v0.1.0 refuses unknown MYOWNPKI_* variables, and a config from the environment would break the "unchanged config" rule.
for name in $(compgen -e | grep '^MYOWNPKI_' || true); do unset "$name"; done

WORK=${UPGRADE_WORK:-$ROOT/.tools/upgrade/work}

usage() {
  sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$SELF" >&2
}

# --- the versions ------------------------------------------------------------------------------------

# matrix_versions SET: pr = the three of the pull-request subset (the oldest, 0.3.5 and the
# previous release = the newest of the list); all = every version of the list.
matrix_versions() {
  local all first last
  all=$(release_versions | tr '\n' ' ')
  first=$(printf '%s' "$all" | awk '{ print $1 }')
  last=$(printf '%s' "$all" | awk '{ print $NF }')
  case $1 in
    all) printf '%s\n' "${all% }" ;;
    pr)
      printf '%s\n' "$first 0.3.5 $last" | tr ' ' '\n' | awk '!seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
      echo
      ;;
    *) return 1 ;;
  esac
}

# --- dry run ------------------------------------------------------------------------------------------

# plan_version VERSION: what a run would do, from the profile alone.
plan_version() {
  local v=$1 id verdict
  profile_load "$v"
  printf '\n== %s (dry run)\n' "$v"
  printf '   profile: %s\n' "$(profile_line)"
  printf '   fetch:   server archive'
  [ "$P_AGENT" = 0 ] || printf ', agent archive'
  printf '\n'
  printf '   old binary: init --demo --with-ca, serve, unseal, 2 certificates (1 revoked)'
  [ "$P_DOMAIN" = 0 ] || printf ', domain rule'
  [ "$P_ACME" = 0 ] || printf ', lego issuance'
  [ "$P_SETTINGS" = 0 ] || printf ', settings version'
  [ "$P_AGENT" = 0 ] || printf ', agent CA and enrolled agent'
  [ "$P_PASS" = 0 ] || printf ', enrollment pass'
  printf ', audit entry, backup\n'
  printf '   update:  the binary of this tree on the same data directory and config\n'
  for id in $(assertion_ids); do
    verdict=$(assertion_applies "$id")
    if [ "$verdict" = yes ]; then
      printf '   %-4s run   %s\n' "$id" "$(assertion_text "$id")"
    else
      printf '   %-4s SKIP  %s\n' "$id" "$verdict"
    fi
  done
}

# --- the child: one version ---------------------------------------------------------------------------

# unpack_archive FILE DIR NAME: unpack a release archive and print the path of the binary NAME in it.
unpack_archive() {
  local file=$1 dir=$2 name=$3 bin
  rm -rf "$dir"
  mkdir -p "$dir"
  tar -xzf "$file" -C "$dir"
  bin=$(find "$dir" -type f -name "$name" | head -n 1)
  [ -n "$bin" ] || die "the archive $(basename "$file") holds no $name"
  chmod +x "$bin"
  printf '%s\n' "$bin"
}

# fetch_old VERSION: OLD_BIN (and OLD_AGENT_BIN) from the cache; status 3 = a file is missing offline.
fetch_old() {
  local v=$1 archive rc=0
  if [ -n "${SMOKE_OLD_BIN:-}" ]; then
    OLD_BIN=$SMOKE_OLD_BIN
    OLD_AGENT_BIN=${SMOKE_OLD_AGENT_BIN:-}
    return 0
  fi
  archive=$(bash "$ROOT/scripts/upgrade/fetch.sh" "$v" server) || rc=$?
  [ "$rc" = 0 ] || return "$rc"
  OLD_BIN=$(unpack_archive "$archive" "$W/old" myownpki)
  OLD_AGENT_BIN=
  if [ "$P_AGENT" = 1 ]; then
    archive=$(bash "$ROOT/scripts/upgrade/fetch.sh" "$v" agent) || rc=$?
    if [ "$rc" = 0 ]; then
      OLD_AGENT_BIN=$(unpack_archive "$archive" "$W/old-agent" myownpki-agent)
    else
      AGENT_SKIP="the agent archive of $v is not in the cache and the network is off"
      rc=0
    fi
  fi
  return 0
}

child_cleanup() {
  local status=$?
  bg_stop_all
  if [ "$status" -ne 0 ]; then
    printf 'upgrade: version %s stopped with status %s; the work directory is kept: %s\n' "${CUR_VERSION:-?}" "$status" "${W:-?}" >&2
  fi
  exit "$status"
}

child_main() {
  local v=$1 rc=0 id
  CUR_VERSION=$v
  profile_load "$v"
  W=$WORK/$v
  T=$W/t
  rm -rf "$W"
  mkdir -p "$T"
  trap child_cleanup EXIT
  say "$v: $(profile_line)"

  AGENT_SKIP=
  ACME_SKIP=
  [ -z "${UPGRADE_SKIP_AGENT:-}" ] || AGENT_SKIP="UPGRADE_SKIP_AGENT is set"
  fetch_old "$v" || rc=$?
  if [ "$rc" = 3 ]; then
    for id in $(assertion_ids); do skip "$id" "the release files of $v are not in the cache and the network is off (task upgrade:fetch)"; done
    trap - EXIT
    return 0
  elif [ "$rc" != 0 ]; then
    die "cannot fetch the release files of $v"
  fi
  NEW_BIN=${NEW_BIN:?set by the parent}
  NEW_AGENT_BIN=${NEW_AGENT_BIN:-}
  SAME_BINARY=0
  [ "$(sha256_file "$OLD_BIN")" != "$(sha256_file "$NEW_BIN")" ] || SAME_BINARY=1
  note "old: $("$OLD_BIN" --version 2>&1 | head -n 1)"
  note "new: $("$NEW_BIN" --version 2>&1 | head -n 1)"
  if [ "$P_AGENT" = 1 ] && [ -z "$AGENT_SKIP" ] && { [ -z "$OLD_AGENT_BIN" ] || [ ! -x "$OLD_AGENT_BIN" ]; }; then
    AGENT_SKIP="no old agent binary (--old-agent-bin)"
  fi

  # ACME needs lego, a port-80 listener and an address the server may connect to (never loopback).
  HOSTIP=$(host_ip)
  LEGO_BIN=${LEGO_BIN:-}
  if [ "$P_ACME" = 1 ]; then
    if [ -n "${UPGRADE_SKIP_ACME:-}" ]; then
      ACME_SKIP="UPGRADE_SKIP_ACME is set"
    elif [ -z "$LEGO_BIN" ] || [ ! -x "$LEGO_BIN" ]; then
      ACME_SKIP="needs lego (LEGO_BIN, or .tools/lego from task acme:lego)"
    elif [ -z "$HOSTIP" ]; then
      ACME_SKIP="needs an address of this host that is not loopback for http-01 (UPGRADE_HOST_IP)"
    elif ! can_bind_port80; then
      ACME_SKIP="needs a listener on port 80 (root, or sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80)"
    elif [ ! -x "${STUBDNS_BIN:-}" ]; then
      ACME_SKIP="the stub DNS server is not built"
    fi
  fi

  # --- ports, files ---
  pick_port ADMIN_PORT
  MAIN_ADMIN_PORT=$ADMIN_PORT
  pick_port PUBLIC_PORT
  pick_port ACME_PORT
  pick_port AGENT_PORT
  pick_port DNS_PORT
  DATA=$W/data
  CFG=$W/config.yaml
  mkdir -p "$W/logs"
  local dns_arg=
  if [ "$P_ACME" = 1 ]; then
    [ -n "$ACME_SKIP" ] || dns_arg=$DNS_PORT
    write_config "$CFG" "$DATA" "$ADMIN_PORT" "$PUBLIC_PORT" "$ACME_PORT" "$dns_arg"
  else
    write_config "$CFG" "$DATA" "$ADMIN_PORT" "$PUBLIC_PORT"
  fi

  # --- the old instance ---
  populate_init
  SECRETS=$T/secrets.txt
  cp "$DATA/init-demo-secrets.txt" "$SECRETS"
  if [ -n "$dns_arg" ]; then
    bg_start "$W/logs/stubdns.log" "$STUBDNS_BIN" --listen "127.0.0.1:$DNS_PORT" --zone upgrade.lan --ip "$HOSTIP"
  fi
  server_start "$OLD_BIN" "$CFG" "$W/logs/old-server.log"
  server_wait "$OLD_BIN" "$CFG"
  api_use "$ADMIN_PORT" "$T/api" "$SECRETS"
  unseal
  populate_certificates
  [ "$P_DOMAIN" = 0 ] || populate_domain
  DIRECTORY_BEFORE=
  if [ "$P_ACME" = 1 ] && [ -z "$ACME_SKIP" ]; then
    populate_acme
    DIRECTORY_BEFORE=$(directory_urls)
  fi
  populate_settings
  if [ "$P_AGENT" = 1 ] && [ -z "$AGENT_SKIP" ]; then
    populate_agent_ca
    # The agent listener needs its CA, so the config grows by one block and the server restarts.
    server_stop
    write_config "$CFG" "$DATA" "$ADMIN_PORT" "$PUBLIC_PORT" "$([ "$P_ACME" = 1 ] && echo "$ACME_PORT")" "$dns_arg" "$AGENT_PORT"
    server_start "$OLD_BIN" "$CFG" "$W/logs/old-server-2.log"
    server_wait "$OLD_BIN" "$CFG"
    api_use "$ADMIN_PORT" "$T/api" "$SECRETS"
    unseal
    populate_agent
  fi
  if [ "$P_PASS" = 1 ] && [ -z "$AGENT_SKIP" ]; then populate_pass; fi
  populate_etags
  populate_audit_entry
  populate_backup
  server_stop
  populate_heads
  facts_write

  # --- the update ---
  say "$v -> this tree: the new binary on the same data directory and the same config"
  assert_a10
  assert_a1_before
  server_start "$NEW_BIN" "$CFG" "$W/logs/new-server.log"
  MAIN_PID=$SERVER_PID
  server_wait "$NEW_BIN" "$CFG"
  api_use "$ADMIN_PORT" "$T/api" "$SECRETS"
  unseal
  A7_BASE=
  if [ "$P_AGENT" = 1 ] && [ -z "$AGENT_SKIP" ]; then
    agents_json || true
    A7_BASE=$(agent_field last_seen_at)
  fi
  assert_a1_after
  check_facts A3 "after the update"
  check_audit A4 "after the update" "$NEW_BIN" "$CFG" "$F_HEAD_instance" "$F_HEAD_tenant"
  assert_a5
  assert_a6
  assert_a8
  assert_a7
  server_stop
  assert_a2
  assert_a9

  trap - EXIT
  bg_stop_all
  if awk -F'	' -v v="$v" '$1 == v && $3 == "FAIL"' "${UPGRADE_RESULTS:-/dev/null}" | grep -q .; then
    printf 'upgrade: the work directory of %s is kept for the failure: %s
' "$v" "$W" >&2
  elif [ "${UPGRADE_KEEP:-0}" != 1 ]; then
    rm -rf "$W"
  fi
}

# --- the parent -----------------------------------------------------------------------------------------

# build_tools: the binaries of this tree and the stub DNS server, once per run.
build_tools() {
  local out=$WORK/bin ext=
  mkdir -p "$out"
  case $(uname -s) in MINGW* | MSYS* | CYGWIN*) ext=.exe ;; esac
  if [ -z "${NEW_BIN:-}" ]; then
    command -v go >/dev/null 2>&1 || die "go is needed to build the binary of this tree (or pass --new-bin)"
    NEW_BIN=$out/myownpki$ext
    (cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$NEW_BIN" ./cmd/myownpki)
  fi
  if [ -z "${NEW_AGENT_BIN:-}" ] && command -v go >/dev/null 2>&1; then
    NEW_AGENT_BIN=$out/myownpki-agent$ext
    (cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$NEW_AGENT_BIN" ./cmd/myownpki-agent)
  fi
  if command -v go >/dev/null 2>&1; then
    STUBDNS_BIN=$out/stubdns$ext
    (cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$STUBDNS_BIN" ./internal/testutil/stubdns)
  fi
  if [ -z "${LEGO_BIN:-}" ]; then
    for ext in '' .exe; do
      if [ -x "$ROOT/.tools/lego$ext" ]; then LEGO_BIN=$ROOT/.tools/lego$ext; fi
    done
  fi
  export NEW_BIN NEW_AGENT_BIN STUBDNS_BIN LEGO_BIN
}

print_summary() {
  local file=$1 fails skips passes
  printf '\n%-8s | %-4s | %-4s | %s\n' Version ID Status Check
  printf '%s\n' '---------+------+------+------------------------------------------------------------'
  awk -F'\t' '{ printf "%-8s | %-4s | %-4s | %s\n", $1, $2, $3, $4 }' "$file"
  fails=$(awk -F'\t' '$3 == "FAIL"' "$file" | wc -l | tr -d ' ')
  skips=$(awk -F'\t' '$3 == "SKIP"' "$file" | wc -l | tr -d ' ')
  passes=$(awk -F'\t' '$3 == "PASS"' "$file" | wc -l | tr -d ' ')
  printf '\nUpgrade test: %s passed, %s failed, %s skipped (a skip is not a pass)\n' "$passes" "$fails" "$skips"
}

parent_main() {
  local versions=("$@") v failed=0 results status
  if [ "${#versions[@]}" -eq 0 ]; then
    if [ -n "${SMOKE_AS:-}" ]; then
      versions=("$SMOKE_AS")
    elif [ -n "${UPGRADE_ONLY:-}" ]; then
      # shellcheck disable=SC2206 # split on commas and blanks on purpose
      versions=(${UPGRADE_ONLY//,/ })
    else
      # shellcheck disable=SC2207
      versions=($(release_versions))
    fi
  fi
  for v in "${versions[@]}"; do
    release_has "$v" || [ -n "${SMOKE_AS:-}" ] || die "version $v is not in scripts/upgrade/releases.txt"
  done
  if [ "$DRY_RUN" = 1 ]; then
    for v in "${versions[@]}"; do plan_version "$v"; done
    return 0
  fi
  if [ -z "${SMOKE_OLD_BIN:-}" ] && [ "$(uname -s)" != Linux ]; then
    die "this test runs old Linux release binaries; use --old-bin FILE --as VERSION for a smoke run on $(uname -s)"
  fi
  for t in curl openssl tar awk sed; do command -v "$t" >/dev/null 2>&1 || die "$t is needed"; done
  mkdir -p "$WORK"
  results=$WORK/results.tsv
  : >"$results"
  export UPGRADE_RESULTS=$results UPGRADE_WORK=$WORK
  build_tools
  for v in "${versions[@]}"; do
    status=0
    bash "$SELF" --child "$v" || status=$?
    if [ "$status" -ne 0 ] && ! awk -F'\t' -v v="$v" '$1 == v && $3 == "FAIL"' "$results" | grep -q .; then
      printf '%s\t%s\tFAIL\t%s\n' "$v" "run" "the run of this version stopped with status $status before it could check (see its log above)" >>"$results"
    fi
    [ "$status" -eq 0 ] || failed=1
  done
  print_summary "$results"
  if awk -F'\t' '$3 == "FAIL"' "$results" | grep -q .; then failed=1; fi
  return "$failed"
}

# --- self-test ------------------------------------------------------------------------------------------------

self_check() {
  local text=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf '   ok   %s\n' "$text"
  else
    printf '   FAIL %s\n' "$text" >&2
    SELF_FAILED=1
  fi
}

self_test() {
  local d out
  SELF_FAILED=0
  d=$(mktemp -d "${TMPDIR:-/tmp}/upgrade-selftest.XXXXXX")
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$d'" EXIT
  say "harness self-test"

  # Profiles.
  profile_load 0.1.0
  self_check "0.1.0 has no ACME, domain, agent" test "$(profile_line)" = 'acme=0 domain=0 agent=0 pass=0 settings_versions=0'
  profile_load 0.2.2
  self_check "0.2.2 has ACME and domain rules" test "$(profile_line)" = 'acme=1 domain=1 agent=0 pass=0 settings_versions=0'
  profile_load 0.3.0
  self_check "0.3.0 has the agent, no pass" test "$(profile_line)" = 'acme=1 domain=1 agent=1 pass=0 settings_versions=0'
  profile_load 0.3.5
  self_check "0.3.5 has the pass" test "$(profile_line)" = 'acme=1 domain=1 agent=1 pass=1 settings_versions=0'
  profile_load 0.3.10
  self_check "0.3.10 has versioned settings" test "$(profile_line)" = 'acme=1 domain=1 agent=1 pass=1 settings_versions=1'
  self_check "version 0.3.10 is newer than 0.3.5" version_ge 0.3.10 0.3.5
  self_check "version 0.3.5 is not newer than 0.3.10" bash -c '. "$1"; ! version_ge 0.3.5 0.3.10' _ "$ROOT/scripts/upgrade/lib.sh"
  self_check "A5 is skipped for 0.1.0" bash -c '. "$1"; . "$2"; profile_load 0.1.0; [ "$(assertion_applies A5)" != yes ]' _ "$ROOT/scripts/upgrade/lib.sh" "$HERE/profiles.sh"

  # The matrix.
  self_check "the pull-request matrix has the oldest, 0.3.5 and the newest" test "$(matrix_versions pr)" = "$(release_versions | head -n 1) 0.3.5 $(release_versions | tail -n 1)"

  # TOTP (RFC 6238 appendix B, SHA-1, 6 digits: the 8-digit values 94287082 and 07081804 end in these).
  self_check "TOTP of RFC 6238 at T=59" test "$(totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 1)" = 287082
  self_check "TOTP of RFC 6238 at T=1111111109" test "$(totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 37037036)" = 081804

  # The demo secrets file of init.
  cat >"$d/secrets.txt" <<'EOF'
# fixture, not a real instance
unseal passphrase: a fixture passphrase
admin user: demo
admin password: fixture-password
secret:   GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ
EOF
  pass='' admin_user='' admin_password='' totp_secret=''
  read_secrets "$d/secrets.txt" >/dev/null
  self_check "read_secrets finds passphrase, user and the TOTP secret" test "$pass|$admin_user|$totp_secret" = 'a fixture passphrase|demo|GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  pass='' admin_user='' admin_password='' totp_secret=''

  # Parsers.
  out=$(printf 'Test CA created: root, issuing (online root).\n\nCheckpoint key fingerprint – note it down; `x audit verify` checks:\n    abcdef0123456789abcd\n\nKeep apart.\n' | parse_checkpoint_key)
  self_check "the checkpoint key is read from the init output" test "$out" = abcdef0123456789abcd
  out=$(printf '  instance         OK – 12 entries, head 12:0123456789abcdef0123\n                   no signed checkpoint yet\n  tenant:default   OK – 7 entries, head 7:fedcba9876543210fedc\n' | parse_audit_heads | tr '\n' ';')
  self_check "audit verify heads are read" test "$out" = 'instance 12:0123456789abcdef0123;tenant:default 7:fedcba9876543210fedc;'
  out=$(printf 'Backup written to x: 9 files, tenants [default].\n  audit instance         head 3:0123456789abcdef0123 (3 entries)\n  audit tenant:default   head 4:fedcba9876543210fedc (4 entries)\n' | parse_audit_heads | tr '\n' ';')
  self_check "backup heads are read" test "$out" = 'instance 3:0123456789abcdef0123;tenant:default 4:fedcba9876543210fedc;'
  printf '{"id":"abc123","ca_id":"zzz","serial":"0A1B","x":{"id":"inner"}}' >"$d/one.json"
  self_check "json_first takes the first id, not ca_id" test "$(json_first id "$d/one.json")|$(json_first serial "$d/one.json")" = 'abc123|0A1B'
  printf -- '-----BEGIN X-----\nAAA\n-----END X-----\n' >"$d/x.pem"
  self_check "a PEM becomes a JSON string" test "$(pem_to_json_string "$d/x.pem")" = '-----BEGIN X-----\nAAA\n-----END X-----\n'

  # Files.
  mkdir -p "$d/data/tenants"
  printf 'one' >"$d/data/system.db"
  printf 'two' >"$d/data/tenants/pki.db"
  out=$(db_fingerprint "$d/data")
  self_check "db_fingerprint is stable" test "$out" = "$(db_fingerprint "$d/data")"
  printf 'three' >>"$d/data/system.db"
  self_check "db_fingerprint notices a change" test "$out" != "$(db_fingerprint "$d/data")"
  pa='' pb=''
  pick_port pa
  pick_port pb
  self_check "pick_port hands out two different ports" test "$pa" != "$pb"

  # The schema expectation of A1, with a fixture of two released and one new file.
  mkdir -p "$d/schema/pki" "$d/schema/system" "$d/schema/audit"
  touch "$d/schema/pki/0001_a.sql" "$d/schema/pki/0002_b.sql" "$d/schema/system/0001_a.sql" "$d/schema/audit/0001_a.sql"
  printf '# pins\npki 0001 a %064d v0.1.0\npki 0002 b %064d v0.2.0\nsystem 0001 a %064d v0.1.0\naudit 0001 a %064d v0.1.0\n' 0 0 0 0 >"$d/pins.txt"
  out=$(SCHEMA_DIR=$d/schema PIN_FILE=$d/pins.txt expected_pending_exit 0.1.0)
  self_check "0.1.0 lacks pki 0002: A1 expects exit 3" test "$out" = 3
  out=$(SCHEMA_DIR=$d/schema PIN_FILE=$d/pins.txt expected_pending_exit 0.2.0)
  self_check "0.2.0 has every file: A1 expects exit 0" test "$out" = 0
  touch "$d/schema/system/0002_new.sql"
  out=$(SCHEMA_DIR=$d/schema PIN_FILE=$d/pins.txt expected_pending_exit 0.2.0)
  self_check "a file that no release shipped makes A1 expect exit 3" test "$out" = 3
  self_check "this tree's pin file counts 21 pki files for 0.3.12" test "$(released_count pki 0.3.12)" = 21
  self_check "this tree's pin file counts 7 pki files for 0.1.0" test "$(released_count pki 0.1.0)" = 7

  # The config files.
  write_config "$d/c1.yaml" "$d/data" 20001 20002
  self_check "the plain config has data_dir, admin and public only" test "$(grep -c . "$d/c1.yaml")" = 8
  write_config "$d/c2.yaml" "$d/data" 20001 20002 20003 20004 20005
  self_check "ACME and agent blocks are written" bash -c 'grep -q "resolver: 127.0.0.1:20004" "$1" && grep -q "ca: agent-ca" "$1" && grep -q "base_url: https://127.0.0.1:20005" "$1"' _ "$d/c2.yaml"
  write_agent_config "$d/agent.yaml" "$d/state" 20005 "$d/root.pem" agent1.upgrade.lan "$d/web"
  self_check "agent.yaml names the server, the bundle and the hostname" bash -c 'grep -q "server: \"https://127.0.0.1:20005\"" "$1" && grep -q "hostname: \"agent1.upgrade.lan\"" "$1"' _ "$d/agent.yaml"

  # CRL number of a real CRL made here.
  if self_crl "$d"; then
    self_check "crl_number reads the CRL number" test "$(crl_number "$d/crl.pem")" = 5
  else
    printf '   SKIP crl_number (openssl could not make a test CRL)\n'
  fi

  # The current binary accepts the generated configs (A10 on the current build) - needs go.
  if [ -n "${NEW_BIN:-}" ] || command -v go >/dev/null 2>&1; then
    if [ -z "${NEW_BIN:-}" ]; then
      NEW_BIN=$d/myownpki
      (cd "$ROOT" && CGO_ENABLED=0 go build -o "$NEW_BIN" ./cmd/myownpki) || NEW_BIN=
    fi
    if [ -n "$NEW_BIN" ]; then
      self_check "config check accepts the plain config" "$NEW_BIN" config check --config "$d/c1.yaml"
      self_check "config check accepts ACME and agent blocks" "$NEW_BIN" config check --config "$d/c2.yaml"
    fi
  else
    printf '   SKIP config check (no go and no NEW_BIN)\n'
  fi

  # The dry run names every assertion.
  DRY_RUN=1
  out=$(plan_version 0.3.5)
  for id in $(assertion_ids); do
    self_check "the dry run of 0.3.5 names $id" bash -c 'printf "%s" "$1" | grep -q "$2"' _ "$out" "$id"
  done
  out=$(plan_version 0.1.0)
  self_check "the dry run of 0.1.0 skips A7 with a reason" bash -c 'printf "%s" "$1" | grep -q "A7   SKIP  needs the agent"' _ "$out"

  if [ "$SELF_FAILED" != 0 ]; then
    echo "harness self-test: FAILED" >&2
    exit 1
  fi
  echo "harness self-test: ok"
}

# self_crl DIR: a CRL with number 5 in DIR/crl.pem (and the CA in DIR/ca.pem), made with openssl.
self_crl() {
  local d=$1 nd
  nd=$(native_path "$d")
  mkdir -p "$d/ca"
  : >"$d/ca/index.txt"
  printf '05\n' >"$d/ca/crlnumber"
  cat >"$d/ca/openssl.cnf" <<EOF
[ ca ]
default_ca = c
[ c ]
database = $nd/ca/index.txt
crlnumber = $nd/ca/crlnumber
default_md = sha256
default_crl_days = 7
[ req ]
distinguished_name = dn
[ dn ]
EOF
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$d/ca/key.pem" -out "$d/ca.pem" \
    -subj "/CN=selftest" -days 2 -config "$d/ca/openssl.cnf" >/dev/null 2>&1 &&
    openssl ca -config "$d/ca/openssl.cnf" -gencrl -keyfile "$d/ca/key.pem" -cert "$d/ca.pem" -out "$d/crl.pem" >/dev/null 2>&1
}

# --- arguments ---------------------------------------------------------------------------------------------------

DRY_RUN=0
SELF_TEST=0
CHILD=
SMOKE_OLD_BIN=${SMOKE_OLD_BIN:-}
SMOKE_OLD_AGENT_BIN=${SMOKE_OLD_AGENT_BIN:-}
SMOKE_AS=${SMOKE_AS:-}
NEW_BIN=${NEW_BIN:-${UPGRADE_NEW_BIN:-}}
NEW_AGENT_BIN=${NEW_AGENT_BIN:-${UPGRADE_NEW_AGENT_BIN:-}}
args=()
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run) DRY_RUN=1 ;;
    --self-test) SELF_TEST=1 ;;
    --child) CHILD=${2:?--child needs a version}; shift ;;
    --print-matrix) matrix_versions "${2:?--print-matrix needs pr or all}" || { echo 'upgrade: the set is pr or all' >&2; exit 2; }; exit 0 ;;
    --list) release_versions; exit 0 ;;
    --offline) export UPGRADE_OFFLINE=1 ;;
    --keep) export UPGRADE_KEEP=1 ;;
    --new-bin) NEW_BIN=${2:?--new-bin needs a file}; shift ;;
    --new-agent-bin) NEW_AGENT_BIN=${2:?--new-agent-bin needs a file}; shift ;;
    --old-bin) SMOKE_OLD_BIN=${2:?--old-bin needs a file}; shift ;;
    --old-agent-bin) SMOKE_OLD_AGENT_BIN=${2:?--old-agent-bin needs a file}; shift ;;
    --as) SMOKE_AS=${2:?--as needs a version}; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) echo "upgrade: unknown option $1" >&2; usage; exit 2 ;;
    *) args+=("$1") ;;
  esac
  shift
done
if [ -n "$SMOKE_OLD_BIN" ] && [ -z "$SMOKE_AS" ]; then echo 'upgrade: --old-bin needs --as VERSION' >&2; exit 2; fi
export SMOKE_OLD_BIN SMOKE_OLD_AGENT_BIN SMOKE_AS

if [ "$SELF_TEST" = 1 ]; then
  self_test
  exit 0
fi
if [ -n "$CHILD" ]; then
  child_main "$CHILD"
  exit 0
fi
parent_main ${args[@]+"${args[@]}"}
