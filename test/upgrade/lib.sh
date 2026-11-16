#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the files of this directory are sourced into one shell and share its variables
# Helpers of the upgrade test (PHASE3 §19.5): logging, the result table, free
# ports, background processes and a few parsers. Sourced by run.sh; defines
# functions, runs nothing. Nothing here prints a secret.

# --- log ---------------------------------------------------------------------

say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die() {
  printf 'upgrade: %s\n' "$*" >&2
  exit 1
}

# --- results -----------------------------------------------------------------
# One line per check in $UPGRADE_RESULTS: VERSION<TAB>ID<TAB>STATUS<TAB>text.
# run.sh prints the table at the end and exits 1 when a line says FAIL.

record() {
  local status=$1 id=$2 text=$3
  printf '%s\t%s\t%s\t%s\n' "${CUR_VERSION:-?}" "$id" "$status" "$text" >>"${UPGRADE_RESULTS:-/dev/null}"
  printf '   %-4s %-4s %s\n' "$status" "$id" "$text"
}
pass() { record PASS "$1" "$2"; }
fail() { record FAIL "$1" "$2"; }
skip() { record SKIP "$1" "$2"; }

# expect ID TEXT CMD...: PASS when the command succeeds, else FAIL. The command's
# output is shown only on failure.
expect() {
  local id=$1 text=$2 out
  shift 2
  if out=$("$@" 2>&1); then
    pass "$id" "$text"
  else
    fail "$id" "$text"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/        | /'
  fi
}

# --- ports and addresses -------------------------------------------------------

PICKED_PORTS=" "

# pick_port NAME: set NAME to a TCP port nothing listens on and this run has not handed
# out yet. Not a command substitution on purpose: the list of handed-out ports must
# survive in this shell.
# (A check, not a reservation: another process could take it before the server
# does; the range stays below the dynamic one so the OS does not hand it out.)
pick_port() {
  local p tries=0
  while [ "$tries" -lt 200 ]; do
    tries=$((tries + 1))
    p=$((20000 + (RANDOM * 32768 + RANDOM) % 20000))
    case $PICKED_PORTS in *" $p "*) continue ;; esac
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      PICKED_PORTS="$PICKED_PORTS$p "
      printf -v "$1" '%s' "$p"
      return 0
    fi
  done
  return 1
}

# host_ip: an address of this host that is not loopback, link-local or a
# documentation address: the server refuses to connect to those for http-01.
# UPGRADE_HOST_IP overrides it. Empty when there is none.
host_ip() {
  if [ -n "${UPGRADE_HOST_IP:-}" ]; then
    printf '%s\n' "$UPGRADE_HOST_IP"
    return 0
  fi
  local candidates ip
  candidates=$(hostname -I 2>/dev/null || true)
  for ip in $candidates; do
    case $ip in
      127.* | 169.254.* | *:*) continue ;;
    esac
    printf '%s\n' "$ip"
    return 0
  done
  return 0
}

# can_bind_port80: success when a process of this user may listen on port 80
# (root, or net.ipv4.ip_unprivileged_port_start <= 80).
can_bind_port80() {
  [ "${UPGRADE_PORT80:-}" = 1 ] && return 0 # the caller made sure (a container, a Windows machine)
  [ "$(id -u)" = 0 ] && return 0
  local start
  start=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
  [ "$start" -le 80 ]
}

# --- processes ---------------------------------------------------------------

BG_PIDS=()

# bg_start LOGFILE CMD...: run a command in the background; its pid is in BG_LAST.
bg_start() {
  local log=$1
  shift
  "$@" >>"$log" 2>&1 </dev/null &
  BG_LAST=$!
  BG_PIDS+=("$BG_LAST")
}

# bg_stop PID: TERM, wait up to 20 seconds, then KILL.
bg_stop() {
  local pid=$1 i
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 40; i++)); do
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.5
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# bg_stop_all: every process of this run (the cleanup trap).
bg_stop_all() {
  local pid
  for pid in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do
    bg_stop "$pid"
  done
  BG_PIDS=()
}

# wait_until SECONDS CMD...: run CMD every half second until it succeeds.
wait_until() {
  local limit=$1 i
  shift
  for ((i = 0; i < limit * 2; i++)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# --- files and parsers ---------------------------------------------------------

# db_fingerprint DIR: one hash over the SQLite files below DIR (name and content),
# to show that a refused start changed nothing.
db_fingerprint() {
  (cd "$1" && find . -name '*.db' -type f | LC_ALL=C sort | while IFS= read -r f; do
    printf '%s %s\n' "$f" "$(sha256_file "$f")"
  done) | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1
}

# parse_checkpoint_key: the fingerprint that `init` prints under "Checkpoint key
# fingerprint", from stdin.
parse_checkpoint_key() {
  awk '/^Checkpoint key fingerprint/ { getline; gsub(/[ \t\r]/, ""); print; exit }'
}

# parse_audit_heads: "scope head" pairs from the output of `audit verify` or of
# `backup` (…head SEQ:HASH…), from stdin: the scope is the first word of the
# line ("instance", "tenant:default").
parse_audit_heads() {
  sed -n -E 's/^[[:space:]]*(audit[[:space:]]+)?([a-z]+(:[a-z0-9-]+)?)[[:space:]]+.*head ([0-9]+:[0-9a-f]{12,64}).*$/\2 \4/p'
}

# fingerprint_pem FILE: SHA-256 of the first certificate, lower case hex.
fingerprint_pem() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

# crl_number FILE: the CRL number as a decimal number.
crl_number() {
  local hex
  hex=$(openssl crl -in "$1" -noout -crlnumber | sed 's/^crlNumber=//; s/^0[xX]//')
  printf '%d\n' "0x${hex:-0}"
}

# json_first KEY FILE: the first string value of "KEY" in a compact JSON file.
json_first() {
  grep -o "\"$1\":\"[^\"]*\"" "$2" | head -n 1 | cut -d'"' -f4
}

# pem_to_json_string FILE: a PEM file as the text inside a JSON string.
pem_to_json_string() {
  awk 'BEGIN { ORS = "" } { gsub(/\r/, ""); printf "%s\\n", $0 }' "$1"
}
