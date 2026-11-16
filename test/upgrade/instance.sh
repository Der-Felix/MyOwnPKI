#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the files of this directory are sourced into one shell and share its variables
# One MyOwnPKI instance of the upgrade test: its config file, its server process
# and the admin API (the sign-in, TOTP and request helpers of deploy/demo/demo.sh,
# which is sourced by run.sh before this file). Sourced; runs nothing.
#
# The harness drives every version the way a person does: `init --demo
# --with-ca`, `serve`, then the REST API of the admin listener (sign in with the
# password and a TOTP code from the demo secrets file, unseal, issue, revoke …).

# native_path PATH: the path as the binary under test reads it (C:/… for a
# Windows binary started from Git Bash; unchanged on Linux).
native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

# write_config FILE DATA ADMIN_PORT PUBLIC_PORT [ACME_PORT [DNS_PORT [AGENT_PORT]]]
# The config of an instance; only keys that every version since 0.1.0 knows,
# plus acme (0.2.2) and agent (0.3.0) blocks when their ports are given.
write_config() {
  local file=$1 data=$2 admin_port=$3 public_port=$4 acme_port=${5:-} dns_port=${6:-} agent_port=${7:-}
  {
    printf 'data_dir: "%s"\n' "$(native_path "$data")"
    printf 'log:\n  level: info\n  format: json\n'
    printf 'admin:\n  listen: 127.0.0.1:%s\n' "$admin_port"
    printf 'public:\n  listen: 127.0.0.1:%s\n' "$public_port"
    if [ -n "$acme_port" ]; then
      printf 'acme:\n  base_url: https://127.0.0.1:%s/acme\n  listen: 127.0.0.1:%s\n  tls_issuer: issuing\n' "$acme_port" "$acme_port"
      if [ -n "$dns_port" ]; then printf '  resolver: 127.0.0.1:%s\n' "$dns_port"; fi
    fi
    if [ -n "$agent_port" ]; then
      printf 'agent:\n  base_url: https://127.0.0.1:%s\n  listen: 127.0.0.1:%s\n  tls_issuer: issuing\n  ca: agent-ca\n' "$agent_port" "$agent_port"
    fi
  } >"$file"
}

# write_agent_config FILE STATE_DIR AGENT_PORT ROOT_PEM HOSTNAME WEBROOT
# The smallest agent.yaml every agent since 0.3.0 accepts: no deployments, the
# enrollment check answered in a webroot (no port 80 needed in manual mode).
write_agent_config() {
  local file=$1 state=$2 port=$3 root=$4 hostname=$5 webroot=$6
  {
    printf 'server: "https://127.0.0.1:%s"\n' "$port"
    printf 'ca_bundle: "%s"\n' "$(native_path "$root")"
    printf 'hostname: "%s"\n' "$hostname"
    printf 'state_dir: "%s"\n' "$(native_path "$state")"
    printf 'log_level: "info"\n'
    printf 'paths: ["%s"]\n' "$(native_path "$webroot")"
    printf 'enrollment:\n  challenge: webroot\n  webroot: "%s"\n' "$(native_path "$webroot")"
  } >"$file"
}

# --- the server process ----------------------------------------------------------

# server_start BIN CONFIG LOG: `serve` in the background; the pid is in SERVER_PID.
server_start() {
  bg_start "$3" "$1" serve --config "$2"
  SERVER_PID=$BG_LAST
}

# server_stop: stop the server started last and wait for it.
server_stop() {
  [ -z "${SERVER_PID:-}" ] || bg_stop "$SERVER_PID"
  SERVER_PID=
}

# server_healthy BIN CONFIG: success when the admin listener answers.
server_healthy() {
  "$1" healthcheck --config "$2" --timeout 3s
}

# server_wait BIN CONFIG: wait up to 90 seconds for the listener.
server_wait() {
  wait_until 90 server_healthy "$1" "$2" || die "the server did not become healthy (see its log)"
}

# --- the admin API (demo.sh does the work) ---------------------------------------

# api_use ADMIN_PORT TMPDIR SECRETS_FILE: point the helpers at one instance and
# start a fresh session. `last_step` of demo.sh stays: a TOTP code is never used
# twice, in whatever instance.
api_use() {
  admin=https://127.0.0.1:$1
  api_base=$admin/api/v1
  tmp=$2
  mkdir -p "$tmp"
  : >"$tmp/jar"
  csrf=
  http_code=
  signed_in=0
  stepped_at=0
  pass=
  admin_user=
  admin_password=
  totp_secret=
  SECRETS_FILE=$3
}

# load_secrets (replaces the one of demo.sh, which copies the file out of a container).
load_secrets() {
  [ -z "$pass" ] || return 0
  [ -f "$SECRETS_FILE" ] || die "no secrets file $SECRETS_FILE"
  read_secrets "$SECRETS_FILE"
}

# unseal: sign in and unseal (nothing when it is unsealed already).
unseal() {
  sign_in
  api GET /system/status || die "cannot read the status: $(problem)"
  if grep -q '"sealed":false' "$tmp/api.json"; then
    note "the server is unsealed already"
    return 0
  fi
  api POST /system/unseal "{\"passphrase\":\"$pass\"}" || die "the unseal was refused: $(problem)"
  grep -q '"sealed":false' "$tmp/api.json" || die "the server is still sealed after the unseal"
}

# api_get_file PATH FILE: GET and keep the answer body in FILE (PEM and JSON are text).
api_get_file() {
  api GET "$1" || die "GET $1: $(problem)"
  cp "$tmp/api.json" "$2"
}

# api_etag PATH: the ETag header of a GET (the version number, quoted), "" when none.
api_etag() {
  curl -sS --noproxy '*' --insecure --max-time 60 -b "$tmp/jar" -c "$tmp/jar" -D - -o /dev/null \
    -H "X-CSRF-Token: $csrf" "$api_base$1" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: //p' | head -n 1
}

# api_with_header METHOD PATH JSON HEADER: like `api` with one more request header.
api_with_header() {
  http_code=$(printf '%s' "$3" | curl -sS --noproxy '*' --insecure --max-time 180 \
    -b "$tmp/jar" -c "$tmp/jar" -X "$1" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -H "$4" \
    --data-binary @- -o "$tmp/api.json" -w '%{http_code}' "$api_base$2") || { http_code=000; return 1; }
  case $http_code in 2*) return 0 ;; *) return 1 ;; esac
}
