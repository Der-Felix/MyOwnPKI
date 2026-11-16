#!/usr/bin/env bash
# demo.sh – drives the MyOwnPKI demo of deploy/demo (see README.md).
#
#   ./demo.sh run       up, unseal, domain, certbot and verify, in this order
#   ./demo.sh up        init once (a demo instance with its test CA), start, wait until healthy
#   ./demo.sh unseal    sign in with the demo secrets file and unseal the server
#   ./demo.sh domain    create the domain demo.test (http-01, open approval)
#   ./demo.sh certbot   certbot gets a certificate for www.demo.test by http-01
#   ./demo.sh verify    chain against the demo root, the name in it, the audit entry
#   ./demo.sh agent     second act: agent CA, agent listener, nginx served by the agent
#   ./demo.sh logs      the logs of the demo containers
#   ./demo.sh down      stop everything and delete the demo volumes
#
# A demo only: the server never reads its passphrase from a file, but a demo
# instance is marked as one for good and keeps every secret in one file
# (init-demo-secrets.txt in its data volume). This script reads that file to do
# what a person would do in the UI: sign in with the password and the TOTP
# code, and unseal. Secrets stay in variables of this process, are never
# printed, never put on a command line and never written anywhere else; under
# GitHub Actions they are masked as well.
#
# Needs: Docker with the compose plugin, curl, OpenSSL 1.1.1 or newer, sed, and
# bash 3.2 or newer. Environment: MYOWNPKI_IMAGE (the server image; default
# the release tag in docker-compose.yml).
set -euo pipefail
umask 077

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
admin=https://127.0.0.1:9443
api_base=$admin/api/v1
domain_name=demo.test
cert_name=www.demo.test
certbot_lineage=demo

tmp=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-demo.XXXXXX")
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die() {
  printf 'demo.sh: %s\n' "$*" >&2
  exit 1
}

# dc: docker compose for this directory with every profile switched on, so that
# `down` also removes the containers of the profiled services. Every call
# below names its services.
dc() {
  docker compose --project-directory "$here" -f "$here/docker-compose.yml" \
    --profile init --profile certbot --profile agent "$@"
}

need() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is needed but not installed"
  done
}

check_tools() {
  need docker curl openssl sed od tr date
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is needed (docker compose version failed)"
  case $(openssl version) in
    "OpenSSL 1.1.1"* | "OpenSSL 3"* | "OpenSSL 4"*) ;;
    *) die "OpenSSL 1.1.1 or newer is needed for the TOTP code and the checks (found: $(openssl version)); on macOS: brew install openssl" ;;
  esac
}

# --- secrets: only in these variables ---------------------------------------

pass=
admin_user=
admin_password=
totp_secret=

mask() {
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    printf '::add-mask::%s\n' "$1"
  fi
  return 0
}

# b32_clean TEXT: the TOTP secret as an authenticator app wants it. The file
# prints it in groups of four ("GEZD GNBV ..."), a person may paste it in lower
# case, with "=" padding, or as the otpauth link: strip a link down to its
# secret parameter, drop white space, "-" and "=", upper-case it.
b32_clean() {
  local s=$1
  case $s in
    *secret=*)
      s=${s#*secret=}
      s=${s%%&*}
      ;;
  esac
  printf '%s' "$s" | tr -d '[:space:]=-' | tr '[:lower:]' '[:upper:]'
}

# read_secrets FILE: the values of the demo secrets file (the format of
# internal/setup and internal/auth: "key: value" lines, "secret:" padded and in
# groups of four), masked and checked; nothing is printed.
read_secrets() {
  local file=$1 line value
  # Every value of the file is a secret (passphrase, password, recovery key
  # and codes, TOTP secret and link): mask all of them before any is used.
  while IFS= read -r line; do
    case $line in '#'* | '' | "admin user:"*) continue ;; esac
    value=$(printf '%s' "${line#*:}" | sed 's/^[[:space:]]*//')
    [ -z "$value" ] || mask "$value"
  done <"$file"
  pass=$(sed -n '/^unseal passphrase: /{s///;p;q;}' "$file" | tr -d '\r')
  admin_user=$(sed -n '/^admin user: /{s///;p;q;}' "$file" | tr -d '\r')
  admin_password=$(sed -n '/^admin password: /{s///;p;q;}' "$file" | tr -d '\r')
  totp_secret=$(sed -n '/^secret:[[:space:]]*/{s///;p;q;}' "$file")
  if [ -z "$totp_secret" ]; then
    totp_secret=$(sed -n 's/^otpauth link:.*[?&]secret=\([^&[:space:]]*\).*/\1/p' "$file" | head -n 1)
  fi
  totp_secret=$(b32_clean "$totp_secret")
  [ -n "$pass" ] || die "the demo secrets file has no unseal passphrase"
  [ -n "$admin_user" ] || die "the demo secrets file has no admin user"
  [ -n "$admin_password" ] || die "the demo secrets file has no admin password"
  [ -n "$totp_secret" ] || die "the demo secrets file has no TOTP secret"
  # The secret as the code generator uses it (no spaces) is a second string
  # for the mask. An authenticator secret has at least 16 characters (80 bits).
  mask "$totp_secret"
  if [ "${#totp_secret}" -lt 16 ] || ! b32_hex "$totp_secret" >/dev/null; then
    die "the TOTP secret in the demo secrets file is not base32 (or shorter than 16 characters)"
  fi
  # The values go into JSON bodies as they are.
  case "$pass$admin_user$admin_password" in
    *'"'* | *\*) die "an unexpected character in the demo secrets file" ;;
  esac
}

# load_secrets copies the demo secrets file out of the data volume into the
# private temporary directory, reads the values, masks them and deletes the copy.
load_secrets() {
  local file=$tmp/secrets.txt
  [ -z "$pass" ] || return 0
  dc cp myownpki:/var/lib/myownpki/init-demo-secrets.txt "$file" >/dev/null 2>&1 ||
    die "cannot read the demo secrets file from the data volume - is the demo up? (./demo.sh up)"
  read_secrets "$file"
  rm -f "$file"
  note "the demo secrets file was read (nothing of it is printed)"
}

# --- TOTP (RFC 6238: SHA-1, 6 digits, 30 s) ----------------------------------

# b32_hex BASE32: the bytes as hex (pure bash; macOS has no base32).
b32_hex() {
  local s alpha=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 bits=0 acc=0 out='' ch prefix i
  s=$(printf '%s' "${1%%=*}" | tr '[:lower:]' '[:upper:]')
  for ((i = 0; i < ${#s}; i++)); do
    ch=${s:i:1}
    prefix=${alpha%%"$ch"*}
    [ "$prefix" != "$alpha" ] || return 1
    acc=$(((acc << 5) | ${#prefix}))
    bits=$((bits + 5))
    if [ "$bits" -ge 8 ]; then
      bits=$((bits - 8))
      out="$out$(printf '%02x' $(((acc >> bits) & 255)))"
      acc=$((acc & ((1 << bits) - 1)))
    fi
  done
  printf '%s' "$out"
}

# totp BASE32-SECRET STEP: the code of the 30-second step STEP (time / 30).
totp() {
  local key counter msg='' mac off i
  key=$(b32_hex "$1") || return 1
  counter=$(printf '%016x' "$2")
  for ((i = 0; i < 16; i += 2)); do msg="$msg\\x${counter:i:2}"; done
  # shellcheck disable=SC2059 # the format is the counter's eight bytes
  mac=$(printf "$msg" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -binary | od -An -tx1 | tr -d ' \n')
  off=$((16#${mac:39:1}))
  printf '%06d' $((((16#${mac:$((off * 2)):8}) & 16#7fffffff) % 1000000))
}

# --- the REST API of the admin listener --------------------------------------

csrf=
http_code=
# api METHOD PATH [JSON]: like a browser (cookie jar, CSRF token of the last
# answer). The answer body goes to $tmp/api.json; the status to $http_code.
# The body is passed on stdin, so no secret appears in a process list. The
# admin certificate is self-signed (a demo on this host's loopback): --insecure.
api() {
  local tok
  local -a body=()
  if [ "$#" -ge 3 ]; then body=(--data-binary @-); fi
  http_code=$(printf '%s' "${3:-}" | curl -sS --noproxy '*' --insecure --max-time 180 \
    -b "$tmp/jar" -c "$tmp/jar" -X "$1" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    ${body[@]+"${body[@]}"} -o "$tmp/api.json" -w '%{http_code}' "$api_base$2") || {
    http_code=000
    return 1
  }
  tok=$(sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' "$tmp/api.json" | head -n 1)
  if [ -n "$tok" ]; then csrf=$tok; fi
  case $http_code in 2*) return 0 ;; *) return 1 ;; esac
}

# problem: what the last answer said, for an error message (no request data).
problem() {
  local detail
  detail=$(sed -n 's/.*"detail":"\([^"]*\)".*/\1/p' "$tmp/api.json" 2>/dev/null | head -n 1)
  printf 'HTTP %s %s' "$http_code" "$detail"
}

last_step=0
# second_factor ENDPOINT: the TOTP code to /auth/totp or /auth/step-up. A code
# works once, and only steps after the last used one count, so the code of the
# next 30-second step is used when the current one is gone, and the script
# waits for the next window when both are. The code is never printed.
second_factor() {
  local tries=0 cur want
  while [ "$tries" -lt 6 ]; do
    tries=$((tries + 1))
    cur=$(($(date +%s) / 30))
    want=$((last_step + 1))
    [ "$want" -ge "$cur" ] || want=$cur
    if [ "$want" -gt $((cur + 1)) ]; then
      note "the codes of this 30-second window are used up - waiting for the next one"
      sleep $((31 - $(date +%s) % 30))
      continue
    fi
    last_step=$want
    if api POST "$1" "{\"code\":\"$(totp "$totp_secret" "$want")\"}"; then return 0; fi
    # Only a refused code is tried again.
    [ "$http_code" = 422 ] || return 1
  done
  return 1
}

signed_in=0
stepped_at=0
sign_in() {
  [ "$signed_in" -eq 0 ] || return 0
  load_secrets
  say "Sign in as $admin_user (password, then the TOTP code from the secrets file)"
  api POST /auth/login "{\"username\":\"$admin_user\",\"password\":\"$admin_password\"}" ||
    die "the sign-in was refused: $(problem)"
  second_factor /auth/totp || die "the second factor was refused: $(problem)"
  signed_in=1
  note "signed in"
}

# step_up: a fresh second factor for a change of CAs or domains (valid for
# minutes, so it is asked for again only when the last one is old).
step_up() {
  sign_in
  if [ $(($(date +%s) - stepped_at)) -lt 240 ]; then return 0; fi
  note "confirming the second factor again (step-up) for a sensitive change"
  second_factor /auth/step-up || die "the step-up was refused: $(problem)"
  stepped_at=$(date +%s)
}

# ca_id NAME: the id of a CA (from /cas).
ca_id() {
  # Runs in a command substitution: report on stderr, print nothing.
  api GET /cas || {
    printf 'demo.sh: cannot list the CAs: %s\n' "$(problem)" >&2
    return 0
  }
  sed -n "s/.*\"id\":\"\([^\"]*\)\",\"name\":\"$1\".*/\1/p" "$tmp/api.json" | head -n 1
}

# fingerprint FILE: SHA-256 of the certificate, lower case hex without colons.
fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

# --- commands -----------------------------------------------------------------

cmd_up() {
  check_tools
  say "Initialize the demo instance (once): a demo admin, a test root and an issuing CA"
  local out
  if out=$(dc run --rm -T init 2>&1); then
    printf '%s\n' "$out"
  elif printf '%s' "$out" | grep -q 'initialized already'; then
    note "the instance is initialized already"
  else
    printf '%s\n' "$out" >&2
    die "init failed. If the image tag does not exist yet (it exists only after the release), set MYOWNPKI_IMAGE, see README.md"
  fi
  say "Start the server (it starts sealed)"
  dc up -d --wait --wait-timeout 180 myownpki || {
    dc logs --no-color --tail 40 myownpki >&2 || true
    die "the server did not become healthy"
  }
  note "the admin UI: $admin/ (the certificate is self-signed)"
}

cmd_unseal() {
  check_tools
  sign_in
  api GET /system/status || die "cannot read the status: $(problem)"
  if grep -q '"sealed":false' "$tmp/api.json"; then
    note "the server is unsealed already"
    return 0
  fi
  say "Unseal with the passphrase from the demo secrets file"
  api POST /system/unseal "{\"passphrase\":\"$pass\"}" || die "the unseal was refused: $(problem)"
  grep -q '"sealed":false' "$tmp/api.json" || die "the server is still sealed"
  note "unsealed - the CA keys are in memory, the ACME listener gets its own certificate"
}

cmd_domain() {
  check_tools
  sign_in
  api GET /domains || die "cannot list the domains: $(problem)"
  if grep -q "\"name\":\"$domain_name\"" "$tmp/api.json"; then
    note "the domain $domain_name exists already"
    return 0
  fi
  local id
  id=$(ca_id issuing)
  [ -n "$id" ] || die "no CA named issuing - was the instance created with ./demo.sh up?"
  say "Create the domain $domain_name (http-01 only, open approval, internal addresses allowed)"
  step_up
  api POST /domains "{\"name\":\"$domain_name\",\"ca_id\":\"$id\",\"include_subdomains\":true,\"challenge_types\":[\"http-01\"],\"approval\":\"open\",\"address_policy\":\"internal\"}" ||
    die "the domain was refused: $(problem)"
  note "created: names below $domain_name are issued by the CA issuing"
}

# root_pem FILE: the root certificate from the authenticated admin API.
root_pem() {
  local id
  sign_in
  id=$(ca_id root)
  [ -n "$id" ] || die "no CA named root"
  api GET "/cas/$id/certificate?format=pem" || die "cannot read the root certificate: $(problem)"
  cp "$tmp/api.json" "$1"
  openssl x509 -in "$1" -noout >/dev/null 2>&1 || die "the root certificate from the API is not a certificate"
}

cmd_certbot() {
  check_tools
  say "Start the certbot container (it answers to the name $cert_name)"
  dc up -d --wait certbot >/dev/null || die "the certbot container did not start"
  say "Run certbot: fetch the root, then http-01 for $cert_name"
  dc exec -T certbot sh /demo/run.sh 2>&1 | tee "$tmp/certbot.log" || {
    dc logs --no-color --tail 40 myownpki >&2 || true
    die "certbot failed (the server log above may say why; is the server unsealed and the domain created?)"
  }
  say "Compare the root certbot fetched over HTTP with the root of the authenticated API"
  local fetched trusted
  fetched=$(sed -n 's/^root SHA-256: //p' "$tmp/certbot.log" | head -n 1)
  root_pem "$tmp/root.pem"
  trusted=$(fingerprint "$tmp/root.pem")
  [ -n "$fetched" ] || die "certbot printed no root fingerprint"
  [ "$fetched" = "$trusted" ] || die "the root fetched by certbot ($fetched) differs from the root of the admin API ($trusted)"
  note "equal: $trusted"
}

cmd_verify() {
  check_tools
  say "Verify the certificate certbot received"
  dc exec -T certbot cat "/etc/letsencrypt/live/$certbot_lineage/fullchain.pem" >"$tmp/fullchain.pem" ||
    die "cannot read the certificate from the certbot container - did ./demo.sh certbot succeed?"
  openssl x509 -in "$tmp/fullchain.pem" -out "$tmp/leaf.pem" || die "fullchain.pem holds no certificate"
  root_pem "$tmp/root.pem"
  local id
  id=$(ca_id issuing)
  [ -n "$id" ] || die "no CA named issuing"
  api GET "/cas/$id/certificate?format=chain" || die "cannot read the CA chain: $(problem)"
  cp "$tmp/api.json" "$tmp/issuing-chain.pem"
  cat "$tmp/fullchain.pem" "$tmp/issuing-chain.pem" >"$tmp/untrusted.pem"
  openssl verify -CAfile "$tmp/root.pem" -untrusted "$tmp/untrusted.pem" "$tmp/leaf.pem" ||
    die "the certificate does not verify against the demo root"
  local san
  san=$(openssl x509 -in "$tmp/leaf.pem" -noout -ext subjectAltName | tail -n +2 | tr -d ' \n')
  [ "$san" = "DNS:$cert_name" ] || die "the subject alternative names are '$san', want DNS:$cert_name"
  note "subject alternative name: $san"
  openssl x509 -in "$tmp/leaf.pem" -noout -subject -issuer -serial -dates
  say "The audit log has the issuance"
  sign_in
  # The entry reaches the audit log through an outbox (written with the
  # issuance, delivered by a worker a moment later): look a few times.
  local attempt found=0
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    api GET '/audit?action=certificate.issue&result=success&limit=20' || die "cannot read the audit log: $(problem)"
    if grep -q '"action":"certificate.issue"' "$tmp/api.json"; then
      found=1
      break
    fi
    sleep 1
  done
  [ "$found" -eq 1 ] || die "no certificate.issue entry in the audit log (after $attempt tries)"
  note "found: certificate.issue (success)"
}

cmd_agent() {
  check_tools
  say "Second act: the agent CA and the agent listener"
  sign_in
  local agent_ca root_id
  agent_ca=$(ca_id agent-ca)
  if [ -z "$agent_ca" ]; then
    root_id=$(ca_id root)
    [ -n "$root_id" ] || die "no CA named root"
    step_up
    note "creating agent-ca (an intermediate below the root, EKU clientAuth only)"
    api POST /cas "{\"name\":\"agent-ca\",\"kind\":\"intermediate\",\"parent_ca_id\":\"$root_id\",\"subject\":{\"common_name\":\"MyOwnPKI Demo Agent CA\"},\"public_base_url\":\"http://myownpki:8080\",\"eku_limit\":[\"clientAuth\"]}" ||
      die "the agent CA was refused: $(problem)"
  else
    note "agent-ca exists already"
  fi
  say "Restart the server with the agent listener (it starts sealed again)"
  DEMO_AGENT_BASE_URL=https://agent.demo.test:8444 DEMO_AGENT_TLS_ISSUER=issuing DEMO_AGENT_CA=agent-ca \
    dc up -d --wait --wait-timeout 180 --force-recreate myownpki || die "the server did not become healthy"
  signed_in=0
  stepped_at=0
  cmd_unseal
  say "Build and start the web service (nginx with myownpki-agent)"
  DEMO_AGENT_BASE_URL=https://agent.demo.test:8444 DEMO_AGENT_TLS_ISSUER=issuing DEMO_AGENT_CA=agent-ca \
    dc up -d --build web || die "the web service did not start (did ./demo.sh certbot run before? see ./demo.sh logs)"
  say "One click left"
  note "Open $admin/ -> Agents -> Enrollment requests and approve web.demo.test."
  note "The agent then gets its certificate, orders one for web.demo.test and deploys it to nginx."
  note "Watch it with ./demo.sh logs, and in the UI under Agents."
}

cmd_logs() {
  dc logs --no-color --tail 200 myownpki certbot web
}

cmd_down() {
  say "Stop the demo and delete its volumes"
  dc down -v --remove-orphans
}

cmd_run() {
  cmd_up
  cmd_unseal
  cmd_domain
  cmd_certbot
  cmd_verify
  say "Done"
  note "Look at $admin/ - the certificate under Certificates, the domain, the audit log."
  note "The second act (nginx served by the agent): ./demo.sh agent. Clean up: ./demo.sh down"
}

main() {
  case "${1:-}" in
    run) cmd_run ;;
    up) cmd_up ;;
    unseal) cmd_unseal ;;
    domain) cmd_domain ;;
    certbot) cmd_certbot ;;
    verify) cmd_verify ;;
    agent) cmd_agent ;;
    logs) cmd_logs ;;
    down) cmd_down ;;
    *)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2
      exit 2
      ;;
  esac
}

# Sourced (by a test), it only defines the functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
