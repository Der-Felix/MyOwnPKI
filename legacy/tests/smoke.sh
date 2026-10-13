#!/usr/bin/env bash
###############################################################################
# tests/smoke.sh - End-to-end smoke test of the legacy suite (Linux/macOS)
#
# Builds a throwaway PKI in a temp directory and checks the results with
# openssl: root + intermediate, a server certificate with deployment guide,
# revocation and CRL. Runs the modular pki.sh and the compiled standalone
# script, then checks the Bash completion.
#
# Usage: legacy/tests/smoke.sh   (run legacy/build.sh first for the standalone)
###############################################################################
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

LEGACY=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# run_suite <script> <label>
run_suite() {
    local pki=$1 label=$2 dir="$WORK/$2/pki" log="$WORK/$2.log"
    mkdir -p "$WORK/$label"
    run() { bash "$pki" --dir "$dir" -y --no-color "$@" >>"$log" 2>&1 || { tail -n 30 "$log" >&2; fail "$label: pki $*"; }; }

    run init --org "Smoke Test" --country DE --cn "Smoke Root CA" --key rsa3072 \
        --no-pass --intermediate server-ca
    run issue server --cn nas.smoke.lan --dns nas.smoke.lan --ip 10.0.0.5 --ca server-ca

    local cert="$dir/issued/nas.smoke.lan/cert.pem"
    local root="$dir/root/certs/ca.crt" inter="$dir/intermediate/server-ca/certs/ca.crt"
    openssl verify -purpose sslserver -CAfile "$root" -untrusted "$inter" "$cert" >/dev/null \
        || fail "$label: chain does not verify for TLS server use"
    openssl x509 -in "$cert" -noout -ext subjectAltName | grep -q "DNS:nas.smoke.lan" \
        || fail "$label: SAN missing"
    grep -q "root.crt" "$dir/issued/nas.smoke.lan/GUIDE.txt" || fail "$label: GUIDE.txt incomplete"
    run verify nas.smoke.lan

    local serial
    serial=$(openssl x509 -in "$cert" -noout -serial | cut -d= -f2)
    run revoke nas.smoke.lan --reason superseded
    openssl crl -in "$dir/publish/server-ca.crl.pem" -noout -text | grep -qi "$serial" \
        || fail "$label: revoked serial not in CRL"
    echo "ok    $label"
}

run_suite "$LEGACY/pki.sh" modular
if [ -f "$LEGACY/dist/pki-standalone.sh" ]; then
    run_suite "$LEGACY/dist/pki-standalone.sh" standalone
else
    echo "skip  standalone (run legacy/build.sh first)"
fi

# Completion: stub the bash-completion helpers so no package is needed.
(
    _init_completion() {
        words=("${COMP_WORDS[@]}"); cword=$COMP_CWORD
        cur=${COMP_WORDS[COMP_CWORD]}; prev=${COMP_WORDS[COMP_CWORD-1]}
    }
    # shellcheck source=../completions/pki.bash
    source "$LEGACY/completions/pki.bash"
    PKI_DIR="$WORK/modular/pki"
    complete_line() {
        read -ra COMP_WORDS <<<"$1"; [[ $1 == *" " ]] && COMP_WORDS+=("")
        COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); COMPREPLY=()
        _pki_completion
        printf '%s' "${COMPREPLY[*]}"
    }
    [ "$(complete_line "pki iss")" = "issue" ] || fail "completion: command"
    [ "$(complete_line "pki issue server --key ")" = "rsa2048 rsa3072 rsa4096 ed25519" ] \
        || fail "completion: key types"
    [ "$(complete_line "pki revoke ")" = "nas.smoke.lan root server-ca" ] \
        || fail "completion: issued certificates and CAs"
    echo "ok    completion"
)
