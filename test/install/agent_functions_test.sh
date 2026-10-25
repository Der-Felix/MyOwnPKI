#!/usr/bin/env bash
# Non-root checks of deploy/install-agent.sh; the agent CI job runs them.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=deploy/install-agent.sh
source deploy/install-agent.sh

fail() { printf 'agent_functions_test: %s\n' "$*" >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/agent-install-functions.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/work" "$tmp/www"
printf 'root test fixture\n' >"$tmp/root.pem"
printf 'join token test fixture\n' >"$tmp/token"
printf 'archive test fixture\n' >"$tmp/myownpki-agent_0.3.0_linux_amd64.tar.gz"
(cd "$tmp" && sha256sum myownpki-agent_0.3.0_linux_amd64.tar.gz >checksums.txt)
verify_checksum "$tmp/myownpki-agent_0.3.0_linux_amd64.tar.gz" "$tmp/checksums.txt" || fail "valid checksum refused"
printf 'changed archive\n' >>"$tmp/myownpki-agent_0.3.0_linux_amd64.tar.gz"
if (verify_checksum "$tmp/myownpki-agent_0.3.0_linux_amd64.tar.gz" "$tmp/checksums.txt"); then
	fail "changed archive accepted"
fi

parse_args --server https://pki.homelab.lan:8444 --ca-bundle "$tmp/root.pem" --token-file "$tmp/token" --webroot "$tmp/www"
work=$tmp/work
ROOT=/etc/myownpki-agent/root.pem
DATA=/var/lib/myownpki-agent
render_config proxy1.homelab.lan
for expected in 'server: "https://pki.homelab.lan:8444"' 'hostname: "proxy1.homelab.lan"' 'challenge: webroot' "webroot: \"$tmp/www\"" "paths: [\"$tmp/www\"]"; do
	grep -Fq -- "$expected" "$work/agent.yaml" || fail "webroot config lacks $expected"
done
[ -f "$token_file" ] || fail "parse_args removed the token"

webroot=
render_config proxy1.homelab.lan
grep -Fq 'challenge: standalone' "$work/agent.yaml" || fail "standalone challenge missing"
grep -Fqx 'paths: []' "$work/agent.yaml" || fail "standalone paths are not empty"
if (parse_args --server http://pki.homelab.lan:8444 --ca-bundle "$tmp/root.pem"); then
	fail "plain HTTP server accepted"
fi
if (parse_args --server https://pki.homelab.lan:8444 --ca-bundle "$tmp/missing.pem"); then
	fail "missing CA bundle accepted"
fi
printf 'install-agent.sh function tests passed\n'
