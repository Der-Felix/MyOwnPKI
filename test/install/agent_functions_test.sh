#!/usr/bin/env bash
# Non-root checks of the deprecated install-agent.sh compatibility wrapper.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=deploy/install-agent.sh
source deploy/install-agent.sh

fail() { printf 'agent_functions_test: %s\n' "$*" >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/agent-install-functions.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf 'archive test fixture\n' >"$tmp/myownpki-agent_0.3.1_linux_amd64.tar.gz"
(cd "$tmp" && sha256sum myownpki-agent_0.3.1_linux_amd64.tar.gz >checksums.txt)
verify_checksum "$tmp/myownpki-agent_0.3.1_linux_amd64.tar.gz" "$tmp/checksums.txt" || fail "valid checksum refused"
printf 'changed archive\n' >>"$tmp/myownpki-agent_0.3.1_linux_amd64.tar.gz"
if (verify_checksum "$tmp/myownpki-agent_0.3.1_linux_amd64.tar.gz" "$tmp/checksums.txt"); then
	fail "changed archive accepted"
fi

[ "$DEFAULT_VERSION" = 0.3.1 ] || fail "wrong default version: $DEFAULT_VERSION"
parse_args --server https://pki.homelab.lan:8444 --ca-bundle "$tmp/root.pem" \
	--root-sha256 AA:BB --token-file "$tmp/token" --webroot /var/www/html --low-ports
cat >"$tmp/agent" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$CAPTURE"
EOF
chmod 0755 "$tmp/agent"
BIN=$tmp/agent
CAPTURE=$tmp/forwarded
export CAPTURE
forward_setup
mapfile -t forwarded <"$CAPTURE"
expected=(setup --server https://pki.homelab.lan:8444 --ca-bundle "$tmp/root.pem" --root-sha256 AA:BB --token-file "$tmp/token" --webroot /var/www/html --low-ports)
[ "${forwarded[*]}" = "${expected[*]}" ] || fail "wrong setup forwarding: ${forwarded[*]}"
if (root_sha256=; parse_args --server https://pki.homelab.lan:8444 --ca-bundle "$tmp/root.pem"); then
	fail "missing root fingerprint accepted"
fi
for removed in render_config ensure_config install_units enroll ensure_dirs put; do
	if declare -F "$removed" >/dev/null; then
		fail "legacy setup implementation remains in wrapper: $removed"
	fi
done
printf 'install-agent.sh wrapper function tests passed\n'
