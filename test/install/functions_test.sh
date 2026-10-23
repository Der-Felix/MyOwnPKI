#!/usr/bin/env bash
# functions_test.sh BIN – tests of the parts of deploy/install.sh that need
# neither root nor systemd: options, the defaults from this machine, the
# generated config (checked with `BIN config check`), reading config values
# and the checksum check. Runs on Linux (CI job "install") and in Git Bash.
# The whole installation is tested by the CI job itself.
set -euo pipefail

bin=${1:?usage: functions_test.sh MYOWNPKI_BINARY}
root=$(cd "$(dirname "$0")/../.." && pwd)
# shellcheck source=deploy/install.sh
source "$root/deploy/install.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: got [$2], want [$3]"
		fail=1
	fi
}
refused() {
	if ("$@") >/dev/null 2>&1; then
		echo "FAIL accepted: $*"
		fail=1
	else
		echo "ok   refused: $*"
	fi
}
reset_opts() {
	version=$DEFAULT_VERSION opt_tls_names='' opt_admin_listen='' opt_allowed='' port80=false config_opts=false
}

# "This machine": two IPv4 addresses and one IPv6 address.
own_addresses() { printf '%s\n' 172.20.23.20 10.9.8.7 2001:db8::20; }
own_name() { echo pki.u.lab; }

reset_opts
parse_args
defaults
check "default tls_names" "$tls_names" "pki.u.lab, 172.20.23.20, 10.9.8.7, 2001:db8::20"
check "default admin.listen" "$admin_listen" "0.0.0.0:9443"
check "default allowed_networks: loopback for the health check, the /24s" "$allowed" "127.0.0.1, 172.20.23.0/24, 10.9.8.0/24"
check "default public.listen" "$public_listen" ":8080"
check "no config options" "$config_opts" "false"

reset_opts
parse_args --admin-listen "[::]:9443"
defaults
check "[::] listen: ::1 for the health check" "$allowed" "::1, 172.20.23.0/24, 10.9.8.0/24"

reset_opts
parse_args --version v0.2.1 --tls-names "pki.u.lab, 172.20.23.20" --admin-listen 172.20.23.20:9443 \
	--allowed-networks "192.168.5.0/24,10.0.0.0/8" --public-port-80
defaults
check "--version without v" "$version" "0.2.1"
check "--tls-names" "$tls_names" "pki.u.lab, 172.20.23.20"
check "--allowed-networks plus the listen address" "$allowed" "172.20.23.20, 192.168.5.0/24, 10.0.0.0/8"
check "--public-port-80" "$public_listen" ":80"
check "config options seen" "$config_opts" "true"

# The generated config: exactly the four keys changed, and config check passes.
render_config "$root/deploy/config.example.yaml" >"$tmp/config.yaml"
check "changed lines (3 header + 4 keys)" "$(diff "$root/deploy/config.example.yaml" "$tmp/config.yaml" | grep -c '^>')" "7"
check "admin.listen" "$(config_value "$tmp/config.yaml" admin listen)" "172.20.23.20:9443"
check "admin.allowed_networks" "$(config_value "$tmp/config.yaml" admin allowed_networks)" "172.20.23.20, 192.168.5.0/24, 10.0.0.0/8"
check "public.listen" "$(config_value "$tmp/config.yaml" public listen)" ":80"
check "acme.listen untouched" "$(config_value "$tmp/config.yaml" acme listen)" "127.0.0.1:8081"
check "data_dir" "$(config_value "$tmp/config.yaml" "" data_dir)" "/var/lib/myownpki"
# On Windows (Git Bash) /var/lib/myownpki is not absolute: check with a local one.
data=$(cd "$tmp" && (pwd -W 2>/dev/null || pwd))/data
sed "s|^data_dir: .*|data_dir: $data|" "$tmp/config.yaml" >"$tmp/check.yaml"
if "$bin" config check --config "$tmp/check.yaml" >"$tmp/check.out" 2>&1; then
	echo "ok   config check of the generated config"
else
	echo "FAIL config check of the generated config:"
	cat "$tmp/check.out"
	fail=1
fi
sed 's/^  allowed_networks:.*/  allowed: ""/' "$root/deploy/config.example.yaml" >"$tmp/drift.yaml"
refused render_config "$tmp/drift.yaml"

# Checksums.
f=$tmp/myownpki_9.9.9_linux_amd64.tar.gz
printf 'archive' >"$f"
h=$(sha256sum "$f" | awk '{ print $1 }')
printf '%s  myownpki_9.9.9_linux_amd64.tar.gz\n%s  install.sh\n' "$h" "$h" >"$tmp/ok"
if (verify_checksum "$f" "$tmp/ok"); then echo "ok   checksum matches"; else echo "FAIL checksum"; fail=1; fi
printf '%s  myownpki_9.9.9_linux_amd64.tar.gz\n' "${h%?}0" >"$tmp/bad"
[ "${h%?}0" != "$h" ] || printf '%s  myownpki_9.9.9_linux_amd64.tar.gz\n' "${h%?}1" >"$tmp/bad"
refused verify_checksum "$f" "$tmp/bad"
printf '%s  install.sh\n' "$h" >"$tmp/missing"
refused verify_checksum "$f" "$tmp/missing"
cat "$tmp/ok" "$tmp/ok" >"$tmp/twice"
refused verify_checksum "$f" "$tmp/twice"

# Options that must not reach the config.
refused parse_args --tls-names 'a"b'
refused parse_args --tls-names 'a\b'
refused parse_args --admin-listen 9443
refused parse_args --allowed-networks '10.0.0.0/8;id'
refused parse_args --version 1.2
refused parse_args --bogus

exit $fail
