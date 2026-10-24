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
	version=$DEFAULT_VERSION archive='' opt_tls_names='' opt_admin_listen='' opt_allowed='' port80=false config_opts=false
	opt_acme='' opt_acme_ca='' acme_port='' low_ports=false
}
# rc_of CMD…: run CMD with set -e in effect inside it (not as a condition,
# where bash switches set -e off) and put its exit code into rc.
rc_of() {
	set +e
	"$@"
	rc=$?
	set -e
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
check "--public-port-80: low ports" "$low_ports" "true"

# --acme: ACME with its own TLS – three more keys, the port of the URL, the
# low-ports drop-in only below 1024.
reset_opts
parse_args --acme https://pki.u.lab/acme/
defaults
check "--acme: base URL without the trailing slash" "$opt_acme" "https://pki.u.lab/acme"
check "--acme: port 443, low ports, CA issuing" "$acme_port $low_ports $opt_acme_ca" "443 true issuing"
render_config "$root/deploy/config.example.yaml" >"$tmp/acme.yaml"
check "--acme: changed lines (3 header + 6 keys; public.listen stays :8080)" "$(diff "$root/deploy/config.example.yaml" "$tmp/acme.yaml" | grep -c '^>')" "9"
check "--acme: acme.base_url" "$(config_value "$tmp/acme.yaml" acme base_url)" "https://pki.u.lab/acme"
check "--acme: acme.listen" "$(config_value "$tmp/acme.yaml" acme listen)" ":443"
check "--acme: acme.tls_issuer" "$(config_value "$tmp/acme.yaml" acme tls_issuer)" "issuing"
check "--acme: admin.listen still set" "$(config_value "$tmp/acme.yaml" admin listen)" "0.0.0.0:9443"
sed "s|^data_dir: .*|data_dir: $data|" "$tmp/acme.yaml" >"$tmp/acme-check.yaml"
if "$bin" config check --config "$tmp/acme-check.yaml" >"$tmp/check.out" 2>&1; then
	echo "ok   config check of the --acme config"
else
	echo "FAIL config check of the --acme config:"
	cat "$tmp/check.out"
	fail=1
fi
reset_opts
parse_args --acme https://172.20.23.20:8443 --acme-ca lab-issuing
check "--acme on 8443: no low ports, own CA" "$acme_port $low_ports $opt_acme_ca" "8443 false lab-issuing"
# shellcheck disable=SC2329 # called through refused
fresh_parse() { reset_opts && parse_args "$@"; }
refused fresh_parse --acme http://pki.u.lab/acme
refused fresh_parse --acme 'https://pki.u.lab/acme"x'
refused fresh_parse --acme https://pki.u.lab:99999/acme
refused fresh_parse --acme https://pki.u.lab/acme --acme-ca 'Issuing CA'
refused fresh_parse --acme-ca issuing

# low-ports.conf and its old name public-port-80.conf grant the same.
settings() { grep -v -e '^#' -e '^$' "$1"; }
check "low-ports.conf = public-port-80.conf (without comments)" \
	"$(settings "$root/deploy/systemd/low-ports.conf" | tr '\n' ' ')" "$(settings "$root/deploy/systemd/public-port-80.conf" | tr '\n' ' ')"

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

# --archive: a relative path still works after main() changed to /, from any
# working directory; a missing file is named as it was given.
a=myownpki_9.9.9_linux_amd64.tar.gz
mkdir -p "$tmp/rel/dl" "$tmp/rel/elsewhere"
cp "$f" "$tmp/rel/dl/$a"
printf '%s  %s\n' "$h" "$a" >"$tmp/rel/dl/checksums.txt"
want=$(cd "$tmp/rel/dl" && pwd -P)/$a
check "--archive DIR/FILE" "$(cd "$tmp/rel" && reset_opts && parse_args --archive "dl/$a" && echo "$archive")" "$want"
check "--archive ./FILE" "$(cd "$tmp/rel/dl" && reset_opts && parse_args --archive "./$a" && echo "$archive")" "$want"
check "--archive ../DIR/FILE, then fetch from /" "$(
	cd "$tmp/rel/elsewhere" && reset_opts && parse_args --archive "../dl/$a" &&
		cd / && work=$tmp/rel/work && mkdir "$work" && arch() { echo amd64; } && fetch 2>/dev/null &&
		cmp "$archive_file" "$want" && echo "$version"
)" "9.9.9"
check "--archive missing: the path as given" "$(cd "$tmp/rel/elsewhere" && reset_opts && (parse_args --archive "dl/$a") 2>&1 || true)" \
	"install.sh: --archive: no such file: dl/$a"
refused parse_args --archive "$tmp/rel/dl"

# put and swap_binary: a failed copy never passes as done. The tests run as
# a normal user: install without -o/-g, and directories with mkdir (Git Bash
# can't chmod 0700 under /tmp).
install() {
	local args=() dir=false
	while [ $# -gt 0 ]; do
		case $1 in -o | -g) shift 2 ;; -d) dir=true; shift ;; *) args+=("$1"); shift ;; esac
	done
	if $dir; then mkdir -p "${args[-1]}"; else command install "${args[@]}"; fi
}
old=$tmp/old-myownpki
printf '#!/bin/sh\necho "myownpki v0.0.1-old (commit test)"\n' >"$old"
chmod 0755 "$old"
old_version=v0.0.1-old
new_version=$("$bin" --version | awk '{ print $2 }')
work=$tmp/work
mkdir -p "$work/x"
cp "$bin" "$work/x/myownpki"

out=$( (
	install() { return 1; }
	if put "$old" "$tmp/never/myownpki" 0755 root root; then :; fi
	echo reached
) 2>&1) || true
check "put: install fails in a condition → stops, nothing written" "$out $([ -e "$tmp/never/myownpki" ] && echo written)" \
	"install.sh: cannot create $tmp/never "
mkdir -p "$tmp/keep"
cp "$old" "$tmp/keep/myownpki"
out=$( (
	mv() { return 1; }
	put "$work/x/myownpki" "$tmp/keep/myownpki" 0755 root root || true
	echo reached
) 2>&1) || true
check "put: mv fails behind || true → stops, old file kept" "$out $("$tmp/keep/myownpki" --version | awk '{ print $2 }')" \
	"install.sh: cannot replace $tmp/keep/myownpki $old_version"

# A fresh directory per case: Windows keeps a binary that just ran locked.
old_at() { BIN=$tmp/$1/myownpki && mkdir -p "$tmp/$1" && cp "$old" "$BIN"; }
old_at swap1
rc_of swap_binary
check "swap_binary: new binary in place" "$rc $put_changed $("$BIN" --version | awk '{ print $2 }')" "0 true $new_version"
rc_of swap_binary
check "swap_binary again: nothing to copy, still ok" "$rc $put_changed" "0 false"
old_at swap2
new_version=v9.9.9
rc_of swap_binary 2>/dev/null
new_version=$("$bin" --version | awk '{ print $2 }')
check "swap_binary: the binary reports another version → refused" "$rc" "1"

# update() with the service faked: `systemctl restart` starts the file at $BIN
# (copied to $upd/running) – or, with "stale", the old binary keeps running,
# as if the unit started another file. healthy answers as told. With
# "bad-copy", put leaves a file that is not the new binary. Sets rc; update
# runs with set -e in effect, as in install.sh.
runs=0
update_run() { # STARTS HEALTHY [bad-copy]
	local starts=$1 health=$2 copy=${3:-}
	runs=$((runs + 1))
	upd=$tmp/upd$runs
	mkdir -p "$upd"
	cp "$old" "$upd/myownpki"
	cp "$old" "$upd/running"
	set +e
	(
		set -e
		BIN=$upd/myownpki BACKUPS=$upd/backups CONF=$upd/config.yaml
		as_service() { :; }
		install_units() { unit_changed=false; }
		systemctl() { if [ "$1" = restart ] && [ "$starts" = new ]; then cp "$BIN" "$upd/running"; fi; }
		healthy() { [ "$health" = yes ]; }
		running_version() { "$upd/running" --version | awk '{ print $2 }'; }
		if [ "$copy" = bad-copy ]; then put() { cp "$old" "$2"; put_changed=true; }; fi
		update
	) >"$upd.out" 2>&1
	rc=$?
	set -e
}
installed() { "$upd/myownpki" --version | awk '{ print $2 }'; }
said() { if grep -qF "$1" "$upd.out"; then echo yes; else echo "no: $(tr '\n' ' ' <"$upd.out")"; fi; }

update_run new yes
check "update: healthy and runs the new version" "$rc $(installed)" "0 $new_version"
check "update: says so" "$(said "Healthy, running $new_version")" "yes"
update_run stale yes
check "update: healthy, but the old binary runs → rolled back, error" "$rc $(installed)" "1 $old_version"
check "update: names the version that runs" "$(said "the service runs $old_version, not $new_version")" "yes"
check "update: rolled back, healthy again" "$(said "rolled back to $old_version, which is healthy again")" "yes"
update_run new no
check "update: not healthy → rolled back, error, restore commands" "$rc $(installed) $(said "restore $upd/backups/")" "1 $old_version yes"
update_run new yes bad-copy
check "update: the copy is not the new binary → rolled back, error" "$rc $(installed)" "1 $old_version"
check "update: says why" "$(said "the new binary was not installed")" "yes"

# Options that must not reach the config.
refused parse_args --tls-names 'a"b'
refused parse_args --tls-names 'a\b'
refused parse_args --admin-listen 9443
refused parse_args --allowed-networks '10.0.0.0/8;id'
refused parse_args --version 1.2
refused parse_args --bogus

exit $fail
