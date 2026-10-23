#!/usr/bin/env bash
# systemd_test.sh ARCHIVE UPDATE_BINARY – the whole systemd installation on a
# throwaway Linux machine with systemd (the CI job "install"), as root:
#
#  1. install.sh --archive ARCHIVE: enabled, not started; modes and owners
#  2. systemd-analyze verify, and security below 2.0 (the value goes to the
#     step summary)
#  3. a second run of the first installation changes nothing
#  4. init --stdin with throwaway values and the test CA, systemctl start,
#     healthcheck, /healthz, the fingerprint in the journal, a CRL over the
#     public listener
#  5. update: UPDATE_BINARY packed into a second archive; install.sh makes a
#     backup (backup verify passes), swaps the binary, the service is
#     healthy again with the new version
#  6. one more run changes nothing
#
# It refuses to run where MyOwnPKI is installed already – it is not a tool for
# a real machine.
set -euo pipefail

archive=${1:?usage: systemd_test.sh ARCHIVE UPDATE_BINARY}
update_bin=${2:?usage: systemd_test.sh ARCHIVE UPDATE_BINARY}
root=$(cd "$(dirname "$0")/../.." && pwd)
install_sh=$root/deploy/install.sh
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
conf=/etc/myownpki/config.yaml
bin=/usr/local/bin/myownpki

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if [ -e /etc/myownpki ] || [ -e /var/lib/myownpki ] || [ -e "$bin" ]; then
	echo "MyOwnPKI is installed on this machine – systemd_test.sh only runs on a throwaway one" >&2
	exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

step() { printf '\n=== %s\n' "$*"; }
fail() {
	printf '::error::%s\n' "$*"
	exit 1
}
svc() { runuser -u myownpki -- env -i PATH=/usr/bin:/bin "$@"; }
healthy() {
	for _ in $(seq 1 30); do
		if svc "$bin" healthcheck --config "$conf" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	return 1
}
# state is a fingerprint of everything install.sh manages.
state() {
	{
		stat -c '%n %a %U:%G %Y %s' "$bin" /etc/systemd/system/myownpki.service /etc/myownpki "$conf" /var/lib/myownpki
		sha256sum "$bin" /etc/systemd/system/myownpki.service "$conf"
		getent passwd myownpki
		systemctl is-enabled myownpki.service
		ls -la /etc/systemd/system/myownpki.service.d 2>/dev/null || true
		ls -la /var/backups/myownpki 2>/dev/null || true
	} | sha256sum
}

step "1. First installation from $(basename "$archive")"
bash "$install_sh" --archive "$archive" | tee "$tmp/run1.log"
grep -q "runuser -u myownpki -- $bin init --config $conf" "$tmp/run1.log" || fail "no next steps in the output"
grep -q 'admin.allowed_networks: "127.0.0.1' "$tmp/run1.log" || fail "the result does not show the config values"
[ "$(systemctl is-enabled myownpki.service)" = enabled ] || fail "the service is not enabled"
if systemctl is-active --quiet myownpki.service; then fail "the first installation started the service"; fi
[ "$(stat -c '%a %U' /var/lib/myownpki)" = "700 myownpki" ] || fail "data directory: $(stat -c '%a %U' /var/lib/myownpki)"
[ "$(stat -c '%a %U:%G' "$conf")" = "640 root:myownpki" ] || fail "config: $(stat -c '%a %U:%G' "$conf")"
[ "$(stat -c '%a %U' "$bin")" = "755 root" ] || fail "binary: $(stat -c '%a %U' "$bin")"

step "2. systemd-analyze verify and security"
systemd-analyze verify /etc/systemd/system/myownpki.service
systemd-analyze security --no-pager myownpki.service | tee "$tmp/security.txt"
exposure=$(sed -n 's/.*Overall exposure level for myownpki.service: \([0-9.]*\).*/\1/p' "$tmp/security.txt")
[ -n "$exposure" ] || fail "no overall exposure in the output of systemd-analyze security"
{
	printf '### systemd-analyze security myownpki.service\n\nOverall exposure: **%s** (systemd %s)\n\n' \
		"$exposure" "$(systemctl --version | awk 'NR == 1 { print $2 }')"
	printf '<details><summary>All checks</summary>\n\n```text\n'
	cat "$tmp/security.txt"
	printf '```\n\n</details>\n\n'
} >>"$summary"
awk -v e="$exposure" 'BEGIN { exit !(e < 2.0) }' || fail "exposure $exposure – it must stay below 2.0"

step "3. A second run of the first installation changes nothing"
before=$(state)
bash "$install_sh" --archive "$archive" | tee "$tmp/run2.log"
grep -q 'Changes:   none' "$tmp/run2.log" || fail "the second run reported changes"
[ "$before" = "$(state)" ] || fail "the second run changed files"

step "4. init with throwaway values, start, health"
pass=$(openssl rand -hex 24)
password=$(openssl rand -hex 16)
if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::add-mask::%s\n::add-mask::%s\n' "$pass" "$password"; fi
printf '%s\n%s\n' "$pass" "$password" |
	svc "$bin" init --stdin --config "$conf" --admin-user ci-admin \
		--recovery-key-file /var/lib/myownpki/ci-recovery.txt --otpauth-file /var/lib/myownpki/ci-otpauth.txt \
		--with-ca --ca-base-url http://127.0.0.1:8080 >"$tmp/init.log" 2>&1 ||
	{ grep -v -i 'recovery\|secret\|otpauth' "$tmp/init.log" >&2; fail "init failed"; }
unset pass password
rm -f /var/lib/myownpki/ci-recovery.txt /var/lib/myownpki/ci-otpauth.txt
systemctl start myownpki.service
healthy || fail "not healthy after the start"
[ "$(curl -fsS --insecure https://127.0.0.1:9443/healthz)" = ok ] || fail "/healthz"
journalctl -u myownpki.service -o cat | grep -q fingerprint_sha256 || fail "no fingerprint in the journal"
curl -fsS -o "$tmp/crl.der" http://127.0.0.1:8080/crl/issuing/1.crl
openssl crl -inform DER -in "$tmp/crl.der" -noout -issuer || fail "the public listener served no CRL"

step "5. Update with a second build"
mkdir "$tmp/old" "$tmp/update"
tar -xzf "$archive" -C "$tmp/old"
new_version=$("$update_bin" --version | awk '{ print $2 }')
install -m 0755 "$update_bin" "$tmp/old/myownpki"
update_archive=$tmp/update/myownpki_${new_version#v}_linux_$(dpkg --print-architecture).tar.gz
tar -czf "$update_archive" -C "$tmp/old" .
(cd "$tmp/update" && sha256sum "$(basename "$update_archive")" >checksums.txt)
bash "$install_sh" --archive "$update_archive" | tee "$tmp/run3.log"
mapfile -t backups < <(find /var/backups/myownpki -mindepth 1 -maxdepth 1 -type d)
[ ${#backups[@]} -eq 1 ] || fail "want one backup, found: ${backups[*]:-none}"
svc "$bin" backup verify "${backups[0]}" || fail "backup verify ${backups[0]}"
systemctl is-active --quiet myownpki.service || fail "not running after the update"
healthy || fail "not healthy after the update"
[ "$("$bin" --version | awk '{ print $2 }')" = "$new_version" ] || fail "the binary is not $new_version"
[ -x "$bin.previous" ] || fail "no previous binary"
printf 'Update: backup %s, now %s, healthy.\n\n' "${backups[0]}" "$new_version" >>"$summary"

step "6. Another run changes nothing"
before=$(state)
bash "$install_sh" --archive "$update_archive" | tee "$tmp/run4.log"
grep -q 'Changes:   none' "$tmp/run4.log" || fail "the run after the update reported changes"
[ "$before" = "$(state)" ] || fail "the run after the update changed files"

step "All checks passed"
