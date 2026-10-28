#!/usr/bin/env bash
# systemd_test.sh ARCHIVE UPDATE_BINARY – the whole systemd installation on a
# throwaway Linux machine with systemd (the CI job "install"), as root:
#
#  1. install.sh --archive ARCHIVE --acme https://acme.ci.test/acme: enabled,
#     not started; modes and owners; the ACME keys and the low-ports drop-in;
#     the backup timer enabled, /var/backups/myownpki 0700
#  2. systemd-analyze verify, and security below 2.0 – the service with the
#     drop-in, and the backup service (the values go to the step summary)
#  3. a second run of the first installation changes nothing
#  4. init --stdin with throwaway values and the test CA, systemctl start,
#     healthcheck, /healthz, the fingerprint in the journal, a CRL over the
#     public listener; ACME on :443 serves its bootstrap certificate (sealed),
#     then an unseal through the API (password + TOTP) issues its own, and a
#     client that trusts only the root reads the directory
#  5. an update whose service comes back healthy but still runs the old
#     binary (a test drop-in starts myownpki.previous) is rolled back and
#     ends with an error – the health check alone would pass it
#  6. update: UPDATE_BINARY packed into a second archive; install.sh makes a
#     backup (backup verify passes), swaps the binary, the service is
#     healthy again and runs the new version – and, sealed after the
#     restart, ACME still serves the issued certificate
#  7. one more run changes nothing
#  8. the daily backup: the backup service run by hand writes a verified
#     scheduled backup; with --backup-keep 2 a second run deletes exactly
#     the older scheduled backups – never the update backups or anything
#     else; --no-backup-timer switches the timer off, and the next run
#     without it leaves it off
#
# ARCHIVE stays relative in CI on purpose: install.sh changes to / before it
# reads it.
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
# ACME with its own TLS on :443 (install.sh --acme); the name resolves to
# loopback through curl --resolve only.
acme_url=https://acme.ci.test/acme
acme_resolve=acme.ci.test:443:127.0.0.1
lowports=/etc/systemd/system/myownpki.service.d/low-ports.conf

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
version_of() { "$1" --version | awk '{ print $2 }'; }
# running is the version of the binary the service runs now.
running() { version_of "/proc/$(systemctl show --property MainPID --value myownpki.service)/exe"; }
healthy() {
	for _ in $(seq 1 30); do
		if svc "$bin" healthcheck --config "$conf" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	return 1
}
# totp BASE32-SECRET: the current code (RFC 6238: SHA-1, 6 digits, 30 s).
totp() {
	local s=$1 key c b='' h off i
	while [ $(( ${#s} % 8 )) -ne 0 ]; do s="$s="; done
	key=$(printf '%s' "$s" | base32 -d | od -An -tx1 | tr -d ' \n')
	c=$(printf '%016x' $(( $(date +%s) / 30 )))
	for (( i = 0; i < 16; i += 2 )); do b+="\\x${c:i:2}"; done
	# shellcheck disable=SC2059 # the format is the counter's eight bytes
	h=$(printf "$b" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -binary | od -An -tx1 | tr -d ' \n')
	off=$(( 0x${h:39:1} ))
	printf '%06d\n' $(( (0x${h:$(( off * 2 )):8} & 0x7fffffff) % 1000000 ))
}
# api METHOD PATH [JSON]: the REST API of the admin listener with a cookie
# jar and the CSRF token of the last answer, like a browser; the answer goes
# to $tmp/api.json. Not in $( ): the token must stay in this shell. The
# bootstrap certificate is self-signed: --insecure, as for /healthz below.
csrf=
api() {
	local tok
	# The body comes on stdin (printf is a builtin): no secret in the
	# process list.
	printf '%s' "${3:-}" | curl -fsS --noproxy '*' --insecure -b "$tmp/jar" -c "$tmp/jar" -X "$1" -H "X-CSRF-Token: $csrf" \
		-H 'Content-Type: application/json' ${3:+--data-binary @-} -o "$tmp/api.json" "https://127.0.0.1:9443/api/v1$2" || return 1
	tok=$(sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' "$tmp/api.json")
	if [ -n "$tok" ]; then csrf=$tok; fi
}
# acme_subject: the subject of what the ACME listener serves.
acme_subject() {
	openssl s_client -connect 127.0.0.1:443 -servername acme.ci.test </dev/null 2>/dev/null | openssl x509 -noout -subject -nameopt RFC2253
}
# acme_directory: the directory over TLS, trusting only the test root.
acme_directory() {
	curl -fsS --noproxy '*' --cacert "$tmp/root.pem" --resolve "$acme_resolve" "$acme_url/directory"
}
# state is a fingerprint of everything install.sh manages.
state() {
	{
		stat -c '%n %a %U:%G %Y %s' "$bin" /etc/systemd/system/myownpki.service /etc/myownpki "$conf" /var/lib/myownpki \
			/etc/systemd/system/myownpki-backup.service /etc/systemd/system/myownpki-backup.timer
		sha256sum "$bin" /etc/systemd/system/myownpki.service "$conf" /etc/systemd/system/myownpki-backup.service /etc/systemd/system/myownpki-backup.timer
		getent passwd myownpki
		systemctl is-enabled myownpki.service myownpki-backup.timer
		ls -la /etc/systemd/system/myownpki-backup.service.d 2>/dev/null || true
		ls -la /etc/systemd/system/myownpki.service.d 2>/dev/null || true
		ls -la /var/backups/myownpki 2>/dev/null || true
	} | sha256sum
}

step "1. First installation from $(basename "$archive"), with ACME on its own TLS"
bash "$install_sh" --archive "$archive" --acme "$acme_url" | tee "$tmp/run1.log"
grep -q "runuser -u myownpki -- $bin init --config $conf" "$tmp/run1.log" || fail "no next steps in the output"
grep -q 'admin.allowed_networks: "127.0.0.1' "$tmp/run1.log" || fail "the result does not show the config values"
grep -q 'acme.listen:            ":443"' "$tmp/run1.log" || fail "the result does not show the ACME values"
grep -q "Low ports: drop-in $lowports" "$tmp/run1.log" || fail "no low-ports drop-in"
[ "$(stat -c '%a %U' "$lowports")" = "644 root" ] || fail "drop-in: $(stat -c '%a %U' "$lowports")"
svc "$bin" config check --config "$conf" >/dev/null || fail "the written config does not pass config check"
[ "$(systemctl is-enabled myownpki.service)" = enabled ] || fail "the service is not enabled"
if systemctl is-active --quiet myownpki.service; then fail "the first installation started the service"; fi
[ "$(stat -c '%a %U' /var/lib/myownpki)" = "700 myownpki" ] || fail "data directory: $(stat -c '%a %U' /var/lib/myownpki)"
[ "$(stat -c '%a %U:%G' "$conf")" = "640 root:myownpki" ] || fail "config: $(stat -c '%a %U:%G' "$conf")"
[ "$(stat -c '%a %U' "$bin")" = "755 root" ] || fail "binary: $(stat -c '%a %U' "$bin")"
[ "$(systemctl is-enabled myownpki-backup.timer)" = enabled ] || fail "the backup timer is not enabled"
systemctl is-active --quiet myownpki-backup.timer || fail "the backup timer is not active"
[ "$(stat -c '%a %U' /var/backups/myownpki)" = "700 myownpki" ] || fail "backup directory: $(stat -c '%a %U' /var/backups/myownpki)"
grep -q 'Backups:   daily into /var/backups/myownpki, the newest 14 kept' "$tmp/run1.log" || fail "the result does not show the backup timer"

step "2. systemd-analyze verify and security"
systemd-analyze verify /etc/systemd/system/myownpki.service /etc/systemd/system/myownpki-backup.service /etc/systemd/system/myownpki-backup.timer
for unit in myownpki.service myownpki-backup.service; do
	systemd-analyze security --no-pager "$unit" | tee "$tmp/security.txt"
	exposure=$(sed -n "s/.*Overall exposure level for $unit: \([0-9.]*\).*/\1/p" "$tmp/security.txt")
	[ -n "$exposure" ] || fail "no overall exposure in the output of systemd-analyze security $unit"
	{
		printf '### systemd-analyze security %s\n\nOverall exposure: **%s** (systemd %s)\n\n' \
			"$unit" "$exposure" "$(systemctl --version | awk 'NR == 1 { print $2 }')"
		printf '<details><summary>All checks</summary>\n\n```text\n'
		cat "$tmp/security.txt"
		printf '```\n\n</details>\n\n'
	} >>"$summary"
	awk -v e="$exposure" 'BEGIN { exit !(e < 2.0) }' || fail "$unit: exposure $exposure – it must stay below 2.0"
done

step "3. A second run of the first installation changes nothing"
before=$(state)
bash "$install_sh" --archive "$archive" --acme "$acme_url" | tee "$tmp/run2.log"
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
# The TOTP secret of ci-admin, for the sign-in below (the first sign-in
# confirms it).
secret=$(sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p' /var/lib/myownpki/ci-otpauth.txt | head -n 1)
[ -n "$secret" ] || fail "no TOTP secret in the otpauth file"
if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::add-mask::%s\n' "$secret"; fi
rm -f /var/lib/myownpki/ci-recovery.txt /var/lib/myownpki/ci-otpauth.txt
systemctl start myownpki.service
healthy || fail "not healthy after the start"
[ "$(curl -fsS --insecure https://127.0.0.1:9443/healthz)" = ok ] || fail "/healthz"
journalctl -u myownpki.service -o cat | grep -q fingerprint_sha256 || fail "no fingerprint in the journal"
curl -fsS -o "$tmp/crl.der" http://127.0.0.1:8080/crl/issuing/1.crl
openssl crl -inform DER -in "$tmp/crl.der" -noout -issuer || fail "the public listener served no CRL"
curl -fsS http://127.0.0.1:8080/ca/root/1.crt | openssl x509 -inform DER -out "$tmp/root.pem" || fail "no root certificate on the public listener"

step "4b. ACME with its own TLS: bootstrap while sealed, its own certificate after the unseal"
subject=$(acme_subject)
[[ $subject == *"CN=MyOwnPKI ACME (bootstrap)"* ]] || fail "sealed: the ACME listener serves $subject"
if acme_directory >/dev/null 2>&1; then fail "a client trusted the ACME bootstrap certificate"; fi
api POST /auth/login "{\"username\":\"ci-admin\",\"password\":\"$password\"}" || fail "sign-in"
api POST /auth/totp "{\"code\":\"$(totp "$secret")\"}" || fail "second factor"
api POST /system/unseal "{\"passphrase\":\"$pass\"}" || fail "unseal through the API"
unset pass password secret
grep -q '"sealed":false' "$tmp/api.json" || fail "still sealed: $(cat "$tmp/api.json")"
acme_directory | tee "$tmp/directory.json"
grep -q "\"newOrder\":\"$acme_url/new-order\"" "$tmp/directory.json" || fail "no ACME directory over TLS with the root as trust anchor"
subject=$(acme_subject)
[[ $subject == "subject=CN=acme.ci.test" ]] || fail "unsealed: the ACME listener serves $subject"
journalctl -u myownpki.service -o cat | grep '"msg":"TLS certificate issued"' | grep -q '"listener":"acme"' ||
	fail "no issuance in the journal"
[ "$(stat -c '%a %U' /var/lib/myownpki/tls/acme.key)" = "600 myownpki" ] || fail "ACME key: $(stat -c '%a %U' /var/lib/myownpki/tls/acme.key)"
# The dashboard reads the backup directory inside the sandbox of the main
# unit (no new rights): a backup that failed its check is a warning.
install -d -m 0700 -o myownpki -g myownpki /var/backups/myownpki/20200101T000000Z-unverified
curl -fsS --noproxy '*' --insecure -b "$tmp/jar" -o "$tmp/dashboard.html" https://127.0.0.1:9443/ || fail "dashboard"
grep -q 'failed its check and was kept as /var/backups/myownpki/20200101T000000Z-unverified' "$tmp/dashboard.html" ||
	fail "the dashboard does not show the failed backup check"
rmdir /var/backups/myownpki/20200101T000000Z-unverified
healthy || fail "not healthy after the unseal"

step "5. An update that leaves the old binary running is rolled back"
mkdir "$tmp/old" "$tmp/update"
tar -xzf "$archive" -C "$tmp/old"
old_version=$(version_of "$bin")
new_version=$(version_of "$update_bin")
[ "$old_version" != "$new_version" ] || fail "the update binary has the same version $old_version"
install -m 0755 "$update_bin" "$tmp/old/myownpki"
update_archive=$tmp/update/myownpki_${new_version#v}_linux_$(dpkg --print-architecture).tar.gz
tar -czf "$update_archive" -C "$tmp/old" .
# install.sh also stages the agent packages of exactly the update's version
# (both architectures, deb/rpm/tar.gz) and checks only names and checksums:
# the snapshot's packages under the update's version will do.
first_version=$(basename "$archive")
first_version=${first_version#myownpki_}
first_version=${first_version%_linux_*}
update_files=("$(basename "$update_archive")")
for agent_arch in amd64 arm64; do
	for agent_format in deb rpm tar.gz; do
		agent_name=myownpki-agent_${new_version#v}_linux_${agent_arch}.${agent_format}
		cp "$(dirname "$archive")/myownpki-agent_${first_version}_linux_${agent_arch}.${agent_format}" "$tmp/update/$agent_name" ||
			fail "the snapshot has no agent package for $agent_arch $agent_format"
		update_files+=("$agent_name")
	done
done
(cd "$tmp/update" && sha256sum -- "${update_files[@]}" >checksums.txt)
stale=/etc/systemd/system/myownpki.service.d/zz-ci-stale.conf
printf '[Service]\nExecStart=\nExecStart=%s.previous serve --config %s\n' "$bin" "$conf" >"$stale"
systemctl daemon-reload
if bash "$install_sh" --archive "$update_archive" >"$tmp/run3.log" 2>&1; then
	cat "$tmp/run3.log"
	fail "install.sh reported success although the service runs the old binary"
fi
cat "$tmp/run3.log"
grep -q "the service runs $old_version, not $new_version" "$tmp/run3.log" || fail "install.sh did not name the running version"
grep -q "rolled back to $old_version, which is healthy again" "$tmp/run3.log" || fail "no rollback"
[ "$(version_of "$bin")" = "$old_version" ] || fail "the binary is not $old_version after the rollback"
healthy || fail "not healthy after the rollback"
rm "$stale"
systemctl daemon-reload

step "6. Update with a second build"
bash "$install_sh" --archive "$update_archive" | tee "$tmp/run4.log"
# install.sh's update backups are <time>-<version> (a timer backup that ran
# meanwhile has no "-").
mapfile -t backups < <(find /var/backups/myownpki -mindepth 1 -maxdepth 1 -type d -name '*-*' | sort)
[ ${#backups[@]} -eq 2 ] || fail "want two update backups (step 5 and 6), found: ${backups[*]:-none}"
for b in "${backups[@]}"; do svc "$bin" backup verify "$b" || fail "backup verify $b"; done
systemctl is-active --quiet myownpki.service || fail "not running after the update"
healthy || fail "not healthy after the update"
[ "$(version_of "$bin")" = "$new_version" ] || fail "the binary is not $new_version"
[ "$(running)" = "$new_version" ] || fail "the service runs $(running), not $new_version"
[ -x "$bin.previous" ] || fail "no previous binary"
# Restarted, so sealed: ACME serves the issued certificate from its file.
acme_directory >/dev/null || fail "sealed after the update: the ACME listener lost its certificate"
[ -f "$lowports" ] || fail "the update removed the low-ports drop-in"
printf 'Update: backup %s, %s → %s, healthy and running.\n\n' "${backups[1]}" "$old_version" "$new_version" >>"$summary"

step "7. Another run changes nothing"
before=$(state)
bash "$install_sh" --archive "$update_archive" | tee "$tmp/run5.log"
grep -q 'Changes:   none' "$tmp/run5.log" || fail "the run after the update reported changes"
[ "$before" = "$(state)" ] || fail "the run after the update changed files"

step "8. The daily backup"
b=/var/backups/myownpki
systemctl start myownpki-backup.service || { journalctl -u myownpki-backup.service --no-pager -n 50; fail "the backup service failed"; }
mapfile -t scheduled < <(find "$b" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z' | sort)
[ ${#scheduled[@]} -eq 1 ] || fail "want one scheduled backup, found: ${scheduled[*]:-none}"
first=${scheduled[0]}
[ "$(stat -c '%a %U' "$first")" = "700 myownpki" ] || fail "scheduled backup: $(stat -c '%a %U' "$first")"
svc "$bin" backup verify "$first" >/dev/null || fail "backup verify $first"
journalctl -u myownpki-backup.service -o cat | grep -q "Verified: the backup passed every check" || fail "no verify in the journal"
# Three older scheduled backups, and what must stay: the two update
# backups, a directory with a scheduled name but no manifest, notes.
for n in 20200101T000000Z 20200102T000000Z 20200103T000000Z; do cp -a "$first" "$b/$n"; done
install -d -o myownpki -g myownpki "$b/20200104T000000Z" "$b/notes"
mapfile -t keep_these < <(find "$b" -mindepth 1 -maxdepth 1 \( -name '*-*' -o -name notes -o -name 20200104T000000Z \) | sort)
[ ${#keep_these[@]} -eq 4 ] || fail "test setup: ${keep_these[*]}"
bash "$install_sh" --archive "$update_archive" --backup-keep 2 | tee "$tmp/run6.log"
grep -q 'the newest 2 kept' "$tmp/run6.log" || fail "--backup-keep 2 not applied"
sleep 1 # the next backup gets another second, so another name
systemctl start myownpki-backup.service || { journalctl -u myownpki-backup.service --no-pager -n 50; fail "the second backup run failed"; }
mapfile -t left < <(find "$b" -mindepth 1 -maxdepth 1 | sort)
mapfile -t scheduled < <(find "$b" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z' ! -name '2020*' | sort)
[ ${#scheduled[@]} -eq 2 ] && [ "${scheduled[0]}" = "$first" ] || fail "want the two runs kept, found: ${scheduled[*]:-none}"
for n in 20200101T000000Z 20200102T000000Z 20200103T000000Z; do
	[ ! -e "$b/$n" ] || fail "$b/$n was not deleted"
	journalctl -u myownpki-backup.service -o cat | grep -q "^Deleted $b/$n\$" || fail "no deletion of $n in the journal"
done
for k in "${keep_these[@]}"; do [ -e "$k" ] || fail "prune deleted $k"; done
[ ${#left[@]} -eq 6 ] || fail "want 2 scheduled + 4 others, found: ${left[*]}"
journalctl -u myownpki-backup.service -o cat | grep -q "Left alone $b/20200104T000000Z: .*has no manifest.json" || fail "the directory without a manifest was not reported"
printf 'Daily backup: %s verified; prune kept 2, deleted 3, left alone %d others.\n\n' "$(basename "$first")" ${#keep_these[@]} >>"$summary"
# --no-backup-timer switches it off; the next run without it leaves it off.
bash "$install_sh" --archive "$update_archive" --no-backup-timer >"$tmp/run7.log"
[ "$(systemctl is-enabled myownpki-backup.timer || true)" = disabled ] || fail "--no-backup-timer: still enabled"
grep -q 'the daily timer is off' "$tmp/run7.log" || fail "the result does not say the timer is off"
bash "$install_sh" --archive "$update_archive" >"$tmp/run8.log"
[ "$(systemctl is-enabled myownpki-backup.timer || true)" = disabled ] || fail "install.sh switched the timer on again"

step "All checks passed"
