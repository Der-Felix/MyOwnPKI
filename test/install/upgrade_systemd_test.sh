#!/usr/bin/env bash
# upgrade_systemd_test.sh VERSION OLD_ARCHIVE OLD_INSTALL_SH NEW_ARCHIVE – the update of a
# systemd installation made by an OLD release (PHASE3 §19.5, step 113), on a throwaway Linux
# machine with systemd, as root (the CI job "install"):
#
#  1. the install.sh of release VERSION installs that release (--archive from the cache of
#     scripts/upgrade/fetch.sh, SHA-256 pinned) with ACME on its own TLS; enabled, the backup
#     timer on, the low-ports drop-in
#  2. init, start, unseal through the API – the old release as an operator runs it; the root
#     certificate, the CRL, the audit heads and the checkpoint key are noted; the daily backup
#     of the old release runs once. A release before 0.9.0 makes format 1 without a signature
#     and has no backup key; from 0.9.0 on, `init` makes the key (its fingerprint is noted)
#     and the backup is format 2 with manifest.sig
#  3. an update that fails its check is rolled back by THIS TREE's install.sh: the old binary
#     is back and healthy, the text names the backup the OLD binary made before the swap
#  4. the update: this tree's install.sh over the old installation. The backup of the update is
#     made by the OLD binary (<time>-<old version>) and verifies: format 1 with
#     --allow-unsigned before 0.9.0; format 2, signed, with --backup-key (the key noted at
#     init, no --allow-unsigned) from 0.9.0 on. The new binary is installed and running, the
#     config, the drop-ins and the timer are as they were, the units pass systemd-analyze,
#     sealed after the restart and unsealed with the old passphrase
#  5. what the old installation had is still there: root certificate, CRL (number not lower),
#     the old audit heads and the checkpoint key (audit verify), db status "up to date"
#  6. the first backup of the NEW binary (the timer's service, in its sandbox) creates the
#     backup key (0600, owner myownpki) when the old release had none, or keeps the key of the
#     old release (the same file, the same fingerprint); it signs the backup (format 2,
#     manifest.sig) and verifies; a second run keeps the key. The old backups still verify:
#     with --allow-unsigned before 0.9.0, with the plain command from 0.9.0 on; what the plain
#     `backup verify` of an unsigned old backup does on a host with a key is printed as a note
#
# The old release's own install.sh is used as it was published. ARCHIVE paths stay relative in
# CI on purpose: install.sh changes to / before it reads them. It refuses to run where MyOwnPKI
# is installed already, and removes what it installed when it ends.
set -euo pipefail

version=${1:?usage: upgrade_systemd_test.sh VERSION OLD_ARCHIVE OLD_INSTALL_SH NEW_ARCHIVE}
old_archive=${2:?usage: upgrade_systemd_test.sh VERSION OLD_ARCHIVE OLD_INSTALL_SH NEW_ARCHIVE}
old_install_sh=${3:?usage: upgrade_systemd_test.sh VERSION OLD_ARCHIVE OLD_INSTALL_SH NEW_ARCHIVE}
new_archive=${4:?usage: upgrade_systemd_test.sh VERSION OLD_ARCHIVE OLD_INSTALL_SH NEW_ARCHIVE}
root=$(cd "$(dirname "$0")/../.." && pwd)
install_sh=$root/deploy/install.sh
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
conf=/etc/myownpki/config.yaml
bin=/usr/local/bin/myownpki
data=/var/lib/myownpki
backups=/var/backups/myownpki
lowports=/etc/systemd/system/myownpki.service.d/low-ports.conf
acme_url=https://acme.ci.test/acme
old_version=v$version
# signed_old: the old release is 0.9.0 or newer, so it makes the backup key at init and signs
# its backups (format 2). Older releases make format 1 and have no key.
signed_old=0
if [ "$(printf '%s\n%s\n' "$version" 0.9.0 | sort -V | head -n 1)" = 0.9.0 ]; then signed_old=1; fi

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if [ -e /etc/myownpki ] || [ -e "$data" ] || [ -e "$bin" ]; then
	echo "MyOwnPKI is installed on this machine – upgrade_systemd_test.sh only runs on a throwaway one" >&2
	exit 1
fi
tmp=$(mktemp -d)

# cleanup removes what this test installed (the check above says there was nothing before).
cleanup() {
	systemctl disable --now myownpki-backup.timer >/dev/null 2>&1 || true
	systemctl stop myownpki-backup.service myownpki.service >/dev/null 2>&1 || true
	systemctl disable myownpki.service >/dev/null 2>&1 || true
	rm -rf /etc/systemd/system/myownpki.service /etc/systemd/system/myownpki.service.d \
		/etc/systemd/system/myownpki-backup.service /etc/systemd/system/myownpki-backup.service.d \
		/etc/systemd/system/myownpki-backup.timer /etc/systemd/system/timers.target.wants/myownpki-backup.timer \
		/etc/systemd/system/multi-user.target.wants/myownpki.service \
		"$bin" "$bin.previous" "$bin.new" /etc/myownpki "$data" "$data".failed-* "$backups" "$tmp"
	systemctl daemon-reload >/dev/null 2>&1 || true
	userdel myownpki >/dev/null 2>&1 || true
	getent group myownpki >/dev/null 2>&1 && groupdel myownpki >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
fail() {
	printf '::error::%s\n' "$*"
	exit 1
}
note() { printf 'NOTE: %s\n' "$*"; }
svc() { runuser -u myownpki -- env -i PATH=/usr/bin:/bin "$@"; }
version_of() { "$1" --version | awk '{ print $2 }'; }
running() { version_of "/proc/$(systemctl show --property MainPID --value myownpki.service)/exe"; }
healthy() {
	for _ in $(seq 1 30); do
		if svc "$bin" healthcheck --config "$conf" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	return 1
}
# totp BASE32-SECRET STEP: the code of the 30-second step STEP (RFC 6238: SHA-1, 6 digits).
totp() {
	local s=$1 key c b='' h off i
	while [ $(( ${#s} % 8 )) -ne 0 ]; do s="$s="; done
	key=$(printf '%s' "$s" | base32 -d | od -An -tx1 | tr -d ' \n')
	c=$(printf '%016x' "$2")
	for (( i = 0; i < 16; i += 2 )); do b+="\\x${c:i:2}"; done
	# shellcheck disable=SC2059 # the format is the counter's eight bytes
	h=$(printf "$b" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -binary | od -An -tx1 | tr -d ' \n')
	off=$(( 0x${h:39:1} ))
	printf '%06d\n' $(( (0x${h:$(( off * 2 )):8} & 0x7fffffff) % 1000000 ))
}
csrf=
last_step=0
api() {
	local tok
	printf '%s' "${3:-}" | curl -fsS --noproxy '*' --insecure -b "$tmp/jar" -c "$tmp/jar" -X "$1" -H "X-CSRF-Token: $csrf" \
		-H 'Content-Type: application/json' ${3:+--data-binary @-} -o "$tmp/api.json" "https://127.0.0.1:9443/api/v1$2" || return 1
	tok=$(sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p' "$tmp/api.json")
	if [ -n "$tok" ]; then csrf=$tok; fi
}
# unseal_api: sign in (a code works once, so the next 30-second step when this one is used up)
# and unseal.
unseal_api() {
	local cur
	cur=$(( $(date +%s) / 30 ))
	if [ "$cur" -le "$last_step" ]; then
		sleep $(( (last_step + 1) * 30 - $(date +%s) + 1 ))
		cur=$(( $(date +%s) / 30 ))
	fi
	last_step=$cur
	: >"$tmp/jar"
	csrf=
	api POST /auth/login "{\"username\":\"ci-admin\",\"password\":\"$password\"}" || fail "sign-in"
	api POST /auth/totp "{\"code\":\"$(totp "$secret" "$cur")\"}" || fail "second factor"
	api POST /system/unseal "{\"passphrase\":\"$pass\"}" || fail "unseal through the API"
	grep -q '"sealed":false' "$tmp/api.json" || fail "still sealed: $(cat "$tmp/api.json")"
}
# heads: "scope head" lines of `audit verify` as the service user.
heads() {
	svc "$bin" audit verify --config "$conf" | sed -n -E 's/^[[:space:]]*([a-z]+(:[a-z0-9-]+)?)[[:space:]]+.*head ([0-9]+:[0-9a-f]{12,64}).*$/\1 \3/p'
}
root_fingerprint() {
	curl -fsS http://127.0.0.1:8080/ca/root/1.crt | openssl x509 -inform DER -noout -fingerprint -sha256
}
crl_number() {
	curl -fsS http://127.0.0.1:8080/crl/issuing/1.crl | openssl crl -inform DER -noout -crlnumber | sed 's/^crlNumber=//; s/^0[xX]//'
}
# update_backups: the directories install.sh makes (<time>-<version>), one per line.
update_backups() {
	find "$backups" -mindepth 1 -maxdepth 1 -type d -name '*-v*' ! -name '*-unverified' | sort
}
manifest_format() { sed -n 's/.*"format": *"\([^"]*\)".*/\1/p' "$1/manifest.json" | head -n 1; }

step "1. Release $version installs itself (its own install.sh, its own archive)"
bash "$old_install_sh" --archive "$old_archive" --acme "$acme_url" | tee "$tmp/run1.log"
[ "$(version_of "$bin")" = "$old_version" ] || fail "the installed binary is $(version_of "$bin"), want $old_version"
[ "$(systemctl is-enabled myownpki.service)" = enabled ] || fail "the service is not enabled"
[ "$(systemctl is-enabled myownpki-backup.timer)" = enabled ] || fail "the backup timer is not enabled"
[ -f "$lowports" ] || fail "no low-ports drop-in"
pre_state=$(sha256sum "$conf" "$lowports" | sha256sum | cut -d' ' -f1)

step "2. init, start and unseal $old_version; the facts to keep"
pass=$(openssl rand -hex 24)
password=$(openssl rand -hex 16)
if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::add-mask::%s\n::add-mask::%s\n' "$pass" "$password"; fi
printf '%s\n%s\n' "$pass" "$password" |
	svc "$bin" init --stdin --config "$conf" --admin-user ci-admin \
		--recovery-key-file "$data/ci-recovery.txt" --otpauth-file "$data/ci-otpauth.txt" \
		--with-ca --ca-base-url http://127.0.0.1:8080 >"$tmp/init.log" 2>&1 ||
	{ grep -v -i 'recovery\|secret\|otpauth' "$tmp/init.log" >&2; fail "init failed"; }
secret=$(sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p' "$data/ci-otpauth.txt" | head -n 1)
[ -n "$secret" ] || fail "no TOTP secret in the otpauth file"
if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::add-mask::%s\n' "$secret"; fi
rm -f "$data/ci-recovery.txt" "$data/ci-otpauth.txt"
checkpoint_key=$(awk '/^Checkpoint key fingerprint/ { getline; gsub(/[ \t]/, ""); print; exit }' "$tmp/init.log")
[ -n "$checkpoint_key" ] || fail "init printed no checkpoint key fingerprint"
old_backup_key=
if [ "$signed_old" = 1 ]; then
	old_backup_key=$(awk '/^Backup key fingerprint/ { getline; gsub(/[ \t]/, ""); print; exit }' "$tmp/init.log")
	[ -n "$old_backup_key" ] || fail "init of $old_version printed no backup key fingerprint"
fi
systemctl start myownpki.service
healthy || fail "not healthy after the start"
unseal_api
root_fp=$(root_fingerprint)
crl_before=$(crl_number)
heads_before=$(heads)
[ -n "$heads_before" ] || fail "audit verify names no heads"
printf 'facts: %s, CRL number %s, heads %s\n' "$root_fp" "$crl_before" "$(printf '%s' "$heads_before" | tr '\n' ' ')"
# The daily backup of the old release: a scheduled backup (format 1, no signature before 0.9.0;
# format 2, signed by the key of init from 0.9.0 on).
systemctl start myownpki-backup.service || { journalctl -u myownpki-backup.service --no-pager -n 40; fail "the daily backup of $old_version failed"; }
mapfile -t scheduled < <(find "$backups" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z' | sort)
[ ${#scheduled[@]} -eq 1 ] || fail "want one scheduled backup of $old_version, found: ${scheduled[*]:-none}"
old_scheduled=${scheduled[0]}
if [ "$signed_old" = 1 ]; then
	[ "$(manifest_format "$old_scheduled")" = "myownpki-backup/2" ] || fail "the backup of $old_version is not format 2: $(manifest_format "$old_scheduled")"
	[ -s "$old_scheduled/manifest.sig" ] || fail "the backup of $old_version has no manifest.sig"
	[ "$(stat -c '%a %U' "$data/backup-signing.key")" = "600 myownpki" ] || fail "backup key of $old_version: $(stat -c '%a %U' "$data/backup-signing.key" 2>&1)"
	svc "$bin" backup verify "$old_scheduled" --backup-key "$old_backup_key" >"$tmp/verify0.log" 2>&1 || { cat "$tmp/verify0.log"; fail "backup verify of the backup of $old_version with the key noted at init"; }
	grep -q 'Signature valid' "$tmp/verify0.log" || fail "the verify of the backup of $old_version does not say 'Signature valid'"
else
	[ "$(manifest_format "$old_scheduled")" = "myownpki-backup/1" ] || fail "the backup of $old_version is not format 1: $(manifest_format "$old_scheduled")"
	[ ! -e "$data/backup-signing.key" ] || fail "$old_version made a backup key"
fi

step "3. An update that fails its check is rolled back by this tree's install.sh"
new_version=$(basename "$new_archive")
new_version=v${new_version#myownpki_}
new_version=${new_version%_linux_*}
[ "$old_version" != "$new_version" ] || fail "the new archive has the same version $new_version"
stale=/etc/systemd/system/myownpki.service.d/zz-ci-stale.conf
printf '[Service]\nExecStart=\nExecStart=%s.previous serve --config %s\n' "$bin" "$conf" >"$stale"
systemctl daemon-reload
if bash "$install_sh" --archive "$new_archive" >"$tmp/run2.log" 2>&1; then
	cat "$tmp/run2.log"
	fail "install.sh reported success although the service runs the old binary"
fi
cat "$tmp/run2.log"
grep -q "the service runs $old_version, not $new_version" "$tmp/run2.log" || fail "install.sh did not name the running version"
grep -q "rolled back to $old_version, which is healthy again" "$tmp/run2.log" || fail "no rollback text"
grep -q "Backup: $backups/" "$tmp/run2.log" || fail "the rollback text does not name the backup"
[ "$(version_of "$bin")" = "$old_version" ] || fail "the binary is $(version_of "$bin") after the rollback"
healthy || fail "not healthy after the rollback"
rm "$stale"
systemctl daemon-reload
systemctl restart myownpki.service
healthy || fail "not healthy after the stale drop-in is gone"

step "4. The update"
bash "$install_sh" --archive "$new_archive" | tee "$tmp/run3.log"
mapfile -t ubackups < <(update_backups)
[ ${#ubackups[@]} -eq 2 ] || fail "want two update backups (the rolled-back and the real one), found: ${ubackups[*]:-none}"
for b in "${ubackups[@]}"; do
	grep -q "\"version\": *\"$old_version\"" "$b/manifest.json" || fail "$b does not say it was made by $old_version"
	if [ "$signed_old" = 1 ]; then
		[ "$(manifest_format "$b")" = "myownpki-backup/2" ] || fail "$b was made by $old_version and must be format 2, is $(manifest_format "$b")"
		[ -s "$b/manifest.sig" ] || fail "$b has no manifest.sig although $old_version signs its backups"
		# No --allow-unsigned: a signed backup must verify against the key noted at init.
		svc "$bin" backup verify "$b" --backup-key "$old_backup_key" >"$tmp/verify.log" 2>&1 || { cat "$tmp/verify.log"; fail "backup verify --backup-key $b"; }
		grep -q 'Signature valid' "$tmp/verify.log" || fail "the verify of $b does not say 'Signature valid'"
	else
		[ "$(manifest_format "$b")" = "myownpki-backup/1" ] || fail "$b was made by $old_version and must be format 1, is $(manifest_format "$b")"
		[ ! -e "$b/manifest.sig" ] || fail "$b has a signature although $old_version cannot sign"
		svc "$bin" backup verify "$b" --allow-unsigned >"$tmp/verify.log" 2>&1 || { cat "$tmp/verify.log"; fail "backup verify --allow-unsigned $b"; }
		grep -q 'unauthenticated' "$tmp/verify.log" || fail "the verify of $b does not say that the backup is unauthenticated"
	fi
done
[ "$(version_of "$bin")" = "$new_version" ] || fail "the binary is $(version_of "$bin"), want $new_version"
[ "$(running)" = "$new_version" ] || fail "the service runs $(running), not $new_version"
[ "$(version_of "$bin.previous")" = "$old_version" ] || fail "$bin.previous is not $old_version"
healthy || fail "not healthy after the update"
[ "$(sha256sum "$conf" "$lowports" | sha256sum | cut -d' ' -f1)" = "$pre_state" ] || fail "the update changed the config or the low-ports drop-in"
[ "$(systemctl is-enabled myownpki.service)" = enabled ] || fail "the service is not enabled after the update"
[ "$(systemctl is-enabled myownpki-backup.timer)" = enabled ] || fail "the backup timer is not enabled after the update"
systemctl is-active --quiet myownpki-backup.timer || fail "the backup timer is not active after the update"
systemd-analyze verify /etc/systemd/system/myownpki.service /etc/systemd/system/myownpki-backup.service /etc/systemd/system/myownpki-backup.timer
for unit in myownpki.service myownpki-backup.service; do
	exposure=$(systemd-analyze security --no-pager "$unit" | sed -n "s/.*Overall exposure level for $unit: \([0-9.]*\).*/\1/p")
	[ -n "$exposure" ] || fail "no overall exposure for $unit"
	awk -v e="$exposure" 'BEGIN { exit !(e < 2.0) }' || fail "$unit: exposure $exposure after the update – it must stay below 2.0"
done
# The restart left the server sealed; the old passphrase and the old second factor unseal it.
[ "$(curl -fsS --insecure https://127.0.0.1:9443/healthz)" = ok ] || fail "/healthz"
unseal_api
if [ "$signed_old" = 1 ]; then
	backup_text="format 2, signed, verify with --backup-key"
else
	backup_text="format 1, verify with --allow-unsigned"
fi
printf 'Update %s -> %s: two backups by %s (%s), running, unsealed with the old passphrase.\n\n' \
	"$old_version" "$new_version" "$old_version" "$backup_text" >>"$summary"

step "5. What the old installation had is still there"
[ "$(root_fingerprint)" = "$root_fp" ] || fail "the root certificate changed"
crl_after=$(crl_number)
[ $(( 16#$crl_after )) -ge $(( 16#$crl_before )) ] || fail "the CRL number went down ($crl_before -> $crl_after)"
for scope in instance tenant:default; do
	head=$(printf '%s\n' "$heads_before" | awk -v s="$scope" '$1 == s { print $2 }')
	[ -n "$head" ] || fail "no head noted for $scope"
	svc "$bin" audit verify --config "$conf" --scope "$scope" --expect-head "$head" --checkpoint-key "$checkpoint_key" >"$tmp/audit.log" 2>&1 ||
		{ cat "$tmp/audit.log"; fail "audit verify of $scope with the head from before the update"; }
done
status=$(svc "$bin" db status --config "$conf") || { printf '%s\n' "$status"; fail "db status after the update"; }
[ "$(printf '%s\n' "$status" | grep -c 'up to date')" -ge 4 ] || { printf '%s\n' "$status"; fail "db status: not every database is up to date"; }

if [ "$signed_old" = 1 ]; then
	step "6. The first backup of the new binary keeps the backup key of $old_version"
else
	step "6. The first backup of the new binary makes the backup key"
fi
key=$data/backup-signing.key
key_before=
if [ "$signed_old" = 1 ]; then
	[ -f "$key" ] || fail "the backup key of $old_version is gone after the update"
	key_before=$(sha256sum "$key")
elif [ -e "$key" ]; then
	note "the update or the start already made $key (before the first backup)"
fi
systemctl start myownpki-backup.service || { journalctl -u myownpki-backup.service --no-pager -n 50; fail "the backup service of $new_version failed (does its sandbox allow the key file?)"; }
[ -f "$key" ] || fail "no backup key $key after the first backup of $new_version"
[ "$(stat -c '%a %U' "$key")" = "600 myownpki" ] || fail "backup key: $(stat -c '%a %U' "$key")"
mapfile -t scheduled < <(find "$backups" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z' | sort)
[ ${#scheduled[@]} -eq 2 ] || fail "want the old and one new scheduled backup, found: ${scheduled[*]:-none}"
new_scheduled=${scheduled[1]}
[ "$(manifest_format "$new_scheduled")" = "myownpki-backup/2" ] || fail "the new backup is not format 2: $(manifest_format "$new_scheduled")"
[ -s "$new_scheduled/manifest.sig" ] || fail "the new backup has no manifest.sig"
svc "$bin" backup verify "$new_scheduled" --config "$conf" >"$tmp/verify2.log" 2>&1 || { cat "$tmp/verify2.log"; fail "backup verify of the new backup"; }
grep -q 'Signature valid' "$tmp/verify2.log" || fail "the verify of the new backup does not say 'Signature valid'"
journalctl -u myownpki-backup.service -o cat | grep -q 'backup key SHA256:' || fail "the journal of the backup service does not show the backup key"
fp=$(sed -n 's/.*made by key \(SHA256:[0-9a-f]*\).*/\1/p' "$tmp/verify2.log" | head -n 1)
[ -n "$fp" ] || fail "no key fingerprint in the verify output"
if [ "$signed_old" = 1 ]; then
	[ "$(sha256sum "$key")" = "$key_before" ] || fail "the new binary replaced the backup key of $old_version"
	[ "$fp" = "$old_backup_key" ] || fail "the new backup is signed by $fp, not by the key $old_backup_key that $old_version made at init"
fi
# A second run signs with the same key.
sleep 1
systemctl start myownpki-backup.service || fail "the second backup run failed"
mapfile -t scheduled < <(find "$backups" -mindepth 1 -maxdepth 1 -type d -regextype posix-extended -regex '.*/[0-9]{8}T[0-9]{6}Z' | sort)
svc "$bin" backup verify "${scheduled[-1]}" --backup-key "$fp" >/dev/null 2>&1 || fail "the second backup is not signed by $fp"
# The backups of the old release.
if [ "$signed_old" = 1 ]; then
	# Signed by the same key: it verifies with the pin and, on this host, as the host's own key.
	svc "$bin" backup verify "$old_scheduled" --backup-key "$fp" >/dev/null 2>&1 || fail "the scheduled backup of $old_version does not verify with --backup-key $fp"
	svc "$bin" backup verify "$old_scheduled" --config "$conf" >"$tmp/verify3.log" 2>&1 || { cat "$tmp/verify3.log"; fail "a plain backup verify of the scheduled backup of $old_version"; }
	grep -q 'the backup key of this host' "$tmp/verify3.log" || fail "the plain verify of the backup of $old_version does not name the key of this host"
	printf 'Backup key %s made by %s at init and kept by %s; the backups of both verify with it (format 2).\n\n' "$fp" "$old_version" "$new_version" >>"$summary"
else
	svc "$bin" backup verify "$old_scheduled" --allow-unsigned >/dev/null 2>&1 || fail "the scheduled backup of $old_version does not verify with --allow-unsigned"
	if svc "$bin" backup verify "$old_scheduled" --config "$conf" >"$tmp/verify3.log" 2>&1; then
		note "on a host with a backup key a plain 'backup verify' of a backup from before 0.9.0 passes"
		verdict=passes
	else
		note "on a host with a backup key a plain 'backup verify' of a backup from before 0.9.0 is refused unless --allow-unsigned (the host key is the expected key):"
		sed 's/^/NOTE:   /' "$tmp/verify3.log"
		verdict="is refused without --allow-unsigned"
	fi
	printf 'Backup key %s made by the first backup of %s; new backups format 2, verified; a plain verify of a pre-0.9.0 backup %s.\n\n' "$fp" "$new_version" "$verdict" >>"$summary"
fi

step "All checks passed for the update from $old_version"
