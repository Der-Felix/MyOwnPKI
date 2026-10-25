#!/usr/bin/env bash
# install-agent.sh – install or update myownpki-agent on Linux (amd64/arm64).
# Download the script and checksums.txt first, verify the script with
# sha256sum --check --ignore-missing checksums.txt, then run it. Never pipe a
# download into a shell. The archive itself is always verified before unpack.

set -euo pipefail

DEFAULT_VERSION=0.3.0
REPO=Der-Felix/MyOwnPKI
SIGNER="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v"
ISSUER=https://token.actions.githubusercontent.com
SVC=myownpki-agent
BIN=/usr/local/bin/myownpki-agent
CONF=/etc/myownpki-agent/agent.yaml
ROOT=/etc/myownpki-agent/root.pem
DATA=/var/lib/myownpki-agent
UNIT=/etc/systemd/system/myownpki-agent.service
DROPINS=/etc/systemd/system/myownpki-agent.service.d
LOWPORTS=$DROPINS/20-low-ports.conf
PATHS=$DROPINS/10-paths.conf

usage() {
	cat <<EOF
Usage: install-agent.sh --server URL --ca-bundle FILE [options]   (as root)

  --server URL          agent listener, https://host[:port] (normally :8444)
  --ca-bundle FILE      root certificate trusted for the agent and ACME listeners
  --token-file FILE     join token; deleted only after successful enrollment
  --webroot DIR         existing webroot for enrollment http-01; default standalone
  --version V           release to install (default $DEFAULT_VERSION)
  --archive FILE        local myownpki-agent_<version>_linux_<arch>.tar.gz;
                        checksums.txt and optionally its signature must be next to it
  -h, --help            this text

An existing agent.yaml is never replaced. Installation options apply only when
that file is first created. Running the script with a newer release updates the
binary and restarts the service; the agent does not update itself.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'install-agent.sh: warning: %s\n' "$*" >&2; }
die() { printf 'install-agent.sh: %s\n' "$*" >&2; exit 1; }
changes=()
changed() { changes+=("$1"); }

version=$DEFAULT_VERSION
archive=
server=
ca_bundle=
token_file=
webroot=
config_opts=false

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--server) server=${2:?--server needs a URL}; config_opts=true; shift 2 ;;
		--ca-bundle) ca_bundle=${2:?--ca-bundle needs a file}; shift 2 ;;
		--token-file) token_file=${2:?--token-file needs a file}; shift 2 ;;
		--webroot) webroot=${2:?--webroot needs a directory}; config_opts=true; shift 2 ;;
		--version) version=${2:?--version needs a value}; shift 2 ;;
		--archive) archive=${2:?--archive needs a file}; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $1" ;;
		esac
	done
	version=${version#v}
	[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version: not a version: $version"
	[ -n "$server" ] || die "--server is required"
	[[ $server =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die "--server: want https://host[:port], without a path"
	[ -n "$ca_bundle" ] || die "--ca-bundle is required"
	[ -f "$ca_bundle" ] || die "--ca-bundle: no such file: $ca_bundle"
	[ -z "$token_file" ] || [ -f "$token_file" ] || die "--token-file: no such file: $token_file"
	if [ -n "$webroot" ]; then
		[[ $webroot =~ ^/[A-Za-z0-9._/@+,=:-]+$ ]] || die "--webroot: an absolute path with letters, digits and ._/@+,=:- only"
		[ "$webroot" != / ] || die "--webroot must not be the whole file system"
		[ -d "$webroot" ] || die "--webroot: no such directory: $webroot"
	fi
	if [ -n "$archive" ]; then
		local dir
		[ -f "$archive" ] || die "--archive: no such file: $archive"
		dir=$(CDPATH='' cd -- "$(dirname -- "$archive")" && pwd -P) || die "--archive: cannot open its directory"
		archive=$dir/$(basename -- "$archive")
	fi
	for file in "$ca_bundle" "$token_file"; do
		if [ -n "$file" ]; then
			local dir
			dir=$(CDPATH='' cd -- "$(dirname -- "$file")" && pwd -P) || die "cannot open the directory of $file"
			if [ "$file" = "$ca_bundle" ]; then ca_bundle=$dir/$(basename -- "$file"); else token_file=$dir/$(basename -- "$file"); fi
		fi
	done
}

arch() {
	case $(uname -m) in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture $(uname -m) – releases exist for amd64 and arm64" ;;
	esac
}

own_name() {
	local name
	name=$(hostname -f 2>/dev/null || true)
	[ -n "$name" ] && [ "$name" != localhost ] || name=$(hostname)
	echo "$name"
}

download() {
	local url=$1 out=$2
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$out" "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$out" "$url"
	else
		die "neither curl nor wget found – install one, or use --archive"
	fi
}

verify_checksum() {
	local file=$1 sums=$2 name want got
	name=$(basename "$file")
	want=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$sums")
	[ -n "$want" ] || die "$name is not listed in checksums.txt – nothing installed"
	[ "$(printf '%s\n' "$want" | wc -l)" -eq 1 ] || die "$name is listed twice – nothing installed"
	got=$(sha256sum "$file" | awk '{ print $1 }')
	[ "$want" = "$got" ] || die "SHA-256 of $name does not match checksums.txt – nothing installed"
}

fetch() {
	local name base dir
	if [ -n "$archive" ]; then
		name=$(basename "$archive")
		[[ $name =~ ^myownpki-agent_([0-9A-Za-z.-]+)_linux_([a-z0-9]+)\.tar\.gz$ ]] || die "--archive: unexpected file name: $name"
		version=${BASH_REMATCH[1]}
		[ "${BASH_REMATCH[2]}" = "$(arch)" ] || die "--archive is for ${BASH_REMATCH[2]}, this machine is $(arch)"
		dir=$(dirname "$archive")
		[ -f "$dir/checksums.txt" ] || die "--archive: no checksums.txt next to $name"
		cp "$archive" "$dir/checksums.txt" "$work/"
		[ ! -f "$dir/checksums.txt.sigstore.json" ] || cp "$dir/checksums.txt.sigstore.json" "$work/"
		source_text="local archive $archive"
	else
		name=myownpki-agent_${version}_linux_$(arch).tar.gz
		base=https://github.com/${REPO}/releases/download/v${version}
		say "Downloading myownpki-agent v${version} for linux/$(arch) …"
		download "$base/$name" "$work/$name"
		download "$base/checksums.txt" "$work/checksums.txt"
		download "$base/checksums.txt.sigstore.json" "$work/checksums.txt.sigstore.json"
		source_text="GitHub release v${version}"
	fi
	archive_file=$work/$name
	verify_checksum "$archive_file" "$work/checksums.txt"
	signature="not checked – cosign is not installed"
	if command -v cosign >/dev/null 2>&1; then
		[ -f "$work/checksums.txt.sigstore.json" ] || die "no signature bundle – nothing installed"
		cosign verify-blob --bundle "$work/checksums.txt.sigstore.json" \
			--certificate-identity "${SIGNER}${version}" --certificate-oidc-issuer "$ISSUER" \
			"$work/checksums.txt" >/dev/null 2>&1 || die "invalid Sigstore signature – nothing installed"
		signature="verified (cosign, release.yml at v${version})"
	fi
}

unpack() {
	local file
	mkdir "$work/x"
	tar -xzf "$archive_file" -C "$work/x" --no-same-owner
	for file in myownpki-agent deploy/agent.example.yaml deploy/systemd/myownpki-agent.service deploy/systemd/agent-low-ports.conf; do
		[ -f "$work/x/$file" ] || die "the archive has no $file"
	done
	new_version=$("$work/x/myownpki-agent" --version 2>/dev/null | awk '{ print $2 }' || true)
	[ -n "$new_version" ] || die "the new binary does not run here – use a TMPDIR that allows programs"
}

put() {
	local src=$1 dst=$2 mode=$3
	put_changed=false
	if [ -f "$dst" ] && cmp -s "$src" "$dst"; then return 0; fi
	install -d -m 0755 "$(dirname "$dst")"
	install -m "$mode" -o root -g root "$src" "$dst.new"
	mv -f "$dst.new" "$dst"
	put_changed=true
	changed "$dst"
}

ensure_dirs() {
	install -d -m 0755 /etc/myownpki-agent
	if [ ! -d "$DATA" ]; then
		install -d -m 0700 -o root -g root "$DATA"
		changed "$DATA"
	fi
	put "$ca_bundle" "$ROOT" 0600
}

render_config() {
	local hostname=$1
	{
		printf '# Written by install-agent.sh; this file is never replaced.\n'
		printf 'server: "%s"\n' "$server"
		printf 'ca_bundle: "%s"\n' "$ROOT"
		printf 'hostname: "%s"\n' "$hostname"
		printf 'state_dir: "%s"\n' "$DATA"
		printf 'log_level: "info"\n'
		if [ -n "$webroot" ]; then
			printf 'enrollment:\n  challenge: webroot\n  webroot: "%s"\n' "$webroot"
			printf 'paths: ["%s"]\n' "$webroot"
		else
			printf 'enrollment:\n  challenge: standalone\npaths: []\n'
		fi
		printf 'deployments: []\n'
	} >"$work/agent.yaml"
}

ensure_config() {
	created_config=false
	if [ -f "$CONF" ]; then
		$config_opts && warn "$CONF exists – installation options were not applied; edit it by hand"
		config_text="kept $CONF"
	else
		render_config "$(own_name)"
		created_config=true
		config_text="created $CONF (no deployments yet; see OPERATIONS chapter Agent)"
	fi
	if $created_config; then
		"$work/x/myownpki-agent" config check --config "$work/agent.yaml" >/dev/null || die "the generated agent.yaml is invalid"
		install -m 0644 -o root -g root "$work/agent.yaml" "$CONF.new"
		mv -f "$CONF.new" "$CONF"
		changed "$CONF"
	fi
	"$work/x/myownpki-agent" status --config "$CONF" >/dev/null || die "agent.yaml or ca_bundle cannot be loaded"
}

install_units() {
	unit_changed=false
	put "$work/x/deploy/systemd/myownpki-agent.service" "$UNIT" 0644
	$put_changed && unit_changed=true
	if $created_config && [ -n "$webroot" ]; then
		printf '[Service]\nReadWritePaths=%s %s\n' "$DATA" "$webroot" >"$work/10-paths.conf"
		put "$work/10-paths.conf" "$PATHS" 0644
		$put_changed && unit_changed=true
	elif $created_config; then
		put "$work/x/deploy/systemd/agent-low-ports.conf" "$LOWPORTS" 0644
		$put_changed && unit_changed=true
	fi
	$unit_changed && systemctl daemon-reload
	if ! systemctl is-enabled --quiet "$SVC.service" 2>/dev/null; then
		systemctl enable --quiet "$SVC.service"
		changed "enabled $SVC.service"
	fi
}

enroll() {
	[ ! -f "$DATA/agent.json" ] || return 0
	local args=(enroll --config "$CONF")
	[ -z "$token_file" ] || args+=(--token-file "$token_file")
	"$BIN" "${args[@]}" || die "enrollment failed; the token file was kept"
	if [ -f "$DATA/agent.json" ] && [ -n "$token_file" ]; then
		rm -f "$token_file"
		changed "deleted the used token file"
	fi
}

main() {
	parse_args "$@"
	[ "$(uname -s)" = Linux ] || die "Linux only"
	[ "$(id -u)" -eq 0 ] || die "run it as root (sudo bash install-agent.sh)"
	local tool
	for tool in systemctl tar sha256sum install awk cmp hostname; do
		command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
	done
	cd /
	work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-agent-install.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	fetch
	unpack
	ensure_dirs
	ensure_config

	local was_active=false binary_changed=false
	systemctl is-active --quiet "$SVC.service" 2>/dev/null && was_active=true
	put "$work/x/myownpki-agent" "$BIN" 0755
	$put_changed && binary_changed=true
	[ "$("$BIN" --version | awk '{ print $2 }')" = "$new_version" ] || die "$BIN does not report $new_version"
	install_units
	enroll
	if $was_active && { $binary_changed || $unit_changed; }; then
		systemctl restart "$SVC.service"
		changed "restarted $SVC.service"
	elif ! $was_active; then
		systemctl start "$SVC.service"
		changed "started $SVC.service"
	fi
	systemctl is-active --quiet "$SVC.service" || die "$SVC.service is not active; see journalctl -u $SVC"

	say ""
	say "myownpki-agent $new_version for linux/$(arch) from $source_text"
	say "  SHA-256:   ok (checksums.txt)"
	say "  Signature: $signature"
	say "  Config:    $config_text"
	if [ ${#changes[@]} -eq 0 ]; then
		say "  Changes:   none – everything was already in place"
	else
		printf '    %s\n' "${changes[@]}"
	fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
