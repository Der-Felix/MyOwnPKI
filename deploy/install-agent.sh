#!/usr/bin/env bash
# Deprecated compatibility wrapper: verify a release tarball, install its
# binary, and forward every setup operation to myownpki-agent setup.

set -euo pipefail

DEFAULT_VERSION=0.3.1
REPO=Der-Felix/MyOwnPKI
SIGNER="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v"
ISSUER=https://token.actions.githubusercontent.com
BIN=/usr/local/bin/myownpki-agent

usage() {
	cat <<EOF
Usage: install-agent.sh --server URL --ca-bundle FILE --root-sha256 HEX [options] (as root)

Deprecated: use the verified tarball or package plus 'myownpki-agent setup'.

  --server URL          agent listener, https://host[:port] (normally :8444)
  --ca-bundle FILE      root certificate trusted for the agent and ACME listeners
  --root-sha256 HEX     independently obtained SHA-256 of the root DER (colons allowed)
  --token-file FILE     regular 0600 join-token file; deleted only after new admission
  --webroot DIR         existing webroot for enrollment http-01; default standalone
  --low-ports           allow standalone and hooks to bind ports below 1024
  --version V           release to install (default $DEFAULT_VERSION)
  --archive FILE        local myownpki-agent_<version>_linux_<arch>.tar.gz;
                        checksums.txt and optionally its signature must be next to it
  -h, --help            this text
EOF
}

say() { printf '%s\n' "$*"; }
die() { printf 'install-agent.sh: %s\n' "$*" >&2; exit 1; }

version=$DEFAULT_VERSION
archive=
server=
ca_bundle=
root_sha256=
token_file=
webroot=
low_ports=false

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--server) server=${2:?--server needs a URL}; shift 2 ;;
		--ca-bundle) ca_bundle=${2:?--ca-bundle needs a file}; shift 2 ;;
		--root-sha256) root_sha256=${2:?--root-sha256 needs a fingerprint}; shift 2 ;;
		--token-file) token_file=${2:?--token-file needs a file}; shift 2 ;;
		--webroot) webroot=${2:?--webroot needs a directory}; shift 2 ;;
		--low-ports) low_ports=true; shift ;;
		--version) version=${2:?--version needs a value}; shift 2 ;;
		--archive) archive=${2:?--archive needs a file}; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $1" ;;
		esac
	done
	version=${version#v}
	[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version: not a version: $version"
	[ -n "$server" ] || die "--server is required"
	[ -n "$ca_bundle" ] || die "--ca-bundle is required"
	[ -n "$root_sha256" ] || die "--root-sha256 is required"
	if [ -n "$archive" ]; then
		local dir
		[ -f "$archive" ] || die "--archive: no such file: $archive"
		dir=$(CDPATH='' cd -- "$(dirname -- "$archive")" && pwd -P) || die "--archive: cannot open its directory"
		archive=$dir/$(basename -- "$archive")
	fi
}

arch() {
	case $(uname -m) in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture $(uname -m) – releases exist for amd64 and arm64" ;;
	esac
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

forward_setup() {
	local args=(setup --server "$server" --ca-bundle "$ca_bundle" --root-sha256 "$root_sha256")
	[ -z "$token_file" ] || args+=(--token-file "$token_file")
	[ -z "$webroot" ] || args+=(--webroot "$webroot")
	$low_ports && args+=(--low-ports)
	"$BIN" "${args[@]}"
}

main() {
	parse_args "$@"
	[ "$(uname -s)" = Linux ] || die "Linux only"
	[ "$(id -u)" -eq 0 ] || die "run it as root (sudo bash install-agent.sh)"
	local tool
	for tool in tar sha256sum install awk; do
		command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
	done
	say "install-agent.sh: warning: deprecated; use myownpki-agent setup directly (will be removed in v0.3.2)"
	work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-agent-install.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	fetch
	unpack
	install -d -m 0755 "$(dirname "$BIN")"
	install -m 0755 -o root -g root "$work/x/myownpki-agent" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	forward_setup
	say "Installed myownpki-agent $new_version from $source_text; SHA-256 verified. Signature: $signature"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
