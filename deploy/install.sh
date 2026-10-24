#!/usr/bin/env bash
# install.sh – install or update MyOwnPKI as a systemd service on Linux
# (Debian, Ubuntu and other systemd distributions; amd64 or arm64). Run as root.
# Guide: docs/OPERATIONS.md §2. Download it, check it, then run it – never
# pipe it into a shell:
#
#   v=0.2.1
#   curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/install.sh"
#   curl -fsSLO "https://github.com/Der-Felix/MyOwnPKI/releases/download/v$v/checksums.txt"
#   sha256sum --check --ignore-missing checksums.txt
#   sudo bash install.sh
#
# What it does:
# - takes the release archive from GitHub (default: the release this script
#   came with) or a local one (--archive, for CI and machines without
#   internet), and checks it: SHA-256 against checksums.txt always, and the
#   Sigstore signature of checksums.txt when cosign is installed – a
#   mismatch stops it before anything is installed;
# - creates the system user myownpki and /var/lib/myownpki (0700);
# - installs /usr/local/bin/myownpki, the unit (and the low-ports drop-in with
#   --public-port-80 or --acme on a port below 1024) and – only if there is
#   none yet – /etc/myownpki/config.yaml;
# - first installation: enables the service, does NOT start it, and prints
#   the next commands (init at the terminal, start, fingerprint, unseal);
# - update (a new binary over an initialized instance): backup and backup
#   verify first, then the new binary, restart, health check – and the old
#   binary back if the service is not healthy or does not run the new one.
#
# Running it again changes nothing that is already in place. It handles no
# secrets: the unseal passphrase and the admin password are only asked by
# `myownpki init`.

set -euo pipefail

# The release this script belongs to; release.yml refuses a tag that differs.
DEFAULT_VERSION=0.2.1

REPO=Der-Felix/MyOwnPKI
SIGNER="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/v"
ISSUER=https://token.actions.githubusercontent.com

SVC=myownpki
BIN=/usr/local/bin/myownpki
UNIT=/etc/systemd/system/myownpki.service
DROPINS=/etc/systemd/system/myownpki.service.d
LOWPORTS=$DROPINS/low-ports.conf
# The old name of low-ports.conf (v0.2.1): an installed one is kept.
OLD_LOWPORTS=$DROPINS/public-port-80.conf
CONF=/etc/myownpki/config.yaml
DATA=/var/lib/myownpki
BACKUPS=/var/backups/myownpki

usage() {
	cat <<EOF
Usage: install.sh [options]   (as root)

  --version V            release to install (default $DEFAULT_VERSION)
  --archive FILE         install a local myownpki_<version>_linux_<arch>.tar.gz;
                         checksums.txt (and checksums.txt.sigstore.json) next to it
  --tls-names LIST       names in the admin certificate (default: hostname -f and
                         this machine's addresses)
  --admin-listen ADDR    admin listener (default 0.0.0.0:9443)
  --allowed-networks L   who may reach the admin listener (default: 127.0.0.1 and
                         the /24 of each own IPv4 address)
  --public-port-80       public listener on :80 without a reverse proxy (drop-in
                         low-ports.conf with CAP_NET_BIND_SERVICE); default :8080
  --acme URL             ACME with its own TLS, without a reverse proxy, e.g.
                         https://pki.u.lab/acme: acme.base_url URL, acme.listen
                         on its port (443 by default; below 1024 with the drop-in
                         low-ports.conf), acme.tls_issuer from --acme-ca
  --acme-ca NAME         the CA that issues the ACME listener's certificate
                         (default issuing – the intermediate of init --with-ca)
  -h, --help             this text

The config options (--tls-names, --admin-listen, --allowed-networks,
--public-port-80, --acme) only apply when /etc/myownpki/config.yaml is created;
an existing config is never changed. The drop-in is installed either way.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'install.sh: warning: %s\n' "$*" >&2; }
die() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}

# changes lists what this run changed; empty at the end = nothing to do.
changes=()
changed() { changes+=("$1"); }

# as_service runs a command as the service user with a clean environment, so
# no MYOWNPKI_* variable of the calling shell reaches the binary.
as_service() {
	runuser -u "$SVC" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$DATA" "$@"
}

# --- options -----------------------------------------------------------------

version=$DEFAULT_VERSION
archive=
opt_tls_names=
opt_admin_listen=
opt_allowed=
port80=false
opt_acme=
opt_acme_ca=
acme_port=
low_ports=false
config_opts=false

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--version) version=${2:?--version needs a value}; shift 2 ;;
		--archive) archive=${2:?--archive needs a file}; shift 2 ;;
		--tls-names) opt_tls_names=${2:?--tls-names needs a value}; config_opts=true; shift 2 ;;
		--admin-listen) opt_admin_listen=${2:?--admin-listen needs a value}; config_opts=true; shift 2 ;;
		--allowed-networks) opt_allowed=${2:?--allowed-networks needs a value}; config_opts=true; shift 2 ;;
		--public-port-80) port80=true; shift ;;
		--acme) opt_acme=${2:?--acme needs a URL}; config_opts=true; shift 2 ;;
		--acme-ca) opt_acme_ca=${2:?--acme-ca needs a CA name}; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $1" ;;
		esac
	done
	version=${version#v}
	[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version: not a version: $version"
	# Values go into YAML in double quotes: no quotes, backslashes or newlines.
	[[ -z $opt_tls_names || $opt_tls_names =~ ^[A-Za-z0-9.:,\ *_-]+$ ]] || die "--tls-names: only names, addresses, commas and spaces"
	[[ -z $opt_admin_listen || $opt_admin_listen =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]*):[0-9]{1,5}$ ]] || die "--admin-listen: HOST:PORT, e.g. 0.0.0.0:9443"
	[[ -z $opt_allowed || $opt_allowed =~ ^[0-9A-Fa-f.:/,\ ]+$ ]] || die "--allowed-networks: only addresses and CIDRs, separated by commas"
	if [ -n "$opt_acme" ]; then
		# https://host[:port][/path] – a DNS name or an IPv4 address; the
		# server checks the rest (config check before the file is used).
		[[ $opt_acme =~ ^https://[A-Za-z0-9.-]+(:([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?$ ]] ||
			die "--acme: want https://HOST[:PORT]/PATH, e.g. https://pki.u.lab/acme"
		acme_port=${BASH_REMATCH[2]:-443}
		[ "$acme_port" -ge 1 ] && [ "$acme_port" -le 65535 ] || die "--acme: port $acme_port is not 1-65535"
		opt_acme=${opt_acme%/}
		opt_acme_ca=${opt_acme_ca:-issuing}
		[[ $opt_acme_ca =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "--acme-ca: not a CA name (the name in myownpki ca list): $opt_acme_ca"
		if [ "$acme_port" -lt 1024 ]; then low_ports=true; fi
	elif [ -n "$opt_acme_ca" ]; then
		die "--acme-ca only goes with --acme"
	fi
	if $port80; then low_ports=true; fi
	# main() changes to / before it reads the archive: make a relative path
	# absolute now, and refuse a missing file with the path as it was given.
	if [ -n "$archive" ]; then
		local dir
		[ -f "$archive" ] || die "--archive: no such file: $archive"
		dir=$(CDPATH='' cd -- "$(dirname -- "$archive")" && pwd -P) || die "--archive: cannot open the directory of $archive"
		archive=$dir/$(basename -- "$archive")
	fi
}

# --- this machine --------------------------------------------------------------

arch() {
	case $(uname -m) in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported architecture $(uname -m) – releases exist for amd64 and arm64" ;;
	esac
}

# own_addresses prints the global addresses of this machine, one per line.
own_addresses() {
	if command -v ip >/dev/null 2>&1; then
		ip -o addr show scope global | awk '{ sub(/\/.*/, "", $4); print $4 }'
	else
		hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true
	fi
}

# own_name prints the fully qualified host name, or the short one.
own_name() {
	local n
	n=$(hostname -f 2>/dev/null || true)
	[ -n "$n" ] && [ "$n" != localhost ] || n=$(hostname)
	echo "$n"
}

# join_unique joins its arguments with ", ", each value once.
join_unique() {
	local out='' v
	for v in "$@"; do
		[ -n "$v" ] || continue
		case ", $out, " in *", $v, "*) continue ;; esac
		out=${out:+$out, }$v
	done
	echo "$out"
}

# defaults computes the four config values: options first, then this machine.
defaults() {
	local addrs a nets=()
	mapfile -t addrs < <(own_addresses)
	tls_names=${opt_tls_names:-$(join_unique "$(own_name)" "${addrs[@]}")}
	admin_listen=${opt_admin_listen:-0.0.0.0:9443}
	# `myownpki healthcheck` connects to the listen address, or to loopback
	# for 0.0.0.0 and [::] – that address must be allowed too.
	local host=${admin_listen%:*}
	host=${host#[}
	host=${host%]}
	case $host in
	'' | 0.0.0.0) health_addr=127.0.0.1 ;;
	::) health_addr=::1 ;;
	*) health_addr=$host ;;
	esac
	if [ -n "$opt_allowed" ]; then
		IFS=', ' read -r -a nets <<<"$opt_allowed"
		allowed=$(join_unique "$health_addr" "${nets[@]}")
	else
		for a in "${addrs[@]}"; do
			[[ $a =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]] && nets+=("${BASH_REMATCH[1]}.0/24")
		done
		allowed=$(join_unique "$health_addr" "${nets[@]}")
		[ ${#nets[@]} -gt 0 ] || warn "no IPv4 address found – the admin listener only allows $health_addr; use --allowed-networks"
	fi
	if $port80; then public_listen=":80"; else public_listen=":8080"; fi
}

# render_config writes the example config with the four values (seven with
# --acme) set to stdout. It fails if the example no longer has exactly
# these keys.
render_config() {
	local example=$1 want=4
	[ -z "$opt_acme" ] || want=7
	awk -v admin_listen="$admin_listen" -v tls_names="$tls_names" -v allowed="$allowed" \
		-v public_listen="$public_listen" -v acme_base="$opt_acme" -v acme_listen=":${acme_port:-443}" \
		-v acme_ca="$opt_acme_ca" -v want="$want" -v stamp="$(date -u +%Y-%m-%d)" '
		NR == 1 { print "# Written by install.sh on " stamp " from deploy/config.example.yaml; edit freely –"
			print "# install.sh never changes it again. Check: myownpki config check --config /etc/myownpki/config.yaml"
			print "#" }
		/^[a-z_]+:/ { section = $1 }
		section == "admin:" && /^  listen:/ { print "  listen: \"" admin_listen "\""; n++; next }
		section == "admin:" && /^  tls_names:/ { print "  tls_names: \"" tls_names "\""; n++; next }
		section == "admin:" && /^  allowed_networks:/ { print "  allowed_networks: \"" allowed "\""; n++; next }
		section == "public:" && /^  listen:/ { print "  listen: \"" public_listen "\""; n++; next }
		acme_base != "" && section == "acme:" && /^  base_url:/ { print "  base_url: \"" acme_base "\""; n++; next }
		acme_base != "" && section == "acme:" && /^  listen:/ { print "  listen: \"" acme_listen "\""; n++; next }
		acme_base != "" && section == "acme:" && /^  tls_issuer:/ { print "  tls_issuer: \"" acme_ca "\""; n++; next }
		{ print }
		END { if (n != want) { print "install.sh: the example config changed – " n " of " want " keys found" > "/dev/stderr"; exit 1 } }
	' "$example"
}

# config_value prints a top-level or section key of a config file, unquoted
# (enough for the keys install.sh reads: data_dir, admin.listen, public.listen).
config_value() {
	local file=$1 section=$2 key=$3
	awk -v want_section="$section" -v key="$key" '
		/^[a-z_]+:/ { section = $1; sub(/:$/, "", section) }
		(want_section == "" && $0 ~ "^" key ":") || (want_section != "" && section == want_section && $0 ~ "^  " key ":") {
			sub(/^[^:]*:[ \t]*/, ""); sub(/[ \t]+#.*$/, ""); gsub(/^"|"$/, ""); print; exit
		}' "$file"
}

# --- the release ------------------------------------------------------------------

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

# verify_checksum FILE CHECKSUMS: the file's SHA-256 must be the one listed for
# its name.
verify_checksum() {
	local file=$1 sums=$2 name want got
	name=$(basename "$file")
	want=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$sums")
	[ -n "$want" ] || die "$name is not listed in checksums.txt – nothing installed"
	[ "$(printf '%s\n' "$want" | wc -l)" -eq 1 ] || die "$name is listed twice in checksums.txt – nothing installed"
	got=$(sha256sum "$file" | awk '{ print $1 }')
	[ "$want" = "$got" ] || die "SHA-256 of $name does not match checksums.txt – nothing installed"
}

# fetch puts the archive, checksums.txt and (if any) the signature bundle into
# $work and checks them; sets archive_file, signature.
fetch() {
	local a name base dir out
	a=$(arch)
	if [ -n "$archive" ]; then
		[ -f "$archive" ] || die "--archive: no such file: $archive"
		name=$(basename "$archive")
		[[ $name =~ ^myownpki_([0-9A-Za-z.-]+)_linux_([a-z0-9]+)\.tar\.gz$ ]] || die "--archive: expected myownpki_<version>_linux_<arch>.tar.gz, got $name"
		version=${BASH_REMATCH[1]}
		[ "${BASH_REMATCH[2]}" = "$a" ] || die "--archive is for ${BASH_REMATCH[2]}, this machine is $a"
		dir=$(dirname "$archive")
		[ -f "$dir/checksums.txt" ] || die "--archive: no checksums.txt next to $name"
		cp "$archive" "$dir/checksums.txt" "$work/"
		[ ! -f "$dir/checksums.txt.sigstore.json" ] || cp "$dir/checksums.txt.sigstore.json" "$work/"
		source_text="local archive $archive"
	else
		name=myownpki_${version}_linux_${a}.tar.gz
		base=https://github.com/${REPO}/releases/download/v${version}
		say "Downloading v${version} for linux/${a} from GitHub …"
		download "$base/$name" "$work/$name"
		download "$base/checksums.txt" "$work/checksums.txt"
		download "$base/checksums.txt.sigstore.json" "$work/checksums.txt.sigstore.json"
		source_text="GitHub release v${version}"
	fi
	archive_file=$work/$name
	verify_checksum "$archive_file" "$work/checksums.txt"
	if command -v cosign >/dev/null 2>&1; then
		if [ -f "$work/checksums.txt.sigstore.json" ]; then
			if ! out=$(cosign verify-blob --bundle "$work/checksums.txt.sigstore.json" \
				--certificate-identity "${SIGNER}${version}" --certificate-oidc-issuer "$ISSUER" \
				"$work/checksums.txt" 2>&1); then
				printf '%s\n' "$out" >&2
				die "the Sigstore signature of checksums.txt is not valid for v${version} – nothing installed"
			fi
			signature="verified (cosign, release.yml at v${version})"
		elif [ -n "$archive" ]; then
			signature="NOT checked – no checksums.txt.sigstore.json next to the archive"
			warn "$signature"
		else
			die "the release has no signature bundle – nothing installed"
		fi
	else
		signature="not checked – cosign is not installed (the SHA-256 only proves the download matches checksums.txt)"
	fi
}

# unpack extracts the archive and checks that it has what install.sh needs.
unpack() {
	local f
	mkdir "$work/x"
	tar -xzf "$archive_file" -C "$work/x" --no-same-owner
	for f in myownpki deploy/config.example.yaml deploy/systemd/myownpki.service deploy/systemd/low-ports.conf; do
		[ -f "$work/x/$f" ] || die "the archive has no $f – this install.sh needs v0.2.2 or later (or the install.sh of the archive's release)"
	done
	# The service user runs the new binary for config check below.
	chmod 0755 "$work" "$work/x" "$work/x/myownpki"
	new_version=$("$work/x/myownpki" --version 2>/dev/null | awk '{ print $2 }' || true)
	[ -n "$new_version" ] ||
		die "the new binary does not run here – is $work on a noexec mount? Set TMPDIR to a directory that allows running programs"
}

# --- installing ------------------------------------------------------------------

# put SRC DST MODE OWNER GROUP: install a file atomically if it differs; sets
# put_changed. It returns 0 whether it copied or not, so no caller needs
# `put … || true` (which would also hide a failed copy). Every step has its
# own `|| die`: set -e does not apply inside a function that is called in a
# condition (`if put …`, `swap_binary || …`).
put() {
	local src=$1 dst=$2 mode=$3 owner=$4 group=$5
	put_changed=false
	if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
		return 0
	fi
	install -d -m 0755 "$(dirname "$dst")" || die "cannot create $(dirname "$dst")"
	install -m "$mode" -o "$owner" -g "$group" "$src" "$dst.new" || die "cannot write $dst.new"
	mv -f "$dst.new" "$dst" || die "cannot replace $dst"
	put_changed=true
	changed "$dst"
}

# swap_binary puts the new binary in place and checks that $BIN now reports
# new_version – a swap that did not happen must never count as done.
swap_binary() {
	local got
	put "$work/x/myownpki" "$BIN" 0755 root root
	got=$("$BIN" --version 2>/dev/null | awk '{ print $2 }' || true)
	if [ "$got" != "$new_version" ]; then
		warn "$BIN reports ${got:-no version}, want $new_version"
		return 1
	fi
}

# running_version prints the version of the binary the running service was
# started from – a healthy service may still be the old binary. /proc/PID/exe
# is that file even after it was replaced on disk.
running_version() {
	local pid
	pid=$(systemctl show --property MainPID --value "$SVC.service" 2>/dev/null || true)
	case $pid in '' | 0) return 0 ;; esac
	"/proc/$pid/exe" --version 2>/dev/null | awk '{ print $2 }' || true
}

ensure_user() {
	local nologin
	getent passwd "$SVC" >/dev/null && return 0
	nologin=$(command -v nologin || echo /usr/sbin/nologin)
	if getent group "$SVC" >/dev/null; then
		useradd --system --gid "$SVC" --home-dir "$DATA" --no-create-home --shell "$nologin" "$SVC"
	else
		useradd --system --user-group --home-dir "$DATA" --no-create-home --shell "$nologin" "$SVC"
	fi
	changed "system user $SVC"
}

ensure_dirs() {
	if [ ! -d "$DATA" ]; then
		install -d -m 0700 -o "$SVC" -g "$SVC" "$DATA"
		changed "$DATA"
	elif [ "$(stat -c %U "$DATA")" != "$SVC" ]; then
		die "$DATA exists but is not owned by $SVC – check it by hand"
	fi
	if [ ! -d "$(dirname "$CONF")" ]; then
		install -d -m 0755 "$(dirname "$CONF")"
		changed "$(dirname "$CONF")"
	fi
}

# ensure_config creates the config from the example, or keeps the existing one.
ensure_config() {
	local data_dir pub
	if [ -f "$CONF" ]; then
		config_text="kept $CONF (install.sh never changes an existing config)"
		$config_opts && warn "$CONF exists – --tls-names, --admin-listen, --allowed-networks and --acme were not applied; edit it by hand"
		pub=$(config_value "$CONF" public listen)
		if $port80 && [ "$pub" != ":80" ] && [ "${pub##*:}" != 80 ]; then
			warn "--public-port-80: set public.listen to \":80\" in $CONF yourself"
		fi
		if [ -n "$opt_acme" ] && [ "$(config_value "$CONF" acme base_url)" != "$opt_acme" ]; then
			warn "--acme: set acme.base_url: \"$opt_acme\", acme.listen: \":$acme_port\" and acme.tls_issuer: \"$opt_acme_ca\" in $CONF yourself"
		fi
	else
		defaults
		render_config "$work/x/deploy/config.example.yaml" >"$work/config.yaml"
		install -m 0640 -o root -g "$SVC" "$work/config.yaml" "$CONF.new"
		as_service "$work/x/myownpki" config check --config "$CONF.new" >/dev/null ||
			{ rm -f "$CONF.new"; die "the new config does not pass config check – nothing written"; }
		mv -f "$CONF.new" "$CONF"
		changed "$CONF"
		config_text="created $CONF:
    admin.listen:           \"$admin_listen\"
    admin.tls_names:        \"$tls_names\"
    admin.allowed_networks: \"$allowed\"
    public.listen:          \"$public_listen\""
		if [ -n "$opt_acme" ]; then
			config_text+="
    acme.base_url:          \"$opt_acme\"
    acme.listen:            \":$acme_port\"
    acme.tls_issuer:        \"$opt_acme_ca\""
		fi
	fi
	data_dir=$(config_value "$CONF" "" data_dir)
	[ "$data_dir" = "$DATA" ] ||
		die "$CONF has data_dir $data_dir; the unit and install.sh use $DATA – change one of them by hand"
}

install_units() {
	unit_changed=false
	put "$work/x/deploy/systemd/myownpki.service" "$UNIT" 0644 root root
	if $put_changed; then unit_changed=true; fi
	# Ports below 1024: low-ports.conf – unless the old public-port-80.conf
	# (v0.2.1, the same content) is installed; that one stays.
	if $low_ports && [ ! -f "$OLD_LOWPORTS" ]; then
		put "$work/x/deploy/systemd/low-ports.conf" "$LOWPORTS" 0644 root root
		if $put_changed; then unit_changed=true; fi
	fi
	if $unit_changed; then systemctl daemon-reload; fi
	if ! systemctl is-enabled --quiet "$SVC.service" 2>/dev/null; then
		systemctl enable --quiet "$SVC.service"
		changed "enabled $SVC.service"
	fi
}

healthy() {
	for _ in $(seq 1 30); do
		if as_service "$BIN" healthcheck --config "$CONF" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	return 1
}

# update: backup with the old binary, swap, restart, health check, roll back.
# It returns only when the service is healthy and runs new_version.
update() {
	local old_version stamp backup running
	old_version=$("$BIN" --version | awk '{ print $2 }')
	say "Update $old_version → $new_version"
	as_service "$work/x/myownpki" config check --config "$CONF" >/dev/null ||
		die "$CONF does not pass config check of $new_version – nothing changed (see: $work/x/myownpki config check)"
	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	backup=$BACKUPS/${stamp}-${old_version}
	install -d -m 0700 -o "$SVC" -g "$SVC" "$BACKUPS"
	say "Backup to $backup …"
	as_service "$BIN" backup "$backup" --config "$CONF" >/dev/null || die "backup failed – nothing changed"
	as_service "$BIN" backup verify "$backup" >/dev/null || die "backup verify failed for $backup – nothing changed"
	changed "backup $backup"
	install -m 0755 "$BIN" "$BIN.previous"
	if ! swap_binary; then rollback "the new binary was not installed"; fi
	install_units
	say "Restarting $SVC.service …"
	systemctl restart "$SVC.service" || warn "systemctl restart $SVC failed"
	if ! healthy; then rollback "$new_version is not healthy"; fi
	running=$(running_version)
	if [ "$running" != "$new_version" ]; then
		rollback "the service runs ${running:-an unknown version}, not $new_version"
	fi
	say "Healthy, running $new_version. The server starts sealed – unseal it in the browser."
	say "Backup: $backup (the previous binary: $BIN.previous)"
}

# rollback REASON: after a failed update, the previous binary back and a
# restart; it always ends install.sh with an error. Uses update's
# old_version, stamp and backup.
rollback() {
	warn "$1 – putting $old_version back"
	if ! install -m 0755 "$BIN.previous" "$BIN.new" || ! mv -f "$BIN.new" "$BIN"; then
		die "could not put $BIN.previous back as $BIN – do it by hand, then systemctl restart $SVC. Backup: $backup"
	fi
	systemctl restart "$SVC.service" || true
	if healthy && [ "$(running_version)" = "$old_version" ]; then
		die "rolled back to $old_version, which is healthy again; see journalctl -u $SVC. Backup: $backup"
	fi
	die "rolled back to $old_version, but it is not healthy either – the new version may have migrated the
  databases. Restore the backup taken before the update:
    systemctl stop $SVC
    mv $DATA $DATA.failed-$stamp
    install -d -m 0700 -o $SVC -g $SVC $DATA
    runuser -u $SVC -- $BIN restore $backup --config $CONF
    systemctl start $SVC"
}

next_steps() {
	local host port
	host=$(config_value "$CONF" admin tls_names)
	host=${host%%,*}
	port=$(config_value "$CONF" admin listen)
	port=${port##*:}
	cat <<EOF

Next steps – the service is enabled but not started:

1. Create the instance, at this terminal, as the service user. It asks for the
   unseal passphrase and the first admin, and shows the recovery key – write
   it down (docs/OPERATIONS.md §3):

     runuser -u $SVC -- $BIN init --config $CONF

2. Start the service:

     systemctl start $SVC

3. The admin certificate's fingerprint – compare it with what the browser shows:

     journalctl -u $SVC -o cat | grep fingerprint_sha256

4. Open https://${host:-<this host>}:${port:-9443}/ , sign in, and unseal (banner → Unseal).
EOF
	if [ -n "$(config_value "$CONF" acme tls_issuer)" ]; then
		cat <<EOF

5. ACME with its own TLS: at the unseal the server issues the certificate of
   $(config_value "$CONF" acme base_url) from CA $(config_value "$CONF" acme tls_issuer). Add a domain under
   ACME → Domains; clients need your root as trust anchor (docs/OPERATIONS.md 10.10).
EOF
	fi
}

main() {
	parse_args "$@"
	[ "$(uname -s)" = Linux ] || die "Linux only"
	[ "$(id -u)" -eq 0 ] || die "run it as root (sudo bash install.sh)"
	local t
	for t in systemctl tar sha256sum install getent useradd runuser awk cmp stat; do
		command -v "$t" >/dev/null 2>&1 || die "$t not found"
	done
	cd /
	work=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-install.XXXXXX")
	trap 'rm -rf "$work"' EXIT

	fetch
	unpack
	ensure_user
	ensure_dirs
	ensure_config

	local had_binary=false initialized=false binary_differs=true
	[ -f "$BIN" ] && had_binary=true
	[ -f "$DATA/system.db" ] && initialized=true
	if $had_binary && cmp -s "$work/x/myownpki" "$BIN"; then binary_differs=false; fi

	if $had_binary && $initialized && $binary_differs; then
		update
	else
		swap_binary || die "$BIN is not $new_version after the copy – check the file system"
		install_units
		if $initialized && $unit_changed && systemctl is-active --quiet "$SVC.service"; then
			warn "the unit changed – restart when convenient: systemctl restart $SVC (the server starts sealed)"
		fi
	fi

	say ""
	say "MyOwnPKI $new_version for linux/$(arch) from $source_text"
	say "  SHA-256:   ok (checksums.txt)"
	say "  Signature: $signature"
	say "  Config:    $config_text"
	for t in "$LOWPORTS" "$OLD_LOWPORTS"; do
		if [ -f "$t" ]; then say "  Low ports: drop-in $t (CAP_NET_BIND_SERVICE)"; fi
	done
	if [ ${#changes[@]} -eq 0 ]; then
		say "  Changes:   none – everything was already in place"
	else
		say "  Changes:"
		printf '    %s\n' "${changes[@]}"
	fi
	if ! $initialized; then next_steps; fi
}

# Sourcing the file (tests) defines the functions without running anything.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
