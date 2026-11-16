#!/usr/bin/env bash
# Shared functions of scripts/upgrade (PHASE3 §19.5): the pinned list of old
# release assets, the checksum helper and the names of the assets of a release.
# Sourced by fetch.sh, pin-release.sh and test/upgrade/run.sh; defines functions
# and a few defaults only, runs nothing.

# The repository's release download base (the asset URL is $base/v<V>/<asset>).
# shellcheck disable=SC2034 # used by the scripts that source this file
upgrade_default_base_url=https://github.com/Der-Felix/MyOwnPKI/releases/download

# upgrade_root: the repository root (the directory above scripts/).
upgrade_root() {
  (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
}

# upgrade_releases_file: the pinned list (UPGRADE_RELEASES overrides it for tests).
upgrade_releases_file() {
  printf '%s\n' "${UPGRADE_RELEASES:-$(upgrade_root)/scripts/upgrade/releases.txt}"
}

# sha256_file FILE: lower case hex SHA-256.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# release_entries: the list without comments and empty lines.
release_entries() {
  grep -Ev '^[[:space:]]*(#|$)' "$(upgrade_releases_file)" || true
}

# release_versions: every version of the list once, in file order.
release_versions() {
  release_entries | awk '!seen[$1]++ { print $1 }'
}

# release_sha VERSION ASSET: the pinned SHA-256, empty when the pair is not listed.
release_sha() {
  release_entries | awk -v v="$1" -v a="$2" '$1 == v && $2 == a { print $3; exit }'
}

# release_has VERSION: success when the version is in the list.
release_has() {
  release_entries | awk -v v="$1" '$1 == v { found = 1 } END { exit !found }'
}

# asset_name KIND VERSION: the release asset a kind of file has (Linux amd64 only).
#   server    the server archive        myownpki_<V>_linux_amd64.tar.gz
#   agent     the agent archive         myownpki-agent_<V>_linux_amd64.tar.gz (from 0.3.0)
#   install   the installation script   install.sh (from 0.2.2)
#   checksums the signed checksum file  checksums.txt
#   packages  the six agent packages    myownpki-agent_<V>_linux_<amd64|arm64>.<deb|rpm|tar.gz>, one name per line
#             (0.3.5 or newer; the install.sh of 0.3.1 and newer wants all six next to --archive)
asset_name() {
  case $1 in
    packages)
      local arch format
      for arch in amd64 arm64; do
        for format in deb rpm tar.gz; do
          printf 'myownpki-agent_%s_linux_%s.%s\n' "$2" "$arch" "$format"
        done
      done
      ;;
    server) printf 'myownpki_%s_linux_amd64.tar.gz\n' "$2" ;;
    agent) printf 'myownpki-agent_%s_linux_amd64.tar.gz\n' "$2" ;;
    install) printf 'install.sh\n' ;;
    checksums) printf 'checksums.txt\n' ;;
    *) return 1 ;;
  esac
}

# version_ge A B: success when version A >= B (dotted numbers, as 0.3.10 >= 0.3.5).
version_ge() {
  local IFS=. a b i
  # shellcheck disable=SC2206 # split on dots on purpose
  a=($1)
  # shellcheck disable=SC2206
  b=($2)
  for i in 0 1 2; do
    if [ "${a[i]:-0}" -gt "${b[i]:-0}" ]; then return 0; fi
    if [ "${a[i]:-0}" -lt "${b[i]:-0}" ]; then return 1; fi
  done
  return 0
}

# url_of_dir DIR: a file:// URL of a directory, for the self-tests (curl on Git for
# Windows wants C:/… in the URL, Linux and macOS the plain path).
url_of_dir() {
  local d
  d=$(cd "$1" && { pwd -W 2>/dev/null || pwd; })
  case $d in
    /*) printf 'file://%s\n' "$d" ;;
    *) printf 'file:///%s\n' "$d" ;;
  esac
}

# curl_download URL FILE: the one place that downloads. https only (a file:// base
# is for the self-tests), TLS 1.2 or newer, three retries; the caller verifies
# the SHA-256 before it uses the file.
curl_download() {
  local url=$1 out=$2 proto='=https'
  case $url in file://*) proto='=file' ;; esac
  curl --fail --location --silent --show-error --proto "$proto" --proto-redir "$proto" \
    --tlsv1.2 --retry 3 --output "$out" "$url"
}
