#!/usr/bin/env bash
# Pin a release for the upgrade test (PHASE3 §19.5, step 108). Run by the owner
# after each release (and once for the versions of the first list).
#
#   pin-release.sh vX.Y.Z [--write] [--no-cosign]   print the lines of releases.txt for a release
#   pin-release.sh --self-test
#
# It downloads checksums.txt and its cosign bundle (checksums.txt.sigstore.json)
# of the release, verifies the signature with `cosign verify-blob` against the
# identity of the release workflow for exactly that tag, and takes the SHA-256
# of the server archive, the agent archive and install.sh from the signed file
# (checksums.txt itself is pinned by its own hash). The lines are printed for
# review; --write puts them into scripts/upgrade/releases.txt (the lines of that
# version are replaced, the file stays in version order).
#
# cosign is optional: without it the script stops and says so; --no-cosign goes
# on with the hashes of the TLS connection to github.com alone and prints a
# warning. Environment: COSIGN (the cosign command, default cosign),
# UPGRADE_BASE_URL (a file:// URL in the self-test), UPGRADE_RELEASES.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/upgrade/lib.sh
. "$here/lib.sh"

die() {
  echo "pin-release: $*" >&2
  exit 1
}

cosign=${COSIGN:-cosign}
base=${UPGRADE_BASE_URL:-$upgrade_default_base_url}
repo_identity='https://github.com/Der-Felix/MyOwnPKI/.github/workflows/release.yml'
oidc_issuer='https://token.actions.githubusercontent.com'

# pin_lines VERSION CHECKSUMS: the releases.txt lines of one release from its
# (verified) checksums.txt; checksums.txt itself is hashed locally.
pin_lines() {
  local version=$1 sums=$2 kind asset sha
  for kind in server agent install; do
    asset=$(asset_name "$kind" "$version")
    sha=$(awk -v a="$asset" '$2 == a { print $1 }' "$sums")
    [ -n "$sha" ] || continue
    printf '%s' "$sha" | grep -Eq '^[0-9a-f]{64}$' || die "checksums.txt has no valid SHA-256 for $asset"
    printf '%s %s %s\n' "$version" "$asset" "$sha"
  done
  printf '%s checksums.txt %s\n' "$version" "$(sha256_file "$sums")"
}

# write_lines VERSION LINES: replace the lines of VERSION in releases.txt.
write_lines() {
  local version=$1 lines=$2 file tmp
  file=$(upgrade_releases_file)
  tmp=$(mktemp "${TMPDIR:-/tmp}/upgrade-releases.XXXXXX")
  {
    grep -E '^[[:space:]]*#' "$file" || true
    { { grep -Ev '^[[:space:]]*(#|$)' "$file" || true; } | awk -v v="$version" '$1 != v'; printf '%s\n' "$lines"; } |
      sort -s -t. -k1,1n -k2,2n -k3,3n
  } >"$tmp"
  mv "$tmp" "$file"
}

pin() {
  local tag=$1 write=$2 use_cosign=$3 version work lines
  printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "$tag is not a release tag vX.Y.Z"
  version=${tag#v}
  work=$(mktemp -d "${TMPDIR:-/tmp}/upgrade-pin.XXXXXX")
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$work'" EXIT
  curl_download "$base/$tag/checksums.txt" "$work/checksums.txt" || die "cannot download checksums.txt of $tag"
  if [ "$use_cosign" = 1 ]; then
    command -v "$cosign" >/dev/null 2>&1 || die "cosign was not found (COSIGN=$cosign). Install it (https://github.com/sigstore/cosign/releases) or pass --no-cosign to rely on the TLS connection to github.com alone"
    curl_download "$base/$tag/checksums.txt.sigstore.json" "$work/checksums.txt.sigstore.json" ||
      die "$tag has no checksums.txt.sigstore.json: the signature cannot be verified"
    "$cosign" verify-blob --bundle "$work/checksums.txt.sigstore.json" \
      --certificate-identity "$repo_identity@refs/tags/$tag" --certificate-oidc-issuer "$oidc_issuer" \
      "$work/checksums.txt" >&2 || die "the signature of checksums.txt of $tag is not valid for the release workflow – nothing is pinned"
  else
    echo "pin-release: WARNING: the signature of checksums.txt was NOT verified (--no-cosign)" >&2
  fi
  lines=$(pin_lines "$version" "$work/checksums.txt")
  printf '%s\n' "$lines"
  if [ "$write" = 1 ]; then
    write_lines "$version" "$lines"
    echo "pin-release: $(upgrade_releases_file) has the lines of $version now – review them with git diff" >&2
  fi
}

self_test() {
  local work out sums
  work=$(mktemp -d "${TMPDIR:-/tmp}/upgrade-pin-test.XXXXXX")
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$work'" EXIT
  mkdir -p "$work/serve/v9.9.9"
  sums=$work/serve/v9.9.9/checksums.txt
  {
    echo "$(printf 'a%.0s' $(seq 1 64))  install.sh"
    echo "$(printf 'b%.0s' $(seq 1 64))  myownpki-agent_9.9.9_linux_amd64.tar.gz"
    echo "$(printf 'c%.0s' $(seq 1 64))  myownpki-agent_9.9.9_linux_arm64.tar.gz"
    echo "$(printf 'd%.0s' $(seq 1 64))  myownpki_9.9.9_linux_amd64.tar.gz"
    echo "$(printf 'e%.0s' $(seq 1 64))  myownpki_9.9.9_windows_amd64.zip"
  } >"$sums"
  export UPGRADE_BASE_URL UPGRADE_RELEASES="$work/releases.txt"
  UPGRADE_BASE_URL=$(url_of_dir "$work/serve")
  printf '# header\n0.3.5 install.sh %s\n10.0.0 install.sh %s\n' "$(printf '1%.0s' $(seq 1 64))" "$(printf '2%.0s' $(seq 1 64))" >"$work/releases.txt"
  me=$here/pin-release.sh

  out=$(bash "$me" v9.9.9 --no-cosign 2>/dev/null) || die "self-test: pinning failed"
  [ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 4 ] || die "self-test: want four lines (server, agent, install, checksums), got: $out"
  printf '%s\n' "$out" | grep -q "^9.9.9 myownpki_9.9.9_linux_amd64.tar.gz $(printf 'd%.0s' $(seq 1 64))\$" || die "self-test: the server line is wrong: $out"
  printf '%s\n' "$out" | grep -q "^9.9.9 checksums.txt $(sha256_file "$sums")\$" || die "self-test: checksums.txt is not pinned by its own hash"
  if printf '%s\n' "$out" | grep -q 'arm64\|windows'; then die "self-test: a file of another platform was pinned"; fi

  # Without cosign (and without --no-cosign) nothing is printed.
  if COSIGN=/nonexistent/cosign bash "$me" v9.9.9 >/dev/null 2>&1; then die "self-test: pinning without cosign and without --no-cosign worked"; fi

  # --write replaces the lines of the version and keeps the numeric order.
  bash "$me" v9.9.9 --no-cosign --write >/dev/null 2>&1 || die "self-test: --write failed"
  bash "$me" v9.9.9 --no-cosign --write >/dev/null 2>&1 || die "self-test: --write twice failed"
  [ "$(grep -c '^9.9.9 ' "$work/releases.txt")" = 4 ] || die "self-test: --write twice doubled the lines"
  [ "$(awk '!/^#/ { print $1 }' "$work/releases.txt" | uniq | tr '\n' ' ')" = '0.3.5 9.9.9 10.0.0 ' ] || die "self-test: the list is not in version order"
  [ "$(head -n 1 "$work/releases.txt")" = '# header' ] || die "self-test: the header comment was lost"

  # A tag that is not a release.
  if bash "$me" 9.9.9 --no-cosign >/dev/null 2>&1; then die "self-test: a bare version was accepted"; fi
  echo "pin-release self-test: ok"
}

tag=
write=0
use_cosign=1
while [ "$#" -gt 0 ]; do
  case $1 in
    --write) write=1 ;;
    --no-cosign) use_cosign=0 ;;
    --self-test) self_test; exit 0 ;;
    -h | --help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$0"; exit 0 ;;
    -*) echo "pin-release: unknown option $1" >&2; exit 2 ;;
    *) [ -z "$tag" ] || { echo 'pin-release: one tag only' >&2; exit 2; }; tag=$1 ;;
  esac
  shift
done
[ -n "$tag" ] || { echo 'usage: pin-release.sh vX.Y.Z [--write] [--no-cosign] | --self-test' >&2; exit 2; }
pin "$tag" "$write" "$use_cosign"
