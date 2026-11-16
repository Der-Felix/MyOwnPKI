#!/usr/bin/env bash
# Fetch the old release files of the upgrade test (PHASE3 §19.5, step 108).
#
#   fetch.sh [--offline] [--cache DIR] VERSION [KIND...]   fetch and verify; print the path of each file
#   fetch.sh [--offline] [--cache DIR] --all               every version and kind of releases.txt
#                                                          (only the versions of UPGRADE_ONLY, when it is set)
#   fetch.sh --list                                        the pinned list
#   fetch.sh --self-test                                   try it against a local directory
#
# KIND is server (default), agent, install, checksums or packages (the six agent packages, pinned only
# for the previous release: the install.sh of 0.3.x wants them next to --archive). VERSION is a bare
# number, 0.3.12, and must be in scripts/upgrade/releases.txt: there is no
# "latest". Every file is downloaded to <cache>/<version>/<name>.part, compared
# with the SHA-256 of releases.txt and only then moved into place; a mismatch
# deletes the file and fails. A file already in the cache is compared again
# every time. Nothing downloaded is ever run by this script.
#
# Environment: UPGRADE_CACHE (default .tools/upgrade/cache), UPGRADE_OFFLINE=1
# (same as --offline: no network, a missing file is exit 3, "skip"),
# UPGRADE_BASE_URL (default the GitHub release download URL; a file:// URL is
# for the self-test), UPGRADE_RELEASES (the list).
#
# Exit status: 0 done, 1 error (mismatch, unknown version), 2 usage,
# 3 a file is missing and --offline forbids the download.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/upgrade/lib.sh
. "$here/lib.sh"

die() {
  echo "fetch: $*" >&2
  exit 1
}

cache=${UPGRADE_CACHE:-$(upgrade_root)/.tools/upgrade/cache}
offline=${UPGRADE_OFFLINE:-0}
base=${UPGRADE_BASE_URL:-$upgrade_default_base_url}

# fetch_one VERSION KIND: print the verified path of every asset of the kind (the packages
# kind has six); returns 3 (offline) or 4 (not in the list), or exits 1.
fetch_one() {
  local version=$1 kind=$2 names asset rc=0
  names=$(asset_name "$kind" "$version") || die "unknown kind $kind (server, agent, install, checksums, packages)"
  while IFS= read -r asset; do
    fetch_asset "$version" "$asset" || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
  done <<<"$names"
}

# fetch_asset VERSION ASSET: one file of the list.
fetch_asset() {
  local version=$1 asset=$2 want dir file got
  release_has "$version" || die "version $version is not in $(upgrade_releases_file) – there is no \"latest\"; add it with scripts/upgrade/pin-release.sh"
  want=$(release_sha "$version" "$asset")
  if [ -z "$want" ]; then
    echo "fetch: $version has no $asset in the list (the release has no such file)" >&2
    return 4
  fi
  dir=$cache/$version
  file=$dir/$asset
  mkdir -p "$dir"
  if [ -f "$file" ]; then
    got=$(sha256_file "$file")
    if [ "$got" = "$want" ]; then
      printf '%s\n' "$file"
      return 0
    fi
    echo "fetch: $file does not match the pinned SHA-256 – deleted" >&2
    rm -f "$file"
  fi
  if [ "$offline" = 1 ]; then
    echo "fetch: $asset of $version is not in the cache and the network is off (task upgrade:fetch)" >&2
    return 3
  fi
  rm -f "$file.part"
  curl_download "$base/v$version/$asset" "$file.part" || { rm -f "$file.part"; die "download of $asset of $version failed"; }
  got=$(sha256_file "$file.part")
  if [ "$got" != "$want" ]; then
    rm -f "$file.part"
    die "$asset of $version has SHA-256 $got, pinned is $want – refused and deleted"
  fi
  mv "$file.part" "$file"
  printf '%s\n' "$file"
}

# kinds_of VERSION: the kinds the list has for a version.
kinds_of() {
  local kind
  for kind in server agent install checksums packages; do
    [ -z "$(release_sha "$1" "$(asset_name "$kind" "$1" | head -n 1)")" ] || printf '%s\n' "$kind"
  done
}

cmd_all() {
  local version kind rc=0 only=${UPGRADE_ONLY:-}
  for version in $(release_versions); do
    # UPGRADE_ONLY (as for test/upgrade/run.sh) narrows the versions: one matrix job fetches only its own.
    if [ -n "$only" ]; then
      case ",${only// /,}," in *",$version,"*) ;; *) continue ;; esac
    fi
    for kind in $(kinds_of "$version"); do
      fetch_one "$version" "$kind" >/dev/null || rc=$?
      [ "$rc" -ne 1 ] || exit 1
    done
  done
  [ "$rc" -eq 0 ] || exit "$rc"
  echo "fetch: every file of $(upgrade_releases_file) is in $cache and matches its SHA-256"
}

cmd_self_test() {
  local work out rc
  work=$(mktemp -d "${TMPDIR:-/tmp}/upgrade-fetch-test.XXXXXX")
  # shellcheck disable=SC2064 # the directory is fixed now
  trap "rm -rf '$work'" EXIT
  mkdir -p "$work/serve/v9.9.9"
  printf 'server archive\n' >"$work/serve/v9.9.9/myownpki_9.9.9_linux_amd64.tar.gz"
  printf 'agent archive\n' >"$work/serve/v9.9.9/myownpki-agent_9.9.9_linux_amd64.tar.gz"
  printf 'echo hello\n' >"$work/serve/v9.9.9/install.sh"
  printf 'sums\n' >"$work/serve/v9.9.9/checksums.txt"
  for n in $(asset_name packages 9.9.9); do printf 'package %s\n' "$n" >"$work/serve/v9.9.9/$n"; done
  {
    echo '# test list'
    for kind in server agent install checksums packages; do
      for n in $(asset_name "$kind" 9.9.9); do
        echo "9.9.9 $n $(sha256_file "$work/serve/v9.9.9/$n")"
      done
    done
  } >"$work/releases.txt"
  # A pinned hash that the served file does not have: a list of its own.
  echo "8.8.8 $(asset_name server 8.8.8) $(printf '0%.0s' $(seq 1 64))" >"$work/bad.txt"
  mkdir -p "$work/serve/v8.8.8"
  printf 'something else\n' >"$work/serve/v8.8.8/myownpki_8.8.8_linux_amd64.tar.gz"
  export UPGRADE_RELEASES="$work/releases.txt" UPGRADE_CACHE="$work/cache" UPGRADE_BASE_URL
  UPGRADE_BASE_URL=$(url_of_dir "$work/serve")
  unset UPGRADE_OFFLINE
  me=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fetch.sh

  out=$(bash "$me" 9.9.9) || die "self-test: a pinned file was not fetched"
  [ "$(bash "$me" 9.9.9 packages | wc -l | tr -d ' ')" = 6 ] || die "self-test: the packages kind did not give six files"
  [ "$out" = "$work/cache/9.9.9/myownpki_9.9.9_linux_amd64.tar.gz" ] || die "self-test: unexpected path $out"
  [ "$(bash "$me" 9.9.9 packages | wc -l | tr -d ' ')" = 6 ] || die "self-test: the packages kind did not give six files"
  bash "$me" --all >/dev/null || die "self-test: --all failed"
  UPGRADE_ONLY=7.7.7 bash "$me" --all >/dev/null || die "self-test: --all with an UPGRADE_ONLY that names no listed version failed"

  # Second run offline: the cache answers without the network.
  UPGRADE_BASE_URL=file:///nonexistent bash "$me" --offline --all >/dev/null || die "self-test: the cache did not answer offline"

  # A file that changed in the cache is refused offline and replaced online.
  printf 'tampered\n' >"$work/cache/9.9.9/install.sh"
  rc=0
  UPGRADE_BASE_URL=file:///nonexistent bash "$me" --offline 9.9.9 install >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 3 ] || die "self-test: a tampered cache file was accepted offline (status $rc)"
  bash "$me" 9.9.9 install >/dev/null || die "self-test: a tampered cache file was not replaced online"
  [ "$(cat "$work/cache/9.9.9/install.sh")" = 'echo hello' ] || die "self-test: the replacement is not the served file"

  # A download with another hash is refused and leaves nothing behind.
  rc=0
  UPGRADE_RELEASES="$work/bad.txt" bash "$me" 8.8.8 >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 1 ] || die "self-test: a wrong hash was accepted (status $rc)"
  [ ! -e "$work/cache/8.8.8/myownpki_8.8.8_linux_amd64.tar.gz" ] || die "self-test: the refused file stayed in the cache"
  [ ! -e "$work/cache/8.8.8/myownpki_8.8.8_linux_amd64.tar.gz.part" ] || die "self-test: the .part file stayed"

  # A version that is not in the list, "latest", a kind the release does not have.
  for bad in 7.7.7 latest; do
    rc=0
    bash "$me" "$bad" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || die "self-test: version $bad was accepted (status $rc)"
  done
  rc=0
  UPGRADE_RELEASES="$work/bad.txt" bash "$me" 8.8.8 agent >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 4 ] || die "self-test: a kind that the release does not have gave status $rc, not 4"
  echo "fetch self-test: ok"
}

list_only=0
all=0
args=()
while [ "$#" -gt 0 ]; do
  case $1 in
    --offline) offline=1 ;;
    --cache) [ "$#" -ge 2 ] || { echo 'fetch: --cache needs a directory' >&2; exit 2; }; cache=$2; shift ;;
    --list) list_only=1 ;;
    --all) all=1 ;;
    --self-test) cmd_self_test; exit 0 ;;
    -h | --help) sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$0"; exit 0 ;;
    -*) echo "fetch: unknown option $1" >&2; exit 2 ;;
    *) args+=("$1") ;;
  esac
  shift
done

if [ "$list_only" = 1 ]; then
  release_entries
  exit 0
fi
if [ "$all" = 1 ]; then
  cmd_all
  exit 0
fi
[ "${#args[@]}" -ge 1 ] || { echo 'usage: fetch.sh [--offline] [--cache DIR] VERSION [KIND...] | --all | --list | --self-test' >&2; exit 2; }
version=${args[0]}
kinds=("${args[@]:1}")
[ "${#kinds[@]}" -gt 0 ] || kinds=(server)
rc=0
for kind in "${kinds[@]}"; do
  fetch_one "$version" "$kind" || { rc=$?; break; }
done
exit "$rc"
