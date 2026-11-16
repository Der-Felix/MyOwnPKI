#!/usr/bin/env bash
# The update of a systemd installation made by an OLD release, as root on a disposable
# runner (PHASE3 §19.5, step 113): for 0.2.2 (the first with install.sh and the backup timer)
# and the previous release (the newest of scripts/upgrade/releases.txt) the release's own
# install.sh and archive come from the cache of scripts/upgrade/fetch.sh (SHA-256 pinned,
# downloaded when missing), and the install.sh of this tree updates them
# (test/install/upgrade_systemd_test.sh). Needs the snapshot build in dist/ (the job `install`).
#
#   UPGRADE_OFFLINE=1   no download: a missing file is a SKIP line, exit 0
#   UPGRADE_ONLY=0.3.12 only these versions of the two
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
# shellcheck source=scripts/upgrade/lib.sh
. scripts/upgrade/lib.sh
ci_require_disposable
ci_refuse_existing_server

archive=$(find dist -maxdepth 1 -name 'myownpki_*_linux_amd64.tar.gz' | head -n 1)
[ -n "$archive" ] || { echo 'no snapshot archive in dist/ (scripts/ci/install-snapshot.sh)' >&2; exit 1; }

versions=(0.2.2)
last=$(release_versions | tail -n 1)
[ "$last" = 0.2.2 ] || versions+=("$last")
only=${UPGRADE_ONLY:-}
skipped=0
for v in "${versions[@]}"; do
  if [ -n "$only" ]; then
    case ",${only// /,}," in *",$v,"*) ;; *) continue ;; esac
  fi
  rc=0
  old_archive=$(bash scripts/upgrade/fetch.sh "$v" server) || rc=$?
  if [ "$rc" -eq 0 ]; then
    # install.sh and checksums.txt: the second one must lie next to the archive (install.sh checks it).
    extra=$(bash scripts/upgrade/fetch.sh "$v" install checksums) || rc=$?
    old_install=$(printf '%s\n' "$extra" | head -n 1)
  fi
  # The install.sh of 0.3.1 and newer wants the six agent packages next to --archive.
  if [ "$rc" -eq 0 ] && version_ge "$v" 0.3.1; then
    if [ -z "$(release_sha "$v" "$(asset_name packages "$v" | head -n 1)")" ]; then
      echo "the agent packages of $v are not pinned: bash scripts/upgrade/pin-release.sh v$v --write --packages" >&2
      exit 1
    fi
    bash scripts/upgrade/fetch.sh "$v" packages >/dev/null || rc=$?
  fi
  if [ "$rc" -eq 3 ]; then
    echo "SKIP: the release files of $v are not in the cache and the network is off (task upgrade:fetch)"
    skipped=$((skipped + 1))
    continue
  fi
  [ "$rc" -eq 0 ] || exit "$rc"
  echo "=== update from $v ($old_archive)"
  sudo --preserve-env=GITHUB_ACTIONS,GITHUB_STEP_SUMMARY \
    bash test/install/upgrade_systemd_test.sh "$v" "$old_archive" "$old_install" "$archive"
done
[ "$skipped" -eq 0 ] || echo "upgrade-systemd: $skipped version(s) skipped (a skip is not a pass)"
