#!/usr/bin/env bash
# The wire format of the agent protocol stays compatible (docs/PHASE3.md §19.5, step 115):
# `buf breaking` (WIRE_JSON, buf.yaml) of this tree against
#   - origin/main, as before;
#   - the last release of scripts/upgrade/releases.txt, on every run: an agent of that
#     release must keep talking to the server of this tree ("update the server first");
#   - the tag v0.3.0, the baseline of the protocol, with --nightly.
# Only the direction "old agent, new server" is promised and checked (docs/OPERATIONS.md
# §9). A new agent against an old server is not: it happens only after a server rollback.
#
#   check-agent-protocol.sh             main and the last release
#   check-agent-protocol.sh --nightly   also v0.3.0
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=scripts/upgrade/lib.sh
. scripts/upgrade/lib.sh

nightly=false
case ${1:-} in
  '') ;;
  --nightly) nightly=true ;;
  *) echo 'usage: check-agent-protocol.sh [--nightly]' >&2; exit 2 ;;
esac

# against_tag TAG: fetch the tag when the checkout has no tags (CI checks out one commit)
# and compare with it.
against_tag() {
  local tag=$1
  if ! git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    git fetch --no-tags --depth=1 origin "+refs/tags/$tag:refs/tags/$tag"
  fi
  if ! git cat-file -e "$tag:buf.yaml" 2>/dev/null; then
    echo "$tag has no agent protocol (no buf.yaml): nothing to compare" >&2
    return 1
  fi
  echo "agent protocol against $tag"
  go run ./internal/tools/buf breaking --against ".git#tag=$tag"
}

git fetch --no-tags origin main:refs/remotes/origin/main
if git cat-file -e origin/main:buf.yaml 2>/dev/null; then
  echo 'agent protocol against origin/main'
  go run ./internal/tools/buf breaking --against '.git#branch=origin/main'
else
  echo 'main has no agent protocol yet; the introduction in v0.3.0 is the compatibility baseline'
fi

last=$(release_versions | tail -n 1)
[ -n "$last" ] || { echo 'scripts/upgrade/releases.txt lists no release' >&2; exit 1; }
against_tag "v$last"
if $nightly; then
  against_tag v0.3.0
fi
