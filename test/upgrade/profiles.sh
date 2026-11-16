#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the files of this directory are sourced into one shell and share its variables
# Capability profiles of the upgrade test (PHASE3 §19.5, step 112): what a start
# version can do, so the harness populates only what that version has and says
# so for the rest. Sourced by run.sh; defines functions, runs nothing.
#
# The capabilities (set by profile_load VERSION, all 0 or 1):
#   P_ACME       0.2.2  ACME server with its own TLS listener (acme.tls_issuer), the way
#                       the harness reaches it; 0.2.0 and 0.2.1 need a TLS proxy and are
#                       no start versions
#   P_DOMAIN     0.2.0  domain rules (REST /domains)
#   P_AGENT      0.3.0  agent listener, agent archive, enrollment
#   P_PASS       0.3.5  enrollment passes (join tokens of kind "pass")
#   P_SETTINGS   0.3.10 versioned settings and domains (ETag, /settings/versions)
#   P_INSTALL    0.2.2  install.sh in the release (step 113)

# profile_load VERSION: set the P_* variables.
profile_load() {
  local v=$1
  P_VERSION=$v
  P_ACME=0 P_DOMAIN=0 P_AGENT=0 P_PASS=0 P_SETTINGS=0 P_INSTALL=0
  version_ge "$v" 0.2.0 && P_DOMAIN=1
  version_ge "$v" 0.2.2 && { P_ACME=1; P_INSTALL=1; }
  version_ge "$v" 0.3.0 && P_AGENT=1
  version_ge "$v" 0.3.5 && P_PASS=1
  version_ge "$v" 0.3.10 && P_SETTINGS=1
  return 0
}

# profile_line: the profile on one line, for the log and the dry run.
profile_line() {
  printf 'acme=%s domain=%s agent=%s pass=%s settings_versions=%s' "$P_ACME" "$P_DOMAIN" "$P_AGENT" "$P_PASS" "$P_SETTINGS"
}

# assertion_ids: every assertion of PHASE3 §19.5 in order of the plan.
assertion_ids() {
  printf '%s\n' A1 A2 A3 A4 A5 A6 A7 A8 A9 A10
}

# assertion_text ID: what the assertion checks, in one line.
assertion_text() {
  case $1 in
    A1) echo 'db status before the start: exit 3 and pending (exit 0 for the same schema); after the start every database up to date' ;;
    A2) echo 'the old binary refuses the migrated data (newer-version text) and changes nothing' ;;
    A3) echo 'the pre-update leaf verifies, the revoked one is revoked in the CRL, CRL number not lower, CA fingerprints unchanged' ;;
    A4) echo 'audit verify with the old head and the checkpoint key passes for every scope' ;;
    A5) echo 'a second ACME issuance with the old lego account works; the directory keeps its endpoints' ;;
    A6) echo 'the domain rule reads back; from 0.3.10 its history and a PATCH with the old ETag work' ;;
    A7) echo 'the old agent keeps running: last_seen advances, version unchanged' ;;
    A8) echo 'backup verify and restore of the pre-update backup with the new binary; start, unseal, A3 and A4 again; a new backup verifies' ;;
    A9) echo 'rollback: restore the pre-update backup with the old binary, start, unseal, same facts' ;;
    A10) echo 'config check of the new binary accepts the old config.yaml (and agent.yaml)' ;;
    *) return 1 ;;
  esac
}

# assertion_applies ID: print "yes", or the reason in words when the profile has
# nothing to check (the harness then prints a SKIP line). Run-time reasons (no
# lego, no port 80, offline) come on top of this in run.sh.
assertion_applies() {
  case $1 in
    A5)
      [ "$P_ACME" = 1 ] || { echo "needs ACME with its own TLS listener (0.2.2 or newer); this version has none"; return 0; }
      ;;
    A6)
      [ "$P_DOMAIN" = 1 ] || { echo "needs domain rules (0.2.0 or newer); this version has none"; return 0; }
      ;;
    A7)
      [ "$P_AGENT" = 1 ] || { echo "needs the agent (0.3.0 or newer); this version has none"; return 0; }
      ;;
  esac
  echo yes
}
