#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the files of this directory are sourced into one shell and share its variables
# The assertions A1 to A10 of PHASE3 §19.5. Sourced by run.sh after populate.sh;
# runs nothing by itself. Every assertion records PASS, FAIL or SKIP and goes on:
# one version shows all its problems at once. Inputs as in populate.sh, plus
# NEW_BIN, NEW_AGENT_BIN, SAME_BINARY (1 when the "old" binary is the new one: the
# smoke run) and the facts of populate.sh.

# --- A1: the schema, before and after the start -----------------------------------------

# released_count KIND VERSION: how many migration files of KIND the release VERSION
# shipped, from the pin file (internal/store/testdata/released-migrations.txt).
released_count() {
  local kind=$1 version=$2 k v name sha rel n=0
  while read -r k v name sha rel; do
    [ "$k" = "$kind" ] || continue
    if version_ge "$version" "${rel#v}"; then n=$((n + 1)); fi
  done < <(grep -Ev '^[[:space:]]*(#|$)' "${PIN_FILE:-$ROOT/internal/store/testdata/released-migrations.txt}")
  printf '%s\n' "$n"
}

# tree_count KIND: the migration files of KIND in this tree.
tree_count() {
  find "${SCHEMA_DIR:-$ROOT/internal/store/schema}/$1" -name '*.sql' -type f | wc -l | tr -d ' '
}

# expected_pending_exit VERSION: the exit status `db status` of this tree's binary
# has on the data of VERSION: 3 when a database kind has files the release did not
# ship, else 0.
expected_pending_exit() {
  local kind
  for kind in audit pki system; do
    if [ "$(tree_count "$kind")" -gt "$(released_count "$kind" "$1")" ]; then
      echo 3
      return 0
    fi
  done
  echo 0
}

assert_a1_before() {
  local want out rc=0
  want=$(expected_pending_exit "$P_VERSION")
  EXPECTED_PENDING=$want
  [ "$SAME_BINARY" != 1 ] || want=0
  out=$("$NEW_BIN" db status --config "$CFG" 2>&1) || rc=$?
  if [ "$rc" != "$want" ]; then
    fail A1 "db status before the start exits $rc, want $want"
    printf '%s\n' "$out" | tail -n 12 | sed 's/^/        | /'
  elif [ "$want" = 3 ] && ! printf '%s' "$out" | grep -q 'pending'; then
    fail A1 "db status exits 3 but does not say pending"
  elif printf '%s' "$out" | grep -qE 'PROBLEM|ErrModified|applied migration was modified'; then
    fail A1 "db status reports a problem on the old data"
    printf '%s\n' "$out" | grep -E 'PROBLEM|modified' | sed 's/^/        | /'
  else
    pass A1 "db status before the start: exit $rc$([ "$want" = 3 ] && echo ', pending')"
  fi
}

assert_a1_after() {
  local out rc=0 ok
  out=$("$NEW_BIN" db status --config "$CFG" 2>&1) || rc=$?
  ok=$(printf '%s\n' "$out" | grep -c 'up to date')
  if [ "$rc" != 0 ] || [ "$ok" -lt 4 ] || printf '%s' "$out" | grep -qE 'pending|PROBLEM'; then
    fail A1 "db status after the start: exit $rc, $ok databases up to date (want 4)"
    printf '%s\n' "$out" | tail -n 12 | sed 's/^/        | /'
  else
    pass A1 "after the start every database is up to date (exit 0, no ErrModified, no ErrNewer)"
  fi
}

# --- A2: the old binary refuses migrated data ---------------------------------------------

assert_a2() {
  local before after out rc=0 rc2=0
  if [ "$SAME_BINARY" = 1 ]; then
    skip A2 "the old and the new binary are the same (smoke run): nothing is newer"
    return 0
  fi
  if [ "$EXPECTED_PENDING" = 0 ]; then
    skip A2 "this tree has the schema of $P_VERSION: the databases are not newer"
    return 0
  fi
  # A server that was stopped hard leaves a WAL behind, and the first opener folds it into the file: let the
  # new binary do that before the snapshot, so that only the refused old start can change a file.
  "$NEW_BIN" db migrate --config "$CFG" >/dev/null 2>&1 || true
  before=$(db_fingerprint "$DATA")
  out=$("$OLD_BIN" db status --config "$CFG" 2>&1) || rc=$?
  if [ "$rc" != 1 ] || ! printf '%s' "$out" | grep -q 'newer version'; then
    fail A2 "the old db status exits $rc and says: $(printf '%s' "$out" | grep -E 'PROBLEM' | head -n 1)"
    return 0
  fi
  # The server must not start either (it would otherwise run on a schema it does not know).
  timeout 60 "$OLD_BIN" serve --config "$CFG" >"$T/old-refuses.log" 2>&1 || rc2=$?
  after=$(db_fingerprint "$DATA")
  if [ "$rc2" = 0 ] || [ "$rc2" = 124 ]; then
    fail A2 "the old serve did not stop with an error (exit $rc2)"
  elif ! grep -q 'newer version' "$T/old-refuses.log"; then
    fail A2 "the old serve stopped (exit $rc2) without the newer-version text"
    tail -n 5 "$T/old-refuses.log" | sed 's/^/        | /'
  elif [ "$before" != "$after" ]; then
    fail A2 "the refused old start changed a database file"
  else
    pass A2 "the old binary refuses the migrated data (newer-version text) and changes no file"
  fi
}

# --- A3: certificates, CRL, CAs ------------------------------------------------------------

# serial_of FILE: the serial of a certificate, upper case, no leading zeros.
serial_of() {
  openssl x509 -in "$1" -noout -serial | sed 's/^serial=//' | tr '[:lower:]' '[:upper:]' | sed 's/^0*//'
}

# check_facts ID LABEL: the facts about certificates and CAs against the instance the
# API helpers point at (running, unsealed, signed in): new server, restored copy or rolled-back old one.
check_facts() {
  local id=$1 label=$2 d=$T/facts-$1 root_id issuing_id crl_now revoked_out bad=0 why=
  mkdir -p "$d"
  root_id=$(ca_id root)
  issuing_id=$(ca_id issuing)
  [ -n "$root_id" ] && [ -n "$issuing_id" ] || { fail "$id" "$label: the CAs root and issuing are not there"; return 0; }
  api_get_file "/cas/$root_id/certificate?format=pem" "$d/root.pem"
  api_get_file "/cas/$issuing_id/certificate?format=pem" "$d/issuing.pem"
  api_get_file "/certificates/$F_LEAF_ID/download/pem" "$d/leaf.pem"
  api_get_file "/certificates/$F_REV_ID/download/pem" "$d/revoked.pem"
  api_get_file "/cas/$issuing_id/crl?format=pem" "$d/crl.pem"
  if [ "$(fingerprint_pem "$d/root.pem")" != "$F_ROOT_FP" ] || [ "$(fingerprint_pem "$d/issuing.pem")" != "$F_ISSUING_FP" ]; then
    bad=1 why="a CA certificate changed"
  fi
  # The leaf verifies against the unchanged chain and is not revoked by the CRL of the issuing CA …
  if ! openssl verify -purpose sslserver -crl_check -CAfile "$d/root.pem" -untrusted "$d/issuing.pem" -CRLfile "$d/crl.pem" "$d/leaf.pem" 2>&1 | grep -q ': OK'; then
    bad=1 why="the certificate from before the update no longer verifies"
  fi
  # … the revoked one is revoked in it, and the CRL carries the signature of the issuing CA.
  # openssl exits with 2 for a revoked certificate: read its words, not its status.
  revoked_out=$(openssl verify -purpose sslserver -crl_check -CAfile "$d/root.pem" -untrusted "$d/issuing.pem" -CRLfile "$d/crl.pem" "$d/revoked.pem" 2>&1 || true)
  if ! printf '%s' "$revoked_out" | grep -q 'certificate revoked'; then
    bad=1 why="the revoked certificate is not revoked in the CRL"
  fi
  if ! openssl crl -in "$d/crl.pem" -CAfile "$d/issuing.pem" -noout -verify 2>&1 | grep -q 'verify OK'; then
    bad=1 why="the signature of the CRL does not verify"
  fi
  if [ "$(serial_of "$d/leaf.pem")" != "$(printf '%s' "$F_LEAF_SERIAL" | tr '[:lower:]' '[:upper:]' | sed 's/^0*//')" ]; then
    bad=1 why="the certificate has another serial than before"
  fi
  crl_now=$(crl_number "$d/crl.pem")
  if [ "$crl_now" -lt "$F_CRL_NUMBER" ]; then
    bad=1 why="the CRL number went down ($crl_now < $F_CRL_NUMBER)"
  fi
  if [ "$bad" = 0 ]; then
    pass "$id" "$label: leaf verifies, revoked certificate is in the CRL (signature ok, number $crl_now >= $F_CRL_NUMBER), CA fingerprints unchanged"
  else
    fail "$id" "$label: $why"
  fi
}


# --- A4: the audit chains ---------------------------------------------------------------------

# check_audit ID LABEL BIN CONFIG HEAD_INSTANCE HEAD_TENANT: the old head is a prefix of the chain.
check_audit() {
  local id=$1 label=$2 bin=$3 cfg=$4 hi=$5 ht=$6 scope head out bad=0
  for scope in instance tenant:default; do
    head=$hi
    [ "$scope" = instance ] || head=$ht
    if ! out=$("$bin" audit verify --config "$cfg" --scope "$scope" --expect-head "$head" --checkpoint-key "$F_CKEY" 2>&1); then
      bad=1
      printf '%s\n' "$out" | tail -n 6 | sed 's/^/        | /'
    fi
  done
  if [ "$bad" = 0 ]; then
    pass "$id" "$label: audit verify with the old head and the checkpoint key passes for instance and tenant:default"
  else
    fail "$id" "$label: audit verify failed (the old log is no prefix, or the checkpoint key does not fit)"
  fi
}

# --- A5: ACME again ---------------------------------------------------------------------------

directory_urls() {
  curl -sS --noproxy '*' --max-time 10 --cacert "$T/root.pem" "https://127.0.0.1:$ACME_PORT/acme/directory" |
    grep -oE '"(newNonce|newAccount|newOrder|revokeCert|keyChange)":"[^"]*"' | LC_ALL=C sort
}

assert_a5() {
  if [ "$(assertion_applies A5)" != yes ]; then skip A5 "$(assertion_applies A5)"; return 0; fi
  if [ -n "$ACME_SKIP" ]; then skip A5 "$ACME_SKIP"; return 0; fi
  local after
  after=$(directory_urls) || true
  if [ "$after" != "$DIRECTORY_BEFORE" ]; then
    fail A5 "the ACME directory changed its endpoints"
    return 0
  fi
  wait_until 60 acme_ready || { fail A5 "the ACME listener does not serve a certificate the root verifies after the update"; return 0; }
  if run_lego acme2.upgrade.lan && verify_acme_cert "$LEGO_CERT" acme2.upgrade.lan; then
    pass A5 "a second issuance with the account of the old lego works; the directory has the same endpoints"
  else
    fail A5 "lego could not issue after the update (see $T/lego-acme2.upgrade.lan.log)"
  fi
}

# --- A6: domain rule and history -----------------------------------------------------------------

assert_a6() {
  if [ "$(assertion_applies A6)" != yes ]; then skip A6 "$(assertion_applies A6)"; return 0; fi
  local bad=0 etag_now
  api GET /domains || { fail A6 "GET /domains: $(problem)"; return 0; }
  grep -q '"name":"upgrade.lan"' "$tmp/api.json" || bad=1
  api GET "/domains/$F_DOMAIN_ID" || bad=1
  grep -q '"include_subdomains":true' "$tmp/api.json" && grep -q '"approval":"open"' "$tmp/api.json" || bad=1
  if [ "$bad" = 1 ]; then
    fail A6 "the domain rule upgrade.lan does not read back as it was made"
    return 0
  fi
  if [ "$P_PASS" = 1 ] && [ -z "$AGENT_SKIP" ]; then
    api GET /agent-join-tokens || bad=1
    grep -q "\"label\":\"$F_PASS_LABEL\"" "$tmp/api.json" || bad=1
    [ "$bad" = 0 ] || { fail A6 "the enrollment pass '$F_PASS_LABEL' is not in the list after the update"; return 0; }
  fi
  if [ "$P_SETTINGS" != 1 ]; then
    pass A6 "the domain rule reads back (no history before 0.3.10)"
    return 0
  fi
  # A version that was made before the update stays readable, and the old ETag still works.
  api GET "/domains/$F_DOMAIN_ID/versions" || bad=1
  grep -q '"version":' "$tmp/api.json" || bad=1
  api GET /settings/versions || bad=1
  grep -q '"version":' "$tmp/api.json" || bad=1
  etag_now=$(api_etag "/domains/$F_DOMAIN_ID")
  [ "$etag_now" = "$F_DOMAIN_ETAG" ] || { fail A6 "the domain ETag changed over the update ($F_DOMAIN_ETAG, now $etag_now)"; return 0; }
  api_with_header PATCH "/domains/$F_DOMAIN_ID" '{"validity_days":50}' "If-Match: $F_DOMAIN_ETAG" || bad=1
  api GET /settings || bad=1
  cp "$tmp/api.json" "$T/settings-after.json"
  api_with_header PUT /settings "$(cat "$T/settings-after.json")" "If-Match: $F_SETTINGS_ETAG" || bad=1
  if [ "$bad" = 1 ]; then
    fail A6 "the history of the domain or the settings, or a change with the old ETag, does not work: $(problem)"
  else
    pass A6 "the domain rule and its history read back; a PATCH and a PUT with the ETags from before the update work"
  fi
}

# --- A7: the old agent keeps running ----------------------------------------------------------------

# agents_refresh: GET /agents; a session that ended during the long wait is replaced by a new sign-in.
agents_refresh() {
  agents_json && return 0
  signed_in=0
  sign_in
  agents_json
}

# agent_seen_after BASE: success when the agent's last report is newer than BASE;
# AGENT_SEEN and AGENT_VERSION_NOW hold what the list said.
agent_seen_after() {
  agents_refresh || true
  AGENT_SEEN=$(agent_field last_seen_at)
  AGENT_VERSION_NOW=$(agent_field version)
  [[ -n "$AGENT_SEEN" && "$AGENT_SEEN" > "$1" ]]
}

# agent_wait SECONDS: poll every 10 seconds; stops early when the agent process ends.
agent_wait() {
  local i
  for ((i = 0; i < $1; i += 10)); do
    agent_seen_after "$A7_BASE" && return 0
    kill -0 "$AGENT_PID" 2>/dev/null || return 2
    sleep 10
  done
  return 1
}

# The wait is the one slow part of the test: the agent reports every 270 to 330
# seconds, and the update can fall right after a report. A slow report must not
# make a run flaky, a broken agent must still fail it:
#   1. UPGRADE_AGENT_WAIT seconds (default 480: one full cycle plus the restart);
#   2. when nothing came, the log of the agent decides: "agent report failed" lines
#      mean the new server refuses the old agent - FAIL at once, with the lines;
#   3. no failed report: the agent is only slow - UPGRADE_AGENT_GRACE more seconds
#      (default 150), then FAIL. A report of the agent counts however late it is.
assert_a7() {
  if [ "$(assertion_applies A7)" != yes ]; then skip A7 "$(assertion_applies A7)"; return 0; fi
  if [ -n "$AGENT_SKIP" ]; then skip A7 "$AGENT_SKIP"; return 0; fi
  local wait=${UPGRADE_AGENT_WAIT:-480} grace=${UPGRADE_AGENT_GRACE:-150} rc=0
  sign_in
  kill -0 "$AGENT_PID" 2>/dev/null || { fail A7 "the old agent process is gone"; return 0; }
  note "waiting up to ${wait}s for the next report of the old agent (it reports every 4.5 to 5.5 minutes)"
  agent_wait "$wait" || rc=$?
  if [ "$rc" = 1 ]; then
    if grep -q 'agent report failed' "$T/agent/run.log"; then
      fail A7 "the old agent's reports to the new server fail"
      grep 'agent report failed' "$T/agent/run.log" | tail -n 3 | cut -c1-300 | sed 's/^/        | /'
      return 0
    fi
    note "no report yet and none failed: the agent is slow, waiting up to ${grace}s more"
    rc=0
    agent_wait "$grace" || rc=$?
  fi
  case $rc in
    0)
      if [ "$AGENT_VERSION_NOW" != "$F_AGENT_VERSION" ]; then
        fail A7 "the agent's version changed from $F_AGENT_VERSION to $AGENT_VERSION_NOW"
      else
        pass A7 "the old agent ($AGENT_VERSION_NOW) kept reporting: last_seen $A7_BASE -> $AGENT_SEEN"
      fi
      ;;
    2) fail A7 "the old agent process stopped" ;;
    *)
      fail A7 "the old agent did not report to the new server within $((wait + grace))s (last seen ${AGENT_SEEN:-never})"
      tail -n 8 "$T/agent/run.log" | cut -c1-300 | sed 's/^/        | /'
      ;;
  esac
}


# --- A8: the pre-update backup with the new binary ----------------------------------------------------

assert_a8() {
  local data2=$T/data2 cfg2=$T/config2.yaml admin2 public2 out
  pick_port admin2
  pick_port public2
  mkdir -p "$T/second"
  write_config "$cfg2" "$data2" "$admin2" "$public2"
  if ! out=$("$NEW_BIN" backup verify "$BACKUP_PRE" --checkpoint-key "$F_CKEY" 2>&1); then
    fail A8 "backup verify of the pre-update backup failed"
    printf '%s\n' "$out" | tail -n 6 | sed 's/^/        | /'
    return 0
  fi
  if ! out=$("$NEW_BIN" restore "$BACKUP_PRE" --config "$cfg2" --checkpoint-key "$F_CKEY" 2>&1); then
    fail A8 "restore of the pre-update backup with the new binary failed"
    printf '%s\n' "$out" | tail -n 6 | sed 's/^/        | /'
    return 0
  fi
  # The copy runs on its own ports; the secrets file of the original instance still fits (same users, same key ring).
  server_start "$NEW_BIN" "$cfg2" "$T/second/server.log"
  if ! wait_until 90 server_healthy "$NEW_BIN" "$cfg2"; then
    fail A8 "the new binary does not start on the restored pre-update backup (see $T/second/server.log)"
    server_stop
    return 0
  fi
  api_use "$admin2" "$T/second/api" "$SECRETS"
  unseal
  check_facts A8 "restored pre-update backup, new binary"
  check_audit A8 "restored pre-update backup, new binary" "$NEW_BIN" "$cfg2" "$F_BACKUP_HEAD_instance" "$F_BACKUP_HEAD_tenant"
  server_stop
  SERVER_PID=$MAIN_PID
  api_use "$MAIN_ADMIN_PORT" "$T/api" "$SECRETS"
  # A backup made after the update verifies (the main instance runs the new binary).
  if out=$("$NEW_BIN" backup "$T/backup-post" --config "$CFG" 2>&1) && "$NEW_BIN" backup verify "$T/backup-post" --checkpoint-key "$F_CKEY" >/dev/null 2>&1; then
    pass A8 "a backup made after the update verifies"
  else
    fail A8 "a backup made after the update does not verify: $(printf '%s' "$out" | tail -n 3)"
  fi
}

# --- A9: rollback ------------------------------------------------------------------------------------------

assert_a9() {
  local out
  # The data of the new version is moved away, the pre-update backup restored by the OLD binary.
  mv "$DATA" "$T/data-after-update"
  if ! out=$("$OLD_BIN" restore "$BACKUP_PRE" --config "$CFG" --checkpoint-key "$F_CKEY" 2>&1); then
    fail A9 "the old binary cannot restore the pre-update backup"
    printf '%s\n' "$out" | tail -n 6 | sed 's/^/        | /'
    return 0
  fi
  server_start "$OLD_BIN" "$CFG" "$T/rollback-server.log"
  if ! wait_until 90 server_healthy "$OLD_BIN" "$CFG"; then
    fail A9 "the old binary does not start on the restored data (see $T/rollback-server.log)"
    server_stop
    return 0
  fi
  api_use "$MAIN_ADMIN_PORT" "$T/api-rollback" "$SECRETS"
  unseal
  check_facts A9 "rollback to $P_VERSION"
  check_audit A9 "rollback to $P_VERSION" "$OLD_BIN" "$CFG" "$F_BACKUP_HEAD_instance" "$F_BACKUP_HEAD_tenant"
  server_stop
}

# --- A10: the old config ----------------------------------------------------------------------------------------

assert_a10() {
  local out bad=0
  if ! out=$("$NEW_BIN" config check --config "$CFG" 2>&1); then
    bad=1
    printf '%s\n' "$out" | tail -n 8 | sed 's/^/        | /'
  fi
  if [ "$P_AGENT" = 1 ] && [ -z "$AGENT_SKIP" ] && [ -x "${NEW_AGENT_BIN:-}" ]; then
    if ! out=$("$NEW_AGENT_BIN" config check --config "$AGENT_CFG" 2>&1); then
      bad=1
      printf '%s\n' "$out" | tail -n 8 | sed 's/^/        | /'
    fi
  fi
  if [ "$bad" = 0 ]; then
    pass A10 "the new binaries accept the old config.yaml$([ "$P_AGENT" = 1 ] && [ -z "$AGENT_SKIP" ] && echo ' and agent.yaml')"
  else
    fail A10 "a key of the old configuration is refused by the new binary"
  fi
}
