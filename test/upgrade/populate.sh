#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2154 # the files of this directory are sourced into one shell and share its variables
# Populate an instance made by an OLD release (PHASE3 §19.5): what a real
# installation holds by the time its owner updates. Sourced by run.sh after
# lib.sh, instance.sh and profiles.sh; runs nothing by itself.
#
# Inputs (set by run.sh): OLD_BIN, OLD_AGENT_BIN, CFG, DATA, T (scratch dir of the
# version), PUBLIC_PORT, ACME_PORT, AGENT_PORT, DNS_PORT, HOSTIP, LEGO_BIN and the
# P_* capabilities. Outputs: the F_* facts below, also written to $T/facts.txt.
#
# Facts of the old instance, used by the assertions after the update:
#   F_CKEY            checkpoint key fingerprint printed by `init`
#   F_ROOT_FP, F_ISSUING_FP   SHA-256 of the CA certificates
#   F_LEAF_ID, F_LEAF_SERIAL  a certificate that stays valid
#   F_REV_ID, F_REV_SERIAL    a certificate that was revoked
#   F_CRL_NUMBER      the CRL number after the revocation
#   F_DOMAIN_ID, F_DOMAIN_ETAG   the domain rule and its version (0.3.10)
#   F_SETTINGS_ETAG   the settings version (0.3.10)
#   F_AGENT_ID, F_AGENT_VERSION, F_AGENT_SEEN   the agent and its last report
#   F_PASS_LABEL      the enrollment pass (0.3.5)
#   F_HEAD_instance, F_HEAD_tenant   audit heads when the old server was stopped
#   F_BACKUP_HEAD_instance, F_BACKUP_HEAD_tenant   audit heads in the pre-update backup

# facts_write: dump the F_* variables.
facts_write() {
  (set -o posix 2>/dev/null; set) | grep '^F_' >"$T/facts.txt" || true
}

# --- init and the first start -----------------------------------------------------

populate_init() {
  local out
  say "init $P_VERSION: a demo instance with a test root and an issuing CA"
  out=$("$OLD_BIN" init --demo --with-ca --ca-base-url "http://127.0.0.1:$PUBLIC_PORT" --config "$CFG" 2>&1) ||
    die "init of $P_VERSION failed: $(printf '%s' "$out" | tail -n 5)"
  F_CKEY=$(printf '%s\n' "$out" | parse_checkpoint_key)
  [ -n "$F_CKEY" ] || die "init printed no checkpoint key fingerprint"
  [ -f "$DATA/init-demo-secrets.txt" ] || die "init wrote no demo secrets file"
  note "checkpoint key $F_CKEY"
}

# --- certificates by REST ------------------------------------------------------------

# issue_rest NAME HOST: a CSR made here, issued through POST /certificates, the
# certificate saved as $T/NAME.pem; sets ISSUED_ID and ISSUED_SERIAL.
issue_rest() {
  local name=$1 host=$2 csr body
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/$name.key" -out "$T/$name.csr" \
    -subj "/CN=$host" -addext "subjectAltName=DNS:$host" >/dev/null 2>&1 || die "openssl could not make a CSR for $host"
  csr=$(pem_to_json_string "$T/$name.csr")
  body="{\"ca_id\":\"$ISSUING_ID\",\"preset\":\"server\",\"subject\":{\"common_name\":\"$host\"},\"csr_pem\":\"$csr\"}"
  api POST /certificates "$body" || die "issuing $host was refused: $(problem)"
  ISSUED_ID=$(json_first id "$tmp/api.json")
  ISSUED_SERIAL=$(json_first serial "$tmp/api.json")
  [ -n "$ISSUED_ID" ] && [ -n "$ISSUED_SERIAL" ] || die "the answer to the issuance of $host has no id or serial"
  api_get_file "/certificates/$ISSUED_ID/download/pem" "$T/$name.pem"
}

# fetch_cas: the ids and certificates of the two CAs of the test PKI.
fetch_cas() {
  ROOT_ID=$(ca_id root)
  ISSUING_ID=$(ca_id issuing)
  [ -n "$ROOT_ID" ] && [ -n "$ISSUING_ID" ] || die "the instance has no CAs named root and issuing"
  api_get_file "/cas/$ROOT_ID/certificate?format=pem" "$T/root.pem"
  api_get_file "/cas/$ISSUING_ID/certificate?format=pem" "$T/issuing.pem"
  F_ROOT_FP=$(fingerprint_pem "$T/root.pem")
  F_ISSUING_FP=$(fingerprint_pem "$T/issuing.pem")
}

populate_certificates() {
  say "two certificates by REST, one revoked"
  fetch_cas
  issue_rest leaf rest-ok.upgrade.lan
  F_LEAF_ID=$ISSUED_ID
  F_LEAF_SERIAL=$ISSUED_SERIAL
  issue_rest revoked rest-revoked.upgrade.lan
  F_REV_ID=$ISSUED_ID
  F_REV_SERIAL=$ISSUED_SERIAL
  step_up
  api POST "/certificates/$F_REV_ID/revoke" '{"reason":"cessationOfOperation"}' || die "the revocation was refused: $(problem)"
  api_get_file "/cas/$ISSUING_ID/crl?format=pem" "$T/crl.pem"
  F_CRL_NUMBER=$(crl_number "$T/crl.pem")
  note "CRL number $F_CRL_NUMBER; revoked serial $F_REV_SERIAL"
}

# --- domain rule, ACME, settings -----------------------------------------------------

# acme_ready: the ACME listener serves the certificate of the issuing CA (after the unseal).
acme_ready() {
  curl -sS --noproxy '*' --max-time 5 --cacert "$T/root.pem" -o /dev/null "https://127.0.0.1:$ACME_PORT/acme/directory"
}

# run_lego NAME: one http-01 issuance with lego; the account lives in $T/lego.
run_lego() {
  local name=$1
  LEGO_CA_CERTIFICATES="$T/root.pem" LEGO_LOG_FORMAT=text NO_PROXY='*' no_proxy='*' \
    "$LEGO_BIN" run --server "https://127.0.0.1:$ACME_PORT/acme/directory" --path "$T/lego" \
    --email admin@upgrade.lan --accept-tos --domains "$name" --http --http.address :80 --no-random-sleep >"$T/lego-$name.log" 2>&1 ||
    { tail -n 20 "$T/lego-$name.log" >&2; return 1; }
  LEGO_CERT=$(find "$T/lego" -name "$name.crt" | head -n 1)
  [ -n "$LEGO_CERT" ] || return 1
}

# verify_acme_cert FILE HOST: the certificate names HOST and verifies against the old chain.
verify_acme_cert() {
  local chain=$1 host=$2 leaf
  leaf=$T/acme-leaf.pem
  openssl x509 -in "$chain" -out "$leaf" || return 1
  openssl x509 -in "$leaf" -noout -ext subjectAltName | grep -q "DNS:$host" || return 1
  openssl verify -purpose sslserver -CAfile "$T/root.pem" -untrusted "$T/issuing.pem" "$leaf" | grep -q ': OK'
}

populate_domain() {
  say "a domain rule"
  step_up
  api POST /domains "{\"name\":\"upgrade.lan\",\"ca_id\":\"$ISSUING_ID\",\"include_subdomains\":true,\"challenge_types\":[\"http-01\"],\"approval\":\"open\",\"address_policy\":\"internal\"}" ||
    die "the domain was refused: $(problem)"
  F_DOMAIN_ID=$(json_first id "$tmp/api.json")
  [ -n "$F_DOMAIN_ID" ] || die "the domain answer has no id"
  if [ "$P_SETTINGS" = 1 ]; then
    # A second state, so that the history has a version before the update.
    api PATCH "/domains/$F_DOMAIN_ID" '{"validity_days":45}' || die "changing the domain was refused: $(problem)"
  fi
}

populate_acme() {
  say "one ACME issuance with lego (the account stays in $T/lego)"
  wait_until 60 acme_ready || die "the ACME listener does not serve a certificate that the root verifies"
  run_lego acme1.upgrade.lan || die "lego could not get a certificate (see $T/lego-acme1.upgrade.lan.log)"
  verify_acme_cert "$LEGO_CERT" acme1.upgrade.lan || die "the ACME certificate does not verify against the old chain"
  note "issued acme1.upgrade.lan"
}

populate_settings() {
  say "a settings change (versioned from 0.3.10)"
  api GET /settings || die "cannot read the settings: $(problem)"
  # A real change, so that 0.3.10 and newer store a version: allow_server_keygen flips.
  if grep -q '"allow_server_keygen":true' "$tmp/api.json"; then
    sed 's/"allow_server_keygen":true/"allow_server_keygen":false/' "$tmp/api.json" >"$T/settings-changed.json"
  else
    sed 's/"allow_server_keygen":false/"allow_server_keygen":true/' "$tmp/api.json" >"$T/settings-changed.json"
  fi
  step_up
  api PUT /settings "$(cat "$T/settings-changed.json")" || die "changing the settings was refused: $(problem)"
}

# --- agent ----------------------------------------------------------------------------

# populate_agent_ca: agent-ca below the root; the server needs a restart with the
# agent listener in its config afterwards (done by run.sh with write_config).
populate_agent_ca() {
  say "agent CA (an intermediate for client certificates)"
  step_up
  api POST /cas "{\"name\":\"agent-ca\",\"kind\":\"intermediate\",\"parent_ca_id\":\"$ROOT_ID\",\"subject\":{\"common_name\":\"Upgrade Test Agent CA\"},\"public_base_url\":\"http://127.0.0.1:$PUBLIC_PORT\",\"eku_limit\":[\"clientAuth\"]}" ||
    die "the agent CA was refused: $(problem)"
}

# agents_json: GET /agents into $T/agents.json.
agents_json() {
  api_get_file /agents "$T/agents.json"
}

# agent_field FIELD: a value of the first agent of the list ("" when none).
agent_field() {
  json_first "$1" "$T/agents.json"
}

agent_registered() {
  agents_json && grep -q "\"hostname\":\"$AGENT_HOST\"" "$T/agents.json"
}

agent_reported() {
  agents_json && grep -q "\"last_seen_at\":\"" "$T/agents.json"
}

populate_agent() {
  say "agent enrollment (manual mode, approved by an admin)"
  mkdir -p "$T/agent/state" "$T/agent/webroot"
  AGENT_HOST=agent1.upgrade.lan
  AGENT_CFG=$T/agent/agent.yaml
  write_agent_config "$AGENT_CFG" "$T/agent/state" "$AGENT_PORT" "$T/root.pem" "$AGENT_HOST" "$T/agent/webroot"
  "$OLD_AGENT_BIN" config check --config "$AGENT_CFG" >/dev/null 2>&1 || die "the old agent refuses its own minimal agent.yaml"
  # manual: an admin decides every enrollment (the setting needs a fresh second factor).
  api GET /settings || die "cannot read the settings: $(problem)"
  sed 's/"agent_enrollment":"[a-z]*"/"agent_enrollment":"manual"/' "$tmp/api.json" >"$T/settings-manual.json"
  step_up
  api PUT /settings "$(cat "$T/settings-manual.json")" || die "setting the enrollment mode was refused: $(problem)"
  "$OLD_AGENT_BIN" enroll --config "$AGENT_CFG" >"$T/agent/enroll.log" 2>&1 || {
    tail -n 10 "$T/agent/enroll.log" >&2
    die "the old agent could not start its enrollment"
  }
  api_get_file /agent-enrollments "$T/agent/enrollments.json"
  local id
  id=$(grep -o "\"id\":\"[^\"]*\",\"hostname\":\"$AGENT_HOST\"" "$T/agent/enrollments.json" | head -n 1 | cut -d'"' -f4)
  [ -n "$id" ] || die "the enrollment of $AGENT_HOST is not in the queue"
  step_up
  api POST "/agent-enrollments/$id/approve" '{}' || die "the approval was refused: $(problem)"
  bg_start "$T/agent/run.log" "$OLD_AGENT_BIN" run --config "$AGENT_CFG"
  AGENT_PID=$BG_LAST
  note "the agent polls every 30 seconds; waiting for its first report"
  wait_until 240 agent_reported || { tail -n 10 "$T/agent/run.log" >&2; die "the agent did not report within four minutes"; }
  F_AGENT_ID=$(agent_field id)
  F_AGENT_VERSION=$(agent_field version)
  F_AGENT_SEEN=$(agent_field last_seen_at)
  note "agent $F_AGENT_ID version $F_AGENT_VERSION last seen $F_AGENT_SEEN"
}

populate_pass() {
  say "an enrollment pass"
  step_up
  F_PASS_LABEL="upgrade pass"
  api POST /agent-join-tokens "{\"kind\":\"pass\",\"label\":\"$F_PASS_LABEL\",\"names\":[\"pass1.upgrade.lan\"],\"valid_hours\":24,\"max_uses\":3}" ||
    die "the enrollment pass was refused: $(problem)"
}

# --- audit entry, backup, quiet --------------------------------------------------------

# populate_etags: the versions of the domain and the settings as the old server leaves them, taken after
# the last change (0.3.10: every change stores a version; the ETag is the number of the newest).
populate_etags() {
  [ "$P_SETTINGS" = 1 ] || return 0
  F_DOMAIN_ETAG=$(api_etag "/domains/$F_DOMAIN_ID")
  F_SETTINGS_ETAG=$(api_etag /settings)
  [ -n "$F_DOMAIN_ETAG" ] && [ -n "$F_SETTINGS_ETAG" ] || die "the domain or the settings have no ETag"
  note "ETags: domain $F_DOMAIN_ETAG, settings $F_SETTINGS_ETAG"
}

populate_audit_entry() {
  # A failed sign-in is an audit entry that no other step makes.
  say "an audit entry of its own (a failed sign-in)"
  curl -sS --noproxy '*' --insecure --max-time 30 -o /dev/null -X POST -H 'Content-Type: application/json' \
    --data '{"username":"upgrade-nobody","password":"not the password"}' "$api_base/auth/login" || true
}

# audit_heads BIN CONFIG: "scope head" lines of `audit verify`.
audit_heads() {
  "$1" audit verify --config "$2" | parse_audit_heads
}

populate_backup() {
  local out
  say "the pre-update backup, made by $P_VERSION while it runs"
  BACKUP_PRE=$T/backup-pre
  out=$("$OLD_BIN" backup "$BACKUP_PRE" --config "$CFG" 2>&1) || die "the backup failed: $(printf '%s' "$out" | tail -n 5)"
  F_BACKUP_HEAD_instance=$(printf '%s\n' "$out" | parse_audit_heads | awk '$1 == "instance" { print $2 }')
  F_BACKUP_HEAD_tenant=$(printf '%s\n' "$out" | parse_audit_heads | awk '$1 == "tenant:default" { print $2 }')
  [ -n "$F_BACKUP_HEAD_instance" ] && [ -n "$F_BACKUP_HEAD_tenant" ] || die "the backup output names no audit heads: $out"
  "$OLD_BIN" backup verify "$BACKUP_PRE" --checkpoint-key "$F_CKEY" >/dev/null || die "the old version cannot verify its own backup"
}

# populate_heads: with the old server stopped, the heads of both audit chains.
populate_heads() {
  local heads
  heads=$(audit_heads "$OLD_BIN" "$CFG") || die "audit verify of the old data failed"
  F_HEAD_instance=$(printf '%s\n' "$heads" | awk '$1 == "instance" { print $2 }')
  F_HEAD_tenant=$(printf '%s\n' "$heads" | awk '$1 == "tenant:default" { print $2 }')
  [ -n "$F_HEAD_instance" ] && [ -n "$F_HEAD_tenant" ] || die "audit verify names no heads: $heads"
}
