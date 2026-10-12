#!/usr/bin/env bash
###############################################################################
# lib/ui.sh - Interactive Terminal Menu, Input Helpers, and Guided Wizards
###############################################################################

# All interactive prompts write to stderr so stdout remains clean for pipes.
ask() { # ask <var> <prompt> [default]
    local __ask_v=$1 __ask_p=$2 __ask_d=${3:-} __ask_a
    if [ -n "$__ask_d" ]; then
        printf '%s [%s]: ' "$__ask_p" "$__ask_d" >&2
    else
        printf '%s: ' "$__ask_p" >&2
    fi
    IFS= read -r __ask_a || { printf '\n' >&2; exit 0; }
    __ask_a=$(trim "$__ask_a")
    [ -z "$__ask_a" ] && __ask_a=$__ask_d
    printf -v "$__ask_v" '%s' "$__ask_a"
}

# Prompts for mandatory input
ask_req() {
    local __req_v=$1
    while :; do
        ask "$@"
        [ -n "${!__req_v}" ] && return 0
        warn "This field cannot be empty"
    done
}

# Yes/No prompt (returns 'yes' or 'no')
ask_yn() { # ask_yn <var> <prompt> <y|n>
    local __yn_v=$1 __yn_a __yn_d=${3:-n}
    case $__yn_d in j|ja|y|yes) __yn_d=y ;; *) __yn_d=n ;; esac
    while :; do
        ask __yn_a "$2 (y/n)" "$__yn_d"
        case $(lower "$__yn_a") in
            y|yes|j|ja) printf -v "$__yn_v" yes; return ;;
            n|no|nein)  printf -v "$__yn_v" no; return ;;
        esac
    done
}

# Confirmation prompt (defaults to No)
confirm() {
    local r
    ask_yn r "$1" n
    [ "$r" = yes ]
}

# Selection from numbered menu options
ask_choice() { # ask_choice <var> <prompt> <default> "value|description" ...
    local __ch_v=$1 __ch_p=$2 __ch_d=$3; shift 3
    local __ch_i=1 __ch_o __ch_def="" __ch_a __ch_n
    for __ch_o in "$@"; do
        printf '   %2d) %-18s %s\n' "$__ch_i" "${__ch_o%%|*}" "$( [ "$__ch_o" != "${__ch_o#*|}" ] && printf '%s' "${__ch_o#*|}")" >&2
        [ "${__ch_o%%|*}" = "$__ch_d" ] && __ch_def=$__ch_i
        __ch_i=$((__ch_i+1))
    done
    while :; do
        ask __ch_a "$__ch_p" "$__ch_def"
        if is_int "$__ch_a" && [ "$__ch_a" -ge 1 ] && [ "$__ch_a" -le $# ]; then
            __ch_n=1
            for __ch_o in "$@"; do
                [ "$__ch_n" = "$__ch_a" ] && { printf -v "$__ch_v" '%s' "${__ch_o%%|*}"; return; }
                __ch_n=$((__ch_n+1))
            done
        fi
        # Allow typing option value directly (e.g. "server")
        for __ch_o in "$@"; do
            [ "${__ch_o%%|*}" = "$__ch_a" ] && { printf -v "$__ch_v" '%s' "$__ch_a"; return; }
        done
        warn "Please enter a number 1-$# or the name"
    done
}

# Collects multiple values (comma-separated or line-by-line, blank line finishes)
ask_list() { # ask_list <var> <label> [initial]
    local __ls_v=$1 __ls_l=$2 __ls_acc=${3:-} __ls_a __ls_x
    printf '%s  (separate multiple values with comma or enter line-by-line; empty input = finish)\n' "$__ls_l" >&2
    [ -n "$__ls_acc" ] && printf '  already entered: %s\n' "$__ls_acc" >&2
    while :; do
        printf '  + ' >&2
        IFS= read -r __ls_a || break
        __ls_a=$(trim "$__ls_a")
        [ -z "$__ls_a" ] && break
        split_list "$__ls_a"
        for __ls_x in "${SPLIT[@]}"; do
            __ls_acc=$(add_uniq "$__ls_acc" "$__ls_x")
        done
    done
    printf -v "$__ls_v" '%s' "$__ls_acc"
}

pause() {
    printf '\nPress [Enter] to continue... ' >&2
    IFS= read -r _ || exit 0
}

choose_keytype() { # <var> <default>
    ask_choice "$1" "Select key type" "$2" \
        "rsa2048|compatible & fast (minimum standard)" \
        "rsa3072|recommended for leaf certificates" \
        "rsa4096|recommended for CAs (high security)" \
        "ed25519|modern & compact (NOT for web browsers!)"
}

choose_ca() { # <var>
    local __cc_opts=() __cc_n
    for __cc_n in $(list_intermediates); do
        load_ca_meta "$__cc_n"
        __cc_opts+=("$__cc_n|$M_CN ($M_KEY)")
    done
    __cc_opts+=("root|Root CA directly (only if necessary)" "selfsigned|Self-signed (standalone, no CA hierarchy)")
    ask_choice "$1" "Select issuing CA" "${DEFAULT_CA:-root}" "${__cc_opts[@]}"
}

pick_issued() { # <var> <prompt>
    local __pk_opts=() __pk_n
    for __pk_n in $(list_issued); do
        __pk_opts+=("$__pk_n|$(awk -F'"' '/^PRESET=/{print $2}' "$PKI_DIR/issued/$__pk_n/cert.meta") valid until $(cert_end_date "$PKI_DIR/issued/$__pk_n/cert.pem")")
    done
    [ ${#__pk_opts[@]} -gt 0 ] || die "No certificates have been issued yet"
    ask_choice "$1" "$2" "" "${__pk_opts[@]}"
}

pick_any() { # Leaf, Intermediate, or root
    local __pa_opts=() __pa_n
    __pa_opts+=("root|Root CA")
    for __pa_n in $(list_intermediates); do
        __pa_opts+=("$__pa_n|Intermediate CA")
    done
    for __pa_n in $(list_issued); do
        __pa_opts+=("$__pa_n|$(awk -F'"' '/^PRESET=/{print $2}' "$PKI_DIR/issued/$__pa_n/cert.meta")")
    done
    ask_choice "$1" "$2" "" "${__pa_opts[@]}"
}

###############################################################################
# Interactive Wizards
###############################################################################
i_init() {
    banner "PKI Initialization Wizard"
    [ -f "$PKI_DIR/root/certs/ca.crt" ] && die "A PKI already exists in $PKI_DIR"
    info "PKI directory: $PKI_DIR (change with: pki --dir /path)"

    set_conf_defaults
    section "1. Subject Base Information (applied to all certificates)"
    ask PKI_COUNTRY  "Country Code (2 letters, ISO)" "DE"
    ask PKI_STATE    "State / Province (optional)" ""
    ask PKI_LOCALITY "City / Locality (optional)" ""
    ask_req PKI_ORG  "Organization / Homelab Name" "Homelab"
    ask PKI_OU       "Organizational Unit / OU (optional)" ""
    check_safe Organization "$PKI_ORG"
    check_safe OU "$PKI_OU"
    check_safe Locality "$PKI_LOCALITY"
    check_safe State "$PKI_STATE"

    section "2. Root CA Configuration"
    ask_req R_CN "Common Name of Root CA" "$PKI_ORG Root CA"
    choose_keytype R_KEY rsa4096
    DEFAULT_CA_KEY=$R_KEY
    ask R_DAYS "Validity in days" "$ROOT_DAYS"
    ROOT_DAYS=$R_DAYS
    ask_yn R_PASS "Protect Root key with passphrase? (strongly recommended)" y

    section "3. Global PKI Defaults"
    ask DEFAULT_LEAF_KEY "Default key type for leaf certificates" "rsa3072"
    valid_keytype "$DEFAULT_LEAF_KEY" || die "Invalid key type"
    ask CRL_DAYS "CRL validity in days" "30"
    info "Optional: HTTP URL for publishing CRL and CA certificates (publish/)"
    ask AIA_BASE_URL "AIA/CRL Base URL, e.g. http://pki.lan (empty = none)" ""

    create_root

    section "4. Create Intermediate CAs"
    info "Recommendation: Create at least a 'server-ca' for web and server services."
    local more=yes
    while [ "$more" = yes ]; do
        ask_yn more "Create an Intermediate CA now?" y
        [ "$more" = yes ] || break
        ( i_ca_new_inner ) || warn "Intermediate CA creation skipped"
        load_config
    done
    ok "PKI successfully initialized! You can now issue certificates directly."
}

i_ca_new_inner() {
    N_NAME="" N_CN="" N_KEY="" N_DAYS="" N_PASS=yes N_PATHLEN=0 N_PERMIT_DNS="" N_PERMIT_IP="" N_EKU_LIMIT="" N_OCSP_URL=""
    ask_req N_NAME "Short identifier for Intermediate CA (e.g. server-ca, client-ca, vpn-ca)" ""
    N_NAME=$(lower "$N_NAME")
    ask_req N_CN "Common Name (CN)" "$PKI_ORG $(printf '%s' "$N_NAME" | sed 's/-/ /g')"
    choose_keytype N_KEY "${DEFAULT_CA_KEY:-rsa4096}"
    ask N_DAYS "Validity in days" "$INTERMEDIATE_DAYS"
    ask_yn N_PASS "Protect CA key with passphrase?" y

    local adv
    ask_yn adv "Configure advanced restrictions (Name Constraints, EKU limit, OCSP)?" n
    if [ "$adv" = yes ]; then
        info "Name Constraints: CA may ONLY issue certificates matching these suffixes (e.g. .lan .home.arpa)"
        ask_list N_PERMIT_DNS "Permitted DNS suffixes (empty = unrestricted)"
        ask_list N_PERMIT_IP  "Permitted IPv4 subnets in CIDR (e.g. 10.0.0.0/8, empty = unrestricted)"
        info "EKU Restriction: Certificates issued by this CA will be restricted to these purposes (e.g. serverAuth, clientAuth)"
        ask N_EKU_LIMIT "EKU Restriction (empty = none)" ""
        ask N_OCSP_URL "OCSP URL for this CA, e.g. http://ocsp.lan:2560 (empty = none)" ""
        ask N_PATHLEN "Maximum depth of subordinate CAs (pathlen)" "0"
    fi
    create_intermediate
}

i_ca_new() {
    require_pki
    banner "Create Intermediate CA"
    i_ca_new_inner
}

i_issue() {
    local p opts=()
    require_pki
    banner "Certificate Issuance Wizard"
    reset_issue_vars

    for p in $PRESETS; do
        load_preset "$p"
        opts+=("$p|$P_DESC")
    done

    ask_choice I_PRESET "Select preset / intended usage" server "${opts[@]}"
    load_preset "$I_PRESET"
    info "$P_DESC"
    choose_ca I_CA

    section "1. Certificate Identity"
    case $I_PRESET in
        wildcard)
            ask_req I_DOMAIN "Base domain (covers *.domain + base domain)" "lan"
            I_DOMAIN=$(lower "${I_DOMAIN#\*.}")
            I_CN="*.$I_DOMAIN"
            I_DNS="*.$I_DOMAIN,$I_DOMAIN"
            info "CN: $I_CN  SANs: $I_DNS"
            ;;
        smime|user)
            ask_req I_CN "Full Name of Person (CN)" ""
            ask_list I_EMAIL "Email address(es)"
            ;;
        codesign)
            ask_req I_CN "Signing Identity (CN)" "$PKI_ORG Code Signing"
            ;;
        ocsp)
            ask_req I_CN "Responder Identity (CN)" "$PKI_ORG OCSP Responder ($I_CA)"
            ;;
        timestamp)
            ask_req I_CN "Timestamp Authority Name (CN)" "$PKI_ORG Timestamp Authority"
            ;;
        client|vpn-client)
            ask_req I_CN "Client Identity (user or device, e.g. user-laptop)" ""
            ;;
        *)
            ask_req I_CN "Hostname / FQDN (automatically added as SAN)" ""
            [ "$P_CN_AUTO" = dns ] && autodetect_offer
            ;;
    esac

    case " $P_SAN_ASK " in
        *" dns "*)
            info "Additional DNS hostnames (aliases, short names). CN is included automatically."
            ask_list I_DNS "DNS hostnames" "$I_DNS"
            ;;
    esac
    case " $P_SAN_ASK " in
        *" ip "*)
            ask_list I_IP "IP addresses (IPv4/IPv6)" "$I_IP"
            ;;
    esac
    case " $P_SAN_ASK " in
        *" email "*)
            [ -z "$I_EMAIL" ] && ask_list I_EMAIL "Email addresses (optional)"
            ;;
    esac
    case " $P_SAN_ASK " in
        *" uri "*)
            ask_list I_URI "URIs (optional, e.g. spiffe://lab/node1)"
            ;;
    esac

    if [ "$I_PRESET" = custom ]; then
        section "Define Custom Key Usage"
        ask I_CUSTOM_KU "keyUsage" "digitalSignature, keyEncipherment"
        ask I_CUSTOM_EKU "extendedKeyUsage" "serverAuth, clientAuth"
    fi

    section "2. Key & Validity"
    choose_keytype I_KEY "$DEFAULT_LEAF_KEY"
    ask I_DAYS "Validity in days" "$P_DAYS"

    case $(preset_family "$I_PRESET") in
        server|vpnserver|ocsp|timestamp)
            info "For services like Nginx, Apache, or Proxmox an unencrypted key is recommended for unattended reboots."
            ;;
        *)
            info "For browser/Windows/macOS users the passphrase is embedded directly into the .p12 bundle."
            ;;
    esac
    ask_yn I_KEY_PASS "Protect private key with passphrase?" n

    section "3. Exports & Output"
    local p12def=n
    case $I_PRESET in client|user|smime|vpn-client|codesign) p12def=y ;; esac
    ask_yn I_EXPORT_P12 "Generate PKCS#12 (.p12) for Windows/macOS/Browser/Email?" "$p12def"
    [ "$I_EXPORT_P12" = yes ] && ask_yn I_P12_LEGACY "Also generate legacy PKCS#12 (3DES) for older systems?" n
    ask_yn I_EXPORT_DER "Generate binary DER format (.der)?" n

    ask I_NAME "Directory name under issued/" "$(name_from_cn "$I_CN")"

    banner "Configuration Summary"
    kv "Preset"      "$I_PRESET"
    kv "Issuer CA"   "$I_CA"
    kv "Common Name" "$I_CN"
    kv "DNS SANs"    "${I_DNS:--}"
    kv "IP SANs"     "${I_IP:--}"
    kv "Email"       "${I_EMAIL:--}"
    kv "Key Type"    "$I_KEY $( [ "$I_KEY_PASS" = yes ] && echo '(encrypted)' || echo '(unencrypted)' )"
    kv "Validity"    "$I_DAYS days"
    kv "Exports"     "P12=$I_EXPORT_P12, DER=$I_EXPORT_DER"
    kv "Directory"   "issued/$I_NAME"
    printf '\n' >&2

    if [ -e "$PKI_DIR/issued/$I_NAME/cert.pem" ]; then
        warn "A certificate in 'issued/$I_NAME' already exists!"
        confirm "Overwrite (previous certificate material will be archived)?" || return 0
        I_FORCE=1
    fi

    confirm "Issue certificate now?" || { info "Issuance cancelled"; return 0; }
    issue_cert
}

i_quick() {
    require_pki
    local h use
    banner "Quick Mode: TLS Server Certificate"
    printf '  Enter only the hostname (short or FQDN) or an IP address.\n' >&2
    printf '  All SANs and IPs are discovered automatically via DNS!\n' >&2
    printf '  Defaults: Preset server, %s, 397 days, CA: %s\n\n' "$DEFAULT_LEAF_KEY" "${DEFAULT_CA:-selected below}" >&2

    ask_req h "Hostname or IP address" ""
    reset_issue_vars
    I_PRESET=server

    info "Discovering network configuration ..."
    autodetect "$h" || return 1

    kv "CN"       "$AD_CN"
    kv "DNS SANs" "$( [ -n "$AD_DNS" ] && printf '%s' "$AD_DNS" | sed 's/,/, /g' || echo '-')"
    kv "IP SANs"  "$( [ -n "$AD_IP" ] && printf '%s' "$AD_IP" | sed 's/,/, /g' || echo '(none via DNS)')"
    printf '\n' >&2

    ask_yn use "Accept detected network parameters?" y
    I_CN=$AD_CN
    if [ "$use" = yes ]; then
        I_DNS=$AD_DNS
        I_IP=$AD_IP
    fi

    ask_list I_DNS "Additional DNS hostnames (optional)" "$I_DNS"
    ask_list I_IP  "Additional IP addresses (optional)" "$I_IP"

    if [ -n "$DEFAULT_CA" ]; then
        I_CA=$DEFAULT_CA
    else
        choose_ca I_CA
    fi

    I_NAME=$(name_from_cn "$I_CN")
    if [ -e "$PKI_DIR/issued/$I_NAME/cert.pem" ]; then
        warn "issued/$I_NAME already exists"
        confirm "Overwrite (previous material will be archived)?" || return 0
        I_FORCE=1
    fi
    issue_cert
}

i_sign_csr() {
    require_pki
    banner "Sign External CSR"
    reset_issue_vars; I_NO_CSR_SAN=0
    local csr p opts=() add

    ask_req csr "Path to CSR file" ""
    [ -f "$csr" ] || die "CSR file not found: $csr"
    csr_info "$csr"

    info "CSR inspected: CN='$CSR_CN' Key=$CSR_KEY SAN='${CSR_SAN:-none}'"
    for p in $PRESETS; do
        [ "$p" = wildcard ] && continue
        load_preset "$p"
        opts+=("$p|$P_DESC")
    done

    ask_choice I_PRESET "Preset" server "${opts[@]}"
    choose_ca I_CA
    ask I_CN "Common Name" "$CSR_CN"
    ask_yn add "Import SANs from CSR?" y
    [ "$add" = no ] && I_NO_CSR_SAN=1

    ask_list I_DNS "Additional DNS hostnames"
    ask_list I_IP  "Additional IP addresses"
    load_preset "$I_PRESET"
    ask I_DAYS "Validity in days" "$P_DAYS"
    ask I_NAME "Directory name under issued/" "$(name_from_cn "${I_CN:-$CSR_CN}")"

    confirm "Sign CSR now?" || return 0
    sign_csr "$csr"
}

i_show() {
    require_pki
    local n f
    pick_any n "Which certificate would you like to view?"
    ask_yn f "Verbose OpenSSL text output (-text)?" n
    show_cert "$n" "$( [ "$f" = yes ] && echo full)"
}

i_verify() {
    require_pki
    local n h
    pick_issued n "Which certificate should be verified?"
    ask h "Hostname/IP to verify against (leave blank to skip)" ""
    verify_cert "$n" "$h" || true
}

i_renew() {
    require_pki
    local n k r
    pick_issued n "Which certificate would you like to renew?"
    ask_yn k "Keep existing private key? (n = generate new key, recommended)" n
    ask_yn r "Revoke previous certificate in CA as 'superseded'?" y
    I_KEEP_KEY=0; [ "$k" = yes ] && I_KEEP_KEY=1
    R_REVOKE_OLD=0; [ "$r" = yes ] && R_REVOKE_OLD=1
    I_DAYS=""
    renew_cert "$n"
}

i_renew_ca() {
    require_pki
    local opts=("root|Root CA") n d
    for n in $(list_intermediates); do opts+=("$n|Intermediate CA"); done
    ask_choice n "Which CA would you like to renew?" "" "${opts[@]}"
    ask d "New validity in days" "$( [ "$n" = root ] && echo "$ROOT_DAYS" || echo "$INTERMEDIATE_DAYS")"
    confirm "Sign CA '$n' with renewed expiration date?" || return 0
    renew_ca "$n" "$d"
}

i_revoke() {
    require_pki
    local n r opts=() x
    pick_any n "Which certificate or Intermediate CA should be revoked?"
    [ "$n" = root ] && die "The Root CA cannot be revoked - only renewed or replaced."
    for x in $REVOKE_REASONS; do opts+=("$x|"); done
    ask_choice r "Revocation reason" superseded "${opts[@]}"
    revoke_cert "$n" "$r"
}

i_crl() {
    require_pki
    local opts=("all|Regenerate for all CAs" "root|Root CA only") n x
    for x in $(list_intermediates); do opts+=("$x|Intermediate CA"); done
    ask_choice n "Generate CRL for" all "${opts[@]}"
    if [ "$n" = all ]; then
        for x in root $(list_intermediates); do gen_crl "$x"; done
    else
        gen_crl "$n"
    fi
}

i_export() {
    require_pki
    local n p l der
    pick_issued n "Which certificate would you like to export?"
    ask_yn p "Generate PKCS#12 (.p12)?" y
    l=no
    [ "$p" = yes ] && ask_yn l "Also generate legacy PKCS#12 (3DES) for older systems?" n
    ask_yn der "Generate binary DER certificate (.der)?" n
    [ "$p" = yes ] && export_p12 "$n" "$l"
    [ "$der" = yes ] && export_der "$n"
    print_leaf_files "$PKI_DIR/issued/$n"
}

i_template() {
    local p opts=() name out
    for p in $PRESETS; do
        load_preset "$p"
        opts+=("$p|$P_DESC")
    done
    ask_choice p "Preset for template" server "${opts[@]}"
    ask name "Name (directory under issued/)" ""
    mkdir -p "$PKI_DIR/templates" 2>/dev/null || true
    ask out "Target file" "$PKI_DIR/templates/${name:-$p}.conf"
    print_template "$p" "$name" > "$out"
    ok "Template written successfully: $out"
    info "Edit this file and run 'pki batch $out' later."
}

i_batch() {
    require_pki
    local f
    ask_req f "Template file or directory" "$PKI_DIR/templates"
    B_FORCE=0
    batch_issue "$f"
}

i_ocsp() {
    require_pki
    local ca s port opts=() n
    for n in $(list_issued); do
        [ "$(awk -F'"' '/^PRESET=/{print $2}' "$PKI_DIR/issued/$n/cert.meta")" = ocsp ] && opts+=("$n|")
    done
    [ ${#opts[@]} -gt 0 ] || die "No OCSP signer found! Please issue a certificate using preset 'ocsp' first."
    ask_choice s "OCSP Signer Certificate" "" "${opts[@]}"
    ca=$(awk -F'"' '/^CA=/{print $2}' "$PKI_DIR/issued/$s/cert.meta")
    ask port "TCP port for responder daemon" 2560
    ocsp_server "$ca" "$s" "$port"
}

i_backup() {
    local act
    ask_choice act "Action" backup \
        "backup|Create a full PKI backup archive" \
        "restore|Restore PKI from a backup archive"
    if [ "$act" = backup ]; then
        pki_backup
    else
        local f
        ask_req f "Path to backup archive (.tar.gz)" ""
        pki_restore "$f"
    fi
}

i_search() {
    local q
    ask_req q "Search term (domain, IP, name, serial)" ""
    search_certs "$q"
}

###############################################################################
# Dashboard & Main Menu
###############################################################################
menu_header() {
    local ints n=0 exp=0 x
    printf '\n%s\n' "$HR" >&2
    printf '# %sOpenSSL Homelab PKI Generator %s%s  (%s)\n' "$C_BLD" "$VERSION" "$C_RST" "$OPENSSL" >&2
    printf '# PKI Directory: %s\n' "$PKI_DIR" >&2

    if [ -f "$PKI_DIR/root/certs/ca.crt" ]; then
        ints=$(list_intermediates | tr '\n' ' ')
        for x in $(list_issued); do
            n=$((n+1))
            local d; d=$(cert_days_left "$PKI_DIR/issued/$x/cert.pem")
            [ "$d" != "?" ] && [ "$d" -le "${WARN_DAYS:-30}" ] && exp=$((exp+1))
        done
        local root_days; root_days=$(cert_days_left "$PKI_DIR/root/certs/ca.crt")
        printf '# Root CA      : %s (%s days)  |  Intermediates: %s\n' \
            "$(cert_cn "$PKI_DIR/root/certs/ca.crt")" "$root_days" "${ints:-none}" >&2
        printf '# Certificates : %s issued  |  %s expiring soon  |  Default CA: %s\n' \
            "$n" "$( [ "$exp" -gt 0 ] && printf '%s%s%s' "$C_YEL" "$exp" "$C_RST" || printf '0' )" "${DEFAULT_CA:-none}" >&2
    else
        printf '# Status       : %sNo PKI initialized yet%s -> Select option 1 to set up!\n' "$C_YEL" "$C_RST" >&2
    fi
    printf '%s\n' "$HR" >&2
}

menu() {
    INTERACTIVE=1
    local c
    while :; do
        load_config
        menu_header
        cat >&2 <<'EOF'
  [s] QUICK MODE: Issue TLS Server Certificate in 1 Click (DNS Auto-Detect)
  [d] DASHBOARD / STATUS: Overview of all CAs & Certificates

  1. PKI & CA Management
     1) Initialize New PKI (Root CA)
     2) Create Intermediate CA
     3) System Diagnostics (Doctor)
     4) Create / Restore PKI Backup

  2. Certificate Issuance
     5) Issue Certificate (Wizard)
     6) Sign External CSR
     7) Issue Certificates in Batch

  3. Inspection & Operations
     8) List all Certificates & CAs
     9) Search Certificates
    10) Show Certificate Details
    11) Verify Certificate & Key Match
    12) Run Expiry Check

  4. Lifecycle & Maintenance
    13) Renew Certificate
    14) Renew CA Certificate
    15) Revoke Certificate / Intermediate CA
    16) Regenerate CRL Revocation List
    17) Export PKCS#12 (.p12) / DER
    18) Launch OCSP Responder Daemon

  [p] Show Presets    [h] Help (CLI)    [0/q] Exit
EOF
        printf '%s\n' "$HR" >&2
        printf 'Your choice: ' >&2
        IFS= read -r c || { printf '\n' >&2; exit 0; }
        case $(trim "$c") in
            s|S)      ( i_quick )       || true ;;
            d|D)      ( list_all )      || true ;;
            1)        ( i_init )        || true ;;
            2)        ( i_ca_new )      || true ;;
            3)        ( pki_doctor )    || true ;;
            4)        ( i_backup )      || true ;;
            5)        ( i_issue )       || true ;;
            6)        ( i_sign_csr )    || true ;;
            7)        ( i_batch )       || true ;;
            8)        ( list_all )      || true ;;
            9)        ( i_search )      || true ;;
            10)       ( i_show )        || true ;;
            11)       ( i_verify )      || true ;;
            12)       ( check_all )     || true ;;
            13)       ( i_renew )       || true ;;
            14)       ( i_renew_ca )    || true ;;
            15)       ( i_revoke )      || true ;;
            16)       ( i_crl )         || true ;;
            17)       ( i_export )      || true ;;
            18)       ( i_ocsp )        || true ;;
            p|P)      ( print_presets ) || true ;;
            h|H|help) ( usage )         || true ;;
            0|q|Q|exit) exit 0 ;;
            '')       continue ;;
            *)        warn "Invalid choice: $c"; continue ;;
        esac
        pause
    done
}
