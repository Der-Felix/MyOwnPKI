#!/usr/bin/env bash
###############################################################################
# lib/operations.sh - Certificate Operations: Listing, Verify, Renew, Revoke & CRL
###############################################################################

REVOKE_REASONS="unspecified keyCompromise CACompromise affiliationChanged superseded cessationOfOperation certificateHold"

# Lists all issued leaf certificates
list_issued() {
    local d
    [ -d "$PKI_DIR/issued" ] || return 0
    for d in "$PKI_DIR"/issued/*/; do
        [ -f "$d/cert.meta" ] && basename "$d"
    done
    return 0
}

# Color-formatted status text for certificate lifetime and revocation
status_text() { # <days> <revoked_flag: R>
    if [ "$2" = R ]; then
        printf '%sREVOKED%s' "$C_RED" "$C_RST"
    elif [ "$1" = "?" ]; then
        printf '?'
    elif [ "$1" -lt 0 ]; then
        printf '%sEXPIRED%s' "$C_RED" "$C_RST"
    elif [ "$1" -le "${WARN_DAYS:-30}" ]; then
        printf '%sEXPIRING%s' "$C_YEL" "$C_RST"
    else
        printf '%sOK%s' "$C_GRN" "$C_RST"
    fi
}

# Tabular overview of all CAs and issued certificates
list_all() {
    local n d days st fmt="%-24s %-13s %-12s %-11s %6s  %-10s %s\n"
    require_pki

    printf '%s\n# Certificate Authorities (CAs) in %s\n%s\n' "$HR" "$PKI_DIR" "$HR"
    printf "$fmt" "NAME" "TYPE" "KEY" "VALID UNTIL" "DAYS" "STATUS" "CN"

    for n in root $(list_intermediates); do
        d=$(ca_dir "$n")
        load_ca_meta "$n"
        days=$(cert_days_left "$d/certs/ca.crt")
        st=""
        [ "$n" != root ] && st=$(index_status "$PKI_DIR/root" "$(cert_serial "$d/certs/ca.crt")")
        printf "$fmt" "$n$( [ "$n" = "$DEFAULT_CA" ] && echo '*')" "$M_TYPE" "$M_KEY" "$(cert_end_date "$d/certs/ca.crt")" "$days" "$(status_text "$days" "$st")" "$M_CN"
    done

    printf '\n%s\n# Issued End-Entity Certificates (Leaves)\n%s\n' "$HR" "$HR"
    printf "$fmt" "NAME" "PRESET" "CA" "VALID UNTIL" "DAYS" "STATUS" "CN"

    local total=0 ok_c=0 exp_c=0 rev_c=0
    for n in $(list_issued); do
        total=$((total+1))
        d="$PKI_DIR/issued/$n"
        local pre ca
        pre=$(awk -F'"' '/^PRESET=/{print $2}' "$d/cert.meta")
        ca=$(awk -F'"' '/^CA=/{print $2}' "$d/cert.meta")
        days=$(cert_days_left "$d/cert.pem")
        st=""
        [ "$ca" != selfsigned ] && ca_exists "$ca" && st=$(index_status "$(ca_dir "$ca")" "$(cert_serial "$d/cert.pem")")

        # If issuing parent CA was revoked
        if [ "$ca" != selfsigned ] && [ "$ca" != root ] && ca_exists "$ca" && \
           [ "$(index_status "$PKI_DIR/root" "$(cert_serial "$(ca_dir "$ca")/certs/ca.crt")")" = R ]; then
            st=R
        fi

        if [ "$st" = R ]; then
            rev_c=$((rev_c+1))
        elif [ "$days" != "?" ] && [ "$days" -le "${WARN_DAYS:-30}" ]; then
            exp_c=$((exp_c+1))
        else
            ok_c=$((ok_c+1))
        fi

        printf "$fmt" "$n" "$pre" "$ca" "$(cert_end_date "$d/cert.pem")" "$days" "$(status_text "$days" "$st")" "$(cert_cn "$d/cert.pem")"
    done

    printf '\n  Total: %s certificates (%s%s valid%s, %s%s expiring soon%s, %s%s revoked%s)  |  * = DEFAULT_CA\n\n' \
        "$total" "$C_GRN" "$ok_c" "$C_RST" "$C_YEL" "$exp_c" "$C_RST" "$C_RED" "$rev_c" "$C_RST"
}

# Filters certificates by Name, CN, IP, SAN, Preset, or Serial
search_certs() {
    local query=$1 n d pre ca cn dns ip serial found=0
    [ -n "$query" ] || die "Usage: pki search <query>"
    require_pki
    query=$(lower "$query")

    banner "Search Results for: '$query'"
    local fmt="%-22s %-12s %-12s %-10s %s\n"
    printf "$fmt" "NAME" "PRESET" "CA" "DAYS LEFT" "COMMON NAME / DETAILS"

    for n in $(list_issued); do
        d="$PKI_DIR/issued/$n"
        pre=$(awk -F'"' '/^PRESET=/{print $2}' "$d/cert.meta")
        ca=$(awk -F'"' '/^CA=/{print $2}' "$d/cert.meta")
        cn=$(awk -F'"' '/^CN=/{print $2}' "$d/cert.meta")
        dns=$(awk -F'"' '/^DNS=/{print $2}' "$d/cert.meta")
        ip=$(awk -F'"' '/^IP=/{print $2}' "$d/cert.meta")
        serial=$(cert_serial "$d/cert.pem" 2>/dev/null || true)

        local haystack
        haystack=$(lower "$n $pre $ca $cn $dns $ip $serial")
        if [[ $haystack == *"$query"* ]]; then
            found=$((found+1))
            local days; days=$(cert_days_left "$d/cert.pem")
            printf "$fmt" "$n" "$pre" "$ca" "$days" "$cn $( [ -n "$dns" ] && echo "[$dns]" )"
        fi
    done

    [ "$found" -eq 0 ] && info "No matching certificates found for '$query'"
    printf '\n'
}

# Checks expiry dates for monitoring/cron (Exit code 2 when any certificate/CRL expires soon)
check_all() {
    local warn_days=${1:-$WARN_DAYS} n d days st bad=0 ca next e
    require_pki

    for n in root $(list_intermediates); do
        d=$(ca_dir "$n")
        days=$(cert_days_left "$d/certs/ca.crt")
        if [ "$days" -le "$warn_days" ]; then
            printf 'CA   %-22s %5s days remaining\n' "$n" "$days"
            bad=1
        fi
        if [ -f "$d/crl/ca.crl" ]; then
            next=$("$OPENSSL" crl -in "$d/crl/ca.crl" -noout -nextupdate -dateopt iso_8601 | cut -d= -f2)
            e=$(to_epoch "${next%Z}")
            days=$(( (e - $(date -u +%s)) / 86400 ))
            if [ "$days" -le 7 ]; then
                printf 'CRL  %-22s %5s days  -> pki crl --ca %s\n' "$n" "$days" "$n"
                bad=1
            fi
        fi
    done

    for n in $(list_issued); do
        d="$PKI_DIR/issued/$n"
        ca=$(awk -F'"' '/^CA=/{print $2}' "$d/cert.meta")
        st=""
        [ "$ca" != selfsigned ] && ca_exists "$ca" && st=$(index_status "$(ca_dir "$ca")" "$(cert_serial "$d/cert.pem")")
        [ "$st" = R ] && continue

        days=$(cert_days_left "$d/cert.pem")
        if [ "$days" -le "$warn_days" ]; then
            printf 'CERT %-22s %5s days  -> pki renew %s\n' "$n" "$days" "$n"
            bad=1
        fi
    done

    if [ "$bad" = 0 ]; then
        ok "All certificates and CRLs are valid (warning threshold: $warn_days days)"
        return 0
    fi
    return 2
}

# Resolves a name or path to a certificate file
resolve_cert() {
    if [ -f "$1" ]; then
        printf '%s' "$1"
    elif [ "$1" = root ]; then
        printf '%s' "$PKI_DIR/root/certs/ca.crt"
    elif [ -f "$PKI_DIR/intermediate/$1/certs/ca.crt" ]; then
        printf '%s' "$PKI_DIR/intermediate/$1/certs/ca.crt"
    elif [ -f "$PKI_DIR/issued/$1/cert.pem" ]; then
        printf '%s' "$PKI_DIR/issued/$1/cert.pem"
    else
        die "Certificate not found: '$1' (neither as certificate name nor file path)"
    fi
}

# Displays certificate details
show_cert() {
    local f
    f=$(resolve_cert "$1")

    if [ "${2:-}" = full ]; then
        "$OPENSSL" x509 -in "$f" -noout -text
        return
    fi

    banner "Certificate Details: $f"
    "$OPENSSL" x509 -in "$f" -noout -nameopt utf8,sep_comma_plus_space -subject -issuer -serial \
        -startdate -enddate -dateopt iso_8601
    printf 'Remaining days : %s days\n' "$(cert_days_left "$f")"
    "$OPENSSL" x509 -in "$f" -noout -text | awk '/Public Key Algorithm|Public-Key:/{sub(/^ +/,""); print}'
    "$OPENSSL" x509 -in "$f" -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,nameConstraints,crlDistributionPoints,authorityInfoAccess 2>/dev/null || true
    printf 'SHA-256 Fingerprint: %s\n' "$(cert_fingerprint "$f")"
}

# Validates chain, revocation status, keyUsage/purpose, and private key match
verify_cert() {
    local name=$1 host=${2:-} d="$PKI_DIR/issued/$1" f ca pre crls args=() rc=0

    if [ ! -f "$d/cert.pem" ]; then
        # Verification of a CA
        f=$(resolve_cert "$name")
        "$OPENSSL" verify -CAfile "$PKI_DIR/root/certs/ca.crt" "$f" && return 0 || return 1
    fi

    f="$d/cert.pem"
    ca=$(awk -F'"' '/^CA=/{print $2}' "$d/cert.meta")
    pre=$(awk -F'"' '/^PRESET=/{print $2}' "$d/cert.meta")
    load_preset "$pre"

    banner "Certificate Verification (Verify): $name"

    if [ "$ca" = selfsigned ]; then
        args=(-CAfile "$f" -partial_chain)
    else
        args=(-CAfile "$PKI_DIR/root/certs/ca.crt")
        [ -s "$d/chain.pem" ] && args+=(-untrusted "$d/chain.pem")
        crls=$(mktemp)
        cat "$PKI_DIR/root/crl/ca.crl" > "$crls"
        [ "$ca" != root ] && cat "$(ca_dir "$ca")/crl/ca.crl" >> "$crls"
        args+=(-crl_check_all -CRLfile "$crls")
    fi

    [ "$P_PURPOSE" != any ] && args+=(-purpose "$P_PURPOSE")
    if [ -n "$host" ]; then
        if is_ipv4 "$host" || is_ipv6 "$host"; then
            args+=(-verify_ip "$host")
        else
            args+=(-verify_hostname "$(lower "$host")")
        fi
    fi

    if "$OPENSSL" verify "${args[@]}" "$f"; then
        ok "Certificate chain, CRL revocation status${host:+, hostname '$host'} and purpose ($P_PURPOSE) are VALID"
    else
        err "Verification failed"
        rc=1
    fi
    [ -n "${crls:-}" ] && rm -f "$crls"

    if [ -f "$d/key.pem" ]; then
        if key_is_encrypted "$d/key.pem" && [ -z "${PKI_KEY_PASS:-}" ] && [ ! -t 0 ]; then
            info "Private key is passphrase-protected - key matching check skipped in non-interactive shell"
        else
            key_passin "$d/key.pem"
            if [ "$("$OPENSSL" pkey -in "$d/key.pem" "${KPASSIN[@]}" -pubout 2>/dev/null)" = "$("$OPENSSL" x509 -in "$f" -noout -pubkey)" ]; then
                ok "Private key matches certificate exactly (Public Key Match)"
            else
                err "Private key does NOT match certificate!"
                rc=1
            fi
        fi
    fi
    return $rc
}

# Re-issues a leaf certificate reusing existing parameters from cert.meta
renew_cert() {
    local name=$1 d="$PKI_DIR/issued/$1" old_serial old_ca keep=$I_KEEP_KEY revoke_old=$R_REVOKE_OLD days=$I_DAYS
    [ -f "$d/cert.meta" ] || die "No certificate '$name' or cert.meta file found"
    old_serial=$(cert_serial "$d/cert.pem")

    reset_issue_vars
    # shellcheck disable=SC2086
    load_kv "$d/cert.meta" I_ $I_KEYS SERIAL ISSUED
    old_ca=$I_CA
    [ -n "$days" ] && I_DAYS=$days
    I_KEEP_KEY=$keep
    I_RENEW=1

    [ -f "$d/key.pem" ] || die "No private key available (external CSR) - sign a new CSR with 'pki sign-csr'"

    if [ "$I_EXPORT_P12" = yes ] && [ -z "${PKI_P12_PASS:-}" ] && [ ! -t 0 ]; then
        warn "PKI_P12_PASS not set - .p12 export will not be regenerated (run later: pki export $name)"
        I_EXPORT_P12=no
    fi

    issue_cert

    if [ "$revoke_old" = 1 ] && [ "$old_ca" != selfsigned ]; then
        local cad; cad=$(ca_dir "$old_ca")
        ca_passin "$old_ca"
        if [ -f "$cad/newcerts/$old_serial.pem" ]; then
            ssl ca -config "$cad/ca.cnf" "${PASSIN[@]}" -revoke "$cad/newcerts/$old_serial.pem" -crl_reason superseded \
                && ok "Previous certificate ($old_serial) revoked as 'superseded'" \
                && gen_crl "$old_ca"
        else
            warn "Previous certificate not found in newcerts/ - revocation skipped"
        fi
    fi
    log_action "RENEW name=$name old_serial=$old_serial keep_key=$keep"
}

# Renews a CA retaining the identical private key (all issued certificates remain valid!)
renew_ca() {
    local ca=$1 d days=$2 a n
    ca_exists "$ca" || die "CA '$ca' does not exist"
    d=$(ca_dir "$ca")
    load_ca_meta "$ca"

    [ -z "$days" ] && { if [ "$ca" = root ]; then days=$ROOT_DAYS; else days=$INTERMEDIATE_DAYS; fi; }
    a="$d/archive/$(stamp)"
    mkdir -p "$a"
    cp "$d/certs/ca.crt" "$a/"

    banner "Renew CA: $ca (retaining original private key)"
    ca_passin "$ca"

    if [ "$ca" = root ]; then
        req_selfsign "$d/private/ca.key" "$M_SUBJECT" "$days" "$d/ext.cnf" v3_root "$d/certs/ca.crt.new" "${PASSIN[@]}" \
            || die "Root CA renewal failed"
        mv "$d/certs/ca.crt.new" "$d/certs/ca.crt"
        chmod 644 "$d/certs/ca.crt"
        for n in $(list_intermediates); do
            cat "$(ca_dir "$n")/certs/ca.crt" "$d/certs/ca.crt" > "$(ca_dir "$n")/certs/chain.pem"
        done
        warn "New Root CA certificate must be redistributed to trust stores (publish/root.crt) - certificate thumbprint has changed!"
    else
        local left; left=$(cert_days_left "$PKI_DIR/root/certs/ca.crt")
        [ "$days" -gt "$left" ] && { warn "Validity shortened to Root CA remaining lifetime: $left days"; days=$left; }
        ssl req -new -utf8 -config "$PKI_DIR/.req.cnf" -key "$d/private/ca.key" "${PASSIN[@]}" -subj "$M_SUBJECT" -out "$d/ca.csr" \
            || die "CSR creation for CA failed"
        ca_passin root
        ssl ca -batch -config "$PKI_DIR/root/ca.cnf" "${PASSIN[@]}" -extfile "$d/ext.cnf" -extensions v3_intermediate \
            -days "$days" -notext -preserveDN -in "$d/ca.csr" -out "$d/certs/ca.crt.new" || die "Signing updated Intermediate CA failed"
        mv "$d/certs/ca.crt.new" "$d/certs/ca.crt"
        chmod 644 "$d/certs/ca.crt"
        cat "$d/certs/ca.crt" "$PKI_DIR/root/certs/ca.crt" > "$d/certs/chain.pem"
    fi

    publish_ca "$ca"

    # Update certificate bundles of all affected issued certificates
    for n in $(list_issued); do
        local lca; lca=$(awk -F'"' '/^CA=/{print $2}' "$PKI_DIR/issued/$n/cert.meta")
        if [ "$lca" = "$ca" ] || { [ "$ca" = root ] && [ "$lca" != selfsigned ]; }; then
            write_bundles "$PKI_DIR/issued/$n" "$lca"
            [ -f "$PKI_DIR/issued/$n/cert.p12" ] && warn "$n: cert.p12 contains previous certificate chain -> run 'pki export $n'"
        fi
    done

    log_action "RENEW-CA ca=$ca days=$days"
    ok "CA '$ca' renewed successfully, valid until $(cert_end_date "$d/certs/ca.crt")"
}

# Generates a fresh Certificate Revocation List (CRL) for a CA
gen_crl() {
    local ca=$1 d
    d=$(ca_dir "$1")
    ca_passin "$ca"
    ssl ca -config "$d/ca.cnf" "${PASSIN[@]}" -gencrl -crldays "${CRL_DAYS:-30}" -out "$d/crl/ca.crl" \
        || die "CRL generation for '$ca' failed"
    chmod 644 "$d/crl/ca.crl"
    publish_ca "$ca"
    log_action "CRL generated ca=$ca"
    ok "CRL for CA '$ca' generated (next update due: $("$OPENSSL" crl -in "$d/crl/ca.crl" -noout -nextupdate -dateopt iso_8601 | cut -d= -f2))"
}

# Revokes a certificate or an Intermediate CA
revoke_cert() {
    local name=$1 reason=${2:-unspecified} cert issuer st
    case " $REVOKE_REASONS " in
        *" $reason "*) ;;
        *) die "Invalid revocation reason '$reason'. Allowed: $REVOKE_REASONS" ;;
    esac

    if [ -f "$PKI_DIR/issued/$name/cert.pem" ]; then
        cert="$PKI_DIR/issued/$name/cert.pem"
        issuer=$(awk -F'"' '/^CA=/{print $2}' "$PKI_DIR/issued/$name/cert.meta")
    elif [ -f "$PKI_DIR/intermediate/$name/certs/ca.crt" ]; then
        cert="$PKI_DIR/intermediate/$name/certs/ca.crt"
        issuer=root
        warn "Attention: You are revoking an INTERMEDIATE CA! All certificates signed by this CA will become invalid!"
    else
        die "No certificate or CA found named '$name'"
    fi

    [ "$issuer" = selfsigned ] && die "Self-signed certificates cannot be revoked (no CA CRL infrastructure)"
    st=$(index_status "$(ca_dir "$issuer")" "$(cert_serial "$cert")")
    [ "$st" = R ] && die "'$name' is already revoked"
    [ -z "$st" ] && die "'$name' was not found in database of CA '$issuer'"

    if [ "$INTERACTIVE" = 1 ] || [ "$ASSUME_YES" != 1 ]; then
        confirm "Really revoke '$name' (Serial $(cert_serial "$cert"))? Reason: $reason" || { info "Cancelled"; return 0; }
    fi

    ca_passin "$issuer"
    ssl ca -config "$(ca_dir "$issuer")/ca.cnf" "${PASSIN[@]}" -revoke "$cert" -crl_reason "$reason" \
        || die "Revocation command failed in OpenSSL"

    log_action "REVOKE name=$name ca=$issuer reason=$reason serial=$(cert_serial "$cert")"
    ok "Certificate '$name' successfully revoked (Reason: $reason)"
    gen_crl "$issuer"
    info "CRL was regenerated and published to publish/."
}
