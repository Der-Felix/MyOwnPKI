#!/usr/bin/env bash
###############################################################################
# lib/doctor.sh - Environment and Integrity Verification (Pre-Flight Health Check)
###############################################################################

pki_doctor() {
    banner "PKI System & Environment Health Check (Doctor)"
    local issues=0 warnings=0

    # 1. OpenSSL Verification
    printf '\n%s1. OpenSSL & Cryptography Environment%s\n' "$C_BLD" "$C_RST"
    if [ -n "$OPENSSL" ] && [ -x "$OPENSSL" ]; then
        local v; v=$("$OPENSSL" version 2>/dev/null)
        if echo "$v" | grep -q '^OpenSSL 3'; then
            ok "OpenSSL 3.x available: $v ($OPENSSL)"
        else
            err "OpenSSL is not version 3.x: $v"
            issues=$((issues+1))
        fi
    else
        err "OpenSSL executable not found!"
        issues=$((issues+1))
    fi

    # 2. Bash Version and System Utilities
    printf '\n%s2. Shell & Core System Utilities%s\n' "$C_BLD" "$C_RST"
    if [ -n "${BASH_VERSION:-}" ]; then
        ok "Bash available: version $BASH_VERSION"
    else
        warn "Non-Bash shell detected (current shell: $SHELL)"
        warnings=$((warnings+1))
    fi

    local tool
    for tool in awk sed date tar tr; do
        if have "$tool"; then
            ok "Tool '$tool' available"
        else
            err "Required core tool '$tool' is missing!"
            issues=$((issues+1))
        fi
    done

    for tool in getent host dig timeout; do
        if have "$tool"; then
            ok "Network tool '$tool' available"
        else
            info "Optional network tool '$tool' not found (DNS autodetection limited)"
        fi
    done

    # 3. PKI Directory Structure and Security Permissions
    printf '\n%s3. PKI Directory Layout & Security Permissions%s\n' "$C_BLD" "$C_RST"
    if [ -d "$PKI_DIR" ]; then
        ok "PKI directory exists: $PKI_DIR"
        if [ -w "$PKI_DIR" ]; then
            ok "PKI directory is writable"
        else
            err "PKI directory is NOT writable!"
            issues=$((issues+1))
        fi
    else
        info "PKI directory does not exist yet (will be created on 'pki init')"
    fi

    # 4. Check CAs and Database Integrity
    if [ -f "$PKI_DIR/root/certs/ca.crt" ]; then
        printf '\n%s4. Certificate Authorities & Databases%s\n' "$C_BLD" "$C_RST"
        local root_days; root_days=$(cert_days_left "$PKI_DIR/root/certs/ca.crt")
        if [ "$root_days" -lt 0 ]; then
            err "Root CA has expired ($root_days days)!"
            issues=$((issues+1))
        else
            ok "Root CA is valid ($root_days days remaining)"
        fi

        # Verify private key permissions
        if [ -d "$PKI_DIR/root/private" ]; then
            local priv_perm; priv_perm=$(ls -ld "$PKI_DIR/root/private" 2>/dev/null | awk '{print $1}')
            case $priv_perm in
                drwx------*) ok "Root private directory securely permissions ($priv_perm)" ;;
                *) warn "Root private directory permissions should be 700 (currently: $priv_perm)"; warnings=$((warnings+1)) ;;
            esac
        fi

        local ca
        for ca in $(list_intermediates); do
            local cad; cad=$(ca_dir "$ca")
            local cdays; cdays=$(cert_days_left "$cad/certs/ca.crt")
            if [ "$cdays" -lt 0 ]; then
                err "Intermediate CA '$ca' has expired ($cdays days remaining)!"
                issues=$((issues+1))
            else
                ok "Intermediate CA '$ca' is valid ($cdays days remaining)"
            fi

            if [ -f "$cad/index.txt" ]; then
                local cert_count; cert_count=$(wc -l < "$cad/index.txt" | tr -d ' ')
                ok "Database for '$ca': $cert_count entries"
            fi
        done
    fi

    # Summary
    divider
    if [ "$issues" -eq 0 ] && [ "$warnings" -eq 0 ]; then
        ok "Diagnostics complete: Everything configured optimally! No issues found."
        return 0
    elif [ "$issues" -eq 0 ]; then
        warn "Diagnostics complete: $warnings warning(s) found, system is functional."
        return 0
    else
        err "Diagnostics complete: $issues critical issue(s) detected! Please resolve."
        return 1
    fi
}
