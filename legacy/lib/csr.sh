#!/usr/bin/env bash
###############################################################################
# lib/csr.sh - External Certificate Signing Request (CSR) Parsing and Signing
###############################################################################

# Reads and validates an external CSR and extracts CN, key type, and SANs
csr_info() {
    local csr=$1 txt
    "$OPENSSL" req -in "$csr" -noout -verify >/dev/null 2>&1 || die "CSR signature is invalid or file is not a valid CSR: $csr"
    CSR_CN=$("$OPENSSL" req -in "$csr" -noout -subject -nameopt multiline,utf8,-esc_msb | awk -F' = ' '/commonName/{print $2; exit}')
    txt=$("$OPENSSL" req -in "$csr" -noout -text)
    CSR_SAN=$(printf '%s\n' "$txt" | awk '/Subject Alternative Name/{getline; print; exit}' | sed 's/^ *//')
    CSR_KEY=$(printf '%s\n' "$txt" | awk -F': ' '/Public Key Algorithm/{print $2; exit}')
    CSR_DNS="" CSR_IP="" CSR_EMAIL="" CSR_URI=""

    local IFS=, e
    for e in $CSR_SAN; do
        e=$(trim "$e")
        case $e in
            DNS:*)          CSR_DNS=$(add_uniq "$CSR_DNS" "${e#DNS:}") ;;
            "IP Address:"*) CSR_IP=$(add_uniq "$CSR_IP" "${e#IP Address:}") ;;
            email:*)        CSR_EMAIL=$(add_uniq "$CSR_EMAIL" "${e#email:}") ;;
            URI:*)          CSR_URI=$(add_uniq "$CSR_URI" "${e#URI:}") ;;
        esac
    done
}

# Signs an external CSR
sign_csr() {
    local csr=$1 kt
    [ -f "$csr" ] || die "CSR file not found: $csr"
    csr_info "$csr"
    info "CSR contains: CN='$CSR_CN' Key=$CSR_KEY SAN='${CSR_SAN:-none}'"
    [ -z "$I_CN" ] && I_CN=$CSR_CN

    if [ "$I_NO_CSR_SAN" != 1 ]; then
        I_DNS="$CSR_DNS${I_DNS:+,$I_DNS}"
        I_IP="$CSR_IP${I_IP:+,$I_IP}"
        I_EMAIL="$CSR_EMAIL${I_EMAIL:+,$I_EMAIL}"
        I_URI="$CSR_URI${I_URI:+,$I_URI}"
    fi

    case $CSR_KEY in
        *ED25519*) kt=ed25519 ;;
        *)         kt=rsa ;;
    esac

    # Set key type for keyUsage compatibility
    I_KEY=$( [ "$kt" = ed25519 ] && echo ed25519 || echo rsa2048 )
    I_CSR_FILE=$csr

    [ "$I_CA" = selfsigned ] && die "An external CSR cannot be self-signed by definition"
    issue_cert
}
