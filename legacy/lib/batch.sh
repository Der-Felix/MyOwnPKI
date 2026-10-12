#!/usr/bin/env bash
###############################################################################
# lib/batch.sh - Certificate Templates and Batch Processing
###############################################################################

# Formats a key-value line aligned with comment
tpl_line() {
    printf '%-40s # %s\n' "$1=\"$2\"" "$3"
}

# Outputs a configuration template for a preset to stdout
print_template() {
    local preset=$1 name=${2:-} cn dns="" ip="" email="" ca=${DEFAULT_CA:-server-ca}
    load_preset "$preset" || die "Unknown preset '$preset'. Available presets: $PRESETS"

    case $preset in
        server|server-client) cn="web01.lan"; dns="web01.lan, web01"; ip="10.0.10.5" ;;
        wildcard)             cn="*.lan"; dns="*.lan, lan" ;;
        vpn-server)           cn="vpn.example.org"; dns="vpn.example.org"; ip="203.0.113.10" ;;
        vpn-client)           cn="client01-laptop" ;;
        client)               cn="client01" ;;
        user|smime)           cn="Jane Doe"; email="jane@example.org" ;;
        codesign)             cn="$PKI_ORG Code Signing" ;;
        ocsp)                 cn="$PKI_ORG OCSP Responder" ;;
        timestamp)            cn="$PKI_ORG Timestamp Authority" ;;
        custom)               cn="custom01" ;;
    esac

    [ -z "$name" ] && name=$(name_from_cn "$cn")
    local p12=no cku="" ceku=""
    case $preset in client|user|smime|vpn-client|codesign) p12=yes ;; esac
    [ "$preset" = custom ] && { cku="digitalSignature, keyEncipherment"; ceku="serverAuth, clientAuth"; }

    cat <<EOF
###############################################################################
# Template for pki.sh  -  Preset: $preset
# Purpose: $P_DESC
#
# Usage: pki batch <this-file.conf> [additional...]
# Format: KEY="value" (separate list entries with comma or space)
###############################################################################

######## General Settings
EOF
    tpl_line PRESET "$preset"      "$PRESETS"
    tpl_line NAME   "$name"        "Directory name under issued/ (blank = derived from CN)"
    tpl_line CN     "$cn"          "Common Name (automatically added to SANs for servers)"
    tpl_line OU     ""             "Organizational Unit (blank = default from pki.conf)"
    printf '\n######## Subject Alternative Names (SANs - comma-separated list)\n'
    tpl_line DNS    "$dns"         "DNS hostnames, wildcards supported: *.lan"
    tpl_line IP     "$ip"          "IPv4 and IPv6 addresses"
    tpl_line EMAIL  "$email"       "Email addresses (for smime, user presets)"
    tpl_line URI    ""             "URIs (e.g. spiffe://lab/node1)"
    printf '\n######## Cryptography & Issuing CA\n'
    tpl_line KEY    "${DEFAULT_LEAF_KEY:-rsa3072}" "rsa2048 | rsa3072 | rsa4096 | ed25519"
    tpl_line DAYS   "$P_DAYS"      "Validity in days"
    tpl_line CA     "$ca"          "Intermediate CA name | root | selfsigned"
    tpl_line KEY_PASS no           "yes = encrypt private key with AES-256"
    printf '\n######## Automated Exports\n'
    tpl_line EXPORT_P12 "$p12"     "yes = generate cert.p12 for Windows/macOS/Browser/Email"
    tpl_line P12_LEGACY no         "yes = also generate cert-legacy.p12 (3DES) for legacy systems"
    tpl_line EXPORT_DER no         "yes = generate cert.der (binary DER format)"
    printf '\n######## Advanced Options (only applicable for PRESET="custom")\n'
    tpl_line CUSTOM_KU  "$cku"     "keyUsage (e.g. digitalSignature, keyEncipherment)"
    tpl_line CUSTOM_EKU "$ceku"    "extendedKeyUsage (e.g. serverAuth, clientAuth)"
}

# Processes multiple template files or directories in batch
batch_issue() {
    local f g files=() rcount=0 fcount=0
    for f in "$@"; do
        if [ -d "$f" ]; then
            for g in "$f"/*.conf "$f"/*.meta; do
                [ -f "$g" ] && files+=("$g")
            done
        else
            files+=("$f")
        fi
    done

    [ ${#files[@]} -gt 0 ] || die "No template files specified or found"

    banner "Batch Processing: ${#files[@]} template(s) loaded"

    for f in "${files[@]}"; do
        info "Processing template: $f"
        if ( reset_issue_vars
             # shellcheck disable=SC2086
             load_kv "$f" I_ $I_KEYS SERIAL ISSUED
             I_FORCE=$B_FORCE
             issue_cert ); then
            rcount=$((rcount+1))
        else
            err "Failed processing template: $f"
            fcount=$((fcount+1))
        fi
    done

    banner "Batch completed: $rcount succeeded, $fcount failed"
    [ "$fcount" -eq 0 ]
}
