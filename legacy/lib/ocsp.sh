#!/usr/bin/env bash
###############################################################################
# lib/ocsp.sh - OCSP Responder Daemon and OCSP Verification
###############################################################################

# Starts the built-in OpenSSL OCSP responder daemon
ocsp_server() {
    local ca=$1 signer=$2 port=${3:-2560} cad sd
    [ -n "$ca" ] && [ -n "$signer" ] || die "Usage: pki ocsp-server --ca <ca> --signer <ocsp-cert> [--port 2560]"
    ca_exists "$ca" || die "CA '$ca' does not exist"
    cad=$(ca_dir "$ca")
    sd="$PKI_DIR/issued/$signer"

    [ -f "$sd/cert.pem" ] || die "OCSP signer '$signer' not found (create first using preset 'ocsp')"
    [ "$(awk -F'"' '/^CA=/{print $2}' "$sd/cert.meta")" = "$ca" ] || die "Signer certificate must be issued by CA '$ca'"

    banner "OCSP Responder for CA '$ca' on port $port (Press Ctrl+C to stop)"
    info "Note: Restart the responder after revoking any certificate to reload index.txt."
    key_passin "$sd/key.pem"

    exec "$OPENSSL" ocsp -index "$cad/index.txt" -port "$port" -rsigner "$sd/cert.pem" -rkey "$sd/key.pem" \
        "${KPASSIN[@]}" -CA "$cad/certs/ca.crt" -text -ignore_err
}

# Queries revocation status of a certificate via OCSP
ocsp_check() {
    local name=$1 url=${2:-} d="$PKI_DIR/issued/$1" ca
    [ -f "$d/cert.pem" ] || die "Certificate '$name' not found"
    ca=$(awk -F'"' '/^CA=/{print $2}' "$d/cert.meta")
    [ "$ca" = selfsigned ] && die "Self-signed certificates do not support OCSP"

    if [ -z "$url" ]; then
        load_ca_meta "$ca"
        url=$M_OCSP_URL
    fi
    [ -n "$url" ] || die "No OCSP URL configured (provide --url http://host:2560 or configure in CA metadata)"

    info "Sending OCSP request to: $url ..."
    "$OPENSSL" ocsp -issuer "$(ca_dir "$ca")/certs/ca.crt" -cert "$d/cert.pem" -url "$url" \
        -CAfile "$d/ca-bundle.pem" -no_nonce
}
