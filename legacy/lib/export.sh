#!/usr/bin/env bash
###############################################################################
# lib/export.sh - Certificate Exports (PKCS#12, DER) & Deployment Guide Generator
###############################################################################

# Exports certificate, private key, and chain to PKCS#12 (.p12)
export_p12() {
    local name=$1 d="$PKI_DIR/issued/$1" passout=() legacy=${2:-$I_P12_LEGACY}
    [ -f "$d/key.pem" ] || { warn "No private key found for '$name' (external CSR?) - PKCS#12 export not possible"; return 0; }

    key_passin "$d/key.pem"
    ensure_p12_pass
    passout=(-passout env:PKI_P12_PASS)

    if [ -s "$d/ca-bundle.pem" ] && ! cmp -s "$d/ca-bundle.pem" "$d/cert.pem"; then
        ssl pkcs12 -export -in "$d/cert.pem" -inkey "$d/key.pem" "${KPASSIN[@]}" -certfile "$d/ca-bundle.pem" \
            -name "$name" "${passout[@]}" -out "$d/cert.p12" || die "PKCS#12 export failed"
    else
        ssl pkcs12 -export -in "$d/cert.pem" -inkey "$d/key.pem" "${KPASSIN[@]}" \
            -name "$name" "${passout[@]}" -out "$d/cert.p12" || die "PKCS#12 export failed"
    fi
    chmod 600 "$d/cert.p12"
    ok "PKCS#12 file created: cert.p12 (AES-256/PBKDF2 with complete chain)"

    if [ "$legacy" = yes ]; then
        ssl pkcs12 -export -in "$d/cert.pem" -inkey "$d/key.pem" "${KPASSIN[@]}" -certfile "$d/ca-bundle.pem" \
            -name "$name" "${passout[@]}" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
            -out "$d/cert-legacy.p12" || die "Legacy PKCS#12 export failed"
        chmod 600 "$d/cert-legacy.p12"
        ok "Legacy PKCS#12 created: cert-legacy.p12 (3DES/SHA1 for legacy appliances/Windows)"
    fi
}

# Exports certificate in binary DER format (.der)
export_der() {
    local d="$PKI_DIR/issued/$1"
    "$OPENSSL" x509 -in "$d/cert.pem" -outform der -out "$d/cert.der"
    chmod 644 "$d/cert.der"
    ok "DER format created: cert.der"
}

# Displays all available files in a certificate directory
print_leaf_files() {
    local d=$1 f
    section "Files in ${d#"$PWD"/}"
    for f in key.pem cert.pem chain.pem fullchain.pem ca-bundle.pem combined.pem cert.p12 cert-legacy.p12 cert.der cert.csr ext.cnf cert.meta; do
        [ -e "$d/$f" ] || continue
        case $f in
            key.pem)         printf '  %-16s private key - KEEP STRICTLY CONFIDENTIAL\n' "$f" >&2 ;;
            cert.pem)        printf '  %-16s certificate only (end-entity)\n' "$f" >&2 ;;
            chain.pem)       [ -s "$d/$f" ] && printf '  %-16s intermediate certificate(s) (without root)\n' "$f" >&2 ;;
            fullchain.pem)   printf '  %-16s certificate + intermediate (for Nginx, Traefik, Caddy, Apache)\n' "$f" >&2 ;;
            ca-bundle.pem)   printf '  %-16s intermediate + root (for trust stores, mTLS client validation)\n' "$f" >&2 ;;
            combined.pem)    printf '  %-16s private key + fullchain in a single file (for HAProxy)\n' "$f" >&2 ;;
            cert.p12)        printf '  %-16s PKCS#12 bundle (Windows, macOS, browser, email client)\n' "$f" >&2 ;;
            cert-legacy.p12) printf '  %-16s PKCS#12 3DES/SHA1 for legacy systems and appliances\n' "$f" >&2 ;;
            cert.der)        printf '  %-16s binary DER format certificate\n' "$f" >&2 ;;
            cert.csr)        printf '  %-16s Certificate Signing Request (CSR)\n' "$f" >&2 ;;
            ext.cnf)         printf '  %-16s X.509 extensions configuration used\n' "$f" >&2 ;;
            cert.meta)       printf '  %-16s metadata and reproducible template for renewals\n' "$f" >&2 ;;
        esac
    done
    load_preset "$(awk -F'"' '/^PRESET=/{print $2}' "$d/cert.meta" 2>/dev/null)" 2>/dev/null && [ -n "$P_USE" ] && printf '\n  Intended usage: %s\n' "$P_USE" >&2
    return 0
}

# Maps preset families to common services and recommended files
usage_rows() {
    local p=$1
    case $(preset_family "$p") in
        server)
            echo "Nginx / Traefik / Caddy|fullchain.pem + key.pem"
            echo "Apache HTTPD (>= 2.4.8)|fullchain.pem + key.pem"
            echo "HAProxy|combined.pem"
            echo "Proxmox VE (Web GUI)|fullchain.pem + key.pem"
            echo "TrueNAS CORE / SCALE|fullchain.pem + key.pem"
            echo "UniFi OS (UDM / CloudKey)|fullchain.pem + key.pem"
            echo "UniFi Network App (Linux)|cert.p12"
            echo "Windows / IIS Web Server|cert.p12"
            echo "Docker Containers|fullchain.pem + key.pem (mounted :ro)"
            ;;
        vpnserver)
            echo "OpenVPN Server|cert.pem + key.pem + chain.pem"
            echo "strongSwan (swanctl)|cert.pem + key.pem + chain.pem"
            echo "Windows RRAS (VPN Server)|cert.p12"
            ;;
        client)
            if [ "$p" = vpn-client ]; then echo "OpenVPN Client (.ovpn)|cert.pem + key.pem (+ ca-bundle.pem)"; fi
            echo "Windows / macOS / Browser|cert.p12"
            if [ "$p" = user ] || [ "$p" = smime ]; then echo "Email Client (S/MIME)|cert.p12"; fi
            if [ "$p" = vpn-client ]; then echo "Windows/macOS IKEv2|cert.p12"; fi
            echo "curl / Scripts / REST APIs|cert.pem + key.pem"
            echo "802.1X EAP-TLS (WiFi/Switch)|cert.p12 (OS) or cert.pem + key.pem (wpa_supplicant)"
            ;;
        codesign)
            echo "PowerShell (Authenticode)|cert.p12"
            echo "osslsigncode / openssl cms|fullchain.pem + key.pem"
            ;;
        ocsp)
            echo "OCSP Responder Daemon|cert.pem + key.pem"
            ;;
        timestamp)
            echo "TSA (RFC 3161 openssl ts)|cert.pem + key.pem + chain.pem"
            ;;
        custom)
            echo "Linux Services|fullchain.pem + key.pem"
            echo "Windows / GUI Clients|cert.p12"
            ;;
    esac
    case $(preset_family "$p") in
        server|vpnserver|custom) echo "Client Trust (Install Root CA)|publish/root.pem (once per client device)" ;;
        client) echo "Server Client Verification (mTLS)|ca-bundle.pem (CA trust chain)" ;;
    esac
}

# Quick summary printed directly after certificate issuance
print_quick_usage() {
    local d=$1 name pre what files hint
    name=$(basename "$d")
    pre=$(meta_get "$d" PRESET)

    section "Successfully issued: ${d#"$PKI_DIR"/} (valid until $(cert_end_date "$d/cert.pem"))"
    printf '\n  %s%-32s %s%s\n' "$C_BLD" "USAGE / SERVICE" "RECOMMENDED FILES" "$C_RST" >&2
    while IFS='|' read -r what files; do
        hint=""
        case $files in *cert.p12*) [ -f "$d/cert.p12" ] || hint="  (export with: pki export $name --p12)";; esac
        printf '  %-32s %s%s%s%s\n' "$what" "$files" "$C_YEL" "$hint" "$C_RST" >&2
    done < <(usage_rows "$pre")
    printf '\n' >&2

    if [ ! -f "$d/key.pem" ]; then
        info "Private key retained by requester (external CSR)."
    elif key_is_encrypted "$d/key.pem"; then
        warn "key.pem is password-protected. For unattended daemons create an unencrypted copy: openssl pkey -in key.pem -out key-plain.pem"
    fi
    printf '  Deployment Guide  :  %s\n' "${d#"$PWD"/}/GUIDE.txt" >&2
    printf '  Verify Certificate:  pki verify %s\n\n' "$name" >&2
}

HOWTO_N=0
howto_sec() {
    HOWTO_N=$((HOWTO_N+1))
    printf '\n%s\n# %s. %s\n%s\n' "$HR" "$HOWTO_N" "$1" "$HR"
}

# Writes detailed, tailored deployment documentation (GUIDE.txt & ANLEITUNG.txt)
write_howto() {
    local d=$1 f="$1/GUIDE.txt" fanl="$1/ANLEITUNG.txt" name pre ca cn dns ip fam host tgt root enc=no
    local srvnames="" main="" aliases="" caddyhost x what files clientca orgslug script_cmd
    name=$(basename "$d")
    pre=$(meta_get "$d" PRESET)
    ca=$(meta_get "$d" CA)
    cn=$(meta_get "$d" CN)
    dns=$(meta_get "$d" DNS)
    ip=$(meta_get "$d" IP)
    fam=$(preset_family "$pre")
    root="$PKI_DIR/publish/root.pem"
    tgt="/etc/ssl/$name"
    key_is_encrypted "$d/key.pem" && enc=yes
    orgslug=$(name_from_cn "${PKI_ORG:-pki}")
    script_cmd="${SCRIPT_PATH:-pki}"

    # Prepare names for server configurations
    split_list "$dns"
    for x in "${SPLIT[@]}"; do
        srvnames="${srvnames:+$srvnames }$x"
        caddyhost="${caddyhost:+$caddyhost, }$x"
        case $x in \**) ;; *) if [ -z "$main" ]; then main=$x; continue; fi ;; esac
        aliases="${aliases:+$aliases }$x"
    done
    split_list "$ip"
    for x in "${SPLIT[@]}"; do caddyhost="${caddyhost:+$caddyhost, }$x"; done
    [ -z "$main" ] && main=$cn
    [ -z "$srvnames" ] && srvnames=$cn
    [ -z "$caddyhost" ] && caddyhost=$cn
    host=$main; [ "$pre" = wildcard ] && host="my-server"
    [ -z "$host" ] && host="my-server"
    clientca=$(list_intermediates | grep -i client | head -n1 || true)
    [ -z "$clientca" ] && clientca="<client-ca>"

    HOWTO_N=0
    {
        printf '%s\n# DEPLOYMENT GUIDE & INTEGRATION FOR: %s\n%s\n' "$HR" "$name" "$HR"
        printf '#\n'
        printf '#  Preset       : %s\n' "$pre"
        printf '#  Common Name  : %s\n' "$cn"
        [ -n "$dns" ] && printf '#  DNS SANs     : %s\n' "$(printf '%s' "$dns" | sed 's/,/, /g')"
        [ -n "$ip" ]  && printf '#  IP SANs      : %s\n' "$(printf '%s' "$ip" | sed 's/,/, /g')"
        printf '#  Issuer CA    : %s\n' "$ca"
        printf '#  Valid Until  : %s\n' "$(cert_end_date "$d/cert.pem")"
        printf '#  Directory    : %s\n' "$d"
        printf '#\n#  Generated on %s by pki.sh %s. Updated automatically on "pki renew".\n' "$(now)" "$VERSION"
        printf '#  Note: Paths in examples are standard conventions; adjust for your environment.\n'

        howto_sec "Which file for which purpose?"
        while IFS='|' read -r what files; do printf '  %-32s %s\n' "$what" "$files"; done < <(usage_rows "$pre")
        cat <<EOF

  Files in this directory:
    key.pem          Private key - KEEP CONFIDENTIAL, readable only by daemon
    cert.pem         Leaf certificate only
    chain.pem        Intermediate CA certificate(s) without Root
    fullchain.pem    Leaf + Intermediate            <- Standard for Nginx, Apache, Traefik, Caddy
    ca-bundle.pem    Intermediate + Root             <- For validating peers / client trust
    combined.pem     Private key + fullchain in one  <- HAProxy
    cert.p12         PKCS#12 bundle with password    <- Windows, macOS, browser, email client
EOF

        if [ "$enc" = yes ]; then
            howto_sec "IMPORTANT: key.pem is password-protected"
            cat <<EOF
  Services such as Nginx, Apache, Proxmox, or Docker cannot unlock an encrypted key
  during unattended boot. Generate an unencrypted copy:

    openssl pkey -in $d/key.pem -out $d/key-plain.pem && chmod 600 $d/key-plain.pem

  Then reference 'key-plain.pem' in your service configuration.
EOF
        fi

        case $fam in
        server)
            howto_sec "Step 1: Copy certificates to target server"
            cat <<EOF
  Copy to remote server via SSH / SCP:
    ssh root@$host 'mkdir -p $tgt'
    scp $d/fullchain.pem $d/key.pem $d/combined.pem root@$host:$tgt/
    ssh root@$host 'chmod 644 $tgt/fullchain.pem && chmod 600 $tgt/key.pem $tgt/combined.pem'

  Local usage on this server:
    sudo mkdir -p $tgt
    sudo cp $d/{fullchain,key,combined}.pem $tgt/
    sudo chmod 644 $tgt/fullchain.pem && sudo chmod 600 $tgt/key.pem $tgt/combined.pem
EOF
            howto_sec "Nginx Configuration"
            cat <<EOF
  server {
      listen 443 ssl;
      listen [::]:443 ssl;
      http2 on;
      server_name $srvnames;

      ssl_certificate     $tgt/fullchain.pem;
      ssl_certificate_key $tgt/key.pem;
      ssl_protocols       TLSv1.2 TLSv1.3;

      location / {
          proxy_pass http://127.0.0.1:8080;
      }
  }

  Test syntax and reload:
    nginx -t && systemctl reload nginx
EOF
            howto_sec "Apache HTTPD Configuration"
            cat <<EOF
  <VirtualHost *:443>
      ServerName  $main
$( [ -n "$aliases" ] && printf '      ServerAlias %s\n' "$aliases" )
      SSLEngine on
      SSLCertificateFile    $tgt/fullchain.pem
      SSLCertificateKeyFile $tgt/key.pem
      SSLProtocol -all +TLSv1.2 +TLSv1.3
  </VirtualHost>

  Test syntax and reload:
    apachectl configtest && systemctl reload apache2
EOF
            howto_sec "HAProxy Configuration"
            cat <<EOF
  mkdir -p /etc/haproxy/certs
  cp $tgt/combined.pem /etc/haproxy/certs/$name.pem && chmod 600 /etc/haproxy/certs/$name.pem

  frontend https
      bind :443 ssl crt /etc/haproxy/certs/$name.pem alpn h2,http/1.1
      default_backend app_servers

  Test syntax and reload:
    haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
EOF
            howto_sec "Traefik (Docker Compose)"
            cat <<EOF
  services:
    traefik:
      image: traefik:v3
      ports: ["443:443"]
      command:
        - --entrypoints.websecure.address=:443
        - --providers.file.filename=/etc/traefik/dynamic.yml
      volumes:
        - $tgt:/certs:ro
        - ./dynamic.yml:/etc/traefik/dynamic.yml:ro

  # dynamic.yml
  tls:
    certificates:
      - certFile: /certs/fullchain.pem
        keyFile:  /certs/key.pem
EOF
            howto_sec "Caddy Web Server"
            cat <<EOF
  $caddyhost {
      tls $tgt/fullchain.pem $tgt/key.pem
      reverse_proxy 127.0.0.1:8080
  }

  chown root:caddy $tgt/key.pem && chmod 640 $tgt/key.pem
  caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
EOF
            howto_sec "Proxmox VE (Web GUI)"
            cat <<EOF
  Option A - Shell (standard file locations):
    scp $d/fullchain.pem root@$host:/etc/pve/local/pveproxy-ssl.pem
    scp $d/key.pem       root@$host:/etc/pve/local/pveproxy-ssl.key
    ssh root@$host 'systemctl restart pveproxy'

  Option B - Web GUI:
    Datacenter > Node > System > Certificates > "Upload Custom Certificate"
    - Private Key        = content of key.pem
    - Certificate Chain  = content of fullchain.pem
EOF
            howto_sec "TrueNAS CORE / SCALE"
            cat <<EOF
  1. Credentials > Certificates > Certificate Authorities > Add (Import CA):
     Paste content of $root.
  2. Credentials > Certificates > Certificates > Add (Import Certificate):
     - Certificate = content of fullchain.pem
     - Private Key = content of key.pem
  3. System > General > GUI > Set "GUI SSL Certificate" to the newly imported certificate.
EOF
            howto_sec "UniFi OS (UDM / Gateway / CloudKey)"
            cat <<EOF
  SSH to UniFi Console:
    scp $d/fullchain.pem root@$host:/data/unifi-core/config/unifi-core.crt
    scp $d/key.pem       root@$host:/data/unifi-core/config/unifi-core.key
    ssh root@$host 'systemctl restart unifi-core'
EOF
            howto_sec "Windows Server / IIS"
            cat <<EOF
  PowerShell as Administrator:
    \$pw = Read-Host "P12 Password" -AsSecureString
    Import-PfxCertificate -FilePath .\\cert.p12 -CertStoreLocation Cert:\\LocalMachine\\My -Password \$pw
    Import-Certificate    -FilePath .\\root.crt -CertStoreLocation Cert:\\LocalMachine\\Root

  In IIS Manager: Site > Bindings > https > select SSL certificate "$cn".
EOF
            ;;
        vpnserver)
            howto_sec "OpenVPN Server"
            cat <<EOF
  Deploy files:
    cp $d/cert.pem  /etc/openvpn/server/$name.crt
    cp $d/key.pem   /etc/openvpn/server/$name.key && chmod 600 /etc/openvpn/server/$name.key
    cp $d/chain.pem /etc/openvpn/server/chain.pem
    cp $PKI_DIR/intermediate/$clientca/certs/chain.pem /etc/openvpn/server/ca.pem
    cp $PKI_DIR/publish/$clientca.crl.pem /etc/openvpn/server/crl.pem

  In /etc/openvpn/server/server.conf:
    ca          /etc/openvpn/server/ca.pem
    cert        /etc/openvpn/server/$name.crt
    key         /etc/openvpn/server/$name.key
    extra-certs /etc/openvpn/server/chain.pem
    crl-verify  /etc/openvpn/server/crl.pem
    remote-cert-tls client
EOF
            howto_sec "strongSwan (swanctl)"
            cat <<EOF
  cp $d/cert.pem  /etc/swanctl/x509/$name.pem
  cp $d/key.pem   /etc/swanctl/private/$name.key && chmod 600 /etc/swanctl/private/$name.key
  cp $d/chain.pem /etc/swanctl/x509ca/$ca.pem
  cp $root        /etc/swanctl/x509ca/root.pem
  swanctl --load-all
EOF
            ;;
        client)
            howto_sec "Importing Client Certificate"
            cat <<EOF
  Windows:
    Double click 'cert.p12' > Current User > enter password.
    To trust the Root CA: double click 'root.crt' > Trusted Root Certification Authorities.

  macOS:
    security import $d/cert.p12 -k ~/Library/Keychains/login.keychain-db
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $root

  Linux (curl / mTLS):
    curl --cert $d/cert.pem --key $d/key.pem --cacert $root https://$main/

  802.1X EAP-TLS (Network Authentication):
    - Windows: Certificate imported in Personal store, WiFi configured with EAP-TLS.
    - Linux wpa_supplicant.conf:
        eap=TLS
        identity="$cn"
        ca_cert="$root"
        client_cert="$d/cert.pem"
        private_key="$d/key.pem"
EOF
            ;;
        codesign)
            howto_sec "Code Signing Usage"
            cat <<EOF
  PowerShell script signing:
    \$cert = Get-PfxCertificate -FilePath .\\cert.p12
    Set-AuthenticodeSignature -FilePath .\\script.ps1 -Certificate \$cert -HashAlgorithm SHA256

  Linux / binary signing:
    osslsigncode sign -certs $d/fullchain.pem -key $d/key.pem -h sha256 -in app.exe -out app-signed.exe
EOF
            ;;
        ocsp)
            howto_sec "OCSP Responder Service"
            cat <<EOF
  Launch:
    $script_cmd ocsp-server --ca $ca --signer $name --port 2560
EOF
            ;;
        timestamp)
            howto_sec "Time Stamping Authority (TSA)"
            cat <<EOF
  openssl ts -reply -config tsa.cnf -queryfile request.tsq -signer $d/cert.pem -inkey $d/key.pem -out response.tsr
EOF
            ;;
        custom)
            howto_sec "Custom Integration"
            cat <<EOF
  Ready to deploy: fullchain.pem and key.pem
EOF
            ;;
        esac

        if [ "$fam" = server ] || [ "$fam" = vpnserver ] || [ "$fam" = custom ]; then
            howto_sec "Trusting the Root CA on Client Devices (Once per device)"
            cat <<EOF
  To avoid browser and TLS client warnings on client devices:

  Debian / Ubuntu / Proxmox:
    sudo cp $root /usr/local/share/ca-certificates/$orgslug-root.crt && sudo update-ca-certificates

  RHEL / Rocky Linux / Fedora:
    sudo cp $root /etc/pki/ca-trust/source/anchors/$orgslug-root.pem && sudo update-ca-trust

  macOS:
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $root

  Windows (PowerShell as Administrator):
    Import-Certificate -FilePath .\\root.crt -CertStoreLocation Cert:\\LocalMachine\\Root

  Firefox (Use OS Trust Store):
    In Firefox 'about:config', set 'security.enterprise_roots.enabled' to 'true'.
EOF
        fi

        howto_sec "Testing & Verifying the Certificate"
        cat <<EOF
  Verify chain, CRL, and purpose:
    $script_cmd verify $name$( [ "$fam" = server ] && [ "$pre" != wildcard ] && printf ' --host %s' "$main")

  Test remote TLS handshake after deployment:
    openssl s_client -connect $host:443 -servername $main -CAfile $root </dev/null
    -> Expected result: "Verify return code: 0 (ok)"
EOF

        printf '\n%s\n# Renew Certificate: %s renew %s --revoke-old\n%s\n' "$HR" "$script_cmd" "$name" "$HR"
    } > "$f"
    chmod 644 "$f"
    cp "$f" "$fanl" 2>/dev/null || true
}

# CLI command to regenerate deployment guide
cmd_guide() {
    local n
    [ -n "${1:-}" ] || die "Usage: pki guide <name> | --all"
    if [ "$1" = --all ]; then
        for n in $(list_issued); do
            write_howto "$PKI_DIR/issued/$n"
            ok "GUIDE.txt updated for: $n"
        done
    else
        [ -f "$PKI_DIR/issued/$1/cert.meta" ] || die "Certificate '$1' not found"
        write_howto "$PKI_DIR/issued/$1"
        ok "Documentation written: ${PKI_DIR#"$PWD"/}/issued/$1/GUIDE.txt"
        print_quick_usage "$PKI_DIR/issued/$1"
    fi
}

cmd_anleitung() {
    cmd_guide "$@"
}
