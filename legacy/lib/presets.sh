#!/usr/bin/env bash
###############################################################################
# lib/presets.sh - Certificate Profiles & Presets (KU, EKU, SANs, Validity)
###############################################################################

PRESETS="server wildcard client server-client user vpn-server vpn-client smime codesign ocsp timestamp custom"

# Loads profile definition for a preset into global P_* variables
load_preset() {
    P_DESC=""
    P_USE=""
    P_KU_RSA=""
    P_KU_ED=""
    P_EKU=""
    P_EKU_CRIT=no
    P_DAYS=365
    P_SAN_REQ=""
    P_SAN_ASK=""
    P_EXTRA=""
    P_PURPOSE=any
    P_CN_AUTO=""

    case $1 in
        server)
            P_DESC="TLS Server: Web server, reverse proxy, LDAPS, Proxmox, UniFi, Mail (SMTP/IMAP), Databases"
            P_USE="nginx/Traefik/Caddy: fullchain.pem + key.pem | HAProxy: combined.pem | Windows/IIS: cert.p12"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="serverAuth"
            P_DAYS=397
            P_SAN_REQ="dns|ip"
            P_SAN_ASK="dns ip"
            P_PURPOSE=sslserver
            P_CN_AUTO=dns
            ;;
        wildcard)
            P_DESC="TLS Server Wildcard: *.domain + base domain (e.g., *.homelab.lan and homelab.lan)"
            P_USE="Same as server - one certificate covering all subdomains at that level (e.g. app1.lan, app2.lan)"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="serverAuth"
            P_DAYS=397
            P_SAN_REQ="dns|ip"
            P_SAN_ASK="dns ip"
            P_PURPOSE=sslserver
            P_CN_AUTO=dns
            ;;
        client)
            P_DESC="TLS Client Auth: mTLS, 802.1X EAP-TLS (WiFi/Wired 802.1X), browser login, API clients"
            P_USE="Browser/Windows/macOS/iOS: import cert.p12 | curl/scripts: --cert cert.pem --key key.pem"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="clientAuth"
            P_DAYS=730
            P_SAN_ASK="dns email"
            P_PURPOSE=sslclient
            ;;
        server-client)
            P_DESC="Dual Server + Client: mTLS peers, cluster nodes, etcd, Syslog TLS, SaltStack, MQTT broker/client"
            P_USE="Services that accept inbound connections and initiate outbound mutual TLS connections"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="serverAuth, clientAuth"
            P_DAYS=397
            P_SAN_REQ="dns|ip"
            P_SAN_ASK="dns ip"
            P_PURPOSE=sslserver
            P_CN_AUTO=dns
            ;;
        user)
            P_DESC="User Identity: Client authentication + S/MIME combined (Login + Email signing & encryption)"
            P_USE="Import cert.p12 into mail client and operating system keychain / certificate store"
            P_KU_RSA="digitalSignature, nonRepudiation, keyEncipherment"
            P_KU_ED="digitalSignature, nonRepudiation"
            P_EKU="clientAuth, emailProtection"
            P_DAYS=730
            P_SAN_REQ="email"
            P_SAN_ASK="email"
            P_PURPOSE=sslclient
            P_CN_AUTO=email
            ;;
        vpn-server)
            P_DESC="VPN Server: OpenVPN, IPsec/IKEv2 (strongSwan, Windows RRAS, MikroTik, pfSense/OPNsense)"
            P_USE="OpenVPN: cert/key + ca-bundle.pem | strongSwan: swanctl x509 + private"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="serverAuth, 1.3.6.1.5.5.7.3.17, 1.3.6.1.5.5.8.2.2"
            P_DAYS=730
            P_SAN_REQ="dns|ip"
            P_SAN_ASK="dns ip"
            P_PURPOSE=sslserver
            P_CN_AUTO=dns
            ;;
        vpn-client)
            P_DESC="VPN Client: OpenVPN, IPsec/IKEv2 (user or device authentication)"
            P_USE="OpenVPN: embed inline into .ovpn configuration file | Windows/macOS/iOS: cert.p12"
            P_KU_RSA="digitalSignature, keyEncipherment"
            P_KU_ED="digitalSignature"
            P_EKU="clientAuth, 1.3.6.1.5.5.7.3.17"
            P_DAYS=730
            P_SAN_ASK="dns email"
            P_PURPOSE=sslclient
            ;;
        smime)
            P_DESC="S/MIME: Email signing and encryption (Outlook, Apple Mail, Thunderbird)"
            P_USE="Import cert.p12 into mail client; recipients must trust the Root or Intermediate CA"
            P_KU_RSA="digitalSignature, nonRepudiation, keyEncipherment"
            P_KU_ED="digitalSignature, nonRepudiation"
            P_EKU="emailProtection"
            P_DAYS=730
            P_SAN_REQ="email"
            P_SAN_ASK="email"
            P_PURPOSE=smimesign
            P_CN_AUTO=email
            ;;
        codesign)
            P_DESC="Code Signing: PowerShell scripts, binaries, packages, Git commit & container signatures"
            P_USE="PowerShell: Set-AuthenticodeSignature with cert.p12 | osslsigncode | openssl cms"
            P_KU_RSA="digitalSignature"
            P_KU_ED="digitalSignature"
            P_EKU="codeSigning"
            P_DAYS=1095
            P_PURPOSE=any
            ;;
        ocsp)
            P_DESC="OCSP Responder Signer: signs OCSP responses for the issuing CA"
            P_USE="pki ocsp-server --ca <ca> --signer <name>"
            P_KU_RSA="digitalSignature"
            P_KU_ED="digitalSignature"
            P_EKU="OCSPSigning"
            P_DAYS=365
            P_PURPOSE=ocsphelper
            P_EXTRA="noCheck = ignored"
            ;;
        timestamp)
            P_DESC="Time Stamping Authority (TSA, RFC 3161): signed timestamps for documents and code"
            P_USE="openssl ts -reply ... -signer cert.pem -inkey key.pem"
            P_KU_RSA="digitalSignature, nonRepudiation"
            P_KU_ED="digitalSignature, nonRepudiation"
            P_EKU="timeStamping"
            P_EKU_CRIT=yes
            P_DAYS=1825
            P_PURPOSE=timestampsign
            ;;
        custom)
            P_DESC="Custom Key Usage and Extended Key Usage configured freely"
            P_USE="Special scenarios - KU and EKU are stored in cert.meta for full renewal compatibility"
            P_KU_RSA="digitalSignature"
            P_KU_ED="digitalSignature"
            P_EKU=""
            P_DAYS=365
            P_SAN_ASK="dns ip email uri"
            P_PURPOSE=any
            ;;
        *)
            return 1
            ;;
    esac
}

# Determines preset family for config examples and deployment guides
preset_family() {
    case $1 in
        server|wildcard|server-client) echo server ;;
        vpn-server)                    echo vpnserver ;;
        client|user|vpn-client|smime)  echo client ;;
        codesign|ocsp|timestamp)       echo "$1" ;;
        *)                             echo custom ;;
    esac
}

# Prints an overview of all presets on the terminal
print_presets() {
    local p
    banner "Available Certificate Presets"
    for p in $PRESETS; do
        load_preset "$p"
        printf '\n%s%-16s%s %s\n' "$C_BLD" "● $p" "$C_RST" "$P_DESC"
        printf '  %-18s %s\n' "Usage:" "$P_USE"
        printf '  %-18s %s (RSA) / %s (Ed25519)\n' "keyUsage:" "${P_KU_RSA:--}" "${P_KU_ED:--}"
        printf '  %-18s %s%s\n' "EKU:" "${P_EKU:-customizable}" "$( [ "$P_EKU_CRIT" = yes ] && echo ' (critical)')"
        printf '  %-18s %s days\n' "Default validity:" "$P_DAYS"
        printf '  %-18s %s\n' "Required SANs:" "${P_SAN_REQ:-none (optional)}"
        [ -n "$P_EXTRA" ] && printf '  %-18s %s\n' "Extra flags:" "$P_EXTRA"
    done
    printf '\n'
    info "Tip: With '--ca selfsigned', any preset can also be generated as a standalone self-signed certificate without a CA."
}
