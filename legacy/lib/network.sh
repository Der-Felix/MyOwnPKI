#!/usr/bin/env bash
###############################################################################
# lib/network.sh - Hostname/IP Autodetection (DNS, /etc/hosts) & Quick Mode
###############################################################################

# Resolves all IPs for a hostname (excluding loopback 127.x/::1 and link-local fe80:)
lookup_ips() {
    local n=$1 out=""
    if have getent; then
        out=$(with_timeout getent ahosts "$n" 2>/dev/null | awk '{print $1}') || true
    elif have dscacheutil; then
        out=$(with_timeout dscacheutil -q host -a name "$n" 2>/dev/null | awk '/^ip(v6)?_address:/{print $2}') || true
    fi
    if [ -z "$out" ] && have host; then
        out=$(with_timeout host "$n" 2>/dev/null | awk '/has address|has IPv6 address/{print $NF}') || true
    fi
    printf '%s\n' "$out" | awk 'NF && $1 !~ /^127\./ && $1 != "::1" && tolower($1) !~ /^fe80:/' | sort -u
}

# Resolves FQDN for a short name
lookup_fqdn() {
    local n=$1 out=""
    if have getent; then
        out=$(with_timeout getent hosts "$n" 2>/dev/null | awk 'NR==1{for(i=2;i<=NF;i++) if($i ~ /\./){print $i; exit}}') || true
    fi
    if [ -z "$out" ] && have host; then
        out=$(with_timeout host "$n" 2>/dev/null | awk '/has address/{print $1; exit}') || true
    fi
    out=${out%.}
    lower "$out"
}

# Reverse-DNS lookup for an IP address
lookup_ptr() {
    local ip=$1 out=""
    if have getent; then
        out=$(with_timeout getent hosts "$ip" 2>/dev/null | awk 'NR==1{print $2}') || true
    fi
    if [ -z "$out" ] && have host; then
        out=$(with_timeout host "$ip" 2>/dev/null | awk '/domain name pointer/{print $NF; exit}') || true
    fi
    out=${out%.}
    lower "$out"
}

# autodetect <hostname|ip> -> populates AD_CN, AD_DNS, AD_IP
autodetect() {
    local in fq short x
    in=$(lower "$(trim "$1")")
    AD_CN="" AD_DNS="" AD_IP=""

    if is_ipv4 "$in" || is_ipv6 "$in"; then
        AD_IP=$in
        AD_CN=$in
        fq=$(lookup_ptr "$in")
        if [ -n "$fq" ] && is_hostname "$fq"; then
            AD_CN=$fq
            AD_DNS=$fq
            short=${fq%%.*}
            [ "$short" != "$fq" ] && AD_DNS="$AD_DNS,$short"
        fi
        return 0
    fi

    case $in in
        \**) warn "Please generate wildcard certificates using preset 'wildcard'"; return 1 ;;
    esac

    is_hostname "$in" || { warn "Invalid hostname: $in"; return 1; }

    case $in in
        *.*) fq=$in ;;
        *)   fq=$(lookup_fqdn "$in"); case $fq in *.*) ;; *) fq="" ;; esac ;;
    esac

    short=${in%%.*}
    AD_CN=${fq:-$in}
    AD_DNS=$AD_CN
    [ "$short" != "$AD_CN" ] && AD_DNS="$AD_DNS,$short"

    for x in $(lookup_ips "$AD_CN"); do
        AD_IP=$(add_uniq "$AD_IP" "$(lower "$x")")
    done
    return 0
}

# Interactive prompt: Display DNS auto-discovery findings and offer adoption
autodetect_offer() {
    local use
    info "Resolving network configuration for '$I_CN' via DNS ..."
    autodetect "$I_CN" || return 0
    if [ -z "$AD_IP" ] && [ "$AD_DNS" = "$(lower "$I_CN")" ]; then
        info "No additional domain names or IP addresses discovered on the network"
        return 0
    fi

    kv "CN"       "$AD_CN"
    kv "DNS SANs" "$(printf '%s' "$AD_DNS" | sed 's/,/, /g')"
    kv "IP SANs"  "$( [ -n "$AD_IP" ] && printf '%s' "$AD_IP" | sed 's/,/, /g' || echo '(none detected)')"

    ask_yn use "Accept detected network parameters?" y
    if [ "$use" = yes ]; then
        I_CN=$AD_CN
        I_DNS=$AD_DNS
        I_IP=$AD_IP
    fi
    return 0
}

# CLI Quick Mode: Issue server certificate directly from hostname or IP
cmd_quick() {
    local h=${1:-} args=() nolookup=0
    [ -n "$h" ] && shift || die "Usage: pki quick <hostname|ip> [--dns ..] [--ip ..] [--no-lookup]"

    while [ $# -gt 0 ]; do
        case $1 in
            --no-lookup) nolookup=1 ;;
            *)           args+=("$1") ;;
        esac
        shift
    done

    reset_issue_vars
    I_PRESET=server
    [ ${#args[@]} -gt 0 ] && parse_issue_opts "${args[@]}"

    case $(preset_family "$I_PRESET") in
        server|vpnserver) ;;
        *) die "quick command is reserved for server presets (server, server-client, vpn-server)" ;;
    esac

    if [ "$nolookup" = 1 ]; then
        I_CN=${I_CN:-$(lower "$h")}
    else
        autodetect "$h" || die "Network autodetection failed"
        [ -z "$AD_IP" ] && warn "No IP address resolved for '$h' via DNS - specify manually with --ip if required"
        I_CN=${I_CN:-$AD_CN}
        I_DNS="$AD_DNS${I_DNS:+,$I_DNS}"
        I_IP="$AD_IP${I_IP:+,$I_IP}"
    fi

    issue_cert
}
