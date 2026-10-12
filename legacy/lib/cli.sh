#!/usr/bin/env bash
###############################################################################
# lib/cli.sh - Command Line Interface (CLI) Parser and Argument Dispatcher
###############################################################################

need_arg() {
    [ -n "${2:-}" ] || die "Option $1 requires an argument"
}

# Common options for issue / selfsigned / sign-csr
parse_issue_opts() {
    while [ $# -gt 0 ]; do
        case $1 in
            --cn)         need_arg "$@"; I_CN=$2; shift ;;
            --dns)        need_arg "$@"; I_DNS="${I_DNS:+$I_DNS,}$2"; shift ;;
            --ip)         need_arg "$@"; I_IP="${I_IP:+$I_IP,}$2"; shift ;;
            --email)      need_arg "$@"; I_EMAIL="${I_EMAIL:+$I_EMAIL,}$2"; shift ;;
            --uri)        need_arg "$@"; I_URI="${I_URI:+$I_URI,}$2"; shift ;;
            --domain)     need_arg "$@"; I_DOMAIN=$2; shift ;;
            --ca)         need_arg "$@"; I_CA=$2; shift ;;
            --key)        need_arg "$@"; I_KEY=$2; shift ;;
            --days)       need_arg "$@"; I_DAYS=$2; shift ;;
            --name)       need_arg "$@"; I_NAME=$2; shift ;;
            --ou)         need_arg "$@"; I_OU=$2; shift ;;
            --preset)     need_arg "$@"; I_PRESET=$2; shift ;;
            --ku)         need_arg "$@"; I_CUSTOM_KU=$2; shift ;;
            --eku)        need_arg "$@"; I_CUSTOM_EKU=$2; shift ;;
            --key-pass)   I_KEY_PASS=yes ;;
            --p12)        I_EXPORT_P12=yes ;;
            --p12-legacy) I_EXPORT_P12=yes; I_P12_LEGACY=yes ;;
            --der)        I_EXPORT_DER=yes ;;
            --force)      I_FORCE=1 ;;
            --no-csr-san) I_NO_CSR_SAN=1 ;;
            *) die "Unknown option: $1  (view help with: pki help)" ;;
        esac
        shift
    done
}

cmd_init() {
    set_conf_defaults
    R_CN="" R_KEY="" R_DAYS="" R_PASS=yes
    local ints=() n

    while [ $# -gt 0 ]; do
        case $1 in
            --org)          need_arg "$@"; PKI_ORG=$2; shift ;;
            --country)      need_arg "$@"; PKI_COUNTRY=$2; shift ;;
            --state)        need_arg "$@"; PKI_STATE=$2; shift ;;
            --locality)     need_arg "$@"; PKI_LOCALITY=$2; shift ;;
            --ou)           need_arg "$@"; PKI_OU=$2; shift ;;
            --cn)           need_arg "$@"; R_CN=$2; shift ;;
            --key)          need_arg "$@"; R_KEY=$2; shift ;;
            --days)         need_arg "$@"; R_DAYS=$2; shift ;;
            --leaf-key)     need_arg "$@"; DEFAULT_LEAF_KEY=$2; shift ;;
            --crl-days)     need_arg "$@"; CRL_DAYS=$2; shift ;;
            --aia-url)      need_arg "$@"; AIA_BASE_URL=$2; shift ;;
            --no-pass)      R_PASS=no ;;
            --intermediate) need_arg "$@"; ints+=("$2"); shift ;;
            *) die "Unknown option for init: $1" ;;
        esac
        shift
    done

    for n in "$PKI_ORG" "$PKI_OU" "$PKI_STATE" "$PKI_LOCALITY" "$AIA_BASE_URL"; do
        check_safe Value "$n"
    done
    valid_keytype "$DEFAULT_LEAF_KEY" || die "Invalid --leaf-key"
    [ -z "$R_CN" ] && R_CN="$PKI_ORG Root CA"
    [ -z "$R_KEY" ] && R_KEY=rsa4096
    DEFAULT_CA_KEY=$R_KEY
    [ -z "$R_DAYS" ] && R_DAYS=$ROOT_DAYS
    ROOT_DAYS=$R_DAYS

    create_root

    for n in "${ints[@]}"; do
        N_NAME=$n N_CN="" N_KEY="" N_DAYS="" N_PASS=$R_PASS N_PATHLEN=0
        N_PERMIT_DNS="" N_PERMIT_IP="" N_EKU_LIMIT="" N_OCSP_URL=""
        create_intermediate
    done
}

cmd_ca_new() {
    require_pki
    N_NAME=${1:-}
    [ -n "$N_NAME" ] && shift || die "Usage: pki ca-new <name> [options]"
    N_NAME=$(lower "$N_NAME")
    N_CN="" N_KEY="" N_DAYS="" N_PASS=yes N_PATHLEN=0 N_PERMIT_DNS="" N_PERMIT_IP="" N_EKU_LIMIT="" N_OCSP_URL=""
    local setdef=0

    while [ $# -gt 0 ]; do
        case $1 in
            --cn)         need_arg "$@"; N_CN=$2; shift ;;
            --key)        need_arg "$@"; N_KEY=$2; shift ;;
            --days)       need_arg "$@"; N_DAYS=$2; shift ;;
            --no-pass)    N_PASS=no ;;
            --pathlen)    need_arg "$@"; N_PATHLEN=$2; shift ;;
            --permit-dns) need_arg "$@"; N_PERMIT_DNS="${N_PERMIT_DNS:+$N_PERMIT_DNS,}$2"; shift ;;
            --permit-ip)  need_arg "$@"; N_PERMIT_IP="${N_PERMIT_IP:+$N_PERMIT_IP,}$2"; shift ;;
            --eku-limit)  need_arg "$@"; N_EKU_LIMIT=$2; shift ;;
            --ocsp-url)   need_arg "$@"; N_OCSP_URL=$2; shift ;;
            --default)    setdef=1 ;;
            *) die "Unknown option for ca-new: $1" ;;
        esac
        shift
    done

    check_safe Value "$N_OCSP_URL"
    check_safe Value "$N_EKU_LIMIT"
    create_intermediate

    if [ "$setdef" = 1 ]; then
        DEFAULT_CA=$N_NAME
        write_config
        ok "DEFAULT_CA set to: $N_NAME"
    fi
}

usage() {
    cat <<EOF
$HR
# OpenSSL Homelab PKI Generator $VERSION
$HR

USAGE:
  pki                                   Interactive TUI menu and wizards
  pki [--dir PATH] [-y] <command> [opt] CLI mode (automation, CI/CD, and scripts)

GLOBAL OPTIONS:
  --dir PATH           PKI root directory (default: ./pki or \$PKI_DIR)
  -y, --yes            Assume yes to all prompts (for non-interactive automation)
  --no-color           Disable ANSI colored console output (or set NO_COLOR=1)

COMMANDS BY CATEGORY:

1. Infrastructure & CAs
  init                 Initialize new PKI (Root CA + optional Intermediates)
                       Options: --org NAME, --country CC, --state, --locality, --ou
                                 --cn NAME, --key rsa4096|..., --days 7300, --no-pass
                                 --leaf-key rsa3072, --crl-days 30, --aia-url URL
                                 --intermediate NAME (can be repeated)
  ca-new NAME          Create a new Intermediate CA
                       Options: --cn, --key, --days, --no-pass, --pathlen N
                                 --permit-dns LIST, --permit-ip LIST
                                 --eku-limit LIST, --ocsp-url URL, --default
  doctor               System environment diagnosis & pre-flight health checks

2. Certificate Issuance
  quick HOST           1-Click TLS Server Certificate with automatic DNS/IP discovery!
                       Options: --dns LIST, --ip LIST, --ca CA, --days N, --no-lookup
  issue PRESET         Issue a certificate using a profile preset (see: pki presets)
                       Options: --cn NAME (required)
                                 --dns LIST, --ip LIST, --email LIST, --uri LIST
                                 --domain DOMAIN (for wildcard preset)
                                 --ca CA (default: DEFAULT_CA), --key TYPE, --days N
                                 --name DIR, --ou OU, --key-pass
                                 --p12, --p12-legacy, --der, --force
  selfsigned           Shortcut: pki issue <preset> --ca selfsigned
  sign-csr FILE        Sign an external CSR (same options as 'issue', plus --no-csr-san)

3. Inspection & Diagnostics
  list, ls             Tabular overview of all CAs & issued certificates with validity
  search QUERY         Filter certificates (by name, CN, IP, SAN, status, or serial)
  status, dashboard    Live summary dashboard of PKI health
  show NAME|FILE       Show certificate details (--full for complete OpenSSL text)
  verify NAME          Comprehensive verification: Chain, CRL, Purpose, Key Match (--host H)
  check [--days N]     Expiry monitoring (Exit 0=ok, 2=certificates/CRLs expiring soon)
  guide, anleitung     Regenerate GUIDE.txt integration documentation (Nginx, Proxmox, etc.)

4. Lifecycle & Maintenance
  renew NAME           Renew leaf certificate (--keep-key, --revoke-old, --days N)
  renew-ca NAME        Renew Root or Intermediate CA certificate (retains private key)
  revoke NAME          Revoke a certificate or Intermediate CA (--reason REASON)
  crl [--ca NAME]      Regenerate CRL revocation list (without --ca: all CAs)
  export NAME          Export certificate bundles (--p12, --p12-legacy, --der)
  backup [FILE]        Create secure compressed tar.gz backup of entire PKI directory
  restore FILE         Restore PKI from a backup archive

5. Templates, Batch & Services
  presets              Display all certificate presets and intended usages
  template PRESET      Generate configuration template to stdout or file (-o FILE)
  batch FILE|DIR       Batch issue certificates automatically from template files
  ocsp-server          Launch OpenSSL OCSP responder daemon (--ca CA --signer NAME [--port 2560])
  ocsp-check NAME      Query OCSP revocation status for a certificate (--url URL)

6. Maintenance & Updates
  version              Show current script version, commit SHA, and repository details
  update, upgrade [-y] Check for script updates on GitHub and pull latest release

EXAMPLES:
  pki init --org Homelab --intermediate server-ca --intermediate client-ca
  pki quick pve-node1.lan                   # Autodetects FQDN, shortname, and IP addresses
  pki issue server --cn web01.lan --dns www.lan,web01 --ip 10.0.10.5
  pki issue wildcard --domain homelab.lan
  pki issue client --cn admin-laptop --p12
  pki verify web01.lan --host web01.lan
  pki backup /mnt/secure/pki-backup.tar.gz

ENVIRONMENT VARIABLES FOR HEADLESS AUTOMATION:
  PKI_DIR              PKI directory path (default: ./pki)
  PKI_CA_PASS          Master passphrase for all CA keys
  PKI_CA_PASS_<NAME>   Passphrase for a specific CA (e.g. PKI_CA_PASS_SERVER_CA)
  PKI_KEY_PASS         Passphrase for leaf certificate keys
  PKI_P12_PASS         Passphrase for PKCS#12 exports
EOF
}

# Succeeds only if the suite directory itself is the top level of a Git work
# tree. Being merely located inside some unrelated parent repository does not
# count. Fails quietly when SCRIPT_DIR is unset (standalone build) or git is
# missing.
is_suite_clone() {
    local dir=${SCRIPT_DIR:-} top
    [ -n "$dir" ] && [ -d "$dir" ] || return 1
    command -v git >/dev/null 2>&1 || return 1
    top=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null) || return 1
    [ -n "$top" ] || return 1
    top=$(cd "$top" 2>/dev/null && pwd -P) || return 1
    dir=$(cd "$dir" 2>/dev/null && pwd -P) || return 1
    [ "$top" = "$dir" ]
}

cmd_version() {
    local sha="standalone"
    if is_suite_clone; then
        sha=$(git -C "${SCRIPT_DIR:-}" rev-parse --short HEAD 2>/dev/null || echo "standalone")
    fi
    echo "OpenSSL Homelab PKI Suite v$VERSION ($sha)"
    echo "OpenSSL Binary: $("$OPENSSL" version)"
    echo "Repository:     https://github.com/Der-Felix/pki_script"
    echo "Discussions:    https://github.com/Der-Felix/pki_script/discussions"
}

cmd_update() {
    while [ $# -gt 0 ]; do
        case $1 in
            -y|--yes)   ASSUME_YES=1 ;;
            -h|--help)  echo "Usage: pki update [-y]"; return 0 ;;
            *) die "Unknown option for update: $1" ;;
        esac
        shift
    done

    section "PKI Suite Update Manager"
    if ! command -v git >/dev/null 2>&1; then
        warn "Git command not found in PATH."
        echo "To update manually, pull or download the latest files from:"
        echo "https://github.com/Der-Felix/pki_script"
        return 1
    fi

    local repo=${SCRIPT_DIR:-}
    if ! is_suite_clone; then
        warn "This installation is not a Git clone${repo:+ ($repo)}."
        echo "To enable 1-click updates, clone the repository via:"
        echo "git clone https://github.com/Der-Felix/pki_script.git"
        return 1
    fi

    local current_sha
    current_sha=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    info "Current version: v$VERSION ($current_sha)"
    info "Checking remote repository (origin/main)..."

    if ! git -C "$repo" fetch origin main 2>/dev/null; then
        warn "Could not fetch from remote 'origin/main'. Check network connection."
        return 1
    fi

    local behind_count
    if ! behind_count=$(git -C "$repo" rev-list --count "HEAD..origin/main" 2>/dev/null); then
        err "Could not compare local HEAD with origin/main (git rev-list failed)."
        return 1
    fi
    case $behind_count in
        ''|*[!0-9]*)
            err "Unexpected output from git rev-list: '$behind_count'"
            return 1
            ;;
    esac

    if [ "$behind_count" -eq 0 ]; then
        ok "Everything is up to date! You are running the latest version (v$VERSION - $current_sha)."
        return 0
    fi

    warn "Found $behind_count new update(s) available on 'origin/main'."
    echo "Note: Your 'pki/' data directory, private keys, and certificates are safe and untouched."
    
    if [ "${ASSUME_YES:-0}" = "1" ] || confirm "Do you want to pull and install the latest updates now?"; then
        info "Pulling latest updates..."
        if git -C "$repo" pull --ff-only origin main; then
            local new_sha
            new_sha=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo "unknown")
            ok "Successfully updated to $new_sha! OpenSSL Homelab PKI Suite is up to date."
        else
            err "Fast-forward update failed. Please run 'git pull' manually to resolve local changes."
            return 1
        fi
    else
        info "Update cancelled by user."
    fi
}

dispatch_cli() {
    local cmd=${1:-}
    [ $# -gt 0 ] && shift

    case $cmd in
        '')
            menu
            ;;
        help|-h|--help)
            usage
            ;;
        version|-v|--version)
            cmd_version
            ;;
        update|upgrade)
            cmd_update "$@" || exit $?
            ;;
        presets)
            print_presets
            ;;
        init)
            cmd_init "$@"
            ;;
        ca-new)
            cmd_ca_new "$@"
            ;;
        issue)
            require_pki; reset_issue_vars
            I_PRESET=${1:-}
            [ -n "$I_PRESET" ] && shift || die "Usage: pki issue <preset> --cn ... (view presets with: pki presets)"
            parse_issue_opts "$@"
            issue_cert
            ;;
        quick)
            require_pki
            cmd_quick "$@"
            ;;
        guide|anleitung|howto)
            require_pki
            cmd_guide "$@"
            ;;
        selfsigned)
            [ -f "$PKI_DIR/.req.cnf" ] || { mkdir -p "$PKI_DIR/issued" "$PKI_DIR/log"; write_req_cnf; }
            reset_issue_vars
            I_PRESET=server
            case ${1:-} in ''|-*) ;; *) I_PRESET=$1; shift ;; esac
            parse_issue_opts "$@"
            I_CA=selfsigned
            issue_cert
            ;;
        sign-csr)
            require_pki; reset_issue_vars; I_NO_CSR_SAN=0
            local csr=${1:-}
            [ -n "$csr" ] && shift || die "Usage: pki sign-csr <file.csr> --preset server [--ca ...]"
            I_PRESET=server
            parse_issue_opts "$@"
            sign_csr "$csr"
            ;;
        list|ls)
            list_all
            ;;
        status|dashboard)
            list_all
            ;;
        search)
            search_certs "$@"
            ;;
        doctor)
            pki_doctor
            ;;
        check)
            local wd=""
            while [ $# -gt 0 ]; do
                case $1 in
                    --days) need_arg "$@"; wd=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            check_all "$wd" || exit $?
            ;;
        show)
            [ -n "${1:-}" ] || die "Usage: pki show <name|file> [--full]"
            show_cert "$1" "$( [ "${2:-}" = --full ] && echo full)"
            ;;
        verify)
            require_pki
            local vn=${1:-} vh=""
            [ -n "$vn" ] && shift || die "Usage: pki verify <name> [--host hostname]"
            while [ $# -gt 0 ]; do
                case $1 in
                    --host) need_arg "$@"; vh=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            verify_cert "$vn" "$vh" || exit $?
            ;;
        renew)
            require_pki
            local rn=${1:-}
            [ -n "$rn" ] && shift || die "Usage: pki renew <name> [--keep-key] [--revoke-old] [--days N]"
            I_KEEP_KEY=0; R_REVOKE_OLD=0; I_DAYS=""
            while [ $# -gt 0 ]; do
                case $1 in
                    --keep-key)   I_KEEP_KEY=1 ;;
                    --revoke-old) R_REVOKE_OLD=1 ;;
                    --days)       need_arg "$@"; I_DAYS=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            renew_cert "$rn"
            ;;
        renew-ca)
            require_pki
            local cn=${1:-} cd=""
            [ -n "$cn" ] && shift || die "Usage: pki renew-ca <root|intermediate> [--days N]"
            while [ $# -gt 0 ]; do
                case $1 in
                    --days) need_arg "$@"; cd=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            renew_ca "$cn" "$cd"
            ;;
        revoke)
            require_pki
            local vname=${1:-} reason=unspecified
            [ -n "$vname" ] && shift || die "Usage: pki revoke <name> [--reason reason]"
            while [ $# -gt 0 ]; do
                case $1 in
                    --reason) need_arg "$@"; reason=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            revoke_cert "$vname" "$reason"
            ;;
        crl)
            require_pki
            local cc=""
            while [ $# -gt 0 ]; do
                case $1 in
                    --ca) need_arg "$@"; cc=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            if [ -n "$cc" ]; then
                ca_exists "$cc" || die "CA '$cc' unknown"
                gen_crl "$cc"
            else
                for cc in root $(list_intermediates); do gen_crl "$cc"; done
            fi
            ;;
        export)
            require_pki
            local en=${1:-} ep=0 el=no ed=0
            [ -n "$en" ] && shift || die "Usage: pki export <name> [--p12] [--p12-legacy] [--der]"
            [ -f "$PKI_DIR/issued/$en/cert.pem" ] || die "Certificate '$en' not found"
            while [ $# -gt 0 ]; do
                case $1 in
                    --p12)        ep=1 ;;
                    --p12-legacy) ep=1; el=yes ;;
                    --der)        ed=1 ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            [ "$ep" = 0 ] && [ "$ed" = 0 ] && { ep=1; ed=1; }
            [ "$ep" = 1 ] && export_p12 "$en" "$el"
            [ "$ed" = 1 ] && export_der "$en"
            print_leaf_files "$PKI_DIR/issued/$en"
            ;;
        backup)
            pki_backup "$@"
            ;;
        restore)
            pki_restore "$@"
            ;;
        ocsp-server)
            require_pki
            local oc="" os="" op=2560
            while [ $# -gt 0 ]; do
                case $1 in
                    --ca)     need_arg "$@"; oc=$2; shift ;;
                    --signer) need_arg "$@"; os=$2; shift ;;
                    --port)   need_arg "$@"; op=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            ocsp_server "$oc" "$os" "$op"
            ;;
        ocsp-check)
            require_pki
            local qn=${1:-} qu=""
            [ -n "$qn" ] && shift || die "Usage: pki ocsp-check <name> [--url URL]"
            while [ $# -gt 0 ]; do
                case $1 in
                    --url) need_arg "$@"; qu=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            ocsp_check "$qn" "$qu" || exit $?
            ;;
        template)
            local tp=${1:-} tn="" to=""
            [ -n "$tp" ] && shift || die "Usage: pki template <preset> [--name n] [-o file]"
            while [ $# -gt 0 ]; do
                case $1 in
                    --name)    need_arg "$@"; tn=$2; shift ;;
                    -o|--out)  need_arg "$@"; to=$2; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
                shift
            done
            if [ -n "$to" ]; then
                print_template "$tp" "$tn" > "$to"
                ok "Template written: $to"
            else
                print_template "$tp" "$tn"
            fi
            ;;
        batch)
            require_pki
            local bf=(); B_FORCE=0
            while [ $# -gt 0 ]; do
                case $1 in
                    --force) B_FORCE=1 ;;
                    *)       bf+=("$1") ;;
                esac
                shift
            done
            batch_issue "${bf[@]}" || exit $?
            ;;
        *)
            err "Unknown command: '$cmd'"
            usage >&2
            exit 1
            ;;
    esac
}
