#!/usr/bin/env bash
###############################################################################
# completions/pki.bash - Bash Tab Completion for pki.sh / pki / gen-ca.sh
#
# Activate in current session:
#   source /path/to/pki_script/completions/pki.bash
# Or persist system-wide:
#   sudo cp completions/pki.bash /etc/bash_completion.d/pki
###############################################################################

_pki_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="init ca-new issue quick selfsigned sign-csr ca-sign list ls status dashboard search show verify renew renew-ca revoke crl export guide anleitung howto template batch backup restore doctor presets version update upgrade help"
    local presets="server wildcard client server-client user vpn-server vpn-client smime codesign ocsp timestamp custom"
    local keys="rsa2048 rsa3072 rsa4096 ed25519"
    local revoke_reasons="unspecified keyCompromise CACompromise affiliationChanged superseded cessationOfOperation certificateHold"

    # Resolve PKI directory
    local pki_dir="${PKI_DIR:-./pki}"
    for ((i=1; i < cword; i++)); do
        if [[ "${words[i]}" == "--dir" ]] && [[ -n "${words[i+1]}" ]]; then
            pki_dir="${words[i+1]}"
            break
        fi
    done

    # Discover issued certificates
    _pki_get_issued() {
        if [[ -d "$pki_dir/issued" ]]; then
            command ls -1 "$pki_dir/issued" 2>/dev/null
        fi
    }

    # Discover CAs
    _pki_get_cas() {
        printf 'root\n'
        if [[ -d "$pki_dir/intermediate" ]]; then
            command ls -1 "$pki_dir/intermediate" 2>/dev/null
        fi
    }

    # Offer the words of $1 that match the current word, one per line
    # (mapfile instead of word splitting: safe for names with spaces)
    _pki_reply() {
        mapfile -t COMPREPLY < <(compgen -W "$1" -- "$cur")
    }

    # First word: Command completion
    if [[ $cword -eq 1 ]]; then
        _pki_reply "$commands"
        return 0
    fi

    local cmd="${words[1]}"
    case "$prev" in
        --key|--leaf-key)
            _pki_reply "$keys"
            return 0
            ;;
        --ca)
            _pki_reply "$(_pki_get_cas) selfsigned"
            return 0
            ;;
        --reason)
            _pki_reply "$revoke_reasons"
            return 0
            ;;
        --preset)
            _pki_reply "$presets"
            return 0
            ;;
        --dir)
            _filedir -d
            return 0
            ;;
    esac

    case "$cmd" in
        issue|template)
            if [[ $cword -eq 2 ]]; then
                _pki_reply "$presets"
                return 0
            fi
            _pki_reply "--cn --dns --ip --email --uri --domain --ca --key --days --name --ou --key-pass --p12 --p12-legacy --der --force"
            ;;
        show|verify|renew|export|guide|anleitung|howto|ocsp-check)
            if [[ $cword -eq 2 ]]; then
                _pki_reply "$(_pki_get_issued)"
                return 0
            fi
            if [[ "$cmd" == "verify" ]]; then
                _pki_reply "--host"
            elif [[ "$cmd" == "renew" ]]; then
                _pki_reply "--keep-key --revoke-old --days"
            elif [[ "$cmd" == "export" ]]; then
                _pki_reply "--p12 --p12-legacy --der"
            fi
            ;;
        renew-ca)
            if [[ $cword -eq 2 ]]; then
                _pki_reply "$(_pki_get_cas)"
                return 0
            fi
            _pki_reply "--days"
            ;;
        revoke)
            if [[ $cword -eq 2 ]]; then
                _pki_reply "$(_pki_get_issued) $(_pki_get_cas)"
                return 0
            fi
            _pki_reply "--reason"
            ;;
        crl)
            _pki_reply "--ca"
            ;;
        update|upgrade)
            _pki_reply "-y --yes"
            ;;
        quick)
            _pki_reply "--dns --ip --ca --days --no-lookup"
            ;;
        init)
            _pki_reply "--org --country --state --locality --ou --cn --key --days --leaf-key --crl-days --aia-url --no-pass --intermediate"
            ;;
        ca-new)
            _pki_reply "--cn --key --days --no-pass --pathlen --permit-dns --permit-ip --eku-limit --ocsp-url --default"
            ;;
        sign-csr)
            if [[ $cword -eq 2 ]]; then
                _filedir '@(csr|req)'
                return 0
            fi
            _pki_reply "--preset --ca --cn --dns --ip --days --no-csr-san"
            ;;
        ca-sign)
            if [[ $cword -eq 2 ]]; then
                _filedir '@(csr|req)'
                return 0
            fi
            _pki_reply "--ext --days --out"
            ;;
        batch)
            _filedir
            ;;
        backup|restore)
            _filedir
            ;;
        search)
            _pki_reply "$(_pki_get_issued)"
            ;;
        *)
            ;;
    esac
}

complete -F _pki_completion pki
complete -F _pki_completion pki.sh
complete -F _pki_completion gen-ca.sh
