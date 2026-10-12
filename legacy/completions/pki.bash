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

    local commands="init ca-new issue quick selfsigned sign-csr list ls status dashboard search show verify renew renew-ca revoke crl export guide anleitung howto template batch backup restore doctor presets version update upgrade help"
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

    # First word: Command completion
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    local cmd="${words[1]}"
    case "$prev" in
        --key|--leaf-key)
            COMPREPLY=( $(compgen -W "$keys" -- "$cur") )
            return 0
            ;;
        --ca)
            COMPREPLY=( $(compgen -W "$(_pki_get_cas) selfsigned" -- "$cur") )
            return 0
            ;;
        --reason)
            COMPREPLY=( $(compgen -W "$revoke_reasons" -- "$cur") )
            return 0
            ;;
        --preset)
            COMPREPLY=( $(compgen -W "$presets" -- "$cur") )
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
                COMPREPLY=( $(compgen -W "$presets" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W "--cn --dns --ip --email --uri --domain --ca --key --days --name --ou --key-pass --p12 --p12-legacy --der --force" -- "$cur") )
            ;;
        show|verify|renew|export|guide|anleitung|howto|ocsp-check)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(_pki_get_issued)" -- "$cur") )
                return 0
            fi
            if [[ "$cmd" == "verify" ]]; then
                COMPREPLY=( $(compgen -W "--host" -- "$cur") )
            elif [[ "$cmd" == "renew" ]]; then
                COMPREPLY=( $(compgen -W "--keep-key --revoke-old --days" -- "$cur") )
            elif [[ "$cmd" == "export" ]]; then
                COMPREPLY=( $(compgen -W "--p12 --p12-legacy --der" -- "$cur") )
            fi
            ;;
        renew-ca)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(_pki_get_cas)" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W "--days" -- "$cur") )
            ;;
        revoke)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$(_pki_get_issued) $(_pki_get_cas)" -- "$cur") )
                return 0
            fi
            COMPREPLY=( $(compgen -W "--reason" -- "$cur") )
            ;;
        crl)
            COMPREPLY=( $(compgen -W "--ca" -- "$cur") )
            ;;
        update|upgrade)
            COMPREPLY=( $(compgen -W "-y --yes" -- "$cur") )
            ;;
        quick)
            COMPREPLY=( $(compgen -W "--dns --ip --ca --days --no-lookup" -- "$cur") )
            ;;
        init)
            COMPREPLY=( $(compgen -W "--org --country --state --locality --ou --cn --key --days --leaf-key --crl-days --aia-url --no-pass --intermediate" -- "$cur") )
            ;;
        ca-new)
            COMPREPLY=( $(compgen -W "--cn --key --days --no-pass --pathlen --permit-dns --permit-ip --eku-limit --ocsp-url --default" -- "$cur") )
            ;;
        sign-csr)
            if [[ $cword -eq 2 ]]; then
                _filedir '@(csr|req)'
                return 0
            fi
            COMPREPLY=( $(compgen -W "--preset --ca --cn --dns --ip --days --no-csr-san" -- "$cur") )
            ;;
        batch)
            _filedir
            ;;
        backup|restore)
            _filedir
            ;;
        search)
            COMPREPLY=( $(compgen -W "$(_pki_get_issued)" -- "$cur") )
            ;;
        *)
            ;;
    esac
}

complete -F _pki_completion pki
complete -F _pki_completion pki.sh
complete -F _pki_completion gen-ca.sh
