#!/usr/bin/env bash
###############################################################################
# pki.sh - Modular OpenSSL PKI Generator for Homelabs and Enterprise Setups
#
# Builds and manages a complete, file-based X.509 PKI hierarchy:
#   Root CA  -->  Intermediate CA(s)  -->  End-Entity Certificates (Leaves)
#
# Usage:
#   ./pki.sh                 Interactive TUI menu and guided wizards
#   ./pki.sh <command> ...   CLI mode (for automation, CI/CD, Salt, Ansible)
#   ./pki.sh help            Display CLI help and command overview
#
# Prerequisites:
#   - bash 4.x / 5.x
#   - OpenSSL 3.x
###############################################################################

# Restrict default file creation mask to owner-only
umask 077
set -o errexit -o pipefail -o errtrace

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"

# Load library modules
LIB_DIR="$SCRIPT_DIR/lib"
[ -d "$LIB_DIR" ] || { echo "[ERROR] Module directory not found: $LIB_DIR" >&2; exit 1; }

# shellcheck source=lib/core.sh
source "$LIB_DIR/core.sh"
# shellcheck source=lib/config.sh
source "$LIB_DIR/config.sh"
# shellcheck source=lib/crypto.sh
source "$LIB_DIR/crypto.sh"
# shellcheck source=lib/passwords.sh
source "$LIB_DIR/passwords.sh"
# shellcheck source=lib/presets.sh
source "$LIB_DIR/presets.sh"
# shellcheck source=lib/ca.sh
source "$LIB_DIR/ca.sh"
# shellcheck source=lib/issue.sh
source "$LIB_DIR/issue.sh"
# shellcheck source=lib/csr.sh
source "$LIB_DIR/csr.sh"
# shellcheck source=lib/network.sh
source "$LIB_DIR/network.sh"
# shellcheck source=lib/operations.sh
source "$LIB_DIR/operations.sh"
# shellcheck source=lib/export.sh
source "$LIB_DIR/export.sh"
# shellcheck source=lib/ocsp.sh
source "$LIB_DIR/ocsp.sh"
# shellcheck source=lib/batch.sh
source "$LIB_DIR/batch.sh"
# shellcheck source=lib/backup.sh
source "$LIB_DIR/backup.sh"
# shellcheck source=lib/doctor.sh
source "$LIB_DIR/doctor.sh"
# shellcheck source=lib/ui.sh
source "$LIB_DIR/ui.sh"
# shellcheck source=lib/cli.sh
source "$LIB_DIR/cli.sh"

trap 'err "Unexpected error at line $LINENO: $BASH_COMMAND"' ERR

main() {
    # Process global flags before commands
    while [ $# -gt 0 ]; do
        case $1 in
            --dir)
                need_arg "$@"
                PKI_DIR=$2
                shift 2
                ;;
            -y|--yes)
                ASSUME_YES=1
                shift
                ;;
            --no-color)
                NO_COLOR=1
                setup_colors
                shift
                ;;
            -h|--help)
                set -- help
                break
                ;;
            *)
                break
                ;;
        esac
    done

    # Resolve absolute path for PKI_DIR
    case $PKI_DIR in
        /*) ;;
        *)  PKI_DIR="$PWD/$PKI_DIR" ;;
    esac
    PKI_DIR=${PKI_DIR%/}
    if [ -e "$PKI_DIR" ] && [ ! -d "$PKI_DIR" ]; then
        die "PKI path exists but is not a directory: $PKI_DIR (choose another location with --dir)"
    fi
    case $PKI_DIR in
        *' '*) warn "PKI path contains spaces - this may cause unexpected behavior with OpenSSL: $PKI_DIR" ;;
    esac

    find_openssl
    load_config

    dispatch_cli "$@"
}

main "$@"
