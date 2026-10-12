#!/usr/bin/env bash
###############################################################################
# build.sh - Compiles modular lib/* files into a single standalone script
#
# Generates: dist/pki-standalone.sh (ideal for copying to remote servers)
###############################################################################

set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DIST_DIR="$SCRIPT_DIR/dist"
OUT_FILE="$DIST_DIR/pki-standalone.sh"

mkdir -p "$DIST_DIR"

echo "Building standalone script: $OUT_FILE ..."

{
    cat <<'EOF'
#!/usr/bin/env bash
###############################################################################
# pki-standalone.sh - OpenSSL PKI Suite (Compiled Standalone Script)
# Automatically compiled from modular library modules via build.sh
###############################################################################
umask 077
set -o errexit -o pipefail -o errtrace

SCRIPT_NAME=$(basename "$0")
SCRIPT_PATH=$(cd "$(dirname "$0")" && pwd)/$SCRIPT_NAME

EOF

    MODULES=(
        core.sh
        config.sh
        crypto.sh
        passwords.sh
        presets.sh
        ca.sh
        issue.sh
        csr.sh
        network.sh
        operations.sh
        export.sh
        ocsp.sh
        batch.sh
        backup.sh
        doctor.sh
        ui.sh
        cli.sh
    )

    for mod in "${MODULES[@]}"; do
        echo "## Inlining lib/$mod ..." >&2
        printf '\n###############################################################################\n'
        printf '# MODULE: lib/%s\n' "$mod"
        printf '###############################################################################\n'
        # Strip shebang line from individual modules
        sed '/^#!\/usr\/bin\/env bash/d' "$SCRIPT_DIR/lib/$mod"
    done

    cat <<'EOF'

trap 'err "Unexpected error at line $LINENO: $BASH_COMMAND"' ERR

main() {
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

    case $PKI_DIR in
        /*) ;;
        *)  PKI_DIR="$PWD/$PKI_DIR" ;;
    esac
    PKI_DIR=${PKI_DIR%/}
    if [ -e "$PKI_DIR" ] && [ ! -d "$PKI_DIR" ]; then
        die "PKI path exists but is not a directory: $PKI_DIR (choose another location with --dir)"
    fi

    find_openssl
    load_config
    dispatch_cli "$@"
}

main "$@"
EOF
} > "$OUT_FILE"

chmod +x "$OUT_FILE"
echo "Build complete: $OUT_FILE ($(wc -l < "$OUT_FILE" | tr -d ' ') lines, $(du -h "$OUT_FILE" | awk '{print $1}'))"
