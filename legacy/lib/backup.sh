#!/usr/bin/env bash
###############################################################################
# lib/backup.sh - PKI Backup & Restore Utilities
###############################################################################

# Creates an encrypted/compressed backup archive of the entire PKI directory
pki_backup() {
    require_pki
    local out=${1:-}
    have tar || die "'tar' is not available on this system"

    if [ -z "$out" ]; then
        local bdir="$PKI_DIR/backups"
        mkdir -p "$bdir"
        out="$bdir/pki-backup-$(stamp).tar.gz"
    fi

    banner "Creating PKI Backup"
    info "Backing up $PKI_DIR to $out ..."

    local pki_parent; pki_parent=$(dirname "$PKI_DIR")
    local pki_base; pki_base=$(basename "$PKI_DIR")

    (
        cd "$pki_parent"
        tar -czf "$out" \
            --exclude="$pki_base/backups" \
            --exclude="$pki_base/.req.cnf" \
            "$pki_base"
    ) || die "Backup archive creation failed"

    chmod 600 "$out"
    if tar -tzf "$out" >/dev/null 2>&1; then
        ok "Backup created successfully: $out"
        info "Archive size: $(du -h "$out" 2>/dev/null | awk '{print $1}' || echo 'ok')"
        warn "IMPORTANT: This backup contains private CA keys. Store in a secure, isolated location!"
    else
        die "Archive verification failed: $out"
    fi
}

# Restores the PKI from a backup archive
pki_restore() {
    local src=${1:-}
    [ -n "$src" ] || die "Usage: pki restore <backup-file.tar.gz>"
    [ -f "$src" ] || die "Backup file not found: $src"
    have tar || die "'tar' is not available on this system"

    banner "PKI Restore"
    warn "Target directory: $PKI_DIR"

    if [ -f "$PKI_DIR/root/certs/ca.crt" ]; then
        warn "An active PKI already exists in $PKI_DIR!"
        confirm "Are you sure you want to overwrite the existing PKI with this backup?" || { info "Restore cancelled"; return 0; }
    fi

    local pki_parent; pki_parent=$(dirname "$PKI_DIR")
    mkdir -p "$pki_parent"

    info "Extracting $src to $pki_parent ..."
    (
        cd "$pki_parent"
        tar -xzf "$src"
    ) || die "Extraction failed"

    chmod 700 "$PKI_DIR" 2>/dev/null || true
    [ -d "$PKI_DIR/root/private" ] && chmod 700 "$PKI_DIR/root/private"
    for d in "$PKI_DIR"/intermediate/*/private; do
        [ -d "$d" ] && chmod 700 "$d"
    done

    ok "PKI successfully restored!"
    load_config
    list_all
}
