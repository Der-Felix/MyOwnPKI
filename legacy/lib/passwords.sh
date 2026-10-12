#!/usr/bin/env bash
###############################################################################
# lib/passwords.sh - Secure password handling, caching, and key encryption
###############################################################################

# Check if private key is encrypted
key_is_encrypted() {
    grep -q 'ENCRYPTED' "$1" 2>/dev/null
}

# Test whether the password stored in environment variable $2 unlocks key $1
key_pass_ok() {
    "$OPENSSL" pkey -in "$1" -passin "env:$2" -noout >/dev/null 2>&1
}

# Variable name for temporary in-memory CA password cache
pw_cache_var() {
    printf 'PKI_PWCACHE_%s' "$(upper "$1" | tr '.@-' '___')"
}

# Check if user has predefined an environment variable for CA (PKI_CA_PASS_<NAME> or PKI_CA_PASS)
user_pass_var() {
    local v
    v="PKI_CA_PASS_$(upper "$1" | tr '.@-' '___')"
    if [ -n "${!v:-}" ]; then
        printf '%s' "$v"
    elif [ -n "${PKI_CA_PASS:-}" ]; then
        printf 'PKI_CA_PASS'
    fi
}

# Masked password input from terminal or stdin
read_secret() { # <var> <prompt>
    local __rs_v __rs_ok=0
    printf '%s' "$2" >&2
    if [ -t 0 ]; then
        IFS= read -rs __rs_v || __rs_ok=1
    else
        IFS= read -r __rs_v || __rs_ok=1
    fi
    printf '\n' >&2
    [ "$__rs_ok" = 0 ] || die "End of input (EOF) - operation aborted. When non-interactive, set passwords via PKI_CA_PASS / PKI_KEY_PASS / PKI_P12_PASS."
    printf -v "$1" '%s' "$__rs_v"
}

# Double prompt confirmation for NEW password
new_pass() { # <var> <purpose>
    local __np_a __np_b
    while :; do
        read_secret __np_a "  Enter new password for $2 (min 4 characters): "
        if [ ${#__np_a} -lt 4 ]; then
            warn "Too short - OpenSSL requires at least 4 characters"
            continue
        fi
        read_secret __np_b "  Confirm password: "
        [ "$__np_a" = "$__np_b" ] && break
        warn "Passwords do not match - please re-enter"
    done
    export "$1=$__np_a"
}

# Prompt and verify password for an EXISTING key (max 3 attempts)
unlock_key() { # <var> <keyfile> <purpose>
    local __uk_p __uk_i
    for __uk_i in 1 2 3; do
        read_secret __uk_p "  Password for $3: "
        export "$1=$__uk_p"
        if key_pass_ok "$2" "$1"; then
            return 0
        fi
        warn "Incorrect password (attempt $__uk_i/3)"
    done
    unset "$1"
    die "Aborted after 3 failed attempts - unable to unlock $3. No changes were made."
}

# Prepare -passin arguments for CA private key -> sets array PASSIN
ca_passin() {
    local ca=$1 key uv cv
    key="$(ca_dir "$ca")/private/ca.key"
    PASSIN=()
    key_is_encrypted "$key" || return 0
    uv=$(user_pass_var "$ca")
    if [ -n "$uv" ]; then
        key_pass_ok "$key" "$uv" || die "The password in \$$uv does not match CA key '$ca'"
        PASSIN=(-passin "env:$uv")
        return 0
    fi
    cv=$(pw_cache_var "$ca")
    [ -n "${!cv:-}" ] || unlock_key "$cv" "$key" "CA '$ca'"
    PASSIN=(-passin "env:$cv")
}

# Set password variable for a NEW CA key -> sets NEWPASSVAR
ca_newpass() { # <ca> <description>
    NEWPASSVAR=$(user_pass_var "$1")
    if [ -z "$NEWPASSVAR" ]; then
        NEWPASSVAR=$(pw_cache_var "$1")
        new_pass "$NEWPASSVAR" "$2"
    fi
}

# Prepare -passin for leaf private key -> sets array KPASSIN (if encrypted)
key_passin() {
    KPASSIN=()
    key_is_encrypted "$1" || return 0
    if [ -n "${PKI_KEY_PASS:-}" ]; then
        key_pass_ok "$1" PKI_KEY_PASS || die "The password in \$PKI_KEY_PASS does not match $1"
    else
        unlock_key PKI_KEY_PASS "$1" "the private key of '$(basename "$(dirname "$1")")'"
    fi
    KPASSIN=(-passin env:PKI_KEY_PASS)
}

# Ensure password for .p12 archive export
ensure_p12_pass() {
    [ -n "${PKI_P12_PASS:-}" ] || new_pass PKI_P12_PASS "the .p12 archive (prompted when importing into Windows/macOS/clients)"
}

# Atomically clean up partially initialized directory on abort
cleanup_partial() {
    if [ -n "${PARTIAL_DIR:-}" ] && [ -d "$PARTIAL_DIR" ]; then
        rm -rf "$PARTIAL_DIR"
        warn "Aborted - safely removed partial directory: ${PARTIAL_DIR#"$PKI_DIR"/}"
    fi
    PARTIAL_DIR=""
}
