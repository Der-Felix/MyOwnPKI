#!/usr/bin/env bash
###############################################################################
# lib/core.sh - Core utilities, logging, formatting, and validation helpers
###############################################################################

VERSION="2.0.0"
HR="##############################################################################"
DIVIDER="──────────────────────────────────────────────────────────────────────────────"

# Global runtime variables
PKI_DIR="${PKI_DIR:-$PWD/pki}"
ASSUME_YES=0
INTERACTIVE=0
I_NO_CSR_SAN=0
R_REVOKE_OLD=0
B_FORCE=0
PASSIN=()
KPASSIN=()
SPLIT=()
PARTIAL_DIR=""
STEP_N=0
STEP_TOTAL=0

###############################################################################
# Colors and Output Helpers
###############################################################################
setup_colors() {
    if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
        C_RED=$'\033[31m'
        C_GRN=$'\033[32m'
        C_YEL=$'\033[33m'
        C_BLU=$'\033[34m'
        C_MAG=$'\033[35m'
        C_CYN=$'\033[36m'
        C_BLD=$'\033[1m'
        C_DIM=$'\033[2m'
        C_RST=$'\033[0m'
    else
        C_RED="" C_GRN="" C_YEL="" C_BLU="" C_MAG="" C_CYN="" C_BLD="" C_DIM="" C_RST=""
    fi
}
setup_colors

info()    { printf '%s[INFO]%s  %s\n'   "$C_BLU" "$C_RST" "$*" >&2; }
ok()      { printf '%s[ OK ]%s  %s\n'   "$C_GRN" "$C_RST" "$*" >&2; }
warn()    { printf '%s[WARN]%s  %s\n'   "$C_YEL" "$C_RST" "$*" >&2; }
err()     { printf '%s[ERROR]%s %s\n'   "$C_RED" "$C_RST" "$*" >&2; }
die()     { err "$*"; exit 1; }

step()    { STEP_N=$((STEP_N+1)); printf '%s[%d/%d]%s %s\n' "$C_GRN" "$STEP_N" "$STEP_TOTAL" "$C_RST" "$*" >&2; }
kv()      { printf '  %-16s %s\n' "$1:" "$2" >&2; }

banner() {
    printf '\n%s%s\n# %s\n%s%s\n' "$C_BLD" "$HR" "$1" "$HR" "$C_RST" >&2
}

section() {
    printf '\n%s######## %s%s\n' "$C_BLD" "$1" "$C_RST" >&2
}

divider() {
    printf '%s%s%s\n' "$C_DIM" "$DIVIDER" "$C_RST" >&2
}

###############################################################################
# String and Date Helpers
###############################################################################
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
trim()  { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
now()   { date '+%Y-%m-%d %H:%M:%S'; }
stamp() { date '+%Y%m%d-%H%M%S'; }

# "YYYY-MM-DD HH:MM:SS" (UTC) -> Epoch (supports both GNU date and BSD/macOS date)
to_epoch() {
    date -u -d "$1" +%s 2>/dev/null || date -u -j -f "%Y-%m-%d %H:%M:%S" "$1" +%s 2>/dev/null
}

# Split delimited list "a, b c;d" -> Array SPLIT=(a b c d)
split_list() {
    SPLIT=()
    local IFS=$' \t,;'
    read -r -a SPLIT <<< "$1" || true
}

# Append element to comma-separated list if not already present
add_uniq() {
    local list=$1 item=$2
    case ",$list," in *",$item,"*) printf '%s' "$list"; return;; esac
    if [ -z "$list" ]; then printf '%s' "$item"; else printf '%s,%s' "$list" "$item"; fi
}

###############################################################################
# Validation Helpers
###############################################################################
is_int() { case $1 in ''|*[!0-9]*) return 1;; *) return 0;; esac; }

is_ipv4() {
    local re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$' i
    [[ $1 =~ $re ]] || return 1
    for i in 1 2 3 4; do [ "${BASH_REMATCH[$i]}" -le 255 ] || return 1; done
}

is_ipv6() {
    local re='^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$'
    [[ $1 =~ $re ]] && [[ $1 == *:*:* ]]
}

is_hostname() {
    local l='[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?'
    local re="^(\*\.)?${l}(\.${l})*$"
    [[ $1 =~ $re ]]
}

is_email() { local re='^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'; [[ $1 =~ $re ]]; }
is_uri()   { local re='^[a-zA-Z][a-zA-Z0-9+.-]*:[^[:space:]]+$'; [[ $1 =~ $re ]]; }
is_name()  { local re='^[a-z0-9][a-z0-9._@-]*$'; [[ $1 =~ $re ]]; }

# Free text input check against characters that would break metadata files
check_safe() {
    case $2 in *'"'*|*'\'*|*'$'*|*'`'*) die "$1 must not contain characters \" \\ \$ \`: $2";; esac
}

# Derive directory name from CN: "*.lan" -> "wildcard.lan", "Felix Muster" -> "felix-muster"
name_from_cn() {
    local n; n=$(lower "$1")
    n=${n//\*/wildcard}
    # Transliterate umlauts before transforming disallowed characters
    n=$(printf '%s' "$n" | sed -e 's/ä/ae/g; s/ö/oe/g; s/ü/ue/g; s/Ä/ae/g; s/Ö/oe/g; s/Ü/ue/g; s/ß/ss/g')
    n=$(printf '%s' "$n" | sed -e 's/[^a-z0-9._@-]/-/g' -e 's/--*/-/g' -e 's/^[-.]*//' -e 's/[-.]*$//')
    printf '%s' "$n"
}

# Escape special characters for openssl -subj (/ + and \ are reserved)
dn_escape() { printf '%s' "$1" | sed -e 's/[\\/+]/\\&/g'; }

# CIDR -> Subnet Mask (IPv4 only), for nameConstraints
cidr2mask() {
    local bits=$1 mask="" i oct
    for i in 1 2 3 4; do
        if [ "$bits" -ge 8 ]; then oct=255; bits=$((bits-8))
        else oct=$(( 256 - (1 << (8-bits)) )); [ "$bits" -eq 0 ] && oct=0; bits=0; fi
        mask="${mask:+$mask.}$oct"
    done
    printf '%s' "$mask"
}

# Convert IPv4 to 32-bit integer for subnet calculation
ip2int() { local IFS=.; set -- $1; printf '%s' $(( ($1<<24) + ($2<<16) + ($3<<8) + $4 )); }

# Action logging into $PKI_DIR/log/pki.log
log_action() {
    [ -d "$PKI_DIR/log" ] || return 0
    printf '%s  %s\n' "$(now)" "$*" >> "$PKI_DIR/log/pki.log"
}

# Check if a command is available
have() { command -v "$1" >/dev/null 2>&1; }

# Execute command with timeout (if timeout utility is available)
with_timeout() { if have timeout; then timeout 3 "$@"; else "$@"; fi; }
