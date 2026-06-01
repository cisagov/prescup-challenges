#!/usr/bin/env bash
set -Eeuo pipefail

readonly SSHD_BIN="/usr/sbin/sshd"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly INIT_SCRIPT="/usr/local/lib/.fs_boot/farsight_init.sh"
readonly TOKEN_PATH="/run/.fsd.lock"

log() {
    printf '[entrypoint] %s\n' "$*"
}

fatal() {
    printf '[entrypoint] ERROR: %s\n' "$*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [[ -e "$path" ]] || fatal "Required file missing: $path"
}

require_executable() {
    local path="$1"
    [[ -x "$path" ]] || fatal "Required executable missing or not executable: $path"
}

inject_token() {
    [[ -n "${TOKEN4:-}" ]] || fatal "TOKEN4 environment variable is not set"

    umask 077
    printf '%s\n' "$TOKEN4" > "$TOKEN_PATH"
    chown root:root "$TOKEN_PATH"
    chmod 0600 "$TOKEN_PATH"

    [[ -s "$TOKEN_PATH" ]] || fatal "Failed to create runtime token file"

    unset TOKEN4
    log "Runtime token injected"
}

prepare_runtime() {
    mkdir -p /var/run/sshd
    require_executable "$SSHD_BIN"
    require_file "$SSHD_CONFIG"
    require_executable "$INIT_SCRIPT"
}

start_challenge_services() {
    log "Starting hidden challenge services"
    "$INIT_SCRIPT"
}

start_sshd() {
    log "Starting sshd"
    exec /usr/bin/env -i \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        HOME="/root" \
        "$SSHD_BIN" -D -e -f "$SSHD_CONFIG"
}

main() {
    prepare_runtime
    inject_token
    start_challenge_services
    start_sshd
}

main "$@"
