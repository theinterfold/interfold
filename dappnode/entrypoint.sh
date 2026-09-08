#!/bin/bash
# DAppNode Interfold Ciphernode Entrypoint
set -Eeuo pipefail

umask 077

CONFIG_DIR="${CONFIG_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/config.yaml}"
TEMPLATE_FILE="${TEMPLATE_FILE:-/opt/config.template.yaml}"
SECRETS_FILE="${SECRETS_FILE:-/run/secrets/secrets.json}"
LEGACY_STATE_DIR="${LEGACY_STATE_DIR:-$CONFIG_DIR/.enclave}"
CURRENT_STATE_DIR="${CURRENT_STATE_DIR:-$CONFIG_DIR/.interfold}"
# Current Interfold releases resolve a relative `key_file: key` beside a discovered
# /data/config.yaml to this path for the default node profile.
PASSWORD_FILE="${PASSWORD_FILE:-$CURRENT_STATE_DIR/config/_default/key}"
CREDENTIALS_READY_FILE="${CREDENTIALS_READY_FILE:-$(dirname "$PASSWORD_FILE")/credentials.provisioned}"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"; }
fail() {
    log "ERROR: $1"
    exit 1
}

echo "=========================================="
echo "  Interfold Ciphernode - ${NETWORK:-mainnet}"
echo "=========================================="

# Environment variables are visible in Docker/DAppNode metadata. Refuse the
# legacy secret injection contract instead of silently preferring one source.
if [ -n "${ENCRYPTION_PASSWORD:-}" ] || [ -n "${NETWORK_PRIVATE_KEY:-}" ] || [ -n "${PRIVATE_KEY:-}" ]; then
    fail "credential environment variables are unsupported; upload the DAppNode credentials JSON file"
fi

# Validate RPC URL (required).
[ -n "${RPC_URL:-}" ] || fail "RPC_URL is required; set it in the DAppNode package configuration"
[[ "$RPC_URL" =~ ^wss?:// ]] || fail "RPC_URL must be a WebSocket URL (ws:// or wss://)"

require_uint() {
    local name="$1"
    local value="${!name:-}"
    [[ "$value" =~ ^[0-9]+$ ]] || fail "$name must be an integer"
}

require_address() {
    local name="$1"
    local value="${!name:-}"
    [[ "$value" =~ ^0x[0-9a-fA-F]{40}$ ]] || fail "$name must be a valid Ethereum address"
}

[ -r "$TEMPLATE_FILE" ] || fail "configuration template is not readable: $TEMPLATE_FILE"
mkdir -p "$CONFIG_DIR"

migrate_legacy_state() {
    if [ -L "$LEGACY_STATE_DIR" ] || [ -L "$CURRENT_STATE_DIR" ]; then
        fail "legacy/current state paths must not be symbolic links"
    fi
    if [ -e "$LEGACY_STATE_DIR" ] && [ ! -d "$LEGACY_STATE_DIR" ]; then
        fail "legacy state path is not a directory: $LEGACY_STATE_DIR"
    fi
    if [ -e "$CURRENT_STATE_DIR" ] && [ ! -d "$CURRENT_STATE_DIR" ]; then
        fail "current state path is not a directory: $CURRENT_STATE_DIR"
    fi
    if [ -d "$LEGACY_STATE_DIR" ] && [ -e "$CURRENT_STATE_DIR" ]; then
        fail "both legacy and current state directories exist; refusing an ambiguous upgrade"
    fi
    if [ -d "$LEGACY_STATE_DIR" ]; then
        log "Migrating the v0.1.8 state namespace to the current Interfold state path..."
        mv -- "$LEGACY_STATE_DIR" "$CURRENT_STATE_DIR" \
            || fail "could not migrate legacy state into $CURRENT_STATE_DIR"
    fi
}

migrate_legacy_state

# Set non-secret defaults.
export NETWORK="${NETWORK:-mainnet}"
export QUIC_PORT="${QUIC_PORT:-37173}"
export NODE_ADDRESS="${NODE_ADDRESS:-}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# Protocol v3 stores large ciphertexts on Avail. Operators may override the public endpoint, but
# an enabled Ethereum chain must always render a reader into the ciphernode configuration.
if [ -z "${AVAIL_RPC_URL:-}" ]; then
    case "${CHAIN_ID:-}" in
        1) AVAIL_RPC_URL="https://avail-rpc.publicnode.com/" ;;
        11155111) AVAIL_RPC_URL="https://turing-rpc.avail.so/rpc" ;;
        *) fail "AVAIL_RPC_URL is required for chain ${CHAIN_ID:-unknown}" ;;
    esac
fi
export AVAIL_RPC_URL
[[ "$AVAIL_RPC_URL" =~ ^https?:// ]] || fail "AVAIL_RPC_URL must be an HTTP URL (http:// or https://)"

case "$LOG_LEVEL" in
    info|debug|trace) ;;
    *) fail "LOG_LEVEL must be one of: info, debug, trace" ;;
esac

require_uint CHAIN_ID
require_uint QUIC_PORT
require_address NODE_ADDRESS
require_address INTERFOLD_CONTRACT
require_address CIPHERNODE_REGISTRY_CONTRACT
require_address BONDING_REGISTRY_CONTRACT
require_address SLASHING_MANAGER_CONTRACT
require_address FEE_TOKEN_CONTRACT
require_uint INTERFOLD_DEPLOY_BLOCK
require_uint CIPHERNODE_REGISTRY_DEPLOY_BLOCK
require_uint BONDING_REGISTRY_DEPLOY_BLOCK
require_uint SLASHING_MANAGER_DEPLOY_BLOCK
require_uint FEE_TOKEN_DEPLOY_BLOCK

# Generate config from the fixed template. The 0077 umask keeps RPC
# credentials in the rendered URL out of group/world-readable files.
log "Generating configuration..."
envsubst < "$TEMPLATE_FILE" > "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"

validate_secret_file() {
    [ -f "$SECRETS_FILE" ] || fail "credentials path is not a regular file: $SECRETS_FILE"
    [ ! -L "$SECRETS_FILE" ] || fail "credentials path must not be a symbolic link: $SECRETS_FILE"
    [ -r "$SECRETS_FILE" ] || fail "credentials file is not readable: $SECRETS_FILE"

    local size
    size=$(wc -c < "$SECRETS_FILE")
    [ "$size" -le 16384 ] || fail "credentials file exceeds the 16 KiB limit"

    jq -e '
        type == "object" and
        ((keys | sort == ["password", "private_key"]) or
            (keys | sort == ["network_private_key", "password", "private_key"])) and
        (.password | type == "string" and length > 0 and length <= 1024 and
            test("^[^\\r\\n\\u0000]+$") and . == gsub("^\\s+|\\s+$"; "")) and
        (.private_key | type == "string" and test("^0x[0-9a-fA-F]{64}$")) and
        ((has("network_private_key") | not) or
            (.network_private_key | type == "string" and test("^0x[0-9a-fA-F]{64}$")))
    ' "$SECRETS_FILE" >/dev/null || fail "credentials file must contain valid password and private_key strings"
}

validate_persisted_password_file() {
    [ -f "$PASSWORD_FILE" ] || fail "persisted password path is not a regular file: $PASSWORD_FILE"
    [ ! -L "$PASSWORD_FILE" ] || fail "persisted password path must not be a symbolic link: $PASSWORD_FILE"
    chmod 400 "$PASSWORD_FILE" || fail "could not restrict persisted password permissions"
    [ -r "$PASSWORD_FILE" ] || fail "persisted password file is not readable: $PASSWORD_FILE"
}

validate_credentials_ready_file() {
    [ -f "$CREDENTIALS_READY_FILE" ] || fail "credential readiness marker is not a regular file: $CREDENTIALS_READY_FILE"
    [ ! -L "$CREDENTIALS_READY_FILE" ] || fail "credential readiness marker must not be a symbolic link: $CREDENTIALS_READY_FILE"
    chmod 400 "$CREDENTIALS_READY_FILE" || fail "could not restrict credential readiness marker permissions"
}

mark_credentials_ready() {
    mkdir -p "$(dirname "$CREDENTIALS_READY_FILE")"
    : > "$CREDENTIALS_READY_FILE"
    chmod 400 "$CREDENTIALS_READY_FILE"
}

wallet_identity_available() {
    interfold wallet get --config "$CONFIG_FILE" >/dev/null 2>&1
}

credentials_are_ready() {
    if [ -e "$CREDENTIALS_READY_FILE" ]; then
        validate_credentials_ready_file
        return 0
    fi

    if wallet_identity_available; then
        mark_credentials_ready
        return 0
    fi

    return 1
}

provision_wallet() {
    jq -jr '.private_key, "\n"' "$SECRETS_FILE" \
        | interfold wallet set --private-key-stdin --config "$CONFIG_FILE" \
        || fail "wallet command failed"
    mark_credentials_ready
}

configure_credentials() {
    validate_secret_file

    if [ -e "$PASSWORD_FILE" ]; then
        validate_persisted_password_file
        jq -er '.password' "$SECRETS_FILE" | tr -d '\n' | cmp -s - "$PASSWORD_FILE" \
            || fail "uploaded password does not match the persisted credential key"
        log "Using the matching persisted encryption password."
        if ! credentials_are_ready; then
            log "Encrypted wallet identity is incomplete; retrying wallet provisioning."
            provision_wallet
        fi
        rm -f "$SECRETS_FILE"
        log "Existing encrypted wallet/network identity was preserved."
        return
    fi

    log "Provisioning encrypted credentials through stdin..."
    jq -jr '.password, "\n"' "$SECRETS_FILE" \
        | interfold password set --password-stdin --config "$CONFIG_FILE" \
        || fail "password command failed"
    provision_wallet

    # DAppNode copies fileUpload content into this container before startup.
    # Wallet command derives both Ethereum and libp2p identities. Remove the
    # combined plaintext upload after both encrypted records are persisted.
    rm -f "$SECRETS_FILE"
    log "Credential setup completed."
}

if [ -e "$SECRETS_FILE" ]; then
    configure_credentials
elif [ -s "$PASSWORD_FILE" ]; then
    # Backward-compatible restart/upgrade path: DAppNode file uploads are copied
    # when configuring a container, while encrypted credentials persist in
    # /data. If an older complete install predates the readiness marker, stamp it
    # after the wallet decrypts successfully.
    validate_persisted_password_file
    credentials_are_ready || fail "credential upload is required to complete wallet provisioning: $SECRETS_FILE"
    log "No credential upload present; using persisted credential state."
else
    fail "credentials file is required for first startup: $SECRETS_FILE"
fi

# Build CLI args without shell evaluation.
CLI_ARGS=(--config "$CONFIG_FILE")

case "$LOG_LEVEL" in
    trace) CLI_ARGS=(-vvv "${CLI_ARGS[@]}") ;;
    debug) CLI_ARGS=(-vv "${CLI_ARGS[@]}") ;;
    info)  CLI_ARGS=(-v "${CLI_ARGS[@]}") ;;
esac

# Add peers if provided.
if [ -n "${PEERS:-}" ]; then
    IFS=',' read -ra PEER_ARRAY <<< "$PEERS"
    for peer in "${PEER_ARRAY[@]}"; do
        peer="$(echo "$peer" | xargs)"
        [ -n "$peer" ] && CLI_ARGS+=(--peer "$peer")
    done
fi

# EXTRA_OPTS remains an advanced, non-secret escape hatch. Split it as plain
# arguments; never evaluate it as shell source.
if [ -n "${EXTRA_OPTS:-}" ]; then
    read -r -a EXTRA_ARGS <<< "$EXTRA_OPTS"
    CLI_ARGS+=("${EXTRA_ARGS[@]}")
fi

log "Starting Interfold ciphernode."
exec interfold start "${CLI_ARGS[@]}"
