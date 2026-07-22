#!/bin/bash
# DAppNode Interfold Ciphernode Entrypoint
set -Eeuo pipefail

umask 077

CONFIG_DIR="${CONFIG_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/config.yaml}"
TEMPLATE_FILE="${TEMPLATE_FILE:-/opt/config.template.yaml}"
SECRETS_FILE="${SECRETS_FILE:-/run/secrets/secrets.json}"
CREDENTIAL_PROVISIONER="${CREDENTIAL_PROVISIONER:-/opt/provision-credentials.exp}"
LEGACY_STATE_DIR="${LEGACY_STATE_DIR:-$CONFIG_DIR/.enclave}"
CURRENT_STATE_DIR="${CURRENT_STATE_DIR:-$CONFIG_DIR/.interfold}"
PASSWORD_FILE="${PASSWORD_FILE:-/run/interfold/key}"
LEGACY_PASSWORD_FILE="${LEGACY_PASSWORD_FILE:-$CURRENT_STATE_DIR/config/_default/key}"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"; }
fail() {
    log "ERROR: $1"
    exit 1
}

echo "=========================================="
echo "  Interfold Ciphernode - ${NETWORK:-sepolia}"
echo "=========================================="

# Environment variables are visible in Docker/DAppNode metadata. Refuse the
# legacy secret injection contract instead of silently preferring one source.
if [ -n "${ENCRYPTION_PASSWORD:-}" ] || [ -n "${NETWORK_PRIVATE_KEY:-}" ] || [ -n "${PRIVATE_KEY:-}" ]; then
    fail "credential environment variables are unsupported; upload the DAppNode credentials JSON file"
fi

# Validate RPC URL (required).
[ -n "${RPC_URL:-}" ] || fail "RPC_URL is required; set it in the DAppNode package configuration"
[[ "$RPC_URL" =~ ^wss?:// ]] || fail "RPC_URL must be a WebSocket URL (ws:// or wss://)"
[ -n "${CHAIN_ID:-}" ] || fail "CHAIN_ID is required; set the expected numeric RPC chain ID"
[[ "$CHAIN_ID" =~ ^[1-9][0-9]*$ ]] || fail "CHAIN_ID must be a positive decimal integer"
[ -n "${REORG_CONFIRMATIONS:-}" ] \
    || fail "REORG_CONFIRMATIONS is required for non-local RPC finality"
[[ "$REORG_CONFIRMATIONS" =~ ^[1-9][0-9]*$ ]] \
    || fail "REORG_CONFIRMATIONS must be a positive decimal integer"

for contract_var in INTERFOLD_CONTRACT CIPHERNODE_REGISTRY_CONTRACT \
    BONDING_REGISTRY_CONTRACT SLASHING_MANAGER_CONTRACT; do
    contract_value=${!contract_var:-}
    [[ "$contract_value" =~ ^0x[0-9a-fA-F]{40}$ ]] \
        || fail "$contract_var must be a 20-byte hexadecimal address"
done
for block_var in INTERFOLD_DEPLOY_BLOCK CIPHERNODE_REGISTRY_DEPLOY_BLOCK \
    BONDING_REGISTRY_DEPLOY_BLOCK SLASHING_MANAGER_DEPLOY_BLOCK; do
    block_value=${!block_var:-}
    [[ "$block_value" =~ ^[1-9][0-9]*$ ]] \
        || fail "$block_var must be a positive deployment block"
done

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
        log "Migrating the legacy state namespace to Interfold..."
        mv -- "$LEGACY_STATE_DIR" "$CURRENT_STATE_DIR" \
            || fail "could not migrate legacy state into $CURRENT_STATE_DIR"
    fi
}

migrate_legacy_state

# Move the legacy co-located password into the separately mounted secret
# volume. Refuse ambiguity rather than guessing which key protects the state.
if [ -e "$PASSWORD_FILE" ] && [ -e "$LEGACY_PASSWORD_FILE" ] \
    && [ "$PASSWORD_FILE" != "$LEGACY_PASSWORD_FILE" ]; then
    fail "both separated and legacy password files exist; refusing ambiguous credential state"
fi
if [ ! -e "$PASSWORD_FILE" ] && [ -f "$LEGACY_PASSWORD_FILE" ] \
    && [ "$PASSWORD_FILE" != "$LEGACY_PASSWORD_FILE" ]; then
    mkdir -p "$(dirname "$PASSWORD_FILE")"
    mv -- "$LEGACY_PASSWORD_FILE" "$PASSWORD_FILE" \
        || fail "could not separate the legacy password from encrypted node state"
fi

# Set non-secret defaults.
export NETWORK="${NETWORK:-sepolia}"
export QUIC_PORT="${QUIC_PORT:-37173}"
export NODE_ADDRESS="${NODE_ADDRESS:-}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

case "$LOG_LEVEL" in
    info|debug|trace) ;;
    *) fail "LOG_LEVEL must be one of: info, debug, trace" ;;
esac

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
        (.password | type == "string" and length >= 16 and length <= 1024 and
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

configure_credentials() {
    validate_secret_file

    if [ -e "$PASSWORD_FILE" ]; then
        validate_persisted_password_file
        jq -er '.password' "$SECRETS_FILE" | tr -d '\n' | cmp -s - "$PASSWORD_FILE" \
            || fail "uploaded password does not match the persisted credential key"
        log "Using the matching persisted encryption password."
        rm -f "$SECRETS_FILE"
        log "Existing encrypted wallet/network identity was preserved."
        return
    fi

    [ -r "$CREDENTIAL_PROVISIONER" ] || fail "credential provisioner is not readable: $CREDENTIAL_PROVISIONER"
    log "Provisioning encrypted credentials through hidden stdin prompts..."
    jq -jr '[.password, .private_key][] | @base64 + "\n"' "$SECRETS_FILE" \
        | expect "$CREDENTIAL_PROVISIONER" "$CONFIG_FILE" \
        || fail "one or more credential commands failed"

    # DAppNode copies fileUpload content into this container before startup.
    # Wallet/network keys are encrypted in /data while the password is stored
    # on the separate /run/interfold volume. Remove the combined plaintext upload.
    rm -f "$SECRETS_FILE"
    log "Credential setup completed."
}

if [ -e "$SECRETS_FILE" ]; then
    configure_credentials
elif [ -s "$PASSWORD_FILE" ]; then
    # Backward-compatible restart/upgrade path: DAppNode file uploads are copied
    # when configuring a container, while encrypted credentials persist in
    # /data. Interfold itself will fail startup if wallet/network state is absent.
    validate_persisted_password_file
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
