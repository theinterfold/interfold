#!/bin/bash
# DAppNode Interfold Ciphernode Entrypoint
set -e

CONFIG_DIR="/data"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
TEMPLATE_FILE="/opt/config.template.yaml"

log() { echo "[$(date '+%H:%M:%S')] $1"; }

echo "=========================================="
echo "  Interfold Ciphernode - ${NETWORK:-sepolia}"
echo "=========================================="

# Validate RPC URL (required)
if [ -z "$RPC_URL" ]; then
    log "ERROR: RPC_URL is required!"
    log "Set it in the DAppNode package configuration."
    exit 1
fi

if [[ ! "$RPC_URL" =~ ^wss?:// ]]; then
    log "ERROR: RPC_URL must be a WebSocket URL (ws:// or wss://)"
    exit 1
fi

# Set defaults
export NETWORK="${NETWORK:-sepolia}"
export QUIC_PORT="${QUIC_PORT:-37173}"
export NODE_ADDRESS="${NODE_ADDRESS:-}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# Contract addresses are set by package variants or environment variables
# No need for default placeholders here as variants handle network-specific values

# Generate config from template
log "Generating configuration..."
envsubst < "$TEMPLATE_FILE" > "$CONFIG_FILE"

# Setup secrets if provided
if [ -n "$ENCRYPTION_PASSWORD" ]; then
    log "Setting encryption password..."
    echo "$ENCRYPTION_PASSWORD" | interfold password set --config "$CONFIG_FILE" 2>/dev/null || true
fi

if [ -n "$NETWORK_PRIVATE_KEY" ]; then
    log "Setting network key..."
    interfold net set-key --config "$CONFIG_FILE" --net-keypair "$NETWORK_PRIVATE_KEY" 2>/dev/null || true
fi

if [ -n "$PRIVATE_KEY" ]; then
    log "Setting wallet key..."
    interfold wallet set --config "$CONFIG_FILE" --private-key "$PRIVATE_KEY" 2>/dev/null || true
fi

# Build CLI args
CLI_ARGS="--config $CONFIG_FILE"

case "$LOG_LEVEL" in
    trace) CLI_ARGS="-vvv $CLI_ARGS" ;;
    debug) CLI_ARGS="-vv $CLI_ARGS" ;;
    info)  CLI_ARGS="-v $CLI_ARGS" ;;
esac

# Add peers if provided
if [ -n "$PEERS" ]; then
    IFS=',' read -ra PEER_ARRAY <<< "$PEERS"
    for peer in "${PEER_ARRAY[@]}"; do
        peer=$(echo "$peer" | xargs)
        [ -n "$peer" ] && CLI_ARGS="$CLI_ARGS --peer $peer"
    done
fi

[ -n "$EXTRA_OPTS" ] && CLI_ARGS="$CLI_ARGS $EXTRA_OPTS"

# Start
log "Starting: interfold start $CLI_ARGS"
exec interfold start $CLI_ARGS