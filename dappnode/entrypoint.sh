#!/bin/bash
# DAppNode Interfold Ciphernode Entrypoint
set -Eeuo pipefail

umask 077

CONFIG_DIR="${CONFIG_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-$CONFIG_DIR/config.yaml}"
# Wizard uploads must survive container recreation before identity provisioning.
SECRETS_FILE="${SECRETS_FILE:-$CONFIG_DIR/secrets.json}"
CURRENT_STATE_DIR="${CURRENT_STATE_DIR:-$CONFIG_DIR/.interfold}"
# Current Interfold releases resolve a relative `key_file: key` beside a discovered
# /data/config.yaml to this path for the default node profile.
PASSWORD_FILE="${PASSWORD_FILE:-$CURRENT_STATE_DIR/config/_default/key}"
CREDENTIALS_READY_FILE="$(dirname "$PASSWORD_FILE")/credentials.provisioned"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"; }
fail() {
    log "ERROR: $1"
    exit 1
}

if [ -f /opt/package-network ]; then
    PACKAGE_NETWORK=$(cat /opt/package-network)
    [ -z "${NETWORK:-}" ] || [ "$NETWORK" = "$PACKAGE_NETWORK" ] \
        || fail "NETWORK does not match this package; install the package for the required network"
    export NETWORK="$PACKAGE_NETWORK"
fi

echo "=========================================="
echo "  Interfold Ciphernode - ${NETWORK:-mainnet}"
echo "=========================================="

# Docker exposes environment variables in package metadata. Require a file for credentials.
if [ -n "${ENCRYPTION_PASSWORD:-}" ] || [ -n "${NETWORK_PRIVATE_KEY:-}" ] || [ -n "${PRIVATE_KEY:-}" ]; then
    fail "credential environment variables are unsupported; upload the DAppNode credentials JSON file"
fi

mkdir -p "$CONFIG_DIR"
[ ! -L "$CURRENT_STATE_DIR" ] || fail "node data must not be a symbolic link"
[ ! -e "$CURRENT_STATE_DIR" ] || [ -d "$CURRENT_STATE_DIR" ] || fail "node data path must be a directory"

# Render a candidate beside the saved config so CLI credential paths stay in /data.
export NETWORK="${NETWORK:-mainnet}"
export QUIC_PORT="${QUIC_PORT:-37173}"
export LOG_LEVEL="${LOG_LEVEL:-info}"
export DASHBOARD_ENABLED="${DASHBOARD_ENABLED:-false}"
case "$LOG_LEVEL" in
    info|debug|trace) ;;
    *) fail "LOG_LEVEL must be one of: info, debug, trace" ;;
esac
case "$DASHBOARD_ENABLED" in
    true|false) ;;
    *) fail "DASHBOARD_ENABLED must be true or false" ;;
esac

DERIVED_NODE_ADDRESS=""
export NODE_ADDRESS=0x0000000000000000000000000000000000000000
export SAVED_CONFIG_FILE="$CONFIG_FILE"
[ ! -L "$SAVED_CONFIG_FILE" ] || fail "saved configuration must not be a symbolic link"
PENDING_CONFIG_FILE=$(mktemp "$SAVED_CONFIG_FILE.pending.XXXXXX")
export CONFIG_FILE="$PENDING_CONFIG_FILE"
export CURRENT_STATE_DIR PASSWORD_FILE
trap 'rm -f "$PENDING_CONFIG_FILE"' EXIT

log "Checking network configuration and RPC access..."
# DAppNode clients use separate HTTP and WebSocket ports. The upstream signer keeps the WS port.
if [[ "${RPC_URL:-}" =~ ^ws://(execution\.(mainnet|sepolia)\.dncore\.dappnode):8546/?$ ]]; then
    export RPC_UPSTREAM_HOST="${BASH_REMATCH[1]}"
    envsubst '$RPC_UPSTREAM_HOST' < /opt/rpc-proxy.conf.template > /tmp/interfold-rpc-proxy.conf
    nginx -c /tmp/interfold-rpc-proxy.conf \
        || fail "execution RPC proxy failed to start; check the selected DAppNode execution client"
    export RPC_URL="ws://127.0.0.1:8550"
    log "Using the DAppNode execution client."
fi
python3 "$(dirname "${BASH_SOURCE[0]}")/configure.py" render || fail "check the package Config settings"
python3 "$(dirname "${BASH_SOURCE[0]}")/configure.py" check-rpc || fail "check the execution client or RPC_URL in Config"
# Record the first network before any credential command can create partial state.
# Existing configurations stay unchanged until provisioning and address checks succeed.
[ -e "$SAVED_CONFIG_FILE" ] || cp -- "$CONFIG_FILE" "$SAVED_CONFIG_FILE"

validate_secret_file() {
    [ -f "$SECRETS_FILE" ] || fail "credentials path is not a regular file: $SECRETS_FILE"
    [ ! -L "$SECRETS_FILE" ] || fail "credentials path must not be a symbolic link: $SECRETS_FILE"
    [ -r "$SECRETS_FILE" ] || fail "credentials file is not readable: $SECRETS_FILE"

    local size
    size=$(wc -c < "$SECRETS_FILE")
    [ "$size" -le 16384 ] || fail "credentials file exceeds the 16 KiB limit"

    jq -e '
        type == "object" and
        (keys | sort == ["password", "private_key"]) and
        (.password | type == "string" and length > 0 and length <= 1024 and
            (explode | all(. != 0 and . != 10 and . != 13)) and . == gsub("^\\s+|\\s+$"; "")) and
        (.private_key | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    ' "$SECRETS_FILE" >/dev/null || fail "credentials file must contain valid password and private_key strings"
}

validate_persisted_password_file() {
    [ -f "$PASSWORD_FILE" ] || fail "persisted password path is not a regular file: $PASSWORD_FILE"
    [ ! -L "$PASSWORD_FILE" ] || fail "persisted password path must not be a symbolic link: $PASSWORD_FILE"
    chmod 400 "$PASSWORD_FILE" || fail "could not restrict persisted password permissions"
    [ -r "$PASSWORD_FILE" ] || fail "persisted password file is not readable: $PASSWORD_FILE"
}

provision_wallet() {
    jq -jr '.private_key, "\n"' "$SECRETS_FILE" \
        | interfold wallet set --private-key-stdin --config "$CONFIG_FILE" \
        || fail "wallet command failed"
}

configure_credentials() {
    validate_secret_file

    if [ -e "$PASSWORD_FILE" ]; then
        validate_persisted_password_file
        jq -er '.password' "$SECRETS_FILE" | tr -d '\n' | cmp -s - "$PASSWORD_FILE" \
            || fail "uploaded password does not match the persisted credential key"
        if ! DERIVED_NODE_ADDRESS=$(interfold wallet get --config "$CONFIG_FILE" 2>/dev/null); then
            [ ! -e "$CREDENTIALS_READY_FILE" ] || fail "cannot read the saved identity; restore its encrypted backup"
            log "Completing wallet setup..."
            provision_wallet
        fi
        log "Using the saved node identity."
        return
    fi

    log "Setting up the node identity..."
    jq -jr '.password, "\n"' "$SECRETS_FILE" \
        | interfold password set --password-stdin --config "$CONFIG_FILE" \
        || fail "password command failed"
    provision_wallet
}

if [ -e "$SECRETS_FILE" ]; then
    configure_credentials
elif [ -s "$PASSWORD_FILE" ]; then
    validate_persisted_password_file
    log "Using the saved node identity."
else
    fail "credentials file is required for first startup: $SECRETS_FILE"
fi

# Verify the saved wallet on every start.
if [ -z "${DERIVED_NODE_ADDRESS:-}" ]; then
    DERIVED_NODE_ADDRESS=$(interfold wallet get --config "$CONFIG_FILE") \
        || fail "cannot read the persisted wallet; restore its encrypted credential backup"
fi
[[ "$DERIVED_NODE_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]] || fail "wallet returned an invalid node address"
[ ! -L "$CREDENTIALS_READY_FILE" ] || fail "credential marker must not be a symbolic link"
if [ ! -e "$CREDENTIALS_READY_FILE" ]; then
    : > "$CREDENTIALS_READY_FILE"
    chmod 400 "$CREDENTIALS_READY_FILE"
fi
export NODE_ADDRESS="$DERIVED_NODE_ADDRESS"
python3 "$(dirname "${BASH_SOURCE[0]}")/configure.py" render || fail "could not save the node configuration"
chmod 600 "$CONFIG_FILE"
mv -- "$CONFIG_FILE" "$SAVED_CONFIG_FILE"
CONFIG_FILE="$SAVED_CONFIG_FILE"
[ ! -e "$SECRETS_FILE" ] || rm -f "$SECRETS_FILE"
log "Node address: $NODE_ADDRESS"

if [ "$DASHBOARD_ENABLED" = true ]; then
    DASHBOARD_HOSTNAME="interfold-ciphernode-${NETWORK}.dappnode"
    # Bind the proxy to the DAppNode VPN interface without publishing a host port.
    DASHBOARD_BIND_ADDRESS=$(getent ahostsv4 "$DASHBOARD_HOSTNAME" | awk 'NR == 1 {print $1}') \
        || fail "DAppNode DNS is unavailable; check the package network"
    [[ "$DASHBOARD_BIND_ADDRESS" =~ ^172\.33\.[0-9]+\.[0-9]+$ ]] \
        || fail "dashboard DNS must resolve to the DAppNode core network"
    export DASHBOARD_BIND_ADDRESS
    envsubst '$DASHBOARD_BIND_ADDRESS' < /opt/nginx.conf.template > /tmp/interfold-nginx.conf
    nginx -c /tmp/interfold-nginx.conf || fail "dashboard proxy failed to start"
    log "Dashboard: http://$DASHBOARD_HOSTNAME:8081 (DAppNode VPN network)"
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
