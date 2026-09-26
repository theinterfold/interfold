#!/bin/bash
set -Eeuo pipefail

umask 077

# Paths to config and secrets
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SECRETS_FILE="/run/secrets/secrets.json"
SECRETS_USED=false

# Ensure required files exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE not found!"
    exit 1
fi

# Validate the secrets file. Only a boot that must set the password or the wallet key reads it.
require_secrets() {
    if [ ! -f "$SECRETS_FILE" ]; then
        echo "Error: Secrets file $SECRETS_FILE not found!"
        exit 1
    fi

    jq -e '
        type == "object" and
        (.password | type == "string" and length > 0) and
        (.private_key | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    ' "$SECRETS_FILE" >/dev/null || {
        echo "Error: Invalid 'password' or 'private_key' in secrets file!"
        exit 1
    }
    SECRETS_USED=true
}

# Print the path that the node resolves for a setting. A log line can come before the path, so keep
# only the last line that is an absolute path.
resolve_path() {
    interfold config get "$1" --config "$CONFIG_FILE" | grep '^/' | tail -n 1
}

# Print the path that the node resolves without E3_CONFIG_DIR and E3_DATA_DIR.
resolve_own_path() {
    env -u E3_CONFIG_DIR -u E3_DATA_DIR interfold config get "$1" --config "$CONFIG_FILE" |
        grep '^/' | tail -n 1
}

# `interfold config get` creates the log directory, so look for the key file and the database.
has_state() {
    [ -n "$1" ] && [ -n "$2" ] && { [ -e "$1" ] || [ -e "$2" ]; }
}

# The image sets E3_CONFIG_DIR and E3_DATA_DIR to the volume. They override config.yaml, so keep them
# only for a node whose state belongs there. Never move state that exists: when config.yaml sets its
# own location, or a key file or database exists at the location that earlier images used (beside
# the config file, for example on a mounted directory), the node keeps using that location.
LEGACY_STATE_DIR="$CONFIG_DIR/.interfold"
VOLUME_CONFIG_DIR="$DATA_DIR/config"
VOLUME_DATA_DIR="$DATA_DIR/data"
if [ "${E3_CONFIG_DIR:-}" = "$VOLUME_CONFIG_DIR" ] && [ "${E3_DATA_DIR:-}" = "$VOLUME_DATA_DIR" ]; then
    OWN_KEY_FILE="$(resolve_own_path key_file)" || OWN_KEY_FILE=""
    OWN_DB_FILE="$(resolve_own_path db_file)" || OWN_DB_FILE=""
    VOLUME_KEY_FILE="$(resolve_path key_file)" || VOLUME_KEY_FILE=""
    VOLUME_DB_FILE="$(resolve_path db_file)" || VOLUME_DB_FILE=""
    case "$OWN_KEY_FILE" in "$LEGACY_STATE_DIR"/*) OWN_AT_LEGACY=true ;; *) OWN_AT_LEGACY=false ;; esac
    case "$OWN_DB_FILE" in "$LEGACY_STATE_DIR"/*) ;; *) OWN_AT_LEGACY=false ;; esac
    if [ "$OWN_AT_LEGACY" != true ] || [ "$VOLUME_KEY_FILE" = "$OWN_KEY_FILE" ] ||
        [ "$VOLUME_DB_FILE" = "$OWN_DB_FILE" ]; then
        # config.yaml sets the key file, the database, or their directories.
        unset E3_CONFIG_DIR E3_DATA_DIR
        echo "Using the node state location that $CONFIG_FILE sets"
        echo "Run other interfold commands in this container as: ciphernode-entrypoint.sh <command>"
    elif has_state "$OWN_KEY_FILE" "$OWN_DB_FILE"; then
        if has_state "$VOLUME_KEY_FILE" "$VOLUME_DB_FILE"; then
            echo "Error: Node state exists at $LEGACY_STATE_DIR and on the volume at $DATA_DIR!"
            echo "Keep only the state that the node last used, then start the container again."
            exit 1
        fi
        unset E3_CONFIG_DIR E3_DATA_DIR
        echo "Using the existing node state at $LEGACY_STATE_DIR"
        echo "Run other interfold commands in this container as: ciphernode-entrypoint.sh <command>"
    else
        echo "Keeping node state on the volume at $DATA_DIR"
    fi
fi

# With arguments, run that interfold command with the same state location, for example
# `ciphernode-entrypoint.sh node validate --config ...`. It does not set the password or wallet key.
if [ "$#" -gt 0 ]; then
    exec interfold "$@"
fi

if ! KEY_FILE="$(resolve_path key_file)" || [ -z "$KEY_FILE" ]; then
    echo "Error: Could not resolve the key file path from $CONFIG_FILE!"
    exit 1
fi

# `interfold password set` refuses to replace a key file, so set the password only once.
if [ -f "$KEY_FILE" ]; then
    echo "Password is already set"
else
    require_secrets
    echo "Setting password"
    jq -er '.password' "$SECRETS_FILE" | interfold password set --config "$CONFIG_FILE" --password-stdin
fi

if interfold wallet get --config "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "Wallet key is already set"
else
    require_secrets
    echo "Setting wallet key"
    # The wallet command atomically derives and stores the libp2p key from the operator key.
    jq -er '.private_key' "$SECRETS_FILE" | interfold wallet set --config "$CONFIG_FILE" --private-key-stdin
fi

# A read-only secrets mount cannot be removed. Keep the file and continue the boot.
if [ "$SECRETS_USED" = true ] && ! rm -f "$SECRETS_FILE" 2>/dev/null; then
    echo "Could not remove $SECRETS_FILE. It is probably a read-only mount, so it stays in place."
fi

echo "Starting ciphernode"
exec interfold start -v --config "$CONFIG_FILE"
