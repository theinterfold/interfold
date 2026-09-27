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

# `--name` selects the node profile, and the profile name is part of every state path. Probe the
# same profile that the command below runs.
NAME_ARGS=()
previous_arg=""
for arg in "$@"; do
    case "$arg" in
        --name=*) NAME_ARGS=(--name "${arg#--name=}") ;;
    esac
    if [ "$previous_arg" = "--name" ]; then
        NAME_ARGS=(--name "$arg")
    fi
    previous_arg="$arg"
done

# Print the path that the node resolves for a setting. A log line can come before the path, so keep
# only the last line that is an absolute path.
resolve_path() {
    interfold config get "$1" ${NAME_ARGS[@]+"${NAME_ARGS[@]}"} --config "$CONFIG_FILE" |
        grep '^/' | tail -n 1
}

# Print the path that the node resolves without E3_CONFIG_DIR and E3_DATA_DIR.
resolve_own_path() {
    env -u E3_CONFIG_DIR -u E3_DATA_DIR \
        interfold config get "$1" ${NAME_ARGS[@]+"${NAME_ARGS[@]}"} --config "$CONFIG_FILE" |
        grep '^/' | tail -n 1
}

# Whether $1 names a path that exists. `interfold config get` creates the log directory, so the
# checks below look only at the key file and the database.
exists() {
    [ -n "$1" ] && [ -e "$1" ]
}

# The image sets E3_CONFIG_DIR and E3_DATA_DIR to the volume. They override config.yaml, so they
# decide only the paths that config.yaml leaves to the directories. Never move state that exists:
# for each of the key file and the database, compare where it resolves with and without the
# variables, and use the location that already holds state. Only a path that the variables change
# can exist at two locations. A new node keeps its state on the volume, unless config.yaml sets its
# own location.
LEGACY_STATE_DIR="$CONFIG_DIR/.interfold"
VOLUME_CONFIG_DIR="$DATA_DIR/config"
VOLUME_DATA_DIR="$DATA_DIR/data"
if [ "${E3_CONFIG_DIR:-}" = "$VOLUME_CONFIG_DIR" ] && [ "${E3_DATA_DIR:-}" = "$VOLUME_DATA_DIR" ]; then
    OWN_KEY_FILE="$(resolve_own_path key_file)" || OWN_KEY_FILE=""
    OWN_DB_FILE="$(resolve_own_path db_file)" || OWN_DB_FILE=""
    VOLUME_KEY_FILE="$(resolve_path key_file)" || VOLUME_KEY_FILE=""
    VOLUME_DB_FILE="$(resolve_path db_file)" || VOLUME_DB_FILE=""
    OWN_STATE=false
    VOLUME_STATE=false
    OWN_AT_LEGACY=true
    for pair in "$OWN_KEY_FILE|$VOLUME_KEY_FILE" "$OWN_DB_FILE|$VOLUME_DB_FILE"; do
        own="${pair%%|*}"
        volume="${pair#*|}"
        [ "$own" != "$volume" ] || continue
        if exists "$own"; then OWN_STATE=true; fi
        if exists "$volume"; then VOLUME_STATE=true; fi
        case "$own" in "$LEGACY_STATE_DIR"/*) ;; *) OWN_AT_LEGACY=false ;; esac
    done
    if [ "$OWN_KEY_FILE" = "$VOLUME_KEY_FILE" ] && [ "$OWN_DB_FILE" = "$VOLUME_DB_FILE" ]; then
        # config.yaml sets both paths, so the variables change nothing.
        unset E3_CONFIG_DIR E3_DATA_DIR
        echo "Using the node state location that $CONFIG_FILE sets"
    elif [ "$OWN_STATE" = true ] && [ "$VOLUME_STATE" = true ]; then
        echo "Error: Node state exists at two locations: key $OWN_KEY_FILE, database $OWN_DB_FILE"
        echo "and key $VOLUME_KEY_FILE, database $VOLUME_DB_FILE on the volume at $DATA_DIR!"
        echo "Keep only the state that the node last used, then start the container again."
        exit 1
    elif [ "$OWN_STATE" = true ]; then
        unset E3_CONFIG_DIR E3_DATA_DIR
        echo "Using the existing node state: key $OWN_KEY_FILE, database $OWN_DB_FILE"
    elif [ "$VOLUME_STATE" = true ] || [ "$OWN_AT_LEGACY" = true ]; then
        echo "Keeping node state on the volume at $DATA_DIR"
    else
        # A new node, and config.yaml sets its own location.
        unset E3_CONFIG_DIR E3_DATA_DIR
        echo "Using the node state location that $CONFIG_FILE sets"
    fi
    if [ -z "${E3_DATA_DIR:-}" ]; then
        echo "Run other interfold commands in this container as: ciphernode-entrypoint.sh <command>"
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
