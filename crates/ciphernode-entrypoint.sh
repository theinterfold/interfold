#!/bin/bash
set -e

# Paths to config and secrets
CONFIG_FILE="$CONFIG_DIR/config.yaml"
SECRETS_FILE="/run/secrets/secrets.json"

# Ensure required files exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE not found!"
    exit 1
fi

if [ ! -f "$SECRETS_FILE" ]; then
    echo "Error: Secrets file $SECRETS_FILE not found!"
    exit 1
fi

# Read secrets from the JSON file
PRIVATE_KEY=$(jq -r '.private_key' "$SECRETS_FILE")
PASSWORD=$(jq -r '.password' "$SECRETS_FILE")
NETWORK_PRIVATE_KEY=$(jq -r '.network_private_key' "$SECRETS_FILE")

if [ -z "$PRIVATE_KEY" ] || [ -z "$PASSWORD" ] || [ -z "$NETWORK_PRIVATE_KEY" ]; then
    echo "Error: Missing 'private_key', 'password' or 'network_private_key' in secrets file!"
    exit 1
fi

# Set password
echo "Setting password"
interfold password set --config "$CONFIG_FILE" --password "$PASSWORD"

# Set network private key
echo "Setting network private key"
interfold net set-key --config "$CONFIG_FILE" --net-keypair "$NETWORK_PRIVATE_KEY"

echo "Setting wallet key"
interfold wallet set --config "$CONFIG_FILE" --private-key "$PRIVATE_KEY"

echo "Starting ciphernode"
exec interfold start -v --config "$CONFIG_FILE"


