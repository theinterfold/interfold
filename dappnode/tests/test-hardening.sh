#!/bin/bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT
DAPPNODE_VERSION=$(node -p "require('$ROOT_DIR/dappnode_package.json').version")
DAPPNODE_UPSTREAM_VERSION=$(node -p "require('$ROOT_DIR/dappnode_package.json').upstreamVersion")

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

grep -Fq 'stop_grace_period: 45s' "$ROOT_DIR/docker-compose.yml" \
    || fail "Docker stop grace period must exceed the node shutdown deadline"

assert_contains() {
    grep -Fq -- "$2" "$1" || fail "expected '$2' in $1"
}

assert_not_contains() {
    if grep -Fq -- "$2" "$1"; then
        fail "did not expect '$2' in $1"
    fi
}

make_mock_interfold() {
    local bin_dir=$1
    mkdir -p "$bin_dir"
    printf '%s\n' \
        '#!/bin/bash' \
        'set -Eeuo pipefail' \
        'case "${1:-} ${2:-} ${3:-}" in' \
        '  "password set --password-stdin"*) operation=password ;;' \
        '  "wallet set --private-key-stdin"*) operation=wallet ;;' \
        '  "wallet get --config"*) operation=wallet-get ;;' \
        '  "start "*) operation=start ;;' \
        '  *) operation=unexpected ;;' \
        'esac' \
        'printf "%s\n" "$operation" >> "$CALL_LOG"' \
        'printf "%s" "$0" >> "$ARGV_LOG"' \
        'for arg in "$@"; do printf " %s" "$arg" >> "$ARGV_LOG"; done' \
        'printf "\n" >> "$ARGV_LOG"' \
        '[ "${FAIL_ON:-}" != "$operation" ] || exit 42' \
        'case "$operation" in' \
        '  password)' \
        '    IFS= read -r secret' \
        '    mkdir -p "$(dirname "$PASSWORD_FILE")"' \
        '    printf "%s" "$secret" > "$PASSWORD_FILE"' \
        '    chmod 400 "$PASSWORD_FILE"' \
        '    ;;' \
        '  wallet)' \
        '    IFS= read -r secret' \
        '    printf "%s" "$secret" > "$WALLET_FILE"' \
        '    chmod 400 "$WALLET_FILE"' \
        '    ;;' \
        '  wallet-get)' \
        '    [ "${WALLET_GET_FAIL:-}" != "1" ] || exit 43' \
        '    [ -s "$WALLET_FILE" ] || exit 44' \
        '    printf "0x3333333333333333333333333333333333333333\n"' \
        '    ;;' \
        '  start)' \
        '    : ;;' \
        '  *)' \
        '    exit 2 ;;' \
        'esac' \
        > "$bin_dir/interfold"
    chmod +x "$bin_dir/interfold"
}

write_secrets() {
    local path=$1
    printf '%s\n' '{' \
        '  "password": "correct horse battery staple",' \
        '  "private_key": "0x1111111111111111111111111111111111111111111111111111111111111111"' \
        '}' > "$path"
}

write_legacy_secrets() {
    local path=$1
    printf '%s\n' '{' \
        '  "password": "correct horse battery staple",' \
        '  "private_key": "0x1111111111111111111111111111111111111111111111111111111111111111",' \
        '  "network_private_key": "0x2222222222222222222222222222222222222222222222222222222222222222"' \
        '}' > "$path"
}

run_entrypoint() {
    local case_dir=$1
    shift
    mkdir -p "$case_dir/data" "$case_dir/secrets" "$case_dir/bin"
    : > "$case_dir/calls"
    : > "$case_dir/argv"
    make_mock_interfold "$case_dir/bin"

    env -u ENCRYPTION_PASSWORD -u NETWORK_PRIVATE_KEY -u PRIVATE_KEY \
        PATH="$case_dir/bin:$PATH" \
        CONFIG_DIR="$case_dir/data" \
        CONFIG_FILE="$case_dir/data/config.yaml" \
        TEMPLATE_FILE="$ROOT_DIR/config.template.yaml" \
        SECRETS_FILE="$case_dir/secrets/secrets.json" \
        PASSWORD_FILE="$case_dir/data/password" \
        CREDENTIALS_READY_FILE="$case_dir/data/credentials.provisioned" \
        WALLET_FILE="$case_dir/data/wallet" \
        CALL_LOG="$case_dir/calls" \
        ARGV_LOG="$case_dir/argv" \
        RPC_URL="ws://127.0.0.1:8545" \
        CHAIN_ID=1 \
        NODE_ADDRESS="0x3333333333333333333333333333333333333333" \
        INTERFOLD_CONTRACT="0x4444444444444444444444444444444444444444" \
        CIPHERNODE_REGISTRY_CONTRACT="0x5555555555555555555555555555555555555555" \
        BONDING_REGISTRY_CONTRACT="0x6666666666666666666666666666666666666666" \
        SLASHING_MANAGER_CONTRACT="0x7777777777777777777777777777777777777777" \
        FEE_TOKEN_CONTRACT="0x8888888888888888888888888888888888888888" \
        INTERFOLD_DEPLOY_BLOCK=1 \
        CIPHERNODE_REGISTRY_DEPLOY_BLOCK=2 \
        BONDING_REGISTRY_DEPLOY_BLOCK=3 \
        SLASHING_MANAGER_DEPLOY_BLOCK=4 \
        FEE_TOKEN_DEPLOY_BLOCK=5 \
        PRIVATE_KEY="${TEST_PRIVATE_KEY:-}" \
        "$@" bash "$ROOT_DIR/entrypoint.sh" > "$case_dir/output" 2>&1
}

# Successful provisioning uses the current atomic wallet command, removes the
# plaintext upload, and starts only after every credential command succeeds.
success_dir="$TEST_ROOT/success"
mkdir -p "$success_dir/secrets"
write_secrets "$success_dir/secrets/secrets.json"
run_entrypoint "$success_dir"
[ ! -e "$success_dir/secrets/secrets.json" ] || fail "successful setup retained plaintext credentials"
[ "$(tr '\n' ' ' < "$success_dir/calls")" = "password wallet start " ] || fail "unexpected successful command order"
assert_not_contains "$success_dir/argv" 'correct horse battery staple'
assert_not_contains "$success_dir/argv" '0x1111111111111111111111111111111111111111111111111111111111111111'
assert_contains "$success_dir/data/config.yaml" 'autopassword: false'
assert_contains "$success_dir/data/config.yaml" 'autonetkey: false'
assert_contains "$success_dir/data/config.yaml" 'autowallet: false'
assert_contains "$success_dir/data/config.yaml" 'chain_id: 1'
assert_contains "$success_dir/data/config.yaml" 'slashing_manager:'
assert_contains "$success_dir/data/config.yaml" '0x7777777777777777777777777777777777777777'
assert_contains "$success_dir/data/config.yaml" 'fee_token:'
assert_contains "$success_dir/data/config.yaml" '0x8888888888888888888888888888888888888888'
assert_contains "$success_dir/data/config.yaml" 'https://avail-rpc.publicnode.com/'

# The pinned Avail client uses HTTP JSON-RPC. Rejecting WebSocket URLs at startup avoids a node
# appearing healthy while every data retrieval fails with a local BadScheme error.
invalid_avail_dir="$TEST_ROOT/invalid-avail-rpc"
mkdir -p "$invalid_avail_dir/secrets"
write_secrets "$invalid_avail_dir/secrets/secrets.json"
if run_entrypoint "$invalid_avail_dir" AVAIL_RPC_URL="wss://turing-rpc.avail.so/ws"; then
    fail "WebSocket Avail RPC URL was accepted"
fi
[ ! -s "$invalid_avail_dir/calls" ] || fail "invalid Avail RPC URL invoked Interfold"
assert_contains "$invalid_avail_dir/output" 'AVAIL_RPC_URL must be an HTTP URL'

# A credential command failure must propagate and must never start the node.
failure_dir="$TEST_ROOT/failure"
mkdir -p "$failure_dir/secrets"
write_secrets "$failure_dir/secrets/secrets.json"
if run_entrypoint "$failure_dir" FAIL_ON=wallet; then
    fail "wallet credential failure was ignored"
fi
assert_contains "$failure_dir/calls" 'wallet'
assert_not_contains "$failure_dir/calls" 'start'
[ -e "$failure_dir/secrets/secrets.json" ] || fail "failed setup removed recovery input"
[ ! -e "$failure_dir/data/credentials.provisioned" ] || fail "failed setup created readiness marker"
run_entrypoint "$failure_dir"
[ "$(tr '\n' ' ' < "$failure_dir/calls")" = "wallet-get wallet start " ] \
    || fail "wallet retry did not resume incomplete provisioning"
[ ! -e "$failure_dir/secrets/secrets.json" ] || fail "retried setup did not remove plaintext credentials"
[ -e "$failure_dir/data/credentials.provisioned" ] || fail "retried setup did not create readiness marker"

# Existing state may only be reused with the password that encrypted it.
mismatch_dir="$TEST_ROOT/password-mismatch"
mkdir -p "$mismatch_dir/data" "$mismatch_dir/secrets"
printf '%s' 'different-password' > "$mismatch_dir/data/password"
write_secrets "$mismatch_dir/secrets/secrets.json"
if run_entrypoint "$mismatch_dir"; then
    fail "mismatched persisted password was accepted"
fi
[ ! -s "$mismatch_dir/calls" ] || fail "password mismatch mutated credentials"

# A matching upload on existing state must not rotate either persisted identity.
matching_dir="$TEST_ROOT/password-match"
mkdir -p "$matching_dir/data" "$matching_dir/secrets"
printf '%s' 'correct horse battery staple' > "$matching_dir/data/password"
printf '%s' 'ready' > "$matching_dir/data/credentials.provisioned"
write_secrets "$matching_dir/secrets/secrets.json"
run_entrypoint "$matching_dir"
[ "$(tr '\n' ' ' < "$matching_dir/calls")" = "start " ] || fail "matching persisted state was re-provisioned"
[ ! -e "$matching_dir/secrets/secrets.json" ] || fail "matching upload was not removed"

# Legacy three-field uploads remain accepted; the wallet command derives the libp2p key
# atomically from the wallet key and ignores the obsolete separate network key.
legacy_credentials_dir="$TEST_ROOT/legacy-credentials"
mkdir -p "$legacy_credentials_dir/secrets"
write_legacy_secrets "$legacy_credentials_dir/secrets/secrets.json"
run_entrypoint "$legacy_credentials_dir"
[ "$(tr '\n' ' ' < "$legacy_credentials_dir/calls")" = "password wallet start " ] \
    || fail "legacy credential upload was not accepted"

# Malformed or absent first-start credentials fail before invoking Interfold.
malformed_dir="$TEST_ROOT/malformed"
mkdir -p "$malformed_dir/secrets"
printf '%s\n' '{"password":"only-one-field"}' > "$malformed_dir/secrets/secrets.json"
if run_entrypoint "$malformed_dir"; then
    fail "malformed credentials were accepted"
fi
[ ! -s "$malformed_dir/calls" ] || fail "malformed credentials invoked Interfold"

missing_dir="$TEST_ROOT/missing"
if run_entrypoint "$missing_dir"; then
    fail "first startup without credentials was accepted"
fi
[ ! -s "$missing_dir/calls" ] || fail "missing credentials invoked Interfold"

# A normal restart may reuse credentials already encrypted in the persistent
# /data volume without requiring the one-time plaintext upload again.
restart_dir="$TEST_ROOT/restart"
mkdir -p "$restart_dir/data"
printf '%s' 'persisted-password' > "$restart_dir/data/password"
chmod 400 "$restart_dir/data/password"
printf '%s' 'ready' > "$restart_dir/data/credentials.provisioned"
run_entrypoint "$restart_dir"
[ "$(tr '\n' ' ' < "$restart_dir/calls")" = "start " ] || fail "persisted restart unexpectedly re-provisioned credentials"

old_restart_dir="$TEST_ROOT/old-restart"
mkdir -p "$old_restart_dir/data"
printf '%s' 'persisted-password' > "$old_restart_dir/data/password"
printf '%s' 'wallet' > "$old_restart_dir/data/wallet"
run_entrypoint "$old_restart_dir"
[ "$(tr '\n' ' ' < "$old_restart_dir/calls")" = "wallet-get start " ] \
    || fail "old complete state was not marked and started"
[ -e "$old_restart_dir/data/credentials.provisioned" ] || fail "old complete state was not marked ready"

incomplete_restart_dir="$TEST_ROOT/incomplete-restart"
mkdir -p "$incomplete_restart_dir/data"
printf '%s' 'persisted-password' > "$incomplete_restart_dir/data/password"
if run_entrypoint "$incomplete_restart_dir"; then
    fail "password-only state without upload was accepted"
fi
assert_contains "$incomplete_restart_dir/calls" 'wallet-get'
assert_not_contains "$incomplete_restart_dir/calls" 'start'

# The 0.1.8 state bridge moves the complete custom-config namespace in one
# rename, preserving the unversioned DB/event log for current releases.
upgrade_dir="$TEST_ROOT/legacy-upgrade"
mkdir -p "$upgrade_dir/data/.enclave/config/_default" "$upgrade_dir/data/.enclave/data/_default/db" \
    "$upgrade_dir/data/.enclave/data/_default/log.0"
printf '%s' 'persisted-password' > "$upgrade_dir/data/.enclave/config/_default/key"
printf '%s' 'legacy-state' > "$upgrade_dir/data/.enclave/data/_default/db/sentinel"
printf '%s' 'wallet' > "$upgrade_dir/data/wallet"
run_entrypoint "$upgrade_dir" \
    PASSWORD_FILE="$upgrade_dir/data/.interfold/config/_default/key"
[ ! -e "$upgrade_dir/data/.enclave" ] || fail "legacy state namespace remained after upgrade"
assert_contains "$upgrade_dir/data/.interfold/data/_default/db/sentinel" 'legacy-state'
[ "$(tr '\n' ' ' < "$upgrade_dir/calls")" = "wallet-get start " ] || fail "legacy state upgrade did not start"

ambiguous_dir="$TEST_ROOT/ambiguous-upgrade"
mkdir -p "$ambiguous_dir/data/.enclave" "$ambiguous_dir/data/.interfold"
if run_entrypoint "$ambiguous_dir"; then
    fail "ambiguous legacy/current state was accepted"
fi
[ ! -s "$ambiguous_dir/calls" ] || fail "ambiguous state invoked Interfold"

# Legacy secret environment variables are explicitly rejected.
legacy_dir="$TEST_ROOT/legacy-env"
mkdir -p "$legacy_dir/data"
printf '%s' 'persisted-password' > "$legacy_dir/data/password"
if TEST_PRIVATE_KEY=legacy run_entrypoint "$legacy_dir"; then
    fail "legacy secret environment variable was accepted"
fi

# Entrypoint regressions: credential values must never be expanded into CLI
# flags, even if those legacy flags remain available for interactive users.
assert_not_contains "$ROOT_DIR/entrypoint.sh" '--password "$password"'
assert_not_contains "$ROOT_DIR/entrypoint.sh" '--private-key "$private_key"'
assert_not_contains "$ROOT_DIR/entrypoint.sh" '--net-keypair "$network_private_key"'
assert_contains "$ROOT_DIR/docker-compose.yml" "UPSTREAM_VERSION: $DAPPNODE_UPSTREAM_VERSION"
assert_contains "$ROOT_DIR/docker-compose.yml" "ciphernode.interfold-ciphernode.public.dappnode.eth:$DAPPNODE_VERSION"
assert_contains "$ROOT_DIR/Dockerfile" "ARG UPSTREAM_VERSION=$DAPPNODE_UPSTREAM_VERSION"
assert_contains "$ROOT_DIR/docker-compose.yml" "INTERFOLD_CONTRACT: '0x28cF63B459e6218C69EA97ea7D90541cf648c715'"
assert_contains "$ROOT_DIR/docker-compose.yml" "SLASHING_MANAGER_CONTRACT: '0x974E865B1BB24AF2a9ef8204AdEA9251Cc7C5FD9'"
assert_contains "$ROOT_DIR/healthcheck.sh" '/data/.interfold/data/_default/db'

# Health probe regression: require the exact process/config, protected files,
# and bound QUIC listener rather than accepting an arbitrary matching PID.
health_dir="$TEST_ROOT/health"
mkdir -p "$health_dir/proc/1" "$health_dir/bin" "$health_dir/data" "$health_dir/data/db" "$health_dir/data/log.0"
ln -s "$health_dir/bin/interfold" "$health_dir/proc/1/exe"
: > "$health_dir/bin/interfold"
printf '/usr/local/bin/interfold\0start\0-v\0--config\0%s\0' "$health_dir/data/config.yaml" > "$health_dir/proc/1/cmdline"
printf 'config' > "$health_dir/data/config.yaml"
printf 'password' > "$health_dir/data/password"

printf '%s\n' \
    '#!/bin/sh' \
    '[ "${SS_READY:-1}" = 1 ] && printf "udp listener\n"' \
    > "$health_dir/bin/ss"
printf '%s\n' \
    '#!/bin/sh' \
    'printf "%s\n" "${STAT_MODE:-600}"' \
    > "$health_dir/bin/stat"
chmod +x "$health_dir/bin/ss" "$health_dir/bin/stat"

PROC_ROOT="$health_dir/proc" \
CONFIG_FILE="$health_dir/data/config.yaml" \
PASSWORD_FILE="$health_dir/data/password" \
DB_PATH="$health_dir/data/db" \
EVENT_LOG_PATH="$health_dir/data/log.0" \
SS_BIN="$health_dir/bin/ss" \
STAT_BIN="$health_dir/bin/stat" \
sh "$ROOT_DIR/healthcheck.sh" || fail "healthy local state was rejected"

if PROC_ROOT="$health_dir/proc" \
    CONFIG_FILE="$health_dir/data/config.yaml" \
    PASSWORD_FILE="$health_dir/data/password" \
    DB_PATH="$health_dir/data/db" \
    EVENT_LOG_PATH="$health_dir/data/log.0" \
    SS_BIN="$health_dir/bin/ss" \
    STAT_BIN="$health_dir/bin/stat" \
    SS_READY=0 sh "$ROOT_DIR/healthcheck.sh"; then
    fail "missing QUIC listener was considered healthy"
fi

if PROC_ROOT="$health_dir/proc" \
    CONFIG_FILE="$health_dir/data/config.yaml" \
    PASSWORD_FILE="$health_dir/data/password" \
    DB_PATH="$health_dir/data/db" \
    EVENT_LOG_PATH="$health_dir/data/log.0" \
    SS_BIN="$health_dir/bin/ss" \
    STAT_BIN="$health_dir/bin/stat" \
    STAT_MODE=644 sh "$ROOT_DIR/healthcheck.sh"; then
    fail "insecure credential permissions were considered healthy"
fi

ln -sfn "$health_dir/bin/not-interfold" "$health_dir/proc/1/exe"
if PROC_ROOT="$health_dir/proc" \
    CONFIG_FILE="$health_dir/data/config.yaml" \
    PASSWORD_FILE="$health_dir/data/password" \
    DB_PATH="$health_dir/data/db" \
    EVENT_LOG_PATH="$health_dir/data/log.0" \
    SS_BIN="$health_dir/bin/ss" \
    STAT_BIN="$health_dir/bin/stat" \
    sh "$ROOT_DIR/healthcheck.sh"; then
    fail "unrelated PID 1 was considered healthy"
fi

ln -sfn "$health_dir/bin/interfold" "$health_dir/proc/1/exe"
rmdir "$health_dir/data/log.0"
if PROC_ROOT="$health_dir/proc" \
    CONFIG_FILE="$health_dir/data/config.yaml" \
    PASSWORD_FILE="$health_dir/data/password" \
    DB_PATH="$health_dir/data/db" \
    EVENT_LOG_PATH="$health_dir/data/log.0" \
    SS_BIN="$health_dir/bin/ss" \
    STAT_BIN="$health_dir/bin/stat" \
    sh "$ROOT_DIR/healthcheck.sh"; then
    fail "uninitialized event persistence was considered healthy"
fi

printf 'PASS: DAppNode credential and health hardening regressions\n'
