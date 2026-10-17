#!/bin/bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
RPC_SERVER_PID=""
cleanup() {
    if [ -n "$RPC_SERVER_PID" ]; then
        kill "$RPC_SERVER_PID" 2>/dev/null || true
        wait "$RPC_SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT
DAPPNODE_UPSTREAM_VERSION=$(node -p "require('$ROOT_DIR/dappnode_package.json').upstreamVersion")

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

# Serve HTTP and WebSocket RPC locally for startup checks.
python3 - "$TEST_ROOT/rpc-port" <<'RPC_FIXTURE' &
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import struct
import sys


class RpcHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_response(404)
            self.end_headers()
            return
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        while True:
            header = self.rfile.read(2)
            if not header:
                return
            if header[0] & 15 == 8:
                self.wfile.write(b"\x88\x00")
                self.wfile.flush()
                return
            length = header[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.rfile.read(8))[0]
            mask = self.rfile.read(4)
            payload = self.rfile.read(length)
            request = json.loads(bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
            response = self.reply(request)
            self.wfile.write(bytes([129, len(response)]) + response)
            self.wfile.flush()

    def reply(self, request):
        if request["method"] == "eth_chainId":
            result = "0xaa36a7" if self.path == "/sepolia" else "0x1"
        elif request["method"] == "eth_getCode":
            result = "0x" if self.path == "/no-contracts" else "0x6000"
        else:
            raise ValueError("unexpected JSON-RPC method")
        return json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()

    def do_POST(self):
        if self.path == "/ws-only":
            self.send_response(404)
            self.end_headers()
            return
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        response = self.reply(request)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


server = ThreadingHTTPServer(("127.0.0.1", 0), RpcHandler)
Path(sys.argv[1]).write_text(str(server.server_port))
server.serve_forever()
RPC_FIXTURE
RPC_SERVER_PID=$!
for attempt in $(seq 1 50); do
    [ ! -s "$TEST_ROOT/rpc-port" ] || break
    sleep 0.1
done
[ -s "$TEST_ROOT/rpc-port" ] || fail "RPC fixture did not start"
RPC_FIXTURE_URL="ws://127.0.0.1:$(cat "$TEST_ROOT/rpc-port")"

NODE_SHUTDOWN_DEADLINE_SECS=60
grace_line="$(grep -oE 'stop_grace_period: [0-9]+s' "$ROOT_DIR/docker-compose.yml" | head -1)"
[ -n "$grace_line" ] || fail "docker-compose.yml must declare stop_grace_period"
grace_secs="$(printf '%s' "$grace_line" | grep -oE '[0-9]+')"
[ "$grace_secs" -gt "$NODE_SHUTDOWN_DEADLINE_SECS" ] \
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
        DEPLOYMENT_MANIFEST="$ROOT_DIR/../deployments/manifest.json" \
        DASHBOARD_ENABLED=false \
        NETWORK=mainnet \
        CONFIG_FILE="$case_dir/data/config.yaml" \
        SECRETS_FILE="$case_dir/secrets/secrets.json" \
        PASSWORD_FILE="$case_dir/data/password" \
        WALLET_FILE="$case_dir/data/wallet" \
        CALL_LOG="$case_dir/calls" \
        ARGV_LOG="$case_dir/argv" \
        RPC_URL="$RPC_FIXTURE_URL/mainnet" \
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
[ "$(tr '\n' ' ' < "$success_dir/calls")" = "password wallet wallet-get start " ] || fail "unexpected successful command order"
assert_not_contains "$success_dir/argv" 'correct horse battery staple'
assert_not_contains "$success_dir/argv" '0x1111111111111111111111111111111111111111111111111111111111111111'
assert_contains "$success_dir/data/config.yaml" 'autopassword: false'
assert_contains "$success_dir/data/config.yaml" 'autonetkey: false'
assert_contains "$success_dir/data/config.yaml" 'autowallet: false'
assert_contains "$success_dir/data/config.yaml" 'chain_id: 1'
assert_contains "$success_dir/data/config.yaml" 'slashing_manager:'
assert_contains "$success_dir/data/config.yaml" 'fee_token:'
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
run_entrypoint "$failure_dir"
[ "$(tr '\n' ' ' < "$failure_dir/calls")" = "wallet-get wallet wallet-get start " ] \
    || fail "wallet retry did not resume incomplete provisioning"
[ ! -e "$failure_dir/secrets/secrets.json" ] || fail "retried setup did not remove plaintext credentials"

# Existing state may only be reused with the password that encrypted it.
mismatch_dir="$TEST_ROOT/password-mismatch"
mkdir -p "$mismatch_dir/data" "$mismatch_dir/secrets"
printf '%s' 'different-password' > "$mismatch_dir/data/password"
write_secrets "$mismatch_dir/secrets/secrets.json"
cp "$success_dir/data/config.yaml" "$mismatch_dir/data/config.yaml"
if run_entrypoint "$mismatch_dir"; then
    fail "mismatched persisted password was accepted"
fi
[ ! -s "$mismatch_dir/calls" ] || fail "password mismatch mutated credentials"

# A matching upload on existing state must not rotate either persisted identity.
matching_dir="$TEST_ROOT/password-match"
mkdir -p "$matching_dir/data" "$matching_dir/secrets"
printf '%s' 'correct horse battery staple' > "$matching_dir/data/password"
printf '%s' 'wallet' > "$matching_dir/data/wallet"
write_secrets "$matching_dir/secrets/secrets.json"
cp "$success_dir/data/config.yaml" "$matching_dir/data/config.yaml"
run_entrypoint "$matching_dir"
[ "$(tr '\n' ' ' < "$matching_dir/calls")" = "wallet-get start " ] || fail "matching persisted state was re-provisioned"
[ ! -e "$matching_dir/secrets/secrets.json" ] || fail "matching upload was not removed"

# A saved wallet read failure must not replace either identity with the uploaded key.
write_secrets "$matching_dir/secrets/secrets.json"
if run_entrypoint "$matching_dir" FAIL_ON=wallet-get; then
    fail "unreadable saved identity was accepted"
fi
[ "$(tr '\n' ' ' < "$matching_dir/calls")" = "wallet-get " ] || fail "saved identity read failure re-provisioned credentials"
[ -e "$matching_dir/secrets/secrets.json" ] || fail "saved identity read failure removed recovery input"

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
printf '%s' 'wallet' > "$restart_dir/data/wallet"
cp "$success_dir/data/config.yaml" "$restart_dir/data/config.yaml"
run_entrypoint "$restart_dir"
[ "$(tr '\n' ' ' < "$restart_dir/calls")" = "wallet-get start " ] || fail "persisted restart unexpectedly re-provisioned credentials"

incomplete_restart_dir="$TEST_ROOT/incomplete-restart"
mkdir -p "$incomplete_restart_dir/data"
printf '%s' 'persisted-password' > "$incomplete_restart_dir/data/password"
cp "$success_dir/data/config.yaml" "$incomplete_restart_dir/data/config.yaml"
if run_entrypoint "$incomplete_restart_dir"; then
    fail "password-only state without upload was accepted"
fi
assert_contains "$incomplete_restart_dir/calls" 'wallet-get'
assert_not_contains "$incomplete_restart_dir/calls" 'start'

# Credentials must not be supplied through Docker environment variables.
legacy_dir="$TEST_ROOT/legacy-env"
mkdir -p "$legacy_dir/data"
printf '%s' 'persisted-password' > "$legacy_dir/data/password"
if TEST_PRIVATE_KEY=legacy run_entrypoint "$legacy_dir"; then
    fail "legacy secret environment variable was accepted"
fi

# Passwords may contain ordinary u/0 characters, but never NUL or line breaks.
for password_case in valid-u0 nul cr lf; do
    password_dir="$TEST_ROOT/password-$password_case"
    mkdir -p "$password_dir/secrets"
    write_secrets "$password_dir/secrets/secrets.json"
    python3 - "$password_dir/secrets/secrets.json" "$password_case" <<'CHECK'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
credentials = json.loads(path.read_text())
credentials['password'] = {'valid-u0': 'valid-u0-password', 'nul': 'invalid\x00password', 'cr': 'invalid\rpassword', 'lf': 'invalid\npassword'}[sys.argv[2]]
path.write_text(json.dumps(credentials))
CHECK
    if [ "$password_case" = valid-u0 ]; then
        run_entrypoint "$password_dir" || fail "valid password containing u/0 was rejected"
        [ "$(cat "$password_dir/data/password")" = valid-u0-password ] || fail "password was changed during provisioning"
    else
        if run_entrypoint "$password_dir"; then
            fail "password containing a control character was accepted: $password_case"
        fi
        [ ! -s "$password_dir/calls" ] || fail "invalid password invoked Interfold"
    fi
done

# Presets resolve all deployment fields together and derive the address from the wallet.
for network in mainnet sepolia; do
    preset_dir="$TEST_ROOT/preset-$network"
    mkdir -p "$preset_dir/secrets"
    write_secrets "$preset_dir/secrets/secrets.json"
    run_entrypoint "$preset_dir" NETWORK="$network" RPC_URL="$RPC_FIXTURE_URL/$network"
    python3 - "$preset_dir/data/config.yaml" "$ROOT_DIR/../deployments/manifest.json" "$network" <<'CHECK'
import json, sys, yaml
config = yaml.safe_load(open(sys.argv[1]))
expected = json.load(open(sys.argv[2]))['networks'][sys.argv[3]]
assert config['chains'][0]['chain_id'] == expected['chain_id']
for name in ('interfold', 'ciphernode_registry', 'bonding_registry', 'slashing_manager', 'fee_token'):
    assert config['chains'][0]['contracts'][name] == expected['contracts'][name]
assert config['node']['address'] == '0x3333333333333333333333333333333333333333'
CHECK
done

# Wrong-chain RPCs and missing contracts stop before credential commands or plaintext removal.
for scenario in wrong-chain no-contracts ws-only; do
    rpc_dir="$TEST_ROOT/$scenario"
    mkdir -p "$rpc_dir/secrets"
    write_secrets "$rpc_dir/secrets/secrets.json"
    endpoint="$RPC_FIXTURE_URL/$scenario"
    [ "$scenario" != wrong-chain ] || endpoint="$RPC_FIXTURE_URL/sepolia"
    if run_entrypoint "$rpc_dir" RPC_URL="$endpoint"; then
        fail "invalid RPC was accepted: $scenario"
    fi
    [ ! -s "$rpc_dir/calls" ] || fail "RPC failure invoked credential commands"
    [ -e "$rpc_dir/secrets/secrets.json" ] || fail "RPC failure removed recovery input"
    if [ "$scenario" = ws-only ]; then
        assert_contains "$rpc_dir/output" 'RPC HTTP transport returned HTTP 404'
    fi
done

# A partial backup cannot discard the original network fence.
missing_config_dir="$TEST_ROOT/missing-saved-config"
mkdir -p "$missing_config_dir/data"
printf '%s' 'saved-password' > "$missing_config_dir/data/password"
if run_entrypoint "$missing_config_dir"; then
    fail "existing state without its saved configuration was accepted"
fi
[ ! -s "$missing_config_dir/calls" ] || fail "incomplete backup invoked credential commands"
assert_contains "$missing_config_dir/output" 'restore the complete backup'

# A failed network switch leaves the saved configuration and wallet unchanged.
original_config=$(cksum "$success_dir/data/config.yaml")
if run_entrypoint "$success_dir" NETWORK=sepolia RPC_URL="$RPC_FIXTURE_URL/sepolia"; then
    fail "network switch reused existing state"
fi
[ "$(cksum "$success_dir/data/config.yaml")" = "$original_config" ] || fail "network rejection replaced saved config"
[ ! -s "$success_dir/calls" ] || fail "network rejection changed credentials"

# URL credentials remain a scalar and are absent from startup output.
quoted_dir="$TEST_ROOT/quoted-rpc"
mkdir -p "$quoted_dir/secrets"
write_secrets "$quoted_dir/secrets/secrets.json"
run_entrypoint "$quoted_dir" RPC_URL="ws://user:token'quote@127.0.0.1:$(cat "$TEST_ROOT/rpc-port")/mainnet"
python3 - "$quoted_dir/data/config.yaml" <<'CHECK'
import sys, yaml
config = yaml.safe_load(open(sys.argv[1]))
assert "token'quote@" in config['chains'][0]['rpc_url']
CHECK
assert_not_contains "$quoted_dir/output" "token'quote"

assert_contains "$ROOT_DIR/docker-compose.yml" "UPSTREAM_VERSION: $DAPPNODE_UPSTREAM_VERSION"
assert_contains "$ROOT_DIR/Dockerfile" "ARG UPSTREAM_VERSION=$DAPPNODE_UPSTREAM_VERSION"
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

# Chain ingestion heartbeat: the node writes one file per chain after each successful head read.
# A stale poll, or a head and cursor that stopped moving, is unhealthy; no heartbeat yet is a node
# that is still starting.
mkdir -p "$health_dir/data/log.0" "$health_dir/data/ingestion"
ln -sfn "$health_dir/bin/interfold" "$health_dir/proc/1/exe"
write_heartbeat() {
    printf 'chain_id=1\nhead=%s\ncursor=%s\npolled_at=%s\nprogressed_at=%s\n' \
        "$1" "$2" "$3" "$4" > "$health_dir/data/ingestion/chain-1.heartbeat"
}
run_healthcheck() {
    PROC_ROOT="$health_dir/proc" \
    CONFIG_FILE="$health_dir/data/config.yaml" \
    PASSWORD_FILE="$health_dir/data/password" \
    DB_PATH="$health_dir/data/db" \
    EVENT_LOG_PATH="$health_dir/data/log.0" \
    INGESTION_DIR="$health_dir/data/ingestion" \
    HEALTHCHECK_NOW=1000000 \
    SS_BIN="$health_dir/bin/ss" \
    STAT_BIN="$health_dir/bin/stat" \
    sh "$ROOT_DIR/healthcheck.sh"
}

run_healthcheck || fail "a node without a heartbeat yet was considered unhealthy"

write_heartbeat 500 499 999990 999900
if run_healthcheck; then
    fail "a heartbeat without the ingestion expectation was considered healthy"
fi

# The node writes its expectation before it starts any reader.
printf 'chains=1\nstarted_at=999500\n' > "$health_dir/data/ingestion/expected"
run_healthcheck || fail "a fresh ingestion heartbeat was rejected"

write_heartbeat 500 499 999990 999900
run_healthcheck || fail "a fresh ingestion heartbeat was rejected"

write_heartbeat 500 499 999800 999800
if run_healthcheck; then
    fail "a reader that stopped polling two hundred seconds ago was considered healthy"
fi

write_heartbeat 500 500 999995 999000
if run_healthcheck; then
    fail "a reader that did not progress for a thousand seconds was considered healthy"
fi

printf 'chain_id=1\nhead=500\n' > "$health_dir/data/ingestion/chain-1.heartbeat"
if run_healthcheck; then
    fail "a heartbeat without timestamps was considered healthy"
fi

rm "$health_dir/data/ingestion/chain-1.heartbeat"
run_healthcheck || fail "a removed heartbeat was not treated as a starting node"

# Startup grace: at startup the node records how many chain readers it starts, and when. Within the
# grace (INGESTION_START_GRACE_SECS, 900) a missing heartbeat is a starting node; after it, every
# enabled chain needs one.
write_expected() {
    printf 'chains=%s\nstarted_at=%s\n' "$1" "$2" > "$health_dir/data/ingestion/expected"
}
write_expected 1 999500
run_healthcheck || fail "a node within its startup grace without a heartbeat was considered unhealthy"

write_expected 1 990000
if run_healthcheck; then
    fail "a reader that never reached its first read was considered healthy after the startup grace"
fi

write_heartbeat 500 499 999990 999900
run_healthcheck || fail "a heartbeat for every enabled chain was rejected after the startup grace"

write_expected 2 990000
if run_healthcheck; then
    fail "a second enabled chain without a heartbeat was considered healthy after the startup grace"
fi

printf 'chains=x\nstarted_at=990000\n' > "$health_dir/data/ingestion/expected"
if run_healthcheck; then
    fail "a malformed ingestion expectation was considered healthy"
fi
rm "$health_dir/data/ingestion/expected" "$health_dir/data/ingestion/chain-1.heartbeat"

printf 'PASS: DAppNode credential and health hardening regressions\n'
