#!/bin/bash
# Test the built packages with the real entrypoint and binary on a DAppNode-like network. Only
# `interfold start` is replaced: it keeps the container running instead of starting the node.
# Build first: npm run build --prefix dappnode -- --skip_upload --skip_save
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(node -p "require('$ROOT_DIR/dappnode_package.json').version")
image() {
    printf 'ciphernode.%s:%s' "$(node -p "require('$ROOT_DIR/package_variants/$1/dappnode_package.json').name")" "$VERSION"
}
MAINNET_IMAGE=$(image mainnet)
SEPOLIA_IMAGE=$(image sepolia)
NAME="interfold-dappnode-test-$$"
CLIENT_ALIAS=execution.mainnet.dncore.dappnode
FIXTURES=$(mktemp -d)

cleanup() {
    docker rm -f "$NAME-client" "$NAME-node" >/dev/null 2>&1 || true
    docker volume rm "$NAME-data" >/dev/null 2>&1 || true
    docker network rm "$NAME" >/dev/null 2>&1 || true
    rm -rf "$FIXTURES"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    docker logs "$NAME-node" 2>&1 | tail -n 20 >&2 || true
    exit 1
}

[ "$(docker run --rm --entrypoint cat "$SEPOLIA_IMAGE" /opt/package-network)" = sepolia ] \
    || fail "the Sepolia package image does not select Sepolia"

mkdir -p "$FIXTURES/bin"
printf '%s\n' \
    '#!/bin/sh' \
    'for arg in "$@"; do [ "$arg" != start ] || exec sleep infinity; done' \
    'exec /usr/local/bin/interfold "$@"' \
    > "$FIXTURES/bin/interfold"

# An execution client like DAppNode's: HTTP JSON-RPC only on 8545, WebSocket JSON-RPC only on 8546.
cat > "$FIXTURES/client.py" <<'CLIENT'
import base64
import hashlib
import json
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESULTS = {"eth_chainId": "0x1", "eth_getCode": "0x6000", "web3_clientVersion": sys.argv[1]}


def answer(payload):
    request = json.loads(payload)
    return json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": RESULTS[request["method"]]}).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reject(self):
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.server.server_port != 8545:
            return self.reject()
        body = answer(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        key = self.headers.get("Sec-WebSocket-Key")
        if self.server.server_port != 8546 or not key:
            return self.reject()
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        while True:
            header = self.rfile.read(2)
            if len(header) < 2 or header[0] & 15 == 8:
                return
            length = header[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.rfile.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.rfile.read(8))[0]
            mask = self.rfile.read(4)
            reply = answer(bytes(value ^ mask[index % 4] for index, value in enumerate(self.rfile.read(length))))
            self.wfile.write(bytes([129, len(reply)]) + reply)
            self.wfile.flush()


for port in (8545, 8546):
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
CLIENT

# Ask the node's RPC proxy which client answers each transport.
cat > "$FIXTURES/probe.py" <<'PROBE'
import json
import urllib.request

import websocket

REQUEST = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "web3_clientVersion", "params": []})


def http():
    request = urllib.request.Request(
        "http://127.0.0.1:8550", data=REQUEST.encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)["result"]


def ws():
    connection = websocket.create_connection("ws://127.0.0.1:8550", timeout=10, suppress_origin=True)
    try:
        connection.send(REQUEST)
        return json.loads(connection.recv())["result"]
    finally:
        connection.close()


answers = []
for transport in (http, ws):
    try:
        answers.append(transport())
    except Exception as error:
        answers.append(type(error).__name__)
print(" ".join(answers))
PROBE
chmod -R a+rX "$FIXTURES"
chmod a+x "$FIXTURES/bin/interfold"

start_client() {
    docker run -d --name "$NAME-client" --network "$NAME" --ip "$1" --network-alias "$CLIENT_ALIAS" \
        -v "$FIXTURES:/fixtures:ro" --entrypoint python3 "$MAINNET_IMAGE" /fixtures/client.py "$2" >/dev/null
    local deadline=$((SECONDS + 30))
    until docker exec "$NAME-client" python3 -c \
        'import socket; [socket.create_connection(("127.0.0.1", port), 1).close() for port in (8545, 8546)]' 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || fail "the test execution client did not start"
        sleep 1
    done
}

docker network create --subnet 10.231.0.0/24 "$NAME" >/dev/null
start_client 10.231.0.10 client-1
docker volume create "$NAME-data" >/dev/null
docker run --rm -v "$NAME-data:/data" --entrypoint sh "$MAINNET_IMAGE" -c \
    'printf "%s" "{\"password\":\"image test password\",\"private_key\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}" > /data/secrets.json'
docker run -d --name "$NAME-node" --network "$NAME" -v "$NAME-data:/data" -v "$FIXTURES:/fixtures:ro" \
    -e PATH=/fixtures/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -e RPC_URL="ws://$CLIENT_ALIAS:8546" -e DASHBOARD_ENABLED=false \
    --security-opt no-new-privileges:true "$MAINNET_IMAGE" >/dev/null

deadline=$((SECONDS + 90))
until docker logs "$NAME-node" 2>&1 | grep -q 'Starting Interfold ciphernode'; do
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME-node")" = true ] || fail "the entrypoint stopped"
    [ "$SECONDS" -lt "$deadline" ] || fail "the entrypoint did not reach the node start"
    sleep 1
done

probe() { docker exec "$NAME-node" python3 /fixtures/probe.py; }
answers=$(probe) || fail "could not query the RPC proxy"
[ "$answers" = "client-1 client-1" ] || fail "the RPC proxy did not route HTTP and WebSocket: $answers"

# A client update or another client in Stakers keeps the alias but can change the address.
docker rm -f "$NAME-client" >/dev/null
start_client 10.231.0.20 client-2
deadline=$((SECONDS + 30))
until answers=$(probe) && [ "$answers" = "client-2 client-2" ]; do
    [ "$SECONDS" -lt "$deadline" ] || fail "the RPC proxy did not follow the client to its new address: $answers"
    sleep 1
done

printf 'PASS: DAppNode images, provisioning, and RPC proxy\n'
