#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Render DAppNode configuration and check both RPC transports before provisioning."""

import json
import base64
import os
from contextlib import closing
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import websocket
import yaml


class ConfigurationError(Exception):
    """An operator-facing message that contains no RPC credentials."""


def render():
    network = os.environ["NETWORK"]
    if network not in ("mainnet", "sepolia"):
        raise ConfigurationError("install the Mainnet or Sepolia package")
    manifest = json.loads(Path(os.environ.get("DEPLOYMENT_MANIFEST", "/opt/deployments.json")).read_text())
    if manifest["schema_version"] != 1:
        raise ConfigurationError("unsupported deployment manifest schema")
    preset = manifest["networks"][network]
    avail_url = os.environ.get("AVAIL_RPC_URL") or {
        "mainnet": "https://avail-rpc.publicnode.com/",
        "sepolia": "https://turing-rpc.avail.so/rpc",
    }[network]
    if not re.fullmatch(r"https?://[^\s]+", avail_url):
        raise ConfigurationError("AVAIL_RPC_URL must be an HTTP URL (http:// or https://)")
    rpc_url = os.environ.get("RPC_URL", "")
    if not re.fullmatch(r"wss?://[^\s]+", rpc_url):
        raise ConfigurationError("RPC_URL must be a WebSocket URL (ws:// or wss://)")
    port = os.environ["QUIC_PORT"]
    if not re.fullmatch(r"[0-9]+", port) or not 1 <= int(port) <= 65535:
        raise ConfigurationError("QUIC_PORT must be between 1 and 65535")
    # Build YAML from values directly so URLs with credentials remain strings.
    config = {
        "node": {
            "network": network,
            "address": os.environ["NODE_ADDRESS"],
            "quic_port": int(port),
            # A missing identity must not cause the node to generate another one.
            "autonetkey": False,
            "autopassword": False,
            "autowallet": False,
        },
        "chains": [{
            "name": network,
            "rpc_url": rpc_url,
            "chain_id": preset["chain_id"],
            "data_availability": {"mode": "avail", "rpc_url": avail_url},
            "contracts": {name: preset["contracts"][name] for name in (
                "interfold", "ciphernode_registry", "bonding_registry", "slashing_manager", "fee_token"
            )},
        }],
    }
    if os.environ.get("DASHBOARD_ENABLED", "false") == "true":
        config["node"]["dashboard_port"] = 8080
    saved = Path(os.environ["SAVED_CONFIG_FILE"])
    state = Path(os.environ["CURRENT_STATE_DIR"])
    has_state = Path(os.environ["PASSWORD_FILE"]).exists() or (state / "data").exists()
    if has_state and not saved.exists():
        raise ConfigurationError("saved configuration is missing for existing state; restore the complete backup")
    if has_state:
        previous = yaml.safe_load(saved.read_text())
        if (previous["node"]["network"] != network
                or previous["chains"][0]["chain_id"] != preset["chain_id"]):
            raise ConfigurationError("network change refused for existing state; restore the original network or use a separate data volume")
    Path(os.environ["CONFIG_FILE"]).write_text(yaml.safe_dump(config, sort_keys=False))


def http_url(rpc_url):
    """Return the URL of the node's HTTP signer: only the WebSocket scheme changes."""
    scheme, rest = rpc_url.split("://", 1)
    return {"ws": "http", "wss": "https"}[scheme] + "://" + rest


def check_rpc():
    config = yaml.safe_load(Path(os.environ["CONFIG_FILE"]).read_text())
    chain = config["chains"][0]
    # WebSocket requests share one connection; both transports share a deadline. Do not print the URL.
    deadline = time.monotonic() + 20
    # The node sends no Origin header. Endpoints that restrict origins would reject this check.
    with closing(websocket.create_connection(chain["rpc_url"], timeout=10, suppress_origin=True)) as connection:
        def request(method, params, request_id):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConfigurationError("RPC check timed out; check endpoint access")
            connection.settimeout(remaining)
            connection.send(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}))
            reply = json.loads(connection.recv())
            if reply.get("id") != request_id or "error" in reply or "result" not in reply:
                raise ConfigurationError(f"RPC rejected {method}; check endpoint access and permissions")
            return reply["result"]

        actual = int(request("eth_chainId", [], 1), 16)
        if actual != chain["chain_id"]:
            raise ConfigurationError(f"RPC chain ID is {actual}; expected {chain['chain_id']}")
        for index, (contract, definition) in enumerate(chain["contracts"].items(), 2):
            code = request("eth_getCode", [definition["address"], "latest"], index)
            if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", code):
                raise ConfigurationError(f"no contract code at {contract}; check the deployment overrides")

    endpoint = http_url(chain["rpc_url"])
    parsed = urlsplit(endpoint)
    headers = {"Content-Type": "application/json"}
    if parsed.username is not None:
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
        endpoint = urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[1], parsed.path, parsed.query, parsed.fragment))
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ConfigurationError("RPC check timed out; check endpoint access")
    try:
        with urlopen(Request(endpoint, data=payload, headers=headers), timeout=remaining) as response:
            reply = json.load(response)
    except HTTPError as error:
        raise ConfigurationError(
            f"RPC HTTP transport returned HTTP {error.code}; the endpoint must serve HTTP and WebSocket at the same address"
        ) from None
    if reply.get("id") != 1 or "error" in reply or "result" not in reply:
        raise ConfigurationError("RPC rejected the HTTP chain check; check endpoint access")
    if int(reply["result"], 16) != chain["chain_id"]:
        raise ConfigurationError("HTTP and WebSocket RPC chain IDs do not match")


if __name__ == "__main__":
    try:
        {"render": render, "check-rpc": check_rpc}[sys.argv[1]]()
    except ConfigurationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Library errors can include RPC tokens, headers, or malformed credential URLs.
        print("ERROR: configuration or RPC check failed; check endpoint access and package settings", file=sys.stderr)
        sys.exit(1)
