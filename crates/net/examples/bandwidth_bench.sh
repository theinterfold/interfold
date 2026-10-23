#!/usr/bin/env bash
# Run the bandwidth benchmark: one bandwidth_bench node per container on one Docker bridge, with
# the uplink of each container shaped by tc (HTB rate, netem delay). Debian or Ubuntu hosts with
# Docker only; the containers need NET_ADMIN, the host user needs no sudo.
#
#   cargo build --release -p e3-net --example bandwidth_bench
#   crates/net/examples/bandwidth_bench.sh <output directory>
#
# Settings (environment):
#   PEERS          nodes in the network (default 30). Use more than 21, so that a DHT put reaches
#                  20 of the peers and not all of them, as on mainnet.
#   COMMITTEE      the first COMMITTEE nodes are members and dealers (default 19)
#   C0_BYTES       size of each member's encryption key (C0) document, sent to all members
#                  (default 152633, as on E3-2; 0 sends none)
#   SHARE_BYTES    size of each threshold-share document, one to each other member (default
#                  1776213, as on E3-2; 0 sends none)
#   MBIT           uplink of every node in Mbit/s (default 100)
#   COMMITTEE_MBIT uplink of every member, if set
#   SLOW           per-node uplinks, <index>=<Mbit/s>,... (applied last)
#   DELAY_MS       one-way delay that each uplink adds (default 20)
#   QUEUE_MS       queue of each uplink, in ms at its rate (default 200)
#   DIAL           peers that each node dials at start (default 4); discovery finds the rest
#   WARMUP_SECS    time to connect before the dealers publish (default 60)
#   DEADLINE_SECS  time after the start at which every node stops (default 1800)
#   HOLD           1 runs every node to the deadline, also after every member has every document,
#                  to measure the refreshes of a DKG that lasts longer (default 0)
#   BIN            the bandwidth_bench binary (default target/release/examples/bandwidth_bench)
#   BASE_IMAGE     runtime image with the host's C library, Debian or Ubuntu (default: the host's
#                  distribution)
set -euo pipefail

OUT=${1:?usage: bandwidth_bench.sh <output directory>}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
PEERS=${PEERS:-30}
COMMITTEE=${COMMITTEE:-19}
C0_BYTES=${C0_BYTES:-152633}
SHARE_BYTES=${SHARE_BYTES:-1776213}
MBIT=${MBIT:-100}
COMMITTEE_MBIT=${COMMITTEE_MBIT:-}
SLOW=${SLOW:-}
DELAY_MS=${DELAY_MS:-20}
QUEUE_MS=${QUEUE_MS:-200}
DIAL=${DIAL:-4}
WARMUP_SECS=${WARMUP_SECS:-60}
DEADLINE_SECS=${DEADLINE_SECS:-1800}
HOLD=${HOLD:-0}
BIN=${BIN:-$ROOT/target/release/examples/bandwidth_bench}
BASE_IMAGE=${BASE_IMAGE:-$(. /etc/os-release && echo "$ID:$VERSION_ID")}
PROJECT=bwbench

# The runtime image installs tc with apt-get.
case "$BASE_IMAGE" in
  debian:* | ubuntu:*) ;;
  *)
    echo "BASE_IMAGE ($BASE_IMAGE) must be a Debian or Ubuntu image with the host's C library" >&2
    exit 1
    ;;
esac
if ((COMMITTEE > PEERS)); then
  echo "COMMITTEE ($COMMITTEE) is larger than PEERS ($PEERS)" >&2
  exit 1
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
if compgen -G "$OUT/node-*.json" >/dev/null || compgen -G "$OUT/done-*" >/dev/null; then
  echo "$OUT holds the results of another run" >&2
  exit 1
fi

# The runtime image: the binary on the host's distribution, with iproute2 for tc.
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
cp "$BIN" "$BUILD/bandwidth_bench"
cat >"$BUILD/Dockerfile" <<EOF
FROM $BASE_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \\
    && rm -rf /var/lib/apt/lists/*
COPY bandwidth_bench /app/bandwidth_bench
EOF
docker build -q -t bandwidth_bench:local "$BUILD" >/dev/null

declare -a RATE
for ((i = 0; i < PEERS; i++)); do
  RATE[i]=$MBIT
  if [[ -n "$COMMITTEE_MBIT" ]] && ((i < COMMITTEE)); then
    RATE[i]=$COMMITTEE_MBIT
  fi
done
IFS=',' read -ra OVERRIDES <<<"$SLOW"
for override in "${OVERRIDES[@]}"; do
  [[ -z "$override" ]] && continue
  RATE[${override%%=*}]=${override#*=}
done

START_AT_MS=$((($(date +%s) + WARMUP_SECS) * 1000))
COMPOSE="$OUT/compose.yaml"
{
  echo "name: $PROJECT"
  echo "services:"
  for ((i = 0; i < PEERS; i++)); do
    dial=()
    # Peers spread over the network, so that no node is a hub.
    for ((d = 0; d < DIAL; d++)); do
      peer=$(((i + 1 + 6 * d) % PEERS))
      if ((peer != i)) && [[ " ${dial[*]} " != *"/node$peer/"* ]]; then
        dial+=("/dns4/node$peer/udp/9091/quic-v1")
      fi
    done
    dial_list=$(IFS=','; echo "${dial[*]}")
    cat <<EOF
  node$i:
    image: bandwidth_bench:local
    cap_add: [NET_ADMIN]
    networks: [bench]
    volumes: ["$OUT:/out"]
    environment:
      BENCH_INDEX: "$i"
      BENCH_COMMITTEE: "$COMMITTEE"
      BENCH_DIAL: "$dial_list"
      BENCH_START_AT_MS: "$START_AT_MS"
      BENCH_DEADLINE_SECS: "$DEADLINE_SECS"
      BENCH_HOLD: "$HOLD"
      BENCH_OUT: /out
      BENCH_C0_BYTES: "$C0_BYTES"
      BENCH_SHARE_BYTES: "$SHARE_BYTES"
      BENCH_UPLINK_MBIT: "${RATE[i]}"
      RUST_LOG: "info,libp2p_gossipsub=error"
    command:
      - sh
      - -ec
      - |
        kbit=\$\$(awk "BEGIN { print int(${RATE[i]} * 1000) }")
        limit=\$\$(awk "BEGIN { print int(${RATE[i]} * 1e6 / 8 * ($DELAY_MS + $QUEUE_MS) / 1000 / 1500) + 50 }")
        tc qdisc add dev eth0 root handle 1: htb default 10
        tc class add dev eth0 parent 1: classid 1:10 htb rate \$\${kbit}kbit ceil \$\${kbit}kbit
        tc qdisc add dev eth0 parent 1:10 handle 10: netem delay ${DELAY_MS}ms limit \$\$limit
        exec setpriv --reuid=$(id -u) --regid=$(id -g) --clear-groups /app/bandwidth_bench
EOF
  done
  echo "networks:"
  echo "  bench:"
  echo "    driver: bridge"
} >"$COMPOSE"

cleanup() {
  docker compose -f "$COMPOSE" logs --no-color --timestamps >"$OUT/logs.txt" 2>&1 || true
  docker compose -f "$COMPOSE" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

cat >"$OUT/settings.env" <<EOF
PEERS=$PEERS
COMMITTEE=$COMMITTEE
C0_BYTES=$C0_BYTES
SHARE_BYTES=$SHARE_BYTES
MBIT=$MBIT
COMMITTEE_MBIT=$COMMITTEE_MBIT
SLOW=$SLOW
DELAY_MS=$DELAY_MS
QUEUE_MS=$QUEUE_MS
DIAL=$DIAL
WARMUP_SECS=$WARMUP_SECS
DEADLINE_SECS=$DEADLINE_SECS
HOLD=$HOLD
START_AT_MS=$START_AT_MS
EOF

docker compose -f "$COMPOSE" up --detach --quiet-pull
mapfile -t SERVICES < <(seq -f 'node%g' 0 $((PEERS - 1)))
docker compose -f "$COMPOSE" wait "${SERVICES[@]}" >/dev/null || true
failed=$(docker compose -f "$COMPOSE" ps --all --format '{{.Service}} {{.ExitCode}}' | awk '$2 != 0')
if [[ -n "$failed" ]]; then
  echo "nodes that failed: $failed" >&2
fi
"$BIN" summarize "$OUT" | tee "$OUT/summary.txt"
