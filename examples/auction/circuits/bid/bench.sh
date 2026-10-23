#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Generates, executes, and counts the gates of one bid proof configuration in a scratch package.
#
# Usage (from examples/auction):
#   circuits/bid/bench.sh <tiny|toy|mid|demo> <vickrey|compact> <ntt|table|sparse> <bidders> <levels> [bid]
#
# Environment:
#   BENCH_DIR   scratch root (default: /tmp/bid-bench)
#   PROVE=1     also run `bb prove` and `bb verify`; report seconds and peak memory
#   CASES=1     also run the tampered cases; each one must fail
set -euo pipefail

params=$1 variant=$2 strategy=$3 bidders=$4 levels=$5 bid=${6:-5}
root=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$root/../.." && pwd)
name="$params-$variant-$strategy-n$bidders-B$levels"
dir="${BENCH_DIR:-/tmp/bid-bench}/$name"
nargo=${NARGO:-$HOME/.nargo/bin/nargo}
bb=${BB:-$HOME/.bb/bb}

rm -rf "$dir"
mkdir -p "$dir/src"
cp "$root/$strategy/src/main.nr" "$dir/src/main.nr"
sed "s#path = \"../lib\"#path = \"$root/lib\"#" "$root/$strategy/Nargo.toml" >"$dir/Nargo.toml"

(cd "$crate" && cargo run --release --quiet --bin bid_circuit -- \
  --params "$params" --bidders "$bidders" --levels "$levels" --variant "$variant" \
  --strategy "$strategy" --bid "$bid" --out-dir "$dir" ${CASES:+--cases}) >/dev/null

cd "$dir"
start=$(date +%s)
"$nargo" execute >/dev/null
echo "$name: execute ok ($(($(date +%s) - start)) s incl. compile)"

gates=$("$bb" gates -b "target/bid_$strategy.json" 2>/dev/null | grep -E 'circuit_size|acir_opcodes' | tr -d ' \n')
echo "$name: $gates"

if [ -n "${CASES:-}" ]; then
  for case in bid-plus-one non-thermometer mismatched-pair bid-out-of-range; do
    [ -f "Prover_$case.toml" ] || continue
    if "$nargo" execute --prover-name "Prover_$case" >/dev/null 2>"$dir/$case.err"; then
      echo "$name: case $case UNEXPECTEDLY EXECUTED"
      exit 1
    fi
    echo "$name: case $case fails ($(grep -m1 -E 'Failed|Cannot' "$dir/$case.err" | tr -s ' '))"
  done
fi

if [ -n "${PROVE:-}" ]; then
  "$bb" write_vk -b "target/bid_$strategy.json" -o target --verifier_target noir-recursive >/dev/null 2>&1
  /usr/bin/time -l "$bb" prove -b "target/bid_$strategy.json" -w "target/bid_$strategy.gz" \
    -k target/vk -o target --verifier_target noir-recursive 2>"$dir/prove.time" >/dev/null
  awk '/maximum resident/ {printf "%s: peak RSS %.2f GiB\n", "'"$name"'", $1/1073741824}' "$dir/prove.time"
  awk '/ real / {print "'"$name"': prove wall " $1 " s"}' "$dir/prove.time"
  "$bb" verify -k target/vk -p target/proof -i target/public_inputs --verifier_target noir-recursive 2>&1 |
    grep -o "Proof verified successfully" | sed "s/^/$name: /"
fi
