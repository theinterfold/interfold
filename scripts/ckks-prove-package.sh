#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Compile + execute + bb write_vk/prove/verify one threshold bin package with
# the node's Recursive variant (`-t noir-recursive`, what the CKKS C6 path
# proves with) and report ACIR size, peak RSS and wall time per stage.
#
# Usage: scripts/ckks-prove-package.sh <package> [<package> ...]
# Env:   VARIANT=noir-recursive|evm|noir-recursive-no-zk (default noir-recursive)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
VARIANT="${VARIANT:-noir-recursive}"
WS="$ROOT/circuits/bin/threshold"
OUT_ROOT="${OUT_ROOT:-/tmp/ckks-proofs}"

stage() { # name cmd...
  local name="$1"; shift
  local t0 t1 rss
  t0=$(date +%s.%N)
  /usr/bin/time -l "$@" > "$OUT/$name.log" 2>&1
  local rc=$?
  t1=$(date +%s.%N)
  rss=$(grep "maximum resident" "$OUT/$name.log" | awk '{print $1}')
  printf '  %-10s rc=%d  %6.1fs  rss=%s MiB\n' "$name" "$rc" "$(echo "$t1 - $t0" | bc)" "$(( ${rss:-0} / 1048576 ))"
  return $rc
}

for PKG in "$@"; do
  OUT="$OUT_ROOT/$PKG"; mkdir -p "$OUT"
  echo "== $PKG ($VARIANT)"
  stage compile nargo compile --package "$PKG" || { echo "  compile FAILED (see $OUT/compile.log)"; continue; }
  (cd "$WS" && nargo info --package "$PKG" 2>/dev/null | grep -E "^\| $PKG" | head -1 | sed 's/^/  /')
  stage execute nargo execute --package "$PKG" || { echo "  execute FAILED"; continue; }
  JSON="$WS/target/$PKG.json"; WIT="$WS/target/$PKG.gz"
  stage write_vk bb write_vk -b "$JSON" -o "$OUT" -t "$VARIANT" || continue
  stage prove bb prove -b "$JSON" -w "$WIT" -k "$OUT/vk" -o "$OUT" -t "$VARIANT" || continue
  stage verify bb verify -p "$OUT/proof" -k "$OUT/vk" -i "$OUT/public_inputs" -t "$VARIANT" || continue
  echo "  proof: $(wc -c < "$OUT/proof") bytes; public_inputs: $(wc -c < "$OUT/public_inputs") bytes"
done
