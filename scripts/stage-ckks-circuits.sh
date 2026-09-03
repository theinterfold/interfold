#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Stage the CKKS committee-side proof circuits into the node artifact dir so
# a ciphernode running a CKKS E3 (ParamSet 0/2/3) resolves every artifact the
# fail-closed posture requires (crates/zk-prover/src/ckks_artifacts.rs):
#
#   <circuits>/insecure-512/<committee>/recursive/threshold/<name>/<name>.{json,vk}
#     pk_generation_ckks_ps{0,2,3}            C1-CKKS
#     share_decryption_ckks[_ps2|_ps3]        C6-CKKS
#     relin_round1_hybrid_ckks_digit          C8-CKKS (hybrid plans; from the ps2 package)
#   <circuits>/insecure-512/<committee>/default/threshold/<name>/<name>.{json,vk}
#     decrypted_shares_aggregation_ckks[_ps2|_ps3]   C7-CKKS
#   <circuits>/insecure-dkg-wide-512/<committee>/recursive/dkg/pk/pk.{json,vk}
#     C0 over the wide DKG transport (ParamSet 2)
#
# The CKKS circuits do not depend on the committee size, so the same
# artifacts are linked into every committee dir found under insecure-512/.
# The wide C0 is the BFV `pk` circuit built with the wide preset config;
# `pnpm build:circuits --preset insecure-dkg-wide-512` produces it when the
# plain copy below cannot find a prebuilt one.
#
# Usage: scripts/stage-ckks-circuits.sh [<circuits-dir>]
#   default <circuits-dir> = tests/integration/.interfold/noir/circuits
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUITS_DIR="${1:-$ROOT/tests/integration/.interfold/noir/circuits}"
BIN="$ROOT/circuits/bin/threshold"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"

RECURSIVE=(pk_generation_ckks_ps0 pk_generation_ckks_ps2 pk_generation_ckks_ps3
  share_decryption_ckks share_decryption_ckks_ps2 share_decryption_ckks_ps3)
DEFAULT=(decrypted_shares_aggregation_ckks decrypted_shares_aggregation_ckks_ps2
  decrypted_shares_aggregation_ckks_ps3)
# package -> staged name
C8_PKG=relin_round1_hybrid_ckks_digit_ps2
C8_NAME=relin_round1_hybrid_ckks_digit

build_one() { # <package> <variant: recursive|default>
  local pkg="$1" variant="$2" json="$BIN/target/$1.json" out="$BIN/target/stage-$1-$2"
  if [ ! -f "$json" ]; then
    echo "[stage] nargo compile --package $pkg"
    (cd "$BIN" && nargo compile --package "$pkg" --silence-warnings)
  fi
  mkdir -p "$out"
  if [ ! -f "$out/vk" ]; then
    local target=noir-recursive
    [ "$variant" = default ] && target=noir-recursive-no-zk
    echo "[stage] bb write_vk -t $target $pkg"
    bb write_vk -b "$json" -o "$out" -t "$target" >/dev/null
  fi
}

stage_into() { # <package> <staged-name> <variant> <committee-dir>
  local pkg="$1" name="$2" variant="$3" dest="$4/$3/threshold/$2"
  mkdir -p "$dest"
  cp "$BIN/target/$pkg.json" "$dest/$name.json"
  cp "$BIN/target/stage-$pkg-$variant/vk" "$dest/$name.vk"
  cp "$BIN/target/stage-$pkg-$variant/vk_hash" "$dest/$name.vk_hash" 2>/dev/null || true
}

for p in "${RECURSIVE[@]}"; do build_one "$p" recursive; done
for p in "${DEFAULT[@]}"; do build_one "$p" default; done
build_one "$C8_PKG" recursive

COMMITTEES=()
while IFS= read -r d; do COMMITTEES+=("$(basename "$d")"); done < <(find "$CIRCUITS_DIR/insecure-512" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
if [ "${#COMMITTEES[@]}" -eq 0 ]; then
  echo "no committee dirs under $CIRCUITS_DIR/insecure-512 — run pnpm build:circuits first" >&2
  exit 1
fi
for c in "${COMMITTEES[@]}"; do
  base="$CIRCUITS_DIR/insecure-512/$c"
  for p in "${RECURSIVE[@]}"; do stage_into "$p" "$p" recursive "$base"; done
  for p in "${DEFAULT[@]}"; do stage_into "$p" "$p" default "$base"; done
  stage_into "$C8_PKG" "$C8_NAME" recursive "$base"
  echo "[stage] insecure-512/$c: ${#RECURSIVE[@]}+${#DEFAULT[@]}+1 CKKS circuits"
done

# C0 over the wide DKG transport: the BFV `pk` circuit at the wide shape.
WIDE="$CIRCUITS_DIR/insecure-dkg-wide-512"
if [ ! -d "$WIDE" ]; then
  echo "[stage] wide C0 missing — pnpm build:circuits --preset insecure-dkg-wide-512 --group dkg --circuit pk --committee all (no-clean; ~1-3 min)"
  (cd "$ROOT" && pnpm build:circuits --preset insecure-dkg-wide-512 --group dkg --circuit pk --committee all \
      --no-clean --no-clean-targets --skip-utils-patch --skip-checksums -o "$CIRCUITS_DIR") \
    || { echo "wide C0 build failed — see scripts/build-circuits.ts --help" >&2; exit 1; }
fi
for c in "${COMMITTEES[@]}"; do
  [ -f "$WIDE/$c/recursive/dkg/pk/pk.json" ] && echo "[stage] wide C0 present for $c" || echo "[stage] WARN: wide C0 missing for $c under $WIDE" >&2
done
echo "[stage] done: $CIRCUITS_DIR"
exit 0
