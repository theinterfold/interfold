#!/usr/bin/env bash
# Compile the bid circuits, write their Solidity verifiers, and compute the VK anchors the program
# contract pins.
#
# A bid is a tree of four circuits, each below 2^21 gates so that a browser can prove it (the WASM
# heap is 4 GiB):
#   auction_bid_pair    the proofs of the roles 0 and 1, and the bid itself  (recursive proof)
#   auction_bid_masks   the proofs of the roles 2 and 3, the pair mask        (recursive proof, type 3)
#   auction_bid3        the pair proof and the proof of role 2  (EVM verifier AuctionVerifier3)
#   auction_bid4        the pair proof and the masks proof      (EVM verifier AuctionVerifier4)
#
# Each anchor covers the Interfold user-data encryption tree as the SDK bundles it for the insecure
# SIMD preset (the key hash of the wrapper and the two per-leg chains) and the inner circuits of its
# bid tree. `auction_bid3` returns `vkAnchor3` and `auction_bid4` returns `vkAnchor4` as `vk_anchor`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
CIRCUITS="$ROOT/circuits"
UDE="$REPO/packages/interfold-sdk/circuits/dist/insecure-simd"
VK="$CIRCUITS/target/vk"
VERIFIERS="$ROOT/contracts/verifiers"
ANCHOR="$CIRCUITS/target/vk_anchor.json"

[[ -f "$UDE/user_data_encryption_chunked.json" ]] || {
  echo "missing $UDE (run pnpm sdk:build in the repository root; it needs the insecure-simd circuits from pnpm build:circuits --preset insecure-simd)" >&2
  exit 1
}

rm -rf "$VK"
mkdir -p "$VK" "$VERIFIERS"

# Write the VK hash `bb` derives for `circuit` under `target` into its own directory.
write_vk() {
  local circuit="$1" target="$2" name
  name="$(basename "$circuit" .json)"
  mkdir -p "$VK/$name"
  bb write_vk -b "$circuit" -o "$VK/$name" -t "$target" >/dev/null
}

vk_hash() {
  cargo run --quiet --release --manifest-path "$ROOT/Cargo.toml" -p e3-user-program --example vk_hash -- "$@"
}

to_file() {
  local hex="${1#0x}"
  printf '%064s' "$hex" | tr ' ' '0' | xxd -r -p >"$2"
}

echo "Compiling the bid circuits..."
for dir in pair masks bid3 bid4; do
  (cd "$CIRCUITS/$dir" && nargo compile)
done

echo "Writing recursive VKs..."
# The targets match `proveUserDataEncryptionTree`: ZK for the circuits whose witness holds the
# plaintext or the encryption randomness (the leaves, the pk/ct commitments, the identity circuits
# and the ct0 top level), no-ZK for the circuits that only fold proofs.
for name in ct0_chunk_main ct0_pk_ct_commit ct0_eval_chunk_identity user_data_encryption_ct0_chunked \
  ct1_chunk_main ct1_pk_ct_commit ct1_eval_chunk_identity; do
  write_vk "$UDE/$name.json" noir-recursive
done
for name in user_data_encryption_ct1_chunked user_data_encryption_chunked; do
  write_vk "$UDE/$name.json" noir-recursive-no-zk
done
# The bid tree's inner circuits only fold proofs.
write_vk "$CIRCUITS/pair/target/auction_bid_pair.json" noir-recursive-no-zk
write_vk "$CIRCUITS/masks/target/auction_bid_masks.json" noir-recursive-no-zk

echo "Computing the VK anchor..."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# One leg's chain: its top-level key hash, then the manifest of its leaf circuits in
# `compute_ude_vk_manifest` order: identity, leaf, pk/ct.
leg_chain() {
  local ct="$1" manifest
  manifest="$(vk_hash \
    "$VK/${ct}_eval_chunk_identity/vk_hash" "$VK/${ct}_chunk_main/vk_hash" \
    "$VK/${ct}_pk_ct_commit/vk_hash")"
  to_file "$manifest" "$TMP/${ct}_manifest"
  vk_hash "$VK/user_data_encryption_${ct}_chunked/vk_hash" "$TMP/${ct}_manifest"
}
to_file "$(leg_chain ct0)" "$TMP/ct0_chain"
to_file "$(leg_chain ct1)" "$TMP/ct1_chain"
ude="$VK/user_data_encryption_chunked/vk_hash"
anchor3="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash")"
anchor4="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash" "$VK/auction_bid_masks/vk_hash")"
printf '{\n  "vkAnchor3": "%s",\n  "vkAnchor4": "%s"\n}\n' "$anchor3" "$anchor4" >"$ANCHOR"
echo "VK anchors: $anchor3 (3 roles), $anchor4 (4 roles)"

# `bb` writes every verifier with the same top-level names (`Fr`, `Honk`, `HonkVerifier`, ...), which
# collide when two are in one project. Suffix each top-level identifier with `$2`, and name the
# verifier contract `AuctionVerifier$2`. The libraries (`ZKTranscriptLib$2`, `RelationsLib$2`) are
# linked on deployment. In an `assembly` block `add`, `sub` and `mul` are the EVM opcodes, so they
# keep their names there.
suffix_verifier() {
  local source="$1" suffix="$2" names
  names="$(perl -ne '
    print "$1\n" if /^(?:abstract\s+)?(?:contract|library|interface|struct|enum)\s+(\w+)/
      || /^type\s+(\w+)\s+is/ || /^function\s+(\w+)/ || /^error\s+(\w+)/
      || /^[\w.\[\]]+\s+constant\s+(\w+)/;
  ' "$source" | sort -u | grep -vx HonkVerifier | paste -sd'|' -)"
  NAMES="$names" SUFFIX="$suffix" perl -e '
    my ($names, $suffix, $depth) = ($ENV{NAMES}, $ENV{SUFFIX}, 0);
    (my $yul = $names) =~ s/\b(?:add|sub|mul)\b\|?//g;
    $yul =~ s/\|$//;
    while (<>) {
      my $in_asm = $depth > 0 || /\bassembly\b/;
      my $re = $in_asm ? $yul : $names;
      s/(?<![\w\$])(?:($re)|HonkVerifier)(?!\w)/defined($1) ? "$1$suffix" : "AuctionVerifier$suffix"/ge;
      if ($in_asm) {
        my $tail = /\bassembly\b/ ? substr($_, index($_, "assembly")) : $_;
        $depth += () = $tail =~ /\{/g;
        $depth -= () = $tail =~ /\}/g;
      }
      print;
    }
  ' "$source"
}

for n in 3 4; do
  echo "Writing the Solidity verifier of auction_bid$n..."
  mkdir -p "$VK/auction_bid$n"
  bb write_vk -b "$CIRCUITS/bid$n/target/auction_bid$n.json" -o "$VK/auction_bid$n" -t evm >/dev/null
  bb write_solidity_verifier -k "$VK/auction_bid$n/vk" -o "$TMP/verifier$n.sol" -t evm >/dev/null
  {
    printf '%s\n' \
      '// SPDX-License-Identifier: LGPL-3.0-only' \
      '//' \
      '// This file is provided WITHOUT ANY WARRANTY;' \
      '// without even the implied warranty of MERCHANTABILITY' \
      '// or FITNESS FOR A PARTICULAR PURPOSE.' \
      '//' \
      "// Generated by scripts/compile_circuits.sh from circuits/bid$n. Do not edit."
    tail -n +3 "$TMP/verifier$n.sol" >"$TMP/body$n.sol"
    suffix_verifier "$TMP/body$n.sol" "$n"
  } >"$VERIFIERS/AuctionVerifier$n.sol"
  echo "Wrote $VERIFIERS/AuctionVerifier$n.sol"
done
