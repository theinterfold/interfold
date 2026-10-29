#!/usr/bin/env bash
# Compile the bid circuits, write their Solidity verifiers, and compute the VK anchors the program
# contract pins.
#
# A bid is a tree of circuits, each below 2^21 gates so that a browser can prove it (the WASM heap
# is 4 GiB):
#   auction_bid_pair    the proofs of the roles 0 and 1, and the bid itself  (recursive proof)
#   auction_bid_masks   the proofs of the roles 2 and 3, the pair mask        (recursive proof, type 3)
#   auction_bid_shares  the proofs of the roles 2 and 3, the shares           (recursive proof, type 5)
#   auction_bid2        the pair proof only, type 4         (EVM verifier AuctionVerifier2)
#   auction_bid3        the pair proof and the proof of role 2  (EVM verifier AuctionVerifier3)
#   auction_bid4        the pair proof and the masks or shares proof, types 3 and 5
#                                                               (EVM verifier AuctionVerifier4)
#   auction_mask        the proof of a provider mask, type 4    (EVM verifier AuctionMaskVerifier)
#
# Each anchor covers the Interfold user-data encryption tree as the SDK bundles it for the insecure
# SIMD preset (the key hash of the wrapper and the two per-leg chains) and the inner circuits of its
# tree. `auction_bid2` returns `vkAnchor2`, `auction_bid3` returns `vkAnchor3`, `auction_bid4`
# returns `vkAnchor4` (type 3) or `vkAnchorQnr` (type 5), and `auction_mask` returns `vkAnchorMask`
# as `vk_anchor`. `vkAnchor2` equals `vkAnchor3`: both cover the wrapper and the pair circuit.
# `vkAnchor4` and `vkAnchorQnr` have the same formula: they differ in the key hash of the circuit
# of the roles 2 and 3 (masks or shares). Each verifier contract is its own circuit, so the
# contracts keep the anchors apart; `auction_bid4` serves both types, and the program contract
# tells them apart by the anchor.
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
for dir in pair masks shares bid2 bid3 bid4 mask; do
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
write_vk "$CIRCUITS/shares/target/auction_bid_shares.json" noir-recursive-no-zk

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
anchor2="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash")"
anchor3="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash")"
anchor4="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash" "$VK/auction_bid_masks/vk_hash")"
anchor_qnr="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain" "$VK/auction_bid_pair/vk_hash" "$VK/auction_bid_shares/vk_hash")"
anchor_mask="$(vk_hash "$ude" "$TMP/ct0_chain" "$TMP/ct1_chain")"
printf '{\n  "vkAnchor2": "%s",\n  "vkAnchor3": "%s",\n  "vkAnchor4": "%s",\n  "vkAnchorMask": "%s",\n  "vkAnchorQnr": "%s"\n}\n' \
  "$anchor2" "$anchor3" "$anchor4" "$anchor_mask" "$anchor_qnr" >"$ANCHOR"
echo "VK anchors: $anchor2 (2 roles), $anchor3 (3 roles), $anchor4 (4 roles), $anchor_mask (mask), $anchor_qnr (type 5)"

# `bb` writes every verifier with the same top-level names (`Fr`, `Honk`, `HonkVerifier`, ...), which
# collide when two are in one project. Suffix each top-level identifier with `$2`, and name the
# verifier contract `$3`. The libraries (`ZKTranscriptLib$2`, `RelationsLib$2`) are linked on
# deployment. In an `assembly` block `add`, `sub` and `mul` are the EVM opcodes, so they
# keep their names there.
suffix_verifier() {
  local source="$1" suffix="$2" contract="$3" names
  names="$(perl -ne '
    print "$1\n" if /^(?:abstract\s+)?(?:contract|library|interface|struct|enum)\s+(\w+)/
      || /^type\s+(\w+)\s+is/ || /^function\s+(\w+)/ || /^error\s+(\w+)/
      || /^[\w.\[\]]+\s+constant\s+(\w+)/;
  ' "$source" | sort -u | grep -vx HonkVerifier | paste -sd'|' -)"
  NAMES="$names" SUFFIX="$suffix" CONTRACT="$contract" perl -e '
    my ($names, $suffix, $contract, $depth) = ($ENV{NAMES}, $ENV{SUFFIX}, $ENV{CONTRACT}, 0);
    (my $yul = $names) =~ s/\b(?:add|sub|mul)\b\|?//g;
    $yul =~ s/\|$//;
    while (<>) {
      my $in_asm = $depth > 0 || /\bassembly\b/;
      my $re = $in_asm ? $yul : $names;
      s/(?<![\w\$])(?:($re)|HonkVerifier)(?!\w)/defined($1) ? "$1$suffix" : $contract/ge;
      if ($in_asm) {
        my $tail = /\bassembly\b/ ? substr($_, index($_, "assembly")) : $_;
        $depth += () = $tail =~ /\{/g;
        $depth -= () = $tail =~ /\}/g;
      }
      print;
    }
  ' "$source"
}

# `write_verifier CIRCUIT_DIR NAME SUFFIX CONTRACT`: the Solidity verifier of `circuits/CIRCUIT_DIR`
# (the package `NAME`) in `contracts/verifiers/CONTRACT.sol`.
write_verifier() {
  local dir="$1" name="$2" suffix="$3" contract="$4"
  echo "Writing the Solidity verifier of $name..."
  mkdir -p "$VK/$name"
  bb write_vk -b "$CIRCUITS/$dir/target/$name.json" -o "$VK/$name" -t evm >/dev/null
  bb write_solidity_verifier -k "$VK/$name/vk" -o "$TMP/verifier_$suffix.sol" -t evm >/dev/null
  {
    printf '%s\n' \
      '// SPDX-License-Identifier: LGPL-3.0-only' \
      '//' \
      '// This file is provided WITHOUT ANY WARRANTY;' \
      '// without even the implied warranty of MERCHANTABILITY' \
      '// or FITNESS FOR A PARTICULAR PURPOSE.' \
      '//' \
      "// Generated by scripts/compile_circuits.sh from circuits/$dir. Do not edit."
    tail -n +3 "$TMP/verifier_$suffix.sol" >"$TMP/body_$suffix.sol"
    suffix_verifier "$TMP/body_$suffix.sol" "$suffix" "$contract"
  } >"$VERIFIERS/$contract.sol"
  echo "Wrote $VERIFIERS/$contract.sol"
}

write_verifier bid2 auction_bid2 2 AuctionVerifier2
write_verifier bid3 auction_bid3 3 AuctionVerifier3
write_verifier bid4 auction_bid4 4 AuctionVerifier4
write_verifier mask auction_mask Mask AuctionMaskVerifier
