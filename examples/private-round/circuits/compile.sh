#!/usr/bin/env bash
# Compile the bid and claim circuits, write their Solidity verifiers, and compute the VK anchor the
# program contract pins.
#
#   private_round_bid     the bid proof: both user-data encryption proofs (the bid and the mask), the
#                      plaintext of the bid, the commitment (EVM verifier PrivateRoundBidVerifier).
#                      1,427,418 gates: below 2^21, so a browser can prove it.
#   private_round_claim   the claim proof: the opening of the bid commitment (EVM verifier
#                      PrivateRoundClaimVerifier). About 3,000 gates.
#
# The anchor covers the Interfold user-data encryption tree as the SDK bundles it for the insecure
# SIMD preset: the key hash of the wrapper and the two per-leg chains. Both proofs of the bid circuit
# use the same wrapper circuit, and the bid circuit has no other inner circuit, so the anchor has
# nothing else. `private_round_bid` returns it as `vk_anchor`.
set -euo pipefail

CIRCUITS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CIRCUITS/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
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
  cargo run --quiet --release --manifest-path "$CIRCUITS/tools/Cargo.toml" --bin vk_hash -- "$@"
}

to_file() {
  local hex="${1#0x}"
  printf '%064s' "$hex" | tr ' ' '0' | xxd -r -p >"$2"
}

echo "Compiling the circuits..."
for dir in bid claim; do
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
anchor="$(vk_hash "$VK/user_data_encryption_chunked/vk_hash" "$TMP/ct0_chain" "$TMP/ct1_chain")"
printf '{\n  "vkAnchor": "%s"\n}\n' "$anchor" >"$ANCHOR"
echo "VK anchor: $anchor"

# `bb` writes every verifier with the same top-level names (`Fr`, `Honk`, `HonkVerifier`, ...), which
# collide when two are in one project. Suffix each top-level identifier with `$2`, and name the
# verifier contract `$3`. The libraries (`ZKTranscriptLib$2`, `RelationsLib$2`) are linked on
# deployment. In an `assembly` block `add`, `sub` and `mul` are the EVM opcodes, so they keep their
# names there.
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

# Write the Solidity verifier of the circuit `$1` (`bid` or `claim`) as `$2` with the suffix `$3`.
write_verifier() {
  local dir="$1" contract="$2" suffix="$3" name="private_round_$1"
  echo "Writing the Solidity verifier of $name..."
  mkdir -p "$VK/$name"
  bb write_vk -b "$CIRCUITS/$dir/target/$name.json" -o "$VK/$name" -t evm >/dev/null
  bb write_solidity_verifier -k "$VK/$name/vk" -o "$TMP/$dir.sol" -t evm >/dev/null
  {
    printf '%s\n' \
      '// SPDX-License-Identifier: LGPL-3.0-only' \
      '//' \
      '// This file is provided WITHOUT ANY WARRANTY;' \
      '// without even the implied warranty of MERCHANTABILITY' \
      '// or FITNESS FOR A PARTICULAR PURPOSE.' \
      '//' \
      "// Generated by circuits/compile.sh from circuits/$dir. Do not edit."
    tail -n +3 "$TMP/$dir.sol" >"$TMP/$dir.body.sol"
    suffix_verifier "$TMP/$dir.body.sol" "$suffix" "$contract"
  } >"$VERIFIERS/$contract.sol"
  echo "Wrote $VERIFIERS/$contract.sol"
}

write_verifier bid PrivateRoundBidVerifier Bid
write_verifier claim PrivateRoundClaimVerifier Claim
