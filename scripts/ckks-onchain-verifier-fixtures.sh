#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Build the on-chain CKKS verifier fixtures for ONE param set:
#   * N real C1-CKKS (`pk_generation_ckks_ps<N>`) party proofs — the committee
#     key evidence consumed by CkksPkVerifier;
#   * one real C7-CKKS (`decrypted_shares_aggregation_ckks[_ps<N>]`) proof —
#     the decrypted-output evidence consumed by CkksDecryptionVerifier.
#
# Every proof comes from the SAME `nargo compile` the committed Solidity
# verifier was generated from: the script pins `target/<pkg>.vk` to the vk it
# proves against, exactly like scripts/ckks-credit-fixtures.sh, so a fixture can
# never drift from its verifier.
#
# Usage: scripts/ckks-onchain-verifier-fixtures.sh [param-set] [committee-size] [workdir]
#   param-set      0 | 2 | 3 | 4   (default 2 — the ckks-auction demo)
#   committee-size N party proofs  (default 3 — the `minimum` committee)
#
# Writes packages/interfold-contracts/test/fixtures/ckks_onchain_ps<N>/verifier_input.json
#
# After running: pnpm --filter interfold-contracts test test/CkksPkVerifier.spec.ts
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
BIN="$ROOT/circuits/bin/threshold"
PS="${1:-2}"
N_PARTIES="${2:-3}"
OUT="${3:-/tmp/ckks-onchain-fixture-ps$PS}"
FIX="$ROOT/packages/interfold-contracts/test/fixtures/ckks_onchain_ps$PS"

C1_PKG="pk_generation_ckks_ps$PS"
if [ "$PS" = "0" ]; then
  C7_PKG="decrypted_shares_aggregation_ckks"
else
  C7_PKG="decrypted_shares_aggregation_ckks_ps$PS"
fi

rm -rf "$OUT"; mkdir -p "$OUT"
cd "$BIN"

# --- compile + pin the vk both legs prove against -------------------------
for p in "$C1_PKG" "$C7_PKG"; do
  echo "[fixture] compile $p"
  nargo compile --package "$p" --silence-warnings
  mkdir -p "$OUT/$p"
  echo "[fixture] write_vk $p"
  bb write_vk -b "target/$p.json" -o "$OUT/$p" -t evm >/dev/null
  cp "$OUT/$p/vk" "target/$p.vk"
done

# --- N distinct C1-CKKS party proofs --------------------------------------
# gen_ckks_c1_prover draws a fresh sk / e / e_sm from `rand::rng()` on every
# run, so each pass is a genuinely different party's share.
for i in $(seq 0 $((N_PARTIES - 1))); do
  echo "[fixture] C1 party $i: witness"
  (cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_c1_prover -- --param-set "$PS" >/dev/null)
  sub="c1_party_$i"
  mkdir -p "$OUT/$sub"
  cp "$C1_PKG/Prover.toml" "$OUT/$sub/Prover.toml"
  echo "[fixture] C1 party $i: execute"
  nargo execute --package "$C1_PKG" "${C1_PKG}_$i" --silence-warnings >/dev/null
  echo "[fixture] C1 party $i: prove"
  bb prove -b "target/$C1_PKG.json" -w "target/${C1_PKG}_$i.gz" \
    -k "$OUT/$C1_PKG/vk" -o "$OUT/$sub" -t evm >/dev/null
done

# --- one C7-CKKS aggregation proof ----------------------------------------
echo "[fixture] C7: witness"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_agg_prover -- --param-set "$PS" >/dev/null)
mkdir -p "$OUT/c7"
echo "[fixture] C7: execute"
nargo execute --package "$C7_PKG" "${C7_PKG}_fx" --silence-warnings >/dev/null
echo "[fixture] C7: prove"
bb prove -b "target/$C7_PKG.json" -w "target/${C7_PKG}_fx.gz" \
  -k "$OUT/$C7_PKG/vk" -o "$OUT/c7" -t evm >/dev/null

mkdir -p "$FIX"
node - "$OUT" "$FIX" "$PS" "$N_PARTIES" <<'EOF'
const fs = require("fs"); const path = require("path");
const [out, fix, ps, n] = process.argv.slice(2);
const leg = (sub) => {
  const d = path.join(out, sub);
  const proof = "0x" + fs.readFileSync(path.join(d, "proof")).toString("hex");
  const pi = fs.readFileSync(path.join(d, "public_inputs"));
  const words = [];
  for (let i = 0; i < pi.length; i += 32) words.push("0x" + pi.subarray(i, i + 32).toString("hex"));
  return { proof, publicInputs: words };
};
const parties = [];
for (let i = 0; i < Number(n); i++) parties.push(leg(`c1_party_${i}`));
const c7 = leg("c7");

// C1-CKKS returns (sk_commitment, pk_commitment, e_sm_commitment). bb writes the
// public_inputs file WITHOUT the 8 pairing-point words (they travel inside the
// proof), and that is exactly the array the Honk verifier's `verify` accepts.
for (const [i, p] of parties.entries()) {
  if (p.publicInputs.length !== 3) throw new Error(`party ${i}: expected 3 public inputs, got ${p.publicInputs.length}`);
}
// The parties must be genuinely distinct or CkksPkVerifier's replay guard fires.
for (let i = 0; i < parties.length; i++)
  for (let j = 0; j < i; j++) {
    if (parties[i].publicInputs[1] === parties[j].publicInputs[1]) throw new Error(`parties ${i}/${j} share a pk_commitment`);
    if (parties[i].publicInputs[0] === parties[j].publicInputs[0]) throw new Error(`parties ${i}/${j} share an sk_commitment`);
  }
// C7-CKKS layout: [d_commitments T+1][party_ids T+1][domain_hi][domain_lo][u_global N=512]
// = 2 + 2 + 2 + 512 = 518 for T=1. The fixture witness (gen_ckks_agg_prover) binds
// domain_hi = 1, domain_lo = 2, i.e. decryptionDomain = 0x00..01 || 0x00..02.
if (c7.publicInputs.length !== 518) throw new Error(`C7: expected 518 public inputs, got ${c7.publicInputs.length}`);
const hi = BigInt(c7.publicInputs[4]), lo = BigInt(c7.publicInputs[5]);
if (hi !== 1n || lo !== 2n) throw new Error(`C7: fixture domain words are (${hi}, ${lo}), expected (1, 2)`);
const decryptionDomain = "0x" + hi.toString(16).padStart(32, "0") + lo.toString(16).padStart(32, "0");

const fixture = {
  paramSet: Number(ps),
  committeeSize: Number(n),
  description:
    "Real Honk proofs for the on-chain CKKS verifiers. `parties` are N C1-CKKS " +
    "(pk_generation_ckks_ps" + ps + ") proofs, one per committee member, in ascending party " +
    "order — the CkksPkVerifier input. `c7` is one decrypted_shares_aggregation_ckks proof — " +
    "the CkksDecryptionVerifier input. Regenerate with scripts/ckks-onchain-verifier-fixtures.sh " + ps + ".",
  parties,
  c7,
  // The decryptionDomain the C7 fixture is bound to (hi||lo of its two
  // domain public inputs). CkksDecryptionVerifier.verify MUST be called
  // with exactly this value; any other reverts DomainBindingMismatch.
  c7DecryptionDomain: decryptionDomain,
};
fs.writeFileSync(path.join(fix, "verifier_input.json"), JSON.stringify(fixture, null, 2) + "\n");
console.log("[fixture] wrote", fix);
EOF
