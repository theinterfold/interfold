#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Rebuild the ParamSet-5 private-matching fixtures end to end:
#   1. real FIVE-leg witnesses from TWO encryptions per party
#      (gen_ckks_matching_prover): Greco ct0/ct1 for the vector ciphertext,
#      Greco ct0/ct1 for the mask ciphertext, the ckks_matching_validity_ps5
#      leg — for party A (forward, slot 0) AND party B (reversed, slot 1)
#   2. nargo compile + execute for ct0_ps5 / ct1_ps5 (four times: A vector,
#      A mask, B vector, B mask) / ckks_matching_validity_ps5 (twice)
#   3. bb write_vk + prove -t evm per leg (prove times printed)
#   4. packages/interfold-contracts/test/fixtures/ckks_matching_ps5/verified_input.json
#      (+ out_of_range_entry.json from the `prover-bad` witness, which must
#      FAIL nargo execute)
#
# Re-run after any change to the matching leg, the Greco ps5 configs or the
# encoding contract. Then: scripts/generate-verifiers.ts --write --no-compile
#   --circuits ckks_matching_validity_ps5,user_data_encryption_ckks_ct0_ps5,user_data_encryption_ckks_ct1_ps5
# and `pnpm --filter interfold-contracts test test/CkksMatchingE3Program.spec.ts`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
BIN="$ROOT/circuits/bin/threshold"
OUT="${1:-/tmp/ckks-matching-fixture}"
FIX="$ROOT/packages/interfold-contracts/test/fixtures/ckks_matching_ps5"
GRECO=(user_data_encryption_ckks_ct0_ps5 user_data_encryption_ckks_ct1_ps5)
APP=ckks_matching_validity_ps5
PKGS=("${GRECO[@]}" "$APP")

rm -rf "$OUT"; mkdir -p "$OUT"
# Both parties encrypt under the SAME committee key: generate one key pair
# once and reuse it for B (the key is only needed for the Greco legs).
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_matching_prover -- prover "$OUT/a")
# The example writes no pubkey; B under a fresh key is still a valid fixture
# for the on-chain gate (each submission is checked independently), and the
# spec never evaluates the policy.
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_matching_prover -- prover-b "$OUT/b")

cd "$BIN"
for p in "${PKGS[@]}"; do
  echo "[fixture] compile $p"; nargo compile --package "$p" --silence-warnings
  mkdir -p "$OUT/$p"
  echo "[fixture] write_vk $p"; bb write_vk -b "target/$p.json" -o "$OUT/$p" -t evm >/dev/null
  # generate-verifiers.ts reuses target/<pkg>.vk when present — pin it to
  # THIS compile so the Solidity verifier can never drift from the fixture.
  cp "$OUT/$p/vk" "target/$p.vk"
done

# prove_leg <pkg> <prover-file-stem> <out-subdir>
prove_leg() {
  local p="$1" stem="$2" sub="$3"
  mkdir -p "$OUT/$sub"
  echo "[fixture] execute $p ($stem)"
  nargo execute --package "$p" -p "$stem" "${p}_${sub}" --silence-warnings >/dev/null
  echo "[fixture] prove $p ($stem)"
  /usr/bin/time -p bb prove -b "target/$p.json" -w "target/${p}_${sub}.gz" -k "$OUT/$p/vk" -o "$OUT/$sub" -t evm 2>&1 \
    | grep -E "^real" | sed "s/^/[fixture] $p $sub prove /"
}
# Greco legs: Prover.toml = A vector, Prover_mask.toml = A mask,
# Prover_b.toml = B vector, Prover_mask_b.toml = B mask.
for p in "${GRECO[@]}"; do
  prove_leg "$p" Prover "${p}_va"
  prove_leg "$p" Prover_mask "${p}_ma"
  prove_leg "$p" Prover_b "${p}_vb"
  prove_leg "$p" Prover_mask_b "${p}_mb"
done
prove_leg "$APP" Prover "${APP}_a"
prove_leg "$APP" Prover_b "${APP}_b"

# Out-of-range witness: nargo execute MUST fail on the matching leg. Keep
# the good Prover.toml files aside and restore them afterwards.
for p in "${PKGS[@]}"; do cp "$p/Prover.toml" "$OUT/$p/Prover.toml"; done
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_matching_prover -- prover-bad "$OUT/bad" >/dev/null)
set +e
nargo execute --package "$APP" --silence-warnings >"$OUT/bad/execute.log" 2>&1; BAD_RC=$?
set -e
if [ "$BAD_RC" -eq 0 ]; then echo "over-one witness must fail nargo execute" >&2; exit 1; fi
echo "[fixture] over-one witness rejected by the circuit (rc=$BAD_RC)"
for p in "${PKGS[@]}"; do cp "$OUT/$p/Prover.toml" "$p/Prover.toml"; done
# The B-side Prover files are fixture scaffolding only; nargo ignores them.
rm -f "$APP/Prover_b.toml"
for p in "${GRECO[@]}"; do rm -f "$p/Prover_b.toml" "$p/Prover_mask_b.toml" "$p/Prover_mask.toml"; done

mkdir -p "$FIX"
node - "$OUT" "$FIX" "$BAD_RC" <<'EOF'
const fs = require("fs"); const path = require("path");
const [out, fix, badRc] = process.argv.slice(2);
const metaA = JSON.parse(fs.readFileSync(path.join(out, "a", "meta.json"), "utf8"));
const metaB = JSON.parse(fs.readFileSync(path.join(out, "b", "meta.json"), "utf8"));
const badMeta = JSON.parse(fs.readFileSync(path.join(out, "bad", "meta.json"), "utf8"));
const leg = (sub) => {
  const d = path.join(out, sub);
  const proof = "0x" + fs.readFileSync(path.join(d, "proof")).toString("hex");
  const pi = fs.readFileSync(path.join(d, "public_inputs"));
  const words = [];
  for (let i = 0; i < pi.length; i += 32) words.push("0x" + pi.subarray(i, i + 32).toString("hex"));
  return { proof, publicInputs: words };
};
const pair = (tag) => ({
  ct0: leg(`user_data_encryption_ckks_ct0_ps5_${tag}`),
  ct1: leg(`user_data_encryption_ckks_ct1_ps5_${tag}`),
});
const party = (meta, vtag, mtag, atag) => {
  const vector = pair(vtag), mask = pair(mtag), app = leg(`ckks_matching_validity_ps5_${atag}`);
  for (const [tag, p] of [["vector", vector], ["mask", mask]]) {
    if (p.ct0.publicInputs[3] !== p.ct1.publicInputs[2]) throw new Error(`u_commitment mismatch ct0/ct1 (${atag} ${tag})`);
  }
  if (vector.ct0.publicInputs[2] !== app.publicInputs[3]) throw new Error(`m_commitment_vec mismatch ct0/app (${atag})`);
  if (mask.ct0.publicInputs[2] !== app.publicInputs[4]) throw new Error(`m_commitment_mask mismatch ct0/app (${atag})`);
  if (app.publicInputs[3] !== meta.mCommitmentVec || app.publicInputs[4] !== meta.mCommitmentMask) throw new Error(`m_commitment mismatch app/meta (${atag})`);
  if (JSON.stringify(app.publicInputs) !== JSON.stringify(meta.appPublicInputs)) throw new Error(`app public inputs drifted (${atag})`);
  if (vector.ct0.publicInputs[3] === mask.ct0.publicInputs[3]) throw new Error(`the two encryptions share a u_commitment (${atag})`);
  return {
    ciphertextVec: meta.ciphertextVecHex, ciphertextMask: meta.ciphertextMaskHex,
    vector, mask, app,
    role: meta.role, index: meta.index, values: meta.values, valuesF64: meta.valuesF64, maskValues: meta.mask,
    mCommitmentVec: meta.mCommitmentVec, mCommitmentMask: meta.mCommitmentMask,
    extra: meta.extra,
  };
};
const a = party(metaA, "va", "ma", "a");
const b = party(metaB, "vb", "mb", "b");
if (a.role !== 0 || b.role !== 1) throw new Error("roles drifted");
const dot = a.valuesF64.reduce((s, x, j) => s + x * b.valuesF64[j], 0);
fs.writeFileSync(path.join(fix, "verified_input.json"), JSON.stringify({ a, b, expectedScore: dot }, null, 2) + "\n");
const bad = {
  description: "Out-of-range entry: v_0 = 1.5 (V_0 = 98304 > 2^16), declared honestly by the party. `nargo execute --package ckks_matching_validity_ps5` on this witness fails in `matching_validity -> assert_entry_range(values[0])` (circuits/lib/src/core/threshold/ckks_matching_validity.nr), so NO proof exists for it and the on-chain gate can never see such a submission. The public-input words below are what the party WOULD have published.",
  role: badMeta.role, index: badMeta.index, values: badMeta.values,
  appPublicInputs: badMeta.appPublicInputs,
  nargoExecute: { exitCode: Number(badRc), failedAssertion: "Field::assert_max_bit_size::<18> in assert_entry_range(values[j]), called from matching_validity (ckks_matching_validity.nr)" },
};
fs.writeFileSync(path.join(fix, "out_of_range_entry.json"), JSON.stringify(bad, null, 2) + "\n");
console.log("[fixture] wrote", fix, "expected score", dot);
EOF
exit 0
