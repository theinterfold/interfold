#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Rebuild the ParamSet-5 treasury-risk fixtures end to end:
#   1. real SEVEN-leg witnesses from THREE encryptions (gen_ckks_treasury_prover):
#      Greco ct0/ct1 for the forward, reversed and mask ciphertexts, the
#      ckks_treasury_validity_ps5 leg
#   2. nargo compile + execute for ct0_ps5 / ct1_ps5 (three times: fwd, rev,
#      mask) / ckks_treasury_validity_ps5
#   3. bb write_vk + prove -t evm per leg (prove times printed)
#   4. packages/interfold-contracts/test/fixtures/ckks_treasury_ps5/verified_input.json
#      (+ out_of_range_exposure.json from the `prover-bad` witness, which must
#      FAIL nargo execute)
#
# Re-run after any change to the treasury leg, the Greco ps5 configs or the
# encoding contract. Then: scripts/generate-verifiers.ts --write --no-compile
#   --circuits ckks_treasury_validity_ps5 user_data_encryption_ckks_ct0_ps5 user_data_encryption_ckks_ct1_ps5
# and `pnpm --filter interfold-contracts test test/CkksTreasuryE3Program.spec.ts`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
BIN="$ROOT/circuits/bin/threshold"
OUT="${1:-/tmp/ckks-treasury-fixture}"
FIX="$ROOT/packages/interfold-contracts/test/fixtures/ckks_treasury_ps5"
GRECO=(user_data_encryption_ckks_ct0_ps5 user_data_encryption_ckks_ct1_ps5)
APP=ckks_treasury_validity_ps5
PKGS=("${GRECO[@]}" "$APP")

rm -rf "$OUT"; mkdir -p "$OUT"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_treasury_prover -- prover "$OUT/good")

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
# Greco legs: Prover.toml = forward witness, Prover_rev.toml = reversed,
# Prover_mask.toml = mask.
for p in "${GRECO[@]}"; do
  prove_leg "$p" Prover "${p}_fwd"
  prove_leg "$p" Prover_rev "${p}_rev"
  prove_leg "$p" Prover_mask "${p}_mask"
done
prove_leg "$APP" Prover "$APP"

# Out-of-range witness: nargo execute MUST fail on the treasury leg. Keep the
# good Prover.toml files aside and restore them afterwards.
for p in "${PKGS[@]}"; do cp "$p/Prover.toml" "$OUT/$p/Prover.toml"; done
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_treasury_prover -- prover-bad "$OUT/bad" >/dev/null)
set +e
nargo execute --package "$APP" --silence-warnings >"$OUT/bad/execute.log" 2>&1; BAD_RC=$?
set -e
if [ "$BAD_RC" -eq 0 ]; then echo "over-cap witness must fail nargo execute" >&2; exit 1; fi
echo "[fixture] over-cap witness rejected by the circuit (rc=$BAD_RC)"
for p in "${PKGS[@]}"; do cp "$OUT/$p/Prover.toml" "$p/Prover.toml"; done

mkdir -p "$FIX"
node - "$OUT" "$FIX" "$BAD_RC" <<'EOF'
const fs = require("fs"); const path = require("path");
const [out, fix, badRc] = process.argv.slice(2);
const meta = JSON.parse(fs.readFileSync(path.join(out, "good", "meta.json"), "utf8"));
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
const fwd = pair("fwd"), rev = pair("rev"), mask = pair("mask");
const app = leg("ckks_treasury_validity_ps5");
const W = meta.wordIndex;
for (const [tag, p] of [["fwd", fwd], ["rev", rev], ["mask", mask]]) {
  if (p.ct0.publicInputs[3] !== p.ct1.publicInputs[2]) throw new Error(`u_commitment mismatch ct0/ct1 (${tag})`);
}
if (fwd.ct0.publicInputs[2] !== app.publicInputs[W.mFwd]) throw new Error("m_commitment_fwd mismatch ct0/app");
if (rev.ct0.publicInputs[2] !== app.publicInputs[W.mRev]) throw new Error("m_commitment_rev mismatch ct0/app");
if (mask.ct0.publicInputs[2] !== app.publicInputs[W.mMask]) throw new Error("m_commitment_mask mismatch ct0/app");
if (app.publicInputs[W.mFwd] !== meta.mCommitmentFwd || app.publicInputs[W.mRev] !== meta.mCommitmentRev || app.publicInputs[W.mMask] !== meta.mCommitmentMask) throw new Error("m_commitment mismatch app/meta");
if (JSON.stringify(app.publicInputs) !== JSON.stringify(meta.appPublicInputs)) throw new Error("app public inputs drifted");
const us = new Set([fwd.ct0.publicInputs[3], rev.ct0.publicInputs[3], mask.ct0.publicInputs[3]]);
if (us.size !== 3) throw new Error("two encryptions share a u_commitment");
const fixture = {
  ciphertextFwd: meta.ciphertextFwdHex, ciphertextRev: meta.ciphertextRevHex, ciphertextMask: meta.ciphertextMaskHex,
  forward: fwd, reversed: rev, mask, app,
  index: meta.index, exposures: meta.exposures, exposuresF64: meta.exposuresF64,
  weights: meta.weights, weightsF64: meta.weightsF64, weightWords: meta.weightWords,
  maskValues: meta.mask, singleDaoRisk: meta.singleDaoRisk,
  mCommitmentFwd: meta.mCommitmentFwd, mCommitmentRev: meta.mCommitmentRev, mCommitmentMask: meta.mCommitmentMask,
  wordIndex: meta.wordIndex,
  extra: { address: meta.extra.address, addressWord: meta.extra.addressWord, indexWord: meta.extra.indexWord },
};
fs.writeFileSync(path.join(fix, "verified_input.json"), JSON.stringify(fixture, null, 2) + "\n");
const bad = {
  description: "Out-of-range exposure: X_2 = 2^16 + 1 (x_2 = 1 + 2^-16, over the cap). `nargo execute --package ckks_treasury_validity_ps5` on this witness fails in `treasury_validity -> assert_exposure_range(x[2])` (circuits/lib/src/core/threshold/ckks_treasury_validity.nr), so NO proof exists for it and the on-chain gate can never see such a submission. The public-input words below are what the DAO WOULD have published.",
  index: badMeta.index, exposures: badMeta.exposures, weights: badMeta.weights,
  appPublicInputs: badMeta.appPublicInputs,
  nargoExecute: { exitCode: Number(badRc), failedAssertion: "Field::assert_max_bit_size::<17> in assert_exposure_range(x[a]), called from treasury_validity (ckks_treasury_validity.nr)" },
};
fs.writeFileSync(path.join(fix, "out_of_range_exposure.json"), JSON.stringify(bad, null, 2) + "\n");
console.log("[fixture] wrote", fix);
EOF
exit 0
