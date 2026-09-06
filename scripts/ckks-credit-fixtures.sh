#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Rebuild the ParamSet-4 credit-scoring v2 fixtures end to end:
#   1. real FIVE-leg witnesses from TWO encryptions (gen_ckks_credit_prover):
#      Greco ct0/ct1 for the logit ciphertext, Greco ct0/ct1 for the mask
#      ciphertext, the ckks_credit_validity_ps4 leg
#   2. nargo compile + execute for ct0_ps4 / ct1_ps4 (twice: logit, mask) /
#      ckks_credit_validity_ps4
#   3. bb write_vk + prove -t evm per leg (prove times printed)
#   4. packages/interfold-contracts/test/fixtures/ckks_credit_ps4/verified_input.json
#      (+ out_of_range_feature.json from the `prover-bad` witness, which must
#      FAIL nargo execute)
#
# Re-run after any change to the credit leg, the Greco ps4 configs or the
# encoding contract. Then: scripts/generate-verifiers.ts --write --no-compile
#   --circuits ckks_credit_validity_ps4 user_data_encryption_ckks_ct0_ps4 user_data_encryption_ckks_ct1_ps4
# and `pnpm --filter interfold-contracts test test/CkksCreditE3Program.spec.ts`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
BIN="$ROOT/circuits/bin/threshold"
OUT="${1:-/tmp/ckks-credit-fixture}"
FIX="$ROOT/packages/interfold-contracts/test/fixtures/ckks_credit_ps4"
GRECO=(user_data_encryption_ckks_ct0_ps4 user_data_encryption_ckks_ct1_ps4)
APP=ckks_credit_validity_ps4
PKGS=("${GRECO[@]}" "$APP")

rm -rf "$OUT"; mkdir -p "$OUT"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_credit_prover -- prover "$OUT/good")

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
# Greco legs: Prover.toml = logit witness, Prover_mask.toml = mask witness.
for p in "${GRECO[@]}"; do
  prove_leg "$p" Prover "${p}_z"
  prove_leg "$p" Prover_mask "${p}_m"
done
prove_leg "$APP" Prover "$APP"

# Out-of-range witness: nargo execute MUST fail on the credit leg. Keep the
# good Prover.toml files aside and restore them afterwards.
for p in "${PKGS[@]}"; do cp "$p/Prover.toml" "$OUT/$p/Prover.toml"; done
cp "$APP/Prover.toml" "$OUT/$APP/Prover.good.toml"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_credit_prover -- prover-bad "$OUT/bad" >/dev/null)
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
  ct0: leg(`user_data_encryption_ckks_ct0_ps4_${tag}`),
  ct1: leg(`user_data_encryption_ckks_ct1_ps4_${tag}`),
});
const z = pair("z"), m = pair("m");
const app = leg("ckks_credit_validity_ps4");
for (const [tag, p] of [["z", z], ["m", m]]) {
  if (p.ct0.publicInputs[3] !== p.ct1.publicInputs[2]) throw new Error(`u_commitment mismatch ct0/ct1 (${tag})`);
}
if (z.ct0.publicInputs[2] !== app.publicInputs[13]) throw new Error("m_commitment_z mismatch ct0/app");
if (m.ct0.publicInputs[2] !== app.publicInputs[14]) throw new Error("m_commitment_m mismatch ct0/app");
if (app.publicInputs[13] !== meta.mCommitmentZ || app.publicInputs[14] !== meta.mCommitmentM) throw new Error("m_commitment mismatch app/meta");
if (JSON.stringify(app.publicInputs) !== JSON.stringify(meta.appPublicInputs)) throw new Error("app public inputs drifted");
if (z.ct0.publicInputs[3] === m.ct0.publicInputs[3]) throw new Error("the two encryptions share a u_commitment");
const fixture = {
  ciphertextZ: meta.ciphertextZHex, ciphertextM: meta.ciphertextMHex,
  logit: z, mask: m, app,
  cap: meta.cap, index: meta.index, maskValue: meta.mask, logitValue: meta.logit,
  model: meta.model, modelWords: meta.modelWords,
  mCommitmentZ: meta.mCommitmentZ, mCommitmentM: meta.mCommitmentM,
  extra: {
    address: meta.extra.address, addressWord: meta.extra.addressWord, merkleRoot: meta.extra.merkleRoot,
    indexWord: meta.extra.indexWord,
    features: JSON.stringify(meta.features), bobFeatures: JSON.stringify(meta.extra.bobFeatures),
  },
};
fs.writeFileSync(path.join(fix, "verified_input.json"), JSON.stringify(fixture, null, 2) + "\n");
const bad = {
  description: "Out-of-range feature: x_3 = cap + 1 = 1001, issuer-attested by a leaf that vouches for it (the ONLY check rejecting it is the circuit's own `x_j <= cap`). `nargo execute --package ckks_credit_validity_ps4` on this witness fails in `credit_validity -> assert_cap_range(cap - features[3])` (circuits/lib/src/core/threshold/ckks_credit_validity.nr), so NO proof exists for it and the on-chain gate can never see such a submission. Recorded so the spec asserts the posture from the circuit's inputs: the public-input words below are what the applicant WOULD have published.",
  cap: badMeta.cap, features: badMeta.features, index: badMeta.index, mask: badMeta.mask, model: badMeta.model,
  appPublicInputs: badMeta.appPublicInputs,
  nargoExecute: { exitCode: Number(badRc), failedAssertion: "Field::assert_max_bit_size::<32> in assert_cap_range(cap - features[j]), called from credit_validity (ckks_credit_validity.nr)" },
};
fs.writeFileSync(path.join(fix, "out_of_range_feature.json"), JSON.stringify(bad, null, 2) + "\n");
console.log("[fixture] wrote", fix);
EOF
exit 0
