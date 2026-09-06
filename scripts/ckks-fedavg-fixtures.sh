#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# Rebuild the ParamSet-5 federated-averaging fixtures end to end:
#   1. real FIVE-leg witnesses from TWO encryptions (gen_ckks_fedavg_prover):
#      Greco ct0/ct1 for the gradient ciphertext, Greco ct0/ct1 for the count
#      ciphertext, the ckks_fedavg_validity_ps5 leg
#   2. nargo compile + execute for ct0_ps5 / ct1_ps5 (twice: gradient, count) /
#      ckks_fedavg_validity_ps5
#   3. bb write_vk + prove -t evm per leg (prove times printed)
#   4. packages/interfold-contracts/test/fixtures/ckks_fedavg_ps5/verified_input.json
#      (+ over_norm_bound.json from the `prover-bad` witness, which must FAIL
#      nargo execute)
#
# The Greco ps5 packages are SHARED with the other ParamSet-5 apps: this script
# only writes `Prover_fedavg_*.toml` next to their `Prover.toml` and reuses an
# existing `target/<pkg>.vk` when one is present (the verifier contract was
# generated from it), so it never disturbs a sibling fixture.
#
# Re-run after any change to the fedavg leg, the Greco ps5 configs or the
# encoding contract. Then: scripts/generate-verifiers.ts --write --no-compile
#   --circuits ckks_fedavg_validity_ps5
# and `pnpm --filter interfold-contracts test test/CkksFedAvgE3Program.spec.ts`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
BIN="$ROOT/circuits/bin/threshold"
OUT="${1:-/tmp/ckks-fedavg-fixture}"
FIX="$ROOT/packages/interfold-contracts/test/fixtures/ckks_fedavg_ps5"
GRECO=(user_data_encryption_ckks_ct0_ps5 user_data_encryption_ckks_ct1_ps5)
APP=ckks_fedavg_validity_ps5
PKGS=("${GRECO[@]}" "$APP")

rm -rf "$OUT"; mkdir -p "$OUT"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_fedavg_prover -- prover "$OUT/good")

cd "$BIN"
for p in "${PKGS[@]}"; do
  echo "[fixture] compile $p"; nargo compile --package "$p" --silence-warnings
  mkdir -p "$OUT/$p"
  echo "[fixture] write_vk $p"; bb write_vk -b "target/$p.json" -o "$OUT/$p" -t evm >/dev/null
  # generate-verifiers.ts reuses target/<pkg>.vk when present. The Greco ps5
  # vks are shared with the sibling apps: keep them if they already match
  # this compile, refuse if they do not (a drifted verifier would reject every
  # proof below); the app vk is ours to pin.
  if [ -f "target/$p.vk" ] && ! cmp -s "$OUT/$p/vk" "target/$p.vk"; then
    if [ "$p" = "$APP" ]; then cp "$OUT/$p/vk" "target/$p.vk"; else
      echo "target/$p.vk differs from this compile; regenerate the shared ps5 verifiers first" >&2; exit 1
    fi
  else
    cp "$OUT/$p/vk" "target/$p.vk"
  fi
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
# Greco legs: Prover_fedavg_grad.toml = gradient witness, Prover_fedavg_count.toml = count witness.
for p in "${GRECO[@]}"; do
  prove_leg "$p" Prover_fedavg_grad "${p}_fedavg_g"
  prove_leg "$p" Prover_fedavg_count "${p}_fedavg_c"
done
prove_leg "$APP" Prover "$APP"

# Over-bound witness: nargo execute MUST fail on the fedavg leg. Keep the good
# app Prover.toml aside and restore it afterwards (the Greco stems are unique).
cp "$APP/Prover.toml" "$OUT/$APP/Prover.good.toml"
(cd "$ROOT" && cargo run --release -p e3-zk-helpers --example gen_ckks_fedavg_prover -- prover-bad "$OUT/bad" >/dev/null)
set +e
nargo execute --package "$APP" --silence-warnings >"$OUT/bad/execute.log" 2>&1; BAD_RC=$?
set -e
if [ "$BAD_RC" -eq 0 ]; then echo "over-bound witness must fail nargo execute" >&2; exit 1; fi
echo "[fixture] over-bound witness rejected by the circuit (rc=$BAD_RC)"
cp "$OUT/$APP/Prover.good.toml" "$APP/Prover.toml"

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
  ct0: leg(`user_data_encryption_ckks_ct0_ps5_fedavg_${tag}`),
  ct1: leg(`user_data_encryption_ckks_ct1_ps5_fedavg_${tag}`),
});
const g = pair("g"), c = pair("c");
const app = leg("ckks_fedavg_validity_ps5");
for (const [tag, p] of [["g", g], ["c", c]]) {
  if (p.ct0.publicInputs[3] !== p.ct1.publicInputs[2]) throw new Error(`u_commitment mismatch ct0/ct1 (${tag})`);
}
if (app.publicInputs.length !== 5) throw new Error(`app leg has ${app.publicInputs.length} public inputs, expected 5`);
if (g.ct0.publicInputs[2] !== app.publicInputs[3]) throw new Error("m_commitment_grad mismatch ct0/app");
if (c.ct0.publicInputs[2] !== app.publicInputs[4]) throw new Error("m_commitment_count mismatch ct0/app");
if (app.publicInputs[3] !== meta.mCommitmentG || app.publicInputs[4] !== meta.mCommitmentC) throw new Error("m_commitment mismatch app/meta");
if (JSON.stringify(app.publicInputs) !== JSON.stringify(meta.appPublicInputs)) throw new Error("app public inputs drifted");
if (g.ct0.publicInputs[3] === c.ct0.publicInputs[3]) throw new Error("the two encryptions share a u_commitment");
const fixture = {
  ciphertextG: meta.ciphertextGHex, ciphertextC: meta.ciphertextCHex,
  gradient: g, count: c, app,
  d: meta.d, index: meta.index, countValue: meta.count, update: meta.update, updateF64: meta.updateF64,
  squaredNorm: meta.squaredNorm, squaredNormF64: meta.squaredNormF64,
  normBound: meta.normBound, normBoundWord: meta.normBoundWord,
  mCommitmentG: meta.mCommitmentG, mCommitmentC: meta.mCommitmentC,
  extra: { address: meta.extra.address, addressWord: meta.extra.addressWord, indexWord: meta.extra.indexWord },
};
fs.writeFileSync(path.join(fix, "verified_input.json"), JSON.stringify(fixture, null, 2) + "\n");
const bad = {
  description: "Over-bound update: the genuine update (squared norm ~2.09) declared against a round bound of 1.0 (the ONLY check rejecting it is the circuit's own `sum G_j^2 <= norm_bound`). `nargo execute --package ckks_fedavg_validity_ps5` on this witness fails in `fedavg_validity -> (norm_bound - norm).assert_max_bit_size::<NORM_BITS>` (circuits/lib/src/core/threshold/ckks_fedavg_validity.nr), so NO proof exists for it and the on-chain gate can never see such a submission. Recorded so the spec asserts the posture from the circuit's inputs: the public-input words below are what the client WOULD have published.",
  update: badMeta.update, squaredNorm: badMeta.squaredNorm, normBound: badMeta.normBound, index: badMeta.index, count: badMeta.count,
  appPublicInputs: badMeta.appPublicInputs,
  nargoExecute: { exitCode: Number(badRc), failedAssertion: "Field::assert_max_bit_size::<40> on (norm_bound - norm), called from fedavg_validity (ckks_fedavg_validity.nr)" },
};
fs.writeFileSync(path.join(fix, "over_norm_bound.json"), JSON.stringify(bad, null, 2) + "\n");
console.log("[fixture] wrote", fix);
EOF
exit 0
