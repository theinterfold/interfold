# CKKS private credit scoring on Interfold

A CRISP-shaped E3 program: applicants encrypt their issuer-attested features **in the browser**
(coefficient-encoded CKKS with per-feature masks), prove the encryption is well-formed and attested
(three UltraHonk legs verified on-chain at `publishInput`), the program scores everyone with a public
logistic model **under encryption**, and the threshold committee opens **one** ciphertext whose
coefficients are *masked* scores — only the applicant holding the masks can read their own score.

Trust split (binding): the ciphernode committee runs **no app logic** — it does the DKG and one
threshold decryption of the ciphertext the program publishes. The policy
(`e3_trckks::policy::credit_scoring_policy`) runs in `program/`, called by the coordination server.

```
issuer snapshot ──root──▶ CkksCreditE3Program.setIssuerRoot(e3Id, root)
                                   ▲
applicant browser: masks μ ─▶ X(t)=Σ(x_j/cap+μ_j)t^{j+1} ─▶ CKKS encrypt (WASM)
                 ─▶ Greco ct0 + Greco ct1 + credit leg (bb.js) ─▶ wallet publishInput ─┘
server:  reads every ct from calldata ─▶ Σ ct(X_i)×pt(V_i)+b ─▶ publishCiphertextOutput
committee: threshold decrypt ─▶ coefficient 16·i = ⟨w,x_i⟩ + ⟨w,μ_i⟩ + b  (masked)
browser: z = opened[i] − ⟨w,μ⟩ ; score = σ(z)
```

## Layout

| path | what |
| --- | --- |
| `program/` | `ckks-credit-program`: `Model`, `credit_scoring_policy` wrapper, `decode_opened_scores` (coefficient layout, 4 decimals) |
| `server/` | actix-web + sled on **:8092** — round opener (E3 request + issuer root + model), indexer (recovers cts from calldata), evaluator (runs the program, publishes the output), API. Holds **no masks and no features beyond the public issuer snapshot** |
| `packages/ckks-credit-sdk` | TS: `encryptAndProveApplication` (WASM `encryptCreditAndWitness` + 3 Honk legs), `FeatureTree` (poseidon-lite, pinned to the contract fixture root), `publishApplication` (wallet-bound envelope), `recoverScore` |
| `client/` | Vite React on **:5175** — wallet (anvil dev keys / injected), apply flow with per-stage timings, results + "your score" recovery from `localStorage` masks |
| `scripts/dev.sh` | anvil → deploy (mocks + `CkksCreditE3Program` + ParamSet 4) → 5 ciphernodes → server → client |
| `scripts/e2e.mjs` | headless-Chrome e2e (playwright): 3 applicants, out-of-range rejection, wrong-root + replay reverts, per-user recovery, mask-hiding assertion |
| `scripts/prove-node.mjs` | the same SDK pipeline in Node against the ps4 fixture key (no chain) |

## Encoding contract (pinned by tests)

ParamSet 4: N = 512, moduli `[0xffffee001, 0xffffc4001, 0xffffbe001, 0xffffba001, 0xffffb7001]`,
Δ = 2^40, `RelinCeremonyPlan::PerLevel([1, 2])` — the network evaluates σ on the encrypted logit,
so it performs two ciphertext × ciphertext products and needs a multiparty relinearization key at
each of levels 1 and 2. The committee therefore runs **DKG + a two-level relin ceremony + one
threshold decryption**, and nothing else (no app logic).

Applicant `i` (slot index registered on-chain with the issuer root) encrypts TWO slot-encoded
ciphertexts:

```
ct_z : slot i = z_i = Σ_j w_j·x_j/cap + b      (the public-model logit, computed client-side)
ct_m : slot i = m_i ∈ [0, 1024)                (the output mask, kept in the browser)
```

every other slot zero, proven by the validity leg. The program computes

```
Z = Σ_i ct_z,i     M = Σ_i ct_m,i
out = σ_cubic(Z) + M,   σ_cubic(z) = 0.5 + 0.197·z − 0.004·z³
```

with two relinearized ct×ct products and three rescales, opening at level 3. Slot `i` of the opened
output is `σ(z_i) + m_i`; only applicant `i` can subtract `m_i`. Unused slots open as `σ(0) = 0.5`.
The linear, ceremony-free variant is kept as a library function
(`credit_linear_logit_policy`) — it needs no ct×ct and BFV could serve it equally well; it exists
for comparison, not for this app.

- Rust `e3_zk_helpers::threshold::ckks_credit_validity` (witness builder) ↔ Noir
  `ckks_credit_validity.nr` — pinned by the credit encoding tests and the Noir
  `test_credit_*` cases.
- WASM `encryptCreditAndWitness` (examples/ckks-common) ↔ Rust helper — pinned by
  `credit_bundle_matches_native_builder` (byte-equal TOMLs + commitments under a shared seed) and
  `credit_bundle_solves_all_three_ps4_legs` (nargo execute).
- Policy `credit_applicant_coefficients` uses the f64 path `x_j/cap + μ_j`; the integer form
  rounds identically (tested).

Why per-feature masks: multiplication by the fixed weight polynomial is a bijection of the ring,
so with a single mask the other opened coefficients are linear equations in the raw features.

## What is verified on-chain

| Stage | Verified on-chain by | Circuit |
| ----- | -------------------- | ------- |
| Participant input validity | `CkksAppE3ProgramBase` (three Honk proofs per submission) | `user_data_encryption_ckks_ct0/ct1_ps4` + the app-validity leg |
| Committee public key | `CkksPkVerifier` — one Honk proof PER committee member | `pk_generation_ckks_ps4` (C1-CKKS) |
| Decrypted output (the masked credit scores) | `CkksDecryptionVerifier` — one Honk proof | `decrypted_shares_aggregation_ckks_ps4` (C7-CKKS) |

No `MockPkVerifier` or `MockDecryptionVerifier` is registered for the CKKS scheme id. The
committee key is accepted only if EVERY member supplies a C1-CKKS proof that it knows a small
secret behind its pk share (the rogue-key gate), and the opened output is accepted only if the
C7-CKKS proof shows the published ring element is the threshold reconstruction of `T+1`
C6-committed decryption shares.

Bounds worth stating plainly. The on-chain key check does not prove the published aggregate key
is the SUM of the proven per-party shares (the circuit commits with SAFE/Poseidon over limb
coefficients, the chain commits with keccak256 over serialised bytes, and neither is recomputable
from the other in the EVM); the aggregator enforces that link off-chain. The output check does not
bind the published fixed-point bytes to the proven ring element, because CKKS decode (center mod
Q, divide by the scale, inverse FFT) is not EVM-tractable. Neither circuit carries a domain slot,
so there is no on-chain `e3Id`/committee replay binding.

**RISC0 program-correctness proving remains out of scope.** The homomorphic evaluation itself runs
natively in the server and its ciphertext output is published behind `MockCiphertextVerifier`.
That is the one honest remaining trust assumption in this demo.

## Run it

Prerequisites (repo root): `cargo build --release --bin interfold`; circuits compiled
(`cd circuits/bin/threshold && nargo compile --package user_data_encryption_ckks_ct0_ps4 --package user_data_encryption_ckks_ct1_ps4 --package ckks_credit_validity_ps4`);
committee artifacts staged (`bash scripts/stage-ckks-circuits.sh`, then
`cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture` must print
`c0..c7=proven ceremony=proven` for set 4); WASM package built
(`cd examples/ckks-common/packages/ckks-zk-inputs && pnpm build`); `pnpm install` here and in
`packages/interfold-contracts`.

```bash
cd examples/ckks-credit-scoring
pnpm install && pnpm build:server
pnpm dev:up                       # anvil + contracts + 5 nodes + server :8092 + client :5175
# in another shell, once the client prints "Local:":
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/e2e.mjs --window 600
```

Manual flow: open http://127.0.0.1:5175/rounds → "Request round" (default snapshot = anvil accounts
#6,#7,#8,#9,#0 with demo features; default model) → wait for the committee key (~1 min DKG, no
ceremony) → pick a dev wallet in the navbar → "Mask, encrypt, prove & apply" → after the window (or
"Evaluate now") and the threshold decryption, the round page shows every opened raw value and,
for the connected wallet, "Your score: 0.xxx — computed by the network; only you can read it".

Expected timings (Apple Silicon, release): DKG → key ≈ 60–75 s; browser encrypt+witness ≈ 0.2 s,
execute 0.1/0.25/0.25 s, prove app/ct1/ct0 ≈ 0.9/1.5/1.8 s (≈ 5 s per application incl. backend
init); `publishInput` ≈ 3 M gas; policy eval a few ms; threshold decrypt ≈ 3 s.

CLI alternative to the client for round opening: `cargo run --release --manifest-path server/Cargo.toml --bin cli -- open --duration 600`.
