# CKKS private federated averaging on Interfold

A CRISP-shaped E3 program: each client encrypts its model update **and its private dataset size**
in the browser (coefficient-encoded CKKS, two ciphertexts), proves both encryptions are well-formed
and the update is bounded (five UltraHonk legs verified on-chain at `publishInput`), the program
computes the **sample-weighted sum** of the updates under encryption — one ciphertext × ciphertext
product per client under the committee's level-0 relinearization key — and the threshold committee
opens **one** ciphertext whose coefficients are `Σ nᵢ·gᵢ` and `Σ nᵢ`. True FedAvg where neither any
client's update nor its dataset size is revealed: the network weights by the private counts
homomorphically.

Trust split (binding): the ciphernode committee runs **no app logic** — it does the DKG, one
level-0 relin ceremony and one threshold decryption of the ciphertext the program publishes. The
policy (`e3_trckks::policy::federated_average_policy`) runs in `program/`, called by the
coordination server.

```
opener ──(normBound, minClients, clients[])──▶ CkksFedAvgE3Program.registerRound(e3Id, …)
                                                          ▲
client browser: g ∈ [−1,1]^d, n ∈ [1,1024) ─▶ gradient_block(g), constant(n) ─▶ CKKS encrypt ×2 (WASM)
              ─▶ Greco ct0/ct1 ×2 + fedavg validity leg (bb.js) ─▶ wallet publishInput ─────┘
server:  reads every ct pair from calldata ─▶ Σᵢ ct(nᵢ) × ct(gᵢ) [relin level 0, rescale] ─▶ publishCiphertextOutput
committee: threshold decrypt ─▶ opened[j+1] = Σᵢ nᵢ·g_ij (j < d),  opened[d+1] = Σᵢ nᵢ
everyone: mean_j = opened[j+1] / opened[d+1]
```

## Layout

| path | what |
| --- | --- |
| `program/` | `ckks-fedavg-program`: `RoundParams` (d, norm bound, min clients), `evaluate` (`federated_average_policy` under `RelinKeys::load_from_dir(dir, params, &[0])`), `decode_opened`, `weighted_mean` |
| `server/` | actix-web + sled on **:8095** — round opener (E3 request + on-chain `registerRound`), indexer (recovers both cts from calldata), evaluator (refuses below `min_clients`, runs the program, publishes the output), API. Holds **no updates and no counts** |
| `packages/ckks-fedavg-sdk` | TS: `encryptAndProveUpdate` (WASM `encryptCoefficientsAndWitness` ×2 + 5 Honk legs), `publishUpdate` (wallet-bound nested envelope), `weightedMean`, `FedAvgApi` |
| `client/` | Vite React on **:5178** — wallet (anvil dev keys / injected), submit flow with per-stage timings, results (the d averaged coordinates + total sample count) |
| `scripts/dev.sh` | anvil → deploy (mocks + `CkksFedAvgE3Program` + ParamSet 5) → 5 ciphernodes → server → client |
| `scripts/e2e.mjs` | headless-Chrome e2e (playwright): 3 clients, over-bound rejection, below-minimum refusal, wrong-bound / patched-index / replay reverts, weighted-mean assertion |
| `scripts/prove-node.mjs` | the same SDK pipeline in Node against the ps5 fixture key (no chain) — proves all 5 legs |

Repo-level pieces: circuit `circuits/bin/threshold/ckks_fedavg_validity_ps5` (lib module
`circuits/lib/src/core/threshold/ckks_fedavg_validity.nr`, configs
`circuits/lib/src/configs/ckks_fedavg_ps5.nr`), witness module
`crates/zk-helpers/src/circuits/threshold/ckks_fedavg_validity.rs` + example
`gen_ckks_fedavg_prover.rs`, contract `packages/interfold-contracts/contracts/test/CkksFedAvgE3Program.sol`
+ `test/CkksFedAvgE3Program.spec.ts` (real fixtures from `scripts/ckks-fedavg-fixtures.sh`).

## Encoding contract (pinned by tests)

ParamSet 5: N = 512, moduli `[0xffffee001, 0xffffc4001, 0xffffba001]`, Δ = 2^40,
`RelinCeremonyPlan::PerLevel([0])` — one ct×ct product relinearised at level 0, one rescale, opened
at level 1. The committee runs **DKG + a level-0 relin ceremony + one threshold decryption**, and
nothing else.

Client `i` (slot index = its position in the registered list) encrypts TWO coefficient-encoded
ciphertexts (`e3_trckks::policy::coefficient_layout`):

```
gradient_block(g) : coefficient j+1 = g_j (j < d),  coefficient d+1 = 1.0,  all others 0
constant(n)       : coefficient 0   = n,                                  all others 0
```

The program computes `Σᵢ constant(nᵢ) × gradient_block(gᵢ)`: scalar × vector, so there are NO cross
terms and no masks are needed. The output is `int128[64]` at 4 decimals
(`e3_trckks::program::decode_fixed_point_output`): `opened[j+1] = Σᵢ nᵢ·g_ij`, `opened[d+1] = Σᵢ nᵢ`,
coefficient 0 ≈ 0. `d` is public per round and compiled into the circuit (`CKKS_FEDAVG_D = 8`,
`d ≤ 62` so the block fits the published window).

The validity leg `ckks_fedavg_validity_ps5` (private `m_grad`, `m_count`, `g[d]` as 2^16 fixed-point
words with negatives as `p − |V|`, `count`; public `norm_bound` (2^32 fixed point), `address`,
`index`) proves: `|g_j| ≤ 2^16`; `Σ_j G_j² ≤ norm_bound` in exact integer arithmetic (the poisoning
bound); `1 ≤ count < 1024`; `m_grad` is `gradient_block(g)` at Δ = 2^40 within the encoder slack
(`|2^16·c_{j+1} − Δ·G_j| ≤ 2^15 + slack`, `c_{d+1} == Δ`, all others 0); `m_count` has `c_0 == Δ·count`
and all others 0; and returns `(m_commitment_grad, m_commitment_count)` (`commit_message::<N, BIT_M>`).
The contract equates each `m_commitment` with its Greco ct0 leg, each `u_commitment` across
ct0/ct1, binds `address` to `msg.sender`, `index` to the registered slot and `norm_bound` to the
round's — one update per sender, `u` replay refused.

- Rust `e3_zk_helpers::threshold::ckks_fedavg_validity` (witness builder + native pre-check) ↔ Noir
  `ckks_fedavg_validity.nr` — pinned by `small_vectors_match_noir_test_vectors` and the checked-in
  configs test.
- WASM `encryptCoefficientsAndWitness` (examples/ckks-common) ↔ Rust `try_encrypt_extended` path —
  `scripts/prove-node.mjs` proves all five legs from the SDK; the hardhat spec accepts the native
  fixture through the same contract.

## What is verified on-chain

| Stage | Verified on-chain by | Circuit |
| ----- | -------------------- | ------- |
| Client input validity | `CkksFedAvgE3Program` (five Honk proofs per submission) | `user_data_encryption_ckks_ct0/ct1_ps5` ×2 + `ckks_fedavg_validity_ps5` |
| Committee public key | `CkksPkVerifier` — one Honk proof PER committee member | `pk_generation_ckks_ps5` (C1-CKKS) |
| Decrypted output (the weighted aggregate) | `CkksDecryptionVerifier` — one Honk proof | `decrypted_shares_aggregation_ckks_ps5` (C7-CKKS) |

No `MockPkVerifier` or `MockDecryptionVerifier` is registered for the CKKS scheme id.

## Honest scope

- **The aggregate is public.** Once opened, `Σ nᵢ·gᵢ` and `Σ nᵢ` are on-chain plaintext; with few
  clients this is the usual FedAvg leakage (two clients can each subtract their own contribution).
  The server enforces the round's public minimum client count (demo 3) before evaluating; that is
  a policy knob, not a differential-privacy guarantee.
- Insecure N=512 demo params; 20 smudging bits vs the ~78 the calculator requires at λ=50.
- Cross-term mask hiding ratio is 2^10 (DEMO), not statistical — not used here (no cross terms),
  stated for parity with the other ParamSet 5 apps.
- The published plaintext bytes are not bound to the C7 proof's `u_global` (decode gap).
- RISC0 program-correctness proving is out of scope; the policy runs natively in `program/` and its
  ciphertext output is published behind `MockCiphertextVerifier`.
- The norm bound limits a single poisoned update's magnitude, not its direction; the count bound
  (< 1024) limits how much one client can weight itself. Neither is Byzantine-robust aggregation.

## Run it

Prerequisites (repo root): `cargo build --release --bin interfold`; circuits compiled
(`cd circuits/bin/threshold && nargo compile --package user_data_encryption_ckks_ct0_ps5 --package user_data_encryption_ckks_ct1_ps5 --package ckks_fedavg_validity_ps5`);
committee artifacts staged (`bash scripts/stage-ckks-circuits.sh`, then
`cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture` must print
`c0..c7=proven ceremony=proven` for set 5); WASM package built
(`cd examples/ckks-common/packages/ckks-zk-inputs && pnpm build`); `pnpm install` here and in
`packages/interfold-contracts`.

```bash
cd examples/ckks-federated-averaging
pnpm install && pnpm build:server
pnpm dev:up                       # anvil + contracts + 5 nodes + server :8095 + client :5178
# in another shell, once the client prints "Local:":
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/e2e.mjs --window 600
```

Manual flow: open http://127.0.0.1:5178/rounds → "Request round" (default clients = anvil #6–#9,
bound 2.0, min clients 3) → wait for the committee key (DKG + level-0 ceremony) → pick a dev wallet
in the navbar → the page pre-fills that slot's demo update and count → "Encrypt update + count,
prove 5 legs & submit" → repeat for ≥ 3 wallets → after the window (or "Evaluate now") and the
threshold decryption, the round page shows "Total samples" and the d weighted-mean coordinates.

Node-only smoke (no chain): `node scripts/prove-node.mjs` — proves all five legs against the ps5
fixture key (≈ 9 s on Apple Silicon: encrypt 0.3 s, prove app/ct1G/ct0G/ct1C/ct0C ≈
0.4/1.5/1.6/2.8/1.5 s).

CLI alternative to the client for round opening: `cargo run --release --manifest-path server/Cargo.toml --bin cli -- open --duration 600`.
`dev_cipher.sh` shares `CKKS_RELIN_KEY_DIR` with the nodes (default `/tmp/ckks-relin-keys`).
