# CKKS private treasury risk on Interfold

A CRISP-shaped E3 program: **n DAOs** each encrypt a private exposure vector over 4 public assets
**in the browser** (coefficient-encoded CKKS — `forward(x)`, `reversed(w ∘ x)` under the round's
PUBLIC risk weights `w`, plus a cross-term `mask(m)` — three ciphertexts), prove the encryptions
are well-formed and correctly laid out (seven UltraHonk legs verified on-chain at `publishInput`),
the program sums every DAO's ciphertexts and multiplies the two sums **under encryption**, and
the threshold committee opens **one** ciphertext whose coefficient 0 is
`−Σ_a w_a (Σ_i x_{i,a})²` — the weighted concentration risk of the COMBINED book — while every
other opened coefficient is a mask-hidden cross term. No DAO's book, and not even the aggregate
book, is ever revealed to another DAO, the coordination server, or the committee.

Trust split (binding): the ciphernode committee runs **no app logic** — it does the DKG, one
level-0 relinearization-key ceremony and one threshold decryption of the ciphertext the program
publishes. The policy (`e3_trckks::policy::treasury_risk_policy`) runs in `program/`, called by
the coordination server.

```
round opener ──(w[4], daos[])──▶ CkksTreasuryE3Program.registerRound(e3Id, weights, daos)   (slot = position)
                                   ▲
DAO i browser: x_i ∈ [0,1]^4, m_i ∈ [0,1024)^128 ─▶ forward(x_i), reversed(w∘x_i), mask(m_i) ─▶ CKKS encrypt ×3 (WASM)
               ─▶ 3 × (Greco ct0 + ct1) + treasury validity leg (bb.js) ─▶ wallet publishInput ─┘
server:  reads every triple from calldata ─▶ relin(Σf_i · Σr_i) + Σm_i ─▶ publishCiphertextOutput
committee: threshold decrypt ─▶ 64 coefficients at 4 decimals; c_0 = −Σ_a w_a (Σ_i x_{i,a})²
browser: risk = −opened[0]
```

## Layout

| path | what |
| --- | --- |
| `program/` | `ckks-treasury-program`: `Weights` / `FixedPointWeights`, `DaoInputs = (fwd, rev, mask)`, `treasury_risk_policy` wrapper under `rlk_level_0.bin` (`level_0_key`), `MIN_DAOS = 2`, `decode_opened` (64 × 4 decimals), `risk_from_opened` (= `−opened[0]`), `expected_risk` |
| `server/` | actix-web + sled on **:8094** — round opener (E3 request + `registerRound(weights, daos)`), indexer (recovers all three cts from calldata; evaluates as soon as every registered DAO is in, or at the window close with ≥ 2), evaluator (runs the program, publishes the output), API. Holds **no exposures and no masks** |
| `packages/ckks-treasury-sdk` | TS: `encryptAndProveSubmission` (WASM `encryptCoefficientsAndWitness` ×3 + 7 Honk legs), `layoutVectors` (forward / reversed(w∘x) / mask — the policy's contract), `weightWords` (`p − |W|` on-chain words), `publishSubmission` (wallet-bound nested-tuple envelope), `riskFromOpened`, `expectedRisk` |
| `client/` | Vite React on **:5177** — wallet (anvil dev keys / injected), round opener form (4 weights + DAO list), submit flow (4 exposures + cap, per-stage timings, a "prove under the wrong weights" dev toggle), results (the risk + what is / is not revealed) |
| `scripts/dev.sh` | anvil → deploy (mocks + `CkksTreasuryE3Program` + ParamSet 5) → 5 ciphernodes → server → client |
| `scripts/e2e.mjs` | headless-Chrome e2e (playwright): out-of-range rejection, wrong-weights (`WrongWeights`) rejection, three DAOs accepted, patched-weight + replay reverts, risk = fixed-point oracle, cross-term masking assertion |
| `scripts/prove-node.mjs` | the same SDK pipeline in Node for two DAOs against the ps5 fixture key (no chain) |

Circuit + contract side (repo root): `circuits/lib/src/core/threshold/ckks_treasury_validity.nr`
(+ codegen'd `configs/ckks_treasury_ps5.nr`), bin `circuits/bin/threshold/ckks_treasury_validity_ps5`
(1976 ACIR opcodes), witness module `crates/zk-helpers/src/circuits/threshold/ckks_treasury_validity.rs`,
Prover.toml generator `crates/zk-helpers/examples/gen_ckks_treasury_prover.rs`, fixtures
`scripts/ckks-treasury-fixtures.sh` → `packages/interfold-contracts/test/fixtures/ckks_treasury_ps5/`,
contract `packages/interfold-contracts/contracts/test/CkksTreasuryE3Program.sol` + spec.

## Encoding contract (pinned by tests)

ParamSet 5: N = 512, moduli `[0xffffee001, 0xffffc4001, 0xffffba001]`, Δ = 2^40, opens at level 1,
`RelinCeremonyPlan::PerLevel([0])` — ONE ciphertext × ciphertext product under the committee's
level-0 key, one rescale. Coefficient encoding (`CkksEncoder::encode_coefficients`): coefficient
`k` of the plaintext is exactly `round(Δ · v_k)` — no cosine table, no slots. `Polynomial<N>` in
Noir stores DESCENDING degree: coefficient `k` is `coefficients[N−1−k]`.

| layout | non-zero coefficients | value |
| --- | --- | --- |
| `forward(x)` | `1..=4` | `x_a` at coefficient `a+1`, `0 ≤ x_a ≤ 1` |
| `reversed(w ∘ x)` | `N−4..=N−1` | `w_a · x_a` at coefficient `N−a−1` |
| `mask(m)` | `1..=128` | `m_j ∈ [0, 1024)` integer at coefficient `j+1` |

Exposures are fixed point `x = X / 2^16` with `0 ≤ x ≤ 1` (cap-normalised in the browser:
`exposure / cap`); weights are `w = W / 2^16` with `|w| ≤ 1`, and negative weights travel as the
field word `p − |W|`. The validity leg (`ckks_treasury_validity_ps5`) proves, for the SAME three
message polynomials the Greco ct0 legs commit to: `0 ≤ X_a ≤ 2^16`; the forward message is
EXACTLY `forward(x)`; the reversed message is EXACTLY `reversed(w ∘ x)` under the PUBLIC `w`
(`|2^16·c_k − Δ·W_a·X_a/2^16| ≤ 2^15 + 8`, every other coefficient 0); the mask message has
`Δ·m_j` with `m_j < 1024` on `1..=128`, 0 elsewhere; and returns
`(m_commitment_fwd, m_commitment_rev, m_commitment_mask)` via `commit_message::<N, BIT_M>` with the
ps5 Greco `BIT_M`. Public inputs, in on-chain word order (9 words):
`[w_0..w_3, address, index, m_commitment_fwd, m_commitment_rev, m_commitment_mask]`.

`forward(F) · reversed(R)` has `−⟨F, R⟩ = −Σ_a (Σ_i x_{i,a}) · w_a (Σ_i x_{i,a})` on coefficient 0
(the `t^N ≡ −1` wrap) — **the app negates**. Coefficients `1..` carry `−Σ_{a−b=k} F_a R_b + Σ_i m_{i,k}`:
masked cross terms, no usable signal. The published plaintext is the first **64** coefficients at
**4** decimals (`int128[]`, big-endian; `CkksTreasuryE3Program.decodeOutput` checks the 1024-byte
length, `riskFromOutput` returns `−words[0]`).

## On-chain gate (`CkksTreasuryE3Program`)

`registerRound(e3Id, bytes32[4] weights, address[] daos)` — non-empty, distinct DAOs, once, by
the owner; slot = position; the weight words are stored. `publishInput(e3Id,
abi.encode(TreasurySubmission))` — a single NESTED tuple
`((bytes,bytes,bytes32[],bytes,bytes32[]) ×3, bytes, bytes32[])` (forward pair, reversed pair,
mask pair, validity proof + 9 words). Checks, before any Honk verify: `u_commitment` equal across
ct0/ct1 of each pair; `m_commitment` of each ct0 leg equal to the validity leg's word;
`address == msg.sender`; `index` == the sender's registered slot; the four weight words == the
round's registered weights; one submission per sender; every `u_commitment` new and distinct.
Then seven UltraHonk verifies. **Measured** (hardhat spec, real bb proofs): `publishInput` =
**20,037,798 gas**, calldata **105,600 bytes**. `capInConstructor: false` / cap `1n` in
`ckksAppProgram.ts` + `deployMocks.ts`: inputs are already normalised, so the constructor takes
the three verifiers only.

## Honest scope

- Insecure N=512 demo params; 20 smudging bits vs the ~78 the calculator requires at λ=50.
- Cross-term mask hiding ratio is 2^10 (DEMO), not statistical: each opened cross term is
  `−Σ F_a R_b` (|·| ≤ n²·4) plus `n` uniform integers in `[0, 1024)`.
- The published plaintext bytes are not bound to the C7 proof's `u_global` (decode gap).
- RISC0 program-correctness out; the policy runs natively in `program/` and its ciphertext output
  is published behind `MockCiphertextVerifier`. That is the one honest remaining trust assumption.
- The risk scalar itself is public to every DAO (and to anyone reading the chain): that IS the
  output. With two DAOs a DAO that knows its own book learns
  `Σ_a w_a (x_a + y_a)² − …` — one scalar constraint on the other's book, inherent to the
  functionality, not a leak of the protocol. The server refuses to evaluate with fewer than
  `MIN_DAOS = 2` submissions (one DAO's aggregate is its own book).
- Neither Greco leg nor the validity leg carries a domain slot, so there is no on-chain
  `e3Id`/committee replay binding beyond the per-E3 `u_commitment` set.

## Run it

Prerequisites (repo root): `cargo build --release --bin interfold`; circuits compiled
(`cd circuits/bin/threshold && ~/.nargo/bin/nargo compile --package user_data_encryption_ckks_ct0_ps5 --package user_data_encryption_ckks_ct1_ps5 --package ckks_treasury_validity_ps5`);
committee artifacts staged (`bash scripts/stage-ckks-circuits.sh`, then
`cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture` must print
`c0..c7=proven ceremony=proven` for set 5); WASM package built
(`cd examples/ckks-common/packages/ckks-zk-inputs && pnpm build`); `pnpm install` here and in
`packages/interfold-contracts`.

```bash
cd examples/ckks-treasury-risk
pnpm install && pnpm -r build && pnpm build:server
node scripts/prove-node.mjs        # no chain: 2 DAOs × 7 legs against the ps5 fixture key → PROVE-NODE OK
pnpm dev:up                        # anvil + contracts + 5 nodes + server :8094 + client :5177
# in another shell, once the client prints "Local:":
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/e2e.mjs --window 600
```

Manual flow: open http://127.0.0.1:5177/rounds → weights default to the fixture's
`[0.5, −0.25, 1.0, 0.125]`, DAOs default to anvil #6, #7, #8 → "Request round" → wait for the
committee key (~1 min DKG + level-0 ceremony) → pick "anvil #6 (DAO 0)" in the navbar → round page
shows "You are DAO slot 0" with the demo book `[30, 10, 45, 15]` (cap 100) → "Encrypt forward +
reversed(w∘x) + mask, prove 7 legs & submit" → switch to "anvil #7 (DAO 1)" and "anvil #8 (DAO 2)"
→ same → the server evaluates as soon as all three are in ("Evaluate now" is the manual fallback
once ≥ 2 submitted) → after the threshold decryption the round page shows "Weighted concentration
risk = …" for any wallet, with a paragraph on what is and is not revealed, and the 64 raw opened
coefficients under a disclosure. Demo books give
`Σ_a w_a (Σ_i x_{i,a})² = 0.5·0.55² − 0.25·0.60² + 1.0·0.70² + 0.125·0.55² ≈ 0.5891`.

Evidence in the server / node logs: `CKKS proof posture:` (node boot), `C1-CKKS verified for all`
(committee key), `SubmissionPublished slot 0: DAO …` / `slot 1` / `slot 2` (gates passed, 7 Honk
proofs each), `all 3 DAOs submitted — evaluating now`, `ciphertext output published`,
`C6-CKKS d_commitment verified` (threshold decryption), `PlaintextOutputPublished: 64 coefficients
opened — risk = −c_0 = …`.

Expected timings (Apple Silicon, release): DKG + ceremony → key ≈ 60–90 s; browser encrypt+witness
≈ 0.2 s ×3, prove app/ct1/ct0 ≈ 1.2/1.0/1.2 s per leg (≈ 12 s per submission incl. backend init);
`publishInput` = 20.0 M gas; policy eval a few ms; threshold decrypt ≈ 3 s.

CLI alternative to the client for round opening:
`cargo run --release --manifest-path server/Cargo.toml --bin cli -- open --duration 600`
(`--weights 0.5,-0.25,1,0.125 --dao 0x… --dao 0x…` to override).
