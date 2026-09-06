# CKKS private matching on Interfold

A CRISP-shaped E3 program: two organisations (A and B) each encrypt a private 16-entry profile
vector **in the browser** (coefficient-encoded CKKS — A in the `forward` layout, B in the
`reversed` one — plus a cross-term mask), prove the encryptions are well-formed and correctly laid
out (five UltraHonk legs verified on-chain at `publishInput`), the program multiplies the two
encrypted vectors **under encryption**, and the threshold committee opens **one** ciphertext whose
coefficient 0 is `−⟨a, b⟩` — the compatibility score both parties see — while every other opened
coefficient is a mask-hidden cross term. Neither vector is ever revealed to the other party, the
coordination server, or the committee.

Trust split (binding): the ciphernode committee runs **no app logic** — it does the DKG, one
level-0 relinearization-key ceremony and one threshold decryption of the ciphertext the program
publishes. The policy (`e3_trckks::policy::matching_score_policy`) runs in `program/`, called by
the coordination server.

```
round opener ──[A, B]──▶ CkksMatchingE3Program.registerRound(e3Id, [A, B])   (slot = role)
                                   ▲
party A browser: a ∈ [-1,1]^16, m_a ∈ [0,1024)^128 ─▶ forward(a), mask(m_a) ─▶ CKKS encrypt ×2 (WASM)
party B browser: b ∈ [-1,1]^16, m_b ∈ [0,1024)^128 ─▶ reversed(b), mask(m_b) ─▶ CKKS encrypt ×2 (WASM)
                 ─▶ 2 × (Greco ct0 + ct1) + matching validity leg (bb.js) ─▶ wallet publishInput ─┘
server:  reads both pairs from calldata ─▶ relin(f_a · r_b) + m_a + m_b ─▶ publishCiphertextOutput
committee: threshold decrypt ─▶ 64 coefficients at 4 decimals; c_0 = −⟨a, b⟩
browser: score = −opened[0]
```

## Layout

| path | what |
| --- | --- |
| `program/` | `ckks-matching-program`: `Role`, `RoundInputs` (`[f_a, r_b, m_a, m_b]`), `matching_score_policy` wrapper under `rlk_level_0.bin`, `decode_opened` (64 × 4 decimals), `score_from_opened` (= `−opened[0]`) |
| `server/` | actix-web + sled on **:8093** — round opener (E3 request + `registerRound([A, B])`), indexer (recovers both cts from calldata; evaluates as soon as both parties are in), evaluator (runs the program, publishes the output), API. Holds **no vectors and no masks** |
| `packages/ckks-matching-sdk` | TS: `encryptAndProveSubmission` (WASM `encryptCoefficientsAndWitness` ×2 + 5 Honk legs), `layoutVectors` (forward / reversed / mask — the policy's contract), `publishSubmission` (wallet-bound nested-tuple envelope), `scoreFromOpened`, `expectedScore` |
| `client/` | Vite React on **:5176** — wallet (anvil dev keys / injected), submit flow with per-stage timings and a "prove the wrong layout" dev toggle, results (the score, both parties) |
| `scripts/dev.sh` | anvil → deploy (mocks + `CkksMatchingE3Program` + ParamSet 5) → 5 ciphernodes → server → client |
| `scripts/e2e.mjs` | headless-Chrome e2e (playwright): out-of-range rejection, wrong-layout (`WrongRole`) rejection, both parties accepted, patched-role + replay reverts, score = fixed-point ⟨a, b⟩, cross-term masking assertion |
| `scripts/prove-node.mjs` | the same SDK pipeline in Node for both parties against the ps5 fixture key (no chain) |

Circuit + contract side (repo root): `circuits/lib/src/core/threshold/ckks_matching_validity.nr`
(+ codegen'd `configs/ckks_matching_ps5.nr`), bin `circuits/bin/threshold/ckks_matching_validity_ps5`,
witness module `crates/zk-helpers/src/circuits/threshold/ckks_matching_validity.rs`, Prover.toml
generator `crates/zk-helpers/examples/gen_ckks_matching_prover.rs`, fixtures
`scripts/ckks-matching-fixtures.sh` → `packages/interfold-contracts/test/fixtures/ckks_matching_ps5/`,
contract `packages/interfold-contracts/contracts/test/CkksMatchingE3Program.sol` + spec.

## Encoding contract (pinned by tests)

ParamSet 5: N = 512, moduli `[0xffffee001, 0xffffc4001, 0xffffba001]`, Δ = 2^40, opens at level 1,
`RelinCeremonyPlan::PerLevel([0])` — ONE ciphertext × ciphertext product under the committee's
level-0 key, one rescale. Coefficient encoding (`CkksEncoder::encode_coefficients`): coefficient
`k` of the plaintext is exactly `round(Δ · v_k)` — no cosine table, no slots. `Polynomial<N>` in
Noir stores DESCENDING degree: coefficient `k` is `coefficients[N−1−k]`.

| layout | non-zero coefficients | value |
| --- | --- | --- |
| `forward(a)` (A, role 0, slot 0) | `1..=16` | `a_j` at coefficient `j+1` |
| `reversed(b)` (B, role 1, slot 1) | `N−16..=N−1` | `b_j` at coefficient `N−j−1` |
| `mask(m)` (both) | `1..=128` | `m_j ∈ [0, 1024)` integer at coefficient `j+1` |

Vector entries are fixed point `v = V / 2^16` with `|v| ≤ 1` (cap-normalised in the browser:
`x / cap`). The validity leg (`ckks_matching_validity_ps5`) proves, for the SAME two message
polynomials the Greco ct0 legs commit to: `|V_j| ≤ 2^16`; the vector message is EXACTLY the
role's layout of `values` (`|2^16·c_k − Δ·V_j| ≤ 2^15 + 8`, every other coefficient 0); the mask
message has `Δ·m_j` with `m_j < 1024` on `1..=128`, 0 elsewhere; and returns
`(m_commitment_vec, m_commitment_mask)` via `commit_message::<N, BIT_M>` with the ps5 Greco `BIT_M`.
Public inputs, in on-chain word order: `[role, address, index, m_commitment_vec, m_commitment_mask]`.

`forward(a) · reversed(b)` has `−⟨a, b⟩` on coefficient 0 (the `t^N ≡ −1` wrap) — **the app
negates**. Coefficients `1..` carry `−Σ_{i−j=k} a_i b_j + m_a,k + m_b,k`: masked cross terms, no
usable signal. The published plaintext is the first **64** coefficients at **4** decimals
(`int128[]`, big-endian; `CkksMatchingE3Program.verifyOutput` checks the 1024-byte length).

## On-chain gate (`CkksMatchingE3Program`)

`registerRound(e3Id, [A, B])` — exactly two distinct non-zero parties, once, by the owner; slot
= position. `publishInput(e3Id, abi.encode(MatchingSubmission))` — a single NESTED tuple
`((bytes,bytes,bytes32[],bytes,bytes32[]), (bytes,bytes,bytes32[],bytes,bytes32[]), bytes, bytes32[])`
(vector pair, mask pair, validity proof + 5 words). Checks, before any Honk verify: `u_commitment`
equal across ct0/ct1 of each pair; `m_commitment` of each ct0 leg equal to the validity leg's
word; `address == msg.sender`; `index` == the sender's registered slot; `role == index`; one
submission per sender; every `u_commitment` new. Then five UltraHonk verifies (~5 M gas).
`capInConstructor: false` in `ckksAppProgram.ts`: inputs are already normalised (cap 1), so the
constructor takes the three verifiers only (like credit / treasury / fedavg).

## Honest scope

- Insecure N=512 demo params; 20 smudging bits vs the ~78 the calculator requires at λ=50.
- Cross-term mask hiding ratio is 2^10 (DEMO), not statistical: each opened cross term is
  `−Σ a_i b_j` (|·| ≤ 16) plus two uniform integers in `[0, 1024)`.
- The published plaintext bytes are not bound to the C7 proof's `u_global` (decode gap).
- RISC0 program-correctness out; the policy runs natively in `program/` and its ciphertext output
  is published behind `MockCiphertextVerifier`. That is the one honest remaining trust assumption.
- The score `⟨a, b⟩` itself is public to both parties (and to anyone reading the chain): that IS
  the output. With a 16-entry vector, a party that submits a one-hot vector learns one entry of
  the other's — inherent to inner-product matching, not a leak of the protocol.
- Neither Greco leg nor the validity leg carries a domain slot, so there is no on-chain
  `e3Id`/committee replay binding beyond the per-E3 `u_commitment` set.

## Run it

Prerequisites (repo root): `cargo build --release --bin interfold`; circuits compiled
(`cd circuits/bin/threshold && ~/.nargo/bin/nargo compile --package user_data_encryption_ckks_ct0_ps5 --package user_data_encryption_ckks_ct1_ps5 --package ckks_matching_validity_ps5`);
committee artifacts staged (`bash scripts/stage-ckks-circuits.sh`, then
`cargo test -p e3-zk-prover --release --test ckks_staged_artifacts -- --ignored --nocapture` must print
`c0..c7=proven ceremony=proven` for set 5); WASM package built
(`cd examples/ckks-common/packages/ckks-zk-inputs && pnpm build`); `pnpm install` here and in
`packages/interfold-contracts`.

```bash
cd examples/ckks-matching
pnpm install && pnpm build:server
pnpm dev:up                       # anvil + contracts + 5 nodes + server :8093 + client :5176
# in another shell, once the client prints "Local:":
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node scripts/e2e.mjs --window 600
```

Manual flow: open http://127.0.0.1:5176/rounds → "Request round" (default parties = anvil #6 as A,
#7 as B) → wait for the committee key (~1 min DKG + level-0 ceremony) → pick "anvil #6 (party A)"
in the navbar → round page shows "You are party A (slot 0) · layout forward" with the demo vector
→ "Encrypt forward + mask, prove 5 legs & submit" → switch to "anvil #7 (party B)" → same with the
reversed layout → the server evaluates as soon as both are in ("Evaluate now" is the manual
fallback) → after the threshold decryption the round page shows "Compatibility score ⟨a, b⟩ =
−2.4275" (demo vectors) for either wallet, and the 64 raw opened coefficients under a disclosure.

Evidence in the server / node logs: `CKKS proof posture:` (node boot), `C1-CKKS verified for all`
(committee key), `SubmissionPublished slot 0 (A, forward layout)` / `slot 1 (B, reversed layout)`
(both gates passed), `both parties submitted — evaluating now`, `ciphertext output published`,
`C6-CKKS d_commitment verified` (threshold decryption), `PlaintextOutputPublished: 64 coefficients
opened — score = −c_0 = …`.

Expected timings (Apple Silicon, release): DKG + ceremony → key ≈ 60–90 s; browser encrypt+witness
≈ 0.2 s ×2, prove app/ct1/ct0 ≈ 1.2/1.0/1.2 s per leg (≈ 8 s per submission incl. backend init);
`publishInput` ≈ 5 M gas; policy eval a few ms; threshold decrypt ≈ 3 s.

CLI alternative to the client for round opening:
`cargo run --release --manifest-path server/Cargo.toml --bin cli -- open --duration 600`.
