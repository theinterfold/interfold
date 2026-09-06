# ParamSet 5 apps — shared decisions (matching / treasury / federated averaging)

Written 2026-09-05 as the single source of truth for the three parallel app builds.
Every brief points here. **Nothing on the committee changes for these apps** — it runs
DKG + a level-0 relin ceremony + threshold decryption, exactly as for ParamSet 3.

## Already DONE (do not redo, do not re-derive)

| layer | what | where |
|---|---|---|
| params | ParamSet 5 = `[0xffffee001, 0xffffc4001, 0xffffba001]`, Δ=2^40, opens at level 1, `PerLevel([0])` | `crates/fhe-params/src/ckks_presets.rs` (`COEFFICIENT_*`), `crates/trckks/src/config.rs::coefficient_transport_params` |
| output layout | `OutputLayout::Coefficients` → first **64** coefficients at **4** decimals (`int128[]` big-endian on-chain) | `crates/trckks/src/program.rs` (`COEFFICIENT_OUTPUT_COUNT`, `COEFFICIENT_OUTPUT_DECIMALS`) |
| policies | `matching_score_policy`, `treasury_risk_policy`, `federated_average_policy` + `coefficient_layout::{forward,reversed,mask,gradient_block,constant}` | `crates/trckks/src/policy.rs` (3 e2e tests green: real DKG + ceremony + threshold open) |
| circuit names | `PkGenerationCkksPs5`, `ShareDecryptionCkksPs5`, `DecryptedSharesAggregationCkksPs5` | `crates/events/src/interfold_event/proof.rs` (append-only) |
| Greco preset | `ckks_preset_for_param_set(5)` with `input_bound = 1024.0` | `crates/zk-helpers/.../user_data_encryption_ckks/circuit.rs` |
| Noir configs | `ckks_ps5.nr`, `ckks_pk_generation_ps5.nr`, `ckks_share_decryption_ps5.nr`, `ckks_aggregation_ps5.nr` (codegen'd) | `circuits/lib/src/configs/` |
| Noir bins | `pk_generation_ckks_ps5`, `share_decryption_ckks_ps5`, `decrypted_shares_aggregation_ckks_ps5`, `user_data_encryption_ckks_ct{0,1}_ps5` — all compile + execute | `circuits/bin/threshold/` |
| Solidity verifiers | `PkGenerationCkksPs5Verifier`, `DecryptedSharesAggregationCkksPs5Verifier`, `UserDataEncryptionCkksCt{0,1}Ps5Verifier` | `packages/interfold-contracts/contracts/verifiers/bfv/honk/` |
| deploy wiring | ps5 rows in `CKKS_PK_CIRCUIT_VERIFIERS` / `CKKS_DECRYPTION_CIRCUIT_VERIFIERS` | `scripts/deployAndSave/ckks{Pk,Decryption}Verifier.ts` |
| staging | ps5 committee circuits in `stage-ckks-circuits.sh` and `scaffold-ckks-c6c7-bins.sh` | `scripts/` |

## Encoding contract (PIN THIS ON BOTH SIDES — circuit and client)

N = 512. `Polynomial<N>` in Noir stores DESCENDING degree: coefficient `k` is `coefficients[N-1-k]`.
Coefficient-encoded plaintext: integer coefficient `c_k = round(Δ · v_k)`, Δ = 2^40. NO cosine
table, NO slots — the encoding check is a direct per-coefficient equality
`c_k == round(Δ · v_k)` where `v_k` comes from the circuit's public/private inputs in fixed point.

| layout | non-zero coefficients | value |
|---|---|---|
| `forward(a)`, k ≤ 64 | `1..=k` | `a_{j}` at coefficient `j+1` |
| `reversed(b)`, k ≤ 64 | `N-k..=N-1` | `b_j` at coefficient `N-j-1` |
| `mask(m)`, width 128 | `1..=128` | `m_j` at coefficient `j+1`, `m_j ∈ [0, 1024)` integer |
| `gradient_block(g)`, d ≤ 62 | `1..=d` and `d+1` | `g_j` at `j+1`; `1.0` at `d+1` |
| `constant(n)` | `0` | `n` |

All other coefficients MUST be proven zero. Fixed point for real values: `v = V / 2^16`
(`WEIGHT_FRAC_BITS = 16`, same as credit). Range: `|v| ≤ 1` for vector entries (cap-normalised
by the app: `x/cap`), masks and counts are integers `< 2^10`.

`forward(a)·reversed(b)` has `−⟨a,b⟩` on coefficient 0 (the `t^N ≡ −1` wrap). **The app
negates.** For federated averaging (scalar × vector) there is no wrap and no sign.

## Per-app submission and legs

| app | party submits | Greco pairs | validity leg proves | legs |
|---|---|---|---|---|
| matching | A: `forward(a)`, `mask(m_a)`; B: `reversed(b)`, `mask(m_b)` | 2 | (role-dependent) layout of ct_vec per role bit; `|a_j| ≤ 1`; mask layout + range; both `m_commitment`s | 5 |
| treasury | `forward(x)`, `reversed(w∘x)`, `mask(m)` | 3 | both layouts, `x_a ∈ [0,1]`, `r_a = w_a·x_a` with PUBLIC `w` (fixed point, 2^16), mask layout + range; three `m_commitment`s | **7** |
| federated | `gradient_block(g)`, `constant(n)` | 2 | block layout incl. the `1.0` marker at `d+1`; `Σ g_j² ≤ B` (public bound, fixed point); `1 ≤ n < 1024` integer; two `m_commitment`s | 5 |

Validity circuit names: `ckks_matching_validity_ps5`, `ckks_treasury_validity_ps5`,
`ckks_fedavg_validity_ps5` (lib module `circuits/lib/src/core/threshold/ckks_<app>_validity.nr`,
config module `circuits/lib/src/configs/ckks_<app>_ps5.nr`, bin under `circuits/bin/threshold/`).
`m_commitment` recomputation: `ckks_app_validity::commit_message::<N, BIT_M>(m)` — same packing
width and domain separator as the Greco ct0 leg (copy the credit leg's pattern).

## App wiring (copy `examples/ckks-credit-scoring` file-for-file, rename)

| | matching | treasury | federated |
|---|---|---|---|
| dir | `examples/ckks-matching` | `examples/ckks-treasury-risk` | `examples/ckks-federated-averaging` |
| ports server/client | 8093 / 5176 | 8094 / 5177 | 8095 / 5178 |
| contract | `CkksMatchingE3Program.sol` | `CkksTreasuryE3Program.sol` | `CkksFedAvgE3Program.sol` |
| `ckksAppProgram.ts` key | `matching` | `treasury` | `fedavg` |
| program crate | `ckks-matching-program` | `ckks-treasury-program` | `ckks-fedavg-program` |
| sdk pkg | `ckks-matching-sdk` | `ckks-treasury-sdk` | `ckks-fedavg-sdk` |
| policy | `matching_score_policy` | `treasury_risk_policy` | `federated_average_policy` |
| round semantics | exactly 2 participants (A/B role assigned at registration) | n DAOs, public `w[4]` per round | n clients, public `d`, `B`, min-client count per round |
| result shown | score `−out[0]` | risk `−out[0]` | mean `out[1..=d] / out[d+1]` |

Contracts live in `packages/interfold-contracts/contracts/test/` like `CkksCreditE3Program.sol`
(nested ABI tuples per Greco pair; flat envelopes revert). Register in `ckksAppProgram.ts`
`APPS` and in `deployMocks.ts` with a `cap` (1 for all three: inputs are already normalised).
Relin key file: `RelinKeys::level_key_file(0)` (`rlk_level_0.bin`) — plan `PerLevel([0])`.
`dev_cipher.sh` shares `CKKS_RELIN_KEY_DIR` with the nodes (default `/tmp/ckks-relin-keys`).

## Honest-scope lines every Readme must carry

- Insecure N=512 demo params; 20 smudging bits vs the ~78 the calculator requires at λ=50.
- Cross-term mask hiding ratio is 2^10 (DEMO), not statistical.
- The published plaintext bytes are not bound to the C7 proof's `u_global` (decode gap).
- RISC0 program-correctness out; policy runs natively in `program/`.
- Federated: the aggregate is public; with few clients this is the usual FedAvg leakage —
  the server enforces the round's minimum client count before evaluating.

## Gates (per app, before reporting)

`nargo compile` + `nargo execute` (with a generated Prover.toml) for the validity bin;
`cargo test -p e3-zk-helpers` (new witness module tests); hardhat spec for the program contract
using REAL proofs from `scripts/ckks-<app>-fixtures.sh` (mirror `scripts/ckks-credit-fixtures.sh`);
`cargo test` for the program crate; `pnpm -r build` in the app dir. **Do NOT boot dev.sh stacks** —
deliver the runnable checklist instead.

## Build outcome (2026-09-05) — facts learned, for the next app

| | matching | treasury | fedavg |
|---|---|---|---|
| validity leg | 1,604 ACIR, bb 0.13 s | 1,976 ACIR | 1,138 ACIR, 0.43 s |
| legs / party | 5 | **7** | 5 |
| `publishInput` gas (measured) | see spec | **20,037,798** (calldata 105,600 B) | see spec |
| client proving, all legs (Node, bb.js) | 16–22 s | ~10 s / DAO | 9.3 s |
| hardhat spec | ✓ real proofs | 13/13 | 13/13 |
| verifier contract name | `CkksMatchingValidityPs5Verifier` | `CkksTreasuryValidityPs5Verifier` | `CkksFedavgValidityPs5Verifier` (generator casing) |

Pitfalls every app hit — pre-empt them next time:
- **Policy key type.** The ParamSet-5 policies take ONE `&CkksRelinearizationKey` (level 0);
  `RelinKeys::load_from_dir` returns the `RelinKeys` bundle. Unwrap with a `level0_key()` that
  `bail!`s on `RelinKeys::Hybrid` (pattern: `examples/ckks-matching/program/src/lib.rs:138-150`).
- **Fresh `Cargo.lock` resolves `winnow 0.7.15` → `alloy-dyn-abi 1.4.1` fails (141 errors).**
  Copy a sibling app's lock (pins 0.7.14) instead of resolving fresh.
- **Negative fixed-point words are `p − |V|`** on BOTH the Rust witness and the noir_js input map;
  one helper for both, or the m_commitment test fails with `|V|` vs `p−|V|`.
- **noir_js wants a bare `[Field; N]`**, not `{coefficients: [...]}`: unwrap the Rust
  `Polynomial` shape before `execute`.
- **C7 VK coincidence:** ps3/ps4/ps5 open on the same 2-limb ring, so their C6/C7 circuits and
  `DecryptedSharesAggregationCkksPs{3,4,5}Verifier` share ONE `VK_HASH`. Dispatch-by-param-set is
  a no-op between them for C7; the security boundary is the E3 decryption domain. Negative tests
  must use ps2 as the "other" set.
- **Test-fixture trap:** an out-of-range fixture differs from the genuine one ONLY in the
  m_commitment words. Overwriting those with the genuine values makes the public inputs identical
  to the genuine proof's — which then verifies. Submit the tampered inputs unmodified.
- Codegen templates must match nargo's formatter output exactly (multi-line `Configs::new(` args)
  or the drift tests fail.
