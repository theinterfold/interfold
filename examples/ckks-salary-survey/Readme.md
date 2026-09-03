# CKKS Private Salary Survey — a full-stack Interfold E3 program

A CRISP-shaped example (`examples/CRISP`) built on **threshold CKKS**: participants
encrypt their salary **in the browser**, prove three things about that ciphertext with
UltraHonk, an on-chain gate verifies all three proofs before the ciphertext is admitted,
the coordinator computes Σx and Σx² homomorphically (a genuine relinearized ct×ct
multiplication under the committee's joint relin key), and a committee of five
ciphernodes threshold-decrypts **only** the two aggregates. Individual salaries are
never decrypted by anyone.

```
examples/ckks-salary-survey/
├── Cargo.toml                    # workspace: server + program (path-deps on ../../crates)
├── program/                      # the E3 program: packed statistics policy (plain Rust, no RISC0)
│   └── src/{lib,main}.rs         #   evaluate / decode_statistics + `ckks-salary-program` CLI
├── server/                       # actix-web 4 + sled coordinator (CRISP server shape)
│   └── src/server/{chain,indexer,evaluator,repo,models,routes/…}.rs
│   └── src/cli/main.rs           #   admin CLI (create-round / wait-pubkey / submit / evaluate / wait-results)
├── packages/ckks-salary-sdk/     # TS proof pipeline (browser + Node): encrypt → execute×3 → prove×3 → submission.json
├── client/                       # Vite + React 18 + react-query + react-router (COOP/COEP, wasm, TLA)
│   └── src/{pages,components,hooks,context,providers,lib,utils}
├── scripts/                      # dev.sh (one command), sync-config.mjs, stage-circuits.mjs, dev_server.sh
├── test/                         # e2e.mjs (Playwright browser driver), prove-node.mjs (same SDK in Node)
└── Readme.md
```

## What each proof leg proves

| leg | circuit (`circuits/bin/threshold`) | statement | public inputs / outputs |
| --- | --- | --- | --- |
| ct0 | `user_data_encryption_ckks_ct0_ps3` | Greco: `ct₀ = pk₀·u + e₀ + m + r₁·qᵢ + r₂·Φ` per RNS limb with `u, e₀, m` in the CKKS bounds; `m` bound to `Δ`-scaled encoding | `pk₀ᶜ, ct₀ᶜ, m_commitment, u_commitment` |
| ct1 | `user_data_encryption_ckks_ct1_ps3` | Greco: `ct₁ = pk₁·u + e₁ + p₁·qᵢ + p₂·Φ` with the **same** `u` | `pk₁ᶜ, ct₁ᶜ, u_commitment` |
| app | `ckks_salary_validity_ps3` | the **same** `m` is the slot-replicated encoding of `salary/cap` with `0 ≤ salary ≤ cap`: head `|m₀·cap − Δ·salary| ≤ 2·cap`, tail `|mₖ| ≤ 64` (which also enforces replication across all N/2 slots, required by the packed policy) | `cap` (input), `m_commitment` (output) |

`CkksSalaryE3Program.publishInput` (`packages/interfold-contracts/contracts/test/`) decodes the
7-tuple envelope, requires `ct0.u == ct1.u`, `ct0.m == app.m`, `app.cap == salaryCap`, dedupes on
`(e3Id, u_commitment)` (`DuplicateSubmission`), verifies the three Honk proofs (~8.4M gas total)
and emits `VerifiedInputPublished`.

The app leg's witness is `{ m, value_raw, cap }` where `m` is exactly `ct0_inputs.m` from the
WASM bundle — the SDK assembles that InputMap in TS (`appLegInputs`); no extra WASM builder
was needed.

## Architecture / flow

1. **Round request** (`POST /rounds`, admin): the server quotes + approves the fee and calls
   `Interfold.request` through `CkksSalaryE3Program` with **ParamSet 3** (N=512, three 36-bit
   moduli, Δ=2⁴⁰). The program address selects the CKKS scheme.
2. **DKG + relin ceremony**: the five ciphernodes run the CKKS DKG and the two-round
   relinearization-key ceremony automatically; the joint level-0 key lands in
   `$CKKS_RELIN_KEY_DIR/<chain_id>:<e3_id>/rlk_level_0.bin` (the server reads it from there).
   `CommitteePublished` carries the joint pk → round `open`.
3. **Browser**: `encryptAndWitness` (`@interfold/ckks-zk-inputs` WASM) → noir_js `execute` ×3 →
   bb.js `generateProof` ×3 (`verifierTarget: 'evm'`, 2¹⁸ CRS, multithreaded under COOP/COEP)
   → `POST /rounds/{id}/submit`.
4. **Relay**: the server validates the shape (ParamSet, input counts, cross-leg commitments,
   cap), preflights `publishInput` with `eth_call` (surfaces `DuplicateSubmission` etc.), sends
   the tx with its own key (pays gas), stores the ciphertext in sled, and the indexer confirms
   it from `VerifiedInputPublished`.
5. **Evaluate** (auto when the window closes, or `POST /rounds/{id}/evaluate`): the program
   crate runs `statistics_packed_policy` (Σx in slot 0, relinearized Σx² in slot 1, output scale
   10⁴) and publishes the ciphertext output.
6. **Threshold decryption**: t+1 nodes open the single output; `PlaintextOutputPublished`
   carries the canonical 2-decimal `int128[]`; the indexer decodes count/sum/Σx²/mean/variance/
   stddev and serves them.

## API

```
GET  /health
GET  /rounds                        → [RoundSummary]
GET  /rounds/{id}                   → Round (status timeline, pk, submissions, evaluation, results)
GET  /rounds/{id}/pubkey            → { public_key_hex, param_set, salary_cap, ... } (425 until DKG)
POST /rounds/{id}/submit            { submission } → { tx_hash, gas_used, u_commitment, ... } | 409 duplicate
POST /rounds            (admin)     { duration_secs? } → { e3_id, tx_hash, input_window }
POST /rounds/{id}/evaluate (admin)  → EvaluationRecord
```

Round status: `requested → open → closed → evaluating → complete` (`failed` on E3 failure).

## Running

Prereqs: the interfold toolchain (`rust-toolchain.toml`, nargo, bb 5.1.0, anvil), release builds
of the node + CKKS tools (`cargo build --release -p interfold` and the `crates/test-helpers`
bins), compiled ps3 circuits in `circuits/bin/threshold/target/`, and the WASM package built
(`examples/ckks-common/packages/ckks-zk-inputs`: `pnpm build`).

```bash
cd examples/ckks-salary-survey
pnpm install                       # local workspace: client + sdk (links ../ckks-common's wasm pkg)
pnpm stage:circuits                # copies the 3 compiled circuits into client/public/circuits
cargo build --release              # server, cli, ckks-salary-program

./scripts/dev.sh                   # anvil + contracts + enable program + 5 nodes + server :8091 + client :5174
```

Then open http://127.0.0.1:5174, create a round (admin button), wait for the pk (~70 s), submit
salaries, and watch the round complete. Headless equivalent, with assertions:

```bash
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node test/e2e.mjs
```

`scripts/sync-config.mjs` writes `server/.env` + `client/.env` from
`packages/interfold-contracts/deployed_contracts.json` (run after every deploy). The relayer key
defaults to anvil account #0.

## Live verification (5 ciphernodes, anvil, release build)

`test/e2e.mjs` drives the **real browser path** (Playwright + Chromium, `crossOriginIsolated=true`):
create round → wait pk → 3 salaries typed into the Vite client (WASM encrypt + noir_js ×3 +
bb.js ×3 in the page) → server relay → `VerifiedInputPublished` asserted via `eth_getLogs` →
replayed submission rejected (server 409 **and** `eth_call` reverting with
`DuplicateSubmission`) → window close → evaluate + publish → threshold decrypt → results.

Measured (Apple Silicon, salaries 52 000 / 61 000 / 63 700, cap 500 000):

| stage | measured |
| --- | --- |
| DKG + relin ceremony → pk on-chain | ~72 s |
| browser: WASM encrypt + witness | 130–160 ms |
| browser: noir_js execute ct0 / ct1 / app | 230–300 / 185–190 / 10–20 ms |
| browser: bb.js prove ct0 / ct1 / app | 1.5–1.7 s / 1.4–2.2 s / 0.3–0.45 s |
| browser: total proving (3 legs) | 3.8–5.1 s (first includes CRS/worker warm-up) |
| relay tx (`publishInput`, 3 Honk verifies) | 8 365 709 gas, ~0.8 s incl. preflight |
| policy evaluation (`statistics_packed_policy`, 3 cts) | 4 ms |
| threshold decryption → plaintext on-chain | ~1–2 s after publish |
| result | mean 58 900.00 (exact), variance 25 040 000 vs 25 020 000 (0.08 %) |

The variance error is the CKKS approximation (rescale + smudging noise truncated to 2 decimals
at output scale 10⁴); the mean is exact at the decimal precision published.

## Notes / deviations

- `program/` is plain Rust wrapping `e3_trckks::policy::statistics_packed_policy` (RISC Zero is
  out of scope); the server's evaluator and the `ckks-salary-program` CLI share it.
- The coordinator uses `e3-sdk`'s indexer (`InterfoldIndexer`) exactly like CRISP; the
  `VerifiedInputPublished` handler is a raw-log handler because it needs the tx hash.
- The relayer sets nonces from `pending` explicitly: the Interfold write handle and the program
  relay share one wallet, and the alloy filler's cached nonce goes stale otherwise.
- Wallet-less by design (server relays and pays gas, as CRISP's relay does); a viem/wagmi wallet
  path can be added to the client without touching the SDK.
- Node event DBs grow per ceremony; `dev.sh` wipes `tests/integration/.interfold/data/cn*/db`
  on teardown.
