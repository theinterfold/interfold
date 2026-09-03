# examples/ckks-common — CKKS client-side encryption + Greco witnesses (WASM)

Browser-capable WASM crate (mirroring CRISP's `zk-inputs-wasm`) that performs a
**CKKS public-key encryption with witnessed randomness** and produces the Greco
witness inputs for the CKKS user-data-encryption circuits
(`user_data_encryption_ckks_ct0*` / `_ct1*` in `circuits/bin/threshold`), packaged
as an npm-consumable module.

```
examples/ckks-common/
├── Cargo.toml                          # standalone workspace (path-deps on ../../crates/*)
├── crates/ckks-zk-inputs-wasm/         # Rust: native core (rlib) + wasm-bindgen cdylib
│   ├── .cargo/config.toml              #   --cfg getrandom_backend="wasm_js" for wasm32
│   ├── src/core.rs                     #   encryption + witness math + commitments
│   ├── src/lib.rs                      #   #[wasm_bindgen] JS surface
│   ├── src/tests.rs                    #   native parity + nargo acceptance tests
│   └── src/bin/ckks_test_pubkey.rs     #   fixture keypair generator
└── packages/ckks-zk-inputs/            # npm: @interfold/ckks-zk-inputs
    ├── main.js / init_web.js / init_node.js
    ├── scripts/build.js                #   wasm-pack web + nodejs targets
    ├── scripts/node-smoke.mjs          #   noir_js execute + bb.js prove/verify (Node)
    ├── scripts/browser-smoke.mjs       #   same in headless Chromium (playwright)
    └── smoke.html
```

## JS API (all JSON in / out; big integers travel as decimal strings)

| function | returns |
| --- | --- |
| `ckksParamsForParamSet(set: 0\|2\|3)` | `Uint8Array` — serialized `CkksParameters` (fhe.rs wire encoding), byte-identical to `e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set` |
| `ckksParamSetInfo(set)` | `{param_set, degree, slots, moduli[], scale_bits, input_bound, num_limbs}` |
| `encryptAndWitness(set, pk: Uint8Array, value, cap, replicateSlots, seed?: Uint8Array(32))` | the **witness bundle** (below). ONE encryption feeds the ciphertext AND both witness tomls. `seed` makes it deterministic — pass `undefined` in production. |
| `commitmentsFromInputs(set, inputs)` | `{u_commitment_hex, m_commitment_hex}` recomputed from a `circuit_inputs` / `ct0_inputs` object |
| `messagePolyJson(set, inputs)` | `{message_poly[], message_poly_limbs[][]}` — the scaled message `m` (centered mod Q, circuit order) and its per-limb centered residues, for app-validity circuits |
| `generateKeypair(set)` / `decrypt(set, sk, ct)` | test fixtures only |

Witness bundle fields:

- `ciphertext_hex` — serialized `CkksCiphertext` (no `0x`)
- `prover_toml_ct0`, `prover_toml_ct1` — `Prover.toml` text, **byte-identical to the native
  `e3_zk_helpers::…::generate_toml`** output (both carry all keys; nargo ignores undeclared ones)
- `circuit_inputs` — full native `Inputs::to_json` shape
- `ct0_inputs`, `ct1_inputs` — noir_js `InputMap` objects (only the keys each circuit declares,
  every coefficient stringified)
- `u_commitment_hex`, `m_commitment_hex` — the circuits' public outputs (ct0: idx 3 / idx 2;
  ct1: idx 2), 32-byte `0x` hex
- `message_poly`, `message_poly_limbs`, `encoded_values`

The value encrypted is `value / cap` (must be within the param set's `input_bound`:
ps0 = 100, ps2 = 1000, ps3 = 1). `replicateSlots=true` fills all `N/2` slots — REQUIRED by the
auction bracket and the packed statistics policy.

```js
import init from '@interfold/ckks-zk-inputs/init'
import { encryptAndWitness } from '@interfold/ckks-zk-inputs'
import { Noir } from '@noir-lang/noir_js'
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js'

await init()
const b = encryptAndWitness(3, pkBytes, 52_000, 100_000, true, undefined)
const { witness } = await new Noir(ct1Circuit).execute(b.ct1_inputs)
const api = await Barretenberg.new({ srsSize: 2 ** 18 })   // ct*_ps3 circuit_size ≈ 65k
const proof = await new UltraHonkBackend(ct1Circuit.bytecode, api).generateProof(witness)
```

## Build recipe (the one that works)

Toolchain: interfold's `rust-toolchain.toml` (1.91.1, `wasm32-unknown-unknown` target installed),
`wasm-pack` 0.13+ (0.15 pinned in devDependencies), Node ≥ 18.

```bash
# Rust — native tests (parity + nargo acceptance; nargo + compiled circuits optional)
cd examples/ckks-common
cargo test -p ckks-zk-inputs-wasm --release
cargo +nightly fmt --all && cargo clippy -p ckks-zk-inputs-wasm --all-targets -- -D warnings

# WASM + npm package
cd packages/ckks-zk-inputs
pnpm install --ignore-workspace        # standalone; not yet in root pnpm-workspace.yaml
pnpm fixtures                          # fixtures/pubkey_ps3.bin (seeded test keypair)
pnpm build                             # wasm-pack --target=web (base64-inlined) + --target=nodejs
pnpm test:node                         # noir_js execute + bb.js prove/verify, both ps3 legs
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" pnpm test:browser
```

WASM specifics (mirrors `crates/wasm` and CRISP `zk-inputs-wasm` exactly):
`getrandom = { version = "0.3", features = ["wasm_js"] }` + `getrandom2 = { package = "getrandom",
version = "0.2", features = ["js"] }` in `Cargo.toml`, plus `.cargo/config.toml` setting
`--cfg getrandom_backend="wasm_js"` for the wasm32 target. wasm-bindgen 0.2, `crate-type =
["cdylib", "rlib"]`. **fhe.rs needed NO patch** — the local `../fhe.rs` checkout (CKKS branch)
compiles to wasm32 unmodified, as do zk-helpers / fhe-params / polynomial (rayon's `par_bridge`
runs single-threaded on wasm). Output: ~730 KiB `.wasm` after wasm-opt.

The crate's workspace carries the same DEV-ONLY `[patch."https://github.com/gnosisguild/fhe.rs"]`
→ `../../../fhe.rs/crates/*` as the interfold root, so both resolve `CkksParameters` from the same
source.

## Parity evidence (native tests, `src/tests.rs`)

- `param_set_presets_match_fhe_params`: `ckksParamsForParamSet` bytes == `e3_fhe_params` for 0/2/3.
- `structural_parity_ps0` / `_ps3`: same TOML keys, limb counts and coefficient counts as
  `Inputs::compute` + `generate_toml`.
- `seeded_witness_is_deterministic_and_toml_matches_native_codegen`: fixed seed ⇒ identical
  ciphertext/toml/commitments; toml == `toml::to_string(circuit_inputs)` (the native codegen).
- `commitments_recompute_from_inputs`, `ciphertext_decrypts_to_value` (0.52 in all 256 slots).
- `nargo_executes_our_toml_ps0` / `_ps3` — **acceptance proof**: `nargo execute` on OUR
  `Prover.toml` solves all four circuits, and the solved public outputs equal our commitments:

```
[user_data_encryption_ckks_ct0_ps3] Circuit witness successfully solved
[user_data_encryption_ckks_ct0_ps3] Circuit output: (0x2f18…898b, 0x1353…d5ba, 0x1af2…45f7, 0x2297ef00…035fc7)
[user_data_encryption_ckks_ct1_ps3] Circuit witness successfully solved
[user_data_encryption_ckks_ct1_ps3] Circuit output: (0x2e39…b63d, 0x0427…d6c2, 0x2297ef00…035fc7)
```

(`0x2297ef…` is the shared `u_commitment`, `0x1af2…` the `m_commitment`; both asserted equal to
the bundle's values.) The witness math is a line-for-line port of `Inputs::compute`; the
`decompose_residue` internal asserts (`xi == xi_hat mod R_qi`) are the native pre-checks and would
panic on any deviation.

## Smoke timings (Apple Silicon, ps3 = N=512, L=3, Δ=2^40)

Node (`bb.js` WASM backend, `srsSize 2^21`):

| step | ct1_ps3 | ct0_ps3 |
| --- | --- | --- |
| wasm `encryptAndWitness` (one call covers both legs) | 174–387 ms | — |
| noir_js `execute` | 260–330 ms (1.3 s cold) | 263 ms |
| `Barretenberg.new` (one-time) | 2.0 s | — |
| bb.js `generateProof` | 2.0–3.0 s | 2.0 s |
| bb.js `verifyProof` | 0.5 s | 0.6 s |

Node with `--bb-native` (bb.js native backend): prove 1.5 s, verify 0.24 s.

**Browser (headless Chrome, `crossOriginIsolated=true`, 11 threads):** wasm load 30–57 ms,
`encryptAndWitness` **166 ms**, noir_js execute **255 ms**, `Barretenberg.new` 1.6 s (one-time,
CRS cached in IndexedDB), `generateProof` **1.5 s**, `verifyProof` **0.35 s**. Total for a
participant proving both legs ≈ 5 s cold, ≈ 3.5 s warm. Browser proving is feasible and needs
COOP/COEP headers for the multithreaded backend; use `srsSize: 2 ** 18` (circuit_size 65 268) — a
2^21 CRS exceeds Chrome's IndexedDB per-value cap (`size=134217823 > 133169152`).

## Follow-ups / notes

- `crates/zk-helpers` (other agent's): `DS_USER_DATA_ENCRYPTION_COMMITMENT` and
  `decrypted_shares_aggregation::utils::crt_reconstruct` are private/nested → local copies in
  `core.rs`. If `Inputs` gains a `compute_with_rng`, `witness_from_encryption` collapses into it.
- Not yet added to the root `pnpm-workspace.yaml` (deliberately, to avoid touching shared config);
  `.npmrc` sets `ignore-workspace=true`. Dev deps resolve from CRISP's `node_modules` via symlinks
  in this checkout; a real `pnpm install --ignore-workspace` needs network.
- `package.json` `files` excludes `fixtures/`; the secret key fixture is git-ignored.
