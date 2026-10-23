# Wasm bundle for interfold

## Purpose

`e3-wasm` / `@interfold/wasm` exposes native BFV encryption, parameter metadata, and circuit
commitments to TypeScript in Node and browsers. Cryptographic calculations stay in
[bfv-client](../bfv-client/README.md) and [fhe-params](../fhe-params/README.md).

## Map

| Location                                                                                         | Responsibility                                                                          |
| ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| [`src/lib.rs`](src/lib.rs)                                                                       | wasm-bindgen exports and Rust-to-JS byte/integer/error conversion.                      |
| [`init_web.js`](init_web.js), [`init_node.mjs`](init_node.mjs), [`init_node.cjs`](init_node.cjs) | Universal loader's browser/Node implementations.                                        |
| [`scripts/build.js`](scripts/build.js), [`package.json`](package.json)                           | Node/web binding generation, browser base64 embedding, and conditional package exports. |
| [`scripts/browser-smoke.mjs`](scripts/browser-smoke.mjs), [`smoke.html`](smoke.html)             | Headless-browser load/key-generation/encryption smoke scenario.                         |

Node imports select the generated Node binding; browser initialization loads the embedded binary
once before exported calls. Both route to the same Rust implementation, not a JS encryption copy.

## Usage

This package exposes an `init` subpackage default function which should be used to universally load
the wasm module instead of exporting the default loader.

This is because in modern node there is no need for preloading however in the browser we still need
to load the wasm bundle.

##### ❌ DONT USE THE DEFAULT INIT

```ts
// Bad! Because this uses the raw loader which doesn't exist in node contexts
import init, { bfv_encrypt_number } from '@interfold/wasm'
```

##### ✅ DO USE THE EXPORTED SUBMODULE

```ts
// Good! Use the universal loader
import init from '@interfold/wasm/init'
import { bfv_encrypt_number } from '@interfold/wasm'

export async function bfvEncryptNumber(
  data: bigint,
  public_key: Uint8Array,
  degree: number,
  plaintext_modulus: bigint,
  moduli: BigUint64Array,
): Promise<Uint8Array> {
  await init()
  return bfv_encrypt_number(data, public_key, degree, plaintext_modulus, moduli)
}
```

## Build and tests

With workspace JS dependencies, wasm-pack, and the pinned Rust WASM target installed, run from the
root:

```sh
pnpm wasm:build
pnpm -C crates/wasm test:browser
```

The smoke test needs Playwright Chromium installed (or `CHROME_BIN` pointing to a compatible
browser). It loads built browser output and runs key generation/encryption. Native BFV tests are in
the owner crate; a native Cargo check does not exercise browser entropy/loading. There are no Rust
unit tests local to this wrapper. See [AGENTS.md](AGENTS.md) for export/loader changes.
