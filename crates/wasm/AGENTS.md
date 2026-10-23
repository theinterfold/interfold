# e3-wasm

This is the JavaScript/WASM boundary for native BFV helpers. [README.md](README.md) owns loading and
usage; keep cryptographic calculations in their Rust owners.

- Preserve JS-visible names, integer/byte shapes, and error conversion. Verifiable encryption can
  expose witness randomness deliberately; do not add it to ordinary encryption or diagnostic logs.
- Keep both getrandom generations' JS support and wasm-bindgen compatibility intact. Native Rust
  checking does not establish browser entropy or WebAssembly target compatibility.
- `scripts/build.js` generates separate node/web bindings and embeds the browser binary as base64.
  Change Rust exports, loaders, or the generator rather than hand-editing `dist` JS/TypeScript.
- Preserve the `@interfold/wasm/init` universal loader and package export conditions; the raw web
  initializer is not the Node API. Rebuild both targets for changes that alter the loader shape.

Use the [README build/browser tests](README.md#build-and-tests). API changes also need SDK consumer
coverage; generated bindings and native tests alone do not validate browser loading or proof
compatibility.
