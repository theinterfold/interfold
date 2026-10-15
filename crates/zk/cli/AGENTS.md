# e3-zk-artifacts

This executable owns argument parsing, artifact dispatch, and terminal output, not circuit math.
[README.md](README.md) documents actual root `pnpm zk` commands and output locations.

- Extend metadata/computation in `e3-zk-helpers` rather than implementing a second circuit table or
  witness encoder here. Preserve explicit threshold/DKG and witness-family selection.
- Generation samples data even when only configs are written. `--toml` emits private witness inputs;
  choose an intentional output directory and do not confuse samples with production data.
- VK hash combination is ordered and accepts canonical field bytes. The recursive-tree path must
  validate the full required tree, not only combine convenient top-level wrapper hashes.
- Parity generation writes both presets for the chosen committee. Use `pnpm build:circuits` for
  active preset switches; direct edits to generated configs can leave Rust/Noir/verifiers
  mismatched.

Run `cargo test --locked -p e3-zk-artifacts` for dispatch/generator behavior. Generation and proof
acceptance are different checks; follow
[circuit artifacts](../../../docs/architecture/circuit-artifacts.md) for tool pins, coordinated
rebuilds, and verification requirements.
