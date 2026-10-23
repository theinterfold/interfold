# e3-zk-config

Static BFV configuration, bounds, bit widths, parity, and public-input layouts belong here.
[README.md](README.md) owns construction and rendering APIs.

- Keep normal dependencies free of witness, samples, build tooling, and runtime orchestration.
- `Configs::new` retains the supplied parameter owner. Validate supported ring/CRT/sampler profiles
  before derived arithmetic. Share C3/user-encryption `k0is` across bounds, rendering, and
  preparation.
- Preserve canonical committee T/H distinctions and message width. A host-side field does not change
  compiled Noir or Solidity consumers.
- Render static declarations without creating keys, random samples, or witnesses. Change the
  generator, not generated configuration files.

Run `cargo test --locked -p e3-zk-config` and the affected witness/build checks. Parameter or layout
changes require the [artifact workflow](../../../docs/architecture/circuit-artifacts.md).
