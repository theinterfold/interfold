# e3-tests

This package holds fixture binaries for the integration scripts; `src/main.rs` intentionally does no
work.

- Keep the fixture binaries off the node assembly: they depend only on the BFV client and parameter
  crates (`scripts/checks/cargo-feature-containment.py` enforces this).
