# e3-utils-derive

This proc-macro crate implements `BytesSerde`; the byte-validation contract lives in `e3-utils`.

- Accept only single-field newtype structs and emit useful compile errors for other shapes. Preserve
  generics/where-clause handling when changing expansion.
- Human-readable serializers use prefixed hex; binary serializers use serde byte strings. Do not
  replace binary bytes with a generic sequence/string, which changes persisted and wire layouts.
- Generated paths resolve in the caller (`e3_utils`, `serde`, and `hex`), not in the macro crate.
  Keep `extern crate self as e3_utils` support in the utility owner and test actual expansion.
- Construction must delegate to `AsBytesSerde::try_from_bytes`, retaining exact-size/semantic
  rejection rather than bypassing the implementor's validation.

Run `cargo check --locked -p e3-utils-derive`, then `cargo test --locked -p e3-utils` to exercise
the expansion through a real consumer. Macro compilation alone does not validate generated code;
layout changes also need affected [compatibility review](../../docs/architecture/upgrades.md).
