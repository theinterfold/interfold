# e3-committee

## Purpose

Canonical names and numeric parameters for supported ciphernode committee sizes. This small crate
supplies configuration to runtime, parameter, and circuit tooling; it does not select committee
members or determine their party IDs.

## Map

[`src/lib.rs`](src/lib.rs) contains the whole crate: `CiphernodesCommitteeSize` parses canonical
names and looks up `CiphernodesCommittee { n, h, threshold }`; inline tests pin numeric lookups and
serialized variants. There is no actor, runtime selector, or generated table here.

## Look up a committee

```rust
use e3_committee::CiphernodesCommitteeSize;

let size: CiphernodesCommitteeSize = "minimum".parse().unwrap();
let values = size.values();
assert_eq!((values.n, values.h, values.threshold), (3, 2, 1));
assert_eq!(CiphernodesCommitteeSize::from_n_h(3, 2).unwrap(), size);
assert_eq!(CiphernodesCommitteeSize::from_threshold(1, 3).unwrap(), size);
```

`Minimum`, `Micro`, and `Small` expose N (total parties), H (honest roster), and T (`threshold`).
`from_threshold` receives `(T, N)`, not `(T+1, N)` or `(H, N)`; unsupported pairs return errors.
`as_str()`/Display provide the lowercase tooling names. Serde names and serialized enum order are
compatibility-sensitive, distinct from those lowercase names.

For a dependency inside this workspace, use `e3-committee = { workspace = true }` and import
`e3_committee`. The [FHE parameter API](../fhe-params/README.md) combines committee dimensions with
cryptographic presets; supported dimensions alone do not imply installed circuit artifacts.

## Tests

Run `cargo test --locked -p e3-committee` from the root; no chain/proof tools are needed. Tests
cover names/serialization, all supported dimensions, and rejected parameter pairs. See
[committee selection](../../docs/architecture/committee-selection.md) for runtime membership and
[circuit artifacts](../../docs/architecture/circuit-artifacts.md) for matching generated outputs.
Compatibility rules for table changes are in [AGENTS.md](AGENTS.md).
