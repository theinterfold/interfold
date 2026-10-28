# e3-committee

## Purpose

Canonical committee parameters and ordered membership data shared by runtime and circuit tooling.
This crate preserves supplied membership order; it does not form committees, normalize chain
addresses, or choose active aggregators.

## Map

[`src/lib.rs`](src/lib.rs) owns supported parameter lookup. [`membership.rs`](src/membership.rs)
owns `Committee`: ordered members, zero-based party lookup, and the derived address index. There is
no actor, runtime selector, or generated table here.

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

## Ordered membership

`Committee::new(members)` keeps the supplied strings and order exactly: index is party ID. Lookup
lowercases addresses; duplicate lowercase keys resolve to the last position. Deserialization
rebuilds that index, while serialization and equality use only the member list. Construction does
not validate or deduplicate addresses. Sortition owns canonical formation/normalization and the
[active/standby failover policy](../sortition/src/failover.rs).

## Tests

Run `cargo test --locked -p e3-committee` from the root; no chain/proof tools are needed. Tests
cover names/serialization, all supported dimensions, rejected parameter pairs, and frozen membership
bytes/cache reconstruction. See
[committee selection](../../docs/architecture/committee-selection.md) for runtime membership and
[circuit artifacts](../../docs/architecture/circuit-artifacts.md) for matching generated outputs.
Compatibility rules for table changes are in [AGENTS.md](AGENTS.md).
