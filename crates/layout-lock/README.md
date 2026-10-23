# e3-layout-lock

## Purpose

Test utility that samples serde layouts and locks their bincode encodings in reviewed fixtures.
Consumers list the persisted/wire roots they want covered; this is not a schema migration tool.

## Map and sampling flow

The implementation is in [`src/lib.rs`](src/lib.rs): a synthetic serde deserializer discovers
reachable layouts and creates deterministic named/positional samples; `sample_rows` encodes and
hashes them; `assert_fixture` compares the resulting rows. Consumer tests choose root types and
optional extra metadata. The inline utility tests use small synthetic types rather than the runtime.

## Lock a consumer type

```rust
use e3_layout_lock::{assert_fixture, sample_rows};
use std::path::Path;

let rows = sample_rows::<Option<u64>, _>("optional-counter", |_| String::new());
assert_fixture(Path::new("tests/fixtures/optional-counter.txt"), &rows);
```

The fixture must already contain the accepted rows for normal test runs. `sample_rows` requires
`Serialize + DeserializeOwned`; its callback adds consumer-specific information to each row. See the
[runtime layout test](../tests/tests/layout_lock.rs) for multiple roots, repository value bindings,
and event-ID samples.

Rows contain a named digest (sample/layout names and structure) and positional digests (encoded
sample bytes independent of cosmetic names). Enum paths, optional/empty/full shapes, and flipped
booleans expose many changes that a single round trip would miss.

## Updating and limits

`LAYOUT_LOCK_UPDATE=1` rewrites a consumer fixture instead of comparing it. Only use it after
reviewing the intended format change and the
[schema/wire compatibility decision](../../docs/architecture/upgrades.md). For the broad runtime
fixture the command is `LAYOUT_LOCK_UPDATE=1 cargo test --locked -p e3-tests --test layout_lock`;
that crate has [additional prerequisites](../tests/README.md).

Unlisted roots, hand-written framing, and values inside opaque/encrypted byte strings are not
covered. Some equal-width signedness changes and repeated generic enum names also escape the
samples; the [crate-level documentation](src/lib.rs) describes these limits. A matching lock is not
proof of semantic compatibility.

## Tests

Run `cargo test --locked -p e3-layout-lock` without external tools. Inline tests demonstrate
field/variant swaps, cosmetic renames, optional/empty values, conditional serialization, and the
difference between named and positional digests. The runtime fixture is a separate consumer target
shown above and needs that crate's prerequisites. See [AGENTS.md](AGENTS.md) for reviewing
intentional fixture changes.
