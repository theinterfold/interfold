# HAMT - A Persistent Hash Array Mapped Trie

## Purpose

A persistent, immutable hash map implementation in Rust using a Hash Array Mapped Trie data
structure designed for using in Interfold Sortition.

## Map

[`src/lib.rs`](src/lib.rs) contains `Hamt`, immutable leaf/bitmap/collision nodes, hash-path
traversal, and tests. Inserts/removals copy the changed path and share the rest through `Arc`, so
sortition can retain earlier eligibility snapshots while newer registry state evolves. There is no
disk encoding or cryptographic commitment to the internal trie shape.

## What is a HAMT?

A HAMT is a tree-based data structure that provides efficient immutable key-value storage. Instead
of copying the entire map on updates, it shares structure between versions, making operations both
fast and memory-efficient.

## Features

- **Persistent**: Old versions remain accessible after modifications
- **Immutable**: All operations return new maps without mutating the original
- **Structural Sharing**: Different versions share most of their data via `Arc`
- **Thread-Safe**: Can be safely shared across threads (`Send + Sync`)

## Usage

```rust
use e3_hamt::Hamt;

// Create a new empty map
let map1 = Hamt::new();

// Insert some values (returns new map, original unchanged)
let map2 = map1.insert("hello", 42);
let map3 = map2.insert("world", 100);

// Lookup values
assert_eq!(Some(&42), map3.get(&"hello"));
assert_eq!(Some(&100), map3.get(&"world"));
assert_eq!(None, map3.get(&"missing"));

// Old versions still work!
assert_eq!(None, map1.get(&"hello"));
```

## Structural Sharing Example

```rust
let map1 = Hamt::new();
let map1 = map1.insert("a", 1);
let map1 = map1.insert("b", 2);
let map1 = map1.insert("c", 3);

// map2 shares most of its structure with map1
let map2 = map1.insert("a", 999);

// Both maps are valid and independent
assert_eq!(Some(&1), map1.get(&"a"));    // original value
assert_eq!(Some(&999), map2.get(&"a"));  // updated value
assert_eq!(Some(&2), map2.get(&"b"));    // shared data
```

## Performance Characteristics

- **Insert**: O(log₃₂ n) - 5 bits per level means shallow trees
- **Lookup**: O(log₃₂ n)
- **Space**: Shared structure means only changed paths are copied
- **Memory**: Uses `Arc` for automatic memory management

## Implementation Details

- Uses 5 bits per level (32-way branching)
- Bitmap-compressed internal nodes save memory
- Handles hash collisions with collision nodes
- All nodes are immutable and reference-counted

## Future considerations

We could consider adding a Rc version for signlethreaded usage which is cheaper and faster than
using Arc.

## Benchmarks

Against cloning a HashMap performance on my laptop

```
HAMT total time: 368.344061ms
HashMap total time: 640.458474ms
HAMT is 0.58x the cost
```

## Tests

Run `cargo test --locked -p e3-hamt` from the root without external services. Inline tests cover
insert/lookup/removal, retaining earlier maps, and equivalence with a `BTreeMap` over operation
sequences. The laptop timing above is historical context, not a repository benchmark target or
correctness claim. [Sortition](../sortition/Readme.md) owns snapshot use; [AGENTS.md](AGENTS.md)
covers structural-sharing changes.
