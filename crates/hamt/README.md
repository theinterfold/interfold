# HAMT - A Space Efficient Serializable Hash Array Mapped Trie

A serializable persistent, immutable hash map implementation in Rust using a Hash Array Mapped Trie
data structure designed for using in Interfold Sortition.

## What is a HAMT?

A HAMT is a tree-based data structure that provides efficient immutable key-value storage. Instead
of copying the entire map on updates, it shares structure between versions, making operations both
fast and memory-efficient.

## Features

- **Persistent**: Old versions remain accessible after modifications
- **Immutable**: All operations return new maps without mutating the original
- **Structural Sharing**: Different versions share most of their data via `Arc`
- **Thread-Safe**: Can be safely shared across threads (`Send + Sync`)
- **Space-Efficient Serialization**: Multiple map versions can be serialized together without
  duplicating shared nodes

## Usage

```rust
use hamt::Hamt;

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

## Serialization with Deduplication

When you have multiple related maps (versions), you can serialize them together to avoid duplicating
shared structure:

```rust
use hamt::Hamt;

let map1 = Hamt::new();
let map1 = map1.insert("hello".to_string(), 42);
let map1 = map1.insert("world".to_string(), 100);

// map2 shares structure with map1
let map2 = map1.insert("hello".to_string(), 999);

// Serialize both maps - shared nodes are only serialized once!
let serialized = Hamt::serialize_multiple(&[&map1, &map2]);

// Deserialize back
let deserialized = Hamt::deserialize_multiple(serialized);

assert_eq!(Some(&42), deserialized[0].get(&"hello".to_string()));
assert_eq!(Some(&999), deserialized[1].get(&"hello".to_string()));
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

## Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
```

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
