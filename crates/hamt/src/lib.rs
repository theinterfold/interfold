// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

const BITS_PER_LEVEL: u32 = 5;
const CHUNK_SIZE: usize = 1 << BITS_PER_LEVEL;
const CHUNK_MASK: u64 = (CHUNK_SIZE - 1) as u64;

#[derive(Clone)]
enum Node<K, V> {
    Empty,
    Leaf {
        hash: u64,
        key: K,
        value: V,
    },
    Internal {
        bitmap: u32,
        children: Vec<Arc<Node<K, V>>>,
    },
    Collision {
        hash: u64,
        entries: Vec<(K, V)>,
    },
}

pub struct Hamt<K, V> {
    root: Arc<Node<K, V>>,
    size: usize,
}

impl<K, V> Clone for Hamt<K, V> {
    fn clone(&self) -> Self {
        Hamt {
            root: self.root.clone(),
            size: self.size,
        }
    }
}

impl<K, V> Default for Hamt<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Hamt<K, V>
where
    K: Hash + Eq + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    pub fn new() -> Self {
        Hamt {
            root: Arc::new(Node::Empty),
            size: 0,
        }
    }

    fn hash_key(key: &K) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn chunk(hash: u64, shift: u32) -> usize {
        ((hash >> shift) & CHUNK_MASK) as usize
    }

    fn index_from_bitmap(bitmap: u32, bit: u32) -> usize {
        (bitmap & (bit - 1)).count_ones() as usize
    }

    pub fn insert(&self, key: K, value: V) -> Self {
        let hash = Self::hash_key(&key);
        let is_new = Self::get_rec(&self.root, hash, &key, 0).is_none();
        let new_root = Self::insert_rec(self.root.clone(), hash, key, value, 0);
        Hamt {
            root: new_root,
            size: if is_new { self.size + 1 } else { self.size },
        }
    }

    fn insert_rec(
        node: Arc<Node<K, V>>,
        hash: u64,
        key: K,
        value: V,
        shift: u32,
    ) -> Arc<Node<K, V>> {
        match node.as_ref() {
            Node::Empty => Arc::new(Node::Leaf { hash, key, value }),

            Node::Leaf {
                hash: existing_hash,
                key: existing_key,
                value: existing_value,
            } => {
                if *existing_hash == hash {
                    if existing_key == &key {
                        Arc::new(Node::Leaf { hash, key, value })
                    } else {
                        Arc::new(Node::Collision {
                            hash,
                            entries: vec![
                                (existing_key.clone(), existing_value.clone()),
                                (key, value),
                            ],
                        })
                    }
                } else {
                    let mut new_node = Arc::new(Node::Internal {
                        bitmap: 0,
                        children: Vec::new(),
                    });

                    new_node = Self::insert_rec(
                        new_node,
                        *existing_hash,
                        existing_key.clone(),
                        existing_value.clone(),
                        shift,
                    );

                    new_node = Self::insert_rec(new_node, hash, key, value, shift);
                    new_node
                }
            }

            Node::Internal { bitmap, children } => {
                let chunk = Self::chunk(hash, shift);
                let bit = 1u32 << chunk;
                let index = Self::index_from_bitmap(*bitmap, bit);

                if bitmap & bit == 0 {
                    let mut new_children = children.clone();
                    new_children.insert(index, Arc::new(Node::Leaf { hash, key, value }));

                    Arc::new(Node::Internal {
                        bitmap: bitmap | bit,
                        children: new_children,
                    })
                } else {
                    let child = children[index].clone();
                    let new_child =
                        Self::insert_rec(child, hash, key, value, shift + BITS_PER_LEVEL);

                    let mut new_children = children.clone();
                    new_children[index] = new_child;

                    Arc::new(Node::Internal {
                        bitmap: *bitmap,
                        children: new_children,
                    })
                }
            }

            Node::Collision {
                hash: collision_hash,
                entries,
            } => {
                if *collision_hash == hash {
                    let mut new_entries = entries.clone();

                    if let Some(pos) = new_entries.iter().position(|(k, _)| k == &key) {
                        new_entries[pos] = (key, value);
                    } else {
                        new_entries.push((key, value));
                    }

                    Arc::new(Node::Collision {
                        hash: *collision_hash,
                        entries: new_entries,
                    })
                } else {
                    unreachable!()
                }
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let hash = Self::hash_key(key);
        Self::get_rec(&self.root, hash, key, 0)
    }

    fn get_rec<'a>(node: &'a Node<K, V>, hash: u64, key: &K, shift: u32) -> Option<&'a V> {
        match node {
            Node::Empty => None,

            Node::Leaf {
                hash: leaf_hash,
                key: leaf_key,
                value: leaf_value,
            } => {
                if *leaf_hash == hash && leaf_key == key {
                    Some(leaf_value)
                } else {
                    None
                }
            }

            Node::Internal { bitmap, children } => {
                let chunk = Self::chunk(hash, shift);
                let bit = 1u32 << chunk;

                if bitmap & bit == 0 {
                    None
                } else {
                    let index = Self::index_from_bitmap(*bitmap, bit);
                    Self::get_rec(&children[index], hash, key, shift + BITS_PER_LEVEL)
                }
            }

            Node::Collision {
                hash: collision_hash,
                entries,
            } => {
                if *collision_hash == hash {
                    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
                } else {
                    None
                }
            }
        }
    }

    /// Returns a new HAMT with `key` removed. If the key is absent the
    /// returned HAMT is logically identical to `self` (structure is shared).
    pub fn remove(&self, key: &K) -> Self {
        let hash = Self::hash_key(key);
        match Self::remove_rec(&self.root, hash, key, 0) {
            Some(new_root) => Hamt {
                root: new_root,
                size: self.size - 1,
            },
            None => Hamt {
                root: self.root.clone(),
                size: self.size,
            },
        }
    }

    /// Recursively removes `key`. Returns `Some(new_node)` when the key was
    /// found and removed (the caller decrements the size), or `None` when the
    /// key was absent (the node is left untouched so structure can be shared).
    fn remove_rec(
        node: &Arc<Node<K, V>>,
        hash: u64,
        key: &K,
        shift: u32,
    ) -> Option<Arc<Node<K, V>>> {
        match node.as_ref() {
            Node::Empty => None,

            Node::Leaf {
                hash: leaf_hash,
                key: leaf_key,
                ..
            } => {
                if *leaf_hash == hash && leaf_key == key {
                    Some(Arc::new(Node::Empty))
                } else {
                    None
                }
            }

            Node::Collision {
                hash: collision_hash,
                entries,
            } => {
                if *collision_hash != hash {
                    return None;
                }
                let idx = entries.iter().position(|(k, _)| k == key)?;
                let mut remaining: Vec<(K, V)> = entries.clone();
                remaining.remove(idx);
                if remaining.len() == 1 {
                    let (k, v) = remaining.pop().unwrap();
                    Some(Arc::new(Node::Leaf {
                        hash: *collision_hash,
                        key: k,
                        value: v,
                    }))
                } else {
                    Some(Arc::new(Node::Collision {
                        hash: *collision_hash,
                        entries: remaining,
                    }))
                }
            }

            Node::Internal { bitmap, children } => {
                let chunk = Self::chunk(hash, shift);
                let bit = 1u32 << chunk;
                if bitmap & bit == 0 {
                    return None;
                }
                let index = Self::index_from_bitmap(*bitmap, bit);
                let new_child =
                    Self::remove_rec(&children[index], hash, key, shift + BITS_PER_LEVEL)?;

                let child_is_empty = matches!(new_child.as_ref(), Node::Empty);
                if child_is_empty {
                    let new_bitmap = bitmap & !bit;
                    if new_bitmap == 0 {
                        return Some(Arc::new(Node::Empty));
                    }
                    let mut new_children = children.clone();
                    new_children.remove(index);
                    Some(Arc::new(Node::Internal {
                        bitmap: new_bitmap,
                        children: new_children,
                    }))
                } else {
                    let mut new_children = children.clone();
                    new_children[index] = new_child;
                    Some(Arc::new(Node::Internal {
                        bitmap: *bitmap,
                        children: new_children,
                    }))
                }
            }
        }
    }

    /// Returns true if `key` is present.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Collects all key/value pairs into a `Vec`. Iteration order is
    /// unspecified (hash-driven), so callers that need a deterministic order
    /// must sort the result themselves.
    pub fn entries(&self) -> Vec<(K, V)> {
        let mut out = Vec::with_capacity(self.size);
        Self::collect_entries(&self.root, &mut out);
        out
    }

    fn collect_entries(node: &Arc<Node<K, V>>, out: &mut Vec<(K, V)>) {
        match node.as_ref() {
            Node::Empty => {}
            Node::Leaf { key, value, .. } => out.push((key.clone(), value.clone())),
            Node::Internal { children, .. } => {
                for child in children {
                    Self::collect_entries(child, out);
                }
            }
            Node::Collision { entries, .. } => {
                for (k, v) in entries {
                    out.push((k.clone(), v.clone()));
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedHamt<K, V> {
    nodes: Vec<SerializedNode<K, V>>,
    roots: Vec<HamtRoot>,
}

#[derive(Serialize, Deserialize, Debug)]
struct HamtRoot {
    root_node_id: usize,
    size: usize,
}

#[derive(Serialize, Deserialize, Debug)]
enum SerializedNode<K, V> {
    Empty,
    Leaf { hash: u64, key: K, value: V },
    Internal { bitmap: u32, children: Vec<usize> },
    Collision { hash: u64, entries: Vec<(K, V)> },
}

impl<K, V> Hamt<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + Serialize,
    V: Clone + Send + Sync + Serialize,
{
    pub fn serialize_multiple(hamts: &[&Hamt<K, V>]) -> SerializedHamt<K, V> {
        let mut node_map: HashMap<*const Node<K, V>, usize> = HashMap::new();
        let mut nodes: Vec<SerializedNode<K, V>> = Vec::new();
        let mut roots: Vec<HamtRoot> = Vec::new();

        for hamt in hamts {
            let root_id = Self::serialize_node(&hamt.root, &mut node_map, &mut nodes);
            roots.push(HamtRoot {
                root_node_id: root_id,
                size: hamt.size,
            });
        }

        SerializedHamt { nodes, roots }
    }

    fn serialize_node(
        node: &Arc<Node<K, V>>,
        node_map: &mut HashMap<*const Node<K, V>, usize>,
        nodes: &mut Vec<SerializedNode<K, V>>,
    ) -> usize {
        let node_ptr = Arc::as_ptr(node);

        // Check if we've already serialized this exact node
        if let Some(&id) = node_map.get(&node_ptr) {
            return id;
        }

        let serialized = match node.as_ref() {
            Node::Empty => SerializedNode::Empty,
            Node::Leaf { hash, key, value } => SerializedNode::Leaf {
                hash: *hash,
                key: key.clone(),
                value: value.clone(),
            },
            Node::Internal { bitmap, children } => {
                // Recursively serialize children FIRST, getting their IDs
                let child_ids: Vec<usize> = children
                    .iter()
                    .map(|child| Self::serialize_node(child, node_map, nodes))
                    .collect();
                SerializedNode::Internal {
                    bitmap: *bitmap,
                    children: child_ids,
                }
            }
            Node::Collision { hash, entries } => SerializedNode::Collision {
                hash: *hash,
                entries: entries.clone(),
            },
        };

        // Now add THIS node after its children
        let node_id = nodes.len();
        nodes.push(serialized);
        node_map.insert(node_ptr, node_id);
        node_id
    }

    pub fn deserialize_multiple(serialized: SerializedHamt<K, V>) -> Vec<Hamt<K, V>>
    where
        K: DeserializeOwned,
        V: DeserializeOwned,
    {
        let mut node_cache: Vec<Arc<Node<K, V>>> = Vec::new();

        // Deserialize all nodes - children come before parents, so this works!
        for serialized_node in serialized.nodes {
            let node = match serialized_node {
                SerializedNode::Empty => Arc::new(Node::Empty),
                SerializedNode::Leaf { hash, key, value } => {
                    Arc::new(Node::Leaf { hash, key, value })
                }
                SerializedNode::Internal { bitmap, children } => {
                    let child_nodes = children.iter().map(|&id| node_cache[id].clone()).collect();
                    Arc::new(Node::Internal {
                        bitmap,
                        children: child_nodes,
                    })
                }
                SerializedNode::Collision { hash, entries } => {
                    Arc::new(Node::Collision { hash, entries })
                }
            };
            node_cache.push(node);
        }

        // Create HAMTs from roots
        serialized
            .roots
            .into_iter()
            .map(|root| Hamt {
                root: node_cache[root.root_node_id].clone(),
                size: root.size,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::time::Instant;

    #[test]
    fn it_works() {
        let mut map = Hamt::new();

        map = map.insert("hello", 42);
        map = map.insert("world", 100);
        map = map.insert("rust", 200);

        assert_eq!(Some(&42), map.get(&"hello"));
        assert_eq!(Some(&100), map.get(&"world"));
        assert_eq!(Some(&200), map.get(&"rust"));
        assert_eq!(None, map.get(&"nope"));

        // Persistence - old map still valid
        let map2 = map.insert("hello", 999);
        assert_eq!(Some(&42), map.get(&"hello"));
        assert_eq!(Some(&999), map2.get(&"hello"));
    }

    #[test]
    fn test_serialization_deduplication() -> Result<()> {
        let map1 = Hamt::new();
        let map1 = map1.insert("hello".to_string(), 42);
        let map1 = map1.insert("world".to_string(), 100);

        let map2 = map1.insert("hello".to_string(), 999);

        // Serialize both maps together
        let serialized = Hamt::serialize_multiple(&[&map1, &map2]);

        let bytes = bincode::serialize(&serialized)?;

        println!("Total nodes serialized: {}", serialized.nodes.len());
        println!("Number of HAMTs: {}", serialized.roots.len());

        // Deserialize back
        let from_bytes: SerializedHamt<String, i32> = bincode::deserialize(&bytes)?;
        let deserialized = Hamt::deserialize_multiple(from_bytes);

        assert_eq!(Some(&42), deserialized[0].get(&"hello".to_string()));
        assert_eq!(Some(&100), deserialized[0].get(&"world".to_string()));
        assert_eq!(Some(&999), deserialized[1].get(&"hello".to_string()));
        assert_eq!(Some(&100), deserialized[1].get(&"world".to_string()));
        Ok(())
    }

    #[test]
    fn test_hamt_vs_hashmap_persistence_cost() {
        const NUM_ENTRIES: usize = 100_000;
        const NUM_UPDATES: usize = 1_000;

        println!("\n=== HAMT vs HashMap: Cost of Persistence ===");

        // Test HAMT with persistence
        println!("Testing HAMT (persistent)...");
        let hamt_start = Instant::now();
        let mut hamt = Hamt::new();
        for i in 0..NUM_ENTRIES {
            hamt = hamt.insert(i, i);
        }

        let mut hamt_versions = Vec::new();
        for i in 0..NUM_UPDATES {
            let updated = hamt.insert(i, i * 2);
            hamt_versions.push(updated);
        }
        let hamt_duration = hamt_start.elapsed();

        // Test HashMap with cloning
        println!("Testing HashMap (with cloning)...");
        let hashmap_start = Instant::now();
        let mut hashmap = HashMap::new();
        for i in 0..NUM_ENTRIES {
            hashmap.insert(i, i);
        }

        let mut hashmap_versions = Vec::new();
        for i in 0..NUM_UPDATES {
            let mut cloned = hashmap.clone();
            cloned.insert(i, i * 2);
            hashmap_versions.push(cloned);
        }
        let hashmap_duration = hashmap_start.elapsed();

        println!("\nHAMT total time: {:?}", hamt_duration);
        println!("HashMap total time: {:?}", hashmap_duration);
        println!(
            "HAMT is {:.2}x the cost",
            hamt_duration.as_secs_f64() / hashmap_duration.as_secs_f64()
        );

        // Verify original map unchanged
        assert_eq!(Some(&0), hamt.get(&0));
        assert_eq!(Some(&0), hashmap.get(&0));
    }

    #[test]
    fn test_remove_basic() {
        let map = Hamt::new()
            .insert("a".to_string(), 1)
            .insert("b".to_string(), 2)
            .insert("c".to_string(), 3);
        assert_eq!(3, map.len());

        let removed = map.remove(&"b".to_string());
        assert_eq!(2, removed.len());
        assert_eq!(None, removed.get(&"b".to_string()));
        assert_eq!(Some(&1), removed.get(&"a".to_string()));
        assert_eq!(Some(&3), removed.get(&"c".to_string()));

        // Original map is unchanged (persistence / structural sharing).
        assert_eq!(3, map.len());
        assert_eq!(Some(&2), map.get(&"b".to_string()));
    }

    #[test]
    fn test_remove_absent_key_is_noop() {
        let map = Hamt::new().insert("a".to_string(), 1);
        let same = map.remove(&"missing".to_string());
        assert_eq!(1, same.len());
        assert_eq!(Some(&1), same.get(&"a".to_string()));
    }

    #[test]
    fn test_remove_until_empty() {
        let mut map = Hamt::new();
        for i in 0..50 {
            map = map.insert(i, i * 10);
        }
        for i in 0..50 {
            map = map.remove(&i);
            assert_eq!(None, map.get(&i));
        }
        assert!(map.is_empty());
        assert_eq!(0, map.len());
    }

    #[test]
    fn test_contains_key_and_entries() {
        let map = Hamt::new().insert(1u32, 10).insert(2, 20).insert(3, 30);
        assert!(map.contains_key(&2));
        assert!(!map.contains_key(&99));

        let mut entries = map.entries();
        entries.sort();
        assert_eq!(vec![(1, 10), (2, 20), (3, 30)], entries);
    }

    #[test]
    fn test_equivalence_with_btreemap() {
        use std::collections::BTreeMap;

        // Deterministic pseudo-random sequence of insert/remove operations,
        // checked against a BTreeMap reference oracle.
        let mut hamt: Hamt<u32, u32> = Hamt::new();
        let mut reference: BTreeMap<u32, u32> = BTreeMap::new();
        let mut state: u64 = 0x9e3779b97f4a7c15;

        for _ in 0..5000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let key = ((state >> 33) % 256) as u32;
            let op = (state >> 29) & 0x3;
            if op == 0 {
                hamt = hamt.remove(&key);
                reference.remove(&key);
            } else {
                let value = (state & 0xffff) as u32;
                hamt = hamt.insert(key, value);
                reference.insert(key, value);
            }
            assert_eq!(reference.len(), hamt.len());
        }

        // Every reference entry must be reachable with the same value.
        for (k, v) in &reference {
            assert_eq!(Some(v), hamt.get(k));
        }
        // And the full entry set must match exactly.
        let mut hamt_entries = hamt.entries();
        hamt_entries.sort();
        let ref_entries: Vec<(u32, u32)> = reference.into_iter().collect();
        assert_eq!(ref_entries, hamt_entries);
    }
}
