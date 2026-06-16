// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::any::Any;
use std::{collections::HashMap, marker::PhantomData};

/// A key that is associated to a type within the HetrogenousMap given by the generic parameter T
pub struct TypedKey<T> {
    name: &'static str,
    _phantom: PhantomData<T>,
}

impl<T> TypedKey<T> {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _phantom: PhantomData,
        }
    }
}

/// A map that accepts hetrogenous data and stores it in a typesafe way using a typed key
pub struct HetrogenousMap {
    storage: HashMap<&'static str, Box<dyn Any + Send + Sync>>,
}

impl Default for HetrogenousMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HetrogenousMap {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }

    /// Insert data of type T
    pub fn insert<T: Send + Sync + 'static>(&mut self, key: TypedKey<T>, dep: T) {
        self.storage.insert(key.name, Box::new(dep));
    }

    /// Get data of type T
    pub fn get<T: Send + Sync + 'static>(&self, key: TypedKey<T>) -> Option<&T> {
        self.storage.get(key.name)?.downcast_ref()
    }

    /// Search for data that holds data under the given key name
    pub fn contains(&self, name: &'static str) -> bool {
        self.storage.contains_key(name)
    }

    /// Get a list of all key names
    pub fn keys(&self) -> Vec<String> {
        self.storage.keys().map(|&k| k.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Define test keys
    const STRING_KEY: TypedKey<String> = TypedKey::new("string_value");
    const INT_KEY: TypedKey<i32> = TypedKey::new("int_value");
    const FLOAT_KEY: TypedKey<f64> = TypedKey::new("float_value");
    const VEC_KEY: TypedKey<Vec<i32>> = TypedKey::new("vec_value");
    const ARC_KEY: TypedKey<Arc<String>> = TypedKey::new("arc_value");

    #[test]
    fn test_basic_insert_and_get() {
        let mut map = HetrogenousMap::new();
        map.insert(STRING_KEY, "hello".to_string());
        map.insert(INT_KEY, 42);

        assert_eq!(map.get(STRING_KEY), Some(&"hello".to_string()));
        assert_eq!(map.get(INT_KEY), Some(&42));
    }

    #[test]
    fn test_overwrite_value() {
        let mut map = HetrogenousMap::new();
        map.insert(INT_KEY, 42);
        map.insert(INT_KEY, 24);

        assert_eq!(map.get(INT_KEY), Some(&24));
    }

    #[test]
    fn test_get_nonexistent_key() {
        let map = HetrogenousMap::new();
        assert_eq!(map.get(STRING_KEY), None);
    }

    #[test]
    fn test_contains() {
        let mut map = HetrogenousMap::new();
        map.insert(STRING_KEY, "test".to_string());

        assert!(map.contains("string_value"));
        assert!(!map.contains("nonexistent"));
    }

    #[test]
    fn test_keys() {
        let mut map = HetrogenousMap::new();
        map.insert(STRING_KEY, "test".to_string());
        map.insert(INT_KEY, 42);

        let mut keys = map.keys();
        keys.sort(); // Sort for deterministic comparison
        assert_eq!(keys, vec!["int_value", "string_value"]);
    }

    #[test]
    fn test_complex_types() {
        let mut map = HetrogenousMap::new();

        // Test with Vec
        let vec_data = vec![1, 2, 3];
        map.insert(VEC_KEY, vec_data.clone());
        assert_eq!(map.get(VEC_KEY), Some(&vec_data));

        // Test with Arc
        let arc_data = Arc::new("shared data".to_string());
        map.insert(ARC_KEY, arc_data.clone());
        assert_eq!(map.get(ARC_KEY).map(|a| a.as_str()), Some("shared data"));
    }

    #[test]
    fn test_multiple_types() {
        let mut map = HetrogenousMap::new();

        map.insert(STRING_KEY, "string".to_string());
        map.insert(INT_KEY, 42);
        map.insert(FLOAT_KEY, 1.5);

        assert_eq!(map.get(STRING_KEY), Some(&"string".to_string()));
        assert_eq!(map.get(INT_KEY), Some(&42));
        assert_eq!(map.get(FLOAT_KEY), Some(&1.5));
    }

    // This test verifies that Send + Sync bounds work correctly
    #[test]
    fn test_thread_safety() {
        use std::thread;

        let mut map = HetrogenousMap::new();
        map.insert(STRING_KEY, "test".to_string());

        let map_arc = Arc::new(map);
        let map_clone = map_arc.clone();

        let handle = thread::spawn(move || {
            assert_eq!(map_clone.get(STRING_KEY), Some(&"test".to_string()));
        });

        handle.join().unwrap();
    }
}
