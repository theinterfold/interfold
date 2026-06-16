// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct OrderedSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> OrderedSet<T> {
    pub fn new() -> Self {
        OrderedSet(BTreeSet::new())
    }

    pub fn insert(&mut self, value: T) -> bool {
        self.0.insert(value)
    }

    pub fn contains(&self, value: &T) -> bool {
        self.0.contains(value)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn remove(&mut self, value: &T) -> bool {
        self.0.remove(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }

    pub fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T: Ord + Hash> Hash for OrderedSet<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.len().hash(state);
        for item in &self.0 {
            item.hash(state);
        }
    }
}

impl<T: Ord + PartialEq> PartialEq for OrderedSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Ord + Eq> Eq for OrderedSet<T> {}

impl<T: Ord + fmt::Debug> fmt::Debug for OrderedSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.iter()).finish()
    }
}

impl<T: Ord> IntoIterator for OrderedSet<T> {
    type Item = T;
    type IntoIter = std::collections::btree_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T: Ord> IntoIterator for &'a OrderedSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord> From<Vec<T>> for OrderedSet<T> {
    fn from(vec: Vec<T>) -> Self {
        Self::from_iter(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn test_new() {
        let set: OrderedSet<i32> = OrderedSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_insert() {
        let mut set = OrderedSet::new();
        assert!(set.insert(1));
        assert!(set.insert(2));
        assert!(!set.insert(1)); // Duplicate insertion
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_contains() {
        let mut set = OrderedSet::new();
        set.insert(1);
        set.insert(2);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut set = OrderedSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        set.insert(1);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_iter() {
        let mut set = OrderedSet::new();
        set.insert(3);
        set.insert(1);
        set.insert(2);
        let mut iter = set.iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), Some(&3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_hash() {
        let mut set1 = OrderedSet::new();
        set1.insert(1);
        set1.insert(2);

        let mut set2 = OrderedSet::new();
        set2.insert(2);
        set2.insert(1);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();

        set1.hash(&mut hasher1);
        set2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_eq() {
        let mut set1 = OrderedSet::new();
        set1.insert(1);
        set1.insert(2);

        let mut set2 = OrderedSet::new();
        set2.insert(2);
        set2.insert(1);

        let mut set3 = OrderedSet::new();
        set3.insert(1);
        set3.insert(3);

        assert_eq!(set1, set2);
        assert_ne!(set1, set3);
    }

    #[test]
    fn test_debug() {
        let mut set = OrderedSet::new();
        set.insert(1);
        set.insert(2);
        assert_eq!(format!("{:?}", set), "{1, 2}");
    }

    #[test]
    fn test_into_iter() {
        let mut set = OrderedSet::new();
        set.insert(3);
        set.insert(1);
        set.insert(2);
        let vec: Vec<i32> = set.into_iter().collect();
        assert_eq!(vec, vec![1, 2, 3]);
    }

    #[test]
    fn test_iter_ref() {
        let mut set = OrderedSet::new();
        set.insert(3);
        set.insert(1);
        set.insert(2);
        let vec: Vec<&i32> = (&set).into_iter().collect();
        assert_eq!(vec, vec![&1, &2, &3]);
    }

    #[test]
    fn test_from_vec() {
        let vec = vec![
            "apple".to_string(),
            "banana".to_string(),
            "cherry".to_string(),
            "apple".to_string(),
        ];
        let set: OrderedSet<String> = OrderedSet::from(vec);

        assert_eq!(set.len(), 3);
        assert!(set.contains(&"apple".to_string()));
        assert!(set.contains(&"banana".to_string()));
        assert!(set.contains(&"cherry".to_string()));

        let vec_from_set: Vec<&String> = set.iter().collect();
        assert_eq!(vec_from_set, vec!["apple", "banana", "cherry"]);
    }

    #[test]
    fn test_extend() {
        let mut set = OrderedSet::new();
        set.insert("apple".to_string());

        set.extend(vec![
            "banana".to_string(),
            "cherry".to_string(),
            "apple".to_string(),
        ]);

        assert_eq!(set.len(), 3);
        assert!(set.contains(&"apple".to_string()));
        assert!(set.contains(&"banana".to_string()));
        assert!(set.contains(&"cherry".to_string()));
    }
}
