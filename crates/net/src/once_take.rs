// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::{Arc, Mutex};

use tracing::info;

/// A cloneable wrapper that allows a non-cloneable value to be shared and taken exactly once.
///
/// Useful for passing oneshot channels or other single-use items through cloneable contexts.
///
/// # Example
/// ```
/// use e3_net::OnceTake;
///
/// let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
/// let once = OnceTake::new(tx);
/// let cloned = once.clone();
/// cloned.take().unwrap().send(42).unwrap();
/// assert!(once.take().is_none()); // already taken
/// ```
#[derive(Debug)]
pub struct OnceTake<T>(Arc<Mutex<Option<T>>>);

impl<T> OnceTake<T> {
    /// Wraps an item so it can be cloned and later taken once.
    pub fn new(item: T) -> Self {
        Self(Arc::new(Mutex::new(Some(item))))
    }

    /// Takes the item, returning `None` if already taken.
    pub fn take(&self) -> Option<T> {
        info!("take has been called!");
        self.0.lock().unwrap().take()
    }

    /// Takes the item, returning an error if already taken.
    pub fn try_take(&self) -> anyhow::Result<T> {
        self.take()
            .ok_or_else(|| anyhow::anyhow!("Item already taken."))
    }
}

impl<T> Clone for OnceTake<T> {
    fn clone(&self) -> Self {
        OnceTake(Arc::clone(&self.0))
    }
}
