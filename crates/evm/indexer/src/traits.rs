// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Display;

/// Trait for injectable DataStore. Note the implementor must manage interior mutability
#[async_trait]
pub trait DataStore: Send + Sync + 'static {
    type Error: Display;
    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error>;
    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Self::Error>;
    async fn modify<T, F>(&mut self, key: &str, f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send;
}
