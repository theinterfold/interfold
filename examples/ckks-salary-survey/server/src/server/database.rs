// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sled store implementing the Interfold indexer's `DataStore` (CRISP shape).

use async_trait::async_trait;
use e3_sdk::indexer::DataStore;
use serde::{de::DeserializeOwned, Serialize};
use sled::Db;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("SledDB error: {0}")]
    SledDB(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct SledDB {
    pub db: Db,
}

impl SledDB {
    pub fn new(path: &str) -> Result<Self, DatabaseError> {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    /// Keys with the given prefix (used to list rounds).
    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.db
            .scan_prefix(prefix.as_bytes())
            .filter_map(|kv| kv.ok())
            .filter_map(|(k, _)| String::from_utf8(k.to_vec()).ok())
            .collect()
    }
}

#[async_trait]
impl DataStore for SledDB {
    type Error = DatabaseError;

    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let serialized = serde_json::to_vec(value)?;
        self.db.insert(key.as_bytes(), serialized)?;
        Ok(())
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Self::Error> {
        match self.db.get(key.as_bytes())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn modify<T, F>(&mut self, key: &str, mut f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send,
    {
        let result = self.db.update_and_fetch(key, |old_bytes| {
            let current_value = old_bytes.and_then(|bytes| serde_json::from_slice(bytes).ok());
            f(current_value).and_then(|val| serde_json::to_vec(&val).ok())
        })?;
        result
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(Into::into)
    }
}
