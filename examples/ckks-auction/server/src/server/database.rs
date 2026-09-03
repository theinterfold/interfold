// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! sled-backed `DataStore` for the Interfold indexer (CRISP's `SledDB`).

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
}

#[async_trait]
impl DataStore for SledDB {
    type Error = DatabaseError;

    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.db.insert(key.as_bytes(), serde_json::to_vec(value)?)?;
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
        let result = self.db.update_and_fetch(key, |old| {
            let current = old.and_then(|bytes| serde_json::from_slice(bytes).ok());
            f(current).and_then(|v| serde_json::to_vec(&v).ok())
        })?;
        result
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(Into::into)
    }
}
