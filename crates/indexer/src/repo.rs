// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    models::{CiphertextOutputReference, E3},
    DataStore, SharedStore,
};
use eyre::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct E3Repository<S: DataStore> {
    store: SharedStore<S>,
    e3_id: String,
}

impl<S: DataStore> E3Repository<S> {
    pub fn new(store: SharedStore<S>, e3_id: impl ToString) -> Self {
        Self {
            store,
            e3_id: e3_id.to_string(),
        }
    }

    pub async fn set_e3(&mut self, value: E3) -> Result<()> {
        let key = self.e3_key();
        self.store
            .insert(&key, &value)
            .await
            .map_err(|e| eyre::eyre!("Could not store E3 at '{key}' due to error: {e}"))?;
        Ok(())
    }

    /// Store the initial E3 record without replacing indexed round data.
    pub async fn set_e3_if_absent(&mut self, value: E3) -> Result<bool> {
        let key = self.e3_key();
        let inserted = Arc::new(AtomicBool::new(false));
        let inserted_in_update = Arc::clone(&inserted);
        self.store
            .modify(&key, move |current: Option<E3>| match current {
                Some(current) => Some(current),
                None => {
                    inserted_in_update.store(true, Ordering::Relaxed);
                    Some(value.clone())
                }
            })
            .await
            .map_err(|e| eyre::eyre!("Could not store E3 at '{key}' due to error: {e}"))?;
        Ok(inserted.load(Ordering::Relaxed))
    }

    pub async fn get_e3(&self) -> Result<E3> {
        let key = self.e3_key();
        let e3_crisp = self
            .store
            .get::<E3>(&key)
            .await
            .map_err(|e| eyre::eyre!("Could get crisp at '{key}' due to error: {e}"))?
            .ok_or(eyre::eyre!("No data found at {key}"))?;
        Ok(e3_crisp)
    }
    pub async fn insert_ciphertext_input(&mut self, data: Vec<u8>, index: u64) -> Result<()> {
        let key = self.e3_key();
        self.store
            .modify(&key, |e3_obj: Option<E3>| {
                e3_obj.map(|mut e| {
                    e.ciphertext_inputs.push((data.clone(), index));
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not append ciphertext_input for '{key}'"))?;

        Ok(())
    }
    pub async fn set_plaintext_output(&mut self, data: Vec<u8>) -> Result<()> {
        let key = self.e3_key();
        self.store
            .modify(&key, |e3_obj: Option<E3>| {
                e3_obj.map(|mut e| {
                    e.plaintext_output = data.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not append ciphertext_input for '{key}'"))?;
        Ok(())
    }

    pub async fn set_ciphertext_output(&mut self, data: Vec<u8>) -> Result<()> {
        let key = self.e3_key();
        self.store
            .modify(&key, |e3_obj: Option<E3>| {
                e3_obj.map(|mut e| {
                    e.ciphertext_output = data.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not append ciphertext_input for '{key}'"))?;
        Ok(())
    }

    pub async fn set_ciphertext_commitment(&mut self, data: Vec<u8>) -> Result<()> {
        let key = self.e3_key();
        self.store
            .modify(&key, |e3_obj: Option<E3>| {
                e3_obj.map(|mut e| {
                    e.ciphertext_commitment = data.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set ciphertext_commitment for '{key}'"))?;
        Ok(())
    }

    pub async fn set_ciphertext_output_reference(
        &mut self,
        reference: CiphertextOutputReference,
        commitment: Vec<u8>,
    ) -> Result<()> {
        let key = self.e3_key();
        self.store
            .modify(&key, |e3_obj: Option<E3>| {
                e3_obj.map(|mut e| {
                    e.ciphertext_output_reference = Some(reference.clone());
                    e.ciphertext_commitment = commitment.clone();
                    e
                })
            })
            .await
            .map_err(|_| eyre::eyre!("Could not set ciphertext output reference for '{key}'"))?;
        Ok(())
    }

    fn e3_key(&self) -> String {
        let e3_id = &self.e3_id;
        format!("_e3:{e3_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::E3Repository;
    use crate::{models::E3, InMemoryStore, SharedStore};
    use e3_evm_helpers::contracts::CommitteeSize;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn e3(public_key: u8, ciphertext_output: Vec<u8>) -> E3 {
        E3 {
            chain_id: 1,
            ciphertext_inputs: vec![(vec![3], 0)],
            ciphertext_output,
            ciphertext_output_reference: None,
            ciphertext_commitment: vec![4],
            committee_public_key: vec![public_key],
            committee_public_key_hash: vec![public_key; 32],
            e3_params: vec![5],
            custom_params: vec![6],
            interfold_address: "0x0000000000000000000000000000000000000001".to_string(),
            encryption_scheme_id: vec![7; 32],
            crypto_config_id: vec![8; 32],
            id: "12".to_string(),
            plaintext_output: vec![9],
            request_block: 10,
            seed: [11; 32],
            input_window: [12, 13],
            committee_size: CommitteeSize::Minimum,
            requester: "0x0000000000000000000000000000000000000002".to_string(),
        }
    }

    #[tokio::test]
    async fn committee_replay_does_not_replace_indexed_round_state() {
        let store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        let mut repo = E3Repository::new(store, "12");

        assert!(repo.set_e3_if_absent(e3(1, vec![2])).await.unwrap());
        assert!(!repo.set_e3_if_absent(e3(99, vec![])).await.unwrap());

        let stored = repo.get_e3().await.unwrap();
        assert_eq!(stored.committee_public_key, vec![1]);
        assert_eq!(stored.ciphertext_output, vec![2]);
        assert_eq!(stored.plaintext_output, vec![9]);
    }

    #[tokio::test]
    async fn output_reference_and_commitment_are_stored_together() {
        let store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        let mut repo = E3Repository::new(store, "12");
        repo.set_e3(e3(1, vec![])).await.unwrap();

        let reference = crate::models::CiphertextOutputReference {
            content_hash: vec![7; 32],
            availability_block: 42,
            availability_leaf_index: 9,
        };
        repo.set_ciphertext_output_reference(reference.clone(), vec![8; 32])
            .await
            .unwrap();

        let stored = repo.get_e3().await.unwrap();
        assert_eq!(stored.ciphertext_output_reference, Some(reference));
        assert_eq!(stored.ciphertext_commitment, vec![8; 32]);
    }
}
