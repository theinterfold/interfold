// SPDX-License-Identifier: LGPL-3.0-only

//! Chain authority shared by key admission, proof dispatch and plaintext aggregation.

use alloy::primitives::{keccak256, Address, B256};
use anyhow::{ensure, Result};
use e3_events::{E3id, PublicKeyAggregated, ThresholdShareDecryptionProofRequest};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPublicKey {
    pub pk_commitment: [u8; 32],
    pub committee: Vec<Address>,
    pub honest_committee: Vec<Address>,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
    pub interfold_address: Address,
    pub sk_agg_commits: Vec<[u8; 32]>,
    pub esm_agg_commits: Vec<[u8; 32]>,
}

impl CanonicalPublicKey {
    pub fn validate_key(&self, bytes: &[u8]) -> Result<()> {
        let params = BfvParamSet::from(self.params_preset);
        e3_bfv_client::validate_pk_commitment(
            bytes,
            self.pk_commitment,
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )
    }

    pub fn accepts(&self, data: &PublicKeyAggregated) -> bool {
        data.pk_commitment == self.pk_commitment
            && data.committee_addresses == self.committee
            && data.honest_committee_addresses == self.honest_committee
            && self.validate_key(&data.pubkey).is_ok()
    }

    pub fn domain(&self, interfold_address: Address) -> e3_committee_hash::DecryptionDomainContext {
        e3_committee_hash::DecryptionDomainContext {
            interfold_address,
            committee_hash: e3_committee_hash::hash_committee_addresses(&self.committee),
            committee_public_key: self.pk_commitment.into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct CanonicalKeyState {
    authority: HashMap<E3id, CanonicalPublicKey>,
    bytes: HashMap<E3id, ArcBytes>,
    ciphertext_hashes: HashMap<E3id, Vec<B256>>,
}

#[derive(Clone, Debug, Default)]
pub struct CanonicalPublicKeys(Arc<RwLock<CanonicalKeyState>>);

impl CanonicalPublicKeys {
    pub fn get(&self, id: &E3id) -> Option<CanonicalPublicKey> {
        self.0
            .read()
            .expect("canonical key lock")
            .authority
            .get(id)
            .cloned()
    }

    pub fn insert(&self, id: E3id, key: CanonicalPublicKey) -> Result<()> {
        let mut keys = self.0.write().expect("canonical key lock");
        if let Some(existing) = keys.authority.get(&id) {
            ensure!(
                existing == &key,
                "chain public-key context changed for E3 {id}"
            );
        } else {
            keys.authority.insert(id, key);
        }
        Ok(())
    }

    pub fn remove(&self, id: &E3id) {
        let mut keys = self.0.write().expect("canonical key lock");
        keys.authority.remove(id);
        keys.bytes.remove(id);
        keys.ciphertext_hashes.remove(id);
    }

    /// Retain ciphertext bindings from the confirmed output ingestion path.
    pub fn remember_ciphertexts(&self, id: &E3id, ciphertexts: &[ArcBytes]) -> Result<()> {
        let hashes = ciphertexts
            .iter()
            .map(|bytes| keccak256(&bytes[..]))
            .collect();
        let mut keys = self.0.write().expect("canonical key lock");
        if let Some(existing) = keys.ciphertext_hashes.get(id) {
            ensure!(existing == &hashes, "chain ciphertext changed for E3 {id}");
        } else {
            keys.ciphertext_hashes.insert(id.clone(), hashes);
        }
        Ok(())
    }

    pub fn decryption_domains(
        &self,
        id: &E3id,
    ) -> Option<Vec<e3_committee_hash::DecryptionDomainLimbs>> {
        let keys = self.0.read().expect("canonical key lock");
        let key = keys.authority.get(id)?;
        let hashes = keys.ciphertext_hashes.get(id)?;
        let e3_id = id.clone().try_into().ok()?;
        Some(
            hashes
                .iter()
                .map(|hash| {
                    e3_committee_hash::decryption_domain_limbs(
                        id.chain_id(),
                        e3_id,
                        key.domain(key.interfold_address),
                        *hash,
                    )
                })
                .collect(),
        )
    }

    pub fn forget_bytes(&self, id: &E3id) {
        self.0.write().expect("canonical key lock").bytes.remove(id);
    }

    pub fn public_key(&self, id: &E3id) -> Option<ArcBytes> {
        self.0
            .read()
            .expect("canonical key lock")
            .bytes
            .get(id)
            .cloned()
    }

    pub fn remember_key(&self, id: &E3id, bytes: ArcBytes) -> Result<()> {
        let key = self
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("chain public-key context is unavailable"))?;
        key.validate_key(&bytes)?;
        self.0
            .write()
            .expect("canonical key lock")
            .bytes
            .entry(id.clone())
            .or_insert(bytes);
        Ok(())
    }

    /// Rebuild only the public inputs. Retain the exact secret and ciphertext witnesses.
    pub fn repair_request(
        &self,
        id: &E3id,
        request: &mut ThresholdShareDecryptionProofRequest,
    ) -> Result<()> {
        let key = self
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("chain public-key context is unavailable"))?;
        let bytes = self
            .public_key(id)
            .unwrap_or_else(|| request.aggregated_pk_bytes.clone());
        key.validate_key(&bytes)?;
        request.aggregated_pk_bytes = bytes;
        request.decryption_domain = key.domain(key.interfold_address);
        request.params_preset = key.params_preset;
        request.committee_size = key.committee_size;
        Ok(())
    }

    pub fn accepts_request(
        &self,
        id: &E3id,
        request: &ThresholdShareDecryptionProofRequest,
    ) -> bool {
        self.get(id).is_some_and(|key| {
            request.decryption_domain == key.domain(key.interfold_address)
                && request.params_preset == key.params_preset
                && request.committee_size == key.committee_size
                && key.validate_key(&request.aggregated_pk_bytes).is_ok()
        })
    }
}
