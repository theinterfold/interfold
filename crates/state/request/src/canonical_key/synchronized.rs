// SPDX-License-Identifier: LGPL-3.0-only

use super::{CanonicalPublicKey, CanonicalPublicKeys};
use alloy::primitives::U256;
use anyhow::{ensure, Result};
use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
use e3_events::{E3id, SynchronizedDkgContext};
use e3_fhe_params::BfvDecryptionProtocol;

mod publication;

/// Finalized pre-publication committee recovered by the shared confirmed-history projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynchronizedDkgSelection {
    pub params_profile: e3_fhe_params::BfvProfile,
    pub committee_size: e3_committee::CiphernodesCommitteeSize,
    pub interfold_address: alloy::primitives::Address,
    pub committee: Vec<alloy::primitives::Address>,
}

impl CanonicalPublicKeys {
    pub fn synchronized_selection(&self, id: &E3id) -> Option<SynchronizedDkgSelection> {
        self.0
            .read()
            .expect("canonical key lock")
            .synchronized_selections
            .get(id)
            .cloned()
    }

    pub fn remember_synchronized_selection(
        &self,
        id: E3id,
        selection: SynchronizedDkgSelection,
    ) -> Result<()> {
        ensure!(
            selection.params_profile.protocol() == BfvDecryptionProtocol::Synchronized,
            "synchronized selection cannot use SS"
        );
        selection
            .params_profile
            .validate_committee(selection.committee_size)?;
        ensure!(
            !selection.interfold_address.is_zero()
                && selection.committee.len() == selection.committee_size.values().n
                && selection.committee.iter().all(|node| !node.is_zero())
                && selection
                    .committee
                    .windows(2)
                    .all(|nodes| nodes[0] < nodes[1]),
            "synchronized selection requires a complete canonical committee"
        );
        let mut keys = self.0.write().expect("canonical key lock");
        if let Some(previous) = keys.synchronized_selections.get(&id) {
            ensure!(
                previous == &selection,
                "confirmed synchronized selection changed"
            );
        } else {
            keys.synchronized_selections.insert(id, selection);
        }
        Ok(())
    }

    /// Frozen chain facts needed before publication consent, recovered by the same history owner.
    pub fn synchronized_context(&self, id: &E3id) -> Option<SynchronizedDkgContext> {
        self.0
            .read()
            .expect("canonical key lock")
            .synchronized_contexts
            .get(id)
            .copied()
    }

    pub fn remember_synchronized_context(
        &self,
        id: E3id,
        context: SynchronizedDkgContext,
    ) -> Result<()> {
        ensure!(
            !context.registry.is_zero()
                && !context.verifying_contract.is_zero()
                && context.crypto_config_id
                    == e3_fhe_params::BfvProfile::SyncDecInsecure64
                        .crypto_config_id(e3_committee::CiphernodesCommitteeSize::Minimum)?
                        .0,
            "unsupported synchronized DKG signing context"
        );
        let mut keys = self.0.write().expect("canonical key lock");
        if let Some(previous) = keys.synchronized_contexts.get(&id) {
            ensure!(
                previous == &context,
                "request-frozen synchronized context changed"
            );
        } else {
            keys.synchronized_contexts.insert(id, context);
        }
        Ok(())
    }
}

/// Confirmed setup rows in selected H order, never an SS ESM column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynchronizedDkgAuthority {
    pub version: u8,
    pub context: SynchronizedDkgContext,
    pub setup_binding: [u8; 32],
    pub dealer_batch: [u8; 32],
    pub party_ids: Vec<u32>,
    pub threshold_pk_commits: Vec<[u8; 32]>,
    pub sk_agg_commits: Vec<[u8; 32]>,
    pub key_bundle_commits: Vec<[u8; 32]>,
}

impl SynchronizedDkgAuthority {
    pub(super) fn validate(&self, id: &E3id, key: &CanonicalPublicKey) -> Result<()> {
        ensure!(
            key.params_profile.protocol() == BfvDecryptionProtocol::Synchronized,
            "synchronized authority has an SS profile"
        );
        key.params_profile.validate_committee(key.committee_size)?;
        let shape = key.committee_size.values();
        ensure!(
            self.version == 1
                && !self.context.registry.is_zero()
                && !self.context.verifying_contract.is_zero()
                && !key.interfold_address.is_zero()
                && key.pk_commitment != [0; 32],
            "unsupported or incomplete synchronized authority"
        );
        ensure!(
            self.context.crypto_config_id
                == key.params_profile.crypto_config_id(key.committee_size)?.0,
            "synchronized authority has another crypto configuration"
        );
        ensure!(
            key.committee.len() == shape.n
                && key.committee.iter().all(|node| !node.is_zero())
                && key.committee.windows(2).all(|nodes| nodes[0] < nodes[1]),
            "synchronized authority requires the complete canonical committee"
        );
        ensure!(
            self.party_ids.len() == shape.h
                && self
                    .party_ids
                    .iter()
                    .all(|&party| (party as usize) < shape.n)
                && self.party_ids.windows(2).all(|ids| ids[0] < ids[1])
                && self.threshold_pk_commits.len() == shape.h
                && self.sk_agg_commits.len() == shape.h
                && self.key_bundle_commits.len() == shape.h
                && key.honest_committee
                    == self
                        .party_ids
                        .iter()
                        .map(|&party| key.committee[party as usize])
                        .collect::<Vec<_>>(),
            "synchronized authority rows do not name the exact H roster"
        );
        let setup = DkgSetupContext {
            interfold_address: key.interfold_address,
            committee_hash: hash_committee_addresses(&key.committee),
            crypto_config_id: self.context.crypto_config_id.into(),
        };
        ensure!(
            setup.hash(id.chain_id(), id.clone().try_into()?).0 == self.setup_binding,
            "synchronized authority belongs to another request setup"
        );
        let modulus = U256::from_be_slice(&e3_zk_config::field::get_zkp_modulus().to_bytes_be().1);
        ensure!(
            self.threshold_pk_commits
                .iter()
                .chain(&self.sk_agg_commits)
                .chain(&self.key_bundle_commits)
                .chain([&self.dealer_batch, &key.pk_commitment])
                .all(|field| U256::from_be_bytes(*field) < modulus),
            "synchronized authority contains a noncanonical field"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
