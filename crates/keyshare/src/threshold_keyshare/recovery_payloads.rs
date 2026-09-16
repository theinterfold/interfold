// SPDX-License-Identifier: LGPL-3.0-only

//! Large, immutable DKG recovery inputs stored outside the mutable root snapshot.

use super::{RecoveryPayloadRef, ThresholdKeyshareRecoveryState};
use alloy::primitives::keccak256;
use anyhow::{ensure, Context, Result};
use e3_data::DataStore;
use e3_events::{
    EventContext, Sequenced, ThresholdShareCreated, ThresholdSharePending, TypedEvent,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;

const PENDING_KEY: &str = "threshold-share-pending";

pub struct ThresholdKeyshareRecoveryPayloads {
    store: DataStore,
    pending: Option<TypedEvent<ThresholdSharePending>>,
    shares: BTreeMap<u64, TypedEvent<ThresholdShareCreated>>,
}

impl ThresholdKeyshareRecoveryPayloads {
    pub fn new(store: DataStore) -> Self {
        Self {
            store,
            pending: None,
            shares: BTreeMap::new(),
        }
    }

    pub async fn load(store: DataStore, root: &ThresholdKeyshareRecoveryState) -> Result<Self> {
        let pending = match root.threshold_share_pending_ref.as_ref() {
            Some(reference) => Some(
                Self::read(&store.scope(PENDING_KEY), reference)
                    .await
                    .context("could not load the pending DKG work plan")?,
            ),
            None => None,
        };
        let mut shares = BTreeMap::new();
        for (&party_id, reference) in &root.threshold_share_refs {
            let event: TypedEvent<ThresholdShareCreated> =
                Self::read(&store.scope(Self::share_key(party_id)), reference)
                    .await
                    .with_context(|| format!("could not load DKG share from party {party_id}"))?;
            ensure!(
                event.share.party_id == party_id,
                "stored DKG share party does not match its recovery key"
            );
            shares.insert(party_id, event);
        }
        Ok(Self {
            store,
            pending,
            shares,
        })
    }

    pub fn pending(&self) -> Option<&TypedEvent<ThresholdSharePending>> {
        self.pending.as_ref()
    }

    pub fn shares(&self) -> &BTreeMap<u64, TypedEvent<ThresholdShareCreated>> {
        &self.shares
    }

    pub fn share(&self, party_id: u64) -> Option<&TypedEvent<ThresholdShareCreated>> {
        self.shares.get(&party_id)
    }

    pub fn write_pending(
        &self,
        event: &TypedEvent<ThresholdSharePending>,
        ec: &EventContext<Sequenced>,
    ) -> Result<RecoveryPayloadRef> {
        Self::write(&self.store.scope(PENDING_KEY), event, ec)
    }

    pub fn remember_pending(&mut self, event: TypedEvent<ThresholdSharePending>) {
        self.pending = Some(event);
    }

    pub fn write_share(
        &self,
        event: &TypedEvent<ThresholdShareCreated>,
        ec: &EventContext<Sequenced>,
    ) -> Result<RecoveryPayloadRef> {
        Self::write(
            &self.store.scope(Self::share_key(event.share.party_id)),
            event,
            ec,
        )
    }

    pub fn remember_share(&mut self, event: TypedEvent<ThresholdShareCreated>) {
        self.shares.entry(event.share.party_id).or_insert(event);
    }

    pub fn write_pending_tombstone(&self, ec: &EventContext<Sequenced>) -> Result<()> {
        self.store
            .scope(PENDING_KEY)
            .write_with_context(Option::<Vec<u8>>::None, ec)?;
        Ok(())
    }

    pub fn forget_pending(&mut self) {
        self.pending = None;
    }

    pub fn write_all_share_tombstones(
        &self,
        party_count: u64,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        for party_id in 0..party_count {
            self.store
                .scope(Self::share_key(party_id))
                .write_with_context(Option::<Vec<u8>>::None, ec)?;
        }
        Ok(())
    }

    pub fn forget_shares(&mut self) {
        self.shares.clear();
    }

    fn share_key(party_id: u64) -> String {
        format!("threshold-shares/{party_id}")
    }

    fn write<T: Serialize>(
        store: &DataStore,
        value: &T,
        ec: &EventContext<Sequenced>,
    ) -> Result<RecoveryPayloadRef> {
        let bytes = bincode::serialize(value).context("could not encode DKG recovery payload")?;
        let reference = RecoveryPayloadRef {
            encoded_len: u64::try_from(bytes.len())?,
            digest: keccak256(&bytes).into(),
        };
        store.write_with_context(bytes, ec)?;
        Ok(reference)
    }

    async fn read<T: DeserializeOwned>(
        store: &DataStore,
        reference: &RecoveryPayloadRef,
    ) -> Result<T> {
        let bytes = store
            .read::<Vec<u8>>()
            .await?
            .context("referenced DKG recovery payload is missing")?;
        ensure!(
            bytes.len() as u64 == reference.encoded_len,
            "DKG recovery payload length does not match its reference"
        );
        let digest: [u8; 32] = keccak256(&bytes).into();
        ensure!(
            digest == reference.digest,
            "DKG recovery payload digest does not match its reference"
        );
        bincode::deserialize(&bytes).context("could not decode DKG recovery payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Actor;
    use e3_data::InMemStore;
    use e3_events::{
        E3id, EffectsEnabled, EventConstructorWithTimestamp, EventSource, InterfoldEvent,
        ThresholdShare, Unsequenced,
    };
    use e3_trbfv::shares::BfvEncryptedShares;
    use e3_utils::ArcBytes;
    use e3_zk_helpers::CiphernodesCommitteeSize;
    use std::sync::Arc;

    fn context() -> EventContext<Sequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            EffectsEnabled::new().into(),
            None,
            1,
            None,
            EventSource::Local,
        )
        .into_sequenced(1)
        .get_ctx()
        .clone()
    }

    fn share_event() -> TypedEvent<ThresholdShareCreated> {
        TypedEvent::new(
            ThresholdShareCreated {
                e3_id: E3id::new("1", 1),
                share: Arc::new(ThresholdShare {
                    party_id: 2,
                    pk_share: ArcBytes::from_bytes(&[7; 32]),
                    sk_sss: BfvEncryptedShares::default(),
                    esi_sss: Vec::new(),
                }),
                target_party_id: 0,
                external: true,
                signed_c2a_proof: None,
                signed_c2b_proof: None,
                signed_c3a_proofs: Vec::new(),
                signed_c3b_proofs: Vec::new(),
            },
            context(),
        )
    }

    #[actix::test]
    async fn loads_a_hash_checked_share_from_its_split_payload() -> Result<()> {
        let store = InMemStore::new(false).start();
        let data = DataStore::from_in_mem(&store);
        let payloads = ThresholdKeyshareRecoveryPayloads::new(data.clone());
        let event = share_event();
        let reference = payloads.write_share(&event, event.get_ctx())?;
        let mut root = ThresholdKeyshareRecoveryState::default();
        root.threshold_share_refs.insert(2, reference);

        let loaded = ThresholdKeyshareRecoveryPayloads::load(data, &root).await?;
        assert_eq!(loaded.share(2), Some(&event));
        Ok(())
    }

    #[actix::test]
    async fn rejects_a_payload_that_does_not_match_its_digest() -> Result<()> {
        let store = InMemStore::new(false).start();
        let data = DataStore::from_in_mem(&store);
        let payloads = ThresholdKeyshareRecoveryPayloads::new(data.clone());
        let event = share_event();
        let reference = payloads.write_share(&event, event.get_ctx())?;
        data.scope(ThresholdKeyshareRecoveryPayloads::share_key(2))
            .write_sync(vec![0xff_u8; 32])
            .await?;
        let mut root = ThresholdKeyshareRecoveryState::default();
        root.threshold_share_refs.insert(2, reference);

        assert!(ThresholdKeyshareRecoveryPayloads::load(data, &root)
            .await
            .is_err());
        Ok(())
    }

    #[actix::test]
    async fn rejects_a_missing_referenced_payload() -> Result<()> {
        let store = InMemStore::new(false).start();
        let data = DataStore::from_in_mem(&store);
        let mut root = ThresholdKeyshareRecoveryState::default();
        root.threshold_share_refs.insert(
            2,
            RecoveryPayloadRef {
                encoded_len: 32,
                digest: [0x5a; 32],
            },
        );

        assert!(ThresholdKeyshareRecoveryPayloads::load(data, &root)
            .await
            .is_err());
        Ok(())
    }

    #[actix::test]
    async fn tombstone_retires_a_stored_share() -> Result<()> {
        let store = InMemStore::new(false).start();
        let data = DataStore::from_in_mem(&store);
        let payloads = ThresholdKeyshareRecoveryPayloads::new(data.clone());
        let event = share_event();
        payloads.write_share(&event, event.get_ctx())?;
        payloads.write_all_share_tombstones(3, event.get_ctx())?;

        assert!(data
            .scope(ThresholdKeyshareRecoveryPayloads::share_key(2))
            .read::<Vec<u8>>()
            .await?
            .is_none());
        Ok(())
    }

    #[test]
    fn root_snapshot_size_is_independent_of_payload_size() -> Result<()> {
        let reference = RecoveryPayloadRef {
            encoded_len: u64::MAX,
            digest: [0x5a; 32],
        };
        let mut root = ThresholdKeyshareRecoveryState {
            threshold_share_pending_ref: Some(reference.clone()),
            ..Default::default()
        };
        for party_id in 0..CiphernodesCommitteeSize::Small.values().n as u64 {
            root.threshold_share_refs
                .insert(party_id, reference.clone());
        }

        assert!(bincode::serialized_size(&root)? < 4_096);
        Ok(())
    }
}
