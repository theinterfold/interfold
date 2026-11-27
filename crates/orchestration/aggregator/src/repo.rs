// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::B256;
use anyhow::{ensure, Result};
use e3_data::{Repositories, Repository};
use e3_events::{
    E3id, LbfvKeyShareDocument, LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentReceived,
    SignedLbfvKeyShareManifest, StoreKeys,
};

use crate::{
    LbfvAggregationStateV1, LbfvContributionCollectionStateV1, LbfvPartyContributionStatusV1,
    LbfvPublicKeyPublicationStateV1, PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    ThresholdPlaintextAggregatorRecoveryState, ThresholdPlaintextAggregatorState,
};

pub trait TrBfvPlaintextRepositoryFactory {
    fn trbfv_plaintext(&self, e3_id: &E3id) -> Repository<ThresholdPlaintextAggregatorState>;
    fn trbfv_plaintext_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdPlaintextAggregatorRecoveryState>;
}

impl TrBfvPlaintextRepositoryFactory for Repositories {
    fn trbfv_plaintext(&self, e3_id: &E3id) -> Repository<ThresholdPlaintextAggregatorState> {
        Repository::new(self.store.scope(StoreKeys::plaintext(e3_id)))
    }

    fn trbfv_plaintext_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdPlaintextAggregatorRecoveryState> {
        Repository::new(self.store.scope(StoreKeys::plaintext_recovery(e3_id)))
    }
}

pub trait PublicKeyRepositoryFactory {
    fn publickey(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorState>;
    fn publickey_recovery(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorRecoveryState>;
    fn synchronized_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<crate::workflow::publickey_aggregation::synchronized::PublicationRecord>;
}

impl PublicKeyRepositoryFactory for Repositories {
    fn synchronized_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<crate::workflow::publickey_aggregation::synchronized::PublicationRecord> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_recovery(e3_id))
                .scope("synchronized-publication/v1"),
        )
    }
    fn publickey(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorState> {
        Repository::new(self.store.scope(StoreKeys::publickey(e3_id)))
    }

    fn publickey_recovery(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorRecoveryState> {
        Repository::new(self.store.scope(StoreKeys::publickey_recovery(e3_id)))
    }
}

#[async_trait::async_trait]
pub trait LbfvContributionRepositoryFactory {
    fn publickey_lbfv_aggregation(&self, e3_id: &E3id) -> Repository<LbfvAggregationStateV1>;
    fn publickey_lbfv_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvPublicKeyPublicationStateV1>;

    fn publickey_lbfv_collection(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvContributionCollectionStateV1>;

    fn publickey_lbfv_document(
        &self,
        e3_id: &E3id,
        sha256: &B256,
    ) -> Repository<LbfvKeyShareDocument>;

    async fn persist_publickey_lbfv_manifest(
        &self,
        state: &LbfvContributionCollectionStateV1,
        manifest: &SignedLbfvKeyShareManifest,
    ) -> Result<LbfvContributionCollectionStateV1>;

    /// Persist the artifact before the sidecar records its document slot.
    async fn persist_publickey_lbfv_document(
        &self,
        state: &LbfvContributionCollectionStateV1,
        received: &LbfvKeyShareDocumentReceived,
    ) -> Result<LbfvContributionCollectionStateV1>;

    /// Check one party's durable bundle against its manifest and commitments, and record the
    /// party as ready or permanently invalid. The commitment check runs on a blocking thread.
    async fn validate_publickey_lbfv_party(
        &self,
        state: &LbfvContributionCollectionStateV1,
        party_id: u32,
    ) -> Result<LbfvContributionCollectionStateV1>;

    async fn persist_publickey_lbfv_fetch_failure(
        &self,
        state: &LbfvContributionCollectionStateV1,
        failed: &LbfvKeyShareDocumentFetchFailed,
    ) -> Result<(LbfvContributionCollectionStateV1, bool)>;

    async fn persist_publickey_lbfv_transition(
        &self,
        expected: &LbfvContributionCollectionStateV1,
        updated: &LbfvContributionCollectionStateV1,
    ) -> Result<()>;
}

#[async_trait::async_trait]
impl LbfvContributionRepositoryFactory for Repositories {
    fn publickey_lbfv_aggregation(&self, e3_id: &E3id) -> Repository<LbfvAggregationStateV1> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_lbfv_aggregation(e3_id)),
        )
    }

    fn publickey_lbfv_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvPublicKeyPublicationStateV1> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_lbfv_publication(e3_id)),
        )
    }

    fn publickey_lbfv_collection(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvContributionCollectionStateV1> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_lbfv_collection(e3_id)),
        )
    }

    fn publickey_lbfv_document(
        &self,
        e3_id: &E3id,
        sha256: &B256,
    ) -> Repository<LbfvKeyShareDocument> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_lbfv_document(e3_id, sha256)),
        )
    }

    async fn persist_publickey_lbfv_manifest(
        &self,
        state: &LbfvContributionCollectionStateV1,
        manifest: &SignedLbfvKeyShareManifest,
    ) -> Result<LbfvContributionCollectionStateV1> {
        let collection = self.publickey_lbfv_collection(&state.e3_id);
        if let Some(current) = collection.read().await? {
            ensure!(
                current == *state,
                "persisted l-BFV collection state changed before manifest admission"
            );
        }
        let mut updated = state.clone();
        if updated.admit_manifest(manifest)? {
            collection.write_sync(&updated).await?;
        }
        Ok(updated)
    }

    async fn persist_publickey_lbfv_document(
        &self,
        state: &LbfvContributionCollectionStateV1,
        received: &LbfvKeyShareDocumentReceived,
    ) -> Result<LbfvContributionCollectionStateV1> {
        if !state.validate_document_admission(received)? {
            return Ok(state.clone());
        }
        let collection = self.publickey_lbfv_collection(&state.e3_id);
        let current = collection
            .read()
            .await?
            .ok_or_else(|| anyhow::anyhow!("l-BFV document manifest is not durable"))?;
        ensure!(
            current == *state,
            "persisted l-BFV collection state changed before document admission"
        );
        let artifact = self.publickey_lbfv_document(&state.e3_id, &received.content_hash);
        if let Some(existing) = artifact.read().await? {
            ensure!(
                existing == received.document,
                "persisted l-BFV artifact does not match its content hash"
            );
        } else {
            artifact.write_sync(&received.document).await?;
        }

        let mut updated = state.clone();
        if updated.mark_document_durable(received)? {
            collection.write_sync(&updated).await?;
        }
        Ok(updated)
    }

    async fn validate_publickey_lbfv_party(
        &self,
        state: &LbfvContributionCollectionStateV1,
        party_id: u32,
    ) -> Result<LbfvContributionCollectionStateV1> {
        let Some(party) = state.parties.get(&party_id) else {
            anyhow::bail!("l-BFV bundle party ID is outside the committee");
        };
        if matches!(
            state.verification,
            crate::LbfvContributionVerificationStateV1::Sealed { .. }
                | crate::LbfvContributionVerificationStateV1::Failed { .. }
        ) || party.status != LbfvPartyContributionStatusV1::DocumentsDurable
        {
            return Ok(state.clone());
        }
        let manifest = party
            .manifest
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("durable l-BFV documents have no manifest"))?
            .clone();
        let (public_key_hash, rlk_hash) =
            crate::domain::lbfv_contribution_collection::manifest_hashes(&manifest.payload);
        let public_key = self
            .publickey_lbfv_document(&state.e3_id, &public_key_hash)
            .read()
            .await?
            .ok_or_else(|| anyhow::anyhow!("durable l-BFV public-key artifact is missing"))?;
        let rlk = self
            .publickey_lbfv_document(&state.e3_id, &rlk_hash)
            .read()
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("durable l-BFV relinearization-key artifact is missing")
            })?;

        let preset = state.params_preset;
        let validation = tokio::task::spawn_blocking(move || {
            manifest.validate_documents_for_preset(&public_key, &rlk, preset)?;
            e3_zk_prover::validate_lbfv_key_share_document_commitments(preset, &public_key, &rlk)
        })
        .await
        .map_err(|error| anyhow::anyhow!("l-BFV bundle validation task failed: {error}"))?;

        let mut updated = state.clone();
        match validation {
            Ok(commitments) => {
                updated.mark_party_validated(commitments)?;
            }
            Err(error) => {
                tracing::warn!(party_id, %error, "Permanently excluding an invalid l-BFV bundle");
                updated.mark_party_invalid(party_id)?;
            }
        }
        self.persist_publickey_lbfv_transition(state, &updated)
            .await?;
        Ok(updated)
    }

    async fn persist_publickey_lbfv_fetch_failure(
        &self,
        state: &LbfvContributionCollectionStateV1,
        failed: &LbfvKeyShareDocumentFetchFailed,
    ) -> Result<(LbfvContributionCollectionStateV1, bool)> {
        let mut updated = state.clone();
        let changed = updated.record_fetch_failure(failed)?;
        if changed {
            self.persist_publickey_lbfv_transition(state, &updated)
                .await?;
        }
        Ok((updated, changed))
    }

    async fn persist_publickey_lbfv_transition(
        &self,
        expected: &LbfvContributionCollectionStateV1,
        updated: &LbfvContributionCollectionStateV1,
    ) -> Result<()> {
        updated.validate_loaded()?;
        ensure!(
            expected.e3_id == updated.e3_id,
            "l-BFV collection transition changed the E3 ID"
        );
        let collection = self.publickey_lbfv_collection(&expected.e3_id);
        let current = collection
            .read()
            .await?
            .ok_or_else(|| anyhow::anyhow!("l-BFV collection state is not durable"))?;
        ensure!(
            current == *expected,
            "persisted l-BFV collection state changed before its transition"
        );
        collection.write_sync(updated).await
    }
}

#[cfg(test)]
mod lbfv_tests {
    use super::*;
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};
    use actix::Actor;
    use e3_data::{DataOp, DataStore, GetLog, InMemStore};

    #[actix::test]
    async fn unsolicited_document_is_rejected_without_an_artifact() -> Result<()> {
        let repositories = Repositories::in_mem();
        let fixture = fixture();
        let state = fixture.state.clone();
        let (public_key, _, _) = bundle(&fixture, 0);

        assert!(repositories
            .persist_publickey_lbfv_document(&state, &public_key)
            .await
            .is_err());
        assert!(
            !repositories
                .publickey_lbfv_document(&state.e3_id, &public_key.content_hash)
                .has()
                .await
        );
        Ok(())
    }

    #[actix::test]
    async fn documents_can_arrive_in_role_order_after_the_manifest_is_durable() -> Result<()> {
        let store = InMemStore::new(true).start();
        let repositories = Repositories::new(DataStore::from_in_mem(&store));
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (public_key, relinearization_key, manifest) = bundle(&fixture, 0);

        state = repositories
            .persist_publickey_lbfv_manifest(&state, &manifest)
            .await?;
        state = repositories
            .persist_publickey_lbfv_document(&state, &relinearization_key)
            .await?;
        assert_eq!(
            state.parties[&0].status,
            crate::LbfvPartyContributionStatusV1::FetchingDocuments
        );
        state = repositories
            .persist_publickey_lbfv_document(&state, &public_key)
            .await?;
        assert_eq!(
            state.parties[&0].status,
            crate::LbfvPartyContributionStatusV1::DocumentsDurable
        );
        assert_eq!(
            repositories
                .publickey_lbfv_document(&state.e3_id, &public_key.content_hash)
                .read()
                .await?,
            Some(public_key.document.clone())
        );
        assert_eq!(
            repositories
                .publickey_lbfv_document(&state.e3_id, &relinearization_key.content_hash)
                .read()
                .await?,
            Some(relinearization_key.document.clone())
        );
        let restored = repositories
            .publickey_lbfv_collection(&state.e3_id)
            .read()
            .await?
            .expect("collection sidecar");
        assert_eq!(restored, state);

        let writes = store.send(GetLog).await?;
        let keys = writes
            .iter()
            .filter_map(|operation| match operation {
                DataOp::Insert(insert) => Some(String::from_utf8_lossy(insert.key()).into_owned()),
                DataOp::Remove(_) => None,
            })
            .collect::<Vec<_>>();
        let collection_key = StoreKeys::publickey_lbfv_collection(&state.e3_id);
        for hash in [relinearization_key.content_hash, public_key.content_hash] {
            let artifact_key = StoreKeys::publickey_lbfv_document(&state.e3_id, &hash);
            let artifact_index = keys.iter().position(|key| key == &artifact_key).unwrap();
            let collection_index = keys
                .iter()
                .enumerate()
                .find(|(index, key)| *index > artifact_index && *key == &collection_key)
                .map(|(index, _)| index)
                .unwrap();
            assert!(artifact_index < collection_index);
        }
        Ok(())
    }

    #[actix::test]
    async fn in_memory_manifest_does_not_authorize_document_persistence() -> Result<()> {
        let repositories = Repositories::in_mem();
        let fixture = fixture();
        let mut state = fixture.state.clone();
        let (public_key, _, manifest) = bundle(&fixture, 0);
        state.admit_manifest(&manifest)?;

        assert!(repositories
            .persist_publickey_lbfv_document(&state, &public_key)
            .await
            .is_err());
        assert!(
            !repositories
                .publickey_lbfv_document(&state.e3_id, &public_key.content_hash)
                .has()
                .await
        );
        Ok(())
    }

    #[actix::test]
    async fn claimed_hash_must_match_document_bytes() -> Result<()> {
        let repositories = Repositories::in_mem();
        let fixture = fixture();
        let state = fixture.state.clone();
        let (mut public_key, _, manifest) = bundle(&fixture, 0);
        let state = repositories
            .persist_publickey_lbfv_manifest(&state, &manifest)
            .await?;
        public_key.content_hash = B256::repeat_byte(0xff);

        assert!(repositories
            .persist_publickey_lbfv_document(&state, &public_key)
            .await
            .is_err());
        assert!(
            !repositories
                .publickey_lbfv_document(&state.e3_id, &public_key.content_hash)
                .has()
                .await
        );
        Ok(())
    }
}
