// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Startup composition for the global ZK actor system.

use actix::{Actor, Addr, Recipient};
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use e3_data::Repositories;
use e3_events::{
    AggregateId, BusHandle, Committee, DkgFoldAttestationContext, E3Stage, E3id,
    EncryptionKeyReceived, EventStoreQueryBy, SeqAgg, TypedEvent,
};
use e3_request::E3Meta;
use std::collections::{HashMap, HashSet};

use crate::actors::node_proof_aggregator::recovery::NodeProofRecovery;
use crate::actors::{
    NodeProofAggregator, ProofRequestActor, ProofVerificationActor, ShareVerificationActor,
    ZkActor, ZkVerificationRequest,
};
use crate::ZkBackend;

/// Durable inputs needed by global proof-verification actors before EventStore replay begins.
///
/// These maps are projections of canonical protocol events. They are startup seeds, not separate
/// authorities: live or replayed lifecycle events continue to update the actor caches.
#[derive(Clone, Debug, Default)]
pub struct ZkActorRecovery {
    finalized_committees: HashMap<E3id, Committee>,
    e3_metadata: HashMap<E3id, E3Meta>,
    dkg_fold_attestation_contexts: HashMap<E3id, DkgFoldAttestationContext>,
    node_proofs: NodeProofRecovery,
    pending_c0: Vec<TypedEvent<EncryptionKeyReceived>>,
    /// E3s whose DKG ended before startup, also when they failed. The replay can bring back their
    /// C0 inputs, and the verifier does not admit them.
    dkg_ended: HashSet<E3id>,
    canonical_keys: e3_request::canonical_key::CanonicalPublicKeys,
}

impl ZkActorRecovery {
    pub fn new(
        finalized_committees: HashMap<E3id, Committee>,
        e3_metadata: HashMap<E3id, E3Meta>,
        dkg_fold_attestation_contexts: HashMap<E3id, DkgFoldAttestationContext>,
    ) -> Self {
        Self {
            finalized_committees,
            e3_metadata,
            dkg_fold_attestation_contexts,
            node_proofs: NodeProofRecovery::default(),
            pending_c0: Vec::new(),
            dkg_ended: HashSet::new(),
            canonical_keys: Default::default(),
        }
    }

    pub fn with_canonical_keys(
        mut self,
        keys: e3_request::canonical_key::CanonicalPublicKeys,
    ) -> Self {
        self.canonical_keys = keys;
        self
    }

    pub async fn hydrate(
        &mut self,
        repositories: &Repositories,
        lifecycle_stages: &HashMap<E3id, E3Stage>,
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        aggregates: &[AggregateId],
    ) -> Result<()> {
        self.dkg_ended = lifecycle_stages
            .iter()
            .filter(|(_, stage)| crate::domain::proof_verification::dkg_has_ended(stage))
            .map(|(e3_id, _)| e3_id.clone())
            .collect();
        let active_e3_ids: HashSet<E3id> = self
            .finalized_committees
            .keys()
            .filter(|e3_id| !self.dkg_ended.contains(*e3_id))
            .cloned()
            .collect();
        self.node_proofs = NodeProofRecovery::load(repositories, &active_e3_ids).await?;
        self.pending_c0 = Box::pin(
            crate::actors::proof_verification::recovery::recover_pending_verifications(
                eventstore,
                aggregates,
                &active_e3_ids,
                &self.finalized_committees,
                &self.e3_metadata,
            ),
        )
        .await?;
        Ok(())
    }

    /// Start the C0 verifier with the recovered committees, presets and inputs. It does not admit
    /// the inputs of an E3 whose DKG ended before startup.
    pub(crate) fn setup_proof_verification(
        &mut self,
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
    ) -> Addr<ProofVerificationActor> {
        ProofVerificationActor::setup_with_recovery(
            bus,
            verifier,
            self.finalized_committees.clone(),
            std::mem::take(&mut self.e3_metadata),
            std::mem::take(&mut self.pending_c0),
            std::mem::take(&mut self.dkg_ended),
        )
    }
}

/// Setup all ZK-related actors.
///
/// Requires a `ZkBackend` for proof generation/verification and a `PrivateKeySigner` for signing
/// proofs. `dkg_fold_attestation_contexts_by_chain` is a fallback for synthetic runs that have no
/// on-chain context event. Live and replayed context events carry each E3's registry and verifier.
pub fn setup_zk_actors(
    bus: &BusHandle,
    backend: &ZkBackend,
    signer: PrivateKeySigner,
    dkg_fold_attestation_contexts_by_chain: HashMap<u64, Option<DkgFoldAttestationContext>>,
    mut recovery: ZkActorRecovery,
    proof_aggregation_enabled: bool,
    repositories: Repositories,
) -> ZkActors {
    let zk_actor = ZkActor::new(backend).start();
    let proof_verification = recovery.setup_proof_verification(bus, zk_actor.clone().recipient());
    let ZkActorRecovery {
        finalized_committees,
        dkg_fold_attestation_contexts,
        node_proofs,
        canonical_keys,
        ..
    } = recovery;

    let proof_request = ProofRequestActor::setup_with_recovery(
        bus,
        signer.clone(),
        proof_aggregation_enabled,
        node_proofs.proofs.clone(),
        canonical_keys,
    );
    let share_verification = ShareVerificationActor::setup(bus, finalized_committees);
    let node_proof_aggregator = NodeProofAggregator::setup(
        bus,
        signer,
        dkg_fold_attestation_contexts,
        dkg_fold_attestation_contexts_by_chain,
        proof_aggregation_enabled,
        repositories,
        node_proofs,
    );

    ZkActors {
        zk_actor,
        proof_request,
        proof_verification,
        share_verification,
        node_proof_aggregator,
    }
}

/// Container for all ZK actor addresses.
pub struct ZkActors {
    pub zk_actor: Addr<ZkActor>,
    pub proof_request: Addr<ProofRequestActor>,
    pub proof_verification: Addr<ProofVerificationActor>,
    pub share_verification: Addr<ShareVerificationActor>,
    pub node_proof_aggregator: Addr<NodeProofAggregator>,
}
