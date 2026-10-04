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
    NodeProofAggregator, ProofRequestActor, ProofVerificationActor, ShareVerificationActor, ZkActor,
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
        }
    }

    pub async fn hydrate(
        &mut self,
        repositories: &Repositories,
        lifecycle_stages: &HashMap<E3id, E3Stage>,
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        aggregates: &[AggregateId],
    ) -> Result<()> {
        let active_e3_ids: HashSet<E3id> = self
            .finalized_committees
            .keys()
            .filter(|e3_id| {
                !lifecycle_stages
                    .get(*e3_id)
                    .is_some_and(crate::domain::proof_verification::dkg_has_ended)
            })
            .cloned()
            .collect();
        self.node_proofs = NodeProofRecovery::load(repositories, &active_e3_ids).await?;
        self.pending_c0 =
            crate::actors::proof_verification::recovery::recover_pending_verifications(
                eventstore,
                aggregates,
                &active_e3_ids,
                &self.finalized_committees,
                &self.e3_metadata,
            )
            .await?;
        Ok(())
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
    recovery: ZkActorRecovery,
    proof_aggregation_enabled: bool,
    repositories: Repositories,
) -> ZkActors {
    let ZkActorRecovery {
        finalized_committees,
        e3_metadata,
        dkg_fold_attestation_contexts,
        node_proofs,
        pending_c0,
    } = recovery;
    let zk_actor = ZkActor::new(backend).start();
    let verifier = zk_actor.clone().recipient();

    let proof_request = ProofRequestActor::setup_with_recovery(
        bus,
        signer.clone(),
        proof_aggregation_enabled,
        node_proofs.proofs.clone(),
    );
    let proof_verification = ProofVerificationActor::setup_with_recovery(
        bus,
        verifier,
        finalized_committees.clone(),
        e3_metadata,
        pending_c0,
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
