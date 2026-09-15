// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! l-BFV generation verification completion and sealed-set recovery.

use super::super::*;
use crate::{
    LbfvAggregationStateV1, LbfvContributionRepositoryFactory, LbfvContributionVerificationStateV1,
    PublicKeyRepositoryFactory,
};
use e3_data::AutoPersist;
use std::collections::{BTreeSet, HashMap};

struct LbfvC5Plan {
    state: PublicKeyAggregatorState,
    pending: PkAggregationProofPending,
}

type VerifyingC1Inputs = (
    Vec<(u64, String, ArcBytes)>,
    usize,
    usize,
    usize,
    Vec<Option<SignedProofPayload>>,
    HashMap<u64, String>,
);

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn handle_lbfv_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        ctx: &mut Context<Self>,
    ) {
        if !self.can_run_aggregation_effects()
            || msg.e3_id != self.e3_id
            || msg.kind != VerificationKind::LbfvGenerationProofs
        {
            return;
        }
        let (msg, ec) = msg.into_components();
        let Ok(collection) = self.lbfv_collection_state() else {
            return;
        };
        let LbfvContributionVerificationStateV1::Dispatched { party_ids } =
            &collection.verification
        else {
            return;
        };
        let candidate_party_ids = party_ids.clone();
        let candidate_ids = candidate_party_ids
            .iter()
            .copied()
            .map(u64::from)
            .collect::<BTreeSet<_>>();
        let expected_verification_id = match collection.dispatched_verification_id() {
            Ok(verification_id) => verification_id,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        if msg.verification_id != Some(expected_verification_id) {
            warn!(
                expected = %expected_verification_id,
                received = ?msg.verification_id,
                "Ignoring an l-BFV verification result for a stale candidate set"
            );
            return;
        }
        let Some((
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
            canonical_party_nodes,
        )) = self.verifying_c1_inputs()
        else {
            return;
        };
        let mut dishonest_parties = msg
            .dishonest_parties
            .into_iter()
            .filter(|party_id| candidate_ids.contains(party_id))
            .collect::<BTreeSet<_>>();
        for party_id in collection
            .ineligible_party_ids(&candidate_party_ids)
            .unwrap_or_default()
        {
            dishonest_parties.insert(u64::from(party_id));
        }
        if !dishonest_parties.is_empty() {
            self.persist_lbfv_candidate_rejection(collection, dishonest_parties, ec, ctx);
            return;
        }
        let mut honest_entries = submission_order
            .into_iter()
            .zip(c1_proofs)
            .filter(|((party_id, _, _), _)| {
                candidate_ids.contains(party_id) && !dishonest_parties.contains(party_id)
            })
            .map(|((party_id, node, keyshare), c1)| (party_id, node, keyshare, c1))
            .collect::<Vec<_>>();
        let audit = check_c1_keyshare_commitments(&honest_entries, &self.fhe);
        for party_id in audit.missing_proof {
            dishonest_parties.insert(party_id);
        }
        for (party_id, signed_proof) in audit.mismatched {
            dishonest_parties.insert(party_id);
            if let Ok(faulting_node) = signed_proof.recover_address() {
                if let Err(error) = self.bus.publish(
                    SignedProofFailed {
                        e3_id: self.e3_id.clone(),
                        faulting_node,
                        proof_type: ProofType::C1PkGeneration,
                        signed_payload: signed_proof,
                    },
                    ec.clone(),
                ) {
                    self.bus.err(EType::PublickeyAggregation, error);
                }
            }
        }
        honest_entries.retain(|(party_id, _, _, _)| !dishonest_parties.contains(party_id));
        if !dishonest_parties.is_empty() {
            self.persist_lbfv_candidate_rejection(collection, dishonest_parties, ec, ctx);
            return;
        }
        let selected = PublicKeyAggregation::select_honest_set(
            &self.e3_id,
            honest_entries,
            &dishonest_parties,
            circuit_committee_h,
            threshold_m,
            candidate_ids.len(),
        );
        let HonestSelection::Proceed {
            honest_entries,
            honest_party_ids,
        } = selected
        else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("verified l-BFV candidate set contains fewer than H parties"),
            );
            return;
        };
        let accepted_parties = honest_party_ids
            .iter()
            .map(|party_id| {
                let party_id = u32::try_from(*party_id)
                    .map_err(|_| anyhow::anyhow!("l-BFV accepted party ID does not fit u32"))?;
                Ok(collection.validated_commitments(party_id)?.clone())
            })
            .collect::<Result<Vec<_>>>();
        let accepted_parties = match accepted_parties {
            Ok(accepted) => accepted,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        let plan = match self.build_lbfv_c5_plan(
            honest_entries,
            honest_party_ids,
            dishonest_parties,
            circuit_committee_n,
            circuit_committee_h,
            threshold_m,
            canonical_party_nodes,
            ec.clone(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        let mut sealed = collection.clone();
        if let Err(error) = sealed.seal(accepted_parties) {
            self.bus.err(EType::PublickeyAggregation, error);
            return;
        }
        let repositories = self.repositories.clone();
        let aggregation_collection = sealed.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_transition(&collection, &sealed)
                    .await?;
                let aggregation =
                    ensure_lbfv_aggregation_sidecar(&repositories, &aggregation_collection).await?;
                repositories
                    .publickey(&sealed.e3_id)
                    .write_sync(&plan.state)
                    .await?;
                anyhow::Ok((sealed, aggregation, plan))
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok((sealed, aggregation, plan)) => {
                    actor.replace_lbfv_collection(sealed);
                    actor.replace_lbfv_aggregation(aggregation);
                    if let Err(error) = actor.publish_committed_lbfv_c5_plan(plan, ec) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    pub(in crate::actors::publickey_aggregator) fn apply_sealed_lbfv_collection(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        let Ok(collection) = self.lbfv_collection_state() else {
            return;
        };
        let LbfvContributionVerificationStateV1::Sealed {
            ref candidate_party_ids,
            ref accepted_parties,
        } = collection.verification
        else {
            return;
        };
        let Some((
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
            canonical_party_nodes,
        )) = self.verifying_c1_inputs()
        else {
            return;
        };
        let accepted_ids = accepted_parties
            .iter()
            .map(|party| u64::from(party.party_id))
            .collect::<BTreeSet<_>>();
        let dishonest_parties = collection
            .ineligible_party_ids(candidate_party_ids)
            .unwrap_or_default()
            .into_iter()
            .map(u64::from)
            .collect::<BTreeSet<_>>();
        let honest_entries = submission_order
            .into_iter()
            .zip(c1_proofs)
            .filter(|((party_id, _, _), _)| accepted_ids.contains(party_id))
            .map(|((party_id, node, keyshare), c1)| (party_id, node, keyshare, c1))
            .collect::<Vec<_>>();
        if honest_entries.len() != accepted_ids.len()
            || accepted_ids.len() != circuit_committee_h
            || accepted_ids.len() <= threshold_m
        {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("sealed l-BFV accepted set cannot be applied to public-key state"),
            );
            return;
        }
        let plan = match self.build_lbfv_c5_plan(
            honest_entries,
            accepted_ids,
            dishonest_parties,
            circuit_committee_n,
            circuit_committee_h,
            threshold_m,
            canonical_party_nodes,
            ec.clone(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        let repository = self.repositories.publickey(&self.e3_id);
        let repositories = self.repositories.clone();
        let aggregation_collection = collection.clone();
        ctx.wait(
            async move {
                let aggregation =
                    ensure_lbfv_aggregation_sidecar(&repositories, &aggregation_collection).await?;
                repository.write_sync(&plan.state).await?;
                anyhow::Ok((aggregation, plan))
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok((aggregation, plan)) => {
                    actor.replace_lbfv_aggregation(aggregation);
                    if let Err(error) = actor.publish_committed_lbfv_c5_plan(plan, ec) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    fn verifying_c1_inputs(&self) -> Option<VerifyingC1Inputs> {
        let PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
            canonical_party_nodes,
            ..
        } = self.state.get()?
        else {
            return None;
        };
        Some((
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            c1_proofs,
            canonical_party_nodes,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_lbfv_c5_plan(
        &self,
        mut honest_entries: Vec<(u64, String, ArcBytes, Option<SignedProofPayload>)>,
        honest_party_ids: BTreeSet<u64>,
        dishonest_parties: BTreeSet<u64>,
        circuit_committee_n: usize,
        circuit_committee_h: usize,
        threshold_m: usize,
        canonical_party_nodes: HashMap<u64, String>,
        ec: EventContext<Sequenced>,
    ) -> Result<LbfvC5Plan> {
        honest_entries.sort_by_key(|(party_id, _, _, _)| *party_id);
        anyhow::ensure!(
            honest_entries.len() == circuit_committee_h
                && honest_party_ids.len() == circuit_committee_h,
            "l-BFV C5 plan does not contain exactly H parties"
        );
        anyhow::ensure!(
            canonical_party_nodes.len() == circuit_committee_n,
            "finalized committee does not contain circuit N parties"
        );
        let keyshare_bytes = honest_entries
            .iter()
            .map(|(_, _, keyshare, _)| keyshare.clone())
            .collect::<Vec<_>>();
        let nodes = OrderedSet::from(
            honest_entries
                .iter()
                .map(|(_, node, _, _)| node.clone())
                .collect::<Vec<_>>(),
        );
        let public_key =
            ArcBytes::from_bytes(&self.fhe.get_aggregate_public_key(GetAggregatePublicKey {
                keyshares: OrderedSet::from(keyshare_bytes.clone()),
            })?);
        let pending = PkAggregationProofPending {
            e3_id: self.e3_id.clone(),
            proof_request: PkAggregationProofRequest {
                keyshare_bytes: keyshare_bytes.clone(),
                aggregated_pk_bytes: public_key.clone(),
                params_preset: self.params_preset,
                committee_n: circuit_committee_n,
                committee_h: circuit_committee_h,
                committee_threshold: threshold_m,
            },
            public_key: public_key.clone(),
            nodes: nodes.clone(),
        };
        Ok(LbfvC5Plan {
            state: PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                party_nodes: canonical_party_nodes,
                dkg_node_proofs: HashMap::new(),
                dkg_fold_attestations: HashMap::new(),
                honest_party_ids,
                dishonest_parties,
                circuit_committee_n,
                circuit_committee_h,
                dkg_aggregation_correlation: None,
                dkg_aggregated_proof: None,
                c5_proof_pending: None,
                last_ec: Some(ec),
                nodes_fold_accumulator: None,
                nodes_fold_completed_slots: 0,
                nodes_fold_step_correlation: None,
            },
            pending,
        })
    }

    fn publish_committed_lbfv_c5_plan(
        &mut self,
        plan: LbfvC5Plan,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(&ec, |_| Ok(plan.state))?;
        self.bus.publish(plan.pending, ec.clone())?;
        let early = std::mem::take(&mut self.early_dkg_proofs);
        for event in early {
            self.handle_dkg_recursive_aggregation_complete(event)?;
        }
        self.try_dispatch_lbfv_aggregation_rows(&ec)?;
        self.try_dispatch_dkg_aggregation(&ec)
    }

    fn persist_lbfv_candidate_rejection(
        &mut self,
        collection: crate::LbfvContributionCollectionStateV1,
        dishonest_parties: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        let mut collecting = collection.clone();
        for party_id in dishonest_parties {
            let Ok(party_id) = u32::try_from(party_id) else {
                continue;
            };
            if let Err(error) = collecting.mark_party_invalid(party_id) {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        }
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_transition(&collection, &collecting)
                    .await?;
                anyhow::Ok(collecting)
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(collecting) => {
                    actor.replace_lbfv_collection(collecting);
                    actor.try_progress_lbfv_verification(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }
}

async fn ensure_lbfv_aggregation_sidecar(
    repositories: &e3_data::Repositories,
    collection: &crate::LbfvContributionCollectionStateV1,
) -> Result<e3_data::Persistable<LbfvAggregationStateV1>> {
    collection.validate_loaded()?;
    let accepted_party_ids = match &collection.verification {
        LbfvContributionVerificationStateV1::Sealed {
            accepted_parties, ..
        } => accepted_parties
            .iter()
            .map(|party| party.party_id)
            .collect::<Vec<_>>(),
        _ => anyhow::bail!("l-BFV aggregation sidecar requires a sealed collection"),
    };
    let repository = repositories.publickey_lbfv_aggregation(&collection.e3_id);
    let mut sidecar = repository.load().await?;
    let mut state = match sidecar.get() {
        Some(state) => {
            state.validate_loaded()?;
            anyhow::ensure!(
                state.e3_id == collection.e3_id
                    && state.proof_domain == collection.proof_domain
                    && state.accepted_party_ids == accepted_party_ids,
                "persisted l-BFV aggregation sidecar does not match the sealed collection"
            );
            state
        }
        None => LbfvAggregationStateV1::new(
            collection.e3_id.clone(),
            collection.proof_domain,
            accepted_party_ids,
        )?,
    };

    for party_id in state.accepted_party_ids.clone() {
        let Some(party) = collection.parties.get(&party_id) else {
            anyhow::bail!("sealed l-BFV collection has no party slot {party_id}");
        };
        let Some(manifest) = &party.manifest else {
            anyhow::bail!("sealed l-BFV party {party_id} has no manifest");
        };
        let (public_key_hash, rlk_hash) =
            crate::domain::lbfv_contribution_collection::manifest_hashes(&manifest.payload);
        for hash in [public_key_hash, rlk_hash] {
            let Some(document) = repositories
                .publickey_lbfv_document(&collection.e3_id, &hash)
                .read()
                .await?
            else {
                continue;
            };
            state.record_document(document)?;
        }
    }
    state.validate_loaded()?;
    repository.write_sync(&state).await?;
    sidecar = repository.load().await?;
    anyhow::ensure!(
        sidecar.get().is_some(),
        "l-BFV aggregation sidecar disappeared after persistence"
    );
    Ok(sidecar)
}
