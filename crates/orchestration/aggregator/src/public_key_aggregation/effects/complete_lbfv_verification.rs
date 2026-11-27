// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! l-BFV generation verification completion and sealed-set recovery.

use super::super::*;
use super::aggregate_lbfv::load_lbfv_accepted_shares;
use crate::{
    LbfvAggregationStateV1, LbfvContributionRepositoryFactory, LbfvContributionVerificationStateV1,
    PublicKeyRepositoryFactory,
};
use e3_data::AutoPersist;
use e3_events::EventSource;
use std::collections::{BTreeSet, HashMap};

/// The selected roster's inputs: submissions, `threshold_m`, circuit N, circuit H, and the
/// finalized committee.
type SelectedRosterInputs = (
    Vec<(u64, String, ArcBytes)>,
    usize,
    usize,
    usize,
    HashMap<u64, String>,
);

impl PublicKeyAggregator {
    /// Receive this node's l-BFV generation verdict. The verifier answers each dispatch once and
    /// the bus drops a repeated request, so a verdict that cannot be applied yet is held, not
    /// discarded: effects may be fenced, the roster may not have restored `VerifyingC1`, or the
    /// sealed set may fail to persist.
    pub(in crate::actors::publickey_aggregator) fn receive_lbfv_verification(
        &mut self,
        msg: TypedEvent<LbfvShareVerificationComplete>,
        ctx: &mut Context<Self>,
    ) {
        // Only this node's verifier answers its l-BFV requests, and a key on chain ends the DKG.
        if !self.is_lbfv()
            || self.key_published
            || msg.e3_id != self.e3_id
            || msg.kind != VerificationKind::LbfvGenerationProofs
            || msg.verification_id.is_none()
            || msg.get_ctx().source() != EventSource::Local
        {
            return;
        }
        let (verdict, ec) = msg.into_components();
        if self
            .held_lbfv_verification
            .as_ref()
            .is_none_or(|held| held.verification_id != verdict.verification_id)
        {
            self.held_lbfv_verification = Some(verdict);
        }
        self.apply_held_lbfv_verification(ec, ctx);
    }

    /// Apply the held verdict when it answers the dispatched candidate set. Returns whether such
    /// a verdict exists, so that a recovering node does not dispatch the set again. The verdict
    /// stays held until the sealed set is durable, so a failed attempt is retried by the next
    /// event that reaches this node.
    pub(in crate::actors::publickey_aggregator) fn apply_held_lbfv_verification(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        if !self.can_continue_aggregation_effects() {
            return false;
        }
        if self.key_published {
            self.held_lbfv_verification = None;
            return false;
        }
        let Some(verdict) = self.held_lbfv_verification.clone() else {
            return false;
        };
        let Ok(collection) = self.lbfv_collection_state() else {
            return false;
        };
        let expected_verification_id = match &collection.verification {
            LbfvContributionVerificationStateV1::Dispatched { .. } => {
                match collection.dispatched_verification_id() {
                    Ok(verification_id) => verification_id,
                    Err(error) => {
                        self.bus.err(EType::PublickeyAggregation, error);
                        return false;
                    }
                }
            }
            // The set is sealed or failed: the verdict has nothing left to answer.
            LbfvContributionVerificationStateV1::Sealed { .. }
            | LbfvContributionVerificationStateV1::Failed { .. } => {
                self.held_lbfv_verification = None;
                return false;
            }
            LbfvContributionVerificationStateV1::Collecting
            | LbfvContributionVerificationStateV1::Ready { .. } => return false,
        };
        if verdict.verification_id != Some(expected_verification_id) {
            warn!(
                expected = %expected_verification_id,
                received = ?verdict.verification_id,
                "Dropping an l-BFV verification result for a stale candidate set"
            );
            self.held_lbfv_verification = None;
            return false;
        }
        // Without the selected roster the verdict waits: `CommitmentRosterSelected` restores
        // `VerifyingC1` and resumes the progress of the collection.
        if matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ) {
            self.apply_lbfv_verdict(verdict, collection, ec, ctx);
        }
        true
    }

    fn apply_lbfv_verdict(
        &mut self,
        verdict: LbfvShareVerificationComplete,
        collection: crate::LbfvContributionCollectionStateV1,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        let LbfvContributionVerificationStateV1::Dispatched { party_ids } =
            &collection.verification
        else {
            return;
        };
        let candidate_ids = party_ids
            .iter()
            .copied()
            .map(u64::from)
            .collect::<BTreeSet<_>>();
        let Some((
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            canonical_party_nodes,
        )) = self.selected_roster_inputs()
        else {
            return;
        };
        let dishonest_parties = verdict
            .dishonest_parties
            .into_iter()
            .filter(|party_id| candidate_ids.contains(party_id))
            .collect::<BTreeSet<_>>();
        if !dishonest_parties.is_empty() {
            self.persist_lbfv_candidate_rejection(collection, dishonest_parties, ec, ctx);
            return;
        }
        let honest_entries = submission_order
            .into_iter()
            .filter(|(party_id, _, _)| candidate_ids.contains(party_id))
            .collect::<Vec<_>>();
        if honest_entries.len() != circuit_committee_h
            || candidate_ids.len() != circuit_committee_h
            || candidate_ids.len() <= threshold_m
        {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("verified l-BFV candidate set cannot be applied to the roster"),
            );
            return;
        }
        let accepted_parties = candidate_ids
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
        let plan = match lbfv_generation_plan(
            honest_entries,
            candidate_ids,
            circuit_committee_n,
            circuit_committee_h,
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
                let shares =
                    load_lbfv_accepted_shares(&repositories, &aggregation_collection).await?;
                repositories
                    .publickey(&sealed.e3_id)
                    .write_sync(&plan)
                    .await?;
                anyhow::Ok((sealed, aggregation, shares, plan))
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok((sealed, aggregation, shares, plan)) => {
                    actor.replace_lbfv_collection(sealed);
                    actor.replace_lbfv_aggregation(aggregation);
                    actor.lbfv_shares = Some(Arc::new(shares));
                    // The sealed set is durable: the verdict is answered.
                    actor.held_lbfv_verification = None;
                    if let Err(error) = actor.apply_committed_lbfv_generation_plan(plan, ec) {
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
            ref accepted_parties,
            ..
        } = collection.verification
        else {
            return;
        };
        let Some((
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
            canonical_party_nodes,
        )) = self.selected_roster_inputs()
        else {
            return;
        };
        let accepted_ids = accepted_parties
            .iter()
            .map(|party| u64::from(party.party_id))
            .collect::<BTreeSet<_>>();
        let honest_entries = submission_order
            .into_iter()
            .filter(|(party_id, _, _)| accepted_ids.contains(party_id))
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
        let plan = match lbfv_generation_plan(
            honest_entries,
            accepted_ids,
            circuit_committee_n,
            circuit_committee_h,
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
                let shares =
                    load_lbfv_accepted_shares(&repositories, &aggregation_collection).await?;
                repository.write_sync(&plan).await?;
                anyhow::Ok((aggregation, shares, plan))
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok((aggregation, shares, plan)) => {
                    actor.replace_lbfv_aggregation(aggregation);
                    actor.lbfv_shares = Some(Arc::new(shares));
                    actor.held_lbfv_verification = None;
                    if let Err(error) = actor.apply_committed_lbfv_generation_plan(plan, ec) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    /// The l-BFV path proves no C1, so it reads only the roster from the `VerifyingC1` state.
    fn selected_roster_inputs(&self) -> Option<SelectedRosterInputs> {
        let PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            threshold_m,
            circuit_committee_n,
            circuit_committee_h,
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
            canonical_party_nodes,
        ))
    }

    fn apply_committed_lbfv_generation_plan(
        &mut self,
        plan: PublicKeyAggregatorState,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(&ec, |_| Ok(plan))?;
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
                    // The rejection is durable: the verdict is answered.
                    actor.held_lbfv_verification = None;
                    actor.try_progress_lbfv_verification(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }
}

/// Build the aggregation state for the accepted l-BFV set. The l-BFV path proves no C5: the row
/// aggregation proofs and `DkgAggregationV2` carry the key, so `c5_proof_pending` stays empty.
/// The key shares of the accepted parties are not aggregated here: the unsigned `KeyshareCreated`
/// bytes carry no authentication, and the published key is the envelope built from the sealed
/// documents, so `public_key` stays empty.
fn lbfv_generation_plan(
    mut honest_entries: Vec<(u64, String, ArcBytes)>,
    honest_party_ids: BTreeSet<u64>,
    circuit_committee_n: usize,
    circuit_committee_h: usize,
    canonical_party_nodes: HashMap<u64, String>,
    ec: EventContext<Sequenced>,
) -> Result<PublicKeyAggregatorState> {
    honest_entries.sort_by_key(|(party_id, _, _)| *party_id);
    anyhow::ensure!(
        honest_entries.len() == circuit_committee_h
            && honest_party_ids.len() == circuit_committee_h,
        "l-BFV aggregation plan does not contain exactly H parties"
    );
    anyhow::ensure!(
        canonical_party_nodes.len() == circuit_committee_n,
        "finalized committee does not contain circuit N parties"
    );
    let keyshare_bytes = honest_entries
        .iter()
        .map(|(_, _, keyshare)| keyshare.clone())
        .collect::<Vec<_>>();
    let nodes = OrderedSet::from(
        honest_entries
            .iter()
            .map(|(_, node, _)| node.clone())
            .collect::<Vec<_>>(),
    );
    Ok(PublicKeyAggregatorState::GeneratingC5Proof {
        public_key: ArcBytes::from_bytes(&[]),
        keyshare_bytes,
        nodes,
        party_nodes: canonical_party_nodes,
        dkg_node_proofs: HashMap::new(),
        dkg_fold_attestations: HashMap::new(),
        honest_party_ids,
        dishonest_parties: BTreeSet::new(),
        circuit_committee_n,
        circuit_committee_h,
        dkg_aggregation_correlation: None,
        dkg_aggregated_proof: None,
        c5_proof_pending: None,
        last_ec: Some(ec),
        nodes_fold_accumulator: None,
        nodes_fold_completed_slots: 0,
        nodes_fold_step_correlation: None,
    })
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
    let sidecar = repository.load().await?;
    if let Some(state) = sidecar.get() {
        state.validate_loaded()?;
        anyhow::ensure!(
            state.e3_id == collection.e3_id
                && state.proof_domain == collection.proof_domain
                && state.accepted_party_ids == accepted_party_ids,
            "persisted l-BFV aggregation sidecar does not match the sealed collection"
        );
        return Ok(sidecar);
    }
    let state = LbfvAggregationStateV1::new(
        collection.e3_id.clone(),
        collection.proof_domain,
        accepted_party_ids,
        collection.params_preset,
    )?;
    repository.write_sync(&state).await?;
    let sidecar = repository.load().await?;
    anyhow::ensure!(
        sidecar.get().is_some(),
        "l-BFV aggregation sidecar disappeared after persistence"
    );
    Ok(sidecar)
}
