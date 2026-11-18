// SPDX-License-Identifier: LGPL-3.0-only

//! Local dealer collection. Admission/effects and storage belong to the actor; this definition
//! validates the plan and its statements without enabling the synchronized profile.

use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    DKGInnerProofReady, E3id, Proof, SynchronizedDkgProofJob, SynchronizedDkgProofRequest,
    SynchronizedProofContext, ThresholdSharePending,
};
use e3_fhe_params::BfvProfile;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName, DkgInputType,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealerPlan {
    pub(crate) profile: BfvProfile,
    pub(crate) committee: CiphernodesCommitteeSize,
    pub(crate) context: SynchronizedProofContext,
    pub(crate) circuits: Vec<CircuitName>,
}

impl DealerPlan {
    pub fn from_pending(input: &ThresholdSharePending) -> Result<Self> {
        let profile = input.proof_request.params_profile;
        let committee = input.proof_request.committee_size;
        let config = Configs::for_profile(profile, committee)?;
        let context = input
            .proof_request
            .synchronized
            .clone()
            .context("missing dealer context")?;
        crate::synchronized::request_binding(&config, &context, &input.e3_id)?;
        ensure!(
            u64::from(context.party_id) == input.full_share.party_id
                && input.proof_request.e_sm.is_none()
                && input.full_share.esi_sss.is_empty()
                && input.e_sm_share_computation_request.is_none()
                && input.e_sm_share_encryption_requests.is_empty(),
            "synchronized dealer cannot contain SS work"
        );
        let c2 = &input.sk_share_computation_request;
        ensure!(
            c2.params_profile == profile
                && c2.committee_size == committee
                && c2.dkg_input_type == DkgInputType::SecretKey
                && c2.synchronized.as_ref().map(|s| &s.context) == Some(&context),
            "dealer C2 belongs to another plan"
        );
        let slots: Vec<_> = (0..committee.values().n)
            .filter(|&party| party != context.party_id as usize)
            .flat_map(|party| (0..config.threshold.moduli().len()).map(move |row| (party, row)))
            .collect();
        ensure!(
            input.sk_share_encryption_requests.len() == slots.len(),
            "incomplete dealer C3 plan"
        );
        for (request, (party, row)) in input.sk_share_encryption_requests.iter().zip(slots) {
            ensure!(
                request.params_profile == profile
                    && request.committee_size == committee
                    && request.dkg_input_type == DkgInputType::SecretKey
                    && request.esi_index == 0
                    && (request.recipient_party_id, request.row_index) == (party, row),
                "dealer C3 plan is not canonical recipient/CRT order"
            );
        }
        // Use the leaf producer's sequence owner rather than inventing another C1-C3 layout.
        let dispatch = crate::workflow::proof_request::plan_threshold_dispatch(
            input.proof_request.clone(),
            c2.clone(),
            None,
            input.sk_share_encryption_requests.clone(),
            vec![],
        )?;
        let mut circuits = Vec::new();
        for (index, item) in dispatch.into_iter().enumerate() {
            ensure!(
                item.seq == index + 1,
                "noncontiguous synchronized dealer plan"
            );
            circuits.push(match item.request {
                e3_events::ZkRequest::PkGeneration(_) => CircuitName::PkGeneration,
                e3_events::ZkRequest::ShareComputation(_) => CircuitName::SkShareComputation,
                e3_events::ZkRequest::ShareEncryption(_) => CircuitName::ShareEncryption,
                _ => anyhow::bail!("unexpected dealer leaf"),
            });
        }
        Ok(Self {
            profile,
            committee,
            context,
            circuits,
        })
    }

    pub fn validate_leaf(&self, id: &E3id, input: &DKGInnerProofReady) -> Result<()> {
        let config = self.config()?;
        self.decode_leaf(id, &config, input).map(drop)
    }

    pub(crate) fn config(&self) -> Result<Configs> {
        Ok(Configs::for_profile(self.profile, self.committee)?)
    }

    pub(crate) fn decode_leaf(
        &self,
        id: &E3id,
        config: &Configs,
        input: &DKGInnerProofReady,
    ) -> Result<PublicSignals> {
        let public =
            PublicSignals::decode(config, input.proof.circuit, &input.proof.public_signals)?;
        self.validate_leaf_statement(id, config, input, &public)?;
        Ok(public)
    }

    pub(crate) fn validate_leaf_statement(
        &self,
        id: &E3id,
        config: &Configs,
        input: &DKGInnerProofReady,
        public: &PublicSignals,
    ) -> Result<()> {
        ensure!(
            &input.e3_id == id && input.party_id == u64::from(self.context.party_id),
            "dealer leaf belongs to another E3 or party"
        );
        ensure!(
            input.seq > 0 && self.circuits.get(input.seq - 1) == Some(&input.proof.circuit),
            "dealer leaf is outside its planned slot"
        );
        if input.proof.circuit != CircuitName::ShareEncryption {
            ensure!(
                public.binding()
                    == Some(crate::synchronized::request_binding(
                        config,
                        &self.context,
                        id
                    )?)
                    && public.party_id() == Some(self.context.party_id),
                "dealer leaf identity differs"
            );
        }
        Ok(())
    }

    pub fn request(
        &self,
        id: &E3id,
        proofs: &BTreeMap<usize, DKGInnerProofReady>,
    ) -> Result<Option<SynchronizedDkgProofRequest>> {
        self.validate_leaves(id, proofs)?;
        if proofs.len() != self.circuits.len() {
            return Ok(None);
        }
        let get = |seq| proofs.get(&seq).map(|input| input.proof.clone());
        Ok(Some(SynchronizedDkgProofRequest {
            params_profile: self.profile,
            committee_size: self.committee,
            context: self.context.clone(),
            job: SynchronizedDkgProofJob::Dealer {
                c1: get(1).context("missing C1")?,
                c2: get(2).context("missing C2")?,
                c3: (3..=self.circuits.len())
                    .map(get)
                    .collect::<Option<_>>()
                    .context("missing C3")?,
            },
        }))
    }

    pub(crate) fn validate_leaves(
        &self,
        id: &E3id,
        proofs: &BTreeMap<usize, DKGInnerProofReady>,
    ) -> Result<()> {
        let config = self.config()?;
        let sharing = proofs
            .get(&2)
            .map(|leaf| self.decode_leaf(id, &config, leaf))
            .transpose()?;
        for (&seq, leaf) in proofs {
            ensure!(seq == leaf.seq, "dealer slot differs from input");
            if seq != 2 {
                let public = self.decode_leaf(id, &config, leaf)?;
                if let Some(sharing) = sharing.as_ref().filter(|_| seq >= 3) {
                    self.validate_c3_message(&config, seq, &public, sharing)?;
                }
            }
        }
        Ok(())
    }

    /// C3 has no setup identity. A validated C2 anchors the planned recipient/CRT message.
    pub(crate) fn validate_c3_message(
        &self,
        config: &Configs,
        seq: usize,
        public: &PublicSignals,
        sharing: &PublicSignals,
    ) -> Result<()> {
        let l = config.threshold.moduli().len();
        let slot = seq.checked_sub(3).context("invalid C3 slot")?;
        let recipient = slot / l;
        let recipient = recipient + usize::from(recipient >= self.context.party_id as usize);
        let message = sharing
            .message_commitments()
            .and_then(|fields| fields.get(recipient * l + slot % l))
            .context("missing C2 message for the planned C3 slot")?;
        ensure!(
            Some(message)
                == public
                    .message_commitments()
                    .and_then(|fields| fields.first()),
            "dealer C2/C3 message differs"
        );
        Ok(())
    }

    pub fn validate_result(
        &self,
        id: &E3id,
        proofs: &BTreeMap<usize, DKGInnerProofReady>,
        proof: &Proof,
    ) -> Result<()> {
        ensure!(
            proof.circuit == CircuitName::NodeFold,
            "unexpected dealer result circuit"
        );
        let config = Configs::for_profile(self.profile, self.committee)?;
        let public = PublicSignals::decode(&config, proof.circuit, &proof.public_signals)?;
        let c1 = proofs.get(&1).context("missing dealer C1")?;
        let c2 = proofs.get(&2).context("missing dealer C2")?;
        let c1 = PublicSignals::decode(&config, c1.proof.circuit, &c1.proof.public_signals)?;
        let c2 = PublicSignals::decode(&config, c2.proof.circuit, &c2.proof.public_signals)?;
        ensure!(
            public.binding()
                == Some(crate::synchronized::request_binding(
                    &config,
                    &self.context,
                    id
                )?)
                && public.party_id() == Some(self.context.party_id)
                && public.pk_commitment() == c1.pk_commitment()
                && public.outgoing_root() == c2.outgoing_root()
                && public.message_commitments() == c2.message_commitments(),
            "dealer response differs from its admitted local plan"
        );
        let n = self.committee.values().n;
        let l = config.threshold.moduli().len();
        let keys = public
            .recipient_keys()
            .context("missing dealer recipient keys")?;
        let ciphertexts = public
            .ciphertext_commitments()
            .context("missing dealer ciphertexts")?;
        let mut seq = 3;
        for (party, key) in keys.iter().enumerate().take(n) {
            for row in 0..l {
                if party == self.context.party_id as usize {
                    ensure!(
                        *key == [0; 32] && ciphertexts[party * l + row] == [0; 32],
                        "dealer self transport slot must be empty"
                    );
                } else {
                    let child = proofs.get(&seq).context("missing dealer C3")?;
                    let child = PublicSignals::decode(
                        &config,
                        child.proof.circuit,
                        &child.proof.public_signals,
                    )?;
                    ensure!(
                        Some(*key) == child.pk_commitment()
                            && Some(ciphertexts[party * l + row]) == child.ciphertext_commitment(),
                        "dealer result transport differs from its planned C3"
                    );
                    seq += 1;
                }
            }
        }
        Ok(())
    }
}
