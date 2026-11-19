// SPDX-License-Identifier: LGPL-3.0-only

//! Local dealer collection. Admission/effects and storage belong to the actor; this definition
//! validates the plan and its statements without enabling the synchronized profile.

use alloy::primitives::Address;
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    DKGInnerProofReady, E3id, Proof, SynchronizedDkgProofJob, SynchronizedDkgProofRequest,
    SynchronizedProofContext, ThresholdSharePending,
};
use e3_fhe_params::BfvProfile;
use e3_zk_config::{
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
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
    // The retained native plan owns these public keys. Rebuild them when opening a snapshot.
    #[serde(skip)]
    pub(crate) recipient_keys: Vec<Option<Field>>,
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
        let pk_config = e3_zk_config::dkg::pk::Configs::new(&config.transport)?;
        let mut keys = vec![None; committee.values().n];
        for (request, (party, row)) in input.sk_share_encryption_requests.iter().zip(slots) {
            ensure!(
                request.params_profile == profile
                    && request.committee_size == committee
                    && request.dkg_input_type == DkgInputType::SecretKey
                    && request.esi_index == 0
                    && (request.recipient_party_id, request.row_index) == (party, row),
                "dealer C3 plan is not canonical recipient/CRT order"
            );
            let key_bytes: &[u8] = &request.recipient_pk_raw;
            if let Some((bytes, _)) = keys[party] {
                ensure!(
                    bytes == key_bytes,
                    "dealer native C3 recipient key differs across CRT rows"
                );
            } else {
                let commitment = e3_zk_witness::compute_dkg_pk_commitment_from_public_key_bytes(
                    key_bytes, &pk_config,
                )
                .context("invalid native dealer C3 recipient key")?;
                keys[party] = Some((key_bytes, commitment));
            }
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
            recipient_keys: keys
                .into_iter()
                .map(|key| key.map(|(_, field)| field))
                .collect(),
        })
    }

    pub(crate) fn validate_controller(&self, controller: Option<Address>) -> Result<()> {
        ensure!(
            controller == Some(self.context.setup.interfold_address)
                && !self.context.setup.interfold_address.is_zero(),
            "dealer plan differs from the configured Interfold controller"
        );
        Ok(())
    }

    pub(crate) fn restore_recipient_keys(&mut self, native: Self) -> bool {
        if self.profile != native.profile
            || self.committee != native.committee
            || self.context != native.context
            || self.circuits != native.circuits
        {
            return false;
        }
        self.recipient_keys = native.recipient_keys;
        true
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
        if input.proof.circuit == CircuitName::ShareEncryption {
            let (recipient, _) = self.c3_slot(config, input.seq)?;
            let key = self
                .recipient_keys
                .get(recipient)
                .and_then(|key| *key)
                .context("missing native dealer C3 recipient key")?;
            ensure!(
                public.pk_commitment() == Some(key),
                "dealer C3 recipient key differs from the native plan"
            );
        } else {
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
                if let Some(sharing) = &sharing {
                    if seq == 1 {
                        ensure!(
                            public.sk_commitment() == sharing.sk_commitment(),
                            "dealer C1/C2 secret differs"
                        );
                    } else {
                        self.validate_c3_message(&config, seq, &public, sharing)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Prefer the primary C2 if it can be completed. Each non-self row is independent once
    /// the C2 statement is fixed, so selecting a complete batch never searches row combinations.
    pub(crate) fn select_complete_leaves(
        &self,
        id: &E3id,
        config: &Configs,
        primary: &BTreeMap<usize, DKGInnerProofReady>,
        alternate: &BTreeMap<usize, DKGInnerProofReady>,
    ) -> Option<BTreeMap<usize, DKGInnerProofReady>> {
        let candidates = |seq| primary.get(&seq).into_iter().chain(alternate.get(&seq));
        let decode = |seq, leaf: &DKGInnerProofReady| {
            (leaf.seq == seq)
                .then(|| self.decode_leaf(id, config, leaf).ok())
                .flatten()
        };
        'sharing: for c2 in candidates(2) {
            let Some(sharing) = decode(2, c2) else {
                continue;
            };
            let Some(c1) = candidates(1).find(|leaf| {
                decode(1, leaf)
                    .is_some_and(|public| public.sk_commitment() == sharing.sk_commitment())
            }) else {
                continue;
            };
            let mut selected = BTreeMap::from([(1, c1.clone()), (2, c2.clone())]);
            for seq in 3..=self.circuits.len() {
                let Some(c3) = candidates(seq).find(|leaf| {
                    decode(seq, leaf).is_some_and(|public| {
                        self.validate_c3_message(config, seq, &public, &sharing)
                            .is_ok()
                    })
                }) else {
                    continue 'sharing;
                };
                selected.insert(seq, c3.clone());
            }
            return Some(selected);
        }
        None
    }

    pub(crate) fn c3_slot(&self, config: &Configs, seq: usize) -> Result<(usize, usize)> {
        let l = config.threshold.moduli().len();
        let slot = seq.checked_sub(3).context("invalid C3 slot")?;
        let recipient = slot / l;
        Ok((
            recipient + usize::from(recipient >= self.context.party_id as usize),
            slot % l,
        ))
    }

    /// C3 has no setup identity. The coherent C2 anchors the planned recipient/CRT message.
    pub(crate) fn validate_c3_message(
        &self,
        config: &Configs,
        seq: usize,
        public: &PublicSignals,
        sharing: &PublicSignals,
    ) -> Result<()> {
        let l = config.threshold.moduli().len();
        let (recipient, row) = self.c3_slot(config, seq)?;
        let message = sharing
            .message_commitments()
            .and_then(|fields| fields.get(recipient * l + row))
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
