// SPDX-License-Identifier: LGPL-3.0-only

//! Recipient join planning from the native owner's fixed C4 intent and authenticated dealer rows.
//! These checks establish statement consistency, not signatures, runtime admission or proof validity.

use anyhow::{ensure, Context, Result};
use e3_events::{
    DKGInnerProofReady, Proof, SynchronizedDkgProofJob, SynchronizedDkgProofPublished,
    SynchronizedDkgProofRequest, SynchronizedDkgProofRole, SynchronizedRecipientInputsReady,
    SynchronizedSetupAnchors,
};
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientPlan {
    pub(crate) inputs: SynchronizedRecipientInputsReady,
}

pub(crate) fn leaf_sequence(config: &Configs, circuit: CircuitName) -> Result<usize> {
    Ok(match circuit {
        CircuitName::PkBfv => 0,
        CircuitName::SkShareComputation => 2,
        CircuitName::DkgShareDecryption => {
            let c3_count = (config.committee.values().n - 1) * config.threshold.moduli().len();
            crate::utils::total_expected_for_profile(config.profile, c3_count, 0) - 1
        }
        _ => anyhow::bail!("not a recipient leaf"),
    })
}

impl RecipientPlan {
    pub fn new(inputs: SynchronizedRecipientInputsReady) -> Result<Self> {
        let plan = Self { inputs };
        let config = plan.config()?;
        let input = &plan.inputs;
        super::request_binding(&config, &input.context, &input.e3_id)?;
        ensure!(
            input.dealers.len() == config.committee.values().h
                && input.dealers.windows(2).all(|ids| ids[0] < ids[1])
                && input
                    .dealers
                    .iter()
                    .all(|&id| (id as usize) < config.committee.values().n)
                && input.c2_statements.keys().copied().collect::<BTreeSet<_>>()
                    == input
                        .dealers
                        .iter()
                        .copied()
                        .chain([input.context.party_id])
                        .collect(),
            "recipient intent requires the exact H roster and own C2 provenance"
        );
        for (&owner, bytes) in &input.c2_statements {
            let public = PublicSignals::decode(&config, CircuitName::SkShareComputation, bytes)?;
            plan.identity(&public, owner)?;
        }
        Ok(plan)
    }

    fn config(&self) -> Result<Configs> {
        Ok(Configs::for_profile(
            self.inputs.params_profile,
            self.inputs.committee_size,
        )?)
    }

    fn identity(&self, public: &PublicSignals, owner: u32) -> Result<()> {
        ensure!(
            public.binding()
                == Some(super::request_binding(
                    &self.config()?,
                    &self.inputs.context,
                    &self.inputs.e3_id
                )?)
                && public.party_id() == Some(owner),
            "recipient input has another setup or owner"
        );
        Ok(())
    }

    pub fn validate_leaf(&self, input: &DKGInnerProofReady) -> Result<()> {
        let native = &self.inputs;
        ensure!(
            input.e3_id == native.e3_id && input.party_id == u64::from(native.context.party_id),
            "recipient leaf belongs to another E3 or local owner"
        );
        let config = self.config()?;
        let circuit = input.proof.circuit;
        let expected_seq = leaf_sequence(&config, circuit)?;
        ensure!(
            input.seq == expected_seq,
            "recipient leaf occupies another planned slot"
        );
        let public = PublicSignals::decode(&config, circuit, &input.proof.public_signals)?;
        if circuit == CircuitName::PkBfv {
            ensure!(
                public.pk_commitment() == Some(native.transport_key),
                "C0 differs from native transport key"
            );
            return Ok(());
        }
        self.identity(&public, native.context.party_id)?;
        let own = &native.c2_statements[&native.context.party_id];
        if circuit == CircuitName::SkShareComputation {
            ensure!(
                &input.proof.public_signals == own,
                "own C2 differs from native provenance"
            );
        } else {
            ensure!(
                public.dealers().as_ref() == Some(&native.dealers)
                    && public.sk_commitment() == Some(native.sk_commitment)
                    && public.key_bundle() == Some(native.key_bundle),
                "C4 differs from fixed native roster or anchors"
            );
            let own = PublicSignals::decode(&config, CircuitName::SkShareComputation, own)?;
            ensure!(
                public.outgoing_root() == own.outgoing_root(),
                "C4 outgoing root differs"
            );
            let l = config.threshold.moduli().len();
            let recipient = native.context.party_id as usize;
            for (row, dealer) in native.dealers.iter().enumerate() {
                let c2 = PublicSignals::decode(
                    &config,
                    CircuitName::SkShareComputation,
                    &native.c2_statements[dealer],
                )?;
                ensure!(
                    public.message_commitments().unwrap()[row * l..(row + 1) * l]
                        == c2.message_commitments().unwrap()[recipient * l..(recipient + 1) * l],
                    "C4 differs from verified dealer C2 messages"
                );
            }
        }
        Ok(())
    }

    pub fn validate_dealer(&self, message: &SynchronizedDkgProofPublished) -> Result<()> {
        let native = &self.inputs;
        ensure!(
            message.e3_id == native.e3_id
                && message.context.setup == native.context.setup
                && message.role == SynchronizedDkgProofRole::Dealer
                && message.proof.circuit == CircuitName::NodeFold,
            "dealer join belongs to another setup or role"
        );
        let config = self.config()?;
        let public = PublicSignals::decode(
            &config,
            message.proof.circuit,
            &message.proof.public_signals,
        )?;
        self.identity(&public, message.context.party_id)?;
        let bytes = native
            .c2_statements
            .get(&message.context.party_id)
            .context("dealer outside native provenance")?;
        let c2 = PublicSignals::decode(&config, CircuitName::SkShareComputation, bytes)?;
        ensure!(
            public.outgoing_root() == c2.outgoing_root()
                && public.message_commitments() == c2.message_commitments(),
            "dealer join differs from verified C2 provenance"
        );
        if message.context.party_id != native.context.party_id {
            ensure!(
                public.recipient_keys().unwrap()[native.context.party_id as usize]
                    == native.transport_key,
                "dealer transport differs from native recipient key"
            );
        }
        Ok(())
    }

    pub fn request(
        &self,
        leaves: &BTreeMap<usize, DKGInnerProofReady>,
        dealers: &BTreeMap<u32, SynchronizedDkgProofPublished>,
    ) -> Result<Option<SynchronizedDkgProofRequest>> {
        for (&seq, leaf) in leaves {
            ensure!(seq == leaf.seq, "recipient map slot differs from leaf");
            self.validate_leaf(leaf)?;
        }
        if leaves.len() != 3
            || self
                .inputs
                .dealers
                .iter()
                .any(|id| !dealers.contains_key(id))
        {
            return Ok(None);
        }
        let nodes = self
            .inputs
            .dealers
            .iter()
            .map(|id| {
                let node = &dealers[id];
                self.validate_dealer(node)?;
                Ok(node.proof.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let config = self.config()?;
        let binding = super::request_binding(&config, &self.inputs.context, &self.inputs.e3_id)?;
        let threshold_keys = nodes
            .iter()
            .map(|node| {
                PublicSignals::decode(&config, node.circuit, &node.public_signals)?
                    .pk_commitment()
                    .context("missing dealer threshold key")
            })
            .collect::<Result<Vec<_>>>()?;
        let batch = e3_zk_witness::synchronized::provenance::dealer_batch(
            &config,
            binding,
            &self.inputs.dealers,
            &nodes
                .iter()
                .map(super::provenance::child)
                .collect::<Vec<_>>(),
        )?;
        let expected = SynchronizedSetupAnchors {
            binding,
            recipient: self.inputs.context.party_id,
            dealers: self.inputs.dealers.clone(),
            threshold_keys,
            dealer_batch: batch,
            sk_commitment: self.inputs.sk_commitment,
            key_bundle: self.inputs.key_bundle,
        };
        let c4 = leaves
            .values()
            .find(|leaf| leaf.proof.circuit == CircuitName::DkgShareDecryption)
            .context("missing C4")?;
        Ok(Some(SynchronizedDkgProofRequest {
            params_profile: self.inputs.params_profile,
            committee_size: self.inputs.committee_size,
            context: self.inputs.context.clone(),
            job: SynchronizedDkgProofJob::Recipient {
                c0: leaves[&0].proof.clone(),
                own_c2: leaves[&2].proof.clone(),
                c4: c4.proof.clone(),
                dealers: nodes,
                expected,
            },
        }))
    }

    pub fn validate_result(
        &self,
        request: &SynchronizedDkgProofRequest,
        proof: &Proof,
        setup: &SynchronizedSetupAnchors,
    ) -> Result<()> {
        let SynchronizedDkgProofJob::Recipient { expected, .. } = &request.job else {
            anyhow::bail!("not a recipient request");
        };
        ensure!(
            request.context == self.inputs.context
                && request.params_profile == self.inputs.params_profile
                && request.committee_size == self.inputs.committee_size
                && setup == expected
                && setup.recipient == self.inputs.context.party_id
                && setup.dealers == self.inputs.dealers
                && setup.sk_commitment == self.inputs.sk_commitment
                && setup.key_bundle == self.inputs.key_bundle
                && proof.circuit == CircuitName::NodesFold,
            "recipient response differs from independent expectations"
        );
        let public = PublicSignals::decode(&self.config()?, proof.circuit, &proof.public_signals)?;
        self.identity(&public, setup.recipient)?;
        ensure!(
            public.dealers().as_ref() == Some(&setup.dealers)
                && public.threshold_keys() == Some(setup.threshold_keys.as_slice())
                && public.dealer_batch() == Some(setup.dealer_batch)
                && public.sk_commitment() == Some(setup.sk_commitment)
                && public.key_bundle() == Some(setup.key_bundle),
            "recipient proof differs from admitted setup"
        );
        Ok(())
    }
}
