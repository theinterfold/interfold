// SPDX-License-Identifier: LGPL-3.0-only

//! Explicit disabled-definition API, not worker dispatch or publication. Signature admission and
//! the canonical roster remain the caller's responsibility. No SS folds or proof-skip fallback.

use super::request_binding;
use crate::{
    circuits::vk::{self, VkArtifacts},
    inputs_json_to_input_map, CompiledCircuit, WitnessGenerator, ZkProver,
};
use anyhow::{Context, Result};
use e3_events::{E3id, Proof, SynchronizedProofContext};
use e3_zk_config::{
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
    CircuitName, CircuitVariant,
};
use e3_zk_witness::synchronized::provenance::{self, Child, VerificationKey, VerificationKeys};
use serde_json::Value;

pub struct DealerJoin<'a> {
    pub c1: &'a Proof,
    pub c2: &'a Proof,
    /// Recipient-major, threshold CRT-major, omitting the owner's self slot.
    pub c3: &'a [Proof],
}

pub struct RecipientJoin<'a> {
    pub dealer_ids: &'a [u32],
    pub c0: &'a Proof,
    pub own_c2: &'a Proof,
    pub c4: &'a Proof,
    /// Exactly H dealer joins, in the accepted roster's order.
    pub nodes: &'a [Proof],
}

/// Expected values from authenticated C4/native planning and the selected C1/C5 key authority,
/// never copied from the candidate setup proof. This API does not establish that authority.
#[derive(Clone, Copy)]
pub struct ExpectedSetup<'a> {
    pub dealers: &'a [u32],
    pub threshold_keys: &'a [Field],
    pub dealer_batch: Field,
    pub sk_commitment: Field,
    pub key_bundle: Field,
}

/// Commitments only, not native keys or a C6 witness. Constructed only after contextual and
/// cryptographic verification of the recipient setup statement.
pub struct SetupCommitments {
    binding: [u128; 2],
    recipient: u32,
    dealers: Vec<u32>,
    threshold_keys: Vec<Field>,
    dealer_batch: Field,
    sk_commitment: Field,
    key_bundle: Field,
}

impl SetupCommitments {
    pub fn binding(&self) -> [u128; 2] {
        self.binding
    }

    pub fn recipient(&self) -> u32 {
        self.recipient
    }

    pub fn dealers(&self) -> &[u32] {
        &self.dealers
    }

    pub fn threshold_keys(&self) -> &[Field] {
        &self.threshold_keys
    }

    pub fn sk_commitment(&self) -> Field {
        self.sk_commitment
    }

    pub fn dealer_batch(&self) -> Field {
        self.dealer_batch
    }

    pub fn key_bundle(&self) -> Field {
        self.key_bundle
    }
}

pub(super) struct Keys {
    c0: VkArtifacts,
    c1: VkArtifacts,
    c2: VkArtifacts,
    c3: VkArtifacts,
    c4: VkArtifacts,
    node: VkArtifacts,
}

impl Keys {
    pub(super) fn load(prover: &ZkProver, config: &Configs) -> Result<Self> {
        let directory = config
            .profile
            .artifacts_dir_for_committee(config.committee)?;
        let recursive = prover.circuits_dir(CircuitVariant::Recursive, &directory);
        let default = prover.circuits_dir(CircuitVariant::Default, &directory);
        Ok(Self {
            c0: vk::load_vk_artifacts(&recursive, CircuitName::PkBfv)?,
            c1: vk::load_vk_artifacts(&recursive, CircuitName::PkGeneration)?,
            c2: vk::load_vk_artifacts(&recursive, CircuitName::SkShareComputation)?,
            c3: vk::load_vk_artifacts(&recursive, CircuitName::ShareEncryption)?,
            c4: vk::load_vk_artifacts(&recursive, CircuitName::DkgShareDecryption)?,
            node: vk::load_vk_artifacts(&default, CircuitName::NodeFold)?,
        })
    }

    pub(super) fn as_inputs(&self) -> VerificationKeys<'_> {
        fn key(vk: &VkArtifacts) -> VerificationKey<'_> {
            VerificationKey {
                fields: vk.verification_key_bytes.as_slice(),
                hash: vk.key_hash_bytes,
            }
        }
        VerificationKeys {
            c0: key(&self.c0),
            c1: key(&self.c1),
            c2: key(&self.c2),
            c3: key(&self.c3),
            c4: key(&self.c4),
            node: key(&self.node),
        }
    }
}

pub(super) fn child(proof: &Proof) -> Child<'_> {
    Child {
        circuit: proof.circuit,
        proof: proof.data.as_ref(),
        public_signals: proof.public_signals.as_ref(),
    }
}

pub fn prepare_dealer(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
    input: &DealerJoin<'_>,
) -> Result<Value> {
    let binding = request_binding(config, context, e3_id)?;
    let keys = Keys::load(prover, config)?;
    Ok(provenance::dealer(
        config,
        binding,
        context.party_id,
        child(input.c1),
        child(input.c2),
        &input.c3.iter().map(child).collect::<Vec<_>>(),
        &keys.as_inputs(),
    )?)
}

pub fn prepare_recipient(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
    input: &RecipientJoin<'_>,
) -> Result<Value> {
    let binding = request_binding(config, context, e3_id)?;
    let keys = Keys::load(prover, config)?;
    Ok(provenance::recipient(
        config,
        binding,
        context.party_id,
        input.dealer_ids,
        child(input.c0),
        child(input.own_c2),
        child(input.c4),
        &input.nodes.iter().map(child).collect::<Vec<_>>(),
        &keys.as_inputs(),
    )?)
}

pub(super) fn prove(
    prover: &ZkProver,
    config: &Configs,
    circuit: CircuitName,
    input: Value,
    job: &str,
    variant: CircuitVariant,
) -> Result<Proof> {
    let directory = config
        .profile
        .artifacts_dir_for_committee(config.committee)?;
    let path = prover
        .circuits_dir(variant, &directory)
        .join(circuit.dir_path())
        .join(format!("{}.json", circuit.as_str()));
    let compiled = CompiledCircuit::from_file(&path)?;
    let witness =
        WitnessGenerator::new().generate_witness(&compiled, inputs_json_to_input_map(&input)?)?;
    Ok(prover.generate_proof_with_variant(circuit, &witness, job, variant, &directory)?)
}

pub fn prove_dealer(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
    input: &DealerJoin<'_>,
    job: &str,
) -> Result<Proof> {
    prove(
        prover,
        config,
        CircuitName::NodeFold,
        prepare_dealer(prover, config, context, e3_id, input)?,
        job,
        CircuitVariant::Default,
    )
}

pub fn prove_recipient(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
    input: &RecipientJoin<'_>,
    job: &str,
) -> Result<Proof> {
    prove(
        prover,
        config,
        CircuitName::NodesFold,
        prepare_recipient(prover, config, context, e3_id, input)?,
        job,
        CircuitVariant::Default,
    )
}

/// None means a rejected statement/proof; errors retain local context/artifact/process failures.
/// This API does not authorize an accusation or authenticate a caller-supplied roster.
pub fn verify_recipient(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3_id: &E3id,
    expected: &ExpectedSetup<'_>,
    proof: &Proof,
    job: &str,
) -> Result<Option<SetupCommitments>> {
    let binding = request_binding(config, context, e3_id)?;
    let keys = Keys::load(prover, config)?;
    let tree = keys.as_inputs().setup_tree()?;
    if proof.circuit != CircuitName::NodesFold {
        return Ok(None);
    }
    let Ok(public) = PublicSignals::decode(config, proof.circuit, &proof.public_signals) else {
        return Ok(None);
    };
    if public.binding() != Some(binding)
        || public.party_id() != Some(context.party_id)
        || public.dealers().as_deref() != Some(expected.dealers)
        || public.tree_hash() != Some(tree)
        || public.threshold_keys() != Some(expected.threshold_keys)
        || public.dealer_batch() != Some(expected.dealer_batch)
        || public.sk_commitment() != Some(expected.sk_commitment)
        || public.key_bundle() != Some(expected.key_bundle)
    {
        return Ok(None);
    }
    let directory = config
        .profile
        .artifacts_dir_for_committee(config.committee)?;
    if !prover.verify_fold_proof(proof, job, context.party_id as u64, &directory)? {
        return Ok(None);
    }
    Ok(Some(SetupCommitments {
        binding,
        recipient: context.party_id,
        dealers: expected.dealers.to_vec(),
        threshold_keys: public
            .threshold_keys()
            .context("missing setup threshold keys")?
            .to_vec(),
        dealer_batch: expected.dealer_batch,
        sk_commitment: public
            .sk_commitment()
            .context("missing setup SK commitment")?,
        key_bundle: public.key_bundle().context("missing setup key bundle")?,
    }))
}
