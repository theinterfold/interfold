// SPDX-License-Identifier: LGPL-3.0-only

//! Explicit disabled publication qualification. Callers own canonical context/roster and admitted
//! contribution authority. This module never dispatches workers, signs an intent or enables a route.

use super::{
    provenance::{child, prove, Keys},
    request_binding,
};
use crate::{circuits::vk, ZkProver};
use anyhow::{ensure, Result};
use e3_events::{E3id, Proof, SynchronizedProofContext};
use e3_zk_config::{
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
    CircuitName, CircuitVariant,
};
use e3_zk_witness::{
    synchronized::{provenance::VerificationKey, publication as encoding},
    threshold::{
        pk_aggregation::{Inputs, PkAggregationCircuitData},
        user_data_encryption::compute_public_key_commitment,
    },
};
use fhe::bfv::PublicKey;
use serde_json::Value;

pub struct PublicationJoin<'a> {
    pub dealers: &'a [u32],
    /// H recipient setup proofs, in selected-dealer order, not N proofs.
    pub recipients: &'a [Proof],
    pub c5: &'a Proof,
}

/// Independent admitted authority, never values decoded from the candidate publication proof.
pub struct ExpectedPublication<'a> {
    pub dealers: &'a [u32],
    pub threshold_keys: &'a [Field],
    pub dealer_batch: Field,
    pub sk_commitments: &'a [Field],
    pub key_bundles: &'a [Field],
    pub public_key: &'a PublicKey,
}

/// Read-only handoff after contextual and cryptographic verification. Not a canonical chain event.
pub struct PublicationCommitments {
    binding: [u128; 2],
    dealers: Vec<u32>,
    threshold_keys: Vec<Field>,
    dealer_batch: Field,
    sk_commitments: Vec<Field>,
    key_bundles: Vec<Field>,
    pk_commitment: Field,
}

impl PublicationCommitments {
    pub fn binding(&self) -> [u128; 2] {
        self.binding
    }
    pub fn dealers(&self) -> &[u32] {
        &self.dealers
    }
    pub fn threshold_keys(&self) -> &[Field] {
        &self.threshold_keys
    }
    pub fn dealer_batch(&self) -> Field {
        self.dealer_batch
    }
    pub fn sk_commitments(&self) -> &[Field] {
        &self.sk_commitments
    }
    pub fn key_bundles(&self) -> &[Field] {
        &self.key_bundles
    }
    pub fn pk_commitment(&self) -> Field {
        self.pk_commitment
    }
}

pub fn prepare_c5(config: &Configs, data: &PkAggregationCircuitData) -> Result<Inputs> {
    Ok(encoding::c5(config, data)?)
}

pub fn prove_c5(
    prover: &ZkProver,
    config: &Configs,
    data: &PkAggregationCircuitData,
    job: &str,
) -> Result<Proof> {
    prove(
        prover,
        config,
        CircuitName::PkAggregation,
        prepare_c5(config, data)?.to_json(),
        job,
        CircuitVariant::Default,
    )
}

struct PublicationKeys {
    setup: crate::circuits::vk::VkArtifacts,
    descendants: Field,
    c5: crate::circuits::vk::VkArtifacts,
}

impl PublicationKeys {
    fn load(prover: &ZkProver, config: &Configs) -> Result<Self> {
        let directory = config
            .profile
            .artifacts_dir_for_committee(config.committee)?;
        let default = prover.circuits_dir(CircuitVariant::Default, &directory);
        Ok(Self {
            setup: vk::load_vk_artifacts(&default, CircuitName::NodesFold)?,
            descendants: Keys::load(prover, config)?.as_inputs().setup_tree()?,
            c5: vk::load_vk_artifacts(&default, CircuitName::PkAggregation)?,
        })
    }

    fn inputs(&self) -> encoding::VerificationKeys<'_> {
        fn key(vk: &crate::circuits::vk::VkArtifacts) -> VerificationKey<'_> {
            VerificationKey {
                fields: vk.verification_key_bytes.as_slice(),
                hash: vk.key_hash_bytes,
            }
        }
        encoding::VerificationKeys {
            setup: key(&self.setup),
            descendants: self.descendants,
            c5: key(&self.c5),
        }
    }
}

pub fn prepare_publication(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3: &E3id,
    input: &PublicationJoin<'_>,
) -> Result<Value> {
    let binding = request_binding(config, context, e3)?;
    let keys = PublicationKeys::load(prover, config)?;
    Ok(encoding::publication(
        config,
        binding,
        input.dealers,
        &input.recipients.iter().map(child).collect::<Vec<_>>(),
        child(input.c5),
        &keys.inputs(),
    )?)
}

pub fn prove_publication(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3: &E3id,
    input: &PublicationJoin<'_>,
    job: &str,
) -> Result<Proof> {
    prove(
        prover,
        config,
        CircuitName::DkgAggregator,
        prepare_publication(prover, config, context, e3, input)?,
        job,
        CircuitVariant::Evm,
    )
}

/// A completed invalid proof returns None. Missing artifacts/process failures remain local errors.
pub fn verify_publication(
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3: &E3id,
    expected: &ExpectedPublication<'_>,
    proof: &Proof,
    job: &str,
) -> Result<Option<PublicationCommitments>> {
    let binding = request_binding(config, context, e3)?;
    ensure!(
        expected.public_key.params == config.threshold && expected.public_key.c.len() == 2,
        "publication key has another profile or component count"
    );
    let pk = compute_public_key_commitment(&config.threshold, expected.public_key)?;
    let keys = PublicationKeys::load(prover, config)?;
    let tree = keys.inputs().tree()?;
    if proof.circuit != CircuitName::DkgAggregator {
        return Ok(None);
    }
    let Ok(public) = PublicSignals::decode(config, proof.circuit, &proof.public_signals) else {
        return Ok(None);
    };
    if public.binding() != Some(binding)
        || public.dealers().as_deref() != Some(expected.dealers)
        || public.tree_hash() != Some(tree)
        || public.c5_key_hash() != Some(keys.c5.key_hash_bytes)
        || public.threshold_keys() != Some(expected.threshold_keys)
        || public.dealer_batch() != Some(expected.dealer_batch)
        || public.recipient_sk_commitments() != Some(expected.sk_commitments)
        || public.recipient_key_bundles() != Some(expected.key_bundles)
        || public.pk_commitment() != Some(pk)
    {
        return Ok(None);
    }
    let directory = config
        .profile
        .artifacts_dir_for_committee(config.committee)?;
    if !prover.verify_proof_with_variant(proof, job, 0, CircuitVariant::Evm, &directory)? {
        return Ok(None);
    }
    Ok(Some(PublicationCommitments {
        binding,
        dealers: expected.dealers.to_vec(),
        threshold_keys: expected.threshold_keys.to_vec(),
        dealer_batch: expected.dealer_batch,
        sk_commitments: expected.sk_commitments.to_vec(),
        key_bundles: expected.key_bundles.to_vec(),
        pk_commitment: pk,
    }))
}
