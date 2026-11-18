// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic inputs for the disabled C5/publication definition, not chain/signature admission.

use super::{
    binding_json, dealers, invalid,
    provenance::{fields, hash, insert_child, statement, Child, VerificationKey},
    SetupBinding,
};
use crate::{
    threshold::pk_aggregation::{Inputs, PkAggregationCircuitData},
    WitnessError,
};
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_zk_config::{
    synchronized::{public_signals::Field, Configs},
    CircuitName,
};
use serde_json::{json, Value};

pub fn c5(config: &Configs, data: &PkAggregationCircuitData) -> Result<Inputs, WitnessError> {
    let input = Inputs::compute(&config.pk_aggregation, data)?;
    if &data.public_key.c[1] != create_deterministic_crp_from_default_seed(&config.threshold).poly()
    {
        return Err(invalid("synchronized C5 public key uses another CRS"));
    }
    Ok(input)
}

pub struct VerificationKeys<'a> {
    pub setup: VerificationKey<'a>,
    pub descendants: Field,
    pub c5: VerificationKey<'a>,
}

impl VerificationKeys<'_> {
    pub fn tree(&self) -> Result<Field, WitnessError> {
        hash(&[self.setup.hash, self.descendants])
    }
}

pub fn publication(
    config: &Configs,
    binding: SetupBinding,
    roster: &[u32],
    recipients: &[Child<'_>],
    c5: Child<'_>,
    keys: &VerificationKeys<'_>,
) -> Result<Value, WitnessError> {
    dealers(config, roster)?;
    if recipients.len() != roster.len() {
        return Err(invalid("publication requires exactly H recipient setups"));
    }
    let aggregation = statement(config, &c5, CircuitName::PkAggregation)?;
    let mut batch = None;
    for (&id, child) in roster.iter().zip(recipients) {
        let public = statement(config, child, CircuitName::NodesFold)?;
        if public.tree_hash() != Some(keys.descendants) {
            return Err(WitnessError::VerificationKey(
                "recipient genealogy differs from the local verifier keys".into(),
            ));
        }
        if public.binding() != Some(binding)
            || public.party_id() != Some(id)
            || public.dealers().as_deref() != Some(roster)
            || public.threshold_keys() != aggregation.threshold_keys()
        {
            return Err(invalid(
                "publication child differs from its context, roster or C5",
            ));
        }
        if batch.is_some_and(|expected| public.dealer_batch() != Some(expected)) {
            return Err(invalid("recipients used different dealer batches"));
        }
        batch = public.dealer_batch();
    }
    let mut input = json!({
        "expected_tree_hash": format!("0x{}", hex::encode(keys.tree()?)),
        "setup_binding": binding_json(binding),
        "dealer_ids": roster,
    });
    insert_child(&mut input, "setup", &recipients[0], &keys.setup)?;
    input.as_object_mut().unwrap().remove("setup_proof");
    input["setup_proofs"] = Value::Array(
        recipients
            .iter()
            .map(|child| fields(child.proof))
            .collect::<Result<_, _>>()?,
    );
    input["setup_public"] = Value::Array(
        recipients
            .iter()
            .map(|child| fields(child.public_signals))
            .collect::<Result<_, _>>()?,
    );
    insert_child(&mut input, "c5", &c5, &keys.c5)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvProfile;

    fn encode(values: &[u8]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| {
                let mut field = [0; 32];
                field[31] = *value;
                field
            })
            .collect()
    }

    #[test]
    fn only_complete_canonical_setup_children_are_encoded() {
        let config = Configs::for_profile(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        let bytes = [0; 32]; // Synthetic recursive bytes test encoding, never proof validity.
        let first = encode(&[100, 10, 20, 0, 0, 2, 5, 6, 7, 8, 9]);
        let second = encode(&[100, 10, 20, 2, 0, 2, 5, 6, 7, 18, 19]);
        let aggregate = encode(&[5, 6, 99]);
        let mut descendants = [0; 32];
        descendants[31] = 100;
        let keys = VerificationKeys {
            setup: VerificationKey {
                fields: &bytes,
                hash: [0; 32],
            },
            descendants,
            c5: VerificationKey {
                fields: &bytes,
                hash: [0; 32],
            },
        };
        let attempt = |first: &[u8], second: &[u8], roster: &[u32]| {
            publication(
                &config,
                [10, 20],
                roster,
                &[
                    Child {
                        circuit: CircuitName::NodesFold,
                        proof: &bytes,
                        public_signals: first,
                    },
                    Child {
                        circuit: CircuitName::NodesFold,
                        proof: &bytes,
                        public_signals: second,
                    },
                ],
                Child {
                    circuit: CircuitName::PkAggregation,
                    proof: &bytes,
                    public_signals: &aggregate,
                },
                &keys,
            )
        };
        let input = attempt(&first, &second, &[0, 2]).unwrap();
        assert_eq!(input["setup_public"].as_array().unwrap().len(), 2);
        assert_eq!(input["setup_public"][0].as_array().unwrap().len(), 11);
        assert!(attempt(&first[..first.len() - 32], &second, &[0, 2]).is_err());
        assert!(attempt(&first, &second, &[0]).is_err());
        assert!(attempt(&second, &first, &[0, 2]).is_err());
        for slot in [0, 1, 3, 5, 6, 8] {
            let mut altered = second.clone();
            altered[slot * 32 + 31] ^= 1;
            assert!(attempt(&first, &altered, &[0, 2]).is_err());
        }
        let mut noncanonical = second.clone();
        noncanonical[9 * 32..10 * 32].fill(255);
        assert!(attempt(&first, &noncanonical, &[0, 2]).is_err());
    }
}
