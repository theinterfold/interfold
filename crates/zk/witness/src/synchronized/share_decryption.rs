// SPDX-License-Identifier: LGPL-3.0-only

use super::{binding_json, commitments, dealers, invalid, keys, owner, KeyBytes, SetupBinding};
use crate::encoding::{bigint_2d_to_json_values, poly_coefficients_to_toml_json};
use crate::{compute_share_encryption_commitment_from_message, WitnessError};
use e3_polynomial::Polynomial;
use e3_zk_config::synchronized::Configs;
use num_bigint::BigInt;

pub struct Data {
    pub recipient_id: u32,
    pub dealer_ids: Vec<u32>,
    /// Authenticated public outputs of the owner's C2 and the selected dealers' C2 statements.
    pub expected_outgoing_root: BigInt,
    pub expected_commitments: Vec<Vec<BigInt>>,
    /// Exact native-order decoded transport plaintexts, not reconstructed or resampled messages.
    pub packed_shares: Vec<Vec<Vec<u64>>>,
    pub outgoing_keys: Vec<KeyBytes>,
    pub incoming_keys: Vec<KeyBytes>,
}

pub struct Inputs {
    setup_binding: SetupBinding,
    data: Data,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        binding: SetupBinding,
        data: Data,
    ) -> Result<Self, WitnessError> {
        owner(config, data.recipient_id)?;
        dealers(config, &data.dealer_ids)?;
        let values = config.committee.values();
        keys(config, &data.outgoing_keys, values.n)?;
        keys(config, &data.incoming_keys, values.h)?;
        let limbs = config.threshold.moduli().len();
        let degree = config.threshold.degree();
        if data.expected_commitments.len() != values.h
            || data
                .expected_commitments
                .iter()
                .any(|row| row.len() != limbs)
            || data.packed_shares.len() != values.h
            || data
                .packed_shares
                .iter()
                .any(|row| row.len() != limbs || row.iter().any(|limb| limb.len() != degree))
        {
            return Err(invalid(
                "packed DKG inputs do not match the configured H/CRT/ring shape",
            ));
        }
        if commitments::outgoing_root(config, binding, data.recipient_id, &data.outgoing_keys)?
            != data.expected_outgoing_root
        {
            return Err(invalid(
                "outgoing keys do not open the authenticated C2 root",
            ));
        }
        for (&dealer, incoming) in data.dealer_ids.iter().zip(&data.incoming_keys) {
            if dealer == data.recipient_id && incoming != &data.outgoing_keys[dealer as usize] {
                return Err(invalid("own PRF key directions differ"));
            }
        }
        for (row, packed) in data.packed_shares.iter().enumerate() {
            for (limb, (&modulus, coefficients)) in
                config.threshold.moduli().iter().zip(packed).enumerate()
            {
                for (coefficient, &value) in coefficients.iter().enumerate() {
                    let bit = if limb == 0 && coefficient < config.key_bits {
                        u64::from(
                            (data.incoming_keys[row][coefficient / 8] >> (coefficient % 8)) & 1,
                        )
                    } else {
                        0
                    };
                    if value
                        .checked_sub(bit * modulus)
                        .is_none_or(|residue| residue >= modulus)
                    {
                        return Err(invalid("packed plaintext does not encode its incoming key and canonical residue"));
                    }
                }
                let reversed = Polynomial::new(
                    coefficients
                        .iter()
                        .rev()
                        .copied()
                        .map(BigInt::from)
                        .collect(),
                );
                if compute_share_encryption_commitment_from_message(
                    &reversed,
                    config.share_encryption.bits.msg_bit,
                ) != data.expected_commitments[row][limb]
                {
                    return Err(invalid(
                        "packed plaintext does not open the authenticated C2 commitment",
                    ));
                }
            }
        }
        Ok(Self {
            setup_binding: binding,
            data,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        let packed: Vec<Vec<_>> = self
            .data
            .packed_shares
            .iter()
            .map(|row| {
                row.iter()
                    .map(|coefficients| {
                        let coefficients: Vec<_> =
                            coefficients.iter().copied().map(BigInt::from).collect();
                        poly_coefficients_to_toml_json(&coefficients)
                    })
                    .collect()
            })
            .collect();
        serde_json::json!({
            "setup_binding": binding_json(self.setup_binding),
            "recipient_id": self.data.recipient_id,
            "dealer_ids": self.data.dealer_ids,
            "expected_outgoing_root": self.data.expected_outgoing_root.to_string(),
            "expected_commitments": bigint_2d_to_json_values(&self.data.expected_commitments),
            "packed_shares": packed,
            "outgoing_keys": self.data.outgoing_keys,
            "incoming_keys": self.data.incoming_keys,
        })
    }
}
