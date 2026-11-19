// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    invalid,
    provenance::{canonical, fields, insert_child, statement, Child, VerificationKey},
};
use crate::WitnessError;
use e3_zk_config::{synchronized::Configs, CircuitName};
use serde_json::{json, Value};

/// Public rows come only from C7. Refuse any input whose C6 proof advertised a different row.
/// The recursive verifier checks the proof bodies against those very same fields.
pub fn prepare(
    config: &Configs,
    c6: &[Child<'_>],
    c7: Child<'_>,
    c6_key: VerificationKey<'_>,
    c7_key: VerificationKey<'_>,
) -> Result<Value, WitnessError> {
    statement(config, &c7, CircuitName::DecryptedSharesAggregation)?;
    if c6.len() != config.committee.values().threshold + 1 {
        return Err(invalid("incomplete synchronized C6 proof batch"));
    }
    let mut proofs = Vec::with_capacity(c6.len());
    for (child, row) in c6.iter().zip(
        c7.public_signals
            .chunks_exact(config.c6_public_fields() * 32),
    ) {
        if child.circuit != CircuitName::ThresholdShareDecryption || child.public_signals != row {
            return Err(invalid("C6 proof does not match its exact C7 row"));
        }
        proofs.push(fields(child.proof)?);
    }
    canonical(&c6_key.hash).map_err(|error| WitnessError::VerificationKey(error.to_string()))?;
    let mut input = json!({
        "c6_vk": fields(c6_key.fields)?,
        "c6_key_hash": format!("0x{}", hex::encode(c6_key.hash)),
        "c6_proofs": proofs,
    });
    insert_child(&mut input, "c7", &c7, &c7_key)?;
    Ok(input)
}
