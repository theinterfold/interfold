// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    invalid,
    provenance::{fields, insert_child, statement, Child, VerificationKey},
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
    let mut input = json!({ "c6_proofs": proofs });
    c6_key.insert(&mut input, "c6")?;
    insert_child(&mut input, "c7", &c7, &c7_key)?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvProfile;

    #[test]
    fn local_key_and_child_proof_decoding_errors_stay_distinct() {
        let cfg = Configs::for_profile(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
        )
        .unwrap();
        let width = cfg.c6_public_fields() * 32;
        let mut public = vec![0; 2 * width + e3_zk_config::MAX_MSG_NON_ZERO_COEFFS * 32];
        // Both rows name roster [0, 1]; the second row belongs to owner 1.
        public[5 * 32 - 1] = 1;
        public[width + 5 * 32 - 1] = 1;
        public[width + 3 * 32 - 1] = 1;
        let attempt = |c6_bytes: &[u8], proof: &[u8]| {
            let child = |slot: usize| Child {
                circuit: CircuitName::ThresholdShareDecryption,
                public_signals: &public[slot * width..(slot + 1) * width],
                proof,
            };
            prepare(
                &cfg,
                &[child(0), child(1)],
                Child {
                    circuit: CircuitName::DecryptedSharesAggregation,
                    public_signals: &public,
                    proof: &[0; 32],
                },
                VerificationKey {
                    fields: c6_bytes,
                    hash: [0; 32],
                },
                VerificationKey {
                    fields: &[0; 32],
                    hash: [0; 32],
                },
            )
        };
        assert!(attempt(&[0; 32], &[0; 32]).is_ok());
        assert!(matches!(
            attempt(&[255; 32], &[0; 32]),
            Err(WitnessError::VerificationKey(_))
        ));
        assert!(!matches!(
            attempt(&[0; 32], &[255; 32]).unwrap_err(),
            WitnessError::VerificationKey(_)
        ));
    }
}
