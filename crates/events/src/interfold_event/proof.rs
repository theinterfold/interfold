// SPDX-License-Identifier: LGPL-3.0-only

use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
pub use e3_zk_config::{CircuitName, CircuitVariant};

use serde::{Deserialize, Serialize};

/// A zero-knowledge proof with all data needed for verification.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct Proof {
    /// Circuit that generated this proof.
    pub circuit: CircuitName,
    /// The proof bytes.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub data: ArcBytes,
    /// Public signals from the circuit (inputs and outputs).
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub public_signals: ArcBytes,
}

impl Proof {
    pub fn new(
        circuit: CircuitName,
        data: impl Into<ArcBytes>,
        public_signals: impl Into<ArcBytes>,
    ) -> Self {
        Self {
            circuit,
            data: data.into(),
            public_signals: public_signals.into(),
        }
    }

    /// Extract a named public output field from this proof's public signals.
    ///
    /// Return values sit at the **end** of `public_signals`, after any `pub`
    /// input parameters.  The field name must match one declared in the
    /// circuit's [`CircuitOutputLayout`](e3_zk_config::CircuitOutputLayout).
    pub fn extract_output(&self, field_name: &str) -> Option<ArcBytes> {
        let layout = self.circuit.output_layout();
        layout
            .extract_field(&self.public_signals, field_name)
            .map(ArcBytes::from_bytes)
    }

    /// Extract a named public input field from this proof's public signals.
    ///
    /// Public inputs sit at the **start** of `public_signals`, before any
    /// return values.  The field name must match one declared in the circuit's
    /// [`CircuitInputLayout`](e3_zk_config::CircuitInputLayout).
    pub fn extract_input(&self, field_name: &str) -> Option<ArcBytes> {
        let layout = self.circuit.input_layout();
        layout
            .extract_field(&self.public_signals, field_name)
            .map(ArcBytes::from_bytes)
    }

    /// Read a named public input as a `u32`.
    ///
    /// A `u32` field has zero in bytes `0..28` and the big-endian value in bytes `28..32`. Returns
    /// `None` when the input is missing or does not fit.
    pub fn input_u32(&self, field_name: &str) -> Option<u32> {
        let field = self
            .circuit
            .input_layout()
            .extract_field(&self.public_signals, field_name)?;
        let (high, low) = field.split_at(28);
        high.iter()
            .all(|byte| *byte == 0)
            .then(|| u32::from_be_bytes(low.try_into().expect("four-byte u32 suffix")))
    }

    /// Read a named public input as a `u128`: zero in bytes `0..16`, the big-endian value in bytes
    /// `16..32`. Returns `None` when the input is missing or does not fit.
    pub fn input_u128(&self, field_name: &str) -> Option<u128> {
        let field = self
            .circuit
            .input_layout()
            .extract_field(&self.public_signals, field_name)?;
        let (high, low) = field.split_at(16);
        high.iter()
            .all(|byte| *byte == 0)
            .then(|| u128::from_be_bytes(low.try_into().expect("sixteen-byte u128 suffix")))
    }

    /// Whether the public inputs `session_id_hi` and `session_id_lo` equal the given session limbs.
    pub fn has_session(&self, session_hi: u128, session_lo: u128) -> bool {
        self.input_u128("session_id_hi") == Some(session_hi)
            && self.input_u128("session_id_lo") == Some(session_lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof(circuit: CircuitName, signals: &[u8]) -> Proof {
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[0u8; 8]),
            ArcBytes::from_bytes(signals),
        )
    }

    #[test]
    fn extract_c1_pk_commitment() {
        // C1 has 3 outputs: sk_commitment, pk_commitment, e_sm_commitment
        let mut signals = vec![0u8; 96];
        signals[0..32].copy_from_slice(&[0x11; 32]); // sk_commitment
        signals[32..64].copy_from_slice(&[0x22; 32]); // pk_commitment
        signals[64..96].copy_from_slice(&[0x33; 32]); // e_sm_commitment

        let proof = make_proof(CircuitName::PkGeneration, &signals);
        assert_eq!(
            &*proof.extract_output("pk_commitment").unwrap(),
            &[0x22; 32]
        );
        assert_eq!(
            &*proof.extract_output("sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            &*proof.extract_output("e_sm_commitment").unwrap(),
            &[0x33; 32]
        );
    }

    #[test]
    fn extract_c5_commitment_after_pub_inputs() {
        // C5 has H pub input fields + 1 output. Simulate H=2 → 96 bytes total.
        let mut signals = vec![0xAA; 96];
        signals[64..96].copy_from_slice(&[0xFF; 32]); // commitment (last output)

        let proof = make_proof(CircuitName::PkAggregation, &signals);
        assert_eq!(&*proof.extract_output("commitment").unwrap(), &[0xFF; 32]);
    }

    #[test]
    fn extract_c6_d_commitment_after_pub_inputs() {
        // C6: 5 public inputs + 1 output (`d_commitment` at tail).
        let mut signals = vec![0u8; 192];
        signals[0..32].copy_from_slice(&[0x11; 32]); // expected_sk_commitment
        signals[32..64].copy_from_slice(&[0x22; 32]); // expected_e_sm_commitment
        signals[64..96].copy_from_slice(&[0x33; 32]); // ct_commitment
        signals[96..128].copy_from_slice(&[0x44; 32]); // domain_hi
        signals[128..160].copy_from_slice(&[0x55; 32]); // domain_lo
        signals[160..192].copy_from_slice(&[0x77; 32]); // d_commitment

        let proof = make_proof(CircuitName::ThresholdShareDecryption, &signals);
        assert_eq!(&*proof.extract_output("d_commitment").unwrap(), &[0x77; 32]);
    }

    #[test]
    fn extract_c6_public_inputs() {
        let mut signals = vec![0u8; 192];
        signals[0..32].copy_from_slice(&[0x11; 32]);
        signals[32..64].copy_from_slice(&[0x22; 32]);
        signals[64..96].copy_from_slice(&[0x33; 32]);
        signals[96..128].copy_from_slice(&[0x44; 32]);
        signals[128..160].copy_from_slice(&[0x55; 32]);
        signals[160..192].copy_from_slice(&[0x77; 32]);

        let proof = make_proof(CircuitName::ThresholdShareDecryption, &signals);
        assert_eq!(
            &*proof.extract_input("expected_sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            &*proof.extract_input("expected_e_sm_commitment").unwrap(),
            &[0x22; 32]
        );
        assert_eq!(&*proof.extract_input("ct_commitment").unwrap(), &[0x33; 32]);
        assert_eq!(&*proof.extract_input("domain_hi").unwrap(), &[0x44; 32]);
        assert_eq!(&*proof.extract_input("domain_lo").unwrap(), &[0x55; 32]);
    }

    #[test]
    fn extract_c7_has_no_named_public_outputs() {
        // C7 (`DecryptedSharesAggregation`) has only public inputs in Noir; `output_layout` is
        // `None`, so `extract_output` cannot resolve a return field.
        let signals = vec![0xAB; 32 * 8];
        let proof = make_proof(CircuitName::DecryptedSharesAggregation, &signals);
        assert!(proof.extract_output("d_commitment").is_none());
        assert!(proof.extract_output("commitment").is_none());
    }

    #[test]
    fn extract_nonexistent_field() {
        let proof = make_proof(CircuitName::PkBfv, &[0u8; 32]);
        assert!(proof.extract_output("nonexistent").is_none());
    }

    #[test]
    fn extract_signals_too_short() {
        // C1 needs 96 bytes for outputs, only 64 available
        let proof = make_proof(CircuitName::PkGeneration, &[0u8; 64]);
        assert!(proof.extract_output("pk_commitment").is_none());
    }

    #[test]
    fn extract_empty_signals() {
        let proof = make_proof(CircuitName::PkGeneration, &[]);
        assert!(proof.extract_output("pk_commitment").is_none());
    }

    #[test]
    fn input_layout_share_encryption() {
        // C3 has 2 public inputs: expected_pk_commitment, expected_message_commitment.
        assert_eq!(
            CircuitName::ShareEncryption.input_layout().field_count(),
            Some(2)
        );
        // The chunked C3 also exposes party_idx and mod_idx.
        assert_eq!(
            CircuitName::ShareEncryptionChunked
                .input_layout()
                .field_count(),
            Some(4)
        );
    }

    #[test]
    fn input_layout_other_circuits_none() {
        assert_eq!(CircuitName::PkBfv.input_layout().field_count(), Some(0));
        assert_eq!(
            CircuitName::PkGeneration.input_layout().field_count(),
            Some(0)
        );
    }

    #[test]
    fn rlk_generation_layout_tracks_row_and_commitments() {
        let mut signals = vec![0u8; 256];
        signals[127] = 3;
        signals[128..160].copy_from_slice(&[0x11; 32]);
        signals[160..192].copy_from_slice(&[0x22; 32]);
        signals[192..224].copy_from_slice(&[0x33; 32]);
        signals[224..256].copy_from_slice(&[0x44; 32]);
        let proof = make_proof(CircuitName::RlkGeneration, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 3);
        assert_eq!(
            &*proof.extract_output("sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(&*proof.extract_output("r_commitment").unwrap(), &[0x22; 32]);
        assert_eq!(
            &*proof.extract_output("d0_commitment").unwrap(),
            &[0x33; 32]
        );
        assert_eq!(
            &*proof.extract_output("d2_commitment").unwrap(),
            &[0x44; 32]
        );
        assert!(proof.extract_output("limb_vk_hash").is_none());
    }

    #[test]
    fn lbfv_pk_generation_layout_tracks_row_and_commitments() {
        let mut signals = vec![0u8; 192];
        signals[127] = 2;
        signals[128..160].copy_from_slice(&[0x11; 32]);
        signals[160..192].copy_from_slice(&[0x22; 32]);
        let proof = make_proof(CircuitName::LbfvPkGeneration, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 2);
        assert_eq!(
            &*proof.extract_output("sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            &*proof.extract_output("pk_commitment").unwrap(),
            &[0x22; 32]
        );
        assert!(proof.extract_output("limb_vk_hash").is_none());
    }

    #[test]
    fn rlk_aggregation_layout_tracks_row_component_and_commitment() {
        let mut signals = vec![0u8; 320];
        signals[191] = 4;
        signals[223] = 1;
        signals[288..320].copy_from_slice(&[0x55; 32]);
        let proof = make_proof(CircuitName::RlkAggregation, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 4);
        assert_eq!(proof.extract_input("component").unwrap()[31], 1);
        assert_eq!(
            &*proof.extract_output("agg_commitment").unwrap(),
            &[0x55; 32]
        );
    }

    #[test]
    fn lbfv_pk_aggregation_layout_tracks_row_and_tail_commitment() {
        let mut signals = vec![0u8; 288];
        signals[191] = 4;
        signals[256..288].copy_from_slice(&[0x77; 32]);
        let proof = make_proof(CircuitName::LbfvPkAggregation, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 4);
        assert_eq!(
            &*proof.extract_output("pk_agg_commitment").unwrap(),
            &[0x77; 32]
        );
        assert_eq!(proof.circuit.input_layout().field_count(), Some(6));
    }

    #[test]
    fn extract_input_from_share_encryption() {
        // C3: 2 pub inputs at HEAD + ct_commitment return at tail
        let mut signals = vec![0u8; 96];
        signals[0..32].copy_from_slice(&[0xAA; 32]); // expected_pk_commitment
        signals[32..64].copy_from_slice(&[0xBB; 32]); // expected_message_commitment
        signals[64..96].copy_from_slice(&[0xCC; 32]); // ct_commitment

        let proof = make_proof(CircuitName::ShareEncryption, &signals);
        assert_eq!(
            &*proof.extract_input("expected_pk_commitment").unwrap(),
            &[0xAA; 32]
        );
        assert_eq!(
            &*proof.extract_input("expected_message_commitment").unwrap(),
            &[0xBB; 32]
        );
        assert_eq!(
            &*proof.extract_output("ct_commitment").unwrap(),
            &[0xCC; 32]
        );
        assert!(proof.extract_input("party_idx").is_none());
    }

    #[test]
    fn extract_input_from_share_encryption_chunked() {
        // Chunked C3: four public inputs at the head and ct_commitment at the tail.
        let mut signals = vec![0u8; 160];
        signals[0..32].copy_from_slice(&[0xAA; 32]); // expected_pk_commitment
        signals[32..64].copy_from_slice(&[0xBB; 32]); // expected_message_commitment
        signals[95] = 7; // party_idx
        signals[127] = 2; // mod_idx
        signals[128..160].copy_from_slice(&[0xCC; 32]); // ct_commitment

        let proof = make_proof(CircuitName::ShareEncryptionChunked, &signals);
        assert_eq!(
            &*proof.extract_input("expected_pk_commitment").unwrap(),
            &[0xAA; 32]
        );
        assert_eq!(
            &*proof.extract_input("expected_message_commitment").unwrap(),
            &[0xBB; 32]
        );
        assert_eq!(proof.input_u32("party_idx"), Some(7));
        assert_eq!(proof.input_u32("mod_idx"), Some(2));
        assert_eq!(
            &*proof.extract_output("ct_commitment").unwrap(),
            &[0xCC; 32]
        );
    }

    #[test]
    fn public_integer_inputs_reject_values_that_do_not_fit() {
        // RLK generation: four public inputs, then four outputs.
        let mut signals = vec![0u8; 256];
        signals[31] = 9; // session_id_hi
        signals[63] = 4; // session_id_lo
        signals[95] = 1; // party_id
        let proof = make_proof(CircuitName::RlkGeneration, &signals);
        assert_eq!(proof.input_u32("party_id"), Some(1));
        assert_eq!(proof.input_u128("session_id_hi"), Some(9));
        assert!(proof.has_session(9, 4));
        assert!(!proof.has_session(4, 9));

        signals[40] = 1; // session_id_lo no longer fits a u128
        signals[64] = 1; // party_id no longer fits a u32
        let proof = make_proof(CircuitName::RlkGeneration, &signals);
        assert_eq!(proof.input_u128("session_id_lo"), None);
        assert!(!proof.has_session(9, 4));
        assert_eq!(proof.input_u32("party_id"), None);
        assert_eq!(proof.input_u32("nonexistent"), None);
    }

    #[test]
    fn extract_input_from_non_input_circuit() {
        let proof = make_proof(CircuitName::PkBfv, &[0u8; 32]);
        assert!(proof.extract_input("anything").is_none());
    }
}
