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
        let layout = CircuitName::ShareEncryption.input_layout();
        assert_eq!(layout.field_count(), Some(2));
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
    }

    #[test]
    fn extract_input_from_non_input_circuit() {
        let proof = make_proof(CircuitName::PkBfv, &[0u8; 32]);
        assert!(proof.extract_input("anything").is_none());
    }
}
