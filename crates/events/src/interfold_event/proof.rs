// SPDX-License-Identifier: LGPL-3.0-only

use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::{
    CircuitInputLayout, CircuitOutputLayout, DKG_SHARE_DECRYPTION_OUTPUTS,
    LBFV_PK_AGGREGATION_INPUTS, LBFV_PK_AGGREGATION_OUTPUTS, LBFV_PK_GENERATION_INPUTS,
    LBFV_PK_GENERATION_OUTPUTS, PK_AGGREGATION_OUTPUTS, PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS,
    RLK_AGGREGATION_INPUTS, RLK_AGGREGATION_OUTPUTS, RLK_GENERATION_INPUTS,
    RLK_GENERATION_LIMB_INPUTS, RLK_GENERATION_LIMB_OUTPUTS, RLK_GENERATION_OUTPUTS,
    SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS, THRESHOLD_SHARE_DECRYPTION_INPUTS,
    THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
};
use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// circuit's [`CircuitOutputLayout`].
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
    /// [`CircuitInputLayout`].
    pub fn extract_input(&self, field_name: &str) -> Option<ArcBytes> {
        let layout = self.circuit.input_layout();
        layout
            .extract_field(&self.public_signals, field_name)
            .map(ArcBytes::from_bytes)
    }
}

/// Circuit variants determine the hash oracle used for VK generation and proving.
///
/// - `Default`: poseidon/`noir-recursive-no-zk` — wrapper & fold proofs (no ZK blinding, efficient).
/// - `Recursive`: poseidon/`noir-recursive` — inner/base proofs fed into a wrapper (ZK blinding preserved).
/// - `Evm`: keccak/`evm` — on-chain EVM-verifiable proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CircuitVariant {
    /// noir-recursive-no-zk: for wrapper & fold proofs — poseidon, no ZK blinding.
    #[default]
    Default,
    /// noir-recursive: for inner/base proofs — poseidon with ZK blinding.
    Recursive,
    /// evm: keccak-based for on-chain Solidity verification.
    Evm,
}

impl CircuitVariant {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitVariant::Default => "default",
            CircuitVariant::Recursive => "recursive",
            CircuitVariant::Evm => "evm",
        }
    }

    /// Returns the bb verifier target flag value for this variant.
    pub fn verifier_target(&self) -> &'static str {
        match self {
            CircuitVariant::Default => "noir-recursive-no-zk",
            CircuitVariant::Recursive => "noir-recursive",
            CircuitVariant::Evm => "evm",
        }
    }
}

impl fmt::Display for CircuitVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Circuit identifiers for ZK proofs.
///
/// Bincode encodes this enum by variant order. Do not reorder variants.
/// Add new circuits at the end. Keep retired circuits for compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum CircuitName {
    /// BFV public key proof (C0).
    PkBfv = 0,
    /// TrBFV public key share proof (C1).
    PkGeneration = 1,
    /// Share encryption proof (C3).
    ShareEncryption = 2,
    /// DKG share decryption proof (C4).
    DkgShareDecryption = 3,
    /// Public key aggregation proof (C5).
    PkAggregation = 4,
    /// Decryption share proof (C6).
    ThresholdShareDecryption = 5,
    /// Decrypted shares aggregation proof (C7).
    DecryptedSharesAggregation = 6,
    /// Sequential C3 fold: inner ZK + optional prior `c3_fold` non-ZK proof.
    C3Fold = 7,
    /// Bootstrap circuit for [`CircuitName::C3Fold`] genesis accumulator proof (same ABI, no acc verify).
    C3FoldKernel = 8,
    /// Sequential C6 fold: inner ZK + prior `c6_fold` non-ZK proof (phase-7 aggregator).
    C6Fold = 9,
    /// Bootstrap circuit for [`CircuitName::C6Fold`] genesis accumulator proof (same ABI, no acc verify).
    C6FoldKernel = 10,
    /// Ad-hoc: final sk `c3_fold` + final e_sm `c3_fold`.
    C3abFold = 11,
    /// Ad-hoc: C4a + C4b.
    C4abFold = 12,
    /// Per-node DKG fold (C0..C4 links).
    NodeFold = 13,
    /// Sequential fold of `H` `node_fold` proofs (non-ZK) before `dkg_aggregator`.
    NodesFold = 14,
    /// Bootstrap circuit for [`CircuitName::NodesFold`] genesis accumulator proof (same ABI, no acc verify).
    NodesFoldKernel = 15,
    /// DKG aggregator (folded `node_fold` via `nodes_fold` + C5).
    DkgAggregator = 16,
    /// Phase-7 decryption aggregator (folded C6 via `c6_fold` + C7).
    DecryptionAggregator = 17,
    /// SK coefficient-range proof used by the root-committed chunk pipeline.
    SkShareComputationChunk = 18,
    /// ESM coefficient-range proof used by the root-committed chunk pipeline.
    ESmShareComputationChunk = 19,
    /// Recursive batch of C2 chunk proofs.
    C2ChunkBatch = 20,
    /// Type-bound SK terminal projection from a complete C2 chunk accumulator.
    SkC2ChunkFinalize = 21,
    /// Type-bound ESM terminal projection from a complete C2 chunk accumulator.
    ESmC2ChunkFinalize = 22,
    /// Combines type-bound terminal C2a and C2b chunk proofs.
    C2abChunkFold = 23,
    /// Legacy Sk share computation (C2a). Retain for bincode compatibility. Do not produce.
    SkShareComputation = 24,
    /// Legacy ESM share computation (C2b). Retain for bincode compatibility. Do not produce.
    ESmShareComputation = 25,
    /// Legacy ad-hoc aggregation C2a + C2b. Retain for bincode compatibility. Do not produce.
    C2abFold = 26,
    /// Row-level l-BFV relinearization-key generation proof.
    RlkGeneration = 27,
    /// Row-level l-BFV relinearization-key aggregation proof.
    RlkAggregation = 28,
    /// Row-level l-BFV public-key generation proof.
    LbfvPkGeneration = 29,
    /// Row-level threshold l-BFV public-key aggregation proof.
    LbfvPkAggregation = 30,
    /// One CRT limb of one l-BFV relinearization-key row.
    RlkGenerationLimb = 31,
}

impl CircuitName {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "pk",
            CircuitName::PkGeneration => "pk_generation",
            CircuitName::SkShareComputation => "sk_share_computation",
            CircuitName::ESmShareComputation => "e_sm_share_computation",
            CircuitName::SkShareComputationChunk => "sk_share_computation_chunk",
            CircuitName::ESmShareComputationChunk => "esm_share_computation_chunk",
            CircuitName::C2ChunkBatch => "c2_chunk_batch",
            CircuitName::ShareEncryption => "share_encryption",
            CircuitName::DkgShareDecryption => "share_decryption",
            CircuitName::PkAggregation => "pk_aggregation",
            CircuitName::ThresholdShareDecryption => "share_decryption",
            CircuitName::DecryptedSharesAggregation => "decrypted_shares_aggregation",
            CircuitName::C3Fold => "c3_fold",
            CircuitName::C3FoldKernel => "c3_fold_kernel",
            CircuitName::SkC2ChunkFinalize => "sk_c2_chunk_finalize",
            CircuitName::ESmC2ChunkFinalize => "esm_c2_chunk_finalize",
            CircuitName::C2abChunkFold => "c2ab_chunk_fold",
            CircuitName::C6Fold => "c6_fold",
            CircuitName::C6FoldKernel => "c6_fold_kernel",
            CircuitName::C2abFold => "c2ab_fold",
            CircuitName::C3abFold => "c3ab_fold",
            CircuitName::C4abFold => "c4ab_fold",
            CircuitName::NodeFold => "node_fold",
            CircuitName::NodesFold => "nodes_fold",
            CircuitName::NodesFoldKernel => "nodes_fold_kernel",
            CircuitName::DkgAggregator => "dkg_aggregator",
            CircuitName::DecryptionAggregator => "decryption_aggregator",
            CircuitName::RlkGeneration => "rlk_generation",
            CircuitName::RlkAggregation => "rlk_aggregation",
            CircuitName::LbfvPkGeneration => "lbfv_pk_generation",
            CircuitName::LbfvPkAggregation => "lbfv_pk_aggregation",
            CircuitName::RlkGenerationLimb => "rlk_generation_limb",
        }
    }

    pub fn group(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "dkg",
            CircuitName::SkShareComputation
            | CircuitName::ESmShareComputation
            | CircuitName::SkShareComputationChunk
            | CircuitName::ESmShareComputationChunk
            | CircuitName::ShareEncryption
            | CircuitName::DkgShareDecryption => "dkg",
            CircuitName::PkGeneration => "threshold",
            CircuitName::ThresholdShareDecryption => "threshold",
            CircuitName::PkAggregation => "threshold",
            CircuitName::DecryptedSharesAggregation => "threshold",
            CircuitName::RlkGeneration
            | CircuitName::RlkAggregation
            | CircuitName::LbfvPkGeneration
            | CircuitName::LbfvPkAggregation
            | CircuitName::RlkGenerationLimb => "threshold",
            CircuitName::C3Fold
            | CircuitName::C3FoldKernel
            | CircuitName::C2ChunkBatch
            | CircuitName::SkC2ChunkFinalize
            | CircuitName::ESmC2ChunkFinalize
            | CircuitName::C2abChunkFold
            | CircuitName::C6Fold
            | CircuitName::C6FoldKernel
            | CircuitName::C2abFold
            | CircuitName::C3abFold
            | CircuitName::C4abFold
            | CircuitName::NodeFold
            | CircuitName::NodesFold
            | CircuitName::NodesFoldKernel
            | CircuitName::DkgAggregator
            | CircuitName::DecryptionAggregator => "recursive_aggregation",
        }
    }

    pub fn dir_path(&self) -> String {
        format!("{}/{}", self.group(), self.as_str())
    }

    /// Public input layout for this circuit.
    ///
    /// Public output (return value) layout for this circuit.
    pub fn output_layout(&self) -> CircuitOutputLayout {
        match self {
            CircuitName::PkBfv => CircuitOutputLayout::Fixed {
                fields: PK_BFV_OUTPUTS,
            },
            CircuitName::PkGeneration => CircuitOutputLayout::Fixed {
                fields: PK_GENERATION_OUTPUTS,
            },
            CircuitName::LbfvPkGeneration => CircuitOutputLayout::Fixed {
                fields: LBFV_PK_GENERATION_OUTPUTS,
            },
            CircuitName::LbfvPkAggregation => CircuitOutputLayout::Fixed {
                fields: LBFV_PK_AGGREGATION_OUTPUTS,
            },
            CircuitName::RlkGeneration => CircuitOutputLayout::Fixed {
                fields: RLK_GENERATION_OUTPUTS,
            },
            CircuitName::RlkGenerationLimb => CircuitOutputLayout::Fixed {
                fields: RLK_GENERATION_LIMB_OUTPUTS,
            },
            CircuitName::RlkAggregation => CircuitOutputLayout::Fixed {
                fields: RLK_AGGREGATION_OUTPUTS,
            },
            // Legacy circuits no longer produce proofs. Map to None so old
            // proofs fail closed on extraction but still decode.
            CircuitName::SkShareComputation
            | CircuitName::ESmShareComputation
            | CircuitName::SkShareComputationChunk
            | CircuitName::ESmShareComputationChunk => CircuitOutputLayout::None,
            CircuitName::DkgShareDecryption => CircuitOutputLayout::Fixed {
                fields: DKG_SHARE_DECRYPTION_OUTPUTS,
            },
            CircuitName::PkAggregation => CircuitOutputLayout::Fixed {
                fields: PK_AGGREGATION_OUTPUTS,
            },
            CircuitName::ThresholdShareDecryption => CircuitOutputLayout::Fixed {
                fields: THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
            },
            CircuitName::ShareEncryption => CircuitOutputLayout::Fixed {
                fields: SHARE_ENCRYPTION_OUTPUTS,
            },
            CircuitName::DecryptedSharesAggregation => CircuitOutputLayout::None,
            CircuitName::C3Fold
            | CircuitName::C3FoldKernel
            | CircuitName::C2ChunkBatch
            | CircuitName::SkC2ChunkFinalize
            | CircuitName::ESmC2ChunkFinalize
            | CircuitName::C2abChunkFold
            | CircuitName::C6Fold
            | CircuitName::C6FoldKernel
            | CircuitName::C2abFold
            | CircuitName::C3abFold
            | CircuitName::C4abFold
            | CircuitName::NodeFold
            | CircuitName::NodesFold
            | CircuitName::NodesFoldKernel
            | CircuitName::DkgAggregator
            | CircuitName::DecryptionAggregator => CircuitOutputLayout::None,
        }
    }

    /// Public input layout for circuits with tracked fields at the start of public_signals.
    pub fn input_layout(&self) -> CircuitInputLayout {
        match self {
            CircuitName::LbfvPkGeneration => CircuitInputLayout::Fixed {
                fields: LBFV_PK_GENERATION_INPUTS,
            },
            CircuitName::LbfvPkAggregation => CircuitInputLayout::Fixed {
                fields: LBFV_PK_AGGREGATION_INPUTS,
            },
            CircuitName::RlkGeneration => CircuitInputLayout::Fixed {
                fields: RLK_GENERATION_INPUTS,
            },
            CircuitName::RlkGenerationLimb => CircuitInputLayout::Fixed {
                fields: RLK_GENERATION_LIMB_INPUTS,
            },
            CircuitName::RlkAggregation => CircuitInputLayout::Fixed {
                fields: RLK_AGGREGATION_INPUTS,
            },
            CircuitName::ShareEncryption => CircuitInputLayout::Fixed {
                fields: SHARE_ENCRYPTION_INPUTS,
            },
            CircuitName::ThresholdShareDecryption => CircuitInputLayout::Fixed {
                fields: THRESHOLD_SHARE_DECRYPTION_INPUTS,
            },
            _ => CircuitInputLayout::None,
        }
    }
}

impl fmt::Display for CircuitName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.dir_path())
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
    fn circuit_name_discriminants_preserve_durable_order() {
        let expected = [
            (CircuitName::PkBfv, 0),
            (CircuitName::PkGeneration, 1),
            (CircuitName::ShareEncryption, 2),
            (CircuitName::DkgShareDecryption, 3),
            (CircuitName::PkAggregation, 4),
            (CircuitName::ThresholdShareDecryption, 5),
            (CircuitName::DecryptedSharesAggregation, 6),
            (CircuitName::C3Fold, 7),
            (CircuitName::C3FoldKernel, 8),
            (CircuitName::C6Fold, 9),
            (CircuitName::C6FoldKernel, 10),
            (CircuitName::C3abFold, 11),
            (CircuitName::C4abFold, 12),
            (CircuitName::NodeFold, 13),
            (CircuitName::NodesFold, 14),
            (CircuitName::NodesFoldKernel, 15),
            (CircuitName::DkgAggregator, 16),
            (CircuitName::DecryptionAggregator, 17),
            (CircuitName::SkShareComputationChunk, 18),
            (CircuitName::ESmShareComputationChunk, 19),
            (CircuitName::C2ChunkBatch, 20),
            (CircuitName::SkC2ChunkFinalize, 21),
            (CircuitName::ESmC2ChunkFinalize, 22),
            (CircuitName::C2abChunkFold, 23),
            (CircuitName::SkShareComputation, 24),
            (CircuitName::ESmShareComputation, 25),
            (CircuitName::C2abFold, 26),
            (CircuitName::RlkGeneration, 27),
            (CircuitName::RlkAggregation, 28),
            (CircuitName::LbfvPkGeneration, 29),
            (CircuitName::LbfvPkAggregation, 30),
            (CircuitName::RlkGenerationLimb, 31),
        ];

        for (circuit, discriminant) in expected {
            assert_eq!(circuit as u32, discriminant, "{circuit:?}");
        }
    }

    #[test]
    fn circuit_name_legacy_bincode_bytes_decode_to_the_same_variants() {
        let expected = [
            ([2u8, 0, 0, 0], CircuitName::ShareEncryption),
            ([13u8, 0, 0, 0], CircuitName::NodeFold),
            ([16u8, 0, 0, 0], CircuitName::DkgAggregator),
            ([17u8, 0, 0, 0], CircuitName::DecryptionAggregator),
            ([24u8, 0, 0, 0], CircuitName::SkShareComputation),
            ([25u8, 0, 0, 0], CircuitName::ESmShareComputation),
            ([26u8, 0, 0, 0], CircuitName::C2abFold),
            ([27u8, 0, 0, 0], CircuitName::RlkGeneration),
            ([28u8, 0, 0, 0], CircuitName::RlkAggregation),
            ([29u8, 0, 0, 0], CircuitName::LbfvPkGeneration),
            ([30u8, 0, 0, 0], CircuitName::LbfvPkAggregation),
            ([31u8, 0, 0, 0], CircuitName::RlkGenerationLimb),
        ];

        for (bytes, circuit) in expected {
            assert_eq!(
                bincode::deserialize::<CircuitName>(&bytes).unwrap(),
                circuit
            );
        }
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
    fn extract_ct_commitment_from_share_encryption() {
        let mut signals = vec![0u8; 96];
        signals[0..32].copy_from_slice(&[0xAA; 32]);
        signals[32..64].copy_from_slice(&[0xBB; 32]);
        signals[64..96].copy_from_slice(&[0xCC; 32]);
        let proof = make_proof(CircuitName::ShareEncryption, &signals);
        assert_eq!(
            &*proof.extract_output("ct_commitment").unwrap(),
            &[0xCC; 32]
        );
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
        // C3 has 4 public inputs: expected_pk_commitment, expected_message_commitment,
        // party_idx, mod_idx (matches the Noir main and SHARE_ENCRYPTION_INPUTS).
        assert_eq!(layout.field_count(), Some(4));
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
        let mut signals = vec![0u8; 192];
        signals[31] = 3;
        signals[32..64].copy_from_slice(&[0x11; 32]);
        signals[64..96].copy_from_slice(&[0x22; 32]);
        signals[96..128].copy_from_slice(&[0x33; 32]);
        signals[128..160].copy_from_slice(&[0x44; 32]);
        signals[160..192].copy_from_slice(&[0x55; 32]);
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
        assert_eq!(&*proof.extract_output("limb_vk_hash").unwrap(), &[0x55; 32]);
    }

    #[test]
    fn rlk_generation_limb_layout_tracks_selectors_and_commitments() {
        let mut signals = vec![0u8; 256];
        signals[31] = 3;
        signals[63] = 4;
        signals[64..96].copy_from_slice(&[0x11; 32]);
        signals[224..256].copy_from_slice(&[0x66; 32]);
        let proof = make_proof(CircuitName::RlkGenerationLimb, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 3);
        assert_eq!(proof.extract_input("limb_index").unwrap()[31], 4);
        assert_eq!(
            &*proof.extract_output("sk_commitment").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            &*proof.extract_output("d2_limb_commitment").unwrap(),
            &[0x66; 32]
        );
    }

    #[test]
    fn lbfv_pk_generation_layout_tracks_row_and_commitments() {
        let mut signals = vec![0u8; 96];
        signals[31] = 2;
        signals[32..64].copy_from_slice(&[0x11; 32]);
        signals[64..96].copy_from_slice(&[0x22; 32]);
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
    }

    #[test]
    fn rlk_aggregation_layout_tracks_row_and_commitments() {
        let mut signals = vec![0u8; 160];
        signals[31] = 4;
        signals[96..128].copy_from_slice(&[0x55; 32]);
        signals[128..160].copy_from_slice(&[0x66; 32]);
        let proof = make_proof(CircuitName::RlkAggregation, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 4);
        assert_eq!(
            &*proof.extract_output("d0_agg_commitment").unwrap(),
            &[0x55; 32]
        );
        assert_eq!(
            &*proof.extract_output("d2_agg_commitment").unwrap(),
            &[0x66; 32]
        );
    }

    #[test]
    fn lbfv_pk_aggregation_layout_tracks_row_and_tail_commitment() {
        let mut signals = vec![0u8; 128];
        signals[31] = 4;
        signals[96..128].copy_from_slice(&[0x77; 32]);
        let proof = make_proof(CircuitName::LbfvPkAggregation, &signals);

        assert_eq!(proof.extract_input("row_index").unwrap()[31], 4);
        assert_eq!(
            &*proof.extract_output("pk_agg_commitment").unwrap(),
            &[0x77; 32]
        );
        assert_eq!(proof.circuit.input_layout().field_count(), Some(1));
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
