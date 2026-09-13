// SPDX-License-Identifier: LGPL-3.0-only

use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::{
    CircuitInputLayout, CircuitOutputLayout, DKG_SHARE_DECRYPTION_OUTPUTS, PK_AGGREGATION_OUTPUTS,
    PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS, SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS,
    THRESHOLD_SHARE_DECRYPTION_INPUTS, THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitName {
    /// BFV public key proof (C0).
    PkBfv,
    /// TrBFV public key share proof (C1).
    PkGeneration,
    /// Sk share computation inner proof (C2a, recursive).
    SkShareComputation,
    /// E_SM share computation inner proof (C2b, recursive).
    ESmShareComputation,
    /// Share encryption proof (C3).
    ShareEncryption,
    /// DKG share decryption proof (C4).
    DkgShareDecryption,
    /// Public key aggregation proof (C5).
    PkAggregation,
    /// Decryption share proof (C6).
    ThresholdShareDecryption,
    /// Decrypted shares aggregation proof (C7).
    DecryptedSharesAggregation,
    /// Sequential C3 fold: inner ZK + optional prior `c3_fold` non-ZK proof.
    C3Fold,
    /// Bootstrap circuit for [`CircuitName::C3Fold`] genesis accumulator proof (same ABI, no acc verify).
    C3FoldKernel,
    /// I5 PoC (not shipped): batched non-recursive c3 fold, 1 leaf verified over the kernel genesis.
    C3FoldBatchN2,
    /// I5 PoC (not shipped): batched non-recursive c3 fold, 2 leaves verified over the kernel genesis.
    C3FoldBatchN3,
    /// I5 PoC (not shipped): batched non-recursive c3 fold, 3 leaves verified over the kernel genesis.
    C3FoldBatchN4,
    /// I5 r9 (not shipped): production-fit batched non-recursive c3 fold, 2 leaves,
    /// same public ABI as `c3_fold` (4-field prefix + 3*C3_SLOTS), runtime slots.
    C3FoldBatchB2,
    /// I5 r9 (not shipped): production-fit batched non-recursive c3 fold, 3 leaves.
    C3FoldBatchB3,
    /// I5 r51 (not shipped): production-fit batched non-recursive c3 fold, 6 leaves
    /// (N=19 tree-split sub-gate; requires C3_SLOTS >= 7, e.g. micro committee).
    C3FoldBatchB6,
    /// I5 r51 (not shipped): production-fit batched non-recursive c3 fold, 10 leaves
    /// (N=19 tree-split sub-gate; requires C3_SLOTS >= 11, e.g. micro committee).
    C3FoldBatchB10,
    /// I5a r53 (not shipped): MERGE tier M1 — anchor + 1 b6 sub-gate verify
    /// (in-circuit verifies the b6 sub-gate's non-ZK proof; emits c3_fold's exact
    /// 4+3*C3_SLOTS public ABI over the combined slot array).
    C3FoldBatchMergeM1,
    /// I5a r55 (not shipped): PRODUCTION-SHAPE MERGE tier M7 — anchor + 7 in-circuit
    /// sub-gate verifies (5 x B10 + 2 x B2 = 54 leaves = (N-1)*L at N=19, secure-8192/small)
    /// + slot-fold into the combined 3 x C3_SLOTS state (C3_SLOTS = N_PARTIES * L_THRESHOLD);
    /// emits c3_fold's exact 4+3*C3_SLOTS public ABI (c3ab_fold / node_fold VK-rebuild-only).
    C3FoldBatchMergeM7,
    /// I5a r61 (not shipped): PRODUCTION-SCHEDULE MERGE tier M7x — anchor (slot0, parameterized)
    /// + 6 in-circuit sub-gate verifies (5 x B10 + 1 x B3 = 53 covered slots, a public
    /// slot-index array) + membership slot-fold of the combined 3 x C3_SLOTS state; covers the
    /// production C3b geometry (N=19, L=3, C3_SLOTS = 57, per-node scheduled slots W_P =
    /// {0..57}\{3P, 3P+1, 3P+2}); emits c3_fold's exact 4+3*C3_SLOTS public ABI
    /// (c3ab_fold / node_fold VK-rebuild-only).
    C3FoldBatchMergeM7x,
    /// Sequential C6 fold: inner ZK + prior `c6_fold` non-ZK proof (phase-7 aggregator).
    C6Fold,
    /// Bootstrap circuit for [`CircuitName::C6Fold`] genesis accumulator proof (same ABI, no acc verify).
    C6FoldKernel,
    /// Ad-hoc recursive aggregation: C2a + C2b.
    C2abFold,
    /// Ad-hoc: final sk `c3_fold` + final e_sm `c3_fold`.
    C3abFold,
    /// Ad-hoc: C4a + C4b.
    C4abFold,
    /// Per-node DKG fold (C0..C4 links).
    NodeFold,
    /// Sequential fold of `H` `node_fold` proofs (non-ZK) before `dkg_aggregator`.
    NodesFold,
    /// Bootstrap circuit for [`CircuitName::NodesFold`] genesis accumulator proof (same ABI, no acc verify).
    NodesFoldKernel,
    /// DKG aggregator (folded `node_fold` via `nodes_fold` + C5).
    DkgAggregator,
    /// Phase-7 decryption aggregator (folded C6 via `c6_fold` + C7).
    DecryptionAggregator,
}

impl CircuitName {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "pk",
            CircuitName::PkGeneration => "pk_generation",
            CircuitName::SkShareComputation => "sk_share_computation",
            CircuitName::ESmShareComputation => "e_sm_share_computation",
            CircuitName::ShareEncryption => "share_encryption",
            CircuitName::DkgShareDecryption => "share_decryption",
            CircuitName::PkAggregation => "pk_aggregation",
            CircuitName::ThresholdShareDecryption => "share_decryption",
            CircuitName::DecryptedSharesAggregation => "decrypted_shares_aggregation",
            CircuitName::C3Fold => "c3_fold",
            CircuitName::C3FoldKernel => "c3_fold_kernel",
            CircuitName::C3FoldBatchN2 => "c3_fold_batch_n2",
            CircuitName::C3FoldBatchN3 => "c3_fold_batch_n3",
            CircuitName::C3FoldBatchN4 => "c3_fold_batch_n4",
            CircuitName::C3FoldBatchB2 => "c3_fold_batch_b2",
            CircuitName::C3FoldBatchB3 => "c3_fold_batch_b3",
            CircuitName::C3FoldBatchB6 => "c3_fold_batch_b6",
            CircuitName::C3FoldBatchB10 => "c3_fold_batch_b10",
            CircuitName::C3FoldBatchMergeM1 => "c3_fold_batch_merge_m1",
            CircuitName::C3FoldBatchMergeM7 => "c3_fold_batch_merge_m7",
            CircuitName::C3FoldBatchMergeM7x => "c3_fold_batch_merge_m7x",
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
        }
    }

    pub fn group(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "dkg",
            CircuitName::SkShareComputation => "dkg",
            CircuitName::ESmShareComputation => "dkg",
            CircuitName::ShareEncryption => "dkg",
            CircuitName::DkgShareDecryption => "dkg",
            CircuitName::PkGeneration => "threshold",
            CircuitName::ThresholdShareDecryption => "threshold",
            CircuitName::PkAggregation => "threshold",
            CircuitName::DecryptedSharesAggregation => "threshold",
            CircuitName::C3Fold
            | CircuitName::C3FoldKernel
            | CircuitName::C6Fold
            | CircuitName::C6FoldKernel
            | CircuitName::C2abFold
            | CircuitName::C3abFold
            | CircuitName::C4abFold
            | CircuitName::NodeFold
            | CircuitName::NodesFold
            | CircuitName::NodesFoldKernel
            | CircuitName::DkgAggregator
            | CircuitName::C3FoldBatchN2
            | CircuitName::C3FoldBatchN3
            | CircuitName::C3FoldBatchN4
            | CircuitName::C3FoldBatchB2
            | CircuitName::C3FoldBatchB3
            | CircuitName::C3FoldBatchB6
            | CircuitName::C3FoldBatchB10
            | CircuitName::C3FoldBatchMergeM1
            | CircuitName::C3FoldBatchMergeM7
            | CircuitName::C3FoldBatchMergeM7x
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
            CircuitName::SkShareComputation | CircuitName::ESmShareComputation => {
                CircuitOutputLayout::Dynamic
            }
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
            | CircuitName::C3FoldBatchN2
            | CircuitName::C3FoldBatchN3
            | CircuitName::C3FoldBatchN4
            | CircuitName::C3FoldBatchB2
            | CircuitName::C3FoldBatchB3
            | CircuitName::C3FoldBatchB6
            | CircuitName::C3FoldBatchB10
            | CircuitName::C3FoldBatchMergeM1
            | CircuitName::C3FoldBatchMergeM7
            | CircuitName::C3FoldBatchMergeM7x
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

    /// Public input layout for C3 and C6 circuits (fields at the start of public_signals).
    pub fn input_layout(&self) -> CircuitInputLayout {
        match self {
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
