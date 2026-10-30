// SPDX-License-Identifier: LGPL-3.0-only

//! Static circuit identity, prover variants, and public-signal layout selection.

use crate::{
    CircuitInputLayout, CircuitOutputLayout, DKG_SHARE_DECRYPTION_OUTPUTS, PK_AGGREGATION_OUTPUTS,
    PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS, SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS,
    THRESHOLD_SHARE_DECRYPTION_INPUTS, THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
};
use serde::{Deserialize, Serialize};
use std::fmt;

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
            | CircuitName::DecryptionAggregator => "recursive_aggregation",
        }
    }

    pub fn dir_path(&self) -> String {
        format!("{}/{}", self.group(), self.as_str())
    }

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
