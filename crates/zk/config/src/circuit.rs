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
    /// Retired sequential C3 fold; C3 runs over Chonk. Kept so stored encodings keep their indices.
    C3Fold,
    /// Retired `c3_fold` kernel. Kept so stored encodings keep their indices.
    C3FoldKernel,
    /// Retired sequential C6 fold; C6 runs over Chonk, and the C6 tree anchor keeps this name's
    /// artifact path. Kept so stored encodings keep their indices.
    C6Fold,
    /// Retired `c6_fold` kernel. Kept so stored encodings keep their indices.
    C6FoldKernel,
    /// Ad-hoc recursive aggregation: C2a + C2b.
    C2abFold,
    /// Ad-hoc: final sk C3 Chonk accumulator + final e_sm C3 Chonk accumulator.
    C3abFold,
    /// Ad-hoc: C4a + C4b.
    C4abFold,
    /// Per-node DKG fold (C0..C4 links).
    NodeFold,
    /// Sequential fold of `H` `node_fold` proofs (non-ZK) before `dkg_aggregator`.
    NodesFold,
    /// First step of a [`CircuitName::NodesFold`] chain: proves the first node proofs and starts the
    /// accumulator (same ABI; it verifies no accumulator).
    NodesFoldKernel,
    /// DKG aggregator (folded `node_fold` via `nodes_fold` + C5).
    DkgAggregator,
    /// Phase-7 decryption aggregator (folded C6 via `c6_fold` + C7).
    DecryptionAggregator,
    /// Chunked C2a: a chunk other than the last (non-ZK, verified by the final C2 circuit).
    SkShareComputationChain,
    /// Chunked C2a: the last chunk.
    SkShareComputationChainLast,
    /// Chunked C2b: a chunk other than the last.
    ESmShareComputationChain,
    /// Chunked C2b: the last chunk.
    ESmShareComputationChainLast,
    /// Chunked C4: CRT limb 0 (non-ZK, verified by the final C4 circuit).
    DkgShareDecryptionLimb0,
    /// Chunked C4: CRT limb 1.
    DkgShareDecryptionLimb1,
    /// Chunked C4: CRT limb 2.
    DkgShareDecryptionLimb2,
    /// C3 Chonk stack app: verifies a batch of C3 proofs and writes their rows.
    C3ChonkApp,
    /// C3 Chonk stack kernel that verifies the app.
    C3ChonkInitKernel,
    /// C3 Chonk stack kernel that verifies the init kernel.
    C3ChonkTailKernel,
    /// C3 Chonk stack kernel that verifies the tail kernel and ends the stack.
    C3ChonkHidingKernel,
    /// Rollup proof of one C3 Chonk stack's Chonk proof.
    C3ChonkTube,
    /// Rollup proof merging a C3 Chonk accumulator or tube with a tube.
    C3ChonkAccumulate,
    /// C6 Chonk stack app: verifies a decryption's `T + 1` C6 proofs and writes their columns.
    C6ChonkApp,
    /// C6 Chonk stack kernel that verifies the app.
    C6ChonkInitKernel,
    /// C6 Chonk stack kernel that verifies the init kernel.
    C6ChonkTailKernel,
    /// C6 Chonk stack kernel that verifies the tail kernel and ends the stack.
    C6ChonkHidingKernel,
    /// Rollup proof of the C6 Chonk stack's Chonk proof.
    C6ChonkTube,
    /// Closes the C6 tube's IPA claim; the decryption aggregator verifies it.
    C6ChonkRoot,
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
            CircuitName::SkShareComputationChain => "sk_share_computation_chain",
            CircuitName::SkShareComputationChainLast => "sk_share_computation_chain_last",
            CircuitName::ESmShareComputationChain => "e_sm_share_computation_chain",
            CircuitName::ESmShareComputationChainLast => "e_sm_share_computation_chain_last",
            CircuitName::DkgShareDecryptionLimb0 => "share_decryption_limb_0",
            CircuitName::DkgShareDecryptionLimb1 => "share_decryption_limb_1",
            CircuitName::DkgShareDecryptionLimb2 => "share_decryption_limb_2",
            CircuitName::C3ChonkApp => "c3_chonk_app",
            CircuitName::C3ChonkInitKernel => "c3_chonk_init_kernel",
            CircuitName::C3ChonkTailKernel => "c3_chonk_tail_kernel",
            CircuitName::C3ChonkHidingKernel => "c3_chonk_hiding_kernel",
            CircuitName::C3ChonkTube => "c3_chonk_tube",
            CircuitName::C3ChonkAccumulate => "c3_chonk_accumulate",
            CircuitName::C6ChonkApp => "c6_chonk_app",
            CircuitName::C6ChonkInitKernel => "c6_chonk_init_kernel",
            CircuitName::C6ChonkTailKernel => "c6_chonk_tail_kernel",
            CircuitName::C6ChonkHidingKernel => "c6_chonk_hiding_kernel",
            CircuitName::C6ChonkTube => "c6_chonk_tube",
            CircuitName::C6ChonkRoot => "c6_chonk_root",
        }
    }

    pub fn group(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "dkg",
            CircuitName::SkShareComputation => "dkg",
            CircuitName::ESmShareComputation => "dkg",
            CircuitName::SkShareComputationChain
            | CircuitName::SkShareComputationChainLast
            | CircuitName::ESmShareComputationChain
            | CircuitName::ESmShareComputationChainLast
            | CircuitName::DkgShareDecryptionLimb0
            | CircuitName::DkgShareDecryptionLimb1
            | CircuitName::DkgShareDecryptionLimb2 => "dkg",
            CircuitName::ShareEncryption => "dkg",
            CircuitName::DkgShareDecryption => "dkg",
            CircuitName::PkGeneration => "threshold",
            CircuitName::ThresholdShareDecryption => "threshold",
            CircuitName::PkAggregation => "threshold",
            CircuitName::DecryptedSharesAggregation => "threshold",
            CircuitName::C3ChonkApp
            | CircuitName::C3ChonkInitKernel
            | CircuitName::C3ChonkTailKernel
            | CircuitName::C3ChonkHidingKernel
            | CircuitName::C6ChonkApp
            | CircuitName::C6ChonkInitKernel
            | CircuitName::C6ChonkTailKernel
            | CircuitName::C6ChonkHidingKernel => "chonk",
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
            | CircuitName::DecryptionAggregator
            | CircuitName::C3ChonkTube
            | CircuitName::C3ChonkAccumulate
            | CircuitName::C6ChonkTube
            | CircuitName::C6ChonkRoot => "recursive_aggregation",
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
            | CircuitName::C6Fold
            | CircuitName::C6FoldKernel
            | CircuitName::C2abFold
            | CircuitName::C3abFold
            | CircuitName::C4abFold
            | CircuitName::NodeFold
            | CircuitName::NodesFold
            | CircuitName::NodesFoldKernel
            | CircuitName::DkgAggregator
            | CircuitName::DecryptionAggregator
            | CircuitName::SkShareComputationChain
            | CircuitName::SkShareComputationChainLast
            | CircuitName::ESmShareComputationChain
            | CircuitName::ESmShareComputationChainLast
            | CircuitName::DkgShareDecryptionLimb0
            | CircuitName::DkgShareDecryptionLimb1
            | CircuitName::DkgShareDecryptionLimb2
            | CircuitName::C3ChonkApp
            | CircuitName::C3ChonkInitKernel
            | CircuitName::C3ChonkTailKernel
            | CircuitName::C3ChonkHidingKernel
            | CircuitName::C3ChonkTube
            | CircuitName::C3ChonkAccumulate
            | CircuitName::C6ChonkApp
            | CircuitName::C6ChonkInitKernel
            | CircuitName::C6ChonkTailKernel
            | CircuitName::C6ChonkHidingKernel
            | CircuitName::C6ChonkTube
            | CircuitName::C6ChonkRoot => CircuitOutputLayout::None,
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
