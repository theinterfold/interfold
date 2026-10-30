// SPDX-License-Identifier: LGPL-3.0-only

//! Static circuit identity, prover variants, and public-signal layout selection.

use crate::output_layout::{
    CircuitInputLayout, CircuitOutputLayout, DKG_SHARE_DECRYPTION_OUTPUTS,
    LBFV_PK_AGGREGATION_INPUTS, LBFV_PK_AGGREGATION_OUTPUTS, LBFV_PK_GENERATION_INPUTS,
    LBFV_PK_GENERATION_LIMB_INPUTS, LBFV_PK_GENERATION_LIMB_OUTPUTS, LBFV_PK_GENERATION_OUTPUTS,
    PK_AGGREGATION_OUTPUTS, PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS, RLK_AGGREGATION_INPUTS,
    RLK_AGGREGATION_OUTPUTS, RLK_GENERATION_INPUTS, RLK_GENERATION_LIMB_INPUTS,
    RLK_GENERATION_LIMB_OUTPUTS, RLK_GENERATION_OUTPUTS, SHARE_ENCRYPTION_CHUNKED_INPUTS,
    SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS, THRESHOLD_SHARE_DECRYPTION_INPUTS,
    THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
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
///
/// Bincode encodes this enum by variant order. Do not reorder variants.
/// Add new circuits at the end. Keep retired circuits for compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitName {
    /// BFV public key proof (C0).
    PkBfv = 0,
    /// TrBFV public key share proof (C1).
    PkGeneration = 1,
    /// Single-proof SK share computation (C2a) on the trBFV path.
    SkShareComputation = 2,
    /// Single-proof ESM share computation (C2b) on the trBFV path.
    ESmShareComputation = 3,
    /// Share encryption proof (C3).
    ShareEncryption = 4,
    /// DKG share decryption proof (C4).
    DkgShareDecryption = 5,
    /// Public key aggregation proof (C5).
    PkAggregation = 6,
    /// Decryption share proof (C6).
    ThresholdShareDecryption = 7,
    /// Decrypted shares aggregation proof (C7).
    DecryptedSharesAggregation = 8,
    /// Sequential C3 fold: inner ZK + optional prior `c3_fold` non-ZK proof.
    C3Fold = 9,
    /// Bootstrap circuit for [`CircuitName::C3Fold`] genesis accumulator proof (same ABI, no acc verify).
    C3FoldKernel = 10,
    /// Sequential C6 fold: inner ZK + prior `c6_fold` non-ZK proof (phase-7 aggregator).
    C6Fold = 11,
    /// Bootstrap circuit for [`CircuitName::C6Fold`] genesis accumulator proof (same ABI, no acc verify).
    C6FoldKernel = 12,
    /// Ad-hoc: C2a + C2b single proofs on the trBFV path.
    C2abFold = 13,
    /// Ad-hoc: final sk `c3_fold` + final e_sm `c3_fold`.
    C3abFold = 14,
    /// Ad-hoc: C4a + C4b.
    C4abFold = 15,
    /// Per-node DKG fold (C0..C4 links).
    NodeFold = 16,
    /// Sequential fold of `H` `node_fold` proofs (non-ZK) before `dkg_aggregator`.
    NodesFold = 17,
    /// Bootstrap circuit for [`CircuitName::NodesFold`] genesis accumulator proof (same ABI, no acc verify).
    NodesFoldKernel = 18,
    /// DKG aggregator (folded `node_fold` via `nodes_fold` + C5).
    DkgAggregator = 19,
    /// Phase-7 decryption aggregator (folded C6 via `c6_fold` + C7).
    DecryptionAggregator = 20,
    /// SK coefficient-range proof used by the root-committed chunk pipeline.
    SkShareComputationChunk = 21,
    /// ESM coefficient-range proof used by the root-committed chunk pipeline.
    ESmShareComputationChunk = 22,
    /// Recursive batch of C2 chunk proofs.
    C2ChunkBatch = 23,
    /// Type-bound SK terminal projection from a complete C2 chunk accumulator.
    SkC2ChunkFinalize = 24,
    /// Type-bound ESM terminal projection from a complete C2 chunk accumulator.
    ESmC2ChunkFinalize = 25,
    /// Combines type-bound terminal C2a and C2b chunk proofs.
    C2abChunkFold = 26,
    /// Row-level l-BFV relinearization-key generation proof.
    RlkGeneration = 27,
    /// Row-level l-BFV relinearization-key aggregation proof.
    RlkAggregation = 28,
    /// Row-level l-BFV public-key generation proof.
    LbfvPkGeneration = 29,
    /// Row-level threshold l-BFV public-key aggregation proof.
    LbfvPkAggregation = 30,
    /// Retired: the l-BFV relinearization-key row is proved directly by `RlkGeneration`; kept so
    /// later variants keep their encoding.
    RlkGenerationLimb = 31,
    /// Secure-16384 fold of the five l-BFV generation rows.
    LbfvGenerationFold = 32,
    /// Genesis accumulator for [`CircuitName::LbfvGenerationFold`].
    LbfvGenerationFoldKernel = 33,
    /// Secure-16384 per-node fold with l-BFV generation commitments.
    NodeFoldV2 = 34,
    /// Secure-16384 cross-node fold with l-BFV generation commitments.
    NodesFoldV2 = 35,
    /// Genesis accumulator for [`CircuitName::NodesFoldV2`].
    NodesFoldV2Kernel = 36,
    /// Secure-16384 fold of the five l-BFV aggregation rows.
    LbfvAggregationFold = 37,
    /// Genesis accumulator for [`CircuitName::LbfvAggregationFold`].
    LbfvAggregationFoldKernel = 38,
    /// Secure-16384 DKG aggregator with l-BFV commitments.
    DkgAggregatorV2 = 39,
    /// Retired: the l-BFV public-key row is proved directly by `LbfvPkGeneration`; kept so later
    /// variants keep their encoding.
    LbfvPkGenerationLimb = 40,
    /// Retired: the l-BFV path proves no C1; the row proofs bind `sk` and the C2b chunk leaves
    /// bound `e_sm`. Kept so later variants keep their encoding.
    PkGenerationChunked = 41,
    /// C3 on the l-BFV path: commits the share as a chunk root keyed by party and modulus.
    ShareEncryptionChunked = 42,
    /// C4 on the l-BFV path: opens the decrypted shares against chunk-root commitments.
    DkgShareDecryptionChunked = 43,
    /// [`CircuitName::C3Fold`] over [`CircuitName::ShareEncryptionChunked`] proofs.
    C3FoldChunked = 44,
    /// Genesis accumulator for [`CircuitName::C3FoldChunked`].
    C3FoldKernelChunked = 45,
    /// [`CircuitName::C3abFold`] over chunked C3 folds.
    C3abFoldChunked = 46,
    /// Per-node DKG fold of the l-BFV path's C0..C4 proofs.
    NodeFoldChunked = 47,
    /// C7 for the l-BFV path, whose ciphertext modulus is wider than the bounded C7 supports.
    DecryptedSharesAggregationWide = 48,
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
            CircuitName::SkShareComputationChunk => "sk_share_computation_chunk",
            CircuitName::ESmShareComputationChunk => "esm_share_computation_chunk",
            CircuitName::C2ChunkBatch => "c2_chunk_batch",
            CircuitName::SkC2ChunkFinalize => "sk_c2_chunk_finalize",
            CircuitName::ESmC2ChunkFinalize => "esm_c2_chunk_finalize",
            CircuitName::C2abChunkFold => "c2ab_chunk_fold",
            CircuitName::RlkGeneration => "rlk_generation",
            CircuitName::RlkAggregation => "rlk_aggregation",
            CircuitName::LbfvPkGeneration => "lbfv_pk_generation",
            CircuitName::LbfvPkAggregation => "lbfv_pk_aggregation",
            CircuitName::RlkGenerationLimb => "rlk_generation_limb",
            CircuitName::LbfvGenerationFold => "lbfv_generation_fold",
            CircuitName::LbfvGenerationFoldKernel => "lbfv_generation_fold_kernel",
            CircuitName::NodeFoldV2 => "node_fold_v2",
            CircuitName::NodesFoldV2 => "nodes_fold_v2",
            CircuitName::NodesFoldV2Kernel => "nodes_fold_v2_kernel",
            CircuitName::LbfvAggregationFold => "lbfv_aggregation_fold",
            CircuitName::LbfvAggregationFoldKernel => "lbfv_aggregation_fold_kernel",
            CircuitName::DkgAggregatorV2 => "dkg_aggregator_v2",
            CircuitName::LbfvPkGenerationLimb => "lbfv_pk_generation_limb",
            CircuitName::PkGenerationChunked => "pk_generation_chunked",
            CircuitName::ShareEncryptionChunked => "share_encryption_chunked",
            CircuitName::DkgShareDecryptionChunked => "share_decryption_chunked",
            CircuitName::C3FoldChunked => "c3_fold_chunked",
            CircuitName::C3FoldKernelChunked => "c3_fold_kernel_chunked",
            CircuitName::C3abFoldChunked => "c3ab_fold_chunked",
            CircuitName::NodeFoldChunked => "node_fold_chunked",
            CircuitName::DecryptedSharesAggregationWide => "decrypted_shares_aggregation_wide",
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
            | CircuitName::ShareEncryptionChunked
            | CircuitName::DkgShareDecryption
            | CircuitName::DkgShareDecryptionChunked => "dkg",
            CircuitName::PkGeneration | CircuitName::PkGenerationChunked => "threshold",
            CircuitName::ThresholdShareDecryption => "threshold",
            CircuitName::PkAggregation => "threshold",
            CircuitName::DecryptedSharesAggregation
            | CircuitName::DecryptedSharesAggregationWide => "threshold",
            CircuitName::RlkGeneration
            | CircuitName::RlkAggregation
            | CircuitName::LbfvPkGeneration
            | CircuitName::LbfvPkGenerationLimb
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
            | CircuitName::DecryptionAggregator
            | CircuitName::LbfvGenerationFold
            | CircuitName::LbfvGenerationFoldKernel
            | CircuitName::NodeFoldV2
            | CircuitName::NodesFoldV2
            | CircuitName::NodesFoldV2Kernel
            | CircuitName::LbfvAggregationFold
            | CircuitName::LbfvAggregationFoldKernel
            | CircuitName::DkgAggregatorV2
            | CircuitName::C3FoldChunked
            | CircuitName::C3FoldKernelChunked
            | CircuitName::C3abFoldChunked
            | CircuitName::NodeFoldChunked => "recursive_aggregation",
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
            CircuitName::PkGeneration | CircuitName::PkGenerationChunked => {
                CircuitOutputLayout::Fixed {
                    fields: PK_GENERATION_OUTPUTS,
                }
            }
            CircuitName::LbfvPkGeneration => CircuitOutputLayout::Fixed {
                fields: LBFV_PK_GENERATION_OUTPUTS,
            },
            CircuitName::LbfvPkGenerationLimb => CircuitOutputLayout::Fixed {
                fields: LBFV_PK_GENERATION_LIMB_OUTPUTS,
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
            CircuitName::SkShareComputation | CircuitName::ESmShareComputation => {
                CircuitOutputLayout::Dynamic
            }
            CircuitName::SkShareComputationChunk | CircuitName::ESmShareComputationChunk => {
                CircuitOutputLayout::None
            }
            CircuitName::DkgShareDecryption | CircuitName::DkgShareDecryptionChunked => {
                CircuitOutputLayout::Fixed {
                    fields: DKG_SHARE_DECRYPTION_OUTPUTS,
                }
            }
            CircuitName::PkAggregation => CircuitOutputLayout::Fixed {
                fields: PK_AGGREGATION_OUTPUTS,
            },
            CircuitName::ThresholdShareDecryption => CircuitOutputLayout::Fixed {
                fields: THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
            },
            CircuitName::ShareEncryption | CircuitName::ShareEncryptionChunked => {
                CircuitOutputLayout::Fixed {
                    fields: SHARE_ENCRYPTION_OUTPUTS,
                }
            }
            CircuitName::DecryptedSharesAggregation
            | CircuitName::DecryptedSharesAggregationWide => CircuitOutputLayout::None,
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
            | CircuitName::DecryptionAggregator
            | CircuitName::LbfvGenerationFold
            | CircuitName::LbfvGenerationFoldKernel
            | CircuitName::NodeFoldV2
            | CircuitName::NodesFoldV2
            | CircuitName::NodesFoldV2Kernel
            | CircuitName::LbfvAggregationFold
            | CircuitName::LbfvAggregationFoldKernel
            | CircuitName::DkgAggregatorV2
            | CircuitName::C3FoldChunked
            | CircuitName::C3FoldKernelChunked
            | CircuitName::C3abFoldChunked
            | CircuitName::NodeFoldChunked => CircuitOutputLayout::None,
        }
    }

    /// Public input layout for circuits with tracked fields at the start of public_signals.
    pub fn input_layout(&self) -> CircuitInputLayout {
        match self {
            CircuitName::LbfvPkGeneration => CircuitInputLayout::Fixed {
                fields: LBFV_PK_GENERATION_INPUTS,
            },
            CircuitName::LbfvPkGenerationLimb => CircuitInputLayout::Fixed {
                fields: LBFV_PK_GENERATION_LIMB_INPUTS,
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
            CircuitName::ShareEncryptionChunked => CircuitInputLayout::Fixed {
                fields: SHARE_ENCRYPTION_CHUNKED_INPUTS,
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
