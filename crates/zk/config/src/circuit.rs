// SPDX-License-Identifier: LGPL-3.0-only

//! Static circuit identity, prover variants, and public-signal layout selection.

use crate::output_layout::{
    CircuitInputLayout, CircuitOutputLayout, DKG_SHARE_DECRYPTION_CHUNKED_OUTPUTS,
    DKG_SHARE_DECRYPTION_OUTPUTS, LBFV_PK_AGGREGATION_INPUTS, LBFV_PK_AGGREGATION_OUTPUTS,
    LBFV_PK_GENERATION_INPUTS, LBFV_PK_GENERATION_LIMB_INPUTS, LBFV_PK_GENERATION_LIMB_OUTPUTS,
    LBFV_PK_GENERATION_OUTPUTS, PK_AGGREGATION_OUTPUTS, PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS,
    RLK_AGGREGATION_INPUTS, RLK_AGGREGATION_OUTPUTS, RLK_GENERATION_INPUTS,
    RLK_GENERATION_LIMB_INPUTS, RLK_GENERATION_LIMB_OUTPUTS, RLK_GENERATION_OUTPUTS,
    SHARE_ENCRYPTION_CHUNKED_INPUTS, SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS,
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
    /// Retired sequential C3 fold; C3 runs over Chonk. Kept so stored encodings keep their indices.
    C3Fold = 9,
    /// Retired `c3_fold` kernel. Kept so stored encodings keep their indices.
    C3FoldKernel = 10,
    /// Retired sequential C6 fold; C6 runs over Chonk, and the C6 tree anchor keeps this name's
    /// artifact path. Kept so stored encodings keep their indices.
    C6Fold = 11,
    /// Retired `c6_fold` kernel. Kept so stored encodings keep their indices.
    C6FoldKernel = 12,
    /// Ad-hoc recursive aggregation: C2a + C2b.
    C2abFold = 13,
    /// Ad-hoc: final sk C3 Chonk accumulator + final e_sm C3 Chonk accumulator.
    C3abFold = 14,
    /// Ad-hoc: C4a + C4b.
    C4abFold = 15,
    /// Per-node DKG fold (C0..C4 links).
    NodeFold = 16,
    /// Sequential fold of `H` `node_fold` proofs (non-ZK) before `dkg_aggregator`.
    NodesFold = 17,
    /// First step of a [`CircuitName::NodesFold`] chain: proves the first node proofs and starts the
    /// accumulator (same ABI; it verifies no accumulator).
    NodesFoldKernel = 18,
    /// DKG aggregator (folded `node_fold` via `nodes_fold` + C5).
    DkgAggregator = 19,
    /// Phase-7 decryption aggregator (folded C6 via `c6_fold` + C7).
    DecryptionAggregator = 20,
    /// Chunked C2a: a chunk other than the last (non-ZK, verified by the final C2 circuit).
    SkShareComputationChain = 21,
    /// Chunked C2a: the last chunk.
    SkShareComputationChainLast = 22,
    /// Chunked C2b: a chunk other than the last.
    ESmShareComputationChain = 23,
    /// Chunked C2b: the last chunk.
    ESmShareComputationChainLast = 24,
    /// Chunked C4: CRT limb 0 (non-ZK, verified by the final C4 circuit).
    DkgShareDecryptionLimb0 = 25,
    /// Chunked C4: CRT limb 1.
    DkgShareDecryptionLimb1 = 26,
    /// Chunked C4: CRT limb 2.
    DkgShareDecryptionLimb2 = 27,
    /// C3 Chonk stack app: verifies a batch of C3 proofs and writes their rows.
    C3ChonkApp = 28,
    /// C3 Chonk stack kernel that verifies the app.
    C3ChonkInitKernel = 29,
    /// C3 Chonk stack kernel that verifies the init kernel.
    C3ChonkTailKernel = 30,
    /// C3 Chonk stack kernel that verifies the tail kernel and ends the stack.
    C3ChonkHidingKernel = 31,
    /// Rollup proof of one C3 Chonk stack's Chonk proof.
    C3ChonkTube = 32,
    /// Rollup proof merging a C3 Chonk accumulator or tube with a tube.
    C3ChonkAccumulate = 33,
    /// C6 Chonk stack app: verifies a decryption's `T + 1` C6 proofs and writes their columns.
    C6ChonkApp = 34,
    /// C6 Chonk stack kernel that verifies the app.
    C6ChonkInitKernel = 35,
    /// C6 Chonk stack kernel that verifies the init kernel.
    C6ChonkTailKernel = 36,
    /// C6 Chonk stack kernel that verifies the tail kernel and ends the stack.
    C6ChonkHidingKernel = 37,
    /// Rollup proof of the C6 Chonk stack's Chonk proof.
    C6ChonkTube = 38,
    /// Closes the C6 tube's IPA claim; the decryption aggregator verifies it.
    C6ChonkRoot = 39,
    /// SK coefficient-range proof used by the root-committed chunk pipeline.
    SkShareComputationChunk = 40,
    /// ESM coefficient-range proof used by the root-committed chunk pipeline.
    ESmShareComputationChunk = 41,
    /// Recursive batch of C2 chunk proofs.
    C2ChunkBatch = 42,
    /// Type-bound SK terminal projection from a complete C2 chunk accumulator.
    SkC2ChunkFinalize = 43,
    /// Type-bound ESM terminal projection from a complete C2 chunk accumulator.
    ESmC2ChunkFinalize = 44,
    /// Combines type-bound terminal C2a and C2b chunk proofs.
    C2abChunkFold = 45,
    /// Row-level l-BFV relinearization-key generation proof.
    RlkGeneration = 46,
    /// Row-level l-BFV relinearization-key aggregation proof.
    RlkAggregation = 47,
    /// Row-level l-BFV public-key generation proof.
    LbfvPkGeneration = 48,
    /// Row-level threshold l-BFV public-key aggregation proof.
    LbfvPkAggregation = 49,
    /// Retired: the l-BFV relinearization-key row is proved directly by `RlkGeneration`; kept so
    /// later variants keep their encoding.
    RlkGenerationLimb = 50,
    /// Secure-16384 fold of the five l-BFV generation rows.
    LbfvGenerationFold = 51,
    /// Genesis accumulator for [`CircuitName::LbfvGenerationFold`].
    LbfvGenerationFoldKernel = 52,
    /// Secure-16384 per-node fold with l-BFV generation commitments.
    NodeFoldV2 = 53,
    /// Secure-16384 cross-node fold with l-BFV generation commitments.
    NodesFoldV2 = 54,
    /// Genesis accumulator for [`CircuitName::NodesFoldV2`].
    NodesFoldV2Kernel = 55,
    /// Secure-16384 fold of the five l-BFV aggregation rows.
    LbfvAggregationFold = 56,
    /// Genesis accumulator for [`CircuitName::LbfvAggregationFold`].
    LbfvAggregationFoldKernel = 57,
    /// Secure-16384 DKG aggregator with l-BFV commitments.
    DkgAggregatorV2 = 58,
    /// Retired: the l-BFV public-key row is proved directly by `LbfvPkGeneration`; kept so later
    /// variants keep their encoding.
    LbfvPkGenerationLimb = 59,
    /// Retired: the l-BFV path proves no C1; the row proofs bind `sk` and the C2b chunk leaves
    /// bound `e_sm`. Kept so later variants keep their encoding.
    PkGenerationChunked = 60,
    /// C3 on the l-BFV path: commits the share as a chunk root keyed by party and modulus.
    ShareEncryptionChunked = 61,
    /// C4 on the l-BFV path: opens the decrypted shares against chunk-root commitments.
    DkgShareDecryptionChunked = 62,
    /// Retired sequential C3 fold over [`CircuitName::ShareEncryptionChunked`] proofs; the l-BFV
    /// path proves C3 over Chonk. Kept so stored encodings keep their indices.
    C3FoldChunked = 63,
    /// Retired `c3_fold_chunked` kernel. Kept so stored encodings keep their indices.
    C3FoldKernelChunked = 64,
    /// [`CircuitName::C3abFold`] over the l-BFV C3 Chonk accumulators, with the VK manifest that
    /// `dkg_aggregator_v2` binds.
    C3abFoldChunked = 65,
    /// Per-node DKG fold of the l-BFV path's C0..C4 proofs.
    NodeFoldChunked = 66,
    /// C7 for the l-BFV path, whose ciphertext modulus is wider than the bounded C7 supports.
    DecryptedSharesAggregationWide = 67,
    /// C4ab fold on the l-BFV path: its chunked C4 proofs expose no limb-key tree.
    C4abFoldChunked = 68,
    /// [`CircuitName::C3ChonkApp`] over [`CircuitName::ShareEncryptionChunked`] proofs, each bound
    /// to its slot's party and modulus.
    C3ChonkAppChunked = 69,
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
            CircuitName::C4abFoldChunked => "c4ab_fold_chunked",
            CircuitName::C3ChonkAppChunked => "c3_chonk_app_chunked",
        }
    }

    pub fn group(&self) -> &'static str {
        match self {
            CircuitName::PkBfv => "dkg",
            CircuitName::SkShareComputation
            | CircuitName::ESmShareComputation
            | CircuitName::SkShareComputationChunk
            | CircuitName::ESmShareComputationChunk
            | CircuitName::SkShareComputationChain
            | CircuitName::SkShareComputationChainLast
            | CircuitName::ESmShareComputationChain
            | CircuitName::ESmShareComputationChainLast
            | CircuitName::ShareEncryption
            | CircuitName::ShareEncryptionChunked
            | CircuitName::DkgShareDecryption
            | CircuitName::DkgShareDecryptionLimb0
            | CircuitName::DkgShareDecryptionLimb1
            | CircuitName::DkgShareDecryptionLimb2
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
            CircuitName::C3ChonkApp
            | CircuitName::C3ChonkAppChunked
            | CircuitName::C3ChonkInitKernel
            | CircuitName::C3ChonkTailKernel
            | CircuitName::C3ChonkHidingKernel
            | CircuitName::C6ChonkApp
            | CircuitName::C6ChonkInitKernel
            | CircuitName::C6ChonkTailKernel
            | CircuitName::C6ChonkHidingKernel => "chonk",
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
            | CircuitName::C3ChonkTube
            | CircuitName::C3ChonkAccumulate
            | CircuitName::C6ChonkTube
            | CircuitName::C6ChonkRoot
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
            | CircuitName::NodeFoldChunked
            | CircuitName::C4abFoldChunked => "recursive_aggregation",
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
            CircuitName::DkgShareDecryption => CircuitOutputLayout::Fixed {
                fields: DKG_SHARE_DECRYPTION_OUTPUTS,
            },
            CircuitName::DkgShareDecryptionChunked => CircuitOutputLayout::Fixed {
                fields: DKG_SHARE_DECRYPTION_CHUNKED_OUTPUTS,
            },
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
            | CircuitName::NodeFoldChunked
            | CircuitName::C4abFoldChunked
            | CircuitName::SkShareComputationChain
            | CircuitName::SkShareComputationChainLast
            | CircuitName::ESmShareComputationChain
            | CircuitName::ESmShareComputationChainLast
            | CircuitName::DkgShareDecryptionLimb0
            | CircuitName::DkgShareDecryptionLimb1
            | CircuitName::DkgShareDecryptionLimb2
            | CircuitName::C3ChonkApp
            | CircuitName::C3ChonkAppChunked
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
