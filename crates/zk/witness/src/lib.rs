// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV witness preparation, commitments, and canonical Noir JSON.

pub mod commitments;
pub mod dkg;
pub mod encoding;
pub mod encryption;
pub mod errors;
mod negacyclic;
pub mod packing;
pub mod threshold;
mod validation;

pub use commitments::*;
pub use commitments::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
    compute_ciphertext_commitment_from_power_basis, compute_commitments, compute_dkg_pk_commitment,
    compute_dkg_pk_commitment_from_public_key_bytes, compute_pk_aggregation_commitment,
    compute_pk_commitment_from_keyshare_bytes, compute_recursive_aggregation_commitment,
    compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
    compute_share_encryption_challenge, compute_share_encryption_commitment_from_message,
    compute_threshold_decryption_share_commitment, compute_threshold_pk_challenge,
    compute_threshold_pk_commitment, compute_threshold_share_decryption_challenge,
    compute_user_data_encryption_challenge_commitment, compute_vk_hash,
};
pub use e3_zk_config::output_layout;
pub use e3_zk_config::output_layout::*;
pub use e3_zk_config::DkgInputType;
pub use encoding::*;
pub use encryption::{encrypt_with_intermediates, EncryptionIntermediates};
pub use errors::WitnessError;
