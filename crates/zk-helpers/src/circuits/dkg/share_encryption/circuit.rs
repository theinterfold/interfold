// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit definition and input type for the share-encryption ZK circuit (CIRCUIT 3a/3b).

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use crate::CiphernodesCommittee;
use e3_fhe_params::ParameterType;
use fhe::bfv::Ciphertext;
use fhe::bfv::Plaintext;
use fhe::bfv::PublicKey;
use fhe::bfv::SecretKey;
use fhe_math::rq::{Ntt, Poly};

/// Share-encryption circuit: proves correct encryption of a (secret or smudging) share under the DKG public key.
#[derive(Debug)]
pub struct ShareEncryptionCircuit;

impl Circuit for ShareEncryptionCircuit {
    const NAME: &'static str = "share-encryption";
    const PREFIX: &'static str = "SHARE_ENCRYPTION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::DKG;
    /// None: circuit accepts runtime-varying input type (SecretKey or SmudgingNoise).
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Input to the share-encryption circuit: plaintext, ciphertext, keys, and encryption randomness.
pub struct ShareEncryptionCircuitData {
    /// Plaintext (encoded share row).
    pub plaintext: Plaintext,
    /// Ciphertext (encryption under public_key).
    pub ciphertext: Ciphertext,
    /// DKG public key used to encrypt.
    pub public_key: PublicKey,
    /// Secret key (for input; not revealed in proof).
    pub secret_key: SecretKey,
    /// Encryption randomness u in RNS form (from try_encrypt_extended).
    pub u_rns: Poly<Ntt>,
    /// Encryption error e0 in RNS form.
    pub e0_rns: Poly<Ntt>,
    /// Encryption error e1 in RNS form.
    pub e1_rns: Poly<Ntt>,
    /// Type of DKG input (SecretKey or SmudgingNoise) to determine which circuit variant to use.
    pub dkg_input_type: DkgInputType,
    /// Zero-based recipient party index used in the share-root commitment.
    pub party_idx: u32,
    /// Zero-based CRT modulus index used in the share-root commitment.
    pub mod_idx: u32,
    /// Share-root chunk size (must equal `SHARE_COMPUTATION_CHUNK_SIZE` in Noir).
    pub chunk_size: u32,
    /// Committee this data was generated for (validated against the canonical table).
    pub committee: CiphernodesCommittee,
}
