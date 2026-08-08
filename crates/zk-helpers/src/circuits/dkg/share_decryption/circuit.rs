// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit definition and input type for the share-decryption ZK circuit (CIRCUIT 4a/4b).

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use crate::CiphernodesCommittee;
use e3_fhe_params::ParameterType;
use fhe::bfv::Ciphertext;
use fhe::bfv::SecretKey;

/// Share-decryption circuit: proves correct decryption of H honest parties' ciphertexts under the DKG secret key.
#[derive(Debug)]
pub struct ShareDecryptionCircuit;

impl Circuit for ShareDecryptionCircuit {
    const NAME: &'static str = "share-decryption";
    const PREFIX: &'static str = "SHARE_DECRYPTION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::DKG;
    /// None: circuit accepts runtime-varying input type (SecretKey or SmudgingNoise).
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Data for the share-decryption circuit: secret key, ciphertexts from external honest
/// parties, and the own party's plaintext share row.
pub struct ShareDecryptionCircuitData {
    /// DKG secret key used to decrypt external ciphertexts (private input).
    pub secret_key: SecretKey,
    /// Per-honest-party ciphertexts, length H, indexed by ascending honest party_id.
    /// `None` means that slot is the own party (no ciphertext was produced because the
    /// party does not self-encrypt during DKG); `Some(cts)` carries one ciphertext per
    /// CRT modulus for an external honest party.
    pub honest_ciphertexts: Vec<Option<Vec<Ciphertext>>>,
    /// Recipient party ID whose share row is decrypted.
    pub recipient_party_id: u64,
    /// Own party's plaintext share row per modulus, shape `[L][N]` (length L, each
    /// inner Vec length N). Spliced into the H-sized list at the `None` slot when
    /// computing commitments and decrypted-share inputs.
    pub own_plaintext_share: Vec<Vec<u64>>,
    /// Which input type (SecretKey or SmudgingNoise) to resolve circuit path.
    pub dkg_input_type: DkgInputType,
    /// Share-root chunk size (must equal `SHARE_COMPUTATION_CHUNK_SIZE` in Noir).
    pub chunk_size: u32,
    /// Committee this data was generated for (validated against the canonical table).
    pub committee: CiphernodesCommittee,
}
