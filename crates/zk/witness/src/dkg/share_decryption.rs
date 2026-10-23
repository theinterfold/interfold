// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::commitments::compute_share_encryption_commitment_from_message;
use crate::encoding::bigint_2d_to_json_values;
use crate::encoding::poly_coefficients_to_toml_json;
use crate::WitnessError;
use e3_polynomial::Polynomial;
use e3_zk_config::dkg::share_decryption::Configs;
use fhe::bfv::Ciphertext;
use fhe::bfv::Encoding;
use fhe::bfv::SecretKey;
use fhe_traits::FheDecoder;
use fhe_traits::FheDecrypter;
use num_bigint::BigInt;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;

/// Share-decryption circuit: proves correct decryption of H honest parties' ciphertexts under the DKG secret key.

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
    /// Own party's plaintext share row per modulus, shape `[L][N]` (length L, each
    /// inner Vec length N). Spliced into the H-sized list at the `None` slot when
    /// computing commitments and decrypted-share inputs.
    pub own_plaintext_share: Vec<Vec<u64>>,
}

/// Input for the share-decryption circuit: expected commitments and decrypted shares.
///
/// Coefficients are reduced to the ZKP field modulus for serialization. The circuit verifies
/// that decrypted shares match the expected commitments from the share-encryption circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Expected message commitments from share-encryption (CIRCUIT 3) for H honest parties: [party_idx][mod_idx].
    pub expected_commitments: Vec<Vec<BigInt>>, // [H][L]
    /// Decrypted share coefficients per party and modulus: [party_idx][mod_idx][coeff_idx].
    pub decrypted_shares: Vec<Vec<Vec<BigInt>>>, // [H][L][N]
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        data: &ShareDecryptionCircuitData,
    ) -> Result<Self, WitnessError> {
        let threshold_params = &config.threshold_params;
        let threshold_l = threshold_params.moduli().len();

        let mut expected_commitments: Vec<Vec<BigInt>> = Vec::new();
        let mut decrypted_shares: Vec<Vec<Vec<BigInt>>> = Vec::new();

        let msg_bit = config.bits.msg_bit;

        // Validate own-plaintext shape only when an own slot is present: one row per modulus,
        // each with `params.degree()` coefficients.
        let has_own_slot = data.honest_ciphertexts.iter().any(|s| s.is_none());
        if has_own_slot && data.own_plaintext_share.len() != threshold_l {
            return Err(WitnessError::Other(format!(
                "own_plaintext_share has {} moduli but threshold_l is {}",
                data.own_plaintext_share.len(),
                threshold_l
            )));
        }
        if has_own_slot {
            let degree = config.params.degree();
            if let Some((index, row)) = data
                .own_plaintext_share
                .iter()
                .enumerate()
                .find(|(_, row)| row.len() != degree)
            {
                return Err(WitnessError::Other(format!(
                    "own_plaintext_share[{index}] has {} coefficients; expected {degree}",
                    row.len()
                )));
            }
        }

        // Iterate H slots in ascending honest-party order: external slots BFV-decrypt and
        // commit; the own slot uses the supplied plaintext directly.
        for slot in data.honest_ciphertexts.iter() {
            let mut party_commitments = Vec::with_capacity(threshold_l);
            let mut party_shares = Vec::with_capacity(threshold_l);

            if let Some(party_cts) = slot {
                if party_cts.len() < threshold_l {
                    return Err(WitnessError::Other(format!(
                        "honest_ciphertexts party has {} ciphertexts but threshold_l is {}; \
                         each party must have at least threshold_l ciphertexts",
                        party_cts.len(),
                        threshold_l
                    )));
                }
            }
            for mod_idx in 0..threshold_l {
                let share_coeffs: Cow<'_, [u64]> = match slot {
                    Some(party_cts) => {
                        let ct = &party_cts[mod_idx];
                        let decrypted_pt = data.secret_key.try_decrypt(ct).map_err(|e| {
                            WitnessError::Other(format!(
                                "failed to decrypt honest ciphertext at modulus {}: {:?}",
                                mod_idx, e
                            ))
                        })?;
                        Cow::Owned(Vec::<u64>::try_decode(&decrypted_pt, Encoding::poly())?)
                    }
                    None => Cow::Borrowed(&data.own_plaintext_share[mod_idx]),
                };
                // Reverse to match C3's commitment convention; keep native shares ascending.
                let reversed = Polynomial::new(
                    share_coeffs
                        .iter()
                        .rev()
                        .copied()
                        .map(BigInt::from)
                        .collect(),
                );
                party_commitments.push(compute_share_encryption_commitment_from_message(
                    &reversed, msg_bit,
                ));
                party_shares.push(share_coeffs.iter().copied().map(BigInt::from).collect());
            }

            expected_commitments.push(party_commitments);
            decrypted_shares.push(party_shares);
        }

        Ok(Inputs {
            expected_commitments,
            decrypted_shares,
        })
    }

    // Used as input for Nargo execution.
    /// Serializes input so that `decrypted_shares` matches Noir's `[[Polynomial<N>; L]; H]`:
    /// each polynomial is `{ "coefficients": [number|string, ...] }` (numbers when fit in i64).
    pub fn to_json(&self) -> serde_json::Value {
        let decrypted_shares: Vec<Vec<serde_json::Value>> = self
            .decrypted_shares
            .iter()
            .map(|party_shares| {
                party_shares
                    .iter()
                    .map(|share| poly_coefficients_to_toml_json(share))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "expected_commitments": bigint_2d_to_json_values(&self.expected_commitments),
            "decrypted_shares": decrypted_shares,
        })
    }
}
