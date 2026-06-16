// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the share-decryption circuit: configs, bounds, bit widths, and input.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) honest ciphertexts and secret key. Input values are normalized for the ZKP
//! field so the Noir circuit's range checks and commitment checks succeed.
//!
//! Bit widths:
//! - **`msg_bit`** — [`crate::compute_msg_bit`] on the **DKG** BFV params: coefficients in
//!   `[0, t)` so the bound is `t − 1`. Matches C2 share-encryption
//!   `compute_share_encryption_commitment_from_message` on per-share plaintexts. Emitted as
//!   `SHARE_DECRYPTION_BIT_MSG` in codegen.
//! - **`agg_bit`** — [`crate::compute_modulus_bit`] on the **threshold** BFV params: same as C6
//!   aggregate hashing. Emitted as `SHARE_DECRYPTION_BIT_AGG`; the Noir C4 circuit uses it for
//!   `compute_aggregated_shares_commitment` on the sum (per-share verification still uses `BIT_MSG`).

use crate::circuits::commitments::compute_share_encryption_commitment_from_message;
use crate::dkg::share_decryption::ShareDecryptionCircuit;
use crate::dkg::share_decryption::ShareDecryptionCircuitData;
use crate::math::plaintext_poly_u64;
use crate::CircuitsErrors;
use crate::{bigint_2d_to_json_values, poly_coefficients_to_toml_json};
use crate::{compute_modulus_bit, compute_msg_bit};
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::Polynomial;
use fhe_traits::FheDecrypter;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
/// Output of [`CircuitComputation::compute`] for [`ShareDecryptionCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct ShareDecryptionOutput {
    /// Coefficient bounds used to derive bit widths.
    pub bounds: Bounds,
    /// Bit widths used by the Noir prover for packing.
    pub bits: Bits,
    /// Input for the share-decryption circuit.
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`ShareDecryptionCircuit`].
impl CircuitComputation for ShareDecryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Output = ShareDecryptionOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(ShareDecryptionOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

/// Global configs for the share-decryption circuit: degree, number of moduli, honest parties, bits, and bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    /// Polynomial degree (N).
    pub n: usize,
    /// Number of CRT moduli (L).
    pub l: usize,
    /// Number of honest parties (H).
    pub h: usize,
    pub bits: Bits,
    pub bounds: Bounds,
}

/// Bit widths used by the Noir prover and witness recomputation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    /// Per-share message coefficients in `[0, t)`; matches C2 share encryption
    /// (`compute_msg_bit` on DKG params).
    pub msg_bit: u32,
    /// CRT aggregate polynomials (same ring semantics as C6 `sk` / `e_sm`);
    /// matches [`crate::compute_modulus_bit`] on threshold params.
    pub agg_bit: u32,
}

/// Coefficient bounds for the share-decryption circuit (currently empty; bounds are derived from plaintext modulus).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {}

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

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (_, dkg_params) = build_pair_for_preset(preset)
            .map_err(|e| crate::utils::ZkHelpersUtilsError::ParseBound(e.to_string()))?;

        let n = dkg_params.degree();
        let l = dkg_params.moduli().len();
        let h = data.honest_ciphertexts.len();

        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;

        Ok(Configs {
            n,
            l,
            h,
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = crate::utils::ZkHelpersUtilsError;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, dkg_params) = build_pair_for_preset(preset)
            .map_err(|e| crate::utils::ZkHelpersUtilsError::ParseBound(e.to_string()))?;

        Ok(Bits {
            msg_bit: compute_msg_bit(&dkg_params),
            agg_bit: compute_modulus_bit(&threshold_params),
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(_: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        Ok(Bounds {})
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        let threshold_l = threshold_params.moduli().len();

        let mut expected_commitments: Vec<Vec<BigInt>> = Vec::new();
        let mut decrypted_shares: Vec<Vec<Vec<BigInt>>> = Vec::new();

        let msg_bit = compute_msg_bit(&dkg_params);

        // Validate own-plaintext shape against L only when an own slot is present.
        let has_own_slot = data.honest_ciphertexts.iter().any(|s| s.is_none());
        if has_own_slot && data.own_plaintext_share.len() != threshold_l {
            return Err(CircuitsErrors::Other(format!(
                "own_plaintext_share has {} moduli but threshold_l is {}",
                data.own_plaintext_share.len(),
                threshold_l
            )));
        }

        // Iterate H slots in ascending honest-party order: external slots BFV-decrypt and
        // commit; the own slot uses the supplied plaintext directly.
        for slot in data.honest_ciphertexts.iter() {
            let mut party_commitments = Vec::with_capacity(threshold_l);
            let mut party_shares = Vec::with_capacity(threshold_l);

            match slot {
                Some(party_cts) => {
                    if party_cts.len() < threshold_l {
                        return Err(CircuitsErrors::Other(format!(
                            "honest_ciphertexts party has {} ciphertexts but threshold_l is {}; \
                             each party must have at least threshold_l ciphertexts",
                            party_cts.len(),
                            threshold_l
                        )));
                    }
                    for (mod_idx, ct) in party_cts.iter().enumerate().take(threshold_l) {
                        let decrypted_pt = data.secret_key.try_decrypt(ct).map_err(|e| {
                            CircuitsErrors::Other(format!(
                                "failed to decrypt honest ciphertext at modulus {}: {:?}",
                                mod_idx, e
                            ))
                        })?;
                        let share_coeffs = plaintext_poly_u64(&decrypted_pt)?;
                        // Reverse to match C3's reversed commitment convention.
                        let mut reversed_coeffs = share_coeffs.clone();
                        reversed_coeffs.reverse();
                        party_commitments.push(compute_share_encryption_commitment_from_message(
                            &Polynomial::from_u64_vector(reversed_coeffs),
                            msg_bit,
                        ));
                        party_shares.push(
                            share_coeffs
                                .iter()
                                .map(|c| BigInt::from(*c))
                                .collect::<Vec<_>>(),
                        );
                    }
                }
                None => {
                    for mod_idx in 0..threshold_l {
                        let share_coeffs = &data.own_plaintext_share[mod_idx];
                        // Same reverse-then-commit as the BFV-decrypted branch.
                        let mut reversed_coeffs = share_coeffs.clone();
                        reversed_coeffs.reverse();
                        party_commitments.push(compute_share_encryption_commitment_from_message(
                            &Polynomial::from_u64_vector(reversed_coeffs),
                            msg_bit,
                        ));
                        party_shares.push(
                            share_coeffs
                                .iter()
                                .map(|c| BigInt::from(*c))
                                .collect::<Vec<_>>(),
                        );
                    }
                }
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
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let expected_commitments = bigint_2d_to_json_values(&self.expected_commitments);
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

        let json = serde_json::json!({
            "expected_commitments": expected_commitments,
            "decrypted_shares": decrypted_shares,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();

        let (_, dkg_params) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        assert_eq!(bits.msg_bit, compute_msg_bit(&dkg_params));
        assert_eq!(bits.agg_bit, compute_modulus_bit(&threshold_params));
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let constants = Configs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.n, constants.n);
        assert_eq!(decoded.l, constants.l);
        assert_eq!(decoded.h, constants.h);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }

    #[test]
    fn test_input_decryption_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        // Inputs should have one row per honest party
        assert_eq!(
            inputs.expected_commitments.len(),
            sample.honest_ciphertexts.len()
        );
        assert_eq!(
            inputs.decrypted_shares.len(),
            sample.honest_ciphertexts.len()
        );
    }

    /// Verify expected_commitments[i][j] matches direct commitment computation for each
    /// slot, proving row ordering is consistent. External slots use BFV-decryption; the
    /// own slot uses the supplied plaintext.
    #[test]
    fn test_commitment_ordering_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let preset = BfvPreset::InsecureThreshold512;
        let sample =
            ShareDecryptionCircuitData::generate_sample(preset, committee, DkgInputType::SecretKey)
                .unwrap();

        let (threshold_params, dkg_params) = build_pair_for_preset(preset).unwrap();
        let threshold_l = threshold_params.moduli().len();
        let msg_bit = compute_msg_bit(&dkg_params);

        let inputs = Inputs::compute(preset, &sample).unwrap();
        assert_eq!(
            inputs.expected_commitments.len(),
            sample.honest_ciphertexts.len()
        );

        for (party_idx, slot) in sample.honest_ciphertexts.iter().enumerate() {
            for mod_idx in 0..threshold_l {
                let share_coeffs = match slot {
                    Some(party_cts) => {
                        let decrypted_pt =
                            sample.secret_key.try_decrypt(&party_cts[mod_idx]).unwrap();
                        plaintext_poly_u64(&decrypted_pt).unwrap()
                    }
                    None => sample.own_plaintext_share[mod_idx].clone(),
                };
                // Reverse to match Inputs::compute, which reverses before committing to align
                // with C2's commit_to_party_shares (highest-degree-first convention).
                let mut reversed = share_coeffs.clone();
                reversed.reverse();
                let direct_commitment = compute_share_encryption_commitment_from_message(
                    &Polynomial::from_u64_vector(reversed),
                    msg_bit,
                );
                assert_eq!(
                    inputs.expected_commitments[party_idx][mod_idx], direct_commitment,
                    "expected_commitments[{}][{}] doesn't match direct computation",
                    party_idx, mod_idx
                );
            }
        }
    }
}
