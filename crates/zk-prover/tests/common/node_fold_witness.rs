// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Correlated DKG witness pieces for `node_fold`: [`PkGenerationCircuitData`] plus
//! [`ShareComputationCircuitData`] built from the same secrets so C1 ↔ C2 commitments align.

use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_zk_helpers::circuits::dkg::share_computation::utils::compute_parity_matrix;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::{
    Inputs as ShareComputationInputs, ShareComputationCircuitData,
};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuitData;
use e3_zk_helpers::threshold::pk_generation::PkGenerationCircuitData;
use e3_zk_helpers::CiphernodesCommittee;
use e3_zk_helpers::CircuitsErrors;
use fhe::bfv::Encoding;
use fhe::bfv::SecretKey;
use fhe::mbfv::PublicKeyShare;
use fhe::trbfv::{ShareManager, TRBFV};
use fhe::{bfv::Plaintext, bfv::PublicKey};
use fhe_traits::FheEncoder;
use ndarray::Array2;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use rand::rng;
use std::ops::Deref;

/// Same as [`PkGenerationCircuitData::generate_sample`], plus smudging coefficients for C2b.
///
/// Returns the [`SecretKey`] used for [`PublicKeyShare::new_extended`] so correlated C2a shares can
/// be built with [`ShareComputationCircuitData::generate_sample`]-compatible
/// `coeffs_to_poly_level0(secret_key.coeffs)` (not a round-trip through `pk.sk` limb 0).
pub fn pk_generation_sample_with_esi(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
) -> Result<(PkGenerationCircuitData, Vec<BigInt>, SecretKey), CircuitsErrors> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e)))?;

    let mut rng = rng();

    let secret_key = SecretKey::random(&threshold_params, &mut rng);
    let crp = create_deterministic_crp_from_default_seed(&threshold_params);

    let (pk0_share, _, _sk_fhe, e) =
        PublicKeyShare::new_extended(&secret_key, crp.clone(), &mut rng).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to create public key share: {:?}", e))
        })?;

    let sk_coeffs: Vec<BigInt> = secret_key.coeffs.iter().map(|&c| BigInt::from(c)).collect();
    let mut sk_crt = CrtPolynomial::from_mod_q_polynomial(&sk_coeffs, threshold_params.moduli());
    sk_crt
        .center(threshold_params.moduli())
        .map_err(|e| CircuitsErrors::Sample(format!("center sk CRT: {:?}", e)))?;

    let num_parties = committee.n;
    let threshold = committee.threshold;

    let defaults = preset
        .search_defaults()
        .ok_or_else(|| CircuitsErrors::Sample("missing search defaults".to_string()))?;
    let num_ciphertexts = defaults.z;
    // Lambda is secure or insecure depending on the preset's security tier.
    let lambda = preset
        .lambda()
        .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

    let trbfv = TRBFV::new(num_parties, threshold, threshold_params.clone())
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to create TRBFV: {:?}", e)))?;
    let share_manager = ShareManager::new(num_parties, threshold, threshold_params.clone())
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)))?;

    let esi_coeffs: Vec<BigInt> = trbfv
        .generate_smudging_error(num_ciphertexts as usize, lambda, &mut rng)
        .map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to generate smudging error: {:?}", e))
        })?;

    let e_sm_rns_zeroizing = share_manager
        .bigints_to_poly(&esi_coeffs)
        .map_err(|e| CircuitsErrors::Sample(format!("bigints_to_poly: {:?}", e)))?;

    let e_sm = e_sm_rns_zeroizing.deref().clone();

    let pk = PkGenerationCircuitData {
        committee,
        pk0_share: CrtPolynomial::from_fhe_polynomial(&pk0_share),
        eek: CrtPolynomial::from_fhe_polynomial(&e),
        e_sm: CrtPolynomial::from_fhe_polynomial(&e_sm),
        sk: sk_crt,
    };

    Ok((pk, esi_coeffs, secret_key))
}

/// C2a: same `sk` CRT as [`PkGenerationCircuitData::sk`]; Shamir shares from `secret_key.coeffs`
/// like [`ShareComputationCircuitData::generate_sample`] / `gen_pk_share_and_sk_sss`.
pub fn share_computation_sk_from_pk(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    pk: &PkGenerationCircuitData,
    secret_key: &SecretKey,
) -> Result<ShareComputationCircuitData, CircuitsErrors> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e)))?;
    let mut rng = rng();

    let parity_matrix =
        compute_parity_matrix(threshold_params.moduli(), committee.n, committee.threshold)
            .map_err(CircuitsErrors::Sample)?;

    let mut share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone()).map_err(
            |e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)),
        )?;

    let sk_poly = share_manager
        .coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())
        .map_err(|e| CircuitsErrors::Sample(format!("coeffs_to_poly_level0: {:?}", e)))?;
    let sk_sss_u64 = share_manager
        .generate_secret_shares_from_poly(sk_poly, &mut rng)
        .map_err(|e| {
            CircuitsErrors::Sample(format!("generate_secret_shares_from_poly: {:?}", e))
        })?;
    let secret_sss: Vec<Array2<BigInt>> = sk_sss_u64
        .into_iter()
        .map(|a| a.mapv(BigInt::from))
        .collect();

    Ok(ShareComputationCircuitData {
        dkg_input_type: DkgInputType::SecretKey,
        secret: pk.sk.clone(),
        secret_sss,
        parity_matrix,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
    })
}

/// C2b: `esi_coeffs` from [`pk_generation_sample_with_esi`]; `secret` matches [`PkGenerationCircuitData::e_sm`].
pub fn share_computation_esm_from_esi(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    pk: &PkGenerationCircuitData,
    esi_coeffs: &[BigInt],
) -> Result<ShareComputationCircuitData, CircuitsErrors> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e)))?;
    let mut rng = rng();

    let parity_matrix =
        compute_parity_matrix(threshold_params.moduli(), committee.n, committee.threshold)
            .map_err(CircuitsErrors::Sample)?;

    let mut share_manager =
        ShareManager::new(committee.n, committee.threshold, threshold_params.clone()).map_err(
            |e| CircuitsErrors::Sample(format!("Failed to create ShareManager: {:?}", e)),
        )?;

    let esi_poly = share_manager
        .bigints_to_poly(esi_coeffs)
        .map_err(|e| CircuitsErrors::Sample(format!("bigints_to_poly: {:?}", e)))?;
    let esi_sss_u64 = share_manager
        .generate_secret_shares_from_poly(esi_poly, &mut rng)
        .map_err(|e| {
            CircuitsErrors::Sample(format!("generate_secret_shares_from_poly: {:?}", e))
        })?;
    let secret_sss: Vec<Array2<BigInt>> = esi_sss_u64
        .into_iter()
        .map(|a| a.mapv(BigInt::from))
        .collect();

    Ok(ShareComputationCircuitData {
        dkg_input_type: DkgInputType::SmudgingNoise,
        secret: pk.e_sm.clone(),
        secret_sss,
        parity_matrix,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
    })
}

/// One [`ShareEncryptionCircuitData`] for C3 slot index `slot`.
pub fn share_encryption_for_slot(
    preset: BfvPreset,
    dkg_sk: &SecretKey,
    dkg_pk: &PublicKey,
    share_inputs: &ShareComputationInputs,
    slot: usize,
    dkg_input_type: DkgInputType,
) -> Result<ShareEncryptionCircuitData, CircuitsErrors> {
    let (_, dkg_params) =
        build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

    let (threshold_params, _) = build_pair_for_preset(preset)
        .map_err(|e| CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e)))?;
    let l = threshold_params.moduli().len();
    let party = slot / l;
    let mod_ix = slot % l;

    let degree = share_inputs.y.len();
    let mut share_row = Vec::with_capacity(degree);
    for coeff in 0..degree {
        let v = share_inputs.y[coeff][mod_ix][1 + party].clone();
        let q = BigInt::from(threshold_params.moduli()[mod_ix]);
        let mut x = v % &q;
        if x.is_negative() {
            x += &q;
        }
        let u = x.to_u64().ok_or_else(|| {
            CircuitsErrors::Sample("share coefficient does not fit u64 for plaintext".into())
        })?;
        share_row.push(u);
    }

    let mut rng = rng();
    let pt = Plaintext::try_encode(&share_row, Encoding::poly(), &dkg_params)
        .map_err(|e| CircuitsErrors::Sample(format!("encode plaintext: {:?}", e)))?;

    let (_ct, u_rns, e0_rns, e1_rns) = dkg_pk
        .try_encrypt_extended(&pt, &mut rng)
        .map_err(|e| CircuitsErrors::Sample(format!("encrypt: {:?}", e)))?;

    Ok(ShareEncryptionCircuitData {
        plaintext: pt,
        ciphertext: _ct,
        public_key: dkg_pk.clone(),
        secret_key: dkg_sk.clone(),
        u_rns,
        e0_rns,
        e1_rns,
        dkg_input_type,
    })
}
