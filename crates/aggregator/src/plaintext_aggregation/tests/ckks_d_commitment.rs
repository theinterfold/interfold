// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C6-CKKS `d_commitment` cross-check: the received share bytes must be
//! the ones the proof committed to (same derivation as the witness
//! builder), both ways.

use super::*;
use e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set;
use e3_zk_helpers::circuits::commitments::compute_threshold_decryption_share_commitment;
use e3_zk_helpers::threshold::share_decryption_ckks::{
    Bits as C6Bits, Bounds as C6Bounds, CkksShareDecryptionData, Inputs as C6Inputs,
};
use e3_zk_helpers::threshold::user_data_encryption_ckks::CkksPreset;
use e3_zk_helpers::Computation;
use fhe::trckks::TRCKKS;
use fhe_traits::Serialize as _;

/// One real party share at level 0 on ParamSet `set`, its ciphertext, and
/// the `d_commitment` the C6-CKKS witness builder would emit.
#[allow(clippy::type_complexity)]
fn fixture(set: u8) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32])> {
    let params = ckks_params_for_on_chain_param_set(set)?;
    let preset = CkksPreset {
        params: params.clone(),
        input_bound: 1.0,
    };
    let mut rng = rand::rng();
    let trckks = TRCKKS::new(3, 1, params.clone())?;
    let sk = fhe::ckks::CkksSecretKey::random(&params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng)?;
    let sk_mats = trckks
        .generate_secret_shares_from_poly(trckks.coeffs_to_poly(sk.coeffs.as_ref())?, &mut rng)?;
    let es = trckks.generate_smudging_error(20, &mut rng)?;
    let es_mats =
        trckks.generate_secret_shares_from_poly(trckks.smudging_to_poly(&es)?, &mut rng)?;
    let encoder = fhe::ckks::CkksEncoder::new(&params);
    let ct = pk.try_encrypt(&encoder.encode(&[42.5, -17.25], 0)?, &mut rng)?;
    let sk_share = trckks.share_row_to_poly(&sk_mats, 0)?;
    let es_share = trckks.share_row_to_poly(&es_mats, 0)?;
    let d_share = trckks.decryption_share(&ct, sk_share.clone().into_ntt(), es_share.clone())?;
    let data = CkksShareDecryptionData {
        ciphertext: ct.clone(),
        sk_poly: sk_share,
        es_poly: es_share,
        d_share: d_share.clone(),
        domain_hi: 1,
        domain_lo: 2,
    };
    let inputs = C6Inputs::compute(preset.clone(), &data)?;
    let bounds = C6Bounds::compute(preset.clone(), &())?;
    let bits = C6Bits::compute(preset, &bounds)?;
    // What the circuit hashes: `d_native_trunc` at `BIT_D_NATIVE`.
    let commitment = compute_threshold_decryption_share_commitment(
        &inputs.d_native_trunc,
        bits.d_native_bit,
        params.degree(),
    );
    let (_, be) = commitment.to_bytes_be();
    let mut d_commitment = [0u8; 32];
    d_commitment[32 - be.len()..].copy_from_slice(&be);
    Ok((
        params.to_bytes(),
        ct.to_bytes(),
        d_share.to_bytes(),
        d_commitment,
    ))
}

fn c6_ckks_proof(e3_id: &E3id, d_commitment: [u8; 32]) -> SignedProofPayload {
    // Inputs (5 × 32) then the single output `d_commitment`.
    let mut signals = vec![0u8; 6 * 32];
    signals[5 * 32..].copy_from_slice(&d_commitment);
    SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C6ThresholdShareDecryption,
            proof: Proof::new(
                CircuitName::ThresholdShareDecryptionCkks,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&signals),
            ),
        },
        signature: ArcBytes::from_bytes(&[0u8; 65]),
    }
}

#[test]
fn ckks_d_commitment_cross_check_accepts_the_proven_share_and_rejects_others() -> Result<()> {
    let e3_id = E3id::new("42", 1);
    for set in [0u8, 3] {
        let (params, ct, share, d_commitment) = fixture(set)?;
        let (_, _, other_share, _) = fixture(set)?;
        let ct_out = vec![ArcBytes::from_bytes(&ct)];
        let mut proofs = BTreeMap::new();
        proofs.insert(1u64, vec![c6_ckks_proof(&e3_id, d_commitment)]);
        proofs.insert(2u64, vec![c6_ckks_proof(&e3_id, d_commitment)]);
        proofs.insert(3u64, vec![c6_ckks_proof(&e3_id, [0xAB; 32])]);
        let honest = vec![
            // Party 1: proves AND broadcasts the same share.
            (1u64, vec![ArcBytes::from_bytes(&share)]),
            // Party 2: proves `share` but broadcasts a different one.
            (2u64, vec![ArcBytes::from_bytes(&other_share)]),
            // Party 3: proof commits to garbage.
            (3u64, vec![ArcBytes::from_bytes(&share)]),
            // Party 4: no proof at all.
            (4u64, vec![ArcBytes::from_bytes(&share)]),
        ];
        let mismatched = ThresholdPlaintextAggregation::verify_ckks_shares_match_c6_commitments(
            &params, &ct_out, &honest, &proofs,
        );
        assert_eq!(mismatched, BTreeSet::from([2, 3, 4]), "param set {set}");

        // Undecodable params fail closed for everyone.
        let all = ThresholdPlaintextAggregation::verify_ckks_shares_match_c6_commitments(
            b"junk", &ct_out, &honest, &proofs,
        );
        assert_eq!(all, BTreeSet::from([1, 2, 3, 4]));
    }
    Ok(())
}
