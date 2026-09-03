// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2a/C2b proof-request emission for the CKKS DKG.
//!
//! The BFV flow builds [`e3_events::ShareComputationProofRequest`]s inside
//! `build_shares_generated_plan` and lets the ProofRequest actor turn them
//! into signed C2 proofs. The CKKS flow emits the SAME event payloads —
//! the request struct is scheme-agnostic (secret bytes + Shamir shares +
//! input type + committee size); only the witness assembly differs, and
//! the zk-helpers side already understands CKKS geometry via
//! `compute_ckks_share_inputs`.
//!
//! What stays honest here: `params_preset` in the emitted request is the
//! BFV threshold preset the ProofRequest actor uses for BFV witnesses. A
//! CKKS run must route the request through the CKKS witness path
//! ([`ckks_share_computation_data`] -> `compute_ckks_share_inputs`), which
//! [`verify_ckks_share_witnesses`] exercises end-to-end below; the actor's
//! `ComputeRequest` dispatch keying off scheme is the remaining shell work.

use anyhow::{anyhow, bail, Context, Result};
use e3_crypto::{Cipher, SensitiveBytes};
use e3_fhe::CkksKeyshareMaterial;
use e3_polynomial::CrtPolynomial;
use e3_trbfv::shares::SharedSecret;
use e3_zk_helpers::circuits::dkg::share_computation::utils::compute_parity_matrix;
use e3_zk_helpers::circuits::dkg::share_computation_ckks::{
    compute_ckks_share_inputs, verify_ckks_share_constraints,
};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_helpers::threshold::user_data_encryption_ckks::CkksPreset;
use ndarray::Array2;
use num_bigint::BigInt;

/// Serialized C2 witness payload pair for the ProofRequest actor: the
/// secret contribution and its dealt Shamir shares, encrypted at rest —
/// byte-compatible with `ShareComputationProofRequest.{secret_raw,
/// secret_sss_raw}`.
pub struct CkksC2Witness {
    /// Bincode `Vec<i64>` secret coefficients (encrypted at rest).
    pub secret_raw: SensitiveBytes,
    /// Bincode [`SharedSecret`] dealt matrices (encrypted at rest).
    pub secret_sss_raw: SensitiveBytes,
    /// Which C2 circuit this feeds.
    pub dkg_input_type: DkgInputType,
}

fn to_shared_secret(flat: &[Vec<u64>], rows: usize, cols: usize) -> Result<SharedSecret> {
    let mats = flat
        .iter()
        .enumerate()
        .map(|(m, v)| {
            Array2::from_shape_vec((rows, cols), v.clone())
                .with_context(|| format!("dealt matrix {m} has wrong shape"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SharedSecret::new(mats))
}

/// Build both C2 witness payloads (C2a sk, C2b smudging) from this party's
/// actual dealt material.
pub fn build_c2_witnesses(
    material: &CkksKeyshareMaterial,
    cipher: &Cipher,
) -> Result<(CkksC2Witness, CkksC2Witness)> {
    let sk_secret = to_shared_secret(&material.sk_sss, material.rows, material.cols)?;
    let es_secret = to_shared_secret(&material.es_sss, material.rows, material.cols)?;

    let make = |coeffs: &[i64], sss: &SharedSecret, ty: DkgInputType| -> Result<CkksC2Witness> {
        Ok(CkksC2Witness {
            secret_raw: SensitiveBytes::new(
                bincode::serialize(coeffs).map_err(|e| anyhow!("serialize secret: {e}"))?,
                cipher,
            )?,
            secret_sss_raw: SensitiveBytes::new(
                bincode::serialize(sss).map_err(|e| anyhow!("serialize sss: {e}"))?,
                cipher,
            )?,
            dkg_input_type: ty,
        })
    };
    Ok((
        make(&material.sk_coeffs, &sk_secret, DkgInputType::SecretKey)?,
        make(&material.es_coeffs, &es_secret, DkgInputType::SmudgingNoise)?,
    ))
}

/// Reconstruct the C2 circuit data a witness payload describes — the CKKS
/// counterpart of the ProofRequest actor's BFV witness assembly.
pub fn ckks_share_computation_data(
    preset: &CkksPreset,
    witness: &CkksC2Witness,
    n_parties: usize,
    threshold: usize,
    cipher: &Cipher,
) -> Result<ShareComputationCircuitData> {
    let moduli = preset.params.moduli();
    let secret_coeffs: Vec<i64> = bincode::deserialize(&witness.secret_raw.access(cipher)?)
        .map_err(|e| anyhow!("deserialize secret: {e}"))?;
    let sss: SharedSecret = bincode::deserialize(&witness.secret_sss_raw.access(cipher)?)
        .map_err(|e| anyhow!("deserialize sss: {e}"))?;
    if secret_coeffs.len() != preset.params.degree() {
        bail!(
            "secret has {} coefficients, params degree is {}",
            secret_coeffs.len(),
            preset.params.degree()
        );
    }

    let parity_matrix = compute_parity_matrix(moduli, n_parties, threshold)
        .map_err(|e| anyhow!("parity matrix: {e}"))?;

    let secret_bigint: Vec<BigInt> = secret_coeffs.iter().map(|&c| BigInt::from(c)).collect();
    let mut secret_crt = CrtPolynomial::from_mod_q_polynomial(&secret_bigint, moduli);
    secret_crt
        .center(moduli)
        .map_err(|e| anyhow!("center: {e:?}"))?;

    let secret_sss: Vec<Array2<BigInt>> = sss
        .moduli_data()
        .iter()
        .map(|m| m.map(|&v| BigInt::from(v)))
        .collect();

    Ok(ShareComputationCircuitData {
        dkg_input_type: witness.dkg_input_type,
        secret: secret_crt,
        secret_sss,
        parity_matrix,
        n_parties: n_parties as u32,
        threshold: threshold as u32,
    })
}

/// Full check: this party's dealt material satisfies every C2a and C2b
/// circuit constraint (secret consistency, range, Reed–Solomon parity).
/// This is exactly what the Noir circuits verify — run here through the
/// same witness pipeline `nargo` consumes.
pub fn verify_ckks_share_witnesses(
    preset: &CkksPreset,
    material: &CkksKeyshareMaterial,
    n_parties: usize,
    threshold: usize,
    cipher: &Cipher,
) -> Result<()> {
    let (c2a, c2b) = build_c2_witnesses(material, cipher)?;
    for witness in [&c2a, &c2b] {
        let data = ckks_share_computation_data(preset, witness, n_parties, threshold, cipher)?;
        // Constraint check first: exactly what the Noir circuit enforces
        // (consistency, range, RS parity) — the gate for emitting the
        // proof request.
        verify_ckks_share_constraints(preset, &data)
            .map_err(|e| anyhow!("{:?} witness rejected: {e:?}", witness.dkg_input_type))?;
        // Then the witness assembly the prover consumes must also succeed.
        compute_ckks_share_inputs(preset, &data).map_err(|e| {
            anyhow!(
                "{:?} witness assembly failed: {e:?}",
                witness.dkg_input_type
            )
        })?;
    }
    Ok(())
}
