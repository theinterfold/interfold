// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C7 takes the exact verified C6 public bytes in designated order; it never picks a replacement
//! party or recomputes a self-declared C6 statement from the raw share.

use super::{
    invalid,
    polynomials::{components, native_rows},
    provenance::fields,
    SetupBinding,
};
use crate::{
    commitments::ciphertext_component_commitment, compute_ciphertext_commitment,
    compute_threshold_decryption_share_commitment, encoding::fhe_poly_to_crt_centered,
    WitnessError,
};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::{
    synchronized::{
        public_signals::{Field, PublicSignals},
        Configs,
    },
    MAX_MSG_NON_ZERO_COEFFS,
};
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::{BigInt, Sign};
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub struct Contribution<'a> {
    pub public_signals: &'a [u8],
    pub share: &'a Poly<PowerBasis>,
}

/// The caller supplies independently selected authority; parsing public bytes does not verify proofs.
pub fn prepare(
    config: &Configs,
    setup: SetupBinding,
    domain: [u128; 2],
    roster: &[u32],
    ct: &Ciphertext,
    contributions: &[Contribution<'_>],
    message: &[u64],
) -> Result<Value, WitnessError> {
    if message.len() != MAX_MSG_NON_ZERO_COEFFS
        || message.iter().any(|&v| v >= config.threshold.plaintext())
    {
        return Err(invalid("invalid synchronized C7 plaintext"));
    }
    let rows =
        PublicSignals::decode_c6_batch(config, contributions.iter().map(|c| c.public_signals))?;
    let [c0, c1] = components(config, ct)?;
    let moduli = config.threshold.moduli();
    let centered = fhe_poly_to_crt_centered(&c0, moduli)?;
    let ct_hash = compute_ciphertext_commitment(
        &centered,
        &fhe_poly_to_crt_centered(&c1, moduli)?,
        config.aggregate_bit,
    );
    let c0_hash = ciphertext_component_commitment(&centered, config.aggregate_bit);
    let integer = |f: Field| BigInt::from_bytes_be(Sign::Plus, &f);
    let first = &rows[0];
    if first.binding() != Some(setup)
        || first.decryption_domain() != Some(domain)
        || first.dealers().as_deref() != Some(roster)
        || first.ciphertext_commitment().map(integer) != Some(ct_hash)
        || first.c0_commitment().map(integer) != Some(c0_hash)
    {
        return Err(invalid(
            "C6 batch does not match expected decryption context",
        ));
    }
    let mut shares = Zeroizing::new(Vec::with_capacity(rows.len()));
    let mut public = Vec::with_capacity(rows.len());
    for (c, row) in contributions.iter().zip(rows) {
        shares.push(native_rows(config, c.share)?);
        let commitment = compute_threshold_decryption_share_commitment(
            &CrtPolynomial::from_fhe_polynomial(c.share),
            config.share_bit,
            config.threshold.degree(),
        );
        if row.decryption_share_commitment().map(integer) != Some(commitment) {
            return Err(invalid("synchronized C6 share opening mismatch"));
        }
        public.push(fields(c.public_signals)?);
    }
    Ok(
        json!({"rows": public, "message": message, "c0":native_rows(config,&c0)?, "shares":shares.as_slice()}),
    )
}
