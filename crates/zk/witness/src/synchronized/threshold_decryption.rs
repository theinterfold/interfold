// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C6 preparation borrows the recovered C4 opening and the *same* local draw and native
//! partial used for decryption. No sampling, identity repair, or key substitution here.

use super::{
    binding_json, commitments, dealers, invalid,
    polynomials::{components, native_rows},
    KeyBytes, SetupBinding,
};
use crate::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
    encoding::fhe_poly_to_crt_centered, WitnessError,
};
use e3_zk_config::synchronized::Configs;
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::BigInt;
use serde_json::{json, Value};

pub struct Opening<'a> {
    pub setup: SetupBinding,
    pub domain: [u128; 2],
    pub owner: u32,
    pub roster: &'a [u32],
    pub expected_sk: &'a BigInt,
    pub expected_bundle: &'a BigInt,
    pub expected_ct: &'a BigInt,
    pub outgoing: &'a [KeyBytes],
    pub incoming: &'a [KeyBytes],
    pub sk: &'a Poly<PowerBasis>,
}

impl Opening<'_> {
    pub fn prepare(
        &self,
        config: &Configs,
        ciphertext: &Ciphertext,
        noise: &[BigInt],
        // Metadata from upstream DecryptionShare::into_parts, in one-based coordinates.
        (d, native_owner, coordinates): (&Poly<PowerBasis>, usize, &[usize]),
    ) -> Result<Value, WitnessError> {
        dealers(config, self.roster)?;
        let values = config.committee.values();
        let designated = &self.roster[..=values.threshold];
        if !designated.contains(&self.owner)
            || native_owner != self.owner as usize + 1
            || coordinates
                .iter()
                .copied()
                .ne(designated.iter().map(|id| *id as usize + 1))
        {
            return Err(invalid(
                "partial is not from the fixed designated owner/set",
            ));
        }
        let [ct0, ct1] = components(config, ciphertext)?;
        let sk = zeroize::Zeroizing::new(native_rows(config, self.sk)?);
        let share = zeroize::Zeroizing::new(native_rows(config, d)?);
        let moduli = config.threshold.moduli();
        if &compute_aggregated_shares_commitment(
            &fhe_poly_to_crt_centered(self.sk, moduli)?,
            config.aggregate_bit,
        ) != self.expected_sk
            || &commitments::key_bundle(
                config,
                self.setup,
                self.owner,
                self.roster,
                self.expected_sk,
                self.outgoing,
                self.incoming,
            )? != self.expected_bundle
        {
            return Err(invalid(
                "C6 opening does not match published SK and key bundle",
            ));
        }
        if &compute_ciphertext_commitment(
            &fhe_poly_to_crt_centered(&ct0, moduli)?,
            &fhe_poly_to_crt_centered(&ct1, moduli)?,
            config.aggregate_bit,
        ) != self.expected_ct
        {
            return Err(invalid(
                "C6 ciphertext differs from its expected commitment",
            ));
        }
        let bound = &config.pk_generation.bounds.e_sm_bound;
        if noise.len() != config.threshold.degree() || noise.iter().any(|v| v.magnitude() > bound) {
            return Err(invalid(
                "local noise exceeds configured degree or signed bound",
            ));
        }
        let bound = BigInt::from(bound.clone());
        let mut result = json!({
            "setup": binding_json(self.setup), "domain": binding_json(self.domain),
            "owner": self.owner, "roster": self.roster,
            "expected_sk": self.expected_sk.to_string(), "expected_bundle": self.expected_bundle.to_string(),
            "expected_ct": self.expected_ct.to_string(), "outgoing": self.outgoing, "incoming": self.incoming,
            "sk": sk.as_slice(), "ct": [native_rows(config,&ct0)?, native_rows(config,&ct1)?], "d": share.as_slice(),
        });
        if config.profile == e3_fhe_params::BfvProfile::SyncDecSecure8192 {
            let c1 = fhe_poly_to_crt_centered(&ct1, moduli)?;
            let secret = fhe_poly_to_crt_centered(self.sk, moduli)?;
            let prime = e3_zk_config::field::get_zkp_modulus();
            let products: Vec<_> = c1
                .limbs
                .iter()
                .zip(&secret.limbs)
                .map(|(a, b)| {
                    let product =
                        crate::negacyclic::negacyclic_mul_exact(a, b, config.threshold.degree());
                    product
                        .coefficients()
                        .iter()
                        .map(|v| ((v % &prime + &prime) % &prime).to_string())
                        .collect::<Vec<_>>()
                })
                .collect();
            result["product"] = json!(products);
            result["shifted_noise"] = json!(noise
                .iter()
                .map(|e| (e + &bound).to_string())
                .collect::<Vec<_>>());
            return Ok(result);
        }
        let shifted = zeroize::Zeroizing::new(
            noise
                .iter()
                .map(|e| {
                    u64::try_from(e + &bound)
                        .map_err(|_| invalid("local noise exceeds Minimum encoding"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        result["shifted_noise"] = json!(shifted.as_slice());
        Ok(result)
    }
}
