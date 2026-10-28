// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::field::join_display;
use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::calculate_smudging_bound;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub mod crp;
use crp::crp_matrix_constant_string;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "pk-generation",
    prefix: "PK_GENERATION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub preset: BfvPreset,
    pub committee: CiphernodesCommitteeSize,
    pub bits: Bits,
    pub bounds: Bounds,
    /// Two-limb description of the smudging bound, present when the bound is too wide for one
    /// field element. The C2b leaf then checks the lift with it, and the C1 constants below are
    /// placeholders: no C1 proof exists for such a preset.
    pub wide_lift: Option<WideLift>,
}

/// Widest smudging bound, in bits, that the single-element lift handles. The bound's bit width
/// plus the width of a modulus must stay under the field width, with room for the one-sided
/// quotient window; a larger bound uses [`WideLift`].
pub const NARROW_LIFT_MAX_BITS: u64 = 252;

/// Largest magnitude, in bits, that a term of the wide lift relation may reach. The relation is
/// an integer equation only if both sides stay below half of the 254-bit field prime.
const WIDE_LIFT_MAX_TERM_BITS: u64 = 251;

/// The smudging bound `B` split at `2^shift`: `u = x + B` lies in `[0, 2B]`, and the leaf takes
/// `u = lo + 2^shift * hi`. All fields are circuit constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WideLift {
    pub shift: u32,
    pub bit_hi: u32,
    pub bit_quotient: u32,
    pub bound_hi: BigUint,
    pub bound_lo: BigUint,
    pub span_hi: BigUint,
    pub span_lo: BigUint,
    /// `2^shift mod q_l` for each limb.
    pub radix: Vec<BigUint>,
    /// Bound on `|quotient|` of `centered + quotient * q_l == (lo - B_lo) + radix_l * (hi - B_hi)`.
    pub quotient_bounds: Vec<BigUint>,
}

impl WideLift {
    /// `None` when the narrow single-element lift is sound for `e_sm_bound`.
    pub fn new(e_sm_bound: &BigUint, qis: &[BigUint]) -> Result<Option<Self>, ConfigError> {
        if e_sm_bound.bits() <= NARROW_LIFT_MAX_BITS {
            return Ok(None);
        }
        let span: BigUint = e_sm_bound << 1u32;
        let q_bits = qis.iter().map(BigUint::bits).max().unwrap_or(0);
        // Both the low limb (`shift` bits) and the high limb times a radix (`span - shift +
        // q_bits` bits) must fit well under the field, and the range checks cost `2 * span` bits
        // in total whatever the split, so balance the two terms.
        let shift = (span.bits() + q_bits + 3).div_ceil(2);
        let mask = (BigUint::from(1u32) << shift) - 1u32;
        let (span_hi, span_lo) = (&span >> shift, &span & &mask);
        let (bound_hi, bound_lo) = (e_sm_bound >> shift, e_sm_bound & &mask);
        let bit_hi = span_hi.bits();
        let radix: Vec<BigUint> = qis
            .iter()
            .map(|q| (BigUint::from(1u32) << shift) % q)
            .collect();
        // |lo - B_lo| < 2^shift and |hi - B_hi| <= span_hi, so |rhs| < 2^shift + radix * span_hi.
        let quotient_bounds: Vec<BigUint> = qis
            .iter()
            .zip(&radix)
            .map(|(q, r)| ((BigUint::from(1u32) << shift) + r * &span_hi + q) / q + 1u32)
            .collect();
        let bit_quotient = quotient_bounds.iter().map(BigUint::bits).max().unwrap_or(0);
        let widest_term = [
            shift,
            bit_hi + q_bits,
            // The one-sided window admits |quotient| < 2^(bit_quotient + 1).
            bit_quotient + 1 + q_bits,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
            + 1;
        if widest_term > WIDE_LIFT_MAX_TERM_BITS {
            return Err(ConfigError::Other(format!(
                "Smudging bound of {} bits exceeds the wide lift: a relation term needs {widest_term} bits",
                e_sm_bound.bits()
            )));
        }
        Ok(Some(WideLift {
            shift: u32::try_from(shift).map_err(|e| ConfigError::Other(e.to_string()))?,
            bit_hi: u32::try_from(bit_hi).map_err(|e| ConfigError::Other(e.to_string()))?,
            bit_quotient: u32::try_from(bit_quotient)
                .map_err(|e| ConfigError::Other(e.to_string()))?,
            bound_hi,
            bound_lo,
            span_hi,
            span_lo,
            radix,
            quotient_bounds,
        }))
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub eek_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub e_sm_lifted_bit: u32,
    pub e_sm_quotient_bit: u32,
    pub r_bit: u32,
    pub pk_bit: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub eek_bound: BigUint,
    pub sk_bound: BigUint,
    pub e_sm_bound: BigUint,
    pub e_sm_limb_bounds: Vec<BigUint>,
    pub e_sm_quotient_bounds: Vec<BigUint>,
    pub r_bounds: Vec<BigUint>,
    pub pk_bound: BigUint,
}
impl Configs {
    pub fn new(
        preset: BfvPreset,
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, threshold_params)?;

        let bounds = Bounds::new(preset, threshold_params, committee)?;
        let mut bits = Bits::new(threshold_params, &bounds);
        let qis: Vec<BigUint> = threshold_params
            .moduli()
            .iter()
            .map(|q| BigUint::from(*q))
            .collect();
        let wide_lift = WideLift::new(&bounds.e_sm_bound, &qis)?;
        if wide_lift.is_some() {
            // The C1 widths describe a one-element lift that does not exist for this preset.
            bits.e_sm_lifted_bit = 1;
            bits.e_sm_quotient_bit = 1;
        }

        Ok(Configs {
            params: threshold_params.clone(),
            preset,
            committee,

            bits,
            bounds,
            wide_lift,
        })
    }
}
impl Bounds {
    fn new(
        preset: BfvPreset,
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let committee_n = committee.values().n;

        let n = BigUint::from(threshold_params.degree());
        let ctx = threshold_params.context_at_level(0)?;

        let cbd_bound = (threshold_params.variance() * 2) as u64;

        let sk_bound = BigUint::from(SecretKey::sk_bound() as u128);
        let eek_bound = BigUint::from(cbd_bound);

        let sd = preset
            .search_defaults()
            .ok_or_else(|| ConfigError::Other("missing search defaults".to_string()))?;

        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        let e_sm_bound = calculate_smudging_bound(
            threshold_params.clone(),
            committee_n,
            sd.z as usize,
            sd.mult_depth,
            lambda,
        )
        .map_err(|e| ConfigError::Other(format!("Failed to calculate smudging bound: {:?}", e)))?;

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r_bounds = Vec::with_capacity(num_moduli);
        let mut e_sm_limb_bounds = Vec::with_capacity(num_moduli);
        let mut e_sm_quotient_bounds = Vec::with_capacity(num_moduli);
        let mut pk_bound_max = BigUint::from(0u32);

        for qi in ctx.moduli_operators() {
            let qi_big = BigUint::from(**qi);
            let qi_bound = (&qi_big - 1u32) / 2u32;

            // e_sm[i] is the centered residue of the lifted smudging noise at q_i; the matching
            // CRT quotient is bounded by (e_sm_bound + (q_i - 1) / 2) / q_i.
            e_sm_limb_bounds.push(qi_bound.clone());
            e_sm_quotient_bounds.push((&e_sm_bound + &qi_bound) / &qi_big);

            // `r` is the quotient of the mod-q reduction in the identity the circuit checks:
            //   pk0i = -(a * sk mod X^N + 1) + eek + q * r   (over the integers)
            // so bounding each other term and dividing by q bounds `r`:
            //   |a * sk mod X^N + 1| <= n * (q-1)/2 * sk_bound (negacyclic convolution of n terms,
            //   with |a| <= (q-1)/2 because the CRP is stored centered), |pk0i| <= (q-1)/2 and
            //   |eek| <= eek_bound. Both sides are symmetric, so one bound covers the two-sided
            //   range check. The `+ 2` rather than `+ 1` keeps the margin the unreduced `r1` bound
            //   carried.
            //
            // Reducing modulo the cyclotomic removed `r2` entirely, and at sk_bound = 1 this is the
            // same expression the unreduced `r1` used -- the reduced quotient is no wider.
            r_bounds.push(((&n * &sk_bound + 2u32) * &qi_bound + &eek_bound) / &qi_big);

            // Track maximum pk bound across all moduli
            // We don't need to store them as we only need the maximum bound to compute the commitment bit width
            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
        }

        Ok(Bounds {
            eek_bound,
            sk_bound,
            e_sm_bound,
            e_sm_limb_bounds,
            e_sm_quotient_bounds,
            r_bounds,
            pk_bound: pk_bound_max,
        })
    }
}
impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>, data: &Bounds) -> Self {
        // Calculate bit widths for each bound type
        let eek_bit = calculate_bit_width(&data.eek_bound);
        let sk_bit = calculate_bit_width(&data.sk_bound);
        // e_sm limbs are centered residues, so they share the pk/modulus width. The lifted value
        // carries the smudging bound and needs its own, much wider, window.
        let e_sm_lifted_bit = calculate_bit_width(&data.e_sm_bound);
        let e_sm_bit = data
            .e_sm_limb_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);
        let e_sm_quotient_bit = data
            .e_sm_quotient_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);

        // pk_bit: centered representation uses (max(qi) - 1) / 2 as the bound,
        // matching compute_modulus_bit() used in C5 (pk_aggregation).
        let pk_bit = e3_fhe_params::utils::compute_modulus_bit(threshold_params);

        // One width covers every limb's `r`, so take the widest bound.
        let r_bit = data
            .r_bounds
            .iter()
            .max()
            .map(calculate_bit_width)
            .unwrap_or(0);

        Bits {
            eek_bit,
            sk_bit,
            e_sm_bit,
            e_sm_lifted_bit,
            e_sm_quotient_bit,
            r_bit,
            pk_bit,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let threshold_params = &self.params;
        let prefix = METADATA.prefix;

        let qis_str = join_display(&configs.params.moduli(), ", ");

        let e_sm_limb_bounds_str = join_display(&configs.bounds.e_sm_limb_bounds, ", ");
        // A wide preset has no C1 proof, so its C1 bounds are zero placeholders; the C2b leaf
        // takes its bound from the wide lift constants.
        let (e_sm_bound, e_sm_quotient_bounds_str) = if configs.wide_lift.is_some() {
            (
                BigUint::from(0u32),
                join_display(&vec![0u32; configs.bounds.e_sm_quotient_bounds.len()], ", "),
            )
        } else {
            (
                configs.bounds.e_sm_bound.clone(),
                join_display(&configs.bounds.e_sm_quotient_bounds, ", "),
            )
        };
        let r_bounds_str = join_display(&configs.bounds.r_bounds, ", ");

        let crp_matrix_str = crp_matrix_constant_string(threshold_params)?;

        let b_enc = error_sampler_bound(threshold_params.get_error1_variance());

        Ok(format!(
            r#"use crate::core::threshold::pk_generation::Configs as PkGenerationConfigs;
use crate::math::polynomial::Polynomial;

// Global configs for Threshold Public Key Generation circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

{}

/************************************
-------------------------------------
pk_generation (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

pub global {}_BIT_EEK: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E_SM: u32 = {};
pub global {}_BIT_E_SM_LIFTED: u32 = {};
pub global {}_BIT_E_SM_QUOTIENT: u32 = {};
pub global {}_BIT_R: u32 = {};
pub global {}_BIT_PK: u32 = {};

pub global {}_EEK_BOUND: Field = {};
pub global {}_SK_BOUND: Field = {};
pub global {}_E_SM_BOUND: Field = {};
pub global {}_E_SM_LIMB_BOUNDS: [Field; L] = [{}];
pub global {}_E_SM_QUOTIENT_BOUNDS: [Field; L] = [{}];
pub global {}_R_BOUNDS: [Field; L] = [{}];

pub global {}_B_ENC: Field = {};

pub global {}_CONFIGS: PkGenerationConfigs<N, L> = PkGenerationConfigs::new(
    QIS,
    {}_EEK_BOUND,
    {}_SK_BOUND,
    {}_E_SM_BOUND,
    {}_E_SM_LIMB_BOUNDS,
    {}_E_SM_QUOTIENT_BOUNDS,
    {}_R_BOUNDS,
);
"#,
            configs.params.degree(),
            configs.params.moduli().len(),
            qis_str,
            crp_matrix_str,
            prefix,
            configs.bits.eek_bit,
            prefix,
            configs.bits.sk_bit,
            prefix,
            configs.bits.e_sm_bit,
            prefix,
            configs.bits.e_sm_lifted_bit,
            prefix,
            configs.bits.e_sm_quotient_bit,
            prefix,
            configs.bits.r_bit,
            prefix,
            configs.bits.pk_bit,
            prefix,
            configs.bounds.eek_bound,
            prefix,
            configs.bounds.sk_bound,
            prefix,
            e_sm_bound,
            prefix,
            e_sm_limb_bounds_str,
            prefix,
            e_sm_quotient_bounds_str,
            prefix,
            r_bounds_str,
            prefix,
            b_enc,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
        ))
    }
}

impl Configs {
    pub fn for_preset(
        preset: BfvPreset,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (threshold_params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(preset, &threshold_params, committee)
    }
}
