// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::field::{get_zkp_modulus, join_display};
use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::calculate_smudging_bound;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
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
    pub e_sm_split: ESmSplit,
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
/// The smudging bound split that lets the l-BFV C2b leaves check `|e| <= B` when `B` exceeds the
/// field, as it does at secure-16384. `B + e` and `B - e` are each `high * 2^split_bits + low` with
/// both parts non-negative, and their sum is checked against `2B` limb by limb with one carry, so
/// `e` is never formed in the field. Each residue is tied to `B + e` modulo `q_l` through
/// `radix_mod_q[l] = 2^split_bits mod q_l` and `bound_mod_q[l] = B mod q_l`, with a quotient below
/// `2^quotient_bit` in magnitude.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ESmSplit {
    /// The smudging bound `B` itself. Witnesses read it; it is not emitted, being above the field
    /// at secure-16384.
    pub bound: BigUint,
    pub split_bits: u32,
    pub high_bit: u32,
    pub quotient_bit: u32,
    pub twice_bound_high: BigUint,
    pub twice_bound_low: BigUint,
    pub radix_mod_q: Vec<BigUint>,
    pub bound_mod_q: Vec<BigUint>,
}
impl ESmSplit {
    pub fn new(e_sm_bound: &BigUint, moduli: &[u64]) -> Result<Self, ConfigError> {
        let twice_bound = e_sm_bound * 2u32;
        // `B + e` and `B - e` lie in `[0, 2B]`, which `width` bits hold.
        let width = calculate_bit_width(&twice_bound);
        let split_bits = width.div_ceil(2);
        let high_bit = width - split_bits;
        let radix = BigUint::one() << split_bits;
        let mut radix_mod_q = Vec::with_capacity(moduli.len());
        let mut bound_mod_q = Vec::with_capacity(moduli.len());
        let mut quotient_bound = BigUint::from(0u32);
        let mut q_bit = 0;
        for &q in moduli {
            let q = BigUint::from(q);
            radix_mod_q.push(&radix % &q);
            bound_mod_q.push(e_sm_bound % &q);
            // `t = (high * radix_mod_q + low - bound_mod_q - r) / q` with `high < 2^high_bit`,
            // `low < 2^split_bits` and `|r| < q`: above, below `2^high_bit + 2^split_bits / q + 1`;
            // below, above `-2`.
            quotient_bound = quotient_bound.max((BigUint::one() << high_bit) + &radix / &q + 2u32);
            q_bit = q_bit.max(calculate_bit_width(&q));
        }
        let quotient_bit = calculate_bit_width(&quotient_bound);
        // Every term of the three relations must stay far below the field for them to hold over
        // the integers: `high * radix_mod_q`, `low`, and `q * t`.
        let field_bit = calculate_bit_width(&get_zkp_modulus().to_biguint().expect("positive"));
        let widest = (high_bit + q_bit).max(split_bits).max(quotient_bit + q_bit) + 2;
        if widest >= field_bit - 1 {
            return Err(ConfigError::Other(format!(
                "the smudging bound split needs {widest} bits, too close to the {field_bit}-bit field"
            )));
        }
        Ok(ESmSplit {
            bound: e_sm_bound.clone(),
            split_bits,
            high_bit,
            quotient_bit,
            twice_bound_high: &twice_bound >> split_bits,
            twice_bound_low: &twice_bound % &radix,
            radix_mod_q,
            bound_mod_q,
        })
    }
}
impl Configs {
    pub fn new(
        preset: BfvPreset,
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, threshold_params)?;

        let bounds = Bounds::new(preset, threshold_params, committee)?;
        let bits = Bits::new(threshold_params, &bounds);
        let e_sm_split = ESmSplit::new(&bounds.e_sm_bound, threshold_params.moduli())?;

        Ok(Configs {
            params: threshold_params.clone(),
            preset,
            committee,

            bits,
            bounds,
            e_sm_split,
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
        let e_sm_quotient_bounds_str = join_display(&configs.bounds.e_sm_quotient_bounds, ", ");
        let r_bounds_str = join_display(&configs.bounds.r_bounds, ", ");

        let crp_matrix_str = crp_matrix_constant_string(threshold_params)?;

        let variance = threshold_params.get_error1_variance();
        let b_enc = match variance.to_u64() {
            Some(v) if v < 16 => BigUint::from(2 * v),
            _ => (BigUint::from(3u32) * variance).sqrt(),
        };

        let bits = &configs.bits;
        let bounds = &configs.bounds;
        let split = &configs.e_sm_split;
        let n = configs.params.degree();
        let l = configs.params.moduli().len();
        let radix_mod_q_str = join_display(&split.radix_mod_q, ", ");
        let bound_mod_q_str = join_display(&split.bound_mod_q, ", ");

        // C1 reads the smudging bound as one field element. A bound at or above the field (the
        // l-BFV secure-16384 preset, which has no C1) cannot be written at all: nargo rejects the
        // literal wherever a global references it. Such presets get only the split below.
        let c1_bound = if bounds.e_sm_bound < get_zkp_modulus().to_biguint().expect("positive") {
            format!(
                r#"use crate::core::threshold::pk_generation::Configs as PkGenerationConfigs;

pub global {prefix}_E_SM_BOUND: Field = {e_sm_bound};

pub global {prefix}_CONFIGS: PkGenerationConfigs<N, L> = PkGenerationConfigs::new(
    QIS,
    {prefix}_EEK_BOUND,
    {prefix}_SK_BOUND,
    {prefix}_E_SM_BOUND,
    {prefix}_E_SM_LIMB_BOUNDS,
    {prefix}_E_SM_QUOTIENT_BOUNDS,
    {prefix}_R_BOUNDS,
);
"#,
                e_sm_bound = bounds.e_sm_bound,
            )
        } else {
            String::new()
        };

        Ok(format!(
            r#"use crate::math::polynomial::Polynomial;

// Global configs for Threshold Public Key Generation circuit
pub global N: u32 = {n};
pub global L: u32 = {l};
pub global QIS: [Field; L] = [{qis_str}];

{crp_matrix_str}

/************************************
-------------------------------------
pk_generation (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

pub global {prefix}_BIT_EEK: u32 = {eek_bit};
pub global {prefix}_BIT_SK: u32 = {sk_bit};
pub global {prefix}_BIT_E_SM: u32 = {e_sm_bit};
pub global {prefix}_BIT_E_SM_LIFTED: u32 = {e_sm_lifted_bit};
pub global {prefix}_BIT_E_SM_QUOTIENT: u32 = {e_sm_quotient_bit};
pub global {prefix}_BIT_R: u32 = {r_bit};
pub global {prefix}_BIT_PK: u32 = {pk_bit};

pub global {prefix}_EEK_BOUND: Field = {eek_bound};
pub global {prefix}_SK_BOUND: Field = {sk_bound};
pub global {prefix}_E_SM_LIMB_BOUNDS: [Field; L] = [{e_sm_limb_bounds_str}];
pub global {prefix}_E_SM_QUOTIENT_BOUNDS: [Field; L] = [{e_sm_quotient_bounds_str}];
pub global {prefix}_R_BOUNDS: [Field; L] = [{r_bounds_str}];

pub global {prefix}_B_ENC: Field = {b_enc};

// The smudging bound split for the l-BFV C2b leaves: `B + e` and `B - e` are each
// `high * 2^SPLIT_BITS + low`, and their sum is `2B = TWICE_BOUND_HIGH * 2^SPLIT_BITS + TWICE_BOUND_LOW`.
pub global {prefix}_E_SM_SPLIT_BITS: u32 = {split_bits};
pub global {prefix}_BIT_E_SM_HIGH: u32 = {high_bit};
pub global {prefix}_BIT_E_SM_SPLIT_QUOTIENT: u32 = {quotient_bit};
pub global {prefix}_E_SM_TWICE_BOUND_HIGH: Field = {twice_bound_high};
pub global {prefix}_E_SM_TWICE_BOUND_LOW: Field = {twice_bound_low};
pub global {prefix}_E_SM_RADIX_MOD_Q: [Field; L] = [{radix_mod_q_str}];
pub global {prefix}_E_SM_BOUND_MOD_Q: [Field; L] = [{bound_mod_q_str}];

{c1_bound}"#,
            eek_bit = bits.eek_bit,
            sk_bit = bits.sk_bit,
            e_sm_bit = bits.e_sm_bit,
            e_sm_lifted_bit = bits.e_sm_lifted_bit,
            e_sm_quotient_bit = bits.e_sm_quotient_bit,
            r_bit = bits.r_bit,
            pk_bit = bits.pk_bit,
            eek_bound = bounds.eek_bound,
            sk_bound = bounds.sk_bound,
            split_bits = split.split_bits,
            high_bit = split.high_bit,
            quotient_bit = split.quotient_bit,
            twice_bound_high = split.twice_bound_high,
            twice_bound_low = split.twice_bound_low,
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
