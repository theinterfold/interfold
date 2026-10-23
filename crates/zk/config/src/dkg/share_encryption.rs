// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::field::join_display;
use crate::{CircuitMetadata, ConfigError};
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "share-encryption",
    prefix: "SHARE_ENCRYPTION",
    parameter: ParameterType::DKG,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    /// Plaintext modulus (as usize).
    pub t: usize,
    /// [q]_t reduced to ZKP field modulus.
    pub q_mod_t: BigUint,
    /// centered [q]_t reduced to ZKP field modulus.
    pub q_mod_t_centered: BigInt,
    /// CRT moduli (one per limb).
    /// k0_i = [1/q_i]_t per modulus, for scaling in the circuit.
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
    /// Constants for the scaled-quotient form of the `k0 * k1` term; see [`ScaledQuotient`].
    /// `available` is false for parameter sets that cannot use it, and the circuit then keeps the
    /// direct `k1` path.
    pub scaled_quotient: ScaledQuotient,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub msg_bit: u32,
    /// Width of the ct0-leg reduction quotient.
    pub ct0_r_bit: u32,
    /// Width of the ct1-leg reduction quotient.
    pub ct1_r_bit: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub msg_bound: BigUint,
    pub pk_bounds: Vec<BigUint>,
    /// Bounds on the ct0-leg reduction quotient, per CRT basis.
    pub ct0_r_bounds: Vec<BigUint>,
    /// Bounds on the ct1-leg reduction quotient, per CRT basis.
    pub ct1_r_bounds: Vec<BigUint>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScaledQuotient {
    pub available: bool,
    /// `k` in `SMALL_D = k * q - DELTA`; a power of two.
    pub k: u32,
    pub delta: BigUint,
    pub small_d: Vec<BigUint>,
    pub alpha: Vec<BigUint>,
    pub beta: Vec<BigUint>,
    /// Width of the rounding carry `z`, which is bounded by `SCALE`.
    pub z_bit: u32,
    /// `T = 2^t_pow_bit + t_gap`, the split `rounding_carries` checks against.
    pub t_pow_bit: u32,
    pub t_gap: BigUint,
    pub t_gap_bit: u32,
    /// Widths and offsets for the combined quotients. `Q0` is bounded asymmetrically because
    /// `SMALL_D * m` is non-negative and dominates its positive side, while the negative side only
    /// reaches about `N / 2` from the `pk * u` product.
    pub q0_bit: u32,
    pub q0_offset: BigUint,
    /// `Q0[1] - Q0[0]`: the limbs share the `SMALL_D * m` term, so their difference is far narrower
    /// than either. Bounding the difference rather than the second limb is what buys the second
    /// limb its width.
    pub q0_diff_bit: u32,
    pub q0_diff_offset: BigUint,
    pub q1_bit: u32,
    pub q1_offset: BigUint,
}
impl ScaledQuotient {
    /// Derives the constants, or returns `available: false` when the parameter set cannot use them.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        moduli: &[u64],
        t: u64,
        scale: u64,
        k0is: &[u64],
        n: u64,
        u_bound: u64,
        e0_bound: u128,
        e1_bound: u64,
        msg_bound: &BigUint,
    ) -> Self {
        // Zero-filled per-limb vectors rather than empty ones: codegen emits `[Field; L]` literals,
        // so the arity has to match even when the form is unavailable and the values go unused.
        let unavailable = || Self {
            available: false,
            k: 0,
            delta: BigUint::from(0u32),
            small_d: vec![BigUint::from(0u32); moduli.len()],
            alpha: vec![BigUint::from(0u32); moduli.len()],
            beta: vec![BigUint::from(0u32); moduli.len()],
            z_bit: 0,
            t_pow_bit: 0,
            t_gap: BigUint::from(0u32),
            t_gap_bit: 0,
            q0_bit: 0,
            q0_offset: BigUint::from(0u32),
            q0_diff_bit: 0,
            q0_diff_offset: BigUint::from(0u32),
            q1_bit: 0,
            q1_offset: BigUint::from(0u32),
        };

        let t_big = BigInt::from(t);
        let mut q_prod = BigInt::from(1u32);
        for m in moduli {
            q_prod *= BigInt::from(*m);
        }
        let delta = &q_prod / &t_big;
        let q0_modulus = BigInt::from(moduli[0]);

        // `DELTA < q` leaves no `k >= 1` with a small `k * q - DELTA`; this is the L = 1 case.
        if delta < q0_modulus {
            return unavailable();
        }
        // `DELTA / q` is just *below* an integer (3.99999999937 for secure-8192), so flooring gives
        // 3 and the power-of-two test fails. Round to nearest.
        let k_floor = &delta / &q0_modulus;
        let k_rounded = if (&delta % &q0_modulus) * BigInt::from(2u32) >= q0_modulus {
            k_floor + BigInt::from(1u32)
        } else {
            k_floor
        };
        let k_ratio = k_rounded.to_u64().unwrap_or(0);
        // `k` must be an exact power of two for `SMALL_D` to stay small across limbs.
        if k_ratio == 0 || (k_ratio & (k_ratio - 1)) != 0 {
            return unavailable();
        }
        let k = k_ratio;

        let mut small_d = Vec::new();
        let mut alpha = Vec::new();
        let mut beta = Vec::new();
        for (l, m) in moduli.iter().enumerate() {
            let q = BigInt::from(*m);
            let sd = BigInt::from(k) * &q - &delta;
            if sd <= BigInt::from(0u32) {
                return unavailable();
            }
            let k0 = BigInt::from(k0is[l]);
            // Both must divide exactly, or the substitution does not hold over the integers.
            let beta_num = &k0 * &t_big + BigInt::from(1u32);
            let alpha_num = &k0 * BigInt::from(scale) + &sd;
            if (&beta_num % &q) != BigInt::from(0u32) || (&alpha_num % &q) != BigInt::from(0u32) {
                return unavailable();
            }
            beta.push((&beta_num / &q).to_biguint().unwrap());
            alpha.push((&alpha_num / &q).to_biguint().unwrap());
            small_d.push(sd.to_biguint().unwrap());
        }

        // Bound each combined quotient from the identity's remaining terms.
        //
        // Every check has the form `(value + offset).assert_max_bit_size::<BIT>()`, i.e.
        // `value` in `[-offset, 2^BIT - offset]`. The bounds are asymmetric because `SMALL_D * m` is
        // non-negative and dominates the positive side, while the negative side only reaches about
        // `N * u / 2` from the `pk * u` product.
        let msg = msg_bound.to_bigint().unwrap();
        let n_big = BigInt::from(n);
        // Negative excursion shared by every quotient.
        let excursion = &n_big * BigInt::from(u_bound) / BigInt::from(2u32) + BigInt::from(1u32);

        let mut q0_max = BigInt::from(0u32);
        let mut q1_max = BigInt::from(0u32);
        for (l, m) in moduli.iter().enumerate() {
            let q = BigInt::from(*m);
            let qb = (&q - BigInt::from(1u32)) / BigInt::from(2u32);
            let sd = small_d[l].to_bigint().unwrap();
            let num0 = &qb
                + &n_big * &qb * BigInt::from(u_bound)
                + BigInt::from(e0_bound)
                + &sd * (&msg - BigInt::from(1u32))
                + BigInt::from(scale);
            let num1 = &qb + &n_big * &qb * BigInt::from(u_bound) + BigInt::from(e1_bound);
            let c0 = &num0 / &q;
            let c1 = &num1 / &q;
            if c0 > q0_max {
                q0_max = c0;
            }
            if c1 > q1_max {
                q1_max = c1;
            }
        }

        // `Q0[1] - Q0[0]`: both limbs carry `SMALL_D[l] * m / q[l]`, and those coefficients are
        // close, so the difference is driven by their *rational* gap rather than by either value.
        // Everything else (ct0, pk0 * u, e0, z) is a per-limb residue and contributes at most one
        // excursion on each side. Bounding the difference constrains the pair more tightly than
        // bounding the second limb on its own, which is where its width comes from.
        let (q0_diff_max, q0_diff_offset) = if moduli.len() > 1 {
            let q_a = BigInt::from(moduli[0]);
            let q_b = BigInt::from(moduli[1]);
            let sd_a = small_d[0].to_bigint().unwrap();
            let sd_b = small_d[1].to_bigint().unwrap();
            let gap = (&sd_b * &q_a - &sd_a * &q_b)
                .magnitude()
                .to_bigint()
                .unwrap();
            let spread = &gap * (&msg - BigInt::from(1u32)) / (&q_a * &q_b);
            let offset = BigInt::from(2u32) * &excursion;
            (spread + BigInt::from(2u32) * &excursion, offset)
        } else {
            (BigInt::from(0u32), excursion.clone())
        };

        let width = |v: &BigInt| -> u32 { v.magnitude().bits() as u32 };
        Self {
            available: true,
            k: k as u32,
            delta: delta.to_biguint().unwrap(),
            small_d,
            alpha,
            beta,
            z_bit: width(&BigInt::from(scale)),
            t_pow_bit: (t_big.bits() - 1) as u32,
            t_gap: (&t_big - (BigInt::from(1u32) << (t_big.bits() - 1)))
                .to_biguint()
                .unwrap(),
            t_gap_bit: width(&(&t_big - (BigInt::from(1u32) << (t_big.bits() - 1)))),
            q0_bit: width(&(&q0_max + &excursion)),
            q0_offset: excursion.to_biguint().unwrap(),
            q0_diff_bit: width(&(&q0_diff_max + &q0_diff_offset)),
            q0_diff_offset: q0_diff_offset.to_biguint().unwrap(),
            q1_bit: width(&(&q1_max + &excursion)),
            q1_offset: excursion.to_biguint().unwrap(),
        }
    }
}
impl Configs {
    pub fn new(dkg_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(dkg_params, ParameterType::DKG)?;

        let moduli = dkg_params.moduli().to_vec();
        let t = dkg_params.plaintext();
        let q = dkg_params.context_at_level(0)?.modulus();
        let q_mod_t = q % t;
        let q_mod_t_centered = compute_q_mod_t_centered(&q_mod_t, t);
        let k0is = compute_k0is(&moduli, t)?;

        let bounds = Bounds::new(dkg_params, &k0is)?;
        let bits = Bits::new(&bounds);
        let scaled_quotient = ScaledQuotient::derive(
            &moduli,
            t,
            q_mod_t
                .to_u64()
                .ok_or_else(|| ConfigError::Other("[q]_t does not fit u64".to_string()))?,
            &k0is,
            dkg_params.degree() as u64,
            bounds
                .u_bound
                .to_u64()
                .ok_or_else(|| ConfigError::Other("u_bound does not fit u64".to_string()))?,
            bounds
                .e0_bound
                .to_u128()
                .ok_or_else(|| ConfigError::Other("e0_bound does not fit u128".to_string()))?,
            bounds
                .e1_bound
                .to_u64()
                .ok_or_else(|| ConfigError::Other("e1_bound does not fit u64".to_string()))?,
            &bounds.msg_bound,
        );

        Ok(Configs {
            params: dkg_params.clone(),
            t: t as usize,
            q_mod_t,
            q_mod_t_centered,

            k0is,
            bits,
            bounds,
            scaled_quotient,
        })
    }
}
impl Bounds {
    fn new(dkg_params: &Arc<BfvParameters>, k0is: &[u64]) -> Result<Self, ConfigError> {
        let n = BigUint::from(dkg_params.degree());
        let ctx = dkg_params.context_at_level(0)?;

        let t = BigUint::from(dkg_params.plaintext());

        // CBD bound
        let cbd_bound = (dkg_params.variance() * 2) as u64;
        // Uniform bound
        let uniform_bound = (dkg_params.get_error1_variance() * 3u32).sqrt();

        let u_bound = BigUint::from(SecretKey::sk_bound() as u128);

        // e0 = e1 in the fhe.rs
        let e0_bound = if dkg_params.get_error1_variance() <= &BigUint::from(16u32) {
            BigUint::from(cbd_bound)
        } else {
            uniform_bound
        };
        let e1_bound = BigUint::from(cbd_bound); // e1 = e2 in the fhe.rs

        // Message bound: the message is in [0, t), and `range_check_standard` takes an **exclusive**
        // upper bound, so this is `t`. Passing `t - 1` rejected the legitimate coefficient `t - 1`.

        // `k1` lies in `[0, t)`, so its largest magnitude is `t - 1`.
        let k1_max = &t - 1u32;

        // Calculate bounds for each CRT basis
        let mut pk_bounds = Vec::with_capacity(ctx.moduli().len());
        let mut ct0_r_bounds = Vec::with_capacity(ctx.moduli().len());
        let mut ct1_r_bounds = Vec::with_capacity(ctx.moduli().len());

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_big = BigUint::from(**qi);
            let qi_bound = (&qi_big - 1u32) / 2u32;

            let k0qi = BigUint::from(k0is[i]);

            // PK and R2 bounds (same as qi_bound)
            pk_bounds.push(qi_bound.clone());

            let e0_bound_i = &e0_bound % &qi_big;

            // `r` is the quotient of the mod-q reduction in the identity the circuit checks:
            //   ct = pk * u + e + k0 * k1 + q * r   (mod X^N + 1, over the integers)
            // Bounding each term on the right and dividing by q bounds `r`. Folding modulo X^N + 1
            // does not change this bound, so it is the same expression the unreduced `r1` used.
            let ct0_r_bound =
                (&k1_max * &k0qi + ((&n * &u_bound + 2u32) * &qi_bound + e0_bound_i)) / &qi_big;
            ct0_r_bounds.push(ct0_r_bound);

            // The ct1 leg has no `k0 * k1` term.
            let ct1_r_bound = ((&n * &u_bound + 2u32) * &qi_bound + &e1_bound) / &qi_big;
            ct1_r_bounds.push(ct1_r_bound);
        }

        Ok(Bounds {
            pk_bounds,
            u_bound,
            e0_bound,
            e1_bound,
            msg_bound: t,
            ct0_r_bounds,
            ct1_r_bounds,
        })
    }
}
impl Bits {
    fn new(data: &Bounds) -> Self {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(max_pk_bound);
        let ct_bit = calculate_bit_width(max_pk_bound);
        let u_bit = calculate_bit_width(&data.u_bound);
        let e0_bit = calculate_bit_width(&data.e0_bound);
        let e1_bit = calculate_bit_width(&data.e1_bound);
        let msg_bit = calculate_bit_width(&data.msg_bound);
        // Each `r` is two-sided, so take the widest bound across the CRT bases.
        let ct0_r_bit = calculate_bit_width(data.ct0_r_bounds.iter().max().unwrap());
        let ct1_r_bit = calculate_bit_width(data.ct1_r_bounds.iter().max().unwrap());

        Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            msg_bit,
            ct0_r_bit,
            ct1_r_bit,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;

        let qis_str = join_display(&configs.params.moduli(), ", ");
        let small_d_str = join_display(&configs.scaled_quotient.small_d, ", ");
        let alpha_str = join_display(&configs.scaled_quotient.alpha, ", ");
        let beta_str = join_display(&configs.scaled_quotient.beta, ", ");
        let k0is_str = join_display(&configs.k0is, ", ");
        let pk_bounds_str = join_display(&configs.bounds.pk_bounds, ", ");
        let ct0_r_bounds_str = join_display(&configs.bounds.ct0_r_bounds, ", ");
        let ct1_r_bounds_str = join_display(&configs.bounds.ct1_r_bounds, ", ");

        Ok(format!(
            r#"use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};

/************************************
-------------------------------------
share_encryption_sk (CIRCUIT 3a)
share_encryption_e_sm (CIRCUIT 3b)
-------------------------------------
************************************/

pub global {}_BIT_PK: u32 = {};
pub global {}_BIT_CT: u32 = {};
pub global {}_BIT_U: u32 = {};
pub global {}_BIT_E0: u32 = {};
pub global {}_BIT_E1: u32 = {};
pub global {}_BIT_MSG: u32 = {};
pub global {}_CT0_BIT_R: u32 = {};
pub global {}_CT1_BIT_R: u32 = {};

pub global {}_K0IS: [Field; L] = [{}];
pub global {}_PK_BOUNDS: [Field; L] = [{}];
pub global {}_E0_BOUND: Field = {};
pub global {}_E1_BOUND: Field = {};
pub global {}_U_BOUND: Field = {};
pub global {}_CT0_R_BOUNDS: [Field; L] = [{}];
pub global {}_CT1_R_BOUNDS: [Field; L] = [{}];
pub global {}_MSG_BOUND: Field = {};

// Scaled-quotient form of the `k0 * k1` term. `SCALED_QUOTIENT` is false for parameter sets that
// cannot use it (notably L = 1, where `DELTA < q`); the circuit then keeps the direct `k1` path and
// the constants below go unused.
pub global {}_SCALED_QUOTIENT: bool = {};
pub global {}_SCALE_K: Field = {};
pub global {}_DELTA: Field = {};
pub global {}_SMALL_D: [Field; L] = [{}];
pub global {}_ALPHA: [Field; L] = [{}];
pub global {}_BETA: [Field; L] = [{}];
pub global {}_BIT_Z: u32 = {};
pub global {}_T_POW_BIT: u32 = {};
pub global {}_T_GAP: Field = {};
pub global {}_T_GAP_BIT: u32 = {};
pub global {}_BIT_Q0: u32 = {};
pub global {}_Q0_OFFSET: Field = {};
pub global {}_BIT_Q0_DIFF: u32 = {};
pub global {}_Q0_DIFF_OFFSET: Field = {};
pub global {}_BIT_Q1: u32 = {};
pub global {}_Q1_OFFSET: Field = {};

pub global {}_CONFIGS: ShareEncryptionConfigs<L> = ShareEncryptionConfigs::new(
    PLAINTEXT_MODULUS,
    Q_MOD_T,
    QIS,
    {}_K0IS,
    {}_PK_BOUNDS,
    {}_E0_BOUND,
    {}_E1_BOUND,
    {}_U_BOUND,
    {}_CT0_R_BOUNDS,
    {}_CT1_R_BOUNDS,
    {}_MSG_BOUND,
    {}_SCALED_QUOTIENT,
    {}_SMALL_D,
    {}_ALPHA,
    {}_BETA,
    {}_Q0_OFFSET,
    {}_Q0_DIFF_OFFSET,
    {}_Q1_OFFSET,
);
"#,
            configs.params.degree(),
            configs.params.moduli().len(),
            qis_str,
            configs.t,
            configs.q_mod_t,
            configs.q_mod_t_centered,
            prefix,
            configs.bits.pk_bit,
            prefix,
            configs.bits.ct_bit,
            prefix,
            configs.bits.u_bit,
            prefix,
            configs.bits.e0_bit,
            prefix,
            configs.bits.e1_bit,
            prefix,
            configs.bits.msg_bit,
            prefix,
            configs.bits.ct0_r_bit,
            prefix,
            configs.bits.ct1_r_bit,
            prefix,
            k0is_str,
            prefix,
            pk_bounds_str,
            prefix,
            configs.bounds.e0_bound,
            prefix,
            configs.bounds.e1_bound,
            prefix,
            configs.bounds.u_bound,
            prefix,
            ct0_r_bounds_str,
            prefix,
            ct1_r_bounds_str,
            prefix,
            configs.bounds.msg_bound,
            prefix,
            configs.scaled_quotient.available,
            prefix,
            configs.scaled_quotient.k,
            prefix,
            configs.scaled_quotient.delta,
            prefix,
            small_d_str,
            prefix,
            alpha_str,
            prefix,
            beta_str,
            prefix,
            configs.scaled_quotient.z_bit,
            prefix,
            configs.scaled_quotient.t_pow_bit,
            prefix,
            configs.scaled_quotient.t_gap,
            prefix,
            configs.scaled_quotient.t_gap_bit,
            prefix,
            configs.scaled_quotient.q0_bit,
            prefix,
            configs.scaled_quotient.q0_offset,
            prefix,
            configs.scaled_quotient.q0_diff_bit,
            prefix,
            configs.scaled_quotient.q0_diff_offset,
            prefix,
            configs.scaled_quotient.q1_bit,
            prefix,
            configs.scaled_quotient.q1_offset,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
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
    pub fn for_preset(preset: BfvPreset) -> Result<Self, ConfigError> {
        let (_, dkg_params) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&dkg_params)
    }
}

#[cfg(test)]
mod scaled_quotient_tests {
    use super::*;
    use e3_fhe_params::utils::compute_k0is;
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};

    fn derive_for(preset: BfvPreset) -> (ScaledQuotient, Vec<u64>, u64) {
        let config = Configs::for_preset(preset).unwrap();
        let moduli = config.params.moduli().to_vec();
        let t = config.params.plaintext();
        (config.scaled_quotient, moduli, t)
    }

    /// The substitution only holds if both numerators divide exactly. `derive` returns
    /// `available: false` rather than rounding, so re-check the identities on what it produced.
    fn assert_identities_hold_exactly(preset: BfvPreset) {
        let (sq, moduli, t) = derive_for(preset);
        assert!(
            sq.available,
            "{preset:?} should admit the scaled-quotient form"
        );

        let (_, dkg) = build_pair_for_preset(preset).unwrap();
        let scale = (dkg.context_at_level(0).unwrap().modulus() % t)
            .to_u64()
            .unwrap();
        let k0is = compute_k0is(&moduli, t).unwrap();

        let t_big = BigInt::from(t);
        let mut q_prod = BigInt::from(1u32);
        for m in &moduli {
            q_prod *= BigInt::from(*m);
        }
        // DELTA * T + SCALE == prod(q)
        assert_eq!(
            sq.delta.to_bigint().unwrap() * &t_big + BigInt::from(scale),
            q_prod,
            "DELTA * T + SCALE must reconstruct prod(q)"
        );
        for (l, m) in moduli.iter().enumerate() {
            let q = BigInt::from(*m);
            let k0 = BigInt::from(k0is[l]);
            // SMALL_D = k * q - DELTA
            assert_eq!(
                sq.small_d[l].to_bigint().unwrap(),
                BigInt::from(sq.k) * &q - sq.delta.to_bigint().unwrap(),
                "SMALL_D[{l}]"
            );
            // k0 * T + 1 == BETA * q
            assert_eq!(
                &k0 * &t_big + BigInt::from(1u32),
                sq.beta[l].to_bigint().unwrap() * &q,
                "BETA[{l}] identity"
            );
            // k0 * SCALE + SMALL_D == ALPHA * q
            assert_eq!(
                &k0 * BigInt::from(scale) + sq.small_d[l].to_bigint().unwrap(),
                sq.alpha[l].to_bigint().unwrap() * &q,
                "ALPHA[{l}] identity"
            );
        }
    }

    #[test]
    fn secure_identities_hold_exactly() {
        assert_identities_hold_exactly(BfvPreset::SecureThreshold8192);
    }

    #[test]
    fn insecure_identities_hold_exactly() {
        assert_identities_hold_exactly(BfvPreset::InsecureThreshold64);
    }
}
