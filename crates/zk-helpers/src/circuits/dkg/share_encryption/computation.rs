// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the share-encryption circuit: configs, bounds, bit widths, and input.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) plaintext, ciphertext, and encryption randomness. Input values are
//! normalized for the ZKP field so the Noir circuit's range checks and commitment checks succeed.

use crate::circuits::commitments::{
    compute_dkg_pk_commitment, compute_sc_party_share_root_commitment,
    compute_share_encryption_commitment_from_message,
};
use crate::dkg::share_encryption::ShareEncryptionCircuit;
use crate::dkg::share_encryption::ShareEncryptionCircuitData;
use crate::math::fold_negacyclic;
use crate::math::{compute_k0is, compute_q_mod_t_centered, plaintext_poly_u64};
use crate::polynomial_to_toml_json;
use crate::utils::{compute_modulus_bit, compute_msg_bit};
use crate::CircuitsErrors;
use crate::{calculate_bit_width, crt_polynomial_to_toml_json};
use crate::{compute_q_mod_t, compute_q_product};
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use fhe::bfv::SecretKey;
use fhe_math::zq::Modulus;
use itertools::izip;
use num_bigint::ToBigInt;
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, ToPrimitive};
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelBridge;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`ShareEncryptionCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct ShareEncryptionOutput {
    /// Coefficient bounds used to derive bit widths.
    pub bounds: Bounds,
    /// Bit widths used by the Noir prover for packing.
    pub bits: Bits,
    /// Input for the share-encryption circuit.
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`ShareEncryptionCircuit`].
impl CircuitComputation for ShareEncryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Output = ShareEncryptionOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(ShareEncryptionOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

/// Global configs for the share-encryption circuit: plaintext modulus, [q]_t, moduli, k0is, bits, and bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    /// Circuit degree N.
    pub n: usize,
    /// Number of CRT moduli L.
    pub l: usize,
    /// Share computation chunk size (matches SHARE_COMPUTATION_CHUNK_SIZE).
    pub chunk_size: usize,
    /// Plaintext modulus (as usize).
    pub t: usize,
    /// [q]_t reduced to ZKP field modulus.
    pub q_mod_t: BigUint,
    /// centered [q]_t reduced to ZKP field modulus.
    pub q_mod_t_centered: BigInt,
    /// CRT moduli (one per limb).
    pub moduli: Vec<u64>,
    /// k0_i = [1/q_i]_t per modulus, for scaling in the circuit.
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
    /// Constants for the scaled-quotient form of the `k0 * k1` term; see [`ScaledQuotient`].
    /// `available` is false for parameter sets that cannot use it, and the circuit then keeps the
    /// direct `k1` path.
    pub scaled_quotient: ScaledQuotient,
}

/// Bit widths used by the Noir prover (e.g. for packing coefficients).
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

/// Coefficient bounds for polynomials (used to derive bit widths).
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

/// Input for the share-encryption circuit: CRT limbs for pk, ct, randomness, and message.
///
/// Coefficients are reduced to the ZKP field modulus for serialization. The circuit verifies
/// that the ciphertext and commitments match the public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Whether these inputs are for `share_encryption_chunked` (the l-BFV path), which also takes
    /// `party_idx` and `mod_idx`.
    pub chunked: bool,
    pub party_idx: u32,
    pub mod_idx: u32,
    /// Public key and ciphertext polynomials in CRT form (per modulus).
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    /// ct0-leg reduction quotient, already reduced modulo `X^N + 1`.
    pub ct0_r: CrtPolynomial,
    /// ct1-leg reduction quotient, already reduced modulo `X^N + 1`.
    pub ct1_r: CrtPolynomial,
    /// Carries with `k1 == q_mod_t * m - t * z` and `k1` in `[0, t)`, so the circuit's scaled path
    /// never builds `k1`. A witness rather than an in-circuit hint, matching every other quotient
    /// here. Always produced; the direct path ignores it.
    pub z: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub message: Polynomial,
    pub pk_commitment: BigInt,
    pub msg_commitment: BigInt,
}

/// Constants for C3's scaled-quotient form, when the parameter set admits it.
///
/// C3's identity carries `k0 * k1`, where `k1` is the message scaled by `SCALE = Q mod T` and
/// reduced into `[0, T)`. Computing `k1` costs a modular multiply per coefficient. It can instead
/// be folded into the mod-q quotient:
///
/// ```text
///   k1       = SCALE * m - T * z                 (z is the reduction carry)
///   k0 * T     = BETA * q - 1
///   k0 * SCALE = ALPHA * q - SMALL_D
///   => k0 * k1 = q * (ALPHA * m - BETA * z) - SMALL_D * m + z
///   => ct0     = pk0 * u + e0 - SMALL_D * m + z + q * Q0,  Q0 = r0 + ALPHA * m - BETA * z
/// ```
///
/// The win comes from `Q0` being far narrower than the `r0` it replaces, which needs `SMALL_D` to
/// be small. With `DELTA = floor(prod(q) / T)` and `SMALL_D = k * q - DELTA`, that holds when
/// `DELTA` is close to an integer multiple of `q`. Because every modulus here sits just above a
/// power of two, `DELTA / q` is close to `2^(bits(q) - bits(T))`, so `k` is that power of two and
/// `SMALL_D` is only as large as the moduli's gaps above their powers of two.
///
/// `available` is false when the parameter set does not admit the form -- notably when `DELTA < q`,
/// which happens at `L = 1` because `prod(q) / T` is then smaller than `q` itself. The circuit
/// gates on this and keeps the direct `k1` path in that case.
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

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = dkg_params.moduli().to_vec();
        let t = dkg_params.plaintext();
        let q = compute_q_product(&moduli);
        let q_mod_t = compute_q_mod_t(&q, t);
        let q_mod_t_centered = compute_q_mod_t_centered(&moduli, t);
        let k0is = compute_k0is(&moduli, t)?;

        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        let scaled_quotient =
            ScaledQuotient::derive(
                &moduli,
                t,
                q_mod_t
                    .to_u64()
                    .ok_or_else(|| CircuitsErrors::Other("[q]_t does not fit u64".to_string()))?,
                &k0is,
                dkg_params.degree() as u64,
                bounds
                    .u_bound
                    .to_u64()
                    .ok_or_else(|| CircuitsErrors::Other("u_bound does not fit u64".to_string()))?,
                bounds.e0_bound.to_u128().ok_or_else(|| {
                    CircuitsErrors::Other("e0_bound does not fit u128".to_string())
                })?,
                bounds.e1_bound.to_u64().ok_or_else(|| {
                    CircuitsErrors::Other("e1_bound does not fit u64".to_string())
                })?,
                &bounds.msg_bound,
            );

        Ok(Configs {
            n: dkg_params.degree(),
            l: moduli.len(),
            chunk_size: data.chunk_size as usize,
            t: t as usize,
            q_mod_t,
            q_mod_t_centered,
            moduli,
            k0is,
            bits,
            bounds,
            scaled_quotient,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = crate::utils::ZkHelpersUtilsError;

    fn compute(_: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let ct_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let u_bit = calculate_bit_width(BigInt::from(data.u_bound.clone()));
        let e0_bit = calculate_bit_width(BigInt::from(data.e0_bound.clone()));
        let e1_bit = calculate_bit_width(BigInt::from(data.e1_bound.clone()));
        let msg_bit = calculate_bit_width(BigInt::from(data.msg_bound.clone()));
        // Each `r` is two-sided, so take the widest bound across the CRT bases.
        let ct0_r_bit = calculate_bit_width(BigInt::from(
            data.ct0_r_bounds.iter().max().unwrap().clone(),
        ));
        let ct1_r_bit = calculate_bit_width(BigInt::from(
            data.ct1_r_bounds.iter().max().unwrap().clone(),
        ));

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            msg_bit,
            ct0_r_bit,
            ct1_r_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let n = BigInt::from(dkg_params.degree());
        let ctx = dkg_params.context_at_level(0)?;

        let t = BigInt::from(dkg_params.plaintext());

        let error_bound = crate::utils::error_sampler_bound(dkg_params.get_error1_variance())
            .to_bigint()
            .ok_or_else(|| {
                CircuitsErrors::Other("Failed to convert error bound to BigInt".into())
            })?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in fhe.rs; e1 = e2 in fhe.rs.
        let e0_bound = error_bound.to_u128().unwrap();
        let e1_bound = (dkg_params.variance() * 2) as u64;

        // Message bound: the message is in [0, t), and `range_check_standard` takes an **exclusive**
        // upper bound, so this is `t`. Passing `t - 1` rejected the legitimate coefficient `t - 1`.
        let msg_bound = t.clone();

        // `k1` lies in `[0, t)`, so its largest magnitude is `t - 1`.
        let k1_max = &t - BigInt::from(1);

        // Calculate bounds for each CRT basis
        let moduli: Vec<u64> = ctx.moduli_operators().iter().map(|q| **q).collect();
        let k0is = compute_k0is(&moduli, dkg_params.plaintext())?;

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut ct0_r_bounds: Vec<BigInt> = Vec::new();
        let mut ct1_r_bounds: Vec<BigInt> = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            let k0qi = BigInt::from(k0is[i]);

            // PK and R2 bounds (same as qi_bound)
            pk_bounds.push(qi_bound.clone());

            let e0_bound_i = e0_bound % qi_bigint.clone();

            // `r` is the quotient of the mod-q reduction in the identity the circuit checks:
            //   ct = pk * u + e + k0 * k1 + q * r   (mod X^N + 1, over the integers)
            // Bounding each term on the right and dividing by q bounds `r`. Folding modulo X^N + 1
            // does not change this bound, so it is the same expression the unreduced `r1` used.
            let ct0_r_bound: BigInt = (&k1_max * k0qi.abs()
                + ((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;
            ct0_r_bounds.push(ct0_r_bound);

            // The ct1 leg has no `k0 * k1` term.
            let ct1_r_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            ct1_r_bounds.push(ct1_r_bound);
        }

        Ok(Bounds {
            pk_bounds: pk_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            msg_bound: BigUint::from(msg_bound.to_u128().unwrap()),
            ct0_r_bounds: ct0_r_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            ct1_r_bounds: ct1_r_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
        // row_index (mod_idx) indexes the threshold secret's modulus domain (one C3 proof per
        // threshold Shamir row); it is not bounded by the DKG moduli count.
        let threshold_l = threshold_params.moduli().len();

        let pk = data.public_key.clone();
        let pt = data.plaintext.clone();
        let ct = &data.ciphertext;
        let u = &data.u_rns;
        let e0 = &data.e0_rns;
        let e1 = &data.e1_rns;

        let ctx = dkg_params.context_at_level(pt.level())?;
        let moduli = dkg_params.moduli();

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let t = dkg_params.plaintext();
        let k0is = compute_k0is(moduli, t)?;
        let n = dkg_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| CircuitsErrors::Other("Failed to convert q_mod_t to u64".into()))?;

        let mut e0_mod_q = Polynomial::from_fhe_polynomial(e0);
        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        let mut k1_u64 = plaintext_poly_u64(&pt)?;
        Modulus::new(t)
            .map_err(|e| CircuitsErrors::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t);

        let mut k1 = Polynomial::from_u64_vector(k1_u64);
        k1.reverse();

        let mut message = Polynomial::from_u64_vector(plaintext_poly_u64(&pt)?);
        message.reverse();

        let mut u = CrtPolynomial::from_fhe_polynomial(u).limb(0).clone();
        let mut e1 = CrtPolynomial::from_fhe_polynomial(e1).limb(0).clone();

        u.center(&BigInt::from(moduli[0]));
        u.reverse();

        e1.center(&BigInt::from(moduli[0]));
        e1.reverse();

        let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
        let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk.c[0]);
        let mut pk1 = CrtPolynomial::from_fhe_polynomial(&pk.c[1]);

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();

        ct0.center(moduli)?;
        ct1.center(moduli)?;
        pk0.center(moduli)?;
        pk1.center(moduli)?;

        // e0 is never CRT-decomposed here (see the `e0is`/`e0_quotients` removal note below), so
        // its shape isn't part of this check.
        crate::utils::verify_crt_shapes(&[&ct0, &ct1, &pk0, &pk1], moduli.len(), n as usize)
            .map_err(|e| CircuitsErrors::Other(format!("C3 CRT shape mismatch: {e}")))?;

        let canonical =
            crate::ciphernodes_committee::canonical_committee_for_circuit(&data.committee)
                .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        if data.party_idx as usize >= canonical.n {
            return Err(CircuitsErrors::Other(format!(
                "C3 party_idx {} out of range: committee N is {}",
                data.party_idx, canonical.n
            )));
        }
        if data.mod_idx as usize >= threshold_l {
            return Err(CircuitsErrors::Other(format!(
                "C3 mod_idx {} out of range: threshold L is {}",
                data.mod_idx, threshold_l
            )));
        }

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;

        let mut results: Vec<_> = izip!(
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i))| {
            let qi_bigint = BigInt::from(**qi);

            // The circuit uses the lifted `e0` directly, with no CRT decomposition. That is only
            // correct while `e0_bound < q_i / 2`, which makes the centered residue equal to `e0`.
            // DKG keeps `error1_variance <= 16`, so the bound is `2 * variance`. If a parameter
            // change breaks that, fail here instead of emitting a witness the circuit misreads.
            assert!(
                e0_mod_q
                    .coefficients()
                    .iter()
                    .all(|c| c.abs() * 2 < qi_bigint),
                "DKG e0 must fit in every modulus: |e0| >= q_{i} / 2, so e0_bound >= q_i / 2"
            );

            let k0qi = BigInt::from(k0is[i]);
            let ki = k1.scalar_mul(&k0qi);

            // e0 is used directly here, not a per-modulus CRT limb: e0_bound is identical to
            // e1_bound at every preset (both tiny, nowhere near qi), so e0 already fits in a
            // single residue for every modulus - same treatment as e1 (see `ct1i_hat` below).
            // There is no honest e0_quotient other than zero, so it was never a witness worth
            // generating.
            let ct0i_hat = {
                let pk0i_u_times = pk0i.mul(&u);
                let e0_plus_ki = e0_mod_q.add(&ki);

                assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                assert_eq!((e0_plus_ki.coefficients().len() as u64) - 1, n - 1);

                pk0i_u_times.add(&e0_plus_ki)
            };

            assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let ct1i_hat = {
                let pk1i_u_times = pk1i.mul(&u);

                assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                pk1i_u_times.add(&e1)
            };
            assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // Both quotients are pinned by the reduced identities themselves:
            //   ct0i = (pk0i * u + e0 + k0qi * k1 mod X^N + 1) + qi * ct0_r
            //   ct1i = (pk1i * u + e1            mod X^N + 1) + qi * ct1_r
            // so folding the hats computed above and dividing by qi gives them. The hats already
            // hold the products, so nothing is recomputed and the cyclotomic quotients never exist.
            //
            // Everything here is O(N). Going through `decompose_residue` plus
            // `Polynomial::reduce_by_cyclotomic` instead ran four generic long divisions per limb --
            // 536,870,904 BigInt multiply-subtracts at N = 8192, L = 2 -- and recomputed both
            // products for the self-checks. Measured, that was 8.66s of witness generation per C3
            // proof, and C3 runs about 1,512 times per DKG.
            let ct0_reduced_hat = fold_negacyclic(&ct0i_hat, n as usize);
            let ct1_reduced_hat = fold_negacyclic(&ct1i_hat, n as usize);

            // Exact division is the identity: `div` rejects any coefficient that is not a multiple of
            // qi, so a successful division proves an integer quotient closes the reduced equation and
            // a wrong fold surfaces as a divisibility failure.
            let (ct0_r, ct0_remainder) = ct0i
                .sub(&ct0_reduced_hat)
                .div(&Polynomial::constant(qi_bigint.clone()))
                .expect("ct0i - (pk0i * u + e0 + k0qi * k1 mod X^N + 1) must be divisible by qi");
            assert!(
                ct0_remainder.is_zero(),
                "reduced C3 ct0 identity must divide exactly by qi"
            );
            let (ct1_r, ct1_remainder) = ct1i
                .sub(&ct1_reduced_hat)
                .div(&Polynomial::constant(qi_bigint.clone()))
                .expect("ct1i - (pk1i * u + e1 mod X^N + 1) must be divisible by qi");
            assert!(
                ct1_remainder.is_zero(),
                "reduced C3 ct1 identity must divide exactly by qi"
            );

            // Restate both identities on the derived witnesses. O(N), and independent of `div`.
            assert!(
                ct0i
                    .sub(&ct0_reduced_hat.add(&ct0_r.scalar_mul(&qi_bigint)))
                    .is_zero(),
                "reduced C3 ct0 identity must hold: ct0i == pk0i * u + e0 + k0qi * k1 + qi * r (mod X^N + 1)"
            );
            assert!(
                ct1i
                    .sub(&ct1_reduced_hat.add(&ct1_r.scalar_mul(&qi_bigint)))
                    .is_zero(),
                "reduced C3 ct1 identity must hold: ct1i == pk1i * u + e1 + qi * r (mod X^N + 1)"
            );

            (i, ct0i, ct1i, pk0i, pk1i, ct0_r, ct1_r)
        })
        .collect();

        results.sort_by_key(|(i, ..)| *i);

        let mut pk0is = Vec::with_capacity(results.len());
        let mut pk1is = Vec::with_capacity(results.len());
        let mut ct0is = Vec::with_capacity(results.len());
        let mut ct1is = Vec::with_capacity(results.len());
        let mut ct0_r = Vec::with_capacity(results.len());
        let mut ct1_r = Vec::with_capacity(results.len());

        for (_, ct0i, ct1i, pk0i, pk1i, ct0_ri, ct1_ri) in results {
            pk0is.push(pk0i);
            pk1is.push(pk1i);
            ct0is.push(ct0i);
            ct1is.push(ct1i);
            ct0_r.push(ct0_ri);
            ct1_r.push(ct1_ri);
        }

        let pk0is = CrtPolynomial::new(pk0is);
        let pk1is = CrtPolynomial::new(pk1is);
        let ct0is = CrtPolynomial::new(ct0is);
        let ct1is = CrtPolynomial::new(ct1is);
        let ct0_r = CrtPolynomial::new(ct0_r);
        let ct1_r = CrtPolynomial::new(ct1_r);

        // z[j] = floor(q_mod_t * m[j] / t), i.e. the carry that puts `q_mod_t * m - t * z` in
        // `[0, t)`. The circuit pins it by asserting that window, so an off-by-one here fails there
        // rather than passing silently.
        let t_big = BigInt::from(dkg_params.plaintext());
        let scale_big = BigInt::from(compute_q_mod_t(
            &compute_q_product(dkg_params.moduli()),
            dkg_params.plaintext(),
        ));
        let z_coeffs: Vec<BigInt> = message
            .coefficients()
            .iter()
            .map(|m| (&scale_big * m) / &t_big)
            .collect();
        let z = CrtPolynomial::new(vec![Polynomial::new(z_coeffs)]);

        let pk_bit = compute_modulus_bit(&dkg_params);
        let msg_bit = compute_msg_bit(&dkg_params);
        let pk_commitment = compute_dkg_pk_commitment(&pk0is, &pk1is, pk_bit);
        // The trBFV C3 binds the share to C2's single commitment; the l-BFV path's chunked C2
        // commits each share as a chunk root keyed by (party, modulus) (`share_encryption_chunked`).
        let chunked = e3_fhe_params::supports_lbfv(preset);
        if chunked && data.chunk_size == 0 {
            return Err(CircuitsErrors::Sample(
                "C3 chunk size must be greater than zero".to_string(),
            ));
        }
        if chunked
            && !message
                .coefficients()
                .len()
                .is_multiple_of(data.chunk_size as usize)
        {
            return Err(CircuitsErrors::Sample(format!(
                "C3 chunk size {} must divide message degree {}",
                data.chunk_size,
                message.coefficients().len()
            )));
        }
        let msg_commitment = if chunked {
            compute_sc_party_share_root_commitment(
                data.party_idx as usize,
                data.mod_idx as usize,
                &message,
                msg_bit,
                data.chunk_size as usize,
            )
        } else {
            compute_share_encryption_commitment_from_message(&message, msg_bit)
        };

        Ok(Inputs {
            chunked,
            party_idx: data.party_idx,
            mod_idx: data.mod_idx,
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            ct0_r,
            ct1_r,
            z,
            e0: e0_mod_q,
            e1,
            u,
            message,
            pk_commitment,
            msg_commitment,
        })
    }

    // Used as input for Nargo execution.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let pk1is = crt_polynomial_to_toml_json(&self.pk1is);
        let ct0is = crt_polynomial_to_toml_json(&self.ct0is);
        let ct1is = crt_polynomial_to_toml_json(&self.ct1is);
        let u = polynomial_to_toml_json(&self.u);
        let e0 = polynomial_to_toml_json(&self.e0);
        let e1 = polynomial_to_toml_json(&self.e1);
        let message = polynomial_to_toml_json(&self.message);
        let ct0_r = crt_polynomial_to_toml_json(&self.ct0_r);
        let ct1_r = crt_polynomial_to_toml_json(&self.ct1_r);
        let z = crt_polynomial_to_toml_json(&self.z);
        let pk_commitment = self.pk_commitment.to_string();
        let msg_commitment = self.msg_commitment.to_string();

        let json = serde_json::json!({
            "pk0is": pk0is,
            "pk1is": pk1is,
            "ct0is": ct0is,
            "ct1is": ct1is,
            "u": u,
            "e0": e0,
            "e1": e1,
            "message": message,
            "ct0_r": ct0_r,
            "ct1_r": ct1_r,
            "z": z,
            "expected_pk_commitment": pk_commitment,
            "expected_message_commitment": msg_commitment,
        });
        let mut json = json;
        if self.chunked {
            json["party_idx"] = serde_json::json!(self.party_idx);
            json["mod_idx"] = serde_json::json!(self.mod_idx);
        }

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
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();

        let bounds = Bounds::compute(BfvPreset::InsecureThreshold, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold, &bounds).unwrap();

        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(BigInt::from(max_pk_bound.clone()));

        assert_eq!(max_pk_bound.clone(), BigUint::from(72057594037914240u128));
        assert_eq!(bits.pk_bit, expected_bits);
        assert_eq!(
            bounds.msg_bound,
            BigUint::from(
                BfvPreset::InsecureThreshold
                    .build_pair()
                    .unwrap()
                    .1
                    .plaintext()
            )
        );
    }

    #[test]
    fn test_input_message_consistency() {
        let sd = BfvPreset::InsecureThreshold.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold, &sample).unwrap();

        // inputs.message is plaintext coefficients (reversed, as used in circuit)
        let expected_message =
            Polynomial::from_u64_vector(plaintext_poly_u64(&sample.plaintext).unwrap());
        let mut expected = expected_message;
        expected.reverse();

        assert_eq!(inputs.message.coefficients(), expected.coefficients());
    }

    #[test]
    fn generated_share_encryption_witness_respects_ct0_r_bounds() {
        let preset = BfvPreset::InsecureThreshold;
        let sample = ShareEncryptionCircuitData::generate_sample(
            preset,
            CiphernodesCommitteeSize::Minimum.values(),
            DkgInputType::SecretKey,
            preset.search_defaults().unwrap().z,
        )
        .unwrap();
        let bounds = Bounds::compute(preset, &sample).unwrap();
        let inputs = Inputs::compute(preset, &sample).unwrap();

        for (i, limb) in inputs.ct0_r.limbs.iter().enumerate() {
            let bound = BigInt::from(bounds.ct0_r_bounds[i].clone());
            for (j, coefficient) in limb.coefficients().iter().enumerate() {
                assert!(
                    coefficient.magnitude() <= bound.magnitude(),
                    "ct0_r[{i}][{j}] = {coefficient} outside [-{bound}, {bound}]"
                );
            }
        }
    }
}

#[cfg(test)]
mod scaled_quotient_tests {
    use super::*;
    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use crate::{compute_k0is, compute_q_mod_t, compute_q_product};
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};

    fn derive_for(preset: BfvPreset) -> (ScaledQuotient, Vec<u64>, u64) {
        let (_, dkg) = build_pair_for_preset(preset).unwrap();
        let moduli = dkg.moduli().to_vec();
        let t = dkg.plaintext();
        let scale = compute_q_mod_t(&compute_q_product(&moduli), t);
        let k0is = compute_k0is(&moduli, t).unwrap();
        // `Bounds::compute` ignores its data argument, but still needs one.
        let sd = preset.search_defaults().unwrap();
        let sample = ShareEncryptionCircuitData::generate_sample(
            preset,
            CiphernodesCommitteeSize::Small.values(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let bounds = Bounds::compute(preset, &sample).unwrap();
        let sq = ScaledQuotient::derive(
            &moduli,
            t,
            scale.to_u64().unwrap(),
            &k0is,
            dkg.degree() as u64,
            bounds.u_bound.to_u64().unwrap(),
            bounds.e0_bound.to_u128().unwrap(),
            bounds.e1_bound.to_u64().unwrap(),
            &bounds.msg_bound,
        );
        (sq, moduli, t)
    }

    /// The substitution only holds if both numerators divide exactly. `derive` returns
    /// `available: false` rather than rounding, so re-check the identities on what it produced.
    #[test]
    fn secure_identities_hold_exactly() {
        let (sq, moduli, t) = derive_for(BfvPreset::SecureThreshold8192);
        assert!(
            sq.available,
            "secure-8192 should admit the scaled-quotient form"
        );
        assert_eq!(
            sq.k, 4,
            "k = 2^(bits(q) - bits(T)) = 4 for this parameter set"
        );

        let (_, dkg) = build_pair_for_preset(BfvPreset::SecureThreshold8192).unwrap();
        let scale = compute_q_mod_t(&compute_q_product(&moduli), t)
            .to_u64()
            .unwrap();
        let k0is = compute_k0is(&moduli, t).unwrap();
        let _ = dkg;

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

    /// The insecure DKG set pairs two ~57-bit moduli with a ~56-bit `T`, which fails the
    /// derivation's checks, so `derive` must report the form unavailable.
    ///
    /// The circuit keeps the direct `k1` path for this preset. The insecure set is test-only, so the
    /// fallback costs nothing that matters.
    #[test]
    fn insecure_is_excluded_rather_than_approximated() {
        let (sq, moduli, _) = derive_for(BfvPreset::InsecureThreshold);
        assert_eq!(moduli.len(), 2, "the insecure set has two DKG moduli");
        assert!(
            !sq.available,
            "the insecure set must fall back, not derive bogus constants"
        );
    }
}
