// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sizing-only CKKS presets for the committee-side proof scaling curve.
//!
//! The on-chain param sets ([`ckks_preset_for_param_set`]) are all `N = 512`
//! shapes. To measure how the C1/C2/C6/C7/C8 circuits grow with the ring
//! degree at a FIXED limb count, this module builds a family of presets
//! `ckks_preset_scaling(n, l, k)` that mirror ParamSet 3 (36-bit moduli,
//! `Δ = 2^40`) with only `N` (and optionally the number of hybrid special
//! primes `k`) varying. They are NOT secure parameter sets and are NOT
//! reachable from the node: their only consumer is
//! `examples/gen_ckks_scale_provers.rs`, which emits the
//! `circuits/bin/ckks_scaling/<circuit>_scale_n<N>` packages that
//! `docs/THRESHOLD_CKKS_PROVEN_PIPELINE_AT_SECURE_N.md` measures.
//!
//! [`ckks_preset_for_param_set`]: crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set

use crate::threshold::user_data_encryption_ckks::CkksPreset;
use crate::CircuitsErrors;
use fhe::ckks::CkksParametersBuilder;

/// Bit size of every ciphertext modulus in a scaling preset (ParamSet 3's
/// shape: 36-bit NTT-friendly primes, transport-compatible at N = 512).
pub const CKKS_SCALING_MODULUS_BITS: usize = 36;

/// Bit size of every hybrid special prime in a scaling preset.
pub const CKKS_SCALING_SPECIAL_BITS: usize = 60;

/// Scale bits (ParamSet 3's `Δ = 2^40`).
pub const CKKS_SCALING_SCALE_BITS: i32 = 40;

/// Application input bound baked into the Greco message bound (ParamSet 3
/// encrypts cap-normalized values, `B = 1`).
pub const CKKS_SCALING_INPUT_BOUND: f64 = 1.0;

/// Build a sizing preset with ring degree `n`, `l` ciphertext moduli of
/// [`CKKS_SCALING_MODULUS_BITS`] bits and `special_primes` hybrid special
/// primes of [`CKKS_SCALING_SPECIAL_BITS`] bits (`0` = no hybrid key
/// switching; `> 0` enables it with the default digit size, which is what
/// the per-digit C8 circuit needs).
///
/// `n` must be a power of two `>= 8` and `l >= 1`; the fhe.rs builder
/// enforces the rest (prime availability at `2n`, etc.).
pub fn ckks_preset_scaling(
    n: usize,
    l: usize,
    special_primes: usize,
) -> Result<CkksPreset, CircuitsErrors> {
    if !n.is_power_of_two() || n < 8 {
        return Err(CircuitsErrors::Other(format!(
            "ckks_preset_scaling: degree {n} must be a power of two >= 8"
        )));
    }
    if l == 0 {
        return Err(CircuitsErrors::Other(
            "ckks_preset_scaling: at least one ciphertext modulus is required".into(),
        ));
    }
    let sizes = vec![CKKS_SCALING_MODULUS_BITS; l];
    let mut builder = CkksParametersBuilder::new()
        .set_degree(n)
        .set_moduli_sizes(&sizes)
        .set_scale(2f64.powi(CKKS_SCALING_SCALE_BITS));
    if special_primes > 0 {
        let specials = vec![CKKS_SCALING_SPECIAL_BITS; special_primes];
        builder = builder.set_special_moduli_sizes(&specials);
    }
    let params = builder
        .build_arc()
        .map_err(|e| CircuitsErrors::Other(format!("ckks_preset_scaling({n}, {l}): {e}")))?;
    Ok(CkksPreset {
        params,
        input_bound: CKKS_SCALING_INPUT_BOUND,
    })
}

/// Bin-package suffix for a scaling shape (`_scale_n<N>`), shared by every
/// circuit's package name so a measurement row is addressable by `N`.
pub fn scaling_package_suffix(n: usize) -> String {
    format!("_scale_n{n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaling_preset_varies_only_degree() {
        let a = ckks_preset_scaling(1024, 3, 0).unwrap();
        let b = ckks_preset_scaling(2048, 3, 0).unwrap();
        assert_eq!(a.params.degree(), 1024);
        assert_eq!(b.params.degree(), 2048);
        assert_eq!(a.params.moduli().len(), 3);
        assert_eq!(b.params.moduli().len(), 3);
        for q in a.params.moduli().iter().chain(b.params.moduli()) {
            assert_eq!(64 - q.leading_zeros() as usize, CKKS_SCALING_MODULUS_BITS);
        }
        assert!(!a.params.hybrid_enabled());
        assert_eq!(a.params.scale(), 2f64.powi(CKKS_SCALING_SCALE_BITS));
        assert_eq!(a.input_bound, CKKS_SCALING_INPUT_BOUND);
    }

    #[test]
    fn scaling_preset_hybrid_enables_digits() {
        let p = ckks_preset_scaling(1024, 3, 1).unwrap();
        assert!(p.params.hybrid_enabled());
        assert_eq!(p.params.special_moduli().len(), 1);
        assert_eq!(p.params.dnum(), 3, "alpha = k = 1 => one digit per limb");
    }

    #[test]
    fn scaling_preset_rejects_bad_shapes() {
        assert!(ckks_preset_scaling(1000, 3, 0).is_err());
        assert!(ckks_preset_scaling(1024, 0, 0).is_err());
    }

    #[test]
    fn suffix_names_the_degree() {
        assert_eq!(scaling_package_suffix(4096), "_scale_n4096");
    }
}
