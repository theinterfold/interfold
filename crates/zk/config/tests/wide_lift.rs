// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The two-limb smudging lift: which presets need it, and that its constants keep every term of
//! the C2b relation under the field.
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_zk_config::threshold::pk_generation::{Configs, WideLift, NARROW_LIFT_MAX_BITS};
use num_bigint::BigUint;

const COMMITTEES: [CiphernodesCommitteeSize; 3] = [
    CiphernodesCommitteeSize::Minimum,
    CiphernodesCommitteeSize::Micro,
    CiphernodesCommitteeSize::Small,
];

#[test]
fn only_the_depth_six_preset_needs_the_wide_lift() {
    for preset in [
        BfvPreset::InsecureThreshold64,
        BfvPreset::InsecureThresholdLbfv,
        BfvPreset::InsecureThresholdSimd,
        BfvPreset::SecureThreshold8192,
        BfvPreset::SecureThreshold16384,
        BfvPreset::SecureThreshold16384Simd,
    ] {
        for committee in COMMITTEES {
            // The insecure SIMD preset has no Small committee.
            if let Ok(config) = Configs::for_preset(preset, committee) {
                assert!(
                    config.wide_lift.is_none(),
                    "{preset:?}/{committee:?} must keep the one-element lift"
                );
                assert!(config.bounds.e_sm_bound.bits() <= NARROW_LIFT_MAX_BITS);
            }
        }
    }
    for committee in COMMITTEES {
        let config = Configs::for_preset(BfvPreset::SecureThreshold16384SimdD6, committee)
            .unwrap();
        assert!(config.wide_lift.is_some(), "{committee:?}");
        // The C1 placeholders carry no real width.
        assert_eq!(config.bits.e_sm_lifted_bit, 1);
    }
}

#[test]
fn the_wide_lift_constants_keep_every_relation_term_under_the_field() {
    for committee in COMMITTEES {
        let config = Configs::for_preset(BfvPreset::SecureThreshold16384SimdD6, committee)
            .unwrap();
        let wide = config.wide_lift.unwrap();
        let bound = &config.bounds.e_sm_bound;
        let one = BigUint::from(1u32);
        // B and 2B recompose from their limbs.
        assert_eq!(
            (&wide.bound_hi << wide.shift) + &wide.bound_lo,
            bound.clone()
        );
        assert_eq!(
            (&wide.span_hi << wide.shift) + &wide.span_lo,
            bound << 1u32
        );
        assert!(wide.bound_lo < (&one << wide.shift));
        assert!(wide.span_lo < (&one << wide.shift));
        assert_eq!(wide.span_hi.bits(), u64::from(wide.bit_hi));
        for (index, q) in config.params.moduli().iter().enumerate() {
            let q = BigUint::from(*q);
            assert_eq!(wide.radix[index], (&one << wide.shift) % &q);
            // The right side of the relation, at its largest, and the one-sided quotient
            // window times the modulus, both stay below half of the field prime
            // (2^253 is a safe floor for p / 2).
            let rhs = (&one << wide.shift) + &wide.radix[index] * &wide.span_hi;
            assert!(rhs.bits() < 252, "{committee:?} limb {index}");
            let window = (&one << (wide.bit_quotient + 1)) * &q;
            assert!(window.bits() < 252, "{committee:?} limb {index}");
            assert!(wide.quotient_bounds[index].bits() <= u64::from(wide.bit_quotient));
            // The quotient bound covers the largest honest quotient.
            assert!(&wide.quotient_bounds[index] * &q >= rhs);
        }
        assert!(wide.shift < 252 && wide.bit_hi < 252 && wide.bit_quotient + 1 < 252);
    }
}

#[test]
fn a_bound_beyond_the_wide_lift_is_rejected() {
    // A 4-bit modulus and a 600-bit bound need more than 251 bits for one relation term.
    let bound = BigUint::from(1u32) << 600u32;
    let result = WideLift::new(&bound, &[BigUint::from(11u32)]);
    assert!(result.is_err());
}

#[test]
fn a_bound_inside_the_field_keeps_the_narrow_lift() {
    let bound = BigUint::from(1u32) << 250u32;
    assert!(WideLift::new(&bound, &[BigUint::from(11u32)])
        .unwrap()
        .is_none());
}

