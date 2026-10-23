// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Canonical BN254 field literals shared by static Noir declarations and witnesses.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Zero;
use std::fmt::Display;
use std::str::FromStr;

pub(crate) fn join_display<T: Display>(values: &[T], separator: &str) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(separator)
}

pub fn get_zkp_modulus() -> BigInt {
    BigInt::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("Invalid ZKP modulus")
}

pub fn bigint_to_field(value: &BigInt) -> Fr {
    let zkp_modulus = get_zkp_modulus();
    let reduced = if value < &BigInt::zero() {
        (value % &zkp_modulus) + &zkp_modulus
    } else {
        value % &zkp_modulus
    };
    let biguint = reduced
        .to_biguint()
        .unwrap_or_else(|| (&zkp_modulus + reduced).to_biguint().unwrap());
    Fr::from_le_bytes_mod_order(&biguint.to_bytes_le())
}
