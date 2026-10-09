// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use ark_ff::{BigInteger, PrimeField};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_helpers::encoding::{
    bigint_1d_to_json_values, bigint_2d_to_json_values, bigint_3d_to_json_values, bigint_to_field,
    bigint_to_json_value, crt_polynomial_to_toml_json, polynomial_to_toml_json,
};
use num_bigint::{BigInt, Sign};
use serde_json::json;

#[test]
fn signed_coefficients_keep_canonical_field_values_and_witness_shapes() {
    let cases = [
        ("0", json!(0)),
        ("5", json!(5)),
        ("9223372036854775807", json!(9223372036854775807_i64)),
        ("9223372036854775808", json!("9223372036854775808")),
        (
            "-1",
            json!("21888242871839275222246405745257275088548364400416034343698204186575808495616"),
        ),
        (
            "21888242871839275222246405745257275088548364400416034343698204186575808495622",
            json!(5),
        ),
        (
            "-21888242871839275222246405745257275088548364400416034343698204186575808495617",
            json!(0),
        ),
        (
            "-21888242871839275222246405745257275088548364400416034343698204186575808495618",
            json!("21888242871839275222246405745257275088548364400416034343698204186575808495616"),
        ),
    ];
    let coefficients: Vec<BigInt> = cases.iter().map(|(s, _)| s.parse().unwrap()).collect();
    let expected: Vec<_> = cases.iter().map(|(_, value)| value.clone()).collect();
    for (input, expected) in coefficients.iter().zip(&expected) {
        assert_eq!(bigint_to_json_value(input), *expected);
        let text = expected
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| expected.to_string());
        let field = bigint_to_field(input);
        assert_eq!(
            BigInt::from_bytes_le(Sign::Plus, &field.into_bigint().to_bytes_le()),
            text.parse::<BigInt>().unwrap()
        );
    }
    assert_eq!(bigint_1d_to_json_values(&coefficients), expected);
    assert_eq!(
        bigint_2d_to_json_values(std::slice::from_ref(&coefficients)),
        vec![expected.clone()]
    );
    assert_eq!(
        bigint_3d_to_json_values(&[vec![coefficients.clone()]]),
        vec![vec![expected.clone()]]
    );
    let polynomial = Polynomial::new(coefficients);
    let expected_poly = json!({"coefficients": expected});
    assert_eq!(polynomial_to_toml_json(&polynomial), expected_poly);
    assert_eq!(
        crt_polynomial_to_toml_json(&CrtPolynomial::new(vec![polynomial])),
        vec![expected_poly]
    );
}
