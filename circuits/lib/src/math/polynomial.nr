// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::modulo::U128::ModU128;

/// Polynomial structure representing a polynomial of degree N-1.
///
/// A polynomial P(X) = a_{N-1} * X^{N-1} + a_{N-2} * X^{N-2} + ... + a_1 * X + a_0
/// is represented as an array of coefficients where coefficients[0] = a_{N-1} (highest degree)
/// and coefficients[N-1] = a_0 (constant term).
pub struct Polynomial<let N: u32> {
    /// Array of polynomial coefficients in descending degree order
    /// coefficients[0] = coefficient of X^{N-1} (highest degree term)
    /// coefficients[N-1] = constant term (degree 0)
    pub coefficients: [Field; N],
}

impl<let N: u32> Polynomial<N> {
    /// Creates a new polynomial from an array of coefficients.
    ///
    /// # Arguments
    /// * `coefficients` - Array of N coefficients in descending degree order
    ///                    coefficients[0] = coefficient of X^{N-1}
    ///                    coefficients[N-1] = constant term
    ///
    /// # Returns
    /// A new Polynomial instance with the specified coefficients
    pub fn new(coefficients: [Field; N]) -> Self {
        Polynomial { coefficients }
    }

    /// Adds two polynomials.
    ///
    /// # Arguments
    /// * `other` - The polynomial to add to the current polynomial.
    ///
    /// # Returns
    /// A new polynomial with the coefficients added.
    pub fn add(self, other: Self) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] + other.coefficients[i];
        }

        result
    }

    /// Subtracts two polynomials.
    ///
    /// # Arguments
    /// * `other` - The polynomial to subtract from the current polynomial.
    ///
    /// # Returns
    /// A new polynomial with the coefficients subtracted.
    pub fn sub(self, other: Self) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] - other.coefficients[i];
        }

        result
    }

    /// Multiplies a polynomial by a scalar.
    ///
    /// # Arguments
    /// * `scalar` - The scalar to multiply the polynomial by.
    ///
    /// # Returns
    /// A new polynomial with the coefficients multiplied by the scalar.
    pub fn mul_scalar(self, scalar: Field) -> Self {
        let mut result = Self::new([0; N]);

        for i in 0..N {
            result.coefficients[i] = self.coefficients[i] * scalar;
        }

        result
    }

    /// Evaluates the polynomial at a given point using Horner's method.
    ///
    /// Horner's method computes P(x) = a_{N-1} * x^{N-1} + ... + a_1 * x + a_0
    /// as ((...((a_{N-1} * x + a_{N-2}) * x + a_{N-3}) * x + ...) * x + a_0)
    /// This approach require n multiplications and n additions to evaluate the polynomial.
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate the polynomial.
    ///
    /// # Returns
    /// The value of the polynomial at point x: P(x).
    pub fn eval(self, x: Field) -> Field {
        let mut result = self.coefficients[0];

        for i in 1..self.coefficients.len() {
            result = result * x + self.coefficients[i];
        }

        result
    }

    /// Evaluates the polynomial at a given point with modular reduction.
    ///
    /// This function computes `P(x) mod q` using Horner's method with intermediate
    /// modular reductions to prevent overflow. The result is guaranteed to be in
    /// the range `[0, q)`.
    ///
    /// The function performs modular reduction after each multiplication and addition
    /// to ensure the accumulator always remains in the range `[0, q)`, preventing
    /// any potential overflow issues.
    ///
    /// # Arguments
    /// * `x` - The point at which to evaluate the polynomial
    /// * `q` - The modular arithmetic context containing the modulus
    ///
    /// # Returns
    /// The value `P(x) mod q` in the range `[0, q)`
    pub fn eval_mod(self, x: Field, q: ModU128) -> Field {
        let mut acc = self.coefficients[0];
        let len = self.coefficients.len();

        for i in 1..len {
            acc = q.mul_mod(acc, x);
            acc = q.add(acc, self.coefficients[i]);
        }

        acc
    }

    /// Performs range checking on polynomial coefficients using asymmetric bounds.
    ///
    /// This function constrains all polynomial coefficients to be in the range [-lower_bound, upper_bound],
    /// where `lower_bound` is a non-negative magnitude.
    /// It uses a shifting technique to handle negative numbers efficiently:
    /// 1. Shifts each coefficient by adding `lower_bound`: c' = c + lower_bound
    /// 2. Checks that shifted coefficients are in [0, upper_bound + lower_bound] using bit-size assertions
    /// 3. This ensures original coefficients are in [-lower_bound, upper_bound]
    ///
    /// The function uses two bit-size checks per coefficient to ensure the value is within bounds:
    /// - `shifted_coefficient.assert_max_bit_size::<BIT + 1>()` ensures c' >= 0
    /// - `(range_size - shifted_coefficient).assert_max_bit_size::<BIT + 1>()` ensures c' <= range_size
    ///
    /// # Arguments
    /// * `upper_bound` - The upper bound for coefficient range checking
    /// * `lower_bound` - Non-negative magnitude of the negative bound
    ///                   Coefficients must satisfy: -lower_bound <= c <= upper_bound
    ///
    /// # Generic Parameters
    /// * `BIT` - The bit-length of the total range `upper_bound + lower_bound`
    ///           (choose `BIT` so `upper_bound + lower_bound < 2^BIT`). Since all checked
    ///           values lie in `[0, upper_bound + lower_bound]`, they cannot exceed `BIT + 1` bits.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// the specified bounds.
    pub fn range_check_2bounds<let BIT: u32>(self, upper_bound: Field, lower_bound: Field) {
        let range_size = lower_bound + upper_bound;

        for i in 0..self.coefficients.len() {
            let shifted_coefficient = self.coefficients[i] + lower_bound;

            shifted_coefficient.assert_max_bit_size::<BIT + 1>();
            (range_size - shifted_coefficient).assert_max_bit_size::<BIT + 1>();
        }
    }

    /// Performs range checking on polynomial coefficients for the range [0, upper_bound).
    ///
    /// This function constrains all polynomial coefficients to be non-negative and
    /// strictly less than `upper_bound`. It uses bit-size assertions to verify that
    /// coefficients are in the valid range.
    ///
    /// The function performs two checks per coefficient:
    /// 1. `coeff.assert_max_bit_size::<BIT>()` ensures `coeff >= 0` and `coeff < 2^BIT`
    /// 2. `(upper_bound - 1 - coeff).assert_max_bit_size::<BIT>()` ensures `coeff < upper_bound`
    ///
    /// # Arguments
    /// * `upper_bound` - The exclusive upper bound for coefficient range checking.
    ///                   Coefficients must satisfy: `0 <= c < upper_bound`
    ///
    /// # Generic Parameters
    /// * `BIT` - The bit-length parameter. Must satisfy `upper_bound <= 2^BIT` for
    ///           the range check to work correctly.
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// the range `[0, upper_bound)`.
    pub fn range_check_standard<let BIT: u32>(self, upper_bound: Field) {
        for i in 0..self.coefficients.len() {
            let coeff = self.coefficients[i];
            // Check coeff >= 0 and coeff < 2^BIT
            coeff.assert_max_bit_size::<BIT>();
            // Check coeff <= upper_bound - 1 (i.e., coeff < upper_bound)
            (upper_bound - 1 - coeff).assert_max_bit_size::<BIT>();
        }
    }

    /// Performs range checking on polynomial coefficients for the range [0, 2^BIT).
    ///
    /// This is a specialized range check for coefficients that must be non-negative
    /// and less than a power of two. It's more efficient than `range_check_standard`
    /// when the upper bound is exactly `2^BIT` because it only needs a single
    /// bit-size assertion per coefficient.
    ///
    /// The function verifies that each coefficient satisfies:
    /// - `coeff >= 0` (implicit from bit-size check)
    /// - `coeff < 2^BIT` (enforced by `assert_max_bit_size::<BIT>()`)
    ///
    /// # Generic Parameters
    /// * `BIT` - The bit-length parameter. Coefficients must satisfy: `0 <= c < 2^BIT`
    ///
    /// # Panics
    /// This function will cause the circuit to fail if any coefficient is outside
    /// the range `[0, 2^BIT)`.
    pub fn range_check_power_of_two<let BIT: u32>(self) {
        for i in 0..self.coefficients.len() {
            self.coefficients[i].assert_max_bit_size::<BIT>();
        }
    }
}

#[test]
fn test_polynomial_eval_zero() {
    let coeffs = [1, -2, 1]; // x^2 - 2x + 1 = (x-1)^2
    let poly = Polynomial::new(coeffs);

    let x = 1; // evaluate at x = 1, should be 0
    let result = poly.eval(x);

    assert(result == 0);
}

#[test]
fn test_polynomial_bounds() {
    let coeffs = [-16, 240, 242];
    let poly = Polynomial::new(coeffs);

    // Test double bounds check - constrains to [-240, 242]
    poly.range_check_2bounds::<8>(242, 240);
}

#[test(should_fail_with = "assert_max_bit_size")]
fn test_polynomial_out_of_bounds_coefficients() {
    let coeffs = [-100];
    let poly = Polynomial::new(coeffs);

    // Test double bounds check - constrains to [-98, 99]
    // Should fail because -100 is out of bounds.
    poly.range_check_2bounds::<7>(99, 98);
}

#[test]
fn test_polynomial_add() {
    let coeffs1 = [1, 2, 3]; // 1x^2 + 2x + 3
    let coeffs2 = [4, 5, 6]; // 4x^2 + 5x + 6
    let poly1 = Polynomial::new(coeffs1);
    let poly2 = Polynomial::new(coeffs2);

    let result = poly1.add(poly2);

    // Expected: (1+4)x^2 + (2+5)x + (3+6) = 5x^2 + 7x + 9
    assert(result.coefficients[0] == 5);
    assert(result.coefficients[1] == 7);
    assert(result.coefficients[2] == 9);
}

#[test]
fn test_polynomial_sub() {
    let coeffs1 = [5, 7, 9]; // 5x^2 + 7x + 9
    let coeffs2 = [1, 2, 3]; // 1x^2 + 2x + 3
    let poly1 = Polynomial::new(coeffs1);
    let poly2 = Polynomial::new(coeffs2);

    let result = poly1.sub(poly2);

    // Expected: (5-1)x^2 + (7-2)x + (9-3) = 4x^2 + 5x + 6
    assert(result.coefficients[0] == 4);
    assert(result.coefficients[1] == 5);
    assert(result.coefficients[2] == 6);
}

#[test]
fn test_polynomial_mul_scalar() {
    let coeffs = [1, 2, 3]; // 1x^2 + 2x + 3
    let poly = Polynomial::new(coeffs);
    let scalar = 5;

    let result = poly.mul_scalar(scalar);

    // Expected: 5x^2 + 10x + 15
    assert(result.coefficients[0] == 5);
    assert(result.coefficients[1] == 10);
    assert(result.coefficients[2] == 15);
}

#[test]
fn test_polynomial_mul_scalar_zero() {
    let coeffs = [1, 2, 3];
    let poly = Polynomial::new(coeffs);
    let scalar = 0;

    let result = poly.mul_scalar(scalar);

    // Expected: 0x^2 + 0x + 0 = 0
    assert(result.coefficients[0] == 0);
    assert(result.coefficients[1] == 0);
    assert(result.coefficients[2] == 0);
}

#[test]
fn test_eval_mod_simple() {
    // Test without initial reduction - simple case
    // p(x) = x + 1 at x=5od 7
    // Expected: (5 + 1) mod 7 = 6
    let q = ModU128::new(7);

    let poly1 = Polynomial::new([1, 1]);
    let result1 = poly1.eval_mod(5, q);
    assert(result1 == 6);

    // Test: p(x) = 2x + 3 at x=5od 7
    // Expected: (10 + 3) mod 7 = 13 mod 7 = 6
    let poly2 = Polynomial::new([2, 3]);
    let result2 = poly2.eval_mod(5, q);
    assert(result2 == 6);
}

#[test]
fn test_eval_mod() {
    // Test 1: Simple polynomial x^2 + 2x + 3 at x=5od 7
    // Expected: (25 + 10 + 3) mod 7 = 38 mod 7 = 3
    let q = ModU128::new(7);

    let poly1 = Polynomial::new([1, 2, 3]);
    let result1 = poly1.eval_mod(5, q);
    assert(result1 == 3);

    // Test 2: Higher degree polynomialod small prime
    // p(x) = x^3 + x^2 + x + 1 at x=2od 11
    // Expected: (8 + 4 + 2 + 1) mod 11 = 15 mod 11 = 4
    let q = ModU128::new(11);

    let poly2 = Polynomial::new([1, 1, 1, 1]);
    let result2 = poly2.eval_mod(2, q);
    assert(result2 == 4);

    // Test 3: Polynomial with larger coefficients
    // p(x) = 100x^2 + 50x + 25 at x=10od 73
    // Expected: (10000 + 500 + 25) mod 73 = 10525 mod 73 = 13
    let q = ModU128::new(73);

    let poly3 = Polynomial::new([100, 50, 25]);
    let result3 = poly3.eval_mod(10, q);
    assert(result3 == 13);

    // Test 4: Result should be less than modulus
    let poly4 = Polynomial::new([5, 3, 7]);
    let q = ModU128::new(17);
    let result4 = poly4.eval_mod(4, q);
    assert(result4 as u128 < q.get_mod_field() as u128);

    // Test 5: Compare with regular eval for small values
    let poly5 = Polynomial::new([1, 2, 1]);
    let x = 3;
    let q = ModU128::new(1000);
    let result5 = poly5.eval_mod(x, q);
    let expected5 = poly5.eval(x);
    assert(result5 == expected5);

    // Test 6: Zero polynomial
    let poly6 = Polynomial::new([0, 0, 0]);
    let q = ModU128::new(13);
    let result6 = poly6.eval_mod(100, q);
    assert(result6 == 0);
}

#[test]
fn test_large_party_ids_scenario() {
    // Simulating party IDs in range [1, 100]
    let party_id_1 = 42;
    let party_id_2 = 73;
    let m = ModU128::new(288230376151711717); // ~58 bits

    // Operations that would be used in Lagrange coefficients
    let product = m.mul_mod(party_id_1, party_id_2);
    let diff = m.sub(party_id_2, party_id_1);

    assert(product == 3066);
    assert(diff == 31);
}

#[test]
fn test_eval_vs_eval_mod() {
    // Compare eval and eval_mod for small values where no reduction should occur
    let poly = Polynomial::new([1, 2, 3]);
    let x = 2;
    let q = ModU128::new(1000); // Large enough that no reduction happens

    let result_normal = poly.eval(x);
    let result_mod = poly.eval_mod(x, q);

    // They should be equal: (1)*2 + 2)*2 + 3 = (2+2)*2 + 3 = 4*2 + 3 = 11
    assert(result_normal == 11);
    assert(result_mod == 11);
}
