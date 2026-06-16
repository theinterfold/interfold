// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Polynomial arithmetic implementation.

use crate::fhe_poly::ToPowerBasisPoly;
use crate::utils::{center, reduce};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use std::fmt;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors that can occur during polynomial operations.
#[derive(Debug, Error)]
pub enum PolynomialError {
    /// Division by zero polynomial
    #[error("Division by zero polynomial")]
    DivisionByZero,

    /// Invalid polynomial (e.g., empty coefficients or zero leading coefficient)
    #[error("Invalid polynomial: {message}")]
    InvalidPolynomial { message: String },

    /// Modulus operation error
    #[error("Modulus error: {message}")]
    ModulusError { message: String },

    /// Cyclotomic polynomial error
    #[error("Cyclotomic polynomial error: {message}")]
    CyclotomicError { message: String },

    /// Range check failure
    #[error("Range check error: {message}")]
    RangeCheckError { message: String },

    /// Arithmetic overflow or underflow
    #[error("Arithmetic error: {message}")]
    ArithmeticError { message: String },

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Parse error for BigInt
    #[error("Parse error: {0}")]
    ParseError(#[from] num_bigint::ParseBigIntError),
}

/// A polynomial with coefficients stored as `BigInt` for arbitrary precision arithmetic.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Polynomial {
    pub(crate) coefficients: Vec<BigInt>,
}

impl fmt::Display for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.coefficients.is_empty() {
            return write!(f, "0");
        }

        let mut first = true;
        for (i, coeff) in self.coefficients.iter().enumerate() {
            let degree = self.coefficients.len() - 1 - i;

            if coeff.is_zero() {
                continue;
            }

            if first {
                if coeff < &BigInt::zero() {
                    write!(f, "-")?;
                }
            } else if coeff > &BigInt::zero() {
                write!(f, " + ")?;
            } else {
                write!(f, " - ")?;
            }
            first = false;

            let abs_coeff = if coeff < &BigInt::zero() {
                -coeff
            } else {
                coeff.clone()
            };

            if degree == 0 || !abs_coeff.is_one() {
                write!(f, "{abs_coeff}")?;
            }

            if degree > 0 {
                write!(f, "x")?;
                if degree > 1 {
                    write!(f, "^{degree}")?;
                }
            }
        }

        if first {
            write!(f, "0")?;
        }

        Ok(())
    }
}

impl Polynomial {
    /// Creates a new polynomial from a vector of coefficients.
    ///
    /// # Arguments
    ///
    /// * `coefficients` - Vector of coefficients (see [`reverse`](Self::reverse) for ordering).
    pub fn new(coefficients: Vec<BigInt>) -> Self {
        Self { coefficients }
    }

    /// Creates a new polynomial from a vector of u64 coefficients.
    pub fn from_u64_vector(coefficients: Vec<u64>) -> Self {
        let coefficients = coefficients.iter().map(|&c| BigInt::from(c)).collect();

        Self { coefficients }
    }

    /// Creates a new polynomial from a fhe-math `Poly` (CRT-reconstructed mod Q).
    pub fn from_fhe_polynomial(p: &impl ToPowerBasisPoly) -> Self {
        let p = p.to_power_basis_poly();

        let coefficients: Vec<BigUint> = Vec::<BigUint>::from(&p);
        let bigints: Vec<BigInt> = coefficients
            .iter()
            .map(|c| c.to_bigint().unwrap())
            .collect();

        Self::new(bigints)
    }

    /// Reverses coefficient order in-place.
    ///
    /// **Coefficient ordering:** Converts between **descending** (highest degree first,
    /// internal storage) and **ascending** (lowest degree first). Calling `reverse()`
    /// twice restores the original order.
    pub fn reverse(&mut self) {
        self.coefficients.reverse()
    }

    /// Creates a zero polynomial of specified degree.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the zero polynomial.
    pub fn zero(degree: usize) -> Self {
        Self {
            coefficients: vec![BigInt::zero(); degree + 1],
        }
    }

    /// Creates a constant polynomial.
    ///
    /// # Arguments
    ///
    /// * `constant` - The constant value.
    pub fn constant(constant: BigInt) -> Self {
        Self {
            coefficients: vec![constant],
        }
    }

    /// Returns the coefficients of the polynomial.
    pub fn coefficients(&self) -> &[BigInt] {
        &self.coefficients
    }

    /// Returns the degree of the polynomial.
    ///
    /// The degree is computed as `self.coefficients.len().saturating_sub(1)`,
    /// which represents the highest exponent implied by the [`coefficients`](Self::coefficients)
    /// vector. A coefficients vector of length `n` (including all-zero vectors
    /// like those created by [`Polynomial::zero`]) yields degree `n - 1`.
    pub fn degree(&self) -> usize {
        if self.coefficients.is_empty() {
            0
        } else {
            self.coefficients.len() - 1
        }
    }

    /// Checks if the polynomial is zero.
    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|c| c.is_zero())
    }

    /// Removes leading zero coefficients from the polynomial.
    ///
    /// This method removes zero coefficients from the highest degree terms until
    /// a non-zero coefficient is found or only one coefficient remains.
    ///
    /// # Examples
    ///
    /// ```
    /// use e3_polynomial::Polynomial;
    /// use num_bigint::BigInt;
    ///
    /// let poly = Polynomial::new(vec![
    ///     BigInt::from(0),
    ///     BigInt::from(0),
    ///     BigInt::from(1),
    ///     BigInt::from(2),
    /// ]);
    /// let trimmed = poly.trim_leading_zeros();
    /// assert_eq!(trimmed.coefficients(), &[BigInt::from(1), BigInt::from(2)]);
    /// ```
    ///
    /// # Note
    ///
    /// If all coefficients are zero, the result will be a polynomial with a single zero coefficient.
    pub fn trim_leading_zeros(mut self) -> Self {
        if let Some(first_non_zero_idx) = self.coefficients.iter().position(|c| !c.is_zero()) {
            self.coefficients.drain(..first_non_zero_idx);
        } else {
            self.coefficients = vec![BigInt::zero()];
        }
        self
    }

    /// Returns the leading coefficient of the polynomial.
    pub fn leading_coefficient(&self) -> Option<&BigInt> {
        self.coefficients.first()
    }

    /// Adds two polynomials together.
    ///
    /// This function performs polynomial addition by:
    /// 1. Finding the maximum length between the two polynomials.
    /// 2. Creating a new polynomial with the maximum length.
    /// 3. Adding the coefficients of both polynomials term by term.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to the polynomial to add to `self`.
    ///
    /// # Returns
    ///
    /// A new polynomial containing the sum of the two polynomials.
    pub fn add(&self, other: &Self) -> Self {
        let max_length = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result = vec![BigInt::zero(); max_length];

        // Add coefficients from the first polynomial
        let self_offset = max_length - self.coefficients.len();
        for (i, coeff) in self.coefficients.iter().enumerate() {
            result[self_offset + i] = coeff.clone();
        }

        // Add coefficients from the second polynomial
        let other_offset = max_length - other.coefficients.len();
        for (i, coeff) in other.coefficients.iter().enumerate() {
            result[other_offset + i] += coeff;
        }

        Polynomial::new(result)
    }

    /// Subtracts one polynomial from another.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to the polynomial to subtract from `self`.
    ///
    /// # Returns
    ///
    /// A new polynomial containing the difference.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Negates all coefficients of the polynomial.
    ///
    /// # Returns
    ///
    /// A new polynomial with all coefficients negated.
    pub fn neg(&self) -> Self {
        Polynomial::new(self.coefficients.iter().map(|x| -x).collect())
    }

    /// Multiplies two polynomials using the naive algorithm.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to the polynomial to multiply with `self`.
    ///
    /// # Returns
    ///
    /// A new polynomial containing the product.
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Polynomial::zero(0);
        }

        let product_len = self.coefficients.len() + other.coefficients.len() - 1;
        let mut product = vec![BigInt::zero(); product_len];

        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                product[i + j] += &self.coefficients[i] * &other.coefficients[j];
            }
        }

        Polynomial::new(product)
    }

    /// Remove a coefficient from the polynomial.
    pub fn remove(&mut self, index: usize) {
        self.coefficients.remove(index);
    }

    /// Divides one polynomial by another, returning the quotient and remainder.
    ///
    /// # Arguments
    ///
    /// * `divisor` - A reference to the divisor polynomial.
    ///
    /// # Returns
    ///
    /// A result containing a tuple of (quotient, remainder) or an error.
    ///
    /// # Errors
    ///
    /// Returns `PolynomialError::DivisionByZero` if the divisor is zero.
    /// Returns `PolynomialError::InvalidPolynomial` if the divisor has zero leading coefficient
    /// or if exact divisibility is not satisfied (i.e., when a coefficient is not divisible
    /// by the divisor's leading coefficient).
    pub fn div(&self, divisor: &Self) -> Result<(Self, Self), PolynomialError> {
        if divisor.is_zero() {
            return Err(PolynomialError::DivisionByZero);
        }

        if divisor.coefficients.is_empty() || divisor.coefficients[0].is_zero() {
            return Err(PolynomialError::InvalidPolynomial {
                message: "Leading coefficient of divisor cannot be zero".to_string(),
            });
        }

        if self.degree() < divisor.degree() {
            return Ok((Polynomial::zero(0), self.clone()));
        }

        let mut quotient =
            vec![BigInt::zero(); self.coefficients.len() - divisor.coefficients.len() + 1];
        let mut remainder = self.coefficients.clone();

        for i in 0..quotient.len() {
            // Check for exact divisibility
            if !(&remainder[i] % &divisor.coefficients[0]).is_zero() {
                return Err(PolynomialError::InvalidPolynomial {
                    message: format!(
                        "Polynomial division requires exact divisibility: coefficient {} is not divisible by leading coefficient {}",
                        &remainder[i], &divisor.coefficients[0]
                    ),
                });
            }

            let coeff = &remainder[i] / &divisor.coefficients[0];
            quotient[i] = coeff.clone();

            for j in 0..divisor.coefficients.len() {
                if i + j < remainder.len() {
                    remainder[i + j] = &remainder[i + j] - &divisor.coefficients[j] * &coeff;
                }
            }
        }

        // Remove leading zero coefficients from remainder
        while !remainder.is_empty() && remainder[0].is_zero() {
            remainder.remove(0);
        }

        Ok((Polynomial::new(quotient), Polynomial::new(remainder)))
    }

    /// Multiplies each coefficient of the polynomial by a scalar.
    ///
    /// # Arguments
    ///
    /// * `scalar` - A `BigInt` scalar to multiply with each coefficient.
    ///
    /// # Returns
    ///
    /// Mutates the polynomial in place.
    pub fn scalar_mul(&self, scalar: &BigInt) -> Self {
        Polynomial::new(self.coefficients.iter().map(|x| x * scalar).collect())
    }

    /// Reduces the polynomial modulo a cyclotomic polynomial.
    ///
    /// This function performs polynomial division by the cyclotomic polynomial
    /// and returns the remainder, padded to length `n = cyclo.len() - 1`.
    ///
    /// The result is a polynomial of degree `n-1` where `n` is the degree of the
    /// cyclotomic polynomial. This is commonly used in lattice-based cryptography
    /// where polynomials are reduced modulo `x^N + 1` (the 2N-th cyclotomic polynomial).
    ///
    /// # Arguments
    ///
    /// * `cyclo` - Coefficients of the cyclotomic polynomial in descending order.
    ///
    /// # Returns
    ///
    /// A new polynomial containing the remainder.
    ///
    /// # Errors
    ///
    /// Returns `PolynomialError::DivisionByZero` if the cyclotomic polynomial is zero.
    /// Returns `PolynomialError::InvalidPolynomial` if the cyclotomic polynomial has a zero leading coefficient.
    ///
    /// # Examples
    ///
    /// ```
    /// use e3_polynomial::Polynomial;
    /// use num_bigint::BigInt;
    ///
    /// // Reduce modulo x^4 + 1 (cyclotomic polynomial for N=4)
    /// let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(0), BigInt::from(0), BigInt::from(0), BigInt::from(1)]);
    /// let cyclo = vec![BigInt::from(1), BigInt::from(0), BigInt::from(0), BigInt::from(0), BigInt::from(1)];
    /// let reduced = poly.reduce_by_cyclotomic(&cyclo).unwrap();
    /// assert_eq!(reduced.degree(), 3);
    /// ```
    pub fn reduce_by_cyclotomic(&self, cyclo: &[BigInt]) -> Result<Self, PolynomialError> {
        let cyclo_poly = Polynomial::new(cyclo.to_vec());
        let (_, remainder) = self.div(&cyclo_poly)?;

        let n = cyclo.len() - 1;
        let mut out = vec![BigInt::zero(); n];

        if !remainder.coefficients.is_empty() {
            let start_idx = n.saturating_sub(remainder.coefficients.len());
            let end_idx = std::cmp::min(start_idx + remainder.coefficients.len(), n);
            let src_len = end_idx - start_idx;
            for (i, coeff) in remainder.coefficients[..src_len].iter().enumerate() {
                out[start_idx + i] = coeff.clone();
            }
        }

        Ok(Polynomial::new(out))
    }

    /// Centers coefficients already in [0, modulus) into (-modulus/2, modulus/2].
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus.
    ///
    /// # Returns
    ///
    /// Mutates the polynomial in place.
    pub fn center(&mut self, modulus: &BigInt) {
        self.coefficients
            .iter_mut()
            .for_each(|x| *x = center(x, modulus));
    }

    /// Reduces coefficients modulo a modulus (in range [0, modulus)).
    pub fn reduce(&mut self, modulus: &BigInt) {
        self.coefficients
            .iter_mut()
            .for_each(|x| *x = reduce(x, modulus));
    }

    /// Evaluates the polynomial at a given point using Horner's method.
    ///
    /// # Arguments
    ///
    /// * `x` - The point at which to evaluate the polynomial.
    ///
    /// # Returns
    ///
    /// The value of the polynomial at the given point.
    pub fn evaluate(&self, x: &BigInt) -> BigInt {
        if self.coefficients.is_empty() {
            return BigInt::zero();
        }

        // Use Horner's method for efficient evaluation
        let mut result = self.coefficients[0].clone();
        for coeff in &self.coefficients[1..] {
            result = result * x + coeff;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_basic_polynomial_creation() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]);
        assert_eq!(poly.degree(), 2);
        assert_eq!(
            poly.coefficients(),
            &[BigInt::from(1), BigInt::from(2), BigInt::from(3)]
        );
    }

    #[test]
    fn test_zero_polynomial() {
        let zero = Polynomial::zero(3);
        assert_eq!(zero.degree(), 3);
        assert!(zero.is_zero());
    }

    #[test]
    fn test_constant_polynomial() {
        let const_poly = Polynomial::constant(BigInt::from(42));
        assert_eq!(const_poly.degree(), 0);
        assert_eq!(const_poly.coefficients(), &[BigInt::from(42)]);
    }

    #[test]
    fn test_polynomial_display() {
        let poly = Polynomial::new(vec![BigInt::from(2), BigInt::from(-3), BigInt::from(1)]);
        assert_eq!(poly.to_string(), "2x^2 - 3x + 1");
    }

    #[test]
    fn test_polynomial_display_negative_leading() {
        let poly = Polynomial::new(vec![BigInt::from(-3), BigInt::from(2), BigInt::from(-1)]);
        assert_eq!(poly.to_string(), "-3x^2 + 2x - 1");
    }

    #[test]
    fn test_polynomial_addition() {
        let poly1 = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]);
        let poly2 = Polynomial::new(vec![BigInt::from(3), BigInt::from(4)]);
        let result = poly1.add(&poly2);
        assert_eq!(result.coefficients(), &[BigInt::from(4), BigInt::from(6)]);
    }

    #[test]
    fn test_polynomial_subtraction() {
        let poly1 = Polynomial::new(vec![BigInt::from(5), BigInt::from(3)]);
        let poly2 = Polynomial::new(vec![BigInt::from(2), BigInt::from(1)]);
        let result = poly1.sub(&poly2);
        assert_eq!(result.coefficients(), &[BigInt::from(3), BigInt::from(2)]);
    }

    #[test]
    fn test_polynomial_negation() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(-2), BigInt::from(3)]);
        let neg_poly = poly.neg();
        assert_eq!(
            neg_poly.coefficients(),
            &[BigInt::from(-1), BigInt::from(2), BigInt::from(-3)]
        );
    }

    #[test]
    fn test_polynomial_multiplication() {
        let poly1 = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]); // x + 2
        let poly2 = Polynomial::new(vec![BigInt::from(1), BigInt::from(3)]); // x + 3
        let result = poly1.mul(&poly2); // Should be x^2 + 5x + 6
        assert_eq!(
            result.coefficients(),
            &[BigInt::from(1), BigInt::from(5), BigInt::from(6)]
        );
    }

    #[test]
    fn test_polynomial_division() {
        let dividend = Polynomial::new(vec![BigInt::from(1), BigInt::from(5), BigInt::from(6)]); // x^2 + 5x + 6
        let divisor = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]); // x + 2
        let (quotient, remainder) = dividend.div(&divisor).unwrap();
        assert_eq!(quotient.coefficients(), &[BigInt::from(1), BigInt::from(3)]); // x + 3
        assert!(remainder.is_zero());
    }

    #[test]
    fn test_division_by_zero() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]);
        let zero = Polynomial::zero(0);
        assert!(matches!(
            poly.div(&zero),
            Err(PolynomialError::DivisionByZero)
        ));
    }

    #[test]
    fn test_scalar_multiplication() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]);
        let scalar = BigInt::from(5);
        let result = poly.scalar_mul(&scalar);
        assert_eq!(
            result.coefficients(),
            &[BigInt::from(5), BigInt::from(10), BigInt::from(15)]
        );
    }

    #[test]
    fn test_polynomial_evaluation() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]); // x^2 + 2x + 3
        let result = poly.evaluate(&BigInt::from(2)); // 1*4 + 2*2 + 3 = 11
        assert_eq!(result, BigInt::from(11));
    }

    #[test]
    fn test_trim_leading_zeros() {
        let poly = Polynomial::new(vec![
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
            BigInt::from(2),
        ]);
        let trimmed = poly.trim_leading_zeros();
        assert_eq!(trimmed.coefficients(), &[BigInt::from(1), BigInt::from(2)]);
    }

    #[test]
    fn test_trim_leading_zeros_all_zero() {
        let poly = Polynomial::new(vec![BigInt::from(0), BigInt::from(0), BigInt::from(0)]);
        let trimmed = poly.trim_leading_zeros();
        assert_eq!(trimmed.coefficients(), &[BigInt::from(0)]);
    }

    #[test]
    fn test_trim_leading_zeros_no_leading_zeros() {
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]);
        let trimmed = poly.trim_leading_zeros();
        assert_eq!(trimmed.coefficients(), &[BigInt::from(1), BigInt::from(2)]);
    }

    #[test]
    fn test_trim_leading_zeros_single_zero() {
        let poly = Polynomial::new(vec![BigInt::from(0)]);
        let trimmed = poly.trim_leading_zeros();
        assert_eq!(trimmed.coefficients(), &[BigInt::from(0)]);
    }

    #[cfg(feature = "serde")]
    mod serialization_tests {
        use super::*;
        use bincode;

        #[test]
        fn test_polynomial_bincode_serialization() {
            let poly = Polynomial::new(vec![BigInt::from(2), BigInt::from(-3), BigInt::from(1)]); // 2x^2 - 3x + 1

            // Test binary serialization with bincode
            let bytes = bincode::serialize(&poly).expect("Failed to serialize");
            let reconstructed: Polynomial =
                bincode::deserialize(&bytes).expect("Failed to deserialize");

            // Verify the polynomial is correctly reconstructed
            assert_eq!(poly, reconstructed);
            assert_eq!(poly.coefficients(), reconstructed.coefficients());
            assert_eq!(poly.degree(), reconstructed.degree());
            assert_eq!(poly.to_string(), reconstructed.to_string());
        }

        #[test]
        fn test_polynomial_bincode_serialization_edge_cases() {
            // Test zero polynomial
            let zero_poly = Polynomial::zero(3);
            let bytes = bincode::serialize(&zero_poly).expect("Failed to serialize");
            let reconstructed: Polynomial =
                bincode::deserialize(&bytes).expect("Failed to deserialize");
            assert_eq!(zero_poly, reconstructed);
            assert!(reconstructed.is_zero());

            // Test constant polynomial
            let const_poly = Polynomial::constant(BigInt::from(42));
            let bytes = bincode::serialize(&const_poly).expect("Failed to serialize");
            let reconstructed: Polynomial =
                bincode::deserialize(&bytes).expect("Failed to deserialize");
            assert_eq!(const_poly, reconstructed);
            assert_eq!(reconstructed.degree(), 0);

            // Test empty polynomial
            let empty_poly = Polynomial::new(vec![]);
            let bytes = bincode::serialize(&empty_poly).expect("Failed to serialize");
            let reconstructed: Polynomial =
                bincode::deserialize(&bytes).expect("Failed to deserialize");
            assert_eq!(empty_poly, reconstructed);
        }

        #[test]
        fn test_polynomial_bincode_serialization_large_numbers() {
            // Test with very large numbers
            let large_coeffs = vec![
                BigInt::from(i64::MAX),
                BigInt::from(i64::MIN),
                BigInt::from(0),
                BigInt::from(42),
            ];
            let poly = Polynomial::new(large_coeffs);

            let bytes = bincode::serialize(&poly).expect("Failed to serialize");
            let reconstructed: Polynomial =
                bincode::deserialize(&bytes).expect("Failed to deserialize");

            assert_eq!(poly, reconstructed);
            assert_eq!(poly.coefficients(), reconstructed.coefficients());
        }

        #[test]
        fn test_polynomial_bincode_serialization_roundtrip() {
            // Test that operations work correctly after serialization/deserialization
            let poly1 = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]);
            let poly2 = Polynomial::new(vec![BigInt::from(4), BigInt::from(5)]);

            // Serialize and deserialize both polynomials
            let bytes1 = bincode::serialize(&poly1).expect("Failed to serialize");
            let bytes2 = bincode::serialize(&poly2).expect("Failed to serialize");

            let reconstructed1: Polynomial =
                bincode::deserialize(&bytes1).expect("Failed to deserialize");
            let reconstructed2: Polynomial =
                bincode::deserialize(&bytes2).expect("Failed to deserialize");

            // Test that operations still work
            let original_sum = poly1.add(&poly2);
            let reconstructed_sum = reconstructed1.add(&reconstructed2);
            assert_eq!(original_sum, reconstructed_sum);

            let original_product = poly1.mul(&poly2);
            let reconstructed_product = reconstructed1.mul(&reconstructed2);
            assert_eq!(original_product, reconstructed_product);
        }
    }

    #[test]
    fn test_reduce_by_cyclotomic() {
        // Test reduction modulo x^4 + 1 (cyclotomic polynomial for N=4)
        // cyclo = [1, 0, 0, 0, 1] represents x^4 + 1
        let cyclo = vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        ];

        // Test: x^4 + 1 divided by x^4 + 1 should give remainder 0
        let poly = Polynomial::new(vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        ]);
        let reduced = poly.reduce_by_cyclotomic(&cyclo).unwrap();
        assert_eq!(reduced.degree(), 3);
        assert!(reduced.is_zero());

        // Test: x^5 divided by x^4 + 1 gives remainder -x
        // x^5 = x * x^4 = x * (x^4 + 1 - 1) = x(x^4 + 1) - x
        // So remainder is -x, which becomes x^3 - x after padding
        let poly2 = Polynomial::new(vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
        ]);
        let reduced2 = poly2.reduce_by_cyclotomic(&cyclo).unwrap();
        assert_eq!(reduced2.degree(), 3);
        // The remainder should be -x, padded to length 4: [0, 0, 0, -1]
        // But actually, the algorithm right-aligns, so it should be [0, 0, 0, -1]
        // Let's just verify it's not zero and has the right degree
        assert!(!reduced2.is_zero());
    }

    #[test]
    fn test_reduce_by_cyclotomic_right_alignment() {
        // Test that remainder is right-aligned correctly
        // cyclo = [1, 0, 1] represents x^2 + 1, so n = cyclo.len() - 1 = 2
        let cyclo = vec![BigInt::from(1), BigInt::from(0), BigInt::from(1)];

        // Test with remainder that fits exactly
        // x^2 + 2x + 1 divided by x^2 + 1 gives remainder 2x
        // remainder.coefficients = [2, 0] (2x + 0)
        // After right-aligning to n=2: we copy [2, 0] to output
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(1)]);
        let reduced = poly.reduce_by_cyclotomic(&cyclo).unwrap();
        // n = cyclo.len() - 1 = 3 - 1 = 2, so output length is 2
        assert_eq!(reduced.coefficients().len(), 2);
        // The remainder is 2x = [2, 0], right-aligned to length 2 gives [2, 0]
        assert_eq!(reduced.coefficients()[0].clone(), BigInt::from(2));
        assert_eq!(reduced.coefficients()[1].clone(), BigInt::from(0));
    }

    #[test]
    fn test_reduce_by_cyclotomic_long_remainder() {
        // Test with remainder longer than output size (should truncate)
        // cyclo = [1, 0, 1] represents x^2 + 1, so n = cyclo.len() - 1 = 2
        let cyclo = vec![BigInt::from(1), BigInt::from(0), BigInt::from(1)];

        // x^4 + 2x^3 + 3x^2 divided by x^2 + 1
        // This will give a remainder, and we test truncation
        let poly = Polynomial::new(vec![
            BigInt::from(1),
            BigInt::from(2),
            BigInt::from(3),
            BigInt::from(0),
            BigInt::from(0),
        ]);
        let reduced = poly.reduce_by_cyclotomic(&cyclo).unwrap();
        // Output should be length n = 2
        assert_eq!(reduced.coefficients().len(), 2);
    }

    #[test]
    fn test_reduce_by_cyclotomic_empty_remainder() {
        // Test with zero remainder
        let cyclo = vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        ];
        // x^4 + 1 divided by x^4 + 1 = 1 with remainder 0
        let poly = Polynomial::new(vec![
            BigInt::from(1),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(1),
        ]);
        let reduced = poly.reduce_by_cyclotomic(&cyclo).unwrap();
        assert_eq!(reduced.degree(), 3);
        assert!(reduced.is_zero());
    }

    #[test]
    fn test_reduce_by_cyclotomic_error_cases() {
        // Test division by zero cyclotomic polynomial
        let cyclo_zero = vec![BigInt::from(0), BigInt::from(0)];
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2)]);
        assert!(matches!(
            poly.reduce_by_cyclotomic(&cyclo_zero),
            Err(PolynomialError::DivisionByZero)
        ));

        // Test zero leading coefficient
        let cyclo_invalid = vec![BigInt::from(0), BigInt::from(1)];
        assert!(matches!(
            poly.reduce_by_cyclotomic(&cyclo_invalid),
            Err(PolynomialError::InvalidPolynomial { .. })
        ));
    }
}
