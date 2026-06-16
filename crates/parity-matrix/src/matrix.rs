// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generator matrix construction and null space computation.
//!
//! This module builds generator matrices for polynomial evaluations and computes
//! their null spaces to create parity check matrices.

use crate::errors::{ConstraintError, MathError, ParityMatrixError, ParityMatrixResult};
use crate::math::mod_inverse;
use crate::math::mod_pow;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

/// A matrix with runtime-determined dimensions.
///
/// Use this when dimensions are not known at compile time (e.g., null space results).
/// Dimensions are validated at construction and runtime operations check consistency.
///
/// # Example
///
/// ```
/// use e3_parity_matrix::ParityMatrix;
/// use num_bigint::BigUint;
///
/// let data = vec![
///     vec![BigUint::from(1u32), BigUint::from(2u32)],
///     vec![BigUint::from(3u32), BigUint::from(4u32)],
/// ];
/// let matrix = ParityMatrix::new(data).unwrap();
/// assert_eq!(matrix.rows(), 2);
/// assert_eq!(matrix.cols(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityMatrix {
    data: Vec<Vec<BigUint>>,
    rows: usize,
    cols: usize,
}

impl ParityMatrix {
    /// Creates a new dynamic matrix from data, validating dimensions.
    ///
    /// # Errors
    ///
    /// Returns an error if rows have inconsistent lengths.
    pub fn new(data: Vec<Vec<BigUint>>) -> ParityMatrixResult<Self> {
        if data.is_empty() {
            return Ok(Self {
                data,
                rows: 0,
                cols: 0,
            });
        }

        let rows = data.len();
        let cols = data[0].len();

        for (i, row) in data.iter().enumerate() {
            if row.len() != cols {
                return Err(ParityMatrixError::dimension_mismatch(
                    cols,
                    row.len(),
                    format!("columns in row {}", i),
                ));
            }
        }

        Ok(Self { data, rows, cols })
    }

    /// Creates a zero matrix of the specified dimensions.
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            data: vec![vec![BigUint::zero(); cols]; rows],
            rows,
            cols,
        }
    }

    /// Returns the number of rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Returns a reference to the underlying data.
    pub fn data(&self) -> &[Vec<BigUint>] {
        &self.data
    }

    /// Gets a reference to a specific element.
    ///
    /// # Panics
    ///
    /// Panics if indices are out of bounds.
    pub fn get(&self, row: usize, col: usize) -> &BigUint {
        &self.data[row][col]
    }

    /// Converts the matrix to rows of [`BigInt`] (non-negative; elements are in `[0, q)`).
    pub fn to_bigint_rows(&self) -> Vec<Vec<BigInt>> {
        self.data
            .iter()
            .map(|row| row.iter().map(|c| BigInt::from(c.clone())).collect())
            .collect()
    }
}

impl From<ParityMatrix> for Vec<Vec<BigUint>> {
    fn from(matrix: ParityMatrix) -> Self {
        matrix.data
    }
}

/// Trait for matrices that can be used in matrix operations.
pub trait MatrixLike {
    /// Returns the number of rows.
    fn rows(&self) -> usize;

    /// Returns the number of columns.
    fn cols(&self) -> usize;

    /// Returns a reference to the underlying data.
    fn data(&self) -> &[Vec<BigUint>];
}

impl MatrixLike for ParityMatrix {
    fn rows(&self) -> usize {
        self.rows
    }

    fn cols(&self) -> usize {
        self.cols
    }

    fn data(&self) -> &[Vec<BigUint>] {
        &self.data
    }
}

/// Configuration for parity matrix generation.
///
/// Defines the parameters for constructing a generator matrix over `Z_q`:
/// - `q`: modulus for arithmetic operations
/// - `t`: maximum degree of polynomials (must satisfy `t ≤ (n-1)/2`)
/// - `n`: number of evaluation points (polynomials are evaluated at 0, 1, ..., n)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityMatrixConfig {
    /// Modulus q
    pub q: BigUint,
    /// Degree t of the polynomial
    pub t: usize,
    /// Number of points n
    pub n: usize,
}

/// Build the generator matrix G of size (t+1) × (n+1).
///
/// The generator matrix `G` is defined as `G[i][j] = j^i mod q`, where:
/// - Row `i` corresponds to the monomial `x^i` evaluated at points `0, 1, ..., n`
/// - Column `j` corresponds to evaluation point `j`
///
/// For a polynomial `f(x) = a₀ + a₁x + ... + aₜxᵗ`, the evaluation vector
/// `[f(0), f(1), ..., f(n)]` equals `G^T · [a₀, ..., aₜ]`.
///
/// # Errors
///
/// Returns an error if `t > (n-1)/2`, violating the degree constraint.
///
/// # Example
///
/// ```
/// use e3_parity_matrix::{build_generator_matrix, ParityMatrixConfig, ParityMatrixError};
/// use num_bigint::BigUint;
///
/// let config = ParityMatrixConfig {
///     q: BigUint::from(7u32),
///     t: 2,
///     n: 5,
/// };
/// let g = build_generator_matrix(&config)?;
/// // G is a 3×6 matrix where G[i][j] = j^i mod 7
/// assert_eq!(g.rows(), 3);
/// assert_eq!(g.cols(), 6);
/// # Ok::<(), ParityMatrixError>(())
/// ```
pub fn build_generator_matrix(config: &ParityMatrixConfig) -> ParityMatrixResult<ParityMatrix> {
    // Validate modulus: q must be >= 2 for valid field arithmetic
    if config.q.is_zero() || config.q.is_one() {
        return Err(ParityMatrixError::from(MathError::InvalidModulus {
            modulus: config.q.to_string(),
            reason: "modulus must be >= 2 for valid field arithmetic".to_string(),
        }));
    }

    // Check constraint: t ≤ (n-1)/2
    let max_t = config.n.saturating_sub(1) / 2;
    if config.t > max_t {
        return Err(ParityMatrixError::from(ConstraintError::DegreeConstraint {
            t: config.t,
            n: config.n,
            max_t,
        }));
    }

    let num_coeffs = config.t + 1; // degree t polynomial has t+1 coefficients
    let mut g = vec![vec![BigUint::zero(); config.n + 1]; num_coeffs];

    for (i, row) in g.iter_mut().enumerate().take(num_coeffs) {
        for (j, cell) in row.iter_mut().enumerate().take(config.n + 1) {
            let j_big = BigUint::from(j);
            *cell = mod_pow(&j_big, i, &config.q);
        }
    }

    ParityMatrix::new(g)
}

/// Compute the null space of a matrix over `Z_q` using Gaussian elimination.
///
/// Returns a basis for the null space where each basis vector is a row.
/// The null space consists of all vectors `v` such that `matrix · v = 0 (mod q)`.
///
/// # Errors
///
/// Returns an error if a pivot element is not invertible modulo `q`.
///
/// # Example
///
/// ```
/// use e3_parity_matrix::{build_generator_matrix, null_space, ParityMatrixConfig, ParityMatrixError};
/// use num_bigint::BigUint;
///
/// let config = ParityMatrixConfig {
///     q: BigUint::from(7u32),
///     t: 2,
///     n: 5,
/// };
/// let g = build_generator_matrix(&config)?;
/// let h = null_space(&g, &config.q)?;
/// // H is a basis for vectors orthogonal to all rows of G
/// assert_eq!(h.cols(), g.cols());
/// # Ok::<(), ParityMatrixError>(())
/// ```
pub fn null_space(matrix: &ParityMatrix, q: &BigUint) -> ParityMatrixResult<ParityMatrix> {
    if matrix.rows() == 0 {
        return Ok(ParityMatrix::zeros(0, 0));
    }

    let rows = matrix.rows();
    let cols = matrix.cols();
    let matrix_data = matrix.data();

    // Create augmented matrix [A | I] to track column operations
    // We'll do row reduction on A^T to find the null space
    let mut aug: Vec<Vec<BigUint>> = vec![vec![BigUint::zero(); rows + cols]; cols];

    // Initialize: transpose of original matrix in left part, identity in right part
    for (i, aug_row) in aug.iter_mut().enumerate().take(cols) {
        aug_row[..rows]
            .iter_mut()
            .enumerate()
            .for_each(|(j, aug_cell)| {
                *aug_cell = matrix_data[j][i].clone();
            });
        aug_row[rows + i] = BigUint::one();
    }

    // Gaussian elimination with partial pivoting
    let mut pivot_row = 0;

    for col in 0..rows {
        // Find pivot in current column
        let mut found = false;
        for row in pivot_row..cols {
            if !aug[row][col].is_zero() {
                // Swap rows
                aug.swap(pivot_row, row);
                found = true;
                break;
            }
        }

        if !found {
            continue;
        }

        // Make pivot = 1
        let inv = mod_inverse(&aug[pivot_row][col], q)?;
        for j in 0..aug[pivot_row].len() {
            aug[pivot_row][j] = (&aug[pivot_row][j] * &inv) % q;
        }

        // Eliminate other entries in this column
        for row in 0..cols {
            if row != pivot_row && !aug[row][col].is_zero() {
                let factor = aug[row][col].clone();
                for j in 0..aug[row].len() {
                    let subtract = (&factor * &aug[pivot_row][j]) % q;
                    aug[row][j] = (q + &aug[row][j] - subtract) % q;
                }
            }
        }

        pivot_row += 1;
        if pivot_row >= cols {
            break;
        }
    }

    // The null space basis vectors come from rows that are zero in the left part
    let null_basis: Vec<Vec<BigUint>> = aug
        .iter()
        .take(cols)
        .filter_map(|row| {
            let is_zero_left = row[..rows].iter().all(|x| x.is_zero());
            if is_zero_left {
                let null_vec = row[rows..].to_vec();
                if null_vec.iter().any(|x| !x.is_zero()) {
                    Some(null_vec)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    ParityMatrix::new(null_basis)
}

/// Verify that `H · G^T = 0 (mod q)`.
///
/// Checks that the parity check matrix `H` is orthogonal to the generator matrix `G`,
/// which is a necessary condition for `H` to be a valid null space of `G`.
///
/// # Errors
///
/// Returns an error if verification fails (i.e., `H · G^T ≠ 0`).
///
/// # Example
///
/// ```
/// use e3_parity_matrix::{build_generator_matrix, null_space, verify_parity_matrix, ParityMatrixConfig, ParityMatrixError};
/// use num_bigint::BigUint;
///
/// let config = ParityMatrixConfig {
///     q: BigUint::from(7u32),
///     t: 2,
///     n: 5,
/// };
/// let g = build_generator_matrix(&config)?;
/// let h = null_space(&g, &config.q)?;
/// assert!(verify_parity_matrix(&g, &h, &config.q)?);
/// # Ok::<(), ParityMatrixError>(())
/// ```
pub fn verify_parity_matrix(
    matrix: &ParityMatrix,
    h: &ParityMatrix,
    q: &BigUint,
) -> ParityMatrixResult<bool> {
    if h.rows() == 0 || matrix.rows() == 0 {
        return Ok(true);
    }

    // Validate dimension compatibility: H must have same number of columns as G has rows
    if h.cols() != matrix.cols() {
        return Err(ParityMatrixError::dimension_mismatch(
            matrix.cols(),
            h.cols(),
            "H columns vs G columns",
        ));
    }

    let h_data = h.data();
    let matrix_data = matrix.data();

    // Compute H * G^T
    for (i, h_row) in h_data.iter().enumerate() {
        for (j, matrix_row) in matrix_data.iter().enumerate() {
            let sum = crate::math::dot_product_mod(h_row, matrix_row, q);
            if !sum.is_zero() {
                return Err(ParityMatrixError::verification(format!(
                    "H · G^T ≠ 0 (mod q): entry at position ({}, {}) is {}",
                    i, j, sum
                )));
            }
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::errors::ParityMatrixError;
    use crate::math::evaluate_polynomial;
    use crate::matrix::{
        build_generator_matrix, null_space, verify_parity_matrix, ParityMatrix, ParityMatrixConfig,
    };
    use num_bigint::BigUint;
    use num_traits::One;
    use num_traits::Zero;
    use std::str::FromStr;

    /// Helper: compute H * v mod q
    fn matrix_vector_mult(h: &ParityMatrix, v: &[BigUint], q: &BigUint) -> Vec<BigUint> {
        crate::math::matrix_vector_mult_mod(h.data(), v, q)
    }

    /// Test that H * G^T = 0 and that polynomial evaluations are in the null space of H
    /// t is the degree of polynomial F, so we have t+1 coefficients
    fn test_parity_matrix_for_params(q: BigUint, n: usize, t: usize) {
        let max_t = (n.saturating_sub(1)) / 2;
        assert!(
            t <= max_t,
            "t ({}) must be <= (n-1)/2 = {} for n = {}",
            t,
            max_t,
            n
        );

        let num_coeffs = t + 1; // degree t polynomial has t+1 coefficients
        let g = build_generator_matrix(&ParityMatrixConfig { q: q.clone(), n, t }).unwrap();
        let h = null_space(&g, &q).unwrap();

        // Check dimensions
        assert_eq!(g.rows(), num_coeffs, "G should have t+1 rows");
        assert_eq!(g.cols(), n + 1, "G should have n+1 columns");

        // Note: When n+1 > q, evaluation points repeat mod q, so the rank of G
        // may be less than t+1. We only check exact dimensions when n+1 <= q.
        let n_plus_1 = BigUint::from(n + 1);
        if num_coeffs < n + 1 && n_plus_1 <= q {
            assert_eq!(
                h.rows(),
                n + 1 - num_coeffs,
                "H should have n-t rows for q={}, n={}, t={}",
                q,
                n,
                t
            );
            assert_eq!(h.cols(), n + 1, "H should have n+1 columns");
        } else if h.rows() > 0 {
            assert_eq!(h.cols(), n + 1, "H should have n+1 columns");
        }

        // Verify H * G^T = 0
        assert!(
            verify_parity_matrix(&g, &h, &q).unwrap(),
            "H * G^T should be zero for q={}, n={}, t={}",
            q,
            n,
            t
        );

        // Test with multiple polynomial evaluations (degree t, so t+1 coefficients)
        let test_polys: Vec<Vec<BigUint>> = vec![
            (0..num_coeffs).map(|i| BigUint::from(i + 1) % &q).collect(), // [1, 2, 3, ...]
            (0..num_coeffs).map(|i| BigUint::from(i * 2) % &q).collect(), // [0, 2, 4, ...]
            (0..num_coeffs).map(|_| BigUint::one()).collect(),            // [1, 1, 1, ...]
            std::iter::once(BigUint::one())
                .chain(std::iter::repeat_n(BigUint::zero(), t))
                .collect(), // [1, 0, 0, ...]
        ];

        for coeffs in test_polys.iter().filter(|c| c.len() == num_coeffs) {
            // Evaluate polynomial at all points
            let eval_vec = evaluate_polynomial(coeffs, n, &q);

            // Check H * eval_vec = 0
            if h.rows() > 0 {
                let result = matrix_vector_mult(&h, &eval_vec, &q);
                assert!(
                    result.iter().all(|x| x.is_zero()),
                    "H * v should be 0 for polynomial {:?} with q={}, n={}, t={}",
                    coeffs,
                    q,
                    n,
                    t
                );
            }
        }
    }

    // ==================== Representative tests ====================
    // Most parameter combinations are covered by test_many_combinations below.
    // These tests cover specific edge cases and representative examples.

    #[test]
    fn test_default_params() {
        // Default parameters: q=7, n=5, t=2
        test_parity_matrix_for_params(BigUint::from(7u32), 5, 2);
    }

    #[test]
    fn test_small_prime_q2() {
        // Smallest prime modulus
        test_parity_matrix_for_params(BigUint::from(2u32), 3, 1);
    }

    #[test]
    fn test_large_prime_101() {
        // Large prime with high degree
        test_parity_matrix_for_params(BigUint::from(101u32), 51, 25);
    }

    // ==================== Very large primes ====================

    #[test]
    fn test_large_prime_64bit() {
        // A 64-bit prime, n=7, t=3
        let q = BigUint::from(18446744073709551557u64); // 2^64 - 59 (prime)
        test_parity_matrix_for_params(q, 7, 3);
    }

    #[test]
    fn test_large_prime_128bit() {
        // A 128-bit prime: 2^127 - 1 (Mersenne prime), n=9, t=4
        let q = BigUint::from_str("170141183460469231731687303715884105727").unwrap();
        test_parity_matrix_for_params(q, 9, 4);
    }

    #[test]
    fn test_large_prime_256bit() {
        // A 256-bit prime (BN254 prime), n=11, t=5
        let q = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        test_parity_matrix_for_params(q, 11, 5);
    }

    // ==================== Edge cases ====================

    #[test]
    fn test_t_equals_0() {
        // Degree 0 polynomials (constants)
        test_parity_matrix_for_params(BigUint::from(7u32), 3, 0);
    }

    #[test]
    fn test_minimal_case() {
        // Minimal meaningful case: n=3, t=1 (linear)
        test_parity_matrix_for_params(BigUint::from(5u32), 3, 1);
    }

    // ==================== Stress test with various parameter combinations ====================

    #[test]
    fn test_many_combinations() {
        let primes: Vec<BigUint> = vec![2u32, 3, 5, 7, 11, 13]
            .into_iter()
            .map(BigUint::from)
            .collect();

        for q in &primes {
            // n must be at least 3 for t=1 (since t ≤ (n-1)/2 means n ≥ 2t+1)
            for n in 3..=15 {
                let max_t = (n - 1) / 2;
                for t in 0..=max_t {
                    test_parity_matrix_for_params(q.clone(), n, t);
                }
            }
        }
    }

    // ==================== Tests for higher degree polynomials (should NOT be in null space) ====================

    /// Test that polynomials of degree > t are NOT in the null space of H
    fn test_higher_degree_not_in_nullspace(q: BigUint, n: usize, t: usize, higher_degree: usize) {
        assert!(higher_degree > t, "higher_degree must be > t");
        assert!(
            higher_degree <= n,
            "higher_degree must be <= n for meaningful test"
        );

        let g = build_generator_matrix(&ParityMatrixConfig { q: q.clone(), n, t }).unwrap();
        let h = null_space(&g, &q).unwrap();

        if h.rows() == 0 {
            return; // No parity checks, skip
        }

        // Create a polynomial of degree `higher_degree` (has higher_degree+1 coefficients)
        // Make sure the leading coefficient is non-zero
        let num_coeffs = higher_degree + 1;
        let coeffs: Vec<BigUint> = (1..=num_coeffs).map(|x| BigUint::from(x) % &q).collect();

        // Ensure leading coefficient is non-zero (it should be (higher_degree+1) % q)
        assert!(
            !coeffs[higher_degree].is_zero(),
            "Leading coefficient must be non-zero"
        );

        // Evaluate polynomial at all points
        let eval_vec = evaluate_polynomial(&coeffs, n, &q);

        // Check H * eval_vec ≠ 0
        let result = matrix_vector_mult(&h, &eval_vec, &q);
        assert!(
            !result.iter().all(|x| x.is_zero()),
            "H * v should NOT be 0 for degree-{} polynomial with q={}, n={}, t={}\ncoeffs={:?}\nresult={:?}",
            higher_degree,
            q,
            n,
            t,
            coeffs,
            result
        );
    }

    #[test]
    fn test_degree_t_plus_1_not_in_nullspace() {
        // For various (q, n, t), test that degree t+1 polynomial is not in null space
        let q = BigUint::from(101u32);
        let n = 11;
        let t = 5; // max degree allowed

        // Test with degree t+1
        test_higher_degree_not_in_nullspace(q.clone(), n, t, t + 1);
    }

    #[test]
    fn test_degree_t_plus_2_not_in_nullspace() {
        let q = BigUint::from(101u32);
        let n = 11;
        let t = 4;

        // Test with degree t+2
        test_higher_degree_not_in_nullspace(q.clone(), n, t, t + 2);
    }

    #[test]
    fn test_degree_n_not_in_nullspace() {
        // Test polynomial of degree n (maximum possible given n+1 points)
        let q = BigUint::from(101u32);
        let n = 11;
        let t = 3;

        test_higher_degree_not_in_nullspace(q.clone(), n, t, n);
    }

    #[test]
    fn test_higher_degree_various_params() {
        // Test multiple parameter combinations
        let test_cases = vec![
            (BigUint::from(7u32), 7, 2, 3),   // q=7, n=7, t=2, test degree 3
            (BigUint::from(7u32), 7, 2, 4),   // q=7, n=7, t=2, test degree 4
            (BigUint::from(7u32), 7, 3, 4),   // q=7, n=7, t=3, test degree 4
            (BigUint::from(11u32), 9, 3, 4),  // q=11, n=9, t=3, test degree 4
            (BigUint::from(11u32), 9, 3, 5),  // q=11, n=9, t=3, test degree 5
            (BigUint::from(11u32), 9, 4, 5),  // q=11, n=9, t=4, test degree 5
            (BigUint::from(13u32), 11, 4, 5), // q=13, n=11, t=4, test degree 5
            (BigUint::from(13u32), 11, 4, 6), // q=13, n=11, t=4, test degree 6
            (BigUint::from(13u32), 11, 5, 6), // q=13, n=11, t=5, test degree 6
            (BigUint::from(17u32), 13, 5, 6), // q=17, n=13, t=5, test degree 6
            (BigUint::from(17u32), 13, 5, 7), // q=17, n=13, t=5, test degree 7
            (BigUint::from(17u32), 13, 6, 7), // q=17, n=13, t=6, test degree 7
        ];

        for (q, n, t, higher_deg) in test_cases {
            test_higher_degree_not_in_nullspace(q, n, t, higher_deg);
        }
    }

    #[test]
    fn test_higher_degree_with_random_coeffs() {
        // Test with various non-sequential coefficient patterns
        let q = BigUint::from(101u32);
        let n = 11;
        let t = 4;
        let higher_degree = 6;

        let g = build_generator_matrix(&ParityMatrixConfig { q: q.clone(), n, t }).unwrap();
        let h = null_space(&g, &q).unwrap();

        // Test with different coefficient patterns for degree-6 polynomial
        let test_coeffs: Vec<Vec<BigUint>> = vec![
            // Pattern 1: [0, 0, 0, 0, 0, 0, 1] - pure x^6
            {
                let mut c = vec![BigUint::zero(); higher_degree];
                c.push(BigUint::one());
                c
            },
            // Pattern 2: [1, 0, 0, 0, 0, 0, 1] - 1 + x^6
            {
                let mut c = vec![BigUint::zero(); higher_degree + 1];
                c[0] = BigUint::one();
                c[higher_degree] = BigUint::one();
                c
            },
            // Pattern 3: [5, 3, 7, 2, 9, 4, 8] - random-ish
            vec![5u32, 3, 7, 2, 9, 4, 8]
                .into_iter()
                .map(BigUint::from)
                .collect(),
            // Pattern 4: [99, 50, 25, 12, 6, 3, 1] - decreasing
            vec![99u32, 50, 25, 12, 6, 3, 1]
                .into_iter()
                .map(BigUint::from)
                .collect(),
        ];

        for coeffs in test_coeffs {
            assert_eq!(coeffs.len(), higher_degree + 1);
            assert!(
                !coeffs[higher_degree].is_zero(),
                "Leading coefficient must be non-zero"
            );

            let eval_vec = evaluate_polynomial(&coeffs, n, &q);

            let result = matrix_vector_mult(&h, &eval_vec, &q);
            assert!(
                !result.iter().all(|x| x.is_zero()),
                "H * v should NOT be 0 for degree-{} polynomial with coeffs {:?}",
                higher_degree,
                coeffs
            );
        }
    }

    #[test]
    fn test_just_above_threshold() {
        // For each valid t, test that degree exactly t+1 is detected
        let q = BigUint::from(101u32);

        for n in [7, 9, 11, 13, 15] {
            let max_t = (n - 1) / 2;
            for t in 0..max_t {
                // Test degree t+1 (just above threshold)
                test_higher_degree_not_in_nullspace(q.clone(), n, t, t + 1);
            }
        }
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn test_q_equals_zero() {
        // q = 0 should return InvalidModulus error
        let q = BigUint::zero();
        let config = ParityMatrixConfig {
            q: q.clone(),
            n: 3,
            t: 1,
        };

        let result = build_generator_matrix(&config);
        assert!(result.is_err());
        match result {
            Err(ParityMatrixError::Math { message }) => {
                assert!(message.contains("Invalid modulus"));
                assert!(message.contains("modulus must be >= 2"));
            }
            _ => panic!("Expected Math error for q=0"),
        }
    }

    #[test]
    fn test_q_equals_one() {
        // q = 1 should return InvalidModulus error
        let q = BigUint::one();
        let config = ParityMatrixConfig {
            q: q.clone(),
            n: 3,
            t: 1,
        };

        let result = build_generator_matrix(&config);
        assert!(result.is_err());
        match result {
            Err(ParityMatrixError::Math { message }) => {
                assert!(message.contains("Invalid modulus"));
                assert!(message.contains("modulus must be >= 2"));
            }
            _ => panic!("Expected Math error for q=1"),
        }
    }

    #[test]
    fn test_n_equals_zero() {
        // n = 0 means we have 1 point (point 0)
        let q = BigUint::from(7u32);
        let config = ParityMatrixConfig { q, n: 0, t: 0 };

        let result = build_generator_matrix(&config);
        assert!(result.is_ok());
        if let Ok(g) = result {
            assert_eq!(g.rows(), 1); // t+1 = 1
            assert_eq!(g.cols(), 1); // n+1 = 1
            assert_eq!(g.get(0, 0), &BigUint::one()); // 0^0 = 1
        }
    }

    #[test]
    fn test_n_equals_one() {
        // n = 1 means we have 2 points (0 and 1)
        // max_t = (1-1)/2 = 0, so only t=0 is valid
        let q = BigUint::from(7u32);
        let config = ParityMatrixConfig { q, n: 1, t: 0 };

        let result = build_generator_matrix(&config);
        assert!(result.is_ok());
        if let Ok(g) = result {
            assert_eq!(g.rows(), 1); // t+1 = 1
            assert_eq!(g.cols(), 2); // n+1 = 2
            assert_eq!(g.get(0, 0), &BigUint::one()); // 0^0 = 1
            assert_eq!(g.get(0, 1), &BigUint::one()); // 1^0 = 1
        }
    }

    #[test]
    fn test_t_equals_zero_edge_cases() {
        // Test t=0 (constant polynomials) with various n and q
        let test_cases = vec![
            (BigUint::from(2u32), 3),
            (BigUint::from(3u32), 5),
            (BigUint::from(5u32), 7),
            (BigUint::from(7u32), 9),
            (BigUint::from(11u32), 11),
        ];

        for (q, n) in test_cases {
            let config = ParityMatrixConfig {
                q: q.clone(),
                n,
                t: 0,
            };
            let g = build_generator_matrix(&config).unwrap();
            let h = null_space(&g, &q).unwrap();

            // G should be 1x(n+1) with all ones
            assert_eq!(g.rows(), 1);
            assert_eq!(g.cols(), n + 1);
            assert!(g.data()[0].iter().all(|x| *x == BigUint::one()));

            // Verify H * G^T = 0
            assert!(verify_parity_matrix(&g, &h, &q).unwrap());
        }
    }

    #[test]
    fn test_empty_matrix_null_space() {
        // Empty matrix should return empty null space
        let empty = ParityMatrix::zeros(0, 0);
        let q = BigUint::from(7u32);
        let result = null_space(&empty, &q).unwrap();
        assert_eq!(result.rows(), 0);
    }

    #[test]
    fn test_empty_matrix_verify() {
        // Empty matrices should verify as true
        let empty = ParityMatrix::zeros(0, 0);
        let q = BigUint::from(7u32);
        assert!(verify_parity_matrix(&empty, &empty, &q).unwrap());
    }

    // ==================== Error Condition Tests ====================

    #[test]
    fn test_invalid_constraint_t_too_large() {
        // Test constraint violation: t > (n-1)/2
        let q = BigUint::from(7u32);
        let config = ParityMatrixConfig { q, n: 5, t: 3 }; // max_t = 2, but t=3

        let result = build_generator_matrix(&config);
        assert!(result.is_err());
        match result {
            Err(ParityMatrixError::Constraint { message }) => {
                assert!(message.contains("Degree constraint violated"));
            }
            _ => panic!("Expected Constraint error"),
        }
    }

    #[test]
    fn test_invalid_constraint_t_equals_max_plus_one() {
        // Test t = max_t + 1
        let q = BigUint::from(11u32);
        let n = 7;
        let max_t = (n - 1) / 2; // = 3
        let config = ParityMatrixConfig {
            q,
            n,
            t: max_t + 1, // = 4
        };

        let result = build_generator_matrix(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_dimension_mismatch_verify() {
        // Test verify_parity_matrix with mismatched dimensions
        let q = BigUint::from(7u32);
        let g = ParityMatrix::new(vec![vec![BigUint::one(); 3]]).unwrap(); // 1x3
        let h = ParityMatrix::new(vec![vec![BigUint::one(); 4]]).unwrap(); // 1x4 (mismatch)

        // This should error due to dimension mismatch
        let result = verify_parity_matrix(&g, &h, &q);
        assert!(result.is_err());
    }

    #[test]
    fn test_null_space_with_non_invertible_pivot() {
        // Create a matrix that might cause issues during Gaussian elimination
        // when pivot element is not invertible mod q
        let q = BigUint::from(6u32); // composite modulus
        let matrix = ParityMatrix::new(vec![
            vec![BigUint::from(2u32), BigUint::from(4u32)], // gcd(2, 6) = 2
            vec![BigUint::from(3u32), BigUint::from(3u32)], // gcd(3, 6) = 3
        ])
        .unwrap();

        // null_space should return an error when encountering a non-invertible pivot
        let result = null_space(&matrix, &q);
        assert!(result.is_err());
        match result {
            Err(ParityMatrixError::Math { message }) => {
                assert!(message.contains("Modular inverse does not exist"));
            }
            _ => panic!("Expected Math error for non-invertible pivot"),
        }
    }

    // ==================== Property-Based Tests ====================

    #[cfg(test)]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        // Strategy for generating valid BigUint moduli (primes >= 2)
        fn arb_prime_modulus() -> impl Strategy<Value = BigUint> {
            prop_oneof![
                Just(BigUint::from(2u32)),
                Just(BigUint::from(3u32)),
                Just(BigUint::from(5u32)),
                Just(BigUint::from(7u32)),
                Just(BigUint::from(11u32)),
                Just(BigUint::from(13u32)),
                Just(BigUint::from(17u32)),
                Just(BigUint::from(19u32)),
                Just(BigUint::from(23u32)),
                Just(BigUint::from(29u32)),
                Just(BigUint::from(31u32)),
                Just(BigUint::from(37u32)),
                Just(BigUint::from(41u32)),
                Just(BigUint::from(43u32)),
                Just(BigUint::from(47u32)),
                Just(BigUint::from(53u32)),
                Just(BigUint::from(59u32)),
                Just(BigUint::from(61u32)),
                Just(BigUint::from(67u32)),
                Just(BigUint::from(71u32)),
                Just(BigUint::from(73u32)),
                Just(BigUint::from(79u32)),
                Just(BigUint::from(83u32)),
                Just(BigUint::from(89u32)),
                Just(BigUint::from(97u32)),
                Just(BigUint::from(101u32)),
            ]
        }

        // Strategy for generating valid n (number of points)
        fn arb_n() -> impl Strategy<Value = usize> {
            3usize..=50
        }

        // Strategy for generating valid t given n
        fn arb_t_for_n(n: usize) -> impl Strategy<Value = usize> {
            let max_t = (n.saturating_sub(1)) / 2;
            0usize..=max_t
        }

        // Strategy for generating valid (q, n, t) triplets
        fn arb_valid_config() -> impl Strategy<Value = (BigUint, usize, usize)> {
            arb_prime_modulus().prop_flat_map(|q| {
                let q_clone = q.clone();
                arb_n().prop_flat_map(move |n| {
                    let q_clone2 = q_clone.clone();
                    arb_t_for_n(n).prop_map(move |t| (q_clone2.clone(), n, t))
                })
            })
        }

        proptest! {
            #[test]
            fn prop_h_times_g_transpose_is_zero(
                (q, n, t) in arb_valid_config()
            ) {
                let config = ParityMatrixConfig { q: q.clone(), n, t };
                let g = build_generator_matrix(&config).unwrap();
                let h = null_space(&g, &q).unwrap();

                // Property: H * G^T = 0 for all valid configs
                prop_assert!(
                    verify_parity_matrix(&g, &h, &q).unwrap(),
                    "H * G^T should be zero for q={}, n={}, t={}",
                    q, n, t
                );
            }

            #[test]
            fn prop_polynomial_evaluations_in_null_space(
                (q, n, t) in arb_valid_config()
            ) {
                let config = ParityMatrixConfig { q: q.clone(), n, t };
                let g = build_generator_matrix(&config).unwrap();
                let h = null_space(&g, &q).unwrap();

                if h.rows() == 0 {
                    return Ok(());
                }

                // Generate random polynomial coefficients of degree t
                let num_coeffs = t + 1;
                let coeffs: Vec<BigUint> = (0..num_coeffs)
                    .map(|i| BigUint::from(i as u32 + 1) % &q)
                    .collect();

                // Evaluate polynomial at all points
                let eval_vec = evaluate_polynomial(&coeffs, n, &q);

                // Property: H * eval_vec = 0 for degree-t polynomials
                let result = matrix_vector_mult(&h, &eval_vec, &q);
                prop_assert!(
                    result.iter().all(|x| x.is_zero()),
                    "H * v should be 0 for degree-{} polynomial with q={}, n={}, t={}",
                    t, q, n, t
                );
            }

            #[test]
            fn prop_higher_degree_polynomials_not_in_null_space(
                (q, n, t) in arb_valid_config()
            ) {
                // Only test if we can have a higher degree polynomial
                if t >= n {
                    return Ok(());
                }

                // Skip if n+1 > q, as evaluation points repeat mod q and rank of G may be reduced
                // This can cause higher degree polynomials to appear in null space
                let n_plus_1 = BigUint::from(n + 1);
                if n_plus_1 > q {
                    return Ok(());
                }

                let config = ParityMatrixConfig { q: q.clone(), n, t };
                let g = build_generator_matrix(&config).unwrap();
                let h = null_space(&g, &q).unwrap();

                if h.rows() == 0 {
                    return Ok(());
                }

                // Generate polynomial of degree t+1 (one more than allowed)
                let higher_degree = t + 1;
                let num_coeffs = higher_degree + 1;
                let coeffs: Vec<BigUint> = (1..=num_coeffs)
                    .map(|i| BigUint::from(i as u32) % &q)
                    .collect();

                // Ensure leading coefficient is non-zero
                if coeffs[higher_degree].is_zero() {
                    return Ok(());
                }

                // Evaluate polynomial at all points
                let eval_vec = evaluate_polynomial(&coeffs, n, &q);

                // Property: H * eval_vec ≠ 0 for degree-(t+1) polynomials
                let result = matrix_vector_mult(&h, &eval_vec, &q);
                prop_assert!(
                    !result.iter().all(|x| x.is_zero()),
                    "H * v should NOT be 0 for degree-{} polynomial with q={}, n={}, t={}",
                    higher_degree, q, n, t
                );
            }

            #[test]
            fn prop_generator_matrix_dimensions_correct(
                (q, n, t) in arb_valid_config()
            ) {
                let config = ParityMatrixConfig { q, n, t };
                let g = build_generator_matrix(&config).unwrap();

                // Property: G has correct dimensions
                prop_assert_eq!(g.rows(), t + 1, "G should have t+1 rows");
                if g.rows() > 0 {
                    prop_assert_eq!(g.cols(), n + 1, "G should have n+1 columns");
                }
            }

            #[test]
            fn prop_null_space_has_correct_dimensions(
                (q, n, t) in arb_valid_config()
            ) {
                let config = ParityMatrixConfig { q: q.clone(), n, t };
                let g = build_generator_matrix(&config).unwrap();
                let h = null_space(&g, &q).unwrap();

                // Property: H has correct column dimension
                if h.rows() > 0 {
                    prop_assert_eq!(h.cols(), n + 1, "H should have n+1 columns");
                }
            }
        }
    }
}
