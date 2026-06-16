// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! # Polynomial Library
//!
//! A polynomial library with big integer coefficients designed for cryptographic operations,
//! particularly lattice-based cryptography and homomorphic encryption schemes.
//!
//! ## Features
//!
//! - Uses `num-bigint` for coefficient representation.
//! - Polynomial Modular Arithmetic: Addition, subtraction, multiplication, division reduction modulo cyclotomic polynomials and prime moduli.
//! - Range Checking: Utilities for coefficient range validation.
//! - Serialization: Optional serde support for polynomial serialization with bincode integration.
//!
//! ## Mathematical Background
//!
//! This library implements polynomial arithmetic over the ring of integers,
//! with support for modular reduction operations commonly used in:
//!
//! - Lattice-based cryptography: Polynomial rings over cyclotomic fields.
//! - Homomorphic encryption: BFV, BGV, and CKKS schemes.
//! - Zero-knowledge proofs: Polynomial commitment schemes.

pub mod crt_polynomial;
mod fhe_poly;
pub mod polynomial;
pub mod utils;

pub use crt_polynomial::{CrtPolynomial, CrtPolynomialError};
pub use fhe_poly::ToPowerBasisPoly;
pub use polynomial::{Polynomial, PolynomialError};
pub use utils::*;
