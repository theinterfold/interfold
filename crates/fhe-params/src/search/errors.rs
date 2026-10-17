// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Error types for BFV parameter search
//!
//! This module defines specific error types using `thiserror` for better error handling,
//! debugging, and user experience in BFV parameter search operations.

use thiserror::Error;

/// Main error type for BFV parameter search
///
/// This enum covers all the different types of errors that can occur
/// during BFV parameter search and validation.
#[derive(Error, Debug)]
pub enum BfvParamsError {
    /// Validation errors for BFV parameters
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Parameter search errors
    #[error("Parameter search error: {message}")]
    Search { message: String },

    /// Generic error with context
    #[error("Error: {message}")]
    Generic { message: String },
}

/// Result type alias for BFV parameter operations
pub type BfvParamsResult<T> = Result<T, BfvParamsError>;

/// Validation error type for specific parameter validation failures
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Invalid number of votes/plaintext additions
    #[error("Invalid number of votes: {z} - {reason}")]
    InvalidVotes { z: u128, reason: String },
    /// Ring dimension that is not a power of two in 4..=32768
    #[error("Invalid ring dimension: {d} - must be a power of two in 4..=32768")]
    InvalidRingDimension { d: u64 },
    /// Smallest prime bit-length outside the range that the search supports
    #[error("Invalid minimum prime size: {bits} bits - {reason}")]
    InvalidPrimeBits { bits: u8, reason: String },
}

/// Search error type for parameter search failures
#[derive(Error, Debug)]
pub enum SearchError {
    /// No feasible parameters found
    #[error("No feasible BFV parameters found for the given constraints")]
    NoFeasibleParameters,
}

// Conversion implementations for better error handling
impl From<ValidationError> for BfvParamsError {
    fn from(err: ValidationError) -> Self {
        BfvParamsError::Validation {
            message: err.to_string(),
        }
    }
}

impl From<SearchError> for BfvParamsError {
    fn from(err: SearchError) -> Self {
        BfvParamsError::Search {
            message: err.to_string(),
        }
    }
}

impl From<String> for BfvParamsError {
    fn from(message: String) -> Self {
        BfvParamsError::Generic { message }
    }
}

impl From<&str> for BfvParamsError {
    fn from(message: &str) -> Self {
        BfvParamsError::Generic {
            message: message.to_string(),
        }
    }
}
