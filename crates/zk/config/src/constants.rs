// SPDX-License-Identifier: LGPL-3.0-only

//! Shared dimensions of circuit public values and their native encoding.

/// Size of one Noir BN254 scalar field element in bytes.
pub const FIELD_BYTE_LEN: usize = 32;

/// Number of native ascending message coefficients exposed by C6/C7.
pub const MAX_MSG_NON_ZERO_COEFFS: usize = 50;

/// Size of one native plaintext coefficient in bytes.
pub const MESSAGE_COEFF_BYTE_LEN: usize = std::mem::size_of::<u64>();
