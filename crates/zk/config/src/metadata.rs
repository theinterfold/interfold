// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit metadata shared by computation and code generation.

use e3_fhe_params::ParameterType;
use serde::Serialize;

use crate::constants::{FIELD_BYTE_LEN, MAX_MSG_NON_ZERO_COEFFS, MESSAGE_COEFF_BYTE_LEN};

#[derive(Debug, Clone, Copy)]
pub struct CircuitMetadata {
    pub name: &'static str,
    pub prefix: &'static str,
    pub parameter: ParameterType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitDimensions {
    pub field_byte_len: usize,
    pub message_coeffs_count: usize,
    pub message_coeff_byte_len: usize,
    pub plaintext_byte_len: usize,
}

impl CircuitDimensions {
    pub const fn current() -> Self {
        Self {
            field_byte_len: FIELD_BYTE_LEN,
            message_coeffs_count: MAX_MSG_NON_ZERO_COEFFS,
            message_coeff_byte_len: MESSAGE_COEFF_BYTE_LEN,
            plaintext_byte_len: MAX_MSG_NON_ZERO_COEFFS * MESSAGE_COEFF_BYTE_LEN,
        }
    }
}
