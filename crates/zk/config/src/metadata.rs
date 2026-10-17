// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit metadata shared by computation and code generation.

use e3_fhe_params::ParameterType;

#[derive(Debug, Clone, Copy)]
pub struct CircuitMetadata {
    pub name: &'static str,
    pub prefix: &'static str,
    pub parameter: ParameterType,
}
