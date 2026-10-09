// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit metadata shared by computation and code generation.

use crate::computation::DkgInputType;
use e3_fhe_params::ParameterType;

pub trait Circuit: Send + Sync {
    const NAME: &'static str;
    const PREFIX: &'static str;
    const SUPPORTED_PARAMETER: ParameterType;
    const DKG_INPUT_TYPE: Option<DkgInputType>;

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn prefix(&self) -> &'static str {
        Self::PREFIX
    }

    fn supported_parameter(&self) -> ParameterType {
        Self::SUPPORTED_PARAMETER
    }

    fn dkg_input_type(&self) -> Option<DkgInputType> {
        Self::DKG_INPUT_TYPE
    }
}
