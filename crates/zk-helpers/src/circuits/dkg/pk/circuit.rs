// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::metadata::Circuit;
use e3_fhe_params::ParameterType;
use fhe::bfv::PublicKey;

#[derive(Debug)]
pub struct PkCircuit;

impl Circuit for PkCircuit {
    const NAME: &'static str = "pk";
    const PREFIX: &'static str = "PK";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::DKG;
    const DKG_INPUT_TYPE: Option<DkgInputType> = Some(DkgInputType::SecretKey);
}

pub struct PkCircuitData {
    pub public_key: PublicKey,
}
