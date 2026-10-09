// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::metadata::Circuit;
use e3_fhe_params::ParameterType;
use fhe::bfv::{Plaintext, PublicKey};

#[derive(Debug)]
pub struct UserDataEncryptionCircuit;

impl Circuit for UserDataEncryptionCircuit {
    const NAME: &'static str = "user-data-encryption";
    const PREFIX: &'static str = "USER_DATA_ENCRYPTION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

pub struct UserDataEncryptionCircuitData {
    pub public_key: PublicKey,
    pub plaintext: Plaintext,
}
