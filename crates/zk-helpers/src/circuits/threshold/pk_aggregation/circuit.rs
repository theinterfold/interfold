// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::metadata::Circuit;
use e3_committee::CiphernodesCommittee;
use e3_fhe_params::ParameterType;
use e3_polynomial::CrtPolynomial;
use fhe::bfv::PublicKey;

#[derive(Debug)]
pub struct PkAggregationCircuit;

impl Circuit for PkAggregationCircuit {
    const NAME: &'static str = "pk-aggregation";
    const PREFIX: &'static str = "PK_AGGREGATION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

#[derive(Debug, Clone)]
pub struct PkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub public_key: PublicKey,
    pub pk0_shares: Vec<CrtPolynomial>,
    pub a: CrtPolynomial,
}
