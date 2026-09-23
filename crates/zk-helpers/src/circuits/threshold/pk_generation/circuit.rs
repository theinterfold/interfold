// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use crate::CiphernodesCommittee;
use e3_fhe_params::ParameterType;
use e3_polynomial::{CrtPolynomial, Polynomial};

#[derive(Debug)]
pub struct PkGenerationCircuit;

impl Circuit for PkGenerationCircuit {
    const NAME: &'static str = "pk-generation";
    const PREFIX: &'static str = "PK_GENERATION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

#[derive(Debug, Clone)]
pub struct PkGenerationCircuitData {
    pub committee: CiphernodesCommittee,
    pub pk0_share: CrtPolynomial,
    pub eek: CrtPolynomial,
    pub e_sm: CrtPolynomial,
    /// Smudging noise reconstructed modulo Q, before centering. C1 range-checks this against
    /// `e_sm_bound`; the CRT limbs in `e_sm` cannot carry that bound because it exceeds every q_i.
    pub e_sm_lifted: Polynomial,
    pub sk: CrtPolynomial,
}
