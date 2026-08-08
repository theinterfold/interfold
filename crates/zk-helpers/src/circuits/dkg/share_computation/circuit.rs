// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use e3_parity_matrix::ParityMatrix;
use e3_polynomial::CrtPolynomial;
use ndarray::Array2;
use num_bigint::BigInt;

#[derive(Debug)]
pub struct ShareComputationCircuit;

impl Circuit for ShareComputationCircuit {
    const NAME: &'static str = "share-computation";
    const PREFIX: &'static str = "SHARE_COMPUTATION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    /// None: circuit accepts runtime-varying input type (SecretKey or SmudgingNoise via `ShareComputationCircuitInput::dkg_input_type`).
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Metadata for the per-coefficient-chunk C2 circuit (`sk_share_computation_chunk` /
/// `esm_share_computation_chunk`). Proves one `chunk_size`-coefficient slice of the Shamir secret
/// shares. Consumes the same derived witness as [`ShareComputationCircuit`] but only the
/// `chunk_size`-wide slice starting at `chunk_index * chunk_size`.
#[derive(Debug)]
pub struct ShareComputationChunkCircuit;

impl Circuit for ShareComputationChunkCircuit {
    const NAME: &'static str = "share-computation-chunk";
    const PREFIX: &'static str = "SHARE_COMPUTATION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

pub struct ShareComputationCircuitData {
    /// Which secret type this data is for (determines which branch to use in data).
    pub dkg_input_type: DkgInputType,
    pub secret: CrtPolynomial,
    pub secret_sss: Vec<Array2<BigInt>>,
    pub parity_matrix: Vec<ParityMatrix>,
    pub n_parties: u32,
    pub threshold: u32,
    /// C2 coefficient chunk size (must divide the polynomial degree). Must equal the
    /// `SHARE_COMPUTATION_CHUNK_SIZE` compiled into the Noir circuit.
    pub chunk_size: u32,
}
