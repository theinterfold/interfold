// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Code generation for the share-computation BFV circuit: Prover.toml and configs.nr.

use crate::circuits::computation::CircuitComputation;
use crate::circuits::computation::Computation;
use crate::circuits::dkg::share_computation::{
    utils::parity_matrix_constant_string, Bits, Inputs, ShareComputationCircuit,
    ShareComputationCircuitData, ShareComputationOutput,
};
use crate::circuits::{Artifacts, CircuitCodegen, CircuitsErrors, CodegenToml};
use crate::codegen::CodegenConfigs;
use crate::computation::DkgInputType;
use crate::registry::Circuit;
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use serde_json::Value;

/// Implementation of [`CircuitCodegen`] for [`ShareComputationCircuit`].
impl CircuitCodegen for ShareComputationCircuit {
    type Preset = BfvPreset;
    type Data = ShareComputationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let ShareComputationOutput { inputs, bits, .. } =
            ShareComputationCircuit::compute(preset, data)?;

        let toml = generate_toml(&inputs)?;
        let configs = generate_configs(
            preset,
            &bits,
            data.n_parties as usize,
            data.threshold as usize,
            data.chunk_size as usize,
        )?;

        Ok(Artifacts { toml, configs })
    }
}

pub fn generate_toml(witness: &Inputs) -> Result<CodegenToml, CircuitsErrors> {
    let json = witness.to_json().map_err(CircuitsErrors::SerdeJson)?;

    Ok(toml::to_string(&json)?)
}

/// Builds the Prover.toml for a single C2 coefficient chunk (`sk_share_computation_chunk` /
/// `esm_share_computation_chunk`): `chunk_idx`, a `chunk_size`-coefficient `secret_chunk`, and the
/// matching `y_chunk` slice. This mirrors the slice that `e3-zk-prover` computes at prove time, so
/// the isolated benchmark uses the same witness shape the runtime proves per chunk.
pub fn generate_chunk_toml(
    witness: &Inputs,
    chunk_size: usize,
    chunk_idx: usize,
) -> Result<CodegenToml, CircuitsErrors> {
    let full = witness.to_json().map_err(CircuitsErrors::SerdeJson)?;
    let obj = full
        .as_object()
        .ok_or_else(|| CircuitsErrors::Sample("chunk toml root must be an object".into()))?;

    let start = chunk_idx * chunk_size;
    let end = start + chunk_size;

    let secret_key = match witness.dkg_input_type {
        DkgInputType::SecretKey => "sk_secret",
        DkgInputType::SmudgingNoise => "e_sm_secret",
    };
    let secret = obj
        .get(secret_key)
        .ok_or_else(|| CircuitsErrors::Sample(format!("chunk toml missing {secret_key}")))?;
    let chunk_json = match secret {
        Value::Object(_) => {
            // SK limb: {"coefficients": [c0..cn]}
            let coeffs = secret
                .get("coefficients")
                .and_then(Value::as_array)
                .ok_or_else(|| CircuitsErrors::Sample("chunk SK secret malformed".into()))?;
            if start >= coeffs.len() {
                return Err(CircuitsErrors::Sample(format!(
                    "chunk [{start},{end}) out of bounds for secret of length {}",
                    coeffs.len()
                )));
            }
            let slice_end = end.min(coeffs.len());
            Value::Object(
                [(
                    "coefficients".into(),
                    Value::Array(coeffs[start..slice_end].to_vec()),
                )]
                .into_iter()
                .collect(),
            )
        }
        Value::Array(limbs) => {
            // ESM crt limbs: [{ "coefficients": [..] }, ..]
            let sliced = limbs
                .iter()
                .map(|limb| {
                    let coeffs = limb
                        .get("coefficients")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            CircuitsErrors::Sample("chunk e-sm limb malformed".into())
                        })?;
                    if start >= coeffs.len() {
                        return Err(CircuitsErrors::Sample(format!(
                            "chunk [{start},{end}) out of bounds for e-sm limb of length {}",
                            coeffs.len()
                        )));
                    }
                    let slice_end = end.min(coeffs.len());
                    Ok::<Value, CircuitsErrors>(Value::Object(
                        [(
                            "coefficients".into(),
                            Value::Array(coeffs[start..slice_end].to_vec()),
                        )]
                        .into_iter()
                        .collect(),
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::Array(sliced)
        }
        other => {
            return Err(CircuitsErrors::Sample(format!(
                "chunk secret has unexpected shape: {:?}",
                other.to_string().chars().take(40).collect::<String>()
            )))
        }
    };

    let y_chunk = obj
        .get("y")
        .and_then(Value::as_array)
        .ok_or_else(|| CircuitsErrors::Sample("chunk toml missing y".into()))?
        .get(start..end)
        .ok_or_else(|| {
            CircuitsErrors::Sample(format!("chunk [{start},{end}) out of bounds for witness y"))
        })?
        .to_vec();

    let json = serde_json::json!({
        "chunk_idx": chunk_idx,
        "secret_chunk": chunk_json,
        "y_chunk": y_chunk,
    });

    Ok(toml::to_string(&json)?)
}

/// Builds the configs.nr string (N, L, parity matrix, bit parameters, configs) for the Noir prover.
///
/// `n_parties` and `threshold` are used to build the parity matrix (Reed–Solomon generator null space)
/// and must match the committee size used for the input/sample.
pub fn generate_configs(
    preset: BfvPreset,
    bits: &Bits,
    n_parties: usize,
    threshold: usize,
    chunk_size: usize,
) -> Result<CodegenConfigs, CircuitsErrors> {
    generate_configs_with_chunk_size(preset, bits, n_parties, threshold, chunk_size)
}

pub fn generate_configs_with_chunk_size(
    preset: BfvPreset,
    bits: &Bits,
    n_parties: usize,
    threshold: usize,
    chunk_size: usize,
) -> Result<CodegenConfigs, CircuitsErrors> {
    let (threshold_params, _) =
        build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
    if chunk_size == 0 {
        return Err(CircuitsErrors::Sample(
            "C2 chunk size must be greater than zero".into(),
        ));
    }
    // C2's parity matrix must match a canonical (T, N) committee; reject arbitrary values.
    crate::ciphernodes_committee::try_canonical_from_t_n(n_parties, threshold)
        .map_err(|e| CircuitsErrors::Sample(e.to_string()))?;
    let degree = threshold_params.degree();
    if !degree.is_multiple_of(chunk_size) {
        return Err(CircuitsErrors::Sample(format!(
            "C2 chunk size {chunk_size} must divide polynomial degree {degree}"
        )));
    }
    let chunk_count = degree / chunk_size;
    let config_name = preset.metadata().security.as_config_str();
    let parity_matrix_str = parity_matrix_constant_string(&threshold_params, n_parties, threshold)?;
    let prefix = <ShareComputationCircuit as Circuit>::PREFIX;
    let configs = format!(
        r#"
pub use crate::configs::{}::threshold::{{L as L_THRESHOLD, QIS as QIS_THRESHOLD}};

pub global N: u32 = {};
pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = {};
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = {};

{}
/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

// share_computation_sk - bit parameters
pub global {}_BIT_SHARE: u32 = {};
pub global {}_SK_BIT_SECRET: u32 = {};

// share_computation_sk - configs
pub global {}_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

// share_computation_e_sm - bit parameters
pub global {}_E_SM_BIT_SECRET: u32 = {};

// verify_shares - configs
pub global {}_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);
"#,
        config_name,
        degree,
        chunk_size,
        chunk_count,
        parity_matrix_str,
        prefix,
        bits.bit_share,
        prefix,
        bits.bit_sk_secret,
        prefix,
        prefix,
        bits.bit_e_sm_secret,
        prefix,
    );

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::circuits::computation::Computation;
    use crate::circuits::computation::DkgInputType;
    use crate::circuits::dkg::share_computation::{Bits, Bounds};
    use crate::codegen::write_artifacts;
    use crate::Circuit;
    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();

        let artifacts = ShareComputationCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        let sk_secret = parsed.get("sk_secret").unwrap();
        assert!(sk_secret
            .get("coefficients")
            .and_then(|c| c.as_array())
            .is_some());
        let y = parsed.get("y").and_then(|v| v.as_array()).unwrap();
        assert!(!y.is_empty());
        assert!(parsed.get("expected_secret_commitment").is_some());

        let temp_dir = TempDir::new().unwrap();
        write_artifacts(
            Some(&artifacts.toml),
            &artifacts.configs,
            Some(temp_dir.path()),
        )
        .unwrap();

        let output_path = temp_dir.path().join("Prover.toml");
        assert!(output_path.exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("sk_secret"));
        assert!(content.contains("expected_secret_commitment"));
        assert!(content.contains("y"));

        let configs_path = temp_dir.path().join("configs.nr");
        assert!(configs_path.exists());

        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();
        let prefix = <ShareComputationCircuit as Circuit>::PREFIX;

        assert!(configs_content.contains(
            format!(
                "N: u32 = {}",
                BfvPreset::InsecureThreshold512.metadata().degree
            )
            .as_str()
        ));
        assert!(configs_content
            .contains(format!("{}_BIT_SHARE: u32 = {}", prefix, bits.bit_share).as_str()));
        assert!(configs_content
            .contains(format!("{}_SK_BIT_SECRET: u32 = {}", prefix, bits.bit_sk_secret).as_str()));
        assert!(configs_content.contains(
            format!("{}_E_SM_BIT_SECRET: u32 = {}", prefix, bits.bit_e_sm_secret).as_str()
        ));
    }

    #[test]
    fn test_chunk_toml_shape() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let mut sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        sample.chunk_size = 256;
        let output =
            ShareComputationCircuit::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let chunk = generate_chunk_toml(&output.inputs, 256, 1).unwrap();

        let parsed: toml::Value = chunk.parse().unwrap();
        assert_eq!(parsed.get("chunk_idx").unwrap().as_integer(), Some(1));
        let secret_chunk = parsed.get("secret_chunk").unwrap();
        let coeffs = secret_chunk
            .get("coefficients")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(coeffs.len(), 256);
        let y_chunk = parsed.get("y_chunk").unwrap().as_array().unwrap();
        assert_eq!(y_chunk.len(), 256);
    }

    #[test]
    fn test_chunk_size_is_written_to_configs() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let n_parties = committee.n;
        let threshold = committee.threshold;
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();
        let configs = generate_configs_with_chunk_size(
            BfvPreset::InsecureThreshold512,
            &bits,
            n_parties,
            threshold,
            256,
        )
        .unwrap();

        assert!(configs.contains("SHARE_COMPUTATION_CHUNK_SIZE: u32 = 256"));
        assert!(configs.contains("SHARE_COMPUTATION_N_CHUNKS: u32 = 2"));
    }

    #[test]
    fn test_chunk_size_must_divide_degree() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let n_parties = committee.n;
        let threshold = committee.threshold;
        let sample = ShareComputationCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();
        let error = generate_configs_with_chunk_size(
            BfvPreset::InsecureThreshold512,
            &bits,
            n_parties,
            threshold,
            255,
        )
        .unwrap_err();

        assert!(error.to_string().contains("must divide polynomial degree"));
    }
}
