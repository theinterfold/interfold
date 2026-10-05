// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of one party's l-BFV secrets into Noir witnesses.
//!
//! At secure-16384 the aggregator ignores standalone C1 verification and the published key comes
//! from `lbfv_pk_aggregation` over the row proofs, so C1's public-key equation is dead weight on
//! that path. Only its two secret commitments stay live, and this circuit produces them without the
//! 5-limb public-key relation.
//!
//! One `e_sm` set per party is enough, and a per-limb circuit could not build this commitment
//! anyway: each `e_sm` chunk commitment spans all `L` CRT limbs at once.

use crate::threshold::lbfv_proof_domain::{lbfv_proof_session, validate_lbfv_generation_party_id};
use crate::utils::verify_crt_shapes;
use crate::{
    crt_polynomial_to_toml_json, polynomial_to_toml_json, Artifacts, CiphernodesCommittee, Circuit,
    CircuitCodegen, CircuitComputation, CircuitsErrors, CodegenToml, Computation,
};
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::BigInt;

/// Gadget rows at secure-16384, the only preset with an l-BFV path. Matches `GADGET_DIM`.
pub const LBFV_GADGET_ROWS: usize = 5;

/// Per-party l-BFV secrets circuit.
#[derive(Debug)]
pub struct LbfvPartySecretsCircuit;

impl Circuit for LbfvPartySecretsCircuit {
    const NAME: &'static str = "lbfv-party-secrets";
    const PREFIX: &'static str = "LBFV_PARTY_SECRETS";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// Circuit-ready values for one party's l-BFV secrets.
#[derive(Debug, Clone)]
pub struct LbfvPartySecretsCircuitData {
    /// Committee values used by the matching circuit configuration.
    pub committee: CiphernodesCommittee,
    /// Protocol context used to derive the public proof-session identifier.
    pub proof_domain: LbfvProofDomainContext,
    /// Zero-based party ID in the finalized committee.
    pub party_id: u32,
    /// Secret-key polynomial, one limb per CRT modulus.
    pub sk: CrtPolynomial,
    /// Smudging noise, one limb per CRT modulus.
    pub e_sm: CrtPolynomial,
    /// One key-generation error per gadget row, in row order. Bounded and committed here so the
    /// limb proofs can open to the commitments instead of repeating the check per limb.
    pub eek: Vec<Polynomial>,
}

/// Computed values for one l-BFV party-secrets proof.
pub struct LbfvPartySecretsComputationOutput {
    pub bounds: super::Bounds,
    pub bits: super::Bits,
    pub inputs: LbfvPartySecretsInputs,
}

/// Prover inputs for one party's l-BFV secrets.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LbfvPartySecretsInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub party_id: u32,
    /// The circuit takes a single secret-key polynomial, so only the first centered limb is used.
    /// Every limb carries the same ternary values; `compute` checks that before selecting one.
    pub sk: Polynomial,
    pub e_sm: CrtPolynomial,
    pub eek: Vec<Polynomial>,
}

impl LbfvPartySecretsInputs {
    pub fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "party_id": self.party_id,
            "sk": polynomial_to_toml_json(&self.sk),
            "e_sm": crt_polynomial_to_toml_json(&self.e_sm),
            "eek": self.eek.iter().map(polynomial_to_toml_json).collect::<Vec<_>>(),
        }))
    }
}

impl Computation for LbfvPartySecretsInputs {
    type Preset = BfvPreset;
    type Data = LbfvPartySecretsCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let moduli = params.moduli().to_vec();
        let n = params.degree();

        validate_lbfv_generation_party_id(data.party_id, &data.committee)?;
        verify_crt_shapes(&[&data.sk, &data.e_sm], moduli.len(), n).map_err(|error| {
            CircuitsErrors::Other(format!("invalid l-BFV party-secrets CRT shape: {error}"))
        })?;

        // Center every limb the way C1 does, so both circuits commit to identical coefficients.
        let mut sk_limbs = Vec::with_capacity(moduli.len());
        let mut e_sm_limbs = Vec::with_capacity(moduli.len());
        for (index, modulus) in moduli.iter().enumerate() {
            let modulus = BigInt::from(*modulus);

            let mut sk = data.sk.limb(index).clone();
            sk.reverse();
            sk.center(&modulus);
            sk_limbs.push(sk);

            let mut e_sm = data.e_sm.limb(index).clone();
            e_sm.reverse();
            e_sm.center(&modulus);
            e_sm_limbs.push(e_sm);
        }

        // The circuit takes one `sk`, because a ternary secret is the same in every CRT basis.
        // Reject data where that does not hold rather than silently proving the first limb.
        for (index, limb) in sk_limbs.iter().enumerate().skip(1) {
            if limb != &sk_limbs[0] {
                return Err(CircuitsErrors::Other(format!(
                    "l-BFV party-secrets secret key differs between CRT limb 0 and {index}"
                )));
            }
        }

        let sk = sk_limbs
            .into_iter()
            .next()
            .ok_or_else(|| CircuitsErrors::Other("l-BFV party-secrets has no CRT limb".into()))?;
        if sk.coefficients().len() != n {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV party-secrets secret key has {} coefficients; expected {n}",
                sk.coefficients().len()
            )));
        }

        if data.eek.len() != LBFV_GADGET_ROWS {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV party-secrets expects {LBFV_GADGET_ROWS} row errors; got {}",
                data.eek.len()
            )));
        }
        for (row, eek) in data.eek.iter().enumerate() {
            if eek.coefficients().len() != n {
                return Err(CircuitsErrors::Other(format!(
                    "l-BFV party-secrets error for row {row} has {} coefficients; expected {n}",
                    eek.coefficients().len()
                )));
            }
        }

        let session = lbfv_proof_session(data.proof_domain)?;
        Ok(LbfvPartySecretsInputs {
            session_id_hi: session.session_id_hi,
            session_id_lo: session.session_id_lo,
            party_id: data.party_id,
            sk,
            e_sm: CrtPolynomial::new(e_sm_limbs),
            eek: data.eek.clone(),
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        LbfvPartySecretsInputs::to_json(self)
    }
}

impl CircuitComputation for LbfvPartySecretsCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPartySecretsCircuitData;
    type Output = LbfvPartySecretsComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = super::Bounds::compute(preset, &data.committee)?;
        let bits = super::Bits::compute(preset, &bounds)?;
        let inputs = LbfvPartySecretsInputs::compute(preset, data)?;
        Ok(LbfvPartySecretsComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

impl CircuitCodegen for LbfvPartySecretsCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPartySecretsCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = LbfvPartySecretsInputs::compute(preset, data)?;
        let configs = super::Configs::compute(preset, &data.committee)?;
        Ok(Artifacts {
            toml: generate_lbfv_party_secrets_toml(inputs)?,
            configs: super::codegen::generate_configs(preset, &configs)?,
        })
    }
}

impl LbfvPartySecretsCircuitData {
    /// Generate one party's secrets for code generation and prover tests.
    ///
    /// Reuses the C1 sample generator: both circuits commit to the same two secrets, so sharing the
    /// generator keeps them from drifting apart.
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
    ) -> Result<Self, CircuitsErrors> {
        let sample = super::PkGenerationCircuitData::generate_sample(preset, committee.clone())?;
        // One error per gadget row, taken from the same row generator the limbs use, so a sampled
        // party and its sampled rows agree on every commitment.
        let mut eek = Vec::with_capacity(LBFV_GADGET_ROWS);
        for row in 0..LBFV_GADGET_ROWS as u32 {
            let row_sample = super::LbfvPkGenerationCircuitData::generate_sample_for_row(
                preset,
                committee.clone(),
                row,
            )?;
            eek.push(row_sample.eek);
        }
        Ok(Self {
            committee,
            proof_domain: crate::threshold::lbfv_proof_domain::sample_lbfv_proof_domain(),
            party_id: 0,
            sk: sample.sk,
            e_sm: sample.e_sm,
            eek,
        })
    }
}

/// Serialize one party's l-BFV secrets as `Prover.toml`.
pub fn generate_lbfv_party_secrets_toml(
    inputs: LbfvPartySecretsInputs,
) -> Result<CodegenToml, CircuitsErrors> {
    Ok(toml::to_string(&inputs.to_json()?)?)
}
