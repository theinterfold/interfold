// SPDX-License-Identifier: LGPL-3.0-only

use super::{binding_json, keys, owner, KeyBytes, SetupBinding};
use crate::dkg::share_computation::{Inputs as SharingInputs, ShareComputationCircuitData};
use crate::encoding::{bigint_3d_to_json_values, poly_coefficients_to_toml_json};
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::{synchronized::Configs, DkgInputType};
use ndarray::Array2;
use num_bigint::BigInt;

pub struct Data {
    pub secret: CrtPolynomial,
    pub secret_sss: Vec<Array2<BigInt>>,
    pub outgoing_keys: Vec<KeyBytes>,
}

pub struct Inputs {
    pub setup_binding: SetupBinding,
    pub dealer_id: u32,
    sharing: SharingInputs,
    outgoing_keys: Vec<KeyBytes>,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        binding: SetupBinding,
        dealer_id: u32,
        data: Data,
    ) -> Result<Self, WitnessError> {
        owner(config, dealer_id)?;
        keys(config, &data.outgoing_keys, config.committee.values().n)?;
        let sharing = SharingInputs::compute(
            &config.share_computation,
            &ShareComputationCircuitData {
                dkg_input_type: DkgInputType::SecretKey,
                secret: data.secret,
                secret_sss: data.secret_sss,
            },
        )?;
        Ok(Self {
            setup_binding: binding,
            dealer_id,
            sharing,
            outgoing_keys: data.outgoing_keys,
        })
    }

    pub fn expected_secret_commitment(&self) -> &BigInt {
        &self.sharing.expected_secret_commitment
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "setup_binding": binding_json(self.setup_binding),
            "dealer_id": self.dealer_id,
            "expected_secret_commitment": self.sharing.expected_secret_commitment.to_string(),
            "sk_secret": poly_coefficients_to_toml_json(self.sharing.secret_crt.limb(0).coefficients()),
            "y": bigint_3d_to_json_values(&self.sharing.y),
            "outgoing_keys": self.outgoing_keys,
        })
    }
}
