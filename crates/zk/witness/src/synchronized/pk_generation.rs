// SPDX-License-Identifier: LGPL-3.0-only

use super::{binding_json, invalid, owner, SetupBinding};
use crate::encoding::{crt_polynomial_to_toml_json, polynomial_to_toml_json};
use crate::negacyclic::{exact_reduction_quotient, product_for_fold};
use crate::WitnessError;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_config::{
    synchronized::Configs, threshold::pk_generation::crp::deterministic_crp_crt_polynomial,
};
use num_bigint::BigInt;

pub struct Data {
    pub pk0_share: CrtPolynomial,
    pub eek: CrtPolynomial,
    pub sk: CrtPolynomial,
}

/// Private material deliberately has no Debug or general-purpose persistence encoding.
pub struct Inputs {
    pub setup_binding: SetupBinding,
    pub dealer_id: u32,
    pub eek: Polynomial,
    pub sk: Polynomial,
    pub ris: CrtPolynomial,
    pub pk0is: CrtPolynomial,
}

impl Inputs {
    pub fn compute(
        config: &Configs,
        binding: SetupBinding,
        dealer_id: u32,
        data: &Data,
    ) -> Result<Self, WitnessError> {
        owner(config, dealer_id)?;
        for (name, value) in [
            ("pk0", &data.pk0_share),
            ("eek", &data.eek),
            ("sk", &data.sk),
        ] {
            crate::validation::crt(name, value, &config.threshold)?;
        }
        let mut sk = data.sk.clone();
        let mut eek = data.eek.clone();
        let mut pk0is = data.pk0_share.clone();
        for value in [&mut sk, &mut eek, &mut pk0is] {
            value.reverse();
            value.center(config.threshold.moduli())?;
        }
        if sk.limbs.iter().any(|limb| limb != sk.limb(0))
            || eek.limbs.iter().any(|limb| limb != eek.limb(0))
        {
            return Err(invalid(
                "SK and key-generation error must agree across CRT limbs",
            ));
        }
        let crp = deterministic_crp_crt_polynomial(&config.threshold)?;
        let mut ris = Vec::new();
        for (limb, &modulus) in config.threshold.moduli().iter().enumerate() {
            let expression =
                product_for_fold(&crp.limb(limb).neg(), sk.limb(0), config.threshold.degree())
                    .add(eek.limb(0));
            let (_, quotient) = exact_reduction_quotient(
                pk0is.limb(limb),
                &expression,
                config.threshold.degree(),
                &BigInt::from(modulus),
            )?;
            ris.push(quotient);
        }
        Ok(Self {
            setup_binding: binding,
            dealer_id,
            sk: sk.limb(0).clone(),
            eek: eek.limb(0).clone(),
            ris: CrtPolynomial::new(ris),
            pk0is,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "setup_binding": binding_json(self.setup_binding),
            "dealer_id": self.dealer_id,
            "eek": polynomial_to_toml_json(&self.eek),
            "sk": polynomial_to_toml_json(&self.sk),
            "ris": crt_polynomial_to_toml_json(&self.ris),
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
        })
    }
}
