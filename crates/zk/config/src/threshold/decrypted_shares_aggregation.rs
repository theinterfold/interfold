// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::BfvParameters;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "decrypted-shares-aggregation",
    prefix: "DECRYPTED_SHARES_AGGREGATION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub committee: CiphernodesCommitteeSize,
    pub plaintext_modulus: u64,
    pub q_mod_t: BigUint,
    pub q_mod_t_centered: BigInt,
    pub q_inverse_mod_t: u64,
    pub bits: Bits,
    /// Must match MAX_MSG_NON_ZERO_COEFFS in the selected compiled C6/C7 artifacts.
    pub max_msg_non_zero_coeffs: usize,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    /// Native \([0, q_l)\) width for hashing decryption-share coefficients (C6/C7 `d_commitment`).
    pub d_native_bit: u32,
    /// Width of a single CRT residue, `max_l bits(q_l - 1)`. Every value the interpolation and the
    /// Garner step read is a residue in `[0, q_l)`.
    pub q_bit: u32,
    /// Quotient width for the in-circuit `x mod q_l` reductions. The widest input is the Lagrange
    /// interpolation sum, below `H * q_l^2`, so the quotient stays under `H * q_l`.
    pub k_bit: u32,
    /// Width of the rounded plaintext, `bits(t)`. The decode returns a value in `[0, t]`.
    pub t_bit: u32,
    /// Width of `Q`, the product of the moduli, for the rounded-decode remainder interval.
    pub q_total_bit: u32,
}
impl Configs {
    pub fn new(
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::matching_preset(threshold_params, ParameterType::THRESHOLD)?;
        let t = threshold_params.plaintext();
        let q = threshold_params.context_at_level(0)?.modulus();
        let q_mod_t = q % t;
        let q_mod_t_centered = compute_q_mod_t_centered(&q_mod_t, t);
        let t_big = BigUint::from(t);
        let q_inverse_mod_t = q
            .modinv(&t_big)
            .ok_or_else(|| {
                ConfigError::Other(format!("Q and t are not coprime, gcd = {}", q.gcd(&t_big)))
            })?
            .to_u64()
            .expect("inverse below a u64 modulus must fit u64");
        let bits = Bits::new(threshold_params)?;
        Ok(Configs {
            params: threshold_params.clone(),
            committee,

            plaintext_modulus: t,
            q_mod_t,
            q_mod_t_centered,
            q_inverse_mod_t,
            bits,
            // The circuit's message width. Every application shares it, because the width is
            // compiled into the circuit.
            max_msg_non_zero_coeffs: crate::MAX_MSG_NON_ZERO_COEFFS,
        })
    }
}
impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>) -> Result<Self, ConfigError> {
        let ctx = threshold_params
            .context_at_level(0)
            .map_err(|e| ConfigError::Other(format!("context_at_level: {:?}", e)))?;
        let d_native_bit = compute_native_crt_coeff_bit(threshold_params.moduli());
        // A residue fits `bits(q_l - 1)`; `d_native_bit` is already that maximum.
        let q_bit = d_native_bit;
        // Reduction quotients: the widest reduced input is the interpolation sum, under `H * q^2`,
        // so its quotient is under `H * q`. Six spare bits cover any committee up to 64 parties.
        let k_bit = q_bit + 6;
        let t_bit = calculate_bit_width(&BigUint::from(threshold_params.plaintext()));
        let q_total_bit = calculate_bit_width(ctx.modulus());
        Ok(Bits {
            d_native_bit,
            q_bit,
            k_bit,
            t_bit,
            q_total_bit,
        })
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let prefix = METADATA.prefix;
        let qis_str = configs
            .params
            .moduli()
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        Ok(format!(
            r#"use crate::core::threshold::decrypted_shares_aggregation::Configs as DecryptedSharesAggregationConfigs;

pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};
pub global Q_INVERSE_MOD_T: Field = {};
        
/************************************
-------------------------------------
decrypted_shares_aggregation (CIRCUIT 7)
-------------------------------------
************************************/

pub global {}_BIT_D_NATIVE: u32 = {};
pub global {}_BIT_Q: u32 = {};
pub global {}_BIT_K: u32 = {};
pub global {}_BIT_T: u32 = {};
pub global {}_BIT_Q_TOTAL: u32 = {};

pub global {}_CONFIGS: DecryptedSharesAggregationConfigs<L> =
    DecryptedSharesAggregationConfigs::new(QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T);
"#,
            configs.params.moduli().len(),
            qis_str,
            configs.plaintext_modulus,
            configs.q_mod_t,
            configs.q_mod_t_centered,
            configs.q_inverse_mod_t,
            prefix,
            configs.bits.d_native_bit,
            prefix,
            configs.bits.q_bit,
            prefix,
            configs.bits.k_bit,
            prefix,
            configs.bits.t_bit,
            prefix,
            configs.bits.q_total_bit,
            prefix,
        ))
    }
}

impl Configs {
    pub fn for_preset(
        preset: BfvPreset,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (threshold_params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(&threshold_params, committee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rounding_constants_use_the_full_level_zero_modulus() {
        for preset in [
            BfvPreset::InsecureThreshold64,
            BfvPreset::SecureThreshold8192,
        ] {
            let configs = Configs::for_preset(preset, CiphernodesCommitteeSize::Minimum).unwrap();
            // Full CRT product is independent of the cached context used by the computation.
            let q: BigUint = configs
                .params
                .moduli()
                .iter()
                .map(|&m| BigUint::from(m))
                .product();
            let t = configs.plaintext_modulus;
            assert_eq!((&q * configs.q_inverse_mod_t) % t, BigUint::from(1u32));
            assert_eq!(configs.q_mod_t, &q % t);

            assert_eq!(configs.bits.q_total_bit, q.bits() as u32);
        }
    }
}
