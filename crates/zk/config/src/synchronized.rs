// SPDX-License-Identifier: LGPL-3.0-only

//! Static definitions for the disabled synchronized setup and threshold circuits.

use crate::{dkg, field::join_display, threshold, CircuitName, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{
    utils::{compute_modulus_bit, compute_native_crt_coeff_bit},
    BfvDecryptionProtocol, BfvProfile, ParameterType,
};
use fhe::bfv::BfvParameters;
use std::sync::Arc;

pub mod public_signals;

#[derive(Clone, Debug)]
pub struct Configs {
    pub profile: BfvProfile,
    pub committee: CiphernodesCommitteeSize,
    pub threshold: Arc<BfvParameters>,
    pub transport: Arc<BfvParameters>,
    pub pk: dkg::pk::Configs,
    pub pk_generation: threshold::pk_generation::Configs,
    pub pk_aggregation: threshold::pk_aggregation::Configs,
    pub share_computation: dkg::share_computation::Configs,
    pub share_encryption: dkg::share_encryption::Configs,
    pub key_bits: usize,
    pub share_bit: u32,
    pub aggregate_bit: u32,
    pub profile_id: [u128; 2],
}

impl Configs {
    /// Definition support is not admission. Retain and validate both concrete parameter owners.
    pub fn new(
        profile: BfvProfile,
        committee: CiphernodesCommitteeSize,
        threshold: &Arc<BfvParameters>,
        transport: &Arc<BfvParameters>,
    ) -> Result<Self, ConfigError> {
        let invalid = |message: &str| ConfigError::Other(message.into());
        if profile.protocol() != BfvDecryptionProtocol::Synchronized {
            return Err(invalid("synchronized DKG requires a synchronized profile"));
        }
        profile
            .validate_committee(committee)
            .map_err(|error| invalid(&error.to_string()))?;
        crate::parameters::require_threshold_preset(profile.threshold_preset(), threshold)?;
        let transport_preset = crate::parameters::matching_preset(transport, ParameterType::DKG)?;
        if Some(transport_preset) != profile.dkg_preset().ok() {
            return Err(invalid(
                "transport does not belong to the synchronized profile",
            ));
        }
        let key_bits = profile
            .prf_key_bits()
            .ok_or_else(|| invalid("profile has no PRF key width"))?;
        let packing_q = threshold.moduli()[0];
        if key_bits > threshold.degree()
            || key_bits > 256
            || key_bits % 8 != 0
            || packing_q.checked_mul(2) != Some(transport.plaintext())
        {
            return Err(invalid(
                "synchronized keys do not fit the configured transport",
            ));
        }
        let id = profile
            .crypto_config_id(committee)
            .map_err(|error| invalid(&error.to_string()))?;
        let profile_id = [
            u128::from_be_bytes(id.as_slice()[..16].try_into().unwrap()),
            u128::from_be_bytes(id.as_slice()[16..].try_into().unwrap()),
        ];
        Ok(Self {
            profile,
            committee,
            threshold: threshold.clone(),
            transport: transport.clone(),
            pk: dkg::pk::Configs::new(transport)?,
            pk_generation: threshold::pk_generation::Configs::new(
                profile.threshold_preset(),
                threshold,
                committee,
            )?,
            pk_aggregation: threshold::pk_aggregation::Configs::new(threshold, committee)?,
            share_computation: dkg::share_computation::Configs::new(
                profile.threshold_preset(),
                threshold,
                committee,
            )?,
            share_encryption: dkg::share_encryption::Configs::new(transport)?,
            key_bits,
            share_bit: compute_native_crt_coeff_bit(threshold.moduli()),
            aggregate_bit: compute_modulus_bit(threshold),
            profile_id,
        })
    }

    pub fn for_profile(
        profile: BfvProfile,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (threshold, transport) = profile
            .build_pair()
            .map_err(|error| ConfigError::Other(error.to_string()))?;
        Self::new(profile, committee, &threshold, &transport)
    }

    pub fn source_path(&self) -> String {
        format!(
            "circuits/lib/src/configs/synchronized/{}.nr",
            self.profile.artifacts_namespace().replace('-', "_")
        )
    }

    pub fn c6_public_fields(&self) -> usize {
        // setup, owner, H roster, domain, SK/bundle/ciphertext anchors, d and c0.
        10 + self.committee.values().h
    }

    pub fn public_inputs(&self, circuit: CircuitName) -> Option<usize> {
        circuit.source_path(self.profile)?;
        let values = self.committee.values();
        match circuit {
            CircuitName::PkBfv => Some(0),
            CircuitName::PkGeneration => Some(3),
            CircuitName::SkShareComputation => Some(4),
            CircuitName::ShareEncryption => Some(2),
            CircuitName::DkgShareDecryption => {
                Some(4 + values.h * (1 + self.threshold.moduli().len()))
            }
            CircuitName::NodeFold => Some(3),
            CircuitName::NodesFold => Some(4 + values.h),
            CircuitName::PkAggregation => Some(values.h),
            CircuitName::DkgAggregator => Some(4 + values.h),
            CircuitName::ThresholdShareDecryption => Some(self.c6_public_fields() - 2),
            CircuitName::DecryptedSharesAggregation => Some(
                (values.threshold + 1) * self.c6_public_fields() + crate::MAX_MSG_NON_ZERO_COEFFS,
            ),
            CircuitName::DecryptionAggregator => self
                .public_inputs(CircuitName::DecryptedSharesAggregation)
                .map(|count| 2 + count),
            _ => None,
        }
    }

    pub fn public_outputs(&self, circuit: CircuitName) -> Option<usize> {
        circuit.source_path(self.profile)?;
        match circuit {
            CircuitName::PkBfv | CircuitName::ShareEncryption => Some(1),
            CircuitName::PkGeneration | CircuitName::DkgShareDecryption => Some(2),
            CircuitName::ThresholdShareDecryption => Some(2),
            CircuitName::DecryptedSharesAggregation | CircuitName::DecryptionAggregator => Some(0),
            CircuitName::SkShareComputation => {
                Some(self.committee.values().n * self.threshold.moduli().len() + 1)
            }
            CircuitName::NodeFold => {
                let n = self.committee.values().n;
                Some(3 + n + 2 * n * self.threshold.moduli().len())
            }
            CircuitName::NodesFold => Some(self.committee.values().h + 3),
            CircuitName::PkAggregation => Some(1),
            CircuitName::DkgAggregator => Some(3 * self.committee.values().h + 2),
            _ => None,
        }
    }

    pub fn render(&self) -> Result<String, ConfigError> {
        let committee = self.committee.values();
        let generation = &self.pk_generation;
        let decode =
            threshold::decrypted_shares_aggregation::Configs::new(&self.threshold, self.committee)?;
        if self.profile == BfvProfile::SyncDecSecure8192 {
            // Decryption-only definition; no secure DKG circuit is advertised by this source.
            return Ok(format!(
                "// Generated by `pnpm build:circuits sync-sources`. Do not edit.\n\
                 pub global N: u32 = {};\npub global N_PARTIES: u32 = {};\npub global H: u32 = {};\npub global T: u32 = {};\n\
                 pub global L: u32 = {};\npub global QIS: [Field; L] = [{}];\n\
                 pub global PROFILE_ID: [Field; 2] = [{}, {}];\npub global KEY_BITS: u32 = {};\n\
                 pub global SHARE_BIT: u32 = {};\npub global AGGREGATE_BIT: u32 = {};\npub global C6_NOISE_BOUND: Field = {};\n\
                 pub global C6_PUBLIC_FIELDS: u32 = {};\npub global C7_PLAINTEXT_MODULUS: Field = {};\n\
                 pub global C7_BIT_K: u32 = {};\npub global C7_BIT_T: u32 = {};\npub global C7_BIT_Q_TOTAL: u32 = {};\n",
                self.threshold.degree(), committee.n, committee.h, committee.threshold,
                self.threshold.moduli().len(), join_display(self.threshold.moduli(), ", "),
                self.profile_id[0], self.profile_id[1], self.key_bits, self.share_bit, self.aggregate_bit,
                generation.bounds.e_sm_bound, self.c6_public_fields(), decode.plaintext_modulus,
                decode.bits.k_bit, decode.bits.t_bit, decode.bits.q_total_bit
            ));
        }
        let crp = threshold::pk_generation::crp::crp_matrix_constant_string(&self.threshold)?;
        Ok(format!(
            "// Generated by `pnpm build:circuits sync-sources`. Do not edit.\n\
             use crate::math::polynomial::Polynomial;\n\n\
             {}\n\
             pub global N_PARTIES: u32 = {};\n\
             pub global T: u32 = {};\n\
             pub global H: u32 = {};\n\
             pub global L_THRESHOLD: u32 = {};\n\
             pub global QIS_THRESHOLD: [Field; L_THRESHOLD] = [{}];\n\
             pub global PROFILE_ID: [Field; 2] = [{}, {}];\n\
             pub global PRF_KEY_BITS: u32 = {};\n\
             pub global SHARE_BIT: u32 = {};\n\
             pub global AGGREGATE_BIT: u32 = {};\n\
             pub global C6_NOISE_BOUND: u64 = {};\n\
             pub global C6_PUBLIC_FIELDS: u32 = {};\n\
             pub global C7_PLAINTEXT_MODULUS: Field = {};\n\
             pub global C7_BIT_K: u32 = {};\n\
             pub global C7_BIT_T: u32 = {};\n\
             pub global C7_BIT_Q_TOTAL: u32 = {};\n\
             pub global PK_BIT_PK: u32 = {};\n\
             pub global PK_GENERATION_BIT_EEK: u32 = {};\n\
             pub global PK_GENERATION_BIT_SK: u32 = {};\n\
             pub global PK_GENERATION_BIT_R: u32 = {};\n\
             pub global PK_GENERATION_BIT_PK: u32 = {};\n\
             pub global PK_GENERATION_EEK_BOUND: Field = {};\n\
             {}\n",
            self.share_encryption.render()?,
            committee.n,
            committee.threshold,
            committee.h,
            self.threshold.moduli().len(),
            join_display(self.threshold.moduli(), ", "),
            self.profile_id[0],
            self.profile_id[1],
            self.key_bits,
            self.share_bit,
            self.aggregate_bit,
            u64::try_from(&generation.bounds.e_sm_bound).map_err(|_| ConfigError::Other(
                "local noise exceeds Minimum C6 integer width".into()
            ))?,
            self.c6_public_fields(),
            decode.plaintext_modulus,
            decode.bits.k_bit,
            decode.bits.t_bit,
            decode.bits.q_total_bit,
            self.pk.pk_bit,
            generation.bits.eek_bit,
            generation.bits.sk_bit,
            generation.bits.r_bit,
            generation.bits.pk_bit,
            generation.bounds.eek_bound,
            crp.replace("[Polynomial<N>; L]", "[Polynomial<N>; L_THRESHOLD]"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_owns_the_exact_transport_and_disabled_leaf_definition() {
        let profile = BfvProfile::SyncDecInsecure64;
        let committee = CiphernodesCommitteeSize::Minimum;
        let (threshold, transport) = profile.build_pair().unwrap();
        let config = Configs::new(profile, committee, &threshold, &transport).unwrap();
        assert!(Arc::ptr_eq(&threshold, &config.threshold));
        assert!(Arc::ptr_eq(&transport, &config.transport));
        assert_eq!(config.key_bits, 64);
        assert_eq!(config.share_encryption.bits.msg_bit, 28);
        assert_eq!(
            config.public_inputs(CircuitName::DkgShareDecryption),
            Some(12)
        );
        assert_eq!(
            config.public_outputs(CircuitName::SkShareComputation),
            Some(10)
        );
        assert_eq!(config.public_inputs(CircuitName::NodeFold), Some(3));
        assert_eq!(config.public_outputs(CircuitName::NodeFold), Some(24));
        assert_eq!(config.public_inputs(CircuitName::NodesFold), Some(6));
        assert_eq!(config.public_outputs(CircuitName::NodesFold), Some(5));
        assert_eq!(config.public_inputs(CircuitName::PkAggregation), Some(2));
        assert_eq!(config.public_outputs(CircuitName::PkAggregation), Some(1));
        assert_eq!(config.public_inputs(CircuitName::DkgAggregator), Some(6));
        assert_eq!(config.public_outputs(CircuitName::DkgAggregator), Some(8));
        assert_eq!(
            config.public_outputs(CircuitName::ThresholdShareDecryption),
            Some(2)
        );
        assert!(!profile.admission_enabled());
        let (_, ss_transport) = BfvProfile::SsInsecure64.build_pair().unwrap();
        assert!(Configs::new(profile, committee, &threshold, &ss_transport).is_err());
        assert!(Configs::new(BfvProfile::SsInsecure64, committee, &threshold, &transport).is_err());
        assert!(Configs::new(
            profile,
            CiphernodesCommitteeSize::Micro,
            &threshold,
            &transport
        )
        .is_err());
        assert!(dkg::share_decryption::Configs::new(&threshold, &transport).is_err());
    }
}
