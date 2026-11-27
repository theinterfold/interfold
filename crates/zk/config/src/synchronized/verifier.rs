// SPDX-License-Identifier: LGPL-3.0-only

//! Independent child-key pins for the disabled request-bound verifier route.
use crate::{field::get_zkp_modulus, CircuitName, CircuitVariant, ConfigError};
use alloy_primitives::B256;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvProfile;
use num_bigint::{BigInt, Sign};
use serde::Deserialize;
use std::sync::OnceLock;

const INSECURE: &str =
    include_str!("../../../../../circuits/qualification/sync-insecure-64/minimum/manifest.json");
const SECURE: &str =
    include_str!("../../../../../circuits/qualification/sync-secure-8192/minimum/manifest.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynchronizedChildPins {
    pub c6: B256,
    pub c7: B256,
}

impl SynchronizedChildPins {
    pub fn for_profile(
        profile: BfvProfile,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        static INSECURE_PINS: OnceLock<Result<SynchronizedChildPins, String>> = OnceLock::new();
        static SECURE_PINS: OnceLock<Result<SynchronizedChildPins, String>> = OnceLock::new();
        use CiphernodesCommitteeSize::Minimum;
        let (manifest, cache) = match (profile, committee) {
            (BfvProfile::SyncDecInsecure64, Minimum) => (INSECURE, &INSECURE_PINS),
            (BfvProfile::SyncDecSecure8192, Minimum) => (SECURE, &SECURE_PINS),
            _ => {
                return Err(ConfigError::Other(
                    "no synchronized verifier for this pair".into(),
                ))
            }
        };
        cache
            .get_or_init(|| Self::parse(manifest, profile, committee))
            .clone()
            .map_err(ConfigError::Other)
    }

    fn parse(
        json: &str,
        profile: BfvProfile,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Manifest {
            format_version: u8,
            scope: String,
            admission_enabled: bool,
            profile: String,
            committee: String,
            crypto_config_id: B256,
            circuits: Vec<Circuit>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Circuit {
            role: String,
            path: String,
            target: String,
            vk_hash: B256,
        }
        let m: Manifest = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if m.format_version != 1
            || m.scope != "decryption-only"
            || m.admission_enabled
            || m.profile != profile.name()
            || m.committee != committee.as_str()
            || m.crypto_config_id
                != profile
                    .crypto_config_id(committee)
                    .map_err(|e| e.to_string())?
        {
            return Err("unexpected synchronized verifier route".into());
        }
        let pin = |role: CircuitName| -> Result<B256, String> {
            let mut entries = m.circuits.iter().filter(|c| c.role == role.as_str());
            let c = entries.next().ok_or_else(|| format!("missing {role} VK"))?;
            let variant = CircuitVariant::Recursive;
            if entries.next().is_some()
                || c.path != format!("{}/{}", variant.as_str(), role.dir_path())
                || c.target != variant.verifier_target()
                || c.vk_hash.is_zero()
                || BigInt::from_bytes_be(Sign::Plus, &c.vk_hash.0) >= get_zkp_modulus()
            {
                return Err(format!("invalid or duplicate {role} VK"));
            }
            Ok(c.vk_hash)
        };
        Ok(Self {
            c6: pin(CircuitName::ThresholdShareDecryption)?,
            c7: pin(CircuitName::DecryptedSharesAggregation)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_pins_ignore_order_and_reject_ambiguous_or_missing_keys() {
        let profile = BfvProfile::SyncDecInsecure64;
        let committee = CiphernodesCommitteeSize::Minimum;
        let parse = |f: &serde_json::Value| {
            SynchronizedChildPins::parse(&f.to_string(), profile, committee)
        };
        let mut fixture: serde_json::Value = serde_json::from_str(INSECURE).unwrap();
        let circuits = fixture["circuits"].as_array_mut().unwrap();
        circuits.reverse();
        assert_eq!(
            parse(&fixture).unwrap(),
            SynchronizedChildPins::for_profile(profile, committee).unwrap()
        );
        let entries = fixture["circuits"].as_array_mut().unwrap();
        let index = entries
            .iter()
            .position(|c| c["role"] == "share_decryption")
            .unwrap();
        let c6 = entries.remove(index);
        assert!(parse(&fixture).is_err());
        let mut c4 = c6.clone();
        c4["path"] = "recursive/dkg/share_decryption".into();
        fixture["circuits"].as_array_mut().unwrap().push(c4);
        assert!(parse(&fixture).is_err());
        fixture["circuits"].as_array_mut().unwrap().push(c6);
        assert!(parse(&fixture).is_err());
        assert!(SynchronizedChildPins::parse(SECURE, profile, committee).is_err());
        let secure =
            SynchronizedChildPins::for_profile(BfvProfile::SyncDecSecure8192, committee).unwrap();
        let local = SynchronizedChildPins::for_profile(profile, committee).unwrap();
        assert_ne!(secure.c6, local.c6);
        assert_ne!(secure.c7, local.c7);
    }
}
