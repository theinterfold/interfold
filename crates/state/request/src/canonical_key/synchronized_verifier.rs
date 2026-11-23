// SPDX-License-Identifier: LGPL-3.0-only

//! Independent child-key pins for the disabled request-bound verifier route.
use super::*;
use anyhow::Context;
use serde::Deserialize;
use std::sync::LazyLock;

const MANIFEST: &str =
    include_str!("../../../../../circuits/qualification/sync-insecure-64/minimum/manifest.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynchronizedChildPins {
    pub c6: B256,
    pub c7: B256,
}

impl SynchronizedChildPins {
    pub fn insecure_minimum() -> Result<Self> {
        static PINS: LazyLock<Result<SynchronizedChildPins, String>> =
            LazyLock::new(|| SynchronizedChildPins::parse(MANIFEST).map_err(|e| format!("{e:#}")));
        PINS.as_ref()
            .copied()
            .map_err(|e| anyhow::anyhow!("invalid synchronized verifier manifest: {e}"))
    }

    fn parse(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Manifest {
            format_version: u8,
            profile: String,
            committee: String,
            crypto_config_id: B256,
            circuits: Vec<Circuit>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Circuit {
            role: String,
            target: String,
            vk_hash: B256,
        }
        let m: Manifest = serde_json::from_str(json)?;
        let profile = BfvProfile::SyncDecInsecure64;
        let committee = CiphernodesCommitteeSize::Minimum;
        ensure!(
            m.format_version == 1
                && m.profile == profile.name()
                && m.committee == committee.as_str()
                && m.crypto_config_id == profile.crypto_config_id(committee)?,
            "unexpected verifier route"
        );
        let pin = |role: &str| -> Result<B256> {
            let mut entries = m.circuits.iter().filter(|c| c.role == role);
            let c = entries
                .next()
                .with_context(|| format!("missing {role} VK"))?;
            ensure!(
                entries.next().is_none() && c.target == "noir-recursive" && !c.vk_hash.is_zero(),
                "invalid or duplicate {role} VK"
            );
            Ok(c.vk_hash)
        };
        Ok(Self {
            c6: pin("share_decryption")?,
            c7: pin("decrypted_shares_aggregation")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_pins_ignore_order_and_reject_ambiguous_or_missing_keys() -> Result<()> {
        let mut fixture: serde_json::Value = serde_json::from_str(MANIFEST)?;
        let circuits = fixture["circuits"].as_array_mut().unwrap();
        circuits.reverse();
        assert_eq!(
            SynchronizedChildPins::parse(&fixture.to_string())?,
            SynchronizedChildPins::insecure_minimum()?
        );
        let entries = fixture["circuits"].as_array_mut().unwrap();
        let index = entries
            .iter()
            .position(|c| c["role"] == "share_decryption")
            .unwrap();
        let c6 = entries.remove(index);
        assert!(SynchronizedChildPins::parse(&fixture.to_string()).is_err());
        fixture["circuits"]
            .as_array_mut()
            .unwrap()
            .extend([c6.clone(), c6]);
        assert!(SynchronizedChildPins::parse(&fixture.to_string()).is_err());
        Ok(())
    }
}
