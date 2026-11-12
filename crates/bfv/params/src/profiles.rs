// SPDX-License-Identifier: LGPL-3.0-only

//! Protocol selection is a property of the profile, not of its threshold parameter tuple.

use crate::{
    constants::{insecure_64, INTERFOLD_BFV_VERSION},
    try_build_bfv_params_arc, BfvParamSet, BfvPreset, PresetError,
};
use e3_committee::CiphernodesCommitteeSize;
use fhe::bfv::BfvParameters;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::Arc};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfvDecryptionProtocol {
    #[serde(rename = "secret-shared")]
    SecretShared,
    #[serde(rename = "synchronized")]
    Synchronized,
}

impl BfvDecryptionProtocol {
    /// These names are hashed into configuration identities.
    pub fn name(self) -> &'static str {
        match self {
            Self::SecretShared => "secret-shared",
            Self::Synchronized => "synchronized",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BfvProfile {
    #[serde(rename = "ss-insecure-64")]
    SsInsecure64,
    #[serde(rename = "ss-secure-8192")]
    SsSecure8192,
    #[serde(rename = "sync-insecure-64")]
    SyncDecInsecure64,
}

#[derive(Debug, Error)]
pub enum BfvProfileError {
    #[error("Unknown BFV profile: {0}")]
    UnknownProfile(String),
    #[error("Unsupported BFV profile/committee: {profile}/{committee}")]
    UnsupportedCommittee {
        profile: &'static str,
        committee: CiphernodesCommitteeSize,
    },
    #[error(transparent)]
    Preset(#[from] PresetError),
    #[error("Failed to build BFV profile parameters: {0}")]
    InvalidParameters(#[from] fhe::Error),
    #[error("BFV profile {0} is disabled in this release")]
    AdmissionDisabled(&'static str),
    #[error("BFV profile {0} has no supported DKG preset")]
    UnsupportedDkgPreset(&'static str),
    #[error("Unsupported BFV crypto configuration {0}")]
    UnsupportedConfiguration(String),
}

impl BfvProfile {
    /// Definition order is also the deterministic metadata export order.
    pub const ALL: [Self; 3] = [
        Self::SsInsecure64,
        Self::SsSecure8192,
        Self::SyncDecInsecure64,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::SsInsecure64 => "ss-insecure-64",
            Self::SsSecure8192 => "ss-secure-8192",
            Self::SyncDecInsecure64 => "sync-insecure-64",
        }
    }

    pub fn protocol(self) -> BfvDecryptionProtocol {
        match self {
            Self::SsInsecure64 | Self::SsSecure8192 => BfvDecryptionProtocol::SecretShared,
            Self::SyncDecInsecure64 => BfvDecryptionProtocol::Synchronized,
        }
    }

    pub fn threshold_preset(self) -> BfvPreset {
        match self {
            Self::SsInsecure64 | Self::SyncDecInsecure64 => BfvPreset::InsecureThreshold64,
            Self::SsSecure8192 => BfvPreset::SecureThreshold8192,
        }
    }

    /// Registry slots continue to identify threshold bytes, not the protocol.
    pub fn param_set(self) -> u8 {
        self.threshold_preset()
            .on_chain_param_set()
            .expect("profiles select registered threshold presets")
    }

    pub fn dkg_name(self) -> &'static str {
        match self {
            Self::SsInsecure64 => BfvPreset::InsecureDkg64.name(),
            Self::SsSecure8192 => BfvPreset::SecureDkg8192.name(),
            Self::SyncDecInsecure64 => BfvPreset::InsecureSyncDkg64.name(),
        }
    }

    pub fn dkg_parameters(self) -> BfvParamSet {
        match self {
            Self::SsInsecure64 => BfvPreset::InsecureDkg64.into(),
            Self::SsSecure8192 => BfvPreset::SecureDkg8192.into(),
            Self::SyncDecInsecure64 => BfvPreset::InsecureSyncDkg64.into(),
        }
    }

    /// Transport parameters are selected by protocol, not by the shared threshold tuple.
    pub fn dkg_preset(self) -> Result<BfvPreset, BfvProfileError> {
        match self.protocol() {
            BfvDecryptionProtocol::SecretShared => self
                .threshold_preset()
                .dkg_counterpart()
                .ok_or(BfvProfileError::UnsupportedDkgPreset(self.name())),
            BfvDecryptionProtocol::Synchronized => Ok(BfvPreset::InsecureSyncDkg64),
        }
    }

    pub fn build_pair(self) -> Result<(Arc<BfvParameters>, Arc<BfvParameters>), BfvProfileError> {
        if self.protocol() == BfvDecryptionProtocol::SecretShared {
            return Ok(self.threshold_preset().build_pair()?);
        }
        let threshold = BfvParamSet::from(self.threshold_preset()).build_arc();
        let dkg = self.dkg_parameters();
        let dkg = try_build_bfv_params_arc(
            dkg.degree,
            dkg.plaintext_modulus,
            dkg.moduli,
            dkg.error1_variance,
        )?;
        Ok((threshold, dkg))
    }

    /// Entropy carried in limb zero of synchronized SK-share plaintexts. Degree 64 is test-only.
    pub fn prf_key_bits(self) -> Option<usize> {
        match self {
            Self::SyncDecInsecure64 => Some(insecure_64::DEGREE.min(256)),
            Self::SsInsecure64 | Self::SsSecure8192 => None,
        }
    }

    pub fn statement_version(self) -> &'static str {
        INTERFOLD_BFV_VERSION
    }

    pub fn supports_committee(self, committee: CiphernodesCommitteeSize) -> bool {
        matches!(
            (self, committee),
            (
                Self::SsInsecure64 | Self::SsSecure8192,
                CiphernodesCommitteeSize::Minimum
                    | CiphernodesCommitteeSize::Micro
                    | CiphernodesCommitteeSize::Small
            ) | (Self::SyncDecInsecure64, CiphernodesCommitteeSize::Minimum)
        )
    }

    pub fn validate_committee(
        self,
        committee: CiphernodesCommitteeSize,
    ) -> Result<(), BfvProfileError> {
        if !self.supports_committee(committee) {
            return Err(BfvProfileError::UnsupportedCommittee {
                profile: self.name(),
                committee,
            });
        }
        Ok(())
    }

    /// Release-level gate only. Chain-specific policy can restrict admission further.
    ///
    /// Recovery rechecks this gate for every saved E3 that still has work, including a failed E3
    /// that keeps its context for accusation or slashing work, and the node refuses to start if
    /// one uses a disabled profile. The gate does not apply to the restored context of an E3 that
    /// ended before startup, which only completes. To retire a profile, stop admitting it on chain,
    /// wait until its E3s end, and only then disable it here. See "Retiring a BFV profile" in
    /// `docs/architecture/upgrades.md`.
    pub fn admission_enabled(self) -> bool {
        match self {
            Self::SsInsecure64 | Self::SsSecure8192 => true,
            Self::SyncDecInsecure64 => false,
        }
    }

    pub fn ensure_admission_enabled(self) -> Result<(), BfvProfileError> {
        if !self.admission_enabled() {
            return Err(BfvProfileError::AdmissionDisabled(self.name()));
        }
        Ok(())
    }

    /// Namespace selection does not establish that the artifacts are built or qualified.
    pub fn artifacts_dir_for_committee(
        self,
        committee: CiphernodesCommitteeSize,
    ) -> Result<String, BfvProfileError> {
        self.validate_committee(committee)?;
        let directory = match self {
            Self::SsInsecure64 | Self::SsSecure8192 => self.threshold_preset().artifacts_dir(),
            Self::SyncDecInsecure64 => self.name().into(),
        };
        Ok(format!("{directory}/{committee}"))
    }

    #[cfg(feature = "abi-encoding")]
    pub fn crypto_config_id(
        self,
        committee: CiphernodesCommitteeSize,
    ) -> Result<alloy_primitives::B256, BfvProfileError> {
        self.validate_committee(committee)?;
        let (threshold, dkg) = self.build_pair()?;
        Ok(crate::bfv_profile_crypto_config_id(
            self.protocol(),
            &crate::encode_bfv_params(&threshold),
            &crate::encode_bfv_params(&dkg),
            committee,
            self.statement_version(),
        ))
    }

    /// Resolve the exact request identity, never the shared threshold bytes alone.
    /// Callers decide admission separately so a disabled profile cannot become SS work.
    #[cfg(feature = "abi-encoding")]
    pub fn from_crypto_config_id(
        param_set: u8,
        committee: CiphernodesCommitteeSize,
        crypto_config_id: alloy_primitives::B256,
    ) -> Result<Self, BfvProfileError> {
        SUPPORTED_CRYPTO_CONFIG_IDS
            .iter()
            .find(|(profile, supported, id)| {
                profile.param_set() == param_set
                    && *supported == committee
                    && *id == crypto_config_id
            })
            .map(|(profile, _, _)| *profile)
            .ok_or_else(|| BfvProfileError::UnsupportedConfiguration(crypto_config_id.to_string()))
    }
}

/// The request identity of every supported profile/committee pair, in [`BfvProfile::ALL`] order.
/// Each identity hashes the encoded parameter pair, and building the pair is too slow to repeat for
/// every request event, so the table is built once.
#[cfg(feature = "abi-encoding")]
static SUPPORTED_CRYPTO_CONFIG_IDS: std::sync::LazyLock<
    Vec<(BfvProfile, CiphernodesCommitteeSize, alloy_primitives::B256)>,
> = std::sync::LazyLock::new(|| {
    BfvProfile::ALL
        .into_iter()
        .flat_map(|profile| {
            CiphernodesCommitteeSize::ALL
                .into_iter()
                .filter(move |committee| profile.supports_committee(*committee))
                .map(move |committee| {
                    let id = profile
                        .crypto_config_id(committee)
                        .expect("built-in BFV profile parameters are valid");
                    (profile, committee, id)
                })
        })
        .collect()
});

impl FromStr for BfvProfile {
    type Err = BfvProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let name = value.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|profile| profile.name() == name)
            .ok_or_else(|| BfvProfileError::UnknownProfile(value.into()))
    }
}

impl fmt::Display for BfvProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
