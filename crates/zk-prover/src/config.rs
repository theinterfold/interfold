// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::error::ZkError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::debug;

const VERSIONS_JSON: &str = include_str!("../versions.json");

/// Supported bb binary targets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BbTarget {
    Amd64Linux,
    Amd64Darwin,
    Arm64Linux,
    Arm64Darwin,
}

impl BbTarget {
    /// Detect the current system's target
    pub fn current() -> Option<Self> {
        match (std::env::consts::ARCH, std::env::consts::OS) {
            ("x86_64", "linux") => Some(Self::Amd64Linux),
            ("x86_64", "macos") => Some(Self::Amd64Darwin),
            ("aarch64", "linux") => Some(Self::Arm64Linux),
            ("aarch64", "macos") => Some(Self::Arm64Darwin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amd64Linux => "amd64-linux",
            Self::Amd64Darwin => "amd64-darwin",
            Self::Arm64Linux => "arm64-linux",
            Self::Arm64Darwin => "arm64-darwin",
        }
    }

    /// Returns (arch, os) for URL templating
    pub fn url_parts(&self) -> (&'static str, &'static str) {
        match self {
            Self::Amd64Linux => ("amd64", "linux"),
            Self::Amd64Darwin => ("amd64", "darwin"),
            Self::Arm64Linux => ("arm64", "linux"),
            Self::Arm64Darwin => ("arm64", "darwin"),
        }
    }
}

impl std::fmt::Display for BbTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    pub bb_download_url: String,
    #[serde(default)]
    pub bb_checksums: HashMap<String, String>,
    pub circuits_download_url: String,
    #[serde(default)]
    pub circuits_checksums: HashMap<String, String>,
    pub required_bb_version: String,
    pub required_circuits_version: String,
}

impl Default for ZkConfig {
    fn default() -> Self {
        let mut config: Self = serde_json::from_str(VERSIONS_JSON)
            .expect("versions.json is invalid — this is a build-time bug");
        let archive_digest = env!("E3_CIRCUITS_ARCHIVE_SHA256");
        if !archive_digest.is_empty() {
            config
                .circuits_checksums
                .insert(env!("CARGO_PKG_VERSION").into(), archive_digest.into());
        }
        config
    }
}

impl ZkConfig {
    /// Get checksum for a specific target
    pub fn bb_checksum_for(&self, target: BbTarget) -> Option<&str> {
        self.bb_checksums.get(target.as_str()).map(|s| s.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumManifest {
    pub algorithm: String,
    pub generated: String,
    pub files: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionInfo {
    #[serde(default)]
    pub bb_version: Option<String>,
    #[serde(default)]
    pub bb_checksum: Option<String>,
    #[serde(default)]
    pub circuits_version: Option<String>,
    #[serde(default)]
    pub circuits: HashMap<String, CircuitInfo>,
    #[serde(default)]
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    pub file: String,
    pub checksum: String,
}

impl VersionInfo {
    pub async fn load(path: &Path) -> std::io::Result<Self> {
        let contents = fs::read_to_string(path).await?;
        serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents).await
    }

    pub fn bb_matches(&self, required: &str) -> bool {
        self.bb_version.as_deref() == Some(required)
    }

    pub fn circuits_match(&self, required: &str) -> bool {
        self.circuits_version.as_deref() == Some(required)
    }
}

pub fn verify_checksum(file: &str, data: &[u8], expected: Option<&str>) -> Result<(), ZkError> {
    let Some(expected) = expected else {
        debug!("no checksum provided for {}, skipping verification", file);
        return Ok(());
    };

    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = hex::encode(hasher.finalize());

    if actual != expected {
        return Err(ZkError::ChecksumMismatch {
            file: file.to_string(),
            expected: expected.to_string(),
            actual,
        });
    }

    debug!("checksum verified for {}", file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_honors_build_time_archive_pin() {
        let config = ZkConfig::default();
        let shipped: ZkConfig = serde_json::from_str(VERSIONS_JSON).unwrap();
        let digest = env!("E3_CIRCUITS_ARCHIVE_SHA256");
        if digest.is_empty() {
            assert_eq!(config.circuits_checksums, shipped.circuits_checksums);
        } else {
            assert_eq!(
                config
                    .circuits_checksums
                    .get(env!("CARGO_PKG_VERSION"))
                    .map(String::as_str),
                Some(digest)
            );
            for (version, checksum) in shipped.circuits_checksums {
                if version != env!("CARGO_PKG_VERSION") {
                    assert_eq!(config.circuits_checksums.get(&version), Some(&checksum));
                }
            }
        }
    }

    // BbTarget tests
    #[test]
    fn test_bb_target_as_str() {
        assert_eq!(BbTarget::Amd64Linux.as_str(), "amd64-linux");
        assert_eq!(BbTarget::Amd64Darwin.as_str(), "amd64-darwin");
        assert_eq!(BbTarget::Arm64Linux.as_str(), "arm64-linux");
        assert_eq!(BbTarget::Arm64Darwin.as_str(), "arm64-darwin");
    }

    #[test]
    fn test_bb_target_url_parts() {
        assert_eq!(BbTarget::Amd64Linux.url_parts(), ("amd64", "linux"));
        assert_eq!(BbTarget::Amd64Darwin.url_parts(), ("amd64", "darwin"));
        assert_eq!(BbTarget::Arm64Linux.url_parts(), ("arm64", "linux"));
        assert_eq!(BbTarget::Arm64Darwin.url_parts(), ("arm64", "darwin"));
    }

    #[test]
    fn test_verify_checksum_success() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        let result = verify_checksum("test-file", data, Some(expected));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_checksum_mismatch() {
        let data = b"hello world";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = verify_checksum("test-file", data, Some(wrong));

        let Err(ZkError::ChecksumMismatch {
            file,
            expected,
            actual,
        }) = result
        else {
            panic!("expected ChecksumMismatch error");
        };
        assert_eq!(file, "test-file");
        assert_eq!(expected, wrong);
        assert_eq!(
            actual,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_checksum_skipped_when_none() {
        let result = verify_checksum("test-file", b"any data", None);
        assert!(result.is_ok());
    }

    // ZkConfig tests (remote manifest with all targets)

    #[test]
    fn test_zk_config_bb_checksum_for_target() {
        let mut bb_checksums = HashMap::new();
        bb_checksums.insert("amd64-linux".to_string(), "checksum-amd64".to_string());
        bb_checksums.insert("arm64-darwin".to_string(), "checksum-arm64".to_string());

        let config = ZkConfig {
            bb_checksums,
            ..Default::default()
        };

        assert_eq!(
            config.bb_checksum_for(BbTarget::Amd64Linux),
            Some("checksum-amd64")
        );
        assert_eq!(
            config.bb_checksum_for(BbTarget::Arm64Darwin),
            Some("checksum-arm64")
        );
        assert_eq!(config.bb_checksum_for(BbTarget::Arm64Linux), None);
    }

    #[test]
    fn test_zk_config_default() {
        let config = ZkConfig::default();

        assert!(config.bb_download_url.contains("{version}"));
        assert!(!config.bb_checksums.is_empty());
        assert!(!config.required_bb_version.is_empty());
    }
}
