// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::config::VersionInfo;
use crate::error::ZkError;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info};

use super::{SetupStatus, ZkBackend};

impl ZkBackend {
    pub fn version_file(&self) -> PathBuf {
        self.base_dir.join("version.json")
    }

    pub async fn load_version_info(&self) -> VersionInfo {
        VersionInfo::load(&self.version_file())
            .await
            .unwrap_or_default()
    }

    pub async fn check_status(&self) -> SetupStatus {
        let version_info = self.load_version_info().await;

        let (bb_ok, bb_version) = if self.using_custom_bb {
            self.custom_bb_ok().await
        } else {
            self.default_bb_ok(&version_info).await
        };

        let circuits_ok = version_info.circuits_match(&self.config.required_circuits_version)
            && self.circuits_dir.exists();

        match (bb_ok, circuits_ok) {
            (true, true) => SetupStatus::Ready,
            (false, true) => SetupStatus::BbNeedsUpdate {
                installed: bb_version,
                required: self.config.required_bb_version.clone(),
            },
            (true, false) => SetupStatus::CircuitsNeedUpdate {
                installed: version_info.circuits_version,
                required: self.config.required_circuits_version.clone(),
            },
            (false, false) => SetupStatus::FullSetupNeeded,
        }
    }

    async fn custom_bb_ok(&self) -> (bool, Option<String>) {
        if !self.bb_binary.exists() {
            return (false, None);
        };
        let version = self.verify_bb().await.ok();
        let bb_ok = version
            .as_ref()
            .is_some_and(|o| o == &self.config.required_bb_version);
        (bb_ok, version)
    }

    async fn default_bb_ok(&self, version_info: &VersionInfo) -> (bool, Option<String>) {
        if !self.bb_binary.exists() {
            return (false, None);
        };
        let version = self.verify_bb().await.ok();
        let bb_ok = version_info.bb_matches(&self.config.required_bb_version);
        (bb_ok, version)
    }

    pub async fn ensure_installed(&self) -> Result<(), ZkError> {
        fs::create_dir_all(&self.base_dir).await?;
        fs::create_dir_all(self.base_dir.join("bin")).await?;
        fs::create_dir_all(&self.circuits_dir).await?;
        fs::create_dir_all(&self.work_dir).await?;

        let status = self.check_status().await;

        match status {
            SetupStatus::Ready => {
                debug!("ZK backend is ready");
                Ok(())
            }
            SetupStatus::BbNeedsUpdate {
                installed,
                required,
            } => {
                info!(
                    "updating Barretenberg: {} -> {}",
                    installed.as_deref().unwrap_or("not installed"),
                    required
                );
                self.download_bb().await
            }
            SetupStatus::CircuitsNeedUpdate {
                installed,
                required,
            } => {
                info!(
                    "updating circuits: {} -> {}",
                    installed.as_deref().unwrap_or("not installed"),
                    required
                );
                self.download_circuits().await
            }
            SetupStatus::FullSetupNeeded => {
                info!("setting up ZK proving infrastructure...");
                self.download_bb().await?;
                self.download_circuits().await
            }
        }
    }
}
