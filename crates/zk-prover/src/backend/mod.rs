// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod download;
mod setup;
use e3_config::BBPath;

#[cfg(test)]
mod tests;
use crate::config::ZkConfig;
use crate::error::ZkError;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum SetupStatus {
    Ready,
    BbNeedsUpdate {
        installed: Option<String>,
        required: String,
    },
    CircuitsNeedUpdate {
        installed: Option<String>,
        required: String,
    },
    FullSetupNeeded,
}

#[derive(Debug, Clone)]
pub struct ZkBackend {
    pub base_dir: PathBuf,
    pub bb_binary: PathBuf,
    pub circuits_dir: PathBuf,
    pub work_dir: PathBuf,
    pub config: ZkConfig,
    pub using_custom_bb: bool,
}

impl ZkBackend {
    pub fn new(bb_binary: BBPath, circuits_dir: PathBuf, work_dir: PathBuf) -> Self {
        Self::with_config(bb_binary, circuits_dir, work_dir, ZkConfig::default())
    }

    /// Construct with an explicit config — primarily for tests that need to
    /// override versions or checksums.
    pub fn with_config(
        bb_binary: BBPath,
        circuits_dir: PathBuf,
        work_dir: PathBuf,
        config: ZkConfig,
    ) -> Self {
        let base_dir = circuits_dir
            .parent()
            .expect("circuits_dir should have a parent")
            .to_path_buf();

        Self {
            bb_binary: bb_binary.path(),
            circuits_dir,
            work_dir,
            base_dir,
            config,
            using_custom_bb: bb_binary.is_custom(),
        }
    }

    pub fn with_default_dir(node_name: &str) -> Result<Self, ZkError> {
        let base_dirs = directories::BaseDirs::new().ok_or_else(|| {
            ZkError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine home directory",
            ))
        })?;

        let home_dir = base_dirs.home_dir();
        let noir_dir = home_dir.join(".interfold").join("noir");
        let bb_binary = BBPath::Default(noir_dir.join("bin").join("bb"));
        let circuits_dir = noir_dir.join("circuits");
        let work_dir = noir_dir.join("work").join(node_name);

        Ok(Self::new(bb_binary, circuits_dir, work_dir))
    }

    fn sanitize_e3_id(e3_id: &str) -> Result<&str, ZkError> {
        // Sanitize e3_id to prevent path traversal
        if e3_id.is_empty()
            || e3_id.contains('\0')
            || e3_id.contains("..")
            || e3_id.contains('/')
            || e3_id.contains('\\')
        {
            return Err(ZkError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "e3_id contains invalid characters",
            )));
        }

        Ok(e3_id)
    }

    pub fn work_dir_for(&self, e3_id: &str) -> Result<PathBuf, ZkError> {
        let sanitized = Self::sanitize_e3_id(e3_id)?;
        Ok(self.work_dir.join(sanitized))
    }

    pub async fn cleanup_work_dir(&self, e3_id: &str) -> Result<(), ZkError> {
        let work_dir = self.work_dir_for(e3_id)?;
        if work_dir.exists() {
            tokio::fs::remove_dir_all(&work_dir).await?;
        }
        Ok(())
    }
}
