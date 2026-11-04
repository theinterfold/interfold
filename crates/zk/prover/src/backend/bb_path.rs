// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::{env, path::PathBuf};

#[derive(Debug, Clone)]
pub enum BBPath {
    Custom(PathBuf),
    Default(PathBuf),
}

impl BBPath {
    pub fn new(path: PathBuf, using_custom_bb: bool) -> Self {
        if using_custom_bb {
            Self::Custom(path)
        } else {
            Self::Default(path)
        }
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, BBPath::Custom(_))
    }

    pub fn path(&self) -> PathBuf {
        match self {
            BBPath::Custom(p) => p.clone(),
            BBPath::Default(p) => p.clone(),
        }
    }

    /// Check the environment variable and if found use that otherwise use the given path
    pub fn check(default_path: PathBuf) -> Result<Self> {
        let bb_path = if let Ok(bb_path) = env::var("E3_CUSTOM_BB") {
            BBPath::Custom(bb_path.into())
        } else {
            BBPath::Default(default_path)
        };
        Ok(bb_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkBackend;

    #[tokio::test]
    async fn an_operator_selected_binary_is_not_replaced_by_the_installer() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("operator-bb");
        tokio::fs::write(&binary, b"operator managed")
            .await
            .unwrap();
        let backend = ZkBackend::new(
            BBPath::new(binary.clone(), true),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );

        backend.download_bb().await.unwrap();

        assert_eq!(tokio::fs::read(binary).await.unwrap(), b"operator managed");
    }
}
