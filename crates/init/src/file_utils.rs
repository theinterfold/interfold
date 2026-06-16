// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::Path;

use anyhow::{bail, Result};
use async_recursion::async_recursion;
use tokio::{fs, process::Command};

pub async fn ensure_empty_folder<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        fs::create_dir(path).await?;
    }

    if !path.is_dir() {
        bail!("❌ Path '{}' is not a directory", path.display());
    }

    let mut entries = std::fs::read_dir(path)
        .map_err(|e| anyhow::anyhow!("Failed to read directory '{}': {}", path.display(), e))?;

    if entries.next().is_some() {
        bail!("❌ Directory '{}' is not empty", path.display());
    }

    Ok(())
}

pub async fn delete_path<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path).await?;
        } else {
            fs::remove_file(path).await?;
        }
    }

    Ok(())
}

pub async fn chmod_recursive<P: AsRef<Path>>(path: P, mode: &str) -> Result<()> {
    Command::new("chmod")
        .arg("-R")
        .arg(mode)
        .arg(path.as_ref())
        .status()
        .await?;
    Ok(())
}

pub async fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<()> {
    Command::new("mv")
        .arg(src.as_ref())
        .arg(dst.as_ref())
        .status()
        .await?;
    Ok(())
}

#[async_recursion]
#[allow(clippy::multiple_bound_locations)]
pub async fn remove_all_files_in_dir<P: AsRef<Path> + Send>(dir_path: P) -> Result<()> {
    let mut entries = fs::read_dir(dir_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            fs::remove_file(path).await?;
        } else if path.is_dir() {
            fs::remove_dir_all(path).await?;
        }
    }
    Ok(())
}
