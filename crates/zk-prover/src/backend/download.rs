// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::config::{verify_checksum, BbTarget, ChecksumManifest, CircuitInfo};
use crate::error::ZkError;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;
use tokio::fs;
use tracing::{info, warn};
use walkdir::WalkDir;

use super::ZkBackend;

/// Known committee subdirectories in per-committee circuit release layouts (v0.2.0+).
const COMMITTEE_SUBDIRS: &[&str] = &["minimum", "micro", "small"];

/// Circuit artifact variant directories at `{preset}/{committee?}/{variant}/...`.
const CIRCUIT_VARIANT_DIRS: &[&str] = &["default", "evm", "recursive"];

/// Collect candidate on-disk paths for a manifest entry (legacy flat + per-committee layouts).
fn circuit_manifest_candidates(circuits_dir: &Path, rel_path: &str) -> Vec<PathBuf> {
    let direct = circuits_dir.join(rel_path);
    let mut candidates = vec![direct.clone()];

    let mut parts = rel_path.split('/');
    let Some(preset) = parts.next() else {
        return candidates;
    };
    let Some(next) = parts.next() else {
        return candidates;
    };
    if COMMITTEE_SUBDIRS.contains(&next) || !CIRCUIT_VARIANT_DIRS.contains(&next) {
        return candidates;
    }
    let suffix = parts.collect::<Vec<_>>().join("/");
    let suffix = if suffix.is_empty() {
        String::new()
    } else {
        format!("/{suffix}")
    };

    for committee in COMMITTEE_SUBDIRS {
        candidates.push(circuits_dir.join(format!("{preset}/{committee}/{next}{suffix}")));
    }

    candidates
}

/// Resolve a manifest path to an on-disk file, matching `expected_hash` when multiple committee
/// copies exist (v0.2.0 flat checksums vs per-committee tarball layout).
async fn locate_manifest_artifact(
    circuits_dir: &Path,
    rel_path: &str,
    expected_hash: &str,
) -> Result<PathBuf, ZkError> {
    let mut last_mismatch: Option<(PathBuf, String)> = None;

    for candidate in circuit_manifest_candidates(circuits_dir, rel_path) {
        if !candidate.exists() {
            continue;
        }
        let data = fs::read(&candidate).await?;
        match verify_checksum(rel_path, &data, Some(expected_hash)) {
            Ok(()) => return Ok(candidate),
            Err(ZkError::ChecksumMismatch { actual, .. }) => {
                last_mismatch = Some((candidate, actual));
            }
            Err(e) => return Err(e),
        }
    }

    if let Some((_path, actual)) = last_mismatch {
        return Err(ZkError::ChecksumMismatch {
            file: rel_path.to_string(),
            expected: expected_hash.to_string(),
            actual,
        });
    }

    Err(ZkError::CircuitNotFound(rel_path.to_string()))
}

async fn read_manifest_file(
    circuits_dir: &Path,
    rel_path: &str,
    expected_hash: &str,
) -> Result<Vec<u8>, ZkError> {
    let path = locate_manifest_artifact(circuits_dir, rel_path, expected_hash).await?;
    fs::read(&path).await.map_err(ZkError::from)
}

impl ZkBackend {
    /// Resolve a `checksums.json` entry to an on-disk path (legacy flat or per-committee layout).
    pub async fn locate_manifest_artifact(
        &self,
        rel_path: &str,
        expected_hash: &str,
    ) -> Result<PathBuf, ZkError> {
        locate_manifest_artifact(&self.circuits_dir, rel_path, expected_hash).await
    }

    pub async fn download_bb(&self) -> Result<(), ZkError> {
        if self.using_custom_bb {
            println!("IGNORING DOWNLOAD BECAUSE WE ARE USING A CUSTOM BB");
            return Ok(());
        }

        let target = BbTarget::current().ok_or_else(|| ZkError::UnsupportedPlatform {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        })?;

        let (arch, os) = target.url_parts();
        let version = &self.config.required_bb_version;

        let url = self
            .config
            .bb_download_url
            .replace("{version}", version)
            .replace("{os}", os)
            .replace("{arch}", arch);

        info!("downloading Barretenberg from: {}", url);

        let bytes = download_with_progress(&url, "Downloading bb").await?;
        let expected_checksum = self.config.bb_checksum_for(target);
        verify_checksum(&format!("bb-{}", target), &bytes, expected_checksum)?;

        let decoder = GzDecoder::new(&bytes[..]);
        let mut archive = Archive::new(decoder);

        let bin_dir = self.base_dir.join("bin");
        fs::create_dir_all(&bin_dir).await?;

        let temp_dir = tempfile::tempdir()?;
        archive.unpack(temp_dir.path())?;

        let bb_source = find_bb_in_dir(temp_dir.path())?;

        fs::copy(&bb_source, &self.bb_binary).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.bb_binary).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&self.bb_binary, perms).await?;
        }

        let mut version_info = self.load_version_info().await;
        version_info.bb_version = Some(version.clone());
        version_info.bb_checksum = expected_checksum.map(|s| s.to_string());
        version_info.last_updated = Some(chrono::Utc::now().to_rfc3339());
        version_info.save(&self.version_file()).await?;

        info!("installed Barretenberg v{}", version);
        Ok(())
    }

    pub async fn download_circuits(&self) -> Result<(), ZkError> {
        let version = &self.config.required_circuits_version;
        let url = self
            .config
            .circuits_download_url
            .replace("{version}", version);

        info!("downloading circuits from: {}", url);

        let result = download_with_progress(&url, "Downloading circuits").await;

        let mut version_info = self.load_version_info().await;

        match result {
            Ok(bytes) => {
                if self.circuits_dir.exists() {
                    fs::remove_dir_all(&self.circuits_dir).await?;
                }

                let decoder = GzDecoder::new(&bytes[..]);
                let mut archive = Archive::new(decoder);
                archive.unpack(&self.base_dir)?;

                let circuit_infos = self.verify_circuits().await?;

                version_info.circuits = circuit_infos;
                version_info.circuits_version = Some(version.clone());
                version_info.last_updated = Some(chrono::Utc::now().to_rfc3339());
                version_info.save(&self.version_file()).await?;

                info!("installed circuits v{}", version);
            }
            Err(e) => {
                return Err(ZkError::DownloadFailed(
                    url,
                    format!("could not download circuits: {}", e),
                ));
            }
        }

        Ok(())
    }

    pub async fn verify_bb(&self) -> Result<String, ZkError> {
        if !self.bb_binary.exists() {
            return Err(ZkError::BbNotInstalled);
        }

        let output = tokio::process::Command::new(&self.bb_binary)
            .arg("--version")
            .output()
            .await?;

        if !output.status.success() {
            return Err(ZkError::ProveFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(version)
    }

    async fn verify_circuits(&self) -> Result<HashMap<String, CircuitInfo>, ZkError> {
        let manifest_path = self.circuits_dir.join("checksums.json");
        if !manifest_path.exists() {
            warn!("checksums.json not found, skipping circuit verification");
            return Ok(HashMap::new());
        }

        let manifest_data = fs::read_to_string(&manifest_path).await?;
        let manifest: ChecksumManifest = serde_json::from_str(&manifest_data)?;

        let mut circuit_infos = HashMap::new();

        for (rel_path, expected_hash) in &manifest.files {
            read_manifest_file(&self.circuits_dir, rel_path, expected_hash).await?;

            circuit_infos.insert(
                rel_path.clone(),
                CircuitInfo {
                    file: rel_path.clone(),
                    checksum: expected_hash.clone(),
                },
            );
        }

        info!(
            "verified {} circuit files from checksums.json",
            circuit_infos.len()
        );
        Ok(circuit_infos)
    }
}

fn find_bb_in_dir(dir: &Path) -> Result<PathBuf, ZkError> {
    for candidate in ["bb", "bin/bb", "barretenberg/bin/bb"] {
        let path = dir.join(candidate);
        if path.exists() && path.is_file() {
            return Ok(path);
        }
    }

    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy() == "bb" && e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .ok_or_else(|| {
            ZkError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "bb binary not found in archive",
            ))
        })
}

async fn download_with_progress(url: &str, message: &str) -> Result<Vec<u8>, ZkError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| ZkError::DownloadFailed(url.to_string(), e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| ZkError::DownloadFailed(url.to_string(), e.to_string()))?;

    if !response.status().is_success() {
        return Err(ZkError::DownloadFailed(
            url.to_string(),
            format!("HTTP {}", response.status()),
        ));
    }

    let total_size = response.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ZkError::DownloadFailed(url.to_string(), e.to_string()))?;
        bytes.extend_from_slice(&chunk);
        pb.set_position(bytes.len() as u64);
    }

    pb.finish_with_message("download complete");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel: &str, contents: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[tokio::test]
    async fn read_manifest_file_prefers_direct_layout() {
        let temp = TempDir::new().unwrap();
        let circuits_dir = temp.path();
        let contents = b"flat";
        write_file(
            circuits_dir,
            "insecure-512/default/dkg/pk/pk.json",
            contents,
        );
        let hash = sha256_hex(contents);

        let data = read_manifest_file(circuits_dir, "insecure-512/default/dkg/pk/pk.json", &hash)
            .await
            .unwrap();

        assert_eq!(data, contents);
    }

    #[tokio::test]
    async fn read_manifest_file_picks_committee_matching_checksum() {
        let temp = TempDir::new().unwrap();
        let circuits_dir = temp.path();
        let minimum = b"minimum";
        let small = b"small";
        write_file(
            circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            minimum,
        );
        write_file(
            circuits_dir,
            "insecure-512/small/default/dkg/pk/pk.json",
            small,
        );
        let small_hash = sha256_hex(small);

        let data = read_manifest_file(
            circuits_dir,
            "insecure-512/default/dkg/pk/pk.json",
            &small_hash,
        )
        .await
        .unwrap();

        assert_eq!(data, small);
    }

    #[tokio::test]
    async fn read_manifest_file_accepts_committee_scoped_manifest_path() {
        let temp = TempDir::new().unwrap();
        let circuits_dir = temp.path();
        let contents = b"minimum";
        write_file(
            circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            contents,
        );
        let hash = sha256_hex(contents);

        let data = read_manifest_file(
            circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            &hash,
        )
        .await
        .unwrap();

        assert_eq!(data, contents);
    }
}
