// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::config::{verify_checksum, BbTarget, ChecksumManifest, CircuitInfo, VersionInfo};
use crate::error::ZkError;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
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

// Release validation and installation use the same per-configuration inventory.
const REQUIRED_ARTIFACTS: &str = include_str!("../../required-artifacts.json");

fn supported_configurations() -> Vec<(&'static str, &'static str)> {
    serde_json::from_str(include_str!("../../supported-configurations.json"))
        .expect("invalid supported circuit configuration inventory")
}

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
        self.download_circuits_for_configurations(&supported_configurations())
            .await
    }

    /// Download circuits for an explicit subset of supported preset/committee pairs.
    pub async fn download_circuits_for_configurations(
        &self,
        configurations: &[(&str, &str)],
    ) -> Result<(), ZkError> {
        let version = &self.config.required_circuits_version;
        let archive_name = format!("circuits-{version}.tar.gz");
        let expected_checksum = self
            .config
            .circuits_checksums
            .get(version)
            .ok_or_else(|| ZkError::ChecksumMissing(archive_name.clone()))?;
        let url = self
            .config
            .circuits_download_url
            .replace("{version}", version);

        info!("downloading circuits from: {}", url);

        let result = download_with_progress(&url, "Downloading circuits").await;

        let mut version_info = self.load_version_info().await;

        match result {
            Ok(bytes) => {
                verify_checksum(&archive_name, &bytes, Some(expected_checksum))?;
                self.install_circuits_bytes(&bytes, &mut version_info, configurations)
                    .await?;
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

    /// Install a circuit release archive from the local filesystem. The archive must match the
    /// release pin of the required circuits version unless `allow_unpinned` is set, as for a local
    /// build.
    pub async fn install_circuits_archive(
        &self,
        path: &Path,
        allow_unpinned: bool,
    ) -> Result<(), ZkError> {
        self.install_circuits_archive_for_configurations(
            path,
            &supported_configurations(),
            allow_unpinned,
        )
        .await
    }

    /// Install a local archive for an explicit subset of supported preset/committee pairs.
    pub async fn install_circuits_archive_for_configurations(
        &self,
        path: &Path,
        configurations: &[(&str, &str)],
        allow_unpinned: bool,
    ) -> Result<(), ZkError> {
        let bytes = fs::read(path).await?;
        let version = &self.config.required_circuits_version;
        let archive_name = format!("circuits-{version}.tar.gz");
        match self.config.circuits_checksums.get(version) {
            _ if allow_unpinned => warn!(
                "installing circuits from {} without checking the release pin",
                path.display()
            ),
            Some(pin) => verify_checksum(&archive_name, &bytes, Some(pin))?,
            None => return Err(ZkError::ChecksumMissing(archive_name)),
        }
        let mut version_info = self.load_version_info().await;
        self.install_circuits_bytes(&bytes, &mut version_info, configurations)
            .await?;
        info!(
            "installed circuits v{} from {}",
            self.config.required_circuits_version,
            path.display()
        );
        Ok(())
    }

    async fn install_circuits_bytes(
        &self,
        bytes: &[u8],
        version_info: &mut VersionInfo,
        configurations: &[(&str, &str)],
    ) -> Result<(), ZkError> {
        fs::create_dir_all(&self.base_dir).await?;

        let staging_dir = tempfile::Builder::new()
            .prefix(".circuits-install-")
            .tempdir_in(&self.base_dir)?;
        let staging_root = staging_dir.path().join("payload");
        fs::create_dir(&staging_root).await?;

        let decoder = GzDecoder::new(bytes);
        let mut archive = Archive::new(decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();
            if is_archive_metadata(entry_type) {
                continue;
            }
            let path = entry.path()?.into_owned();
            validate_circuit_archive_entry(&path, entry_type)?;
            if !entry.unpack_in(&staging_root)? {
                return Err(invalid_circuit_archive_path(&path));
            }
        }

        let staged_circuits = staging_root.join("circuits");
        if !staged_circuits.is_dir() {
            return Err(ZkError::InvalidInput(
                "circuit archive does not contain a circuits directory".into(),
            ));
        }

        let circuit_infos = verify_circuits_dir(&staged_circuits, configurations).await?;

        let mut installed_version = version_info.clone();
        installed_version.circuits = circuit_infos;
        installed_version.circuits_version = Some(self.config.required_circuits_version.clone());
        installed_version.last_updated = Some(chrono::Utc::now().to_rfc3339());
        let staged_version = staging_dir.path().join("version.json");
        installed_version.save(&staged_version).await?;

        let backup_circuits = staging_dir.path().join("previous-circuits");
        let had_existing_circuits = self.circuits_dir.exists();
        if had_existing_circuits {
            fs::rename(&self.circuits_dir, &backup_circuits).await?;
        }
        if let Err(install_error) = fs::rename(&staged_circuits, &self.circuits_dir).await {
            if had_existing_circuits {
                self.restore_previous_circuits(&backup_circuits, staging_dir)
                    .await;
            }
            return Err(install_error.into());
        }

        if let Err(install_error) = fs::rename(&staged_version, self.version_file()).await {
            if let Err(rollback_error) = fs::rename(&self.circuits_dir, &staged_circuits).await {
                warn!(
                    error = %rollback_error,
                    from = %self.circuits_dir.display(),
                    to = %staged_circuits.display(),
                    "could not move new circuits during rollback"
                );
            }
            if had_existing_circuits {
                self.restore_previous_circuits(&backup_circuits, staging_dir)
                    .await;
            }
            return Err(install_error.into());
        }
        *version_info = installed_version;
        Ok(())
    }

    async fn restore_previous_circuits(
        &self,
        backup_circuits: &Path,
        staging_dir: tempfile::TempDir,
    ) {
        if let Err(rollback_error) = fs::rename(backup_circuits, &self.circuits_dir).await {
            let recovery_dir = staging_dir.keep();
            warn!(
                error = %rollback_error,
                from = %backup_circuits.display(),
                to = %self.circuits_dir.display(),
                recovery_dir = %recovery_dir.display(),
                "could not restore previous circuits; retained staging directory for recovery"
            );
        }
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
}

fn invalid_circuit_archive_path(path: &Path) -> ZkError {
    ZkError::InvalidInput(format!(
        "circuit archive entry must stay inside circuits: {}",
        path.display()
    ))
}

fn is_archive_metadata(entry_type: tar::EntryType) -> bool {
    entry_type.is_pax_global_extensions()
        || entry_type.is_pax_local_extensions()
        || entry_type.is_gnu_longname()
        || entry_type.is_gnu_longlink()
}

fn validate_circuit_archive_entry(path: &Path, entry_type: tar::EntryType) -> Result<(), ZkError> {
    let mut components = path.components();
    if components.next() != Some(Component::Normal("circuits".as_ref()))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_circuit_archive_path(path));
    }

    if !entry_type.is_file() && !entry_type.is_dir() {
        return Err(ZkError::InvalidInput(format!(
            "circuit archive entry must be a regular file or directory: {}",
            path.display()
        )));
    }

    Ok(())
}

async fn verify_circuits_dir(
    circuits_dir: &Path,
    required_configurations: &[(&str, &str)],
) -> Result<HashMap<String, CircuitInfo>, ZkError> {
    let supported = supported_configurations();
    if required_configurations.is_empty()
        || required_configurations
            .iter()
            .any(|pair| !supported.contains(pair))
    {
        return Err(ZkError::InvalidInput(
            "select at least one supported circuit configuration".into(),
        ));
    }
    let manifest_path = circuits_dir.join("checksums.json");
    if !manifest_path.exists() {
        return Err(ZkError::ChecksumMissing("circuits/checksums.json".into()));
    }

    let manifest_data = fs::read_to_string(&manifest_path).await?;
    let manifest: ChecksumManifest = serde_json::from_str(&manifest_data)?;
    if manifest.files.is_empty() {
        return Err(ZkError::ChecksumMissing("circuits/checksums.json".into()));
    }
    if manifest.algorithm != "sha256" {
        return Err(ZkError::InvalidInput(
            "circuit checksum manifest must use sha256".into(),
        ));
    }

    let mut circuit_infos = HashMap::new();
    let mut verified_paths = HashSet::new();

    for (rel_path, expected_hash) in &manifest.files {
        if rel_path.is_empty()
            || Path::new(rel_path)
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid_circuit_archive_path(Path::new(rel_path)));
        }
        let path = locate_manifest_artifact(circuits_dir, rel_path, expected_hash).await?;
        verified_paths.insert(path);

        circuit_infos.insert(
            rel_path.clone(),
            CircuitInfo {
                file: rel_path.clone(),
                checksum: expected_hash.clone(),
            },
        );
    }

    let required: Vec<&str> = serde_json::from_str(REQUIRED_ARTIFACTS)
        .expect("invalid required circuit artifact inventory");
    let mut configurations: HashSet<PathBuf> = required_configurations
        .iter()
        .map(|(preset, committee)| circuits_dir.join(preset).join(committee))
        .collect();
    for (preset, committee) in supported {
        let preset_dir = circuits_dir.join(preset);
        let pair_dir = preset_dir.join(committee);
        // Additional configurations in a subset archive must also be complete.
        if pair_dir.is_dir() {
            configurations.insert(pair_dir);
        }
        if CIRCUIT_VARIANT_DIRS
            .iter()
            .any(|variant| preset_dir.join(variant).is_dir())
        {
            configurations.insert(preset_dir);
        }
    }
    for configuration in configurations {
        for artifact in &required {
            let path = configuration.join(artifact);
            if !path.is_file() {
                return Err(ZkError::CircuitNotFound(
                    path.strip_prefix(circuits_dir)
                        .unwrap()
                        .display()
                        .to_string(),
                ));
            }
        }
    }

    for entry in WalkDir::new(circuits_dir) {
        let entry = entry.map_err(|error| ZkError::IoError(error.into()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel_path = entry.path().strip_prefix(circuits_dir).unwrap();
        // Build stamps and root manifests are metadata, not prover artifacts.
        if matches!(
            rel_path.to_str(),
            Some("checksums.json" | "SHA256SUMS" | "SOURCE_HASH")
        ) || entry.file_name() == ".build-stamp.json"
        {
            continue;
        }
        if !verified_paths.contains(entry.path()) {
            return Err(ZkError::ChecksumMissing(rel_path.display().to_string()));
        }
    }

    info!(
        "verified {} circuit files from checksums.json",
        circuit_infos.len()
    );
    Ok(circuit_infos)
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
    use crate::config::ZkConfig;
    use e3_config::BBPath;
    use flate2::{write::GzEncoder, Compression};
    use sha2::{Digest, Sha256};
    use std::{collections::HashMap, fs, io::Write};
    use tar::{Builder, Header};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    fn append_archive_file<W: Write>(builder: &mut Builder<W>, path: &str, contents: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, contents).unwrap();
    }

    fn append_global_pax_header<W: Write>(builder: &mut Builder<W>) {
        let contents = b"19 comment=fixture\n";
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::XGlobalHeader);
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "pax_global_header", &contents[..])
            .unwrap();
    }

    fn fixture_artifacts() -> Vec<String> {
        let artifacts: Vec<&str> = serde_json::from_str(REQUIRED_ARTIFACTS).unwrap();
        supported_configurations()
            .into_iter()
            .flat_map(|(preset, committee)| {
                artifacts
                    .iter()
                    .map(move |artifact| format!("{preset}/{committee}/{artifact}"))
            })
            .collect()
    }

    fn fixture_manifest(circuit: &[u8]) -> HashMap<String, String> {
        fixture_artifacts()
            .into_iter()
            .map(|path| (path, sha256_hex(circuit)))
            .collect()
    }

    fn circuit_archive_with_entries(
        circuit: &[u8],
        include_manifest: bool,
        extra_entries: &[(&str, &[u8])],
    ) -> Vec<u8> {
        circuit_archive_with_manifest(
            circuit,
            include_manifest.then(|| fixture_manifest(circuit)),
            extra_entries,
            &[],
        )
    }

    fn circuit_archive_with_manifest(
        circuit: &[u8],
        manifest_files: Option<HashMap<String, String>>,
        extra_entries: &[(&str, &[u8])],
        omitted: &[&str],
    ) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        append_global_pax_header(&mut builder);
        for path in fixture_artifacts() {
            if !omitted.contains(&path.as_str()) {
                append_archive_file(&mut builder, &format!("circuits/{path}"), circuit);
            }
        }

        if let Some(files) = manifest_files {
            let manifest = serde_json::to_vec(&ChecksumManifest {
                algorithm: "sha256".into(),
                generated: "test".into(),
                files,
            })
            .unwrap();
            append_archive_file(&mut builder, "circuits/checksums.json", &manifest);
        }

        for (path, contents) in extra_entries {
            append_archive_file(&mut builder, path, contents);
        }

        builder.into_inner().unwrap().finish().unwrap()
    }

    fn circuit_archive(circuit: &[u8], include_manifest: bool) -> Vec<u8> {
        circuit_archive_with_entries(circuit, include_manifest, &[])
    }

    fn test_backend(temp: &TempDir) -> ZkBackend {
        let base_dir = temp.path().join("noir");
        let config = ZkConfig {
            required_circuits_version: "candidate".into(),
            ..Default::default()
        };
        ZkBackend::with_config(
            BBPath::Default(base_dir.join("bin/bb")),
            base_dir.join("circuits"),
            base_dir.join("work"),
            config,
        )
    }

    async fn serve_archive(bytes: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/circuits-candidate.tar.gz",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        (url, server)
    }

    async fn seed_installation(backend: &ZkBackend) -> Vec<u8> {
        for configuration in ["insecure-512/minimum", "secure-8192/small"] {
            write_file(
                &backend.circuits_dir,
                &format!("{configuration}/default/dkg/pk/pk.json"),
                b"previous-circuit",
            );
        }
        write_file(&backend.circuits_dir, "installed.txt", b"installed");
        VersionInfo {
            bb_version: Some("5.1.0".into()),
            circuits_version: Some("previous".into()),
            last_updated: Some("previous-installation".into()),
            ..Default::default()
        }
        .save(&backend.version_file())
        .await
        .unwrap();
        fs::read(backend.version_file()).unwrap()
    }

    fn assert_installation_unchanged(backend: &ZkBackend, version: &[u8]) {
        assert_eq!(fs::read(backend.version_file()).unwrap(), version);
        for configuration in ["insecure-512/minimum", "secure-8192/small"] {
            assert_eq!(
                fs::read(
                    backend
                        .circuits_dir
                        .join(format!("{configuration}/default/dkg/pk/pk.json"))
                )
                .unwrap(),
                b"previous-circuit"
            );
        }
        assert_eq!(
            fs::read(backend.circuits_dir.join("installed.txt")).unwrap(),
            b"installed"
        );
    }

    #[tokio::test]
    async fn download_requires_complete_manifest() {
        let rel_path = "insecure-512/minimum/default/dkg/pk/pk.vk";
        let valid_manifest = fixture_manifest(b"circuit");
        let mut uncovered = valid_manifest.clone();
        uncovered.remove(rel_path);
        let cases = [
            ("missing", circuit_archive(b"circuit", false)),
            (
                "empty",
                circuit_archive_with_manifest(b"circuit", Some(HashMap::new()), &[], &[]),
            ),
            (
                "uncovered",
                circuit_archive_with_manifest(b"circuit", Some(uncovered), &[], &[]),
            ),
            (
                "missing artifact",
                circuit_archive_with_manifest(
                    b"circuit",
                    Some(valid_manifest.clone()),
                    &[],
                    &[rel_path],
                ),
            ),
            (
                "mismatch",
                circuit_archive_with_manifest(b"different-circuit", Some(valid_manifest), &[], &[]),
            ),
        ];
        for (case, archive) in cases {
            let temp = TempDir::new().unwrap();
            let mut backend = test_backend(&temp);
            let previous_version = seed_installation(&backend).await;
            backend
                .config
                .circuits_checksums
                .insert("candidate".into(), sha256_hex(&archive));
            let (url, server) = serve_archive(archive).await;
            backend.config.circuits_download_url = url;

            let result = backend.download_circuits().await;
            server.await.unwrap();

            assert!(
                matches!(
                    result,
                    Err(ZkError::ChecksumMissing(_)
                        | ZkError::CircuitNotFound(_)
                        | ZkError::ChecksumMismatch { .. })
                ),
                "{case}: {result:?}"
            );
            assert_installation_unchanged(&backend, &previous_version);
        }
    }

    #[tokio::test]
    async fn download_rejects_artifacts_omitted_from_archive_and_manifest() {
        for omitted in [
            "insecure-512/minimum/default/dkg/pk/pk.vk",
            "insecure-512/minimum/recursive/threshold/share_decryption/share_decryption.json",
            "insecure-512/minimum/evm/recursive_aggregation/dkg_aggregator/dkg_aggregator.vk",
            "insecure-512/minimum/default/recursive_aggregation/c6_fold/c6_fold.vk_tree_hash",
        ] {
            let temp = TempDir::new().unwrap();
            let mut backend = test_backend(&temp);
            let previous_version = seed_installation(&backend).await;
            let mut manifest = fixture_manifest(b"circuit");
            manifest.remove(omitted);
            let archive =
                circuit_archive_with_manifest(b"circuit", Some(manifest), &[], &[omitted]);
            backend
                .config
                .circuits_checksums
                .insert("candidate".into(), sha256_hex(&archive));
            let (url, server) = serve_archive(archive).await;
            backend.config.circuits_download_url = url;

            let result = backend.download_circuits().await;
            server.await.unwrap();
            assert!(
                matches!(result, Err(ZkError::CircuitNotFound(ref path)) if path == omitted),
                "{omitted}: {result:?}"
            );
            assert_installation_unchanged(&backend, &previous_version);
        }
    }

    #[tokio::test]
    async fn download_requires_all_release_configurations() {
        let temp = TempDir::new().unwrap();
        let mut backend = test_backend(&temp);
        let previous_version = seed_installation(&backend).await;
        let mut manifest = fixture_manifest(b"circuit");
        let artifacts = fixture_artifacts();
        let omitted: Vec<&str> = artifacts
            .iter()
            .filter(|path| path.starts_with("secure-8192/small/"))
            .map(String::as_str)
            .collect();
        for path in &omitted {
            manifest.remove(*path);
        }
        let archive = circuit_archive_with_manifest(b"circuit", Some(manifest), &[], &omitted);
        backend
            .config
            .circuits_checksums
            .insert("candidate".into(), sha256_hex(&archive));
        let (url, server) = serve_archive(archive).await;
        backend.config.circuits_download_url = url;

        let result = backend.download_circuits().await;
        server.await.unwrap();

        assert!(
            matches!(result, Err(ZkError::CircuitNotFound(ref path)) if path.starts_with("secure-8192/small/")),
            "{result:?}"
        );
        assert_installation_unchanged(&backend, &previous_version);
    }

    #[tokio::test]
    async fn download_authenticates_archive_before_installation() {
        let temp = TempDir::new().unwrap();
        let mut backend = test_backend(&temp);
        let previous_version = seed_installation(&backend).await;
        let genuine = circuit_archive(b"circuit", true);
        backend
            .config
            .circuits_checksums
            .insert("candidate".into(), sha256_hex(&genuine));

        for archive in [
            circuit_archive(b"different-circuit", true),
            b"not an archive".to_vec(),
        ] {
            let (url, server) = serve_archive(archive).await;
            backend.config.circuits_download_url = url;
            let result = backend.download_circuits().await;
            server.await.unwrap();
            assert!(
                matches!(result, Err(ZkError::ChecksumMismatch { ref file, .. }) if file == "circuits-candidate.tar.gz"),
                "{result:?}"
            );
            assert_installation_unchanged(&backend, &previous_version);
        }

        let (url, server) = serve_archive(genuine).await;
        backend.config.circuits_download_url = url;
        backend.download_circuits().await.unwrap();
        server.await.unwrap();
        assert_eq!(
            fs::read(
                backend
                    .circuits_dir
                    .join("insecure-512/minimum/default/dkg/pk/pk.json")
            )
            .unwrap(),
            b"circuit"
        );
        assert!(!backend.circuits_dir.join("installed.txt").exists());
        let version = backend.load_version_info().await;
        assert_eq!(version.circuits_version.as_deref(), Some("candidate"));
        assert_eq!(version.bb_version.as_deref(), Some("5.1.0"));
        assert_eq!(version.circuits.len(), fixture_artifacts().len());
    }

    #[tokio::test]
    async fn download_requires_version_bound_digest() {
        let temp = TempDir::new().unwrap();
        let mut backend = test_backend(&temp);
        let previous_version = seed_installation(&backend).await;
        backend.config.circuits_download_url = "http://127.0.0.1:0/unused".into();
        let result = backend.download_circuits().await;
        assert!(
            matches!(result, Err(ZkError::ChecksumMissing(_))),
            "{result:?}"
        );
        assert_installation_unchanged(&backend, &previous_version);
    }

    #[tokio::test]
    async fn download_restores_circuits_if_version_update_fails() {
        let temp = TempDir::new().unwrap();
        let mut backend = test_backend(&temp);
        seed_installation(&backend).await;
        fs::remove_file(backend.version_file()).unwrap();
        fs::create_dir(backend.version_file()).unwrap();
        write_file(&backend.version_file(), "retained", b"version-path");
        let archive = circuit_archive(b"circuit", true);
        backend
            .config
            .circuits_checksums
            .insert("candidate".into(), sha256_hex(&archive));
        let (url, server) = serve_archive(archive).await;
        backend.config.circuits_download_url = url;
        let result = backend.download_circuits().await;
        server.await.unwrap();
        assert!(matches!(result, Err(ZkError::IoError(_))), "{result:?}");
        assert_eq!(
            fs::read(
                backend
                    .circuits_dir
                    .join("insecure-512/minimum/default/dkg/pk/pk.json")
            )
            .unwrap(),
            b"previous-circuit"
        );
        assert_eq!(
            fs::read(backend.version_file().join("retained")).unwrap(),
            b"version-path"
        );
    }

    // A single blocked worker lets the test change the filesystem between completed operations.
    fn run_with_filesystem_changes<F: std::future::Future>(
        runtime: &tokio::runtime::Runtime,
        future: F,
        mut after_step: impl FnMut(),
    ) -> F::Output {
        let mut future = std::pin::pin!(future);
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "installation timed out"
            );
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = runtime.spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            started_rx.recv().unwrap();
            let result = runtime.block_on(std::future::poll_fn(|cx| {
                std::task::Poll::Ready(future.as_mut().poll(cx))
            }));
            release_tx.send(()).unwrap();
            runtime.block_on(blocker).unwrap();
            runtime.block_on(runtime.spawn_blocking(|| {})).unwrap();
            after_step();
            if let std::task::Poll::Ready(result) = result {
                return result;
            }
        }
    }

    fn assert_failed_rollback_keeps_previous_circuits(fail_version_update: bool) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let temp = TempDir::new().unwrap();
        let mut backend = test_backend(&temp);
        let previous_version = runtime.block_on(seed_installation(&backend));
        let archive = circuit_archive(b"circuit", true);
        backend
            .config
            .circuits_checksums
            .insert("candidate".into(), sha256_hex(&archive));
        let (url, server) = runtime.block_on(serve_archive(archive));
        backend.config.circuits_download_url = url;

        let mut staging_dir = None;
        let mut injected = false;
        let result = run_with_filesystem_changes(&runtime, backend.download_circuits(), || {
            if staging_dir.is_none() {
                staging_dir = fs::read_dir(&backend.base_dir)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".circuits-install-")
                    });
            }
            let Some(staging_dir) = &staging_dir else {
                return;
            };
            if injected
                || !staging_dir.join("previous-circuits").exists()
                || backend.circuits_dir.exists() != fail_version_update
            {
                return;
            }

            if fail_version_update {
                fs::remove_file(staging_dir.join("version.json")).unwrap();
                write_file(
                    &staging_dir.join("payload/circuits"),
                    "blocked",
                    b"occupied",
                );
            } else {
                fs::remove_dir_all(staging_dir.join("payload")).unwrap();
                write_file(&backend.circuits_dir, "blocked", b"occupied");
            }
            injected = true;
        });
        runtime.block_on(server).unwrap();

        assert!(injected, "rollback failure was not injected");
        assert!(
            matches!(result, Err(ZkError::IoError(ref error)) if error.kind() == std::io::ErrorKind::NotFound),
            "original installation error was lost: {result:?}"
        );
        assert_eq!(fs::read(backend.version_file()).unwrap(), previous_version);
        let recovery_dir = staging_dir.unwrap();
        for configuration in ["insecure-512/minimum", "secure-8192/small"] {
            assert_eq!(
                fs::read(recovery_dir.join(format!(
                    "previous-circuits/{configuration}/default/dkg/pk/pk.json"
                )))
                .unwrap(),
                b"previous-circuit"
            );
        }
        assert_eq!(
            fs::read(recovery_dir.join("previous-circuits/installed.txt")).unwrap(),
            b"installed"
        );
    }

    #[test]
    fn download_keeps_backup_if_circuit_install_rollback_fails() {
        assert_failed_rollback_keeps_previous_circuits(false);
    }

    #[test]
    fn download_keeps_backup_if_version_update_rollback_fails() {
        assert_failed_rollback_keeps_previous_circuits(true);
    }

    #[tokio::test]
    async fn local_archive_accepts_pax_metadata_and_records_version() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("circuits.tar.gz");
        let mut manifest = fixture_manifest(b"circuit");
        let artifacts = fixture_artifacts();
        let omitted: Vec<&str> = artifacts
            .iter()
            .filter(|path| !path.starts_with("insecure-512/minimum/"))
            .map(String::as_str)
            .collect();
        for path in &omitted {
            manifest.remove(*path);
        }
        let expected_files = manifest.len();
        fs::write(
            &archive_path,
            circuit_archive_with_manifest(b"circuit", Some(manifest), &[], &omitted),
        )
        .unwrap();
        let backend = test_backend(&temp);
        let previous_version = seed_installation(&backend).await;

        let result = backend.install_circuits_archive(&archive_path, true).await;
        assert!(
            matches!(result, Err(ZkError::CircuitNotFound(_))),
            "{result:?}"
        );
        assert_installation_unchanged(&backend, &previous_version);

        backend
            .install_circuits_archive_for_configurations(
                &archive_path,
                &[("insecure-512", "minimum")],
                true,
            )
            .await
            .unwrap();

        let version = backend.load_version_info().await;
        assert_eq!(version.circuits_version.as_deref(), Some("candidate"));
        assert_eq!(version.circuits.len(), expected_files);
    }

    #[tokio::test]
    async fn local_archive_requires_checksum_manifest() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("circuits.tar.gz");
        fs::write(&archive_path, circuit_archive(b"circuit", false)).unwrap();
        let backend = test_backend(&temp);

        let installed_circuit = backend
            .circuits_dir
            .join("insecure-512/minimum/default/dkg/pk/pk.json");
        write_file(&backend.circuits_dir, "installed.txt", b"installed");
        write_file(
            &backend.circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            b"previous-circuit",
        );

        let result = backend.install_circuits_archive(&archive_path, true).await;

        assert!(matches!(result, Err(ZkError::ChecksumMissing(_))));
        assert_eq!(fs::read(installed_circuit).unwrap(), b"previous-circuit");
        assert_eq!(
            fs::read(backend.circuits_dir.join("installed.txt")).unwrap(),
            b"installed"
        );
    }

    /// A local archive must match the release pin of the required version, unless the operator
    /// allows an unpinned archive, as for a local build.
    #[tokio::test]
    async fn local_archive_must_match_the_release_pin() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("circuits.tar.gz");
        let mut manifest = fixture_manifest(b"circuit");
        let artifacts = fixture_artifacts();
        let omitted: Vec<&str> = artifacts
            .iter()
            .filter(|path| !path.starts_with("insecure-512/minimum/"))
            .map(String::as_str)
            .collect();
        for path in &omitted {
            manifest.remove(*path);
        }
        let archive = circuit_archive_with_manifest(b"circuit", Some(manifest), &[], &omitted);
        fs::write(&archive_path, &archive).unwrap();
        let configurations = [("insecure-512", "minimum")];
        let pinned_to = |digest: String, dir: &TempDir| {
            let base_dir = dir.path().join("noir");
            ZkBackend::with_config(
                BBPath::Default(base_dir.join("bin/bb")),
                base_dir.join("circuits"),
                base_dir.join("work"),
                ZkConfig {
                    required_circuits_version: "candidate".into(),
                    circuits_checksums: HashMap::from([("candidate".into(), digest)]),
                    ..Default::default()
                },
            )
        };

        let unpinned = test_backend(&temp);
        let result = unpinned
            .install_circuits_archive_for_configurations(&archive_path, &configurations, false)
            .await;
        assert!(matches!(result, Err(ZkError::ChecksumMissing(_))), "{result:?}");

        let other = pinned_to(hex::encode(Sha256::digest(b"another archive")), &temp);
        let result = other
            .install_circuits_archive_for_configurations(&archive_path, &configurations, false)
            .await;
        assert!(
            matches!(result, Err(ZkError::ChecksumMismatch { .. })),
            "{result:?}"
        );
        other
            .install_circuits_archive_for_configurations(&archive_path, &configurations, true)
            .await
            .unwrap();

        let own_dir = TempDir::new().unwrap();
        pinned_to(hex::encode(Sha256::digest(&archive)), &own_dir)
            .install_circuits_archive_for_configurations(&archive_path, &configurations, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn local_archive_rejects_entries_outside_circuits() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("circuits.tar.gz");
        fs::write(
            &archive_path,
            circuit_archive_with_entries(b"circuit", true, &[("bin/bb", b"malicious-binary")]),
        )
        .unwrap();
        let backend = test_backend(&temp);
        write_file(&backend.base_dir, "bin/bb", b"installed-binary");
        write_file(&backend.circuits_dir, "installed.txt", b"installed-circuit");

        let result = backend.install_circuits_archive(&archive_path, true).await;

        assert!(matches!(result, Err(ZkError::InvalidInput(_))));
        assert_eq!(
            fs::read(backend.base_dir.join("bin/bb")).unwrap(),
            b"installed-binary"
        );
        assert_eq!(
            fs::read(backend.circuits_dir.join("installed.txt")).unwrap(),
            b"installed-circuit"
        );
    }

    #[tokio::test]
    async fn locate_manifest_artifact_prefers_direct_layout() {
        let temp = TempDir::new().unwrap();
        let circuits_dir = temp.path();
        let contents = b"flat";
        write_file(
            circuits_dir,
            "insecure-512/default/dkg/pk/pk.json",
            contents,
        );
        let hash = sha256_hex(contents);

        let path =
            locate_manifest_artifact(circuits_dir, "insecure-512/default/dkg/pk/pk.json", &hash)
                .await
                .unwrap();

        assert_eq!(fs::read(path).unwrap(), contents);
    }

    #[tokio::test]
    async fn locate_manifest_artifact_picks_committee_matching_checksum() {
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

        let path = locate_manifest_artifact(
            circuits_dir,
            "insecure-512/default/dkg/pk/pk.json",
            &small_hash,
        )
        .await
        .unwrap();

        assert_eq!(fs::read(path).unwrap(), small);
    }

    #[tokio::test]
    async fn locate_manifest_artifact_accepts_committee_scoped_manifest_path() {
        let temp = TempDir::new().unwrap();
        let circuits_dir = temp.path();
        let contents = b"minimum";
        write_file(
            circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            contents,
        );
        let hash = sha256_hex(contents);

        let path = locate_manifest_artifact(
            circuits_dir,
            "insecure-512/minimum/default/dkg/pk/pk.json",
            &hash,
        )
        .await
        .unwrap();

        assert_eq!(fs::read(path).unwrap(), contents);
    }
}
