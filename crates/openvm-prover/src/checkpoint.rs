// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Local checkpoint files. A manifest published last marks a complete stage; its hashes detect
//! corruption, while the stage's native proof verifier establishes validity before resuming.

use std::{
    collections::BTreeMap,
    fs,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use eyre::{ensure, Context, Result};
use openvm_sdk::{types::AppExecutionCommit, OPENVM_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Config;

const OPENVM_REVISION: &str = "59a69b8b0cbee7011ac978e4cc07707ee3681944";
const MAX_APP_PROOF_BYTES: usize = 4 * 1024 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 256 * 1024 * 1024;
const PROOF_LIMIT_ENV: &str = "OPENVM_CHECKPOINT_MAX_PROOF_BYTES";

fn proof_read_limit(default: usize) -> Result<usize> {
    let value = match std::env::var(PROOF_LIMIT_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    parse_read_limit(value.as_deref(), default)
}

fn parse_read_limit(value: Option<&str>, default: usize) -> Result<usize> {
    let limit = match value {
        Some(value) => value
            .parse::<usize>()
            .wrap_err_with(|| format!("{PROOF_LIMIT_ENV} must be a positive byte count"))?,
        None => default,
    };
    ensure!(
        limit > 0 && limit < usize::MAX,
        "{PROOF_LIMIT_ENV} must be a positive byte count below usize::MAX"
    );
    Ok(limit)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    Application,
    Aggregate,
    Root,
}

impl Stage {
    fn files(self) -> &'static [(&'static str, usize)] {
        match self {
            Self::Application => &[("app.proof", MAX_APP_PROOF_BYTES)],
            Self::Aggregate => &[("aggregate.json", MAX_PROOF_BYTES), ("metadata.bin", 64)],
            Self::Root => &[("root.bin", MAX_PROOF_BYTES)],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    app_pk: String,
    executable: String,
    aggregation_pk: String,
    verifier: String,
}

impl Artifacts {
    fn read(config: &Config) -> Result<Self> {
        // Halo2 keys and SRS are deliberately excluded: early stages must not read gigabytes
        // of compression setup. The final seal still has to pass the configured EVM verifier.
        Ok(Self {
            app_pk: file_digest(&config.app_pk)?,
            executable: file_digest(&config.executable)?,
            aggregation_pk: file_digest(&config.aggregation_pk)?,
            verifier: file_digest(&config.verifier_artifact)?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    openvm_version: String,
    openvm_revision: String,
    stage: Stage,
    app_commit: AppExecutionCommit,
    journal_sha256: String,
    artifacts: Artifacts,
    files: BTreeMap<String, String>,
}

pub(crate) struct Checkpoint {
    directory: PathBuf,
    manifest: Manifest,
}

impl Checkpoint {
    pub(crate) fn create(
        directory: &Path,
        config: &Config,
        journal: &[u8],
        stage: Stage,
    ) -> Result<Self> {
        // Validate the import policy before starting a new expensive stage. It never limits
        // saving a proof we have just generated and verified ourselves.
        proof_read_limit(stage.files()[0].1)?;
        // Reserve a new private directory before expensive work. create_dir also rejects files,
        // existing directories and dangling symlinks, without replacing any prior output.
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .wrap_err("Checkpoint output must be a new directory")?;
        sync_parent(directory)?;
        check_new_file(&directory.join("manifest.json"))?;
        Ok(Self {
            directory: directory.to_path_buf(),
            manifest: Manifest {
                schema_version: 1,
                openvm_version: format!("v{OPENVM_VERSION}"),
                openvm_revision: OPENVM_REVISION.to_owned(),
                stage,
                app_commit: config.app_commit.clone(),
                journal_sha256: digest(journal),
                artifacts: Artifacts::read(config)?,
                files: BTreeMap::new(),
            },
        })
    }

    pub(crate) fn open(
        directory: &Path,
        config: &Config,
        journal: &[u8],
        stage: Stage,
    ) -> Result<Self> {
        let manifest: Manifest =
            serde_json::from_slice(&read_regular(&directory.join("manifest.json"), 64 * 1024)?)?;
        ensure!(
            manifest.schema_version == 1,
            "Unsupported checkpoint schema"
        );
        ensure!(
            manifest.openvm_version == format!("v{OPENVM_VERSION}")
                && manifest.openvm_revision == OPENVM_REVISION,
            "Checkpoint OpenVM version differs"
        );
        ensure!(manifest.stage == stage, "Checkpoint stage differs");
        ensure!(
            manifest.app_commit == config.app_commit,
            "Checkpoint application identity differs"
        );
        ensure!(
            manifest.journal_sha256 == digest(journal),
            "Checkpoint journal differs"
        );
        ensure!(
            manifest.artifacts == Artifacts::read(config)?,
            "Checkpoint configuration artifacts differ"
        );
        ensure!(
            manifest
                .files
                .keys()
                .map(String::as_str)
                .eq(stage.files().iter().map(|(name, _)| *name)),
            "Invalid checkpoint file list"
        );
        Ok(Self {
            directory: directory.to_path_buf(),
            manifest,
        })
    }

    pub(crate) fn read(&self, name: &str) -> Result<Vec<u8>> {
        let (_, limit) = self
            .manifest
            .stage
            .files()
            .iter()
            .find(|(expected, _)| *expected == name)
            .ok_or_else(|| eyre::eyre!("Unexpected checkpoint file: {name}"))?;
        let limit = if name == "metadata.bin" {
            *limit
        } else {
            proof_read_limit(*limit)?
        };
        let bytes = read_regular(&self.directory.join(name), limit)?;
        ensure!(
            self.manifest.files.get(name) == Some(&digest(&bytes)),
            "Checkpoint file digest differs: {name}"
        );
        Ok(bytes)
    }

    pub(crate) fn check_artifacts(&self, config: &Config) -> Result<()> {
        ensure!(
            self.manifest.artifacts == Artifacts::read(config)?,
            "Configuration artifacts changed during proving"
        );
        Ok(())
    }

    pub(crate) fn save(mut self, config: &Config, files: &[(&str, Vec<u8>)]) -> Result<()> {
        ensure!(
            files.iter().map(|(name, _)| *name).eq(self
                .manifest
                .stage
                .files()
                .iter()
                .map(|(name, _)| *name)),
            "Invalid checkpoint file list"
        );
        for (name, bytes) in files {
            self.write(name, |writer| Ok(writer.write_all(bytes)?))?;
        }
        self.finish(config)
    }

    pub(crate) fn write(
        &mut self,
        name: &str,
        encode: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            self.manifest
                .stage
                .files()
                .iter()
                .any(|(expected, _)| *expected == name),
            "Unexpected checkpoint file: {name}"
        );
        let file = new_file(&self.directory.join(name))?;
        let mut writer = BufWriter::new(HashWriter {
            inner: file,
            hash: Sha256::new(),
        });
        encode(&mut writer)?;
        writer.flush()?;
        writer.get_ref().inner.sync_all()?;
        self.manifest.files.insert(
            name.to_owned(),
            hex::encode(writer.get_ref().hash.clone().finalize()),
        );
        Ok(())
    }

    pub(crate) fn finish(self, config: &Config) -> Result<()> {
        ensure!(
            self.manifest.files.keys().map(String::as_str).eq(self
                .manifest
                .stage
                .files()
                .iter()
                .map(|(name, _)| *name)),
            "Incomplete checkpoint file list"
        );
        self.check_artifacts(config)?;
        fs::File::open(&self.directory)?.sync_all()?;
        publish_new(
            &self.directory.join("manifest.json"),
            &serde_json::to_vec_pretty(&self.manifest)?,
        )
    }
}

struct HashWriter<W> {
    inner: W,
    hash: Sha256,
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn open_regular(path: &Path, limit: usize) -> Result<(fs::File, usize)> {
    // Reject special files without opening them. Unix flags and the handle check also guard
    // against substituting a symlink or FIFO between this check and open.
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "Expected a regular checkpoint file: {}",
        path.display()
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a substituted symlink or wait indefinitely for a FIFO writer.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "Expected a regular checkpoint file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= limit as u64,
        "Checkpoint file exceeds the read limit ({limit} bytes): {}",
        path.display()
    );
    let length = usize::try_from(metadata.len())?;
    Ok((file, length))
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let (file, length) = open_regular(path, limit)?;
    read_admitted(file, length)
}

fn read_admitted(mut file: fs::File, length: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    // Allocate once from the admitted handle's length. Growth cannot trigger another allocation.
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    ensure!(
        file.read(&mut [0])? == 0,
        "Checkpoint file grew while reading"
    );
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn file_digest(path: &Path) -> Result<String> {
    let mut reader = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn new_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}

pub(crate) fn check_new_file(path: &Path) -> Result<()> {
    check_publication(path, |from, to| fs::hard_link(from, to), sync_parent)
}

fn check_publication(
    path: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
    sync: impl Fn(&Path) -> Result<()>,
) -> Result<()> {
    for candidate in [path.to_path_buf(), partial_path(path)] {
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => eyre::bail!("The output already exists: {}", candidate.display()),
        }
    }
    ensure!(
        parent(path).is_dir(),
        "The output parent must be an existing directory"
    );
    // Exercise the same filesystem operations as publication before expensive proving. Never
    // publish a probe at the final path, and only remove files this invocation created.
    let pending = partial_path(path);
    let probe = partial_path(&pending);
    let mut file = new_file(&pending).wrap_err("Cannot create an output file before proving")?;
    let mut linked = false;
    let result = (|| {
        file.write_all(b"OpenVM output preflight")?;
        file.sync_all()?;
        link(&pending, &probe)?;
        linked = true;
        sync(path)
    })();
    drop(file);
    let cleanup = (|| {
        if linked {
            fs::remove_file(probe)?;
        }
        fs::remove_file(pending)?;
        sync(path)
    })();
    result.wrap_err("Output filesystem must support hard links and directory synchronization")?;
    cleanup.wrap_err("Cannot clean up the output publication preflight")
}

pub(crate) fn publish_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let pending = partial_path(path);
    write_new(&pending, bytes)?;
    // Unlike rename on Unix, hard_link atomically publishes without replacing a destination.
    fs::hard_link(&pending, path)?;
    sync_parent(path)?;
    fs::remove_file(pending)?;
    sync_parent(path)
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(parent(path))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_config;

    #[test]
    fn recorded_revision_matches_the_pinned_sdk_dependency() {
        let sdk = include_str!("../Cargo.lock")
            .split("[[package]]")
            .find(|package| package.contains("name = \"openvm-sdk\"\n"))
            .expect("the worker lockfile must pin openvm-sdk");
        assert!(sdk.contains(&format!("#{OPENVM_REVISION}\"")));
    }

    fn save(directory: &Path, config: &Config, stage: Stage) {
        let files = stage
            .files()
            .iter()
            .map(|(name, _)| (*name, vec![1, 2, 3]))
            .collect::<Vec<_>>();
        Checkpoint::create(directory, config, &[7; 288], stage)
            .unwrap()
            .save(config, &files)
            .unwrap();
    }

    #[test]
    fn every_stage_roundtrips_without_reading_halo2_setup() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        for stage in [Stage::Application, Stage::Aggregate, Stage::Root] {
            let directory = temp.path().join(format!("{stage:?}"));
            save(&directory, &config, stage);
            let saved = Checkpoint::open(&directory, &config, &[7; 288], stage).unwrap();
            for (name, _) in stage.files() {
                assert_eq!(saved.read(name).unwrap(), [1, 2, 3]);
            }
            assert!(!directory.join("manifest.json.partial").exists());
        }
        assert!(!config.halo2_pk.exists() && !config.halo2_params_dir.exists());
    }

    #[test]
    fn checkpoint_and_artifact_paths_can_move_without_changing_their_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let original = temp.path().join("original");
        save(&original, &config, Stage::Root);
        let moved = temp.path().join("moved");
        fs::rename(original, &moved).unwrap();
        let other = tempfile::tempdir().unwrap();
        let relocated = test_config(other.path());
        let saved = Checkpoint::open(&moved, &relocated, &[7; 288], Stage::Root).unwrap();
        assert_eq!(saved.read("root.bin").unwrap(), [1, 2, 3]);
    }

    #[test]
    fn corrupt_or_truncated_files_are_rejected_for_every_stage() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        for stage in [Stage::Application, Stage::Aggregate, Stage::Root] {
            for (name, _) in stage.files() {
                let directory = temp.path().join(format!("{stage:?}-{name}"));
                save(&directory, &config, stage);
                let saved = Checkpoint::open(&directory, &config, &[7; 288], stage).unwrap();
                fs::write(directory.join(name), [1, 2, 4]).unwrap();
                assert!(saved.read(name).is_err(), "{name}: corruption");
                fs::write(directory.join(name), [1, 2]).unwrap();
                assert!(saved.read(name).is_err(), "{name}: truncation");
            }
        }
    }

    #[test]
    fn manifest_mismatches_and_unexpected_file_names_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("root");
        save(&directory, &config, Stage::Root);
        let path = directory.join("manifest.json");
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("openvm_version", serde_json::json!("v0.0")),
            ("openvm_revision", serde_json::json!("other")),
            ("stage", serde_json::json!("aggregate")),
            ("journal_sha256", serde_json::json!("other")),
            ("files", serde_json::json!({"../root.bin": "other"})),
            ("files", serde_json::json!({})),
            (
                "files",
                serde_json::json!({"root.bin": "other", "extra": "other"}),
            ),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err(),
                "{field}"
            );
        }
        fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(Checkpoint::open(&directory, &config, &[8; 288], Stage::Root).is_err());
        let mut different_identity = config;
        different_identity.app_commit.app_exe_commit = [1u32; 8].into();
        assert!(Checkpoint::open(&directory, &different_identity, &[7; 288], Stage::Root).is_err());
    }

    #[test]
    fn artifacts_changed_during_proving_cannot_publish_a_complete_checkpoint() {
        for name in ["app.pk", "guest.vmexe", "aggregation.pk", "verifier.json"] {
            let temp = tempfile::tempdir().unwrap();
            let config = test_config(temp.path());
            let directory = temp.path().join("root");
            let pending = Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).unwrap();
            fs::write(temp.path().join(name), b"changed").unwrap();
            assert!(pending
                .save(&config, &[("root.bin", vec![1, 2, 3])])
                .is_err());
            assert!(!directory.join("manifest.json").exists());
            assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
        }
    }

    #[test]
    fn changed_artifacts_cannot_resume_a_complete_checkpoint() {
        for name in ["app.pk", "guest.vmexe", "aggregation.pk", "verifier.json"] {
            let temp = tempfile::tempdir().unwrap();
            let config = test_config(temp.path());
            let directory = temp.path().join("root");
            save(&directory, &config, Stage::Root);
            fs::write(temp.path().join(name), b"changed").unwrap();
            assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
        }
    }

    #[test]
    fn replacing_a_manifest_cannot_redefine_an_admitted_artifact_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("root");
        save(&directory, &config, Stage::Root);
        let admitted = Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).unwrap();
        fs::write(&config.executable, b"changed").unwrap();
        let path = directory.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        manifest["artifacts"]["executable"] =
            serde_json::json!(file_digest(&config.executable).unwrap());
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        // Reloading this manifest would accept the new digest as its starting point. Finishing
        // an admitted job must compare with the snapshot it actually verified instead.
        assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_ok());
        assert!(admitted.check_artifacts(&config).is_err());
    }

    #[test]
    fn interrupted_writes_and_output_collisions_never_replace_previous_data() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("root");
        let pending = Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).unwrap();
        assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
        fs::write(directory.join("root.bin"), b"existing").unwrap();
        assert!(pending
            .save(&config, &[("root.bin", vec![1, 2, 3])])
            .is_err());
        assert_eq!(fs::read(directory.join("root.bin")).unwrap(), b"existing");
        assert!(!directory.join("manifest.json").exists());
        assert!(Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).is_err());

        let directory = temp.path().join("manifest-collision");
        let pending = Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).unwrap();
        fs::write(directory.join("manifest.json"), b"existing").unwrap();
        assert!(pending
            .save(&config, &[("root.bin", vec![1, 2, 3])])
            .is_err());
        assert_eq!(
            fs::read(directory.join("manifest.json")).unwrap(),
            b"existing"
        );
        assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
    }

    #[test]
    fn locally_encoded_payloads_survive_reader_limits_and_wrong_names_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("aggregate");
        let pending = Checkpoint::create(&directory, &config, &[7; 288], Stage::Aggregate).unwrap();
        pending
            .save(
                &config,
                &[("aggregate.json", vec![]), ("metadata.bin", vec![0; 65])],
            )
            .unwrap();
        // Import limits must not discard a completed local result. This tiny oversized metadata
        // stands in for a large proof without allocating gigabytes in the regression test.
        assert!(directory.join("manifest.json").exists());
        assert_eq!(
            fs::read(directory.join("metadata.bin")).unwrap(),
            vec![0; 65]
        );
        let saved = Checkpoint::open(&directory, &config, &[7; 288], Stage::Aggregate).unwrap();
        assert!(saved.read("metadata.bin").is_err());

        let directory = temp.path().join("read-limit");
        save(&directory, &config, Stage::Aggregate);
        let saved = Checkpoint::open(&directory, &config, &[7; 288], Stage::Aggregate).unwrap();
        assert!(saved.read("../metadata.bin").is_err());
        fs::write(directory.join("metadata.bin"), vec![0; 65]).unwrap();
        assert!(saved.read("metadata.bin").is_err());

        let pending = Checkpoint::create(
            &temp.path().join("wrong-list"),
            &config,
            &[7; 288],
            Stage::Root,
        )
        .unwrap();
        assert!(pending.save(&config, &[("../root.bin", vec![])]).is_err());
    }

    #[test]
    fn known_application_larger_than_two_gib_passes_size_admission_without_loading_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large-app.proof");
        // Exact byte size of an independently generated pilot proof. Sparse length
        // exercises the size boundary without reading or allocating the multi-gigabyte payload.
        let length = 2_224_393_576;
        new_file(&path).unwrap().set_len(length).unwrap();
        let (_, admitted) = open_regular(&path, MAX_APP_PROOF_BYTES).unwrap();
        assert_eq!(admitted as u64, length);
        assert!(open_regular(&path, 2 * 1024 * 1024 * 1024).is_err());
        assert!(open_regular(
            &path,
            parse_read_limit(Some("16"), MAX_APP_PROOF_BYTES).unwrap()
        )
        .is_err());
    }

    #[test]
    fn import_budget_is_explicit_and_rejects_invalid_values() {
        assert_eq!(parse_read_limit(None, 16).unwrap(), 16);
        assert_eq!(parse_read_limit(Some("32"), 16).unwrap(), 32);
        for invalid in ["", "0", "-1", "NaN", "18446744073709551616"] {
            assert!(parse_read_limit(Some(invalid), 16).is_err(), "{invalid}");
        }
        assert!(parse_read_limit(Some(&usize::MAX.to_string()), 16).is_err());
    }

    #[test]
    fn failed_streaming_encoding_cannot_publish_a_complete_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("failed-encoding");
        let mut pending = Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).unwrap();
        assert!(pending
            .write("root.bin", |writer| {
                writer.write_all(b"partial")?;
                eyre::bail!("encoding failed")
            })
            .is_err());
        assert!(pending.finish(&config).is_err());
        assert!(!directory.join("manifest.json").exists());
        assert_eq!(fs::read(directory.join("root.bin")).unwrap(), b"partial");
    }

    #[test]
    fn streaming_hash_accounts_for_short_writes() {
        #[derive(Default)]
        struct ShortWriter(Vec<u8>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let count = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut writer = HashWriter {
            inner: ShortWriter::default(),
            hash: Sha256::new(),
        };
        writer.write_all(b"complete proof").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.inner.0, b"complete proof");
        assert_eq!(
            hex::encode(writer.hash.finalize()),
            digest(b"complete proof")
        );
    }

    #[test]
    fn admitted_handles_reject_size_changes_and_ignore_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("payload");
        fs::write(&path, b"original").unwrap();
        let (file, length) = open_regular(&path, 16).unwrap();
        fs::rename(&path, temp.path().join("moved")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert_eq!(read_admitted(file, length).unwrap(), b"original");

        let (file, length) = open_regular(&path, 16).unwrap();
        fs::write(&path, b"replacement grew").unwrap();
        assert!(read_admitted(file, length).is_err());
        let (file, length) = open_regular(&path, 16).unwrap();
        fs::write(&path, b"short").unwrap();
        assert!(read_admitted(file, length).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_members_reject_symlinks_directories_and_fifos_without_blocking() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("root");
        save(&directory, &config, Stage::Root);
        let saved = Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).unwrap();
        let payload = directory.join("root.bin");
        fs::rename(&payload, temp.path().join("original")).unwrap();
        symlink(temp.path().join("original"), &payload).unwrap();
        assert!(saved.read("root.bin").is_err());
        fs::remove_file(&payload).unwrap();
        fs::create_dir(&payload).unwrap();
        assert!(saved.read("root.bin").is_err());
        fs::remove_dir(&payload).unwrap();
        let fifo = CString::new(payload.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo is a valid NUL-terminated path into this test's private temporary directory.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(saved.read("root.bin").is_err());

        let manifest = directory.join("manifest.json");
        fs::rename(&manifest, temp.path().join("manifest-original")).unwrap();
        symlink(temp.path().join("manifest-original"), &manifest).unwrap();
        assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
        fs::remove_file(&manifest).unwrap();
        let fifo = CString::new(manifest.as_os_str().as_bytes()).unwrap();
        // SAFETY: same private test directory and valid CString as above.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(Checkpoint::open(&directory, &config, &[7; 288], Stage::Root).is_err());
    }

    #[test]
    fn atomic_publication_requires_new_paths_and_preserves_incomplete_files() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("seal");
        check_new_file(&output).unwrap();
        publish_new(&output, b"complete").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"complete");
        assert!(!partial_path(&output).exists());
        assert!(check_new_file(&output).is_err());
        assert!(publish_new(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"complete");

        let output = temp.path().join("interrupted");
        fs::write(partial_path(&output), b"incomplete").unwrap();
        assert!(check_new_file(&output).is_err());
        assert!(publish_new(&output, b"replacement").is_err());
        assert_eq!(fs::read(partial_path(&output)).unwrap(), b"incomplete");
        assert!(!output.exists());
        assert!(check_new_file(&temp.path().join("missing/parent/seal")).is_err());
    }

    #[test]
    fn publication_preflight_rejects_link_and_sync_failures_and_removes_its_files() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("seal");
        let unsupported = || std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(check_publication(&output, |_, _| Err(unsupported()), sync_parent).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        assert!(check_publication(
            &output,
            |from, to| fs::hard_link(from, to),
            |_| Err(unsupported().into()),
        )
        .is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        check_new_file(&output).unwrap();
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);

        let existing = partial_path(&partial_path(&output));
        fs::write(&existing, b"unrelated").unwrap();
        assert!(check_new_file(&output).is_err());
        assert_eq!(fs::read(existing).unwrap(), b"unrelated");
        assert!(!partial_path(&output).exists());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlinks_are_not_outputs_and_checkpoint_directories_are_private() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("dangling");
        symlink(temp.path().join("missing"), &directory).unwrap();
        assert!(Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).is_err());
        assert!(!temp.path().join("missing").exists());
        let directory = temp.path().join("private");
        Checkpoint::create(&directory, &config, &[7; 288], Stage::Root).unwrap();
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let output = temp.path().join("private-seal");
        publish_new(&output, b"proof").unwrap();
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
