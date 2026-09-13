// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"\xff\xff\xff\xffE3B1";
const REFERENCE_BYTES: usize = 8 + 8 + 32;
pub const MAX_BLOB_BYTES: usize = 512 * 1024 * 1024;

pub(crate) struct EventBlobs {
    directory: PathBuf,
}

impl EventBlobs {
    pub(crate) fn new(event_log_directory: &Path) -> Self {
        Self {
            directory: event_log_directory.join("event-blobs-v1"),
        }
    }

    pub(crate) fn store(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            bytes.len() <= MAX_BLOB_BYTES,
            "local event is too large: {} bytes exceed the {}-byte blob limit",
            bytes.len(),
            MAX_BLOB_BYTES
        );
        self.prepare_directory()?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let path = self.path_for(&digest);
        if path.exists() {
            self.verify_existing(&path, bytes.len(), &digest)?;
        } else {
            let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
                .context("failed to create private event blob")?;
            temporary
                .write_all(bytes)
                .context("failed to write event blob")?;
            temporary
                .as_file_mut()
                .sync_all()
                .context("failed to sync event blob")?;
            match temporary.persist_noclobber(&path) {
                Ok(_) => {}
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.verify_existing(&path, bytes.len(), &digest)?;
                }
                Err(error) => return Err(error.error).context("failed to publish event blob"),
            }
        }
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync event blob directory")?;

        let mut reference = Vec::with_capacity(REFERENCE_BYTES);
        reference.extend_from_slice(MAGIC);
        reference.extend_from_slice(&u64::try_from(bytes.len())?.to_le_bytes());
        reference.extend_from_slice(&digest);
        Ok(reference)
    }

    pub(crate) fn resolve(&self, record: &[u8]) -> Result<Option<Vec<u8>>> {
        if !record.starts_with(MAGIC) {
            return Ok(None);
        }
        ensure!(
            record.len() == REFERENCE_BYTES,
            "invalid event blob reference length"
        );
        let len = usize::try_from(u64::from_le_bytes(record[8..16].try_into()?))?;
        ensure!(
            len <= MAX_BLOB_BYTES,
            "event blob reference exceeds size limit"
        );
        let digest: [u8; 32] = record[16..48].try_into()?;
        let path = self.path_for(&digest);
        let mut file = self.open_checked(&path, len)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .context("cannot reserve memory for event blob")?;
        bytes.resize(len, 0);
        file.read_exact(&mut bytes)
            .context("event blob length changed during read")?;
        let mut trailing = [0u8; 1];
        ensure!(
            file.read(&mut trailing)? == 0,
            "event blob grew during read"
        );
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        ensure!(actual == digest, "event blob content hash mismatch");
        Ok(Some(bytes))
    }

    fn verify_existing(&self, path: &Path, len: usize, digest: &[u8; 32]) -> Result<()> {
        let mut file = self.open_checked(path, len)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .context("failed to verify existing event blob")?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        ensure!(
            actual == *digest,
            "existing event blob content hash mismatch"
        );
        Ok(())
    }

    fn open_checked(&self, path: &Path, len: usize) -> Result<File> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("missing event blob {}", path.display()))?;
        ensure!(metadata.is_file(), "event blob is not a regular file");
        ensure!(metadata.len() == len as u64, "event blob has wrong length");
        let file = File::open(path).context("failed to open event blob")?;
        let opened = file.metadata()?;
        ensure!(
            opened.is_file() && opened.len() == len as u64,
            "event blob changed during open"
        );
        Ok(file)
    }

    fn path_for(&self, digest: &[u8; 32]) -> PathBuf {
        let mut name = String::with_capacity(64);
        for byte in digest {
            write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
        }
        self.directory.join(name)
    }

    fn prepare_directory(&self) -> Result<()> {
        fs::create_dir_all(&self.directory).context("failed to create event blob directory")?;
        let metadata = fs::symlink_metadata(&self.directory)?;
        ensure!(metadata.is_dir(), "event blob directory is not a directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
                .context("failed to restrict event blob directory")?;
        }
        let parent = self
            .directory
            .parent()
            .context("event blob directory has no parent")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync event log directory")?;
        Ok(())
    }
}
