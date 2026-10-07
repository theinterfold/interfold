// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The store record: `interfold start` writes the resolved path of its store next to the node's
//! key file, as `<key file>.store-record`. A purge reads it, so it checks the store that the node
//! uses, also when the node ran with another `E3_DATA_DIR`, `data_dir`, or working directory than
//! the purge's configuration gives.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The suffix of a key file's store record.
pub const RECORD_SUFFIX: &str = ".store-record";

/// The store record of `key_file`: `<key file>.store-record`.
pub fn record_path(key_file: &Path) -> PathBuf {
    let mut name = key_file.file_name().unwrap_or_default().to_os_string();
    name.push(RECORD_SUFFIX);
    key_file.with_file_name(name)
}

/// Whether `path` is a store record by its name.
pub fn is_record(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_bytes().ends_with(RECORD_SUFFIX.as_bytes()))
}

/// Record that the node of `key_file` uses the store `db_file`. The new record replaces the earlier
/// one through a rename, so a crash leaves one of the two.
pub fn write(key_file: &Path, db_file: &Path) -> Result<()> {
    let store = std::path::absolute(db_file)?;
    let record = record_path(key_file);
    if let Some(folder) = record.parent() {
        std::fs::create_dir_all(folder)
            .with_context(|| format!("failed to create {}", folder.display()))?;
    }
    let mut temporary = record.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut content = store.into_os_string().into_vec();
    content.push(b'\n');
    std::fs::write(&temporary, content)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, &record)
        .with_context(|| format!("failed to write {}", record.display()))
}

/// The store that the record of `key_file` names, or `None` without a record.
pub fn read(key_file: &Path) -> Result<Option<PathBuf>> {
    let record = record_path(key_file);
    let mut content = match std::fs::read(&record) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", record.display()))
        }
    };
    if content.last() == Some(&b'\n') {
        content.pop();
    }
    anyhow::ensure!(
        content.starts_with(b"/") && !content.contains(&b'\n'),
        "{} does not name a store",
        record.display()
    );
    Ok(Some(PathBuf::from(OsString::from_vec(content))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_names_the_store_next_to_the_key_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let key_file = dir.path().join("config/cn1/key");
        let store = dir.path().join("elsewhere/db");
        assert_eq!(read(&key_file)?, None);

        write(&key_file, &store)?;
        assert_eq!(
            record_path(&key_file),
            dir.path().join("config/cn1/key.store-record")
        );
        assert!(is_record(&record_path(&key_file)));
        assert_eq!(read(&key_file)?, Some(store));

        // A later start with another store replaces the record.
        let other = dir.path().join("other/db");
        write(&key_file, &other)?;
        assert_eq!(read(&key_file)?, Some(other));
        Ok(())
    }

    #[test]
    fn a_record_that_names_no_store_is_an_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let key_file = dir.path().join("key");
        std::fs::write(record_path(&key_file), b"not a path\n")?;
        assert!(read(&key_file).is_err());
        Ok(())
    }
}
