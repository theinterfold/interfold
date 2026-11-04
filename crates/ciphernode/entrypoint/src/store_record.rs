// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The store record: `interfold start` writes the resolved path of its store next to the node's
//! key file, as `<key file>.store-record`. The record keeps every store that the node started
//! with, one path per line, the store of the last start last. A purge reads it, so it checks each
//! store that the node used, also when the node ran with another `E3_DATA_DIR`, `data_dir`, or
//! working directory than the purge's configuration gives, and also when a later start used
//! another store.

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

/// Record that the node of `key_file` starts with the store `db_file`, after the stores of its
/// earlier starts. The new record replaces the earlier one through a rename, so a crash leaves one
/// of the two. A record that cannot be read stays as it is, and this is an error.
pub fn write(key_file: &Path, db_file: &Path) -> Result<()> {
    let store = std::path::absolute(db_file)?;
    anyhow::ensure!(
        !store.as_os_str().as_bytes().contains(&b'\n'),
        "the store path {} holds a line break",
        store.display()
    );
    let mut stores = read(key_file)?;
    stores.retain(|recorded| *recorded != store);
    stores.push(store);
    let record = record_path(key_file);
    if let Some(folder) = record.parent() {
        std::fs::create_dir_all(folder)
            .with_context(|| format!("failed to create {}", folder.display()))?;
    }
    let mut temporary = record.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut content = Vec::new();
    for store in stores {
        content.extend(store.into_os_string().into_vec());
        content.push(b'\n');
    }
    std::fs::write(&temporary, content)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, &record)
        .with_context(|| format!("failed to write {}", record.display()))
}

/// The stores that the record of `key_file` names, the store of the last start last. Without a
/// record, there are none.
pub fn read(key_file: &Path) -> Result<Vec<PathBuf>> {
    let record = record_path(key_file);
    let content = match std::fs::read(&record) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", record.display()))
        }
    };
    let stores: Vec<_> = content
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| PathBuf::from(OsString::from_vec(line.to_vec())))
        .collect();
    anyhow::ensure!(
        !stores.is_empty() && stores.iter().all(|store| store.is_absolute()),
        "{} does not name a store",
        record.display()
    );
    Ok(stores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_names_the_store_next_to_the_key_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let key_file = dir.path().join("config/cn1/key");
        let store = dir.path().join("elsewhere/db");
        assert!(read(&key_file)?.is_empty());

        write(&key_file, &store)?;
        assert_eq!(
            record_path(&key_file),
            dir.path().join("config/cn1/key.store-record")
        );
        assert!(is_record(&record_path(&key_file)));
        assert_eq!(read(&key_file)?, vec![store.clone()]);

        // A later start with another store keeps the earlier one, and the last start's store
        // comes last, also when an earlier start used it.
        let other = dir.path().join("other/db");
        write(&key_file, &other)?;
        assert_eq!(read(&key_file)?, vec![store.clone(), other.clone()]);
        write(&key_file, &store)?;
        assert_eq!(read(&key_file)?, vec![other, store]);
        Ok(())
    }

    #[test]
    fn a_record_that_names_no_store_is_an_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let key_file = dir.path().join("key");
        std::fs::write(record_path(&key_file), b"not a path\n")?;
        assert!(read(&key_file).is_err());
        // A start keeps the unreadable record, so a purge still refuses.
        assert!(write(&key_file, &dir.path().join("db")).is_err());
        assert_eq!(std::fs::read(record_path(&key_file))?, b"not a path\n");
        Ok(())
    }
}
