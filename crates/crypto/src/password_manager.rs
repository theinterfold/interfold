// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use async_trait::async_trait;
use std::{
    env,
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[async_trait]
pub trait PasswordManager {
    async fn get_key(&self) -> Result<Zeroizing<Vec<u8>>>;
    async fn delete_key(&mut self) -> Result<()>;
    async fn set_key(&mut self, contents: Zeroizing<Vec<u8>>) -> Result<()>;
    fn is_set(&self) -> bool;
}

pub struct InMemPasswordManager(pub Option<Zeroizing<Vec<u8>>>);

impl InMemPasswordManager {
    pub fn new(value: Zeroizing<Vec<u8>>) -> Self {
        Self(Some(value))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Self {
        Self::new(Zeroizing::new(value.as_bytes().to_vec()))
    }
}

pub struct EnvPasswordManager(pub Option<Zeroizing<Vec<u8>>>);

impl EnvPasswordManager {
    pub fn new(value: &str) -> Result<Self> {
        let env_string = env::var(value)?.as_bytes().into();
        Ok(Self(Some(Zeroizing::new(env_string))))
    }
}

#[async_trait]
impl PasswordManager for EnvPasswordManager {
    async fn get_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(key) = self.0.clone() {
            return Ok(key);
        }
        Err(anyhow!("No key found"))
    }
    async fn set_key(&mut self, contents: Zeroizing<Vec<u8>>) -> Result<()> {
        self.0 = Some(contents);
        Ok(())
    }

    async fn delete_key(&mut self) -> Result<()> {
        self.0 = None;
        Ok(())
    }

    fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

#[async_trait]
impl PasswordManager for InMemPasswordManager {
    async fn get_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(key) = self.0.clone() {
            return Ok(key);
        }
        Err(anyhow!("No key found"))
    }
    async fn set_key(&mut self, contents: Zeroizing<Vec<u8>>) -> Result<()> {
        self.0 = Some(contents);
        Ok(())
    }

    async fn delete_key(&mut self) -> Result<()> {
        self.0 = None;
        Ok(())
    }

    fn is_set(&self) -> bool {
        self.0.is_some()
    }
}

pub struct FilePasswordManager {
    path: PathBuf,
}

impl FilePasswordManager {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }
}

#[async_trait]
impl PasswordManager for FilePasswordManager {
    // We are assuming a secrets manager will mount the secret on the volume. Hence we would expect
    // the password to be a string provided by the user.
    // See the following for more info:
    //   https://docs.docker.com/engine/swarm/secrets/
    //   https://kubernetes.io/docs/concepts/configuration/secret/
    //   https://developer.hashicorp.com/vault/docs/platform/k8s/injector
    async fn get_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let path = &self.path;

        ensure_file_permissions(path, 0o400)?;

        let bytes = fs::read(&self.path).context("Failed to access keyfile")?;

        Ok(Zeroizing::new(bytes))
    }

    async fn delete_key(&mut self) -> Result<()> {
        let path = &self.path;

        ensure_file_permissions(path, 0o600)?;

        fs::remove_file(path).context("Failed to remove keyfile")?;
        Ok(())
    }

    async fn set_key(&mut self, contents: Zeroizing<Vec<u8>>) -> Result<()> {
        let path = &self.path;

        if contents.is_empty() {
            bail!("Password must contain data!")
        }

        // Ensure parent directories exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create parent directories")?;
        }

        // Check if file exists
        if path.exists() {
            bail!("Keyfile already exists. Refusing to overwrite.")
        }

        // Create new file with restrictive permissions from the start
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .context("Failed to create keyfile")?;

        // Write the contents
        file.write_all(&contents)
            .context("Failed to write data to keyfile")?;

        file.flush().context("Failed to flush data to keyfile")?;

        // Close the file handle explicitly
        drop(file);

        // Set to read-only (400)
        fs::set_permissions(path, Permissions::from_mode(0o400))
            .context("Failed to set permissions on keyfile")?;

        Ok(())
    }

    fn is_set(&self) -> bool {
        let path = &self.path;
        path.exists()
    }
}

fn ensure_file_permissions(path: &PathBuf, perms: u32) -> Result<()> {
    // Get current permissions
    let metadata = fs::metadata(path).context("Failed to get metadata for keyfile")?;

    let current_mode = metadata.permissions().mode() & 0o777;

    // Check if permissions are already 400
    if current_mode != perms {
        // Set permissions to 400
        fs::set_permissions(path, Permissions::from_mode(perms))
            .context("Failed to set permissions for keyfile")?;
    }

    Ok(())
}
