// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::{fs, path::PathBuf};

pub fn load_yaml_with_env(file_path: &PathBuf) -> Result<String> {
    let content = fs::read_to_string(file_path)?;
    Ok(shellexpand::env(&content)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn test_yaml_env_substitution() {
        // The jail holds the lock that the other tests that change the environment take, and
        // restores the environment afterwards.
        Jail::expect_with(|jail| {
            jail.create_file(
                "test.yaml",
                "database:\n  url: $MY_DATABASE_URL\n  password: ${MY_DB_PASSWORD}\n",
            )?;
            jail.set_env("MY_DATABASE_URL", "postgres://localhost:5432");
            jail.set_env("MY_DB_PASSWORD", "secret123");

            let processed = load_yaml_with_env(&jail.directory().join("test.yaml"))
                .map_err(|error| error.to_string())?;

            assert!(processed.contains("postgres://localhost:5432"));
            assert!(processed.contains("secret123"));
            Ok(())
        });
    }
}
