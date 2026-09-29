// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fs, io::Write, path::PathBuf};

use tracing::{error, subscriber::DefaultGuard, trace};
use tracing_subscriber::{fmt, EnvFilter};

/// Use this at the top of a test to include tracing
pub fn with_tracing(level: &str) -> DefaultGuard {
    tracing::subscriber::set_default(
        fmt()
            .with_env_filter(EnvFilter::new(level))
            .with_test_writer()
            .finish(),
    )
}

pub fn write_file_with_dirs(path: &PathBuf, content: &[u8]) -> std::io::Result<()> {
    let abs_path = if path.is_absolute() {
        path.clone()
    } else {
        let cwd = std::env::current_dir()?;
        cwd.join(path)
    };

    match abs_path.to_str() {
        Some(s) => trace!(path = s, "Writing to path"),
        None => error!(path=?abs_path, "Cannot parse path"),
    };

    // Ensure the directory structure exists
    if let Some(parent) = abs_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open the file (creates it if it doesn't exist) and write the content
    let mut file = fs::File::create(&abs_path)?;
    file.write_all(content)?;
    trace!(
        path = abs_path.to_str().unwrap(),
        "File written successfully!"
    );
    Ok(())
}
