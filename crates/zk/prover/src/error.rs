// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkError {
    #[error("Barretenberg binary not found. Run 'interfold noir setup' first.")]
    BbNotInstalled,

    #[error("Circuit '{0}' not found. Run 'interfold noir setup' first.")]
    CircuitNotFound(String),

    #[error("Version mismatch: installed {installed}, required {required}")]
    VersionMismatch { installed: String, required: String },

    #[error("Failed to download {0}: {1}")]
    DownloadFailed(String, String),

    #[error("Checksum mismatch for {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Proof generation failed: {0}")]
    ProveFailed(String),

    #[error("Proof verification failed: {0}")]
    VerifyFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Failed to read proof output: {0}")]
    OutputReadError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("TOML error: {0}")]
    TomlError(#[from] toml::ser::Error),

    #[error("Backend not initialized")]
    NotInitialized,

    #[error("Unsupported platform: {os}-{arch}")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("Inputs generation failed: {0}")]
    InputsGenerationFailed(String),

    #[error("Witness generation failed: {0}")]
    WitnessGenerationFailed(String),

    #[error("checksum missing for {0}")]
    ChecksumMissing(String),

    #[error("Invalid proof input: {0}")]
    InvalidInput(String),
}
