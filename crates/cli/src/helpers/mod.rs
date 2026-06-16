// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use zeroize::{Zeroize, Zeroizing};

pub mod compile_id;
pub mod prompt_password;
pub mod telemetry;

/// Parse to a Zeroizing String
pub fn parse_zeroizing(s: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(s.to_string()))
}

/// Ensure hex is of the form 0x12435687abcdef...
pub fn ensure_hex_zeroizing(s: &str) -> Result<Zeroizing<String>> {
    parse_zeroizing(ensure_hex(s)?)
}

/// Ensure a hexadecimal number
fn ensure_hex(s: &str) -> Result<&str> {
    if !s.starts_with("0x") {
        bail!("hex value must start with '0x'")
    }
    if !s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("private key must only contain hex characters [0-9a-fA-F]");
    }
    hex::decode(&s[2..])?.zeroize();
    Ok(s)
}
