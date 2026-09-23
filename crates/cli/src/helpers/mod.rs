// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Context, Result};
use std::io::BufRead;
use zeroize::{Zeroize, Zeroizing};

pub mod chain;
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

/// Read one secret from stdin without placing it in argv or the environment.
///
/// Only the line terminator is removed. Other whitespace remains part of the
/// secret so callers can apply their normal validation rules.
pub fn read_secret_line(reader: &mut impl BufRead, description: &str) -> Result<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    let bytes_read = reader
        .read_line(&mut value)
        .with_context(|| format!("failed to read {description} from stdin"))?;
    if bytes_read == 0 {
        bail!("{description} was not provided on stdin");
    }

    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.contains(['\r', '\n', '\0']) {
        bail!("{description} on stdin must be a single line");
    }
    if value.is_empty() {
        bail!("{description} on stdin must not be empty");
    }

    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn secret_line_removes_only_the_line_terminator() -> Result<()> {
        let mut input = Cursor::new(b"  secret value  \r\nnext\n");

        assert_eq!(
            &*read_secret_line(&mut input, "password")?,
            "  secret value  "
        );
        assert_eq!(&*read_secret_line(&mut input, "private key")?, "next");
        Ok(())
    }

    #[test]
    fn secret_line_rejects_missing_and_embedded_newlines() {
        assert!(read_secret_line(&mut Cursor::new(Vec::<u8>::new()), "password").is_err());
        assert!(read_secret_line(&mut Cursor::new(b"\n"), "password").is_err());
        assert!(read_secret_line(&mut Cursor::new(b"bad\rvalue\n"), "password").is_err());
    }
}
