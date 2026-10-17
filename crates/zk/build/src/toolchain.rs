// SPDX-License-Identifier: LGPL-3.0-only

//! Version metadata shared by circuit build and execution tools.

use anyhow::{Context, Result};
use regex::Regex;

pub fn pinned_noir_version(manifest: &str) -> Result<String> {
    let pattern = Regex::new(r#"noir-lang/noir", tag = "v([^"]+)""#).unwrap();
    pattern
        .captures(manifest)
        .map(|capture| capture[1].to_string())
        .context("No pinned Noir version in the prover manifest")
}

pub fn reports_version(output: &str, expected: &str) -> bool {
    Regex::new(&format!(
        r"(?m)(^|[\s=])v?{}(\+\S*)?\r?$",
        regex::escape(expected)
    ))
    .unwrap()
    .is_match(output)
}
