// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Serves a project's E3 program to the ciphernodes. The project owns its program and passes it in
//! from a small runner binary:
//!
//! ```ignore
//! fn main() -> anyhow::Result<()> {
//!     e3_program_runner::run(e3_user_program::fhe_processor, e3_user_program::policy())
//! }
//! ```
//!
//! `interfold program start` runs that binary with one argument: `dev` serves the unproved
//! development runner, and `openvm` serves the OpenVM proving service.

mod dev;
mod openvm;

use anyhow::{bail, Result};
use std::ffi::OsString;

pub use e3_compute_provider::{FHEProcessor, InputPolicy};

/// The service that the runner binary serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The unproved development runner.
    Dev,
    /// The OpenVM proving service.
    OpenVm,
}

/// The mode that the first argument after the binary names. Any other argument, a missing one, or
/// one that is not UTF-8 is a usage error.
fn mode_from(args: impl IntoIterator<Item = OsString>) -> Result<Mode> {
    let mut args = args.into_iter();
    let binary = args.next().unwrap_or_default();
    match args.next().as_deref().and_then(|mode| mode.to_str()) {
        Some("dev") => Ok(Mode::Dev),
        Some("openvm") => Ok(Mode::OpenVm),
        _ => bail!("Usage: {} dev|openvm", binary.to_string_lossy()),
    }
}

/// Serves `processor` under `policy` in the mode that the first command-line argument names.
pub fn run(processor: FHEProcessor, policy: InputPolicy) -> Result<()> {
    let mode = mode_from(std::env::args_os())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match mode {
        Mode::Dev => runtime.block_on(dev::serve(processor, policy)),
        Mode::OpenVm => runtime.block_on(openvm::serve(processor, policy)),
    }
}

#[cfg(test)]
mod tests {
    use super::{mode_from, Mode};
    use std::ffi::OsString;

    fn args(mode: &[&str]) -> Vec<OsString> {
        std::iter::once("program-runner")
            .chain(mode.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn the_first_argument_selects_the_mode() {
        assert_eq!(mode_from(args(&["dev"])).unwrap(), Mode::Dev);
        assert_eq!(mode_from(args(&["openvm"])).unwrap(), Mode::OpenVm);
    }

    #[test]
    fn a_missing_or_unknown_mode_is_a_usage_error() {
        assert!(mode_from(args(&[])).is_err());
        assert!(mode_from(args(&["Dev"])).is_err());
        assert!(mode_from(args(&["openvm-cuda"])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_mode_is_a_usage_error() {
        use std::os::unix::ffi::OsStringExt;
        let mode = OsString::from_vec(b"dev\xff".to_vec());
        assert!(mode_from([OsString::from("program-runner"), mode]).is_err());
    }
}
