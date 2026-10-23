// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_console::{log, Console};

pub const GIT_SHA: &str = env!("GIT_SHA");

/// Optional Cargo features compiled into this binary, one per line.
///
/// Feature gates are resolved at compile time, so a checkout says nothing about
/// what the installed binary can do. Scripts that need a feature must ask the
/// binary itself. The `interfold-<platform>` release archives build `--bin interfold` with
/// no features and report an empty list. The test-only release archive reports
/// `test-only-skip-proof-aggregation`.
pub fn compiled_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "test-only-skip-proof-aggregation") {
        features.push("test-only-skip-proof-aggregation");
    }
    features
}

pub async fn execute(out: Console, features: bool) -> anyhow::Result<()> {
    if features {
        for feature in compiled_features() {
            log!(out, "{}", feature);
        }
        return Ok(());
    }
    log!(out, "{}", GIT_SHA);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::compiled_features;

    #[test]
    #[cfg(feature = "test-only-skip-proof-aggregation")]
    fn reports_the_skip_feature_when_compiled_in() {
        assert!(compiled_features().contains(&"test-only-skip-proof-aggregation"));
    }

    #[test]
    #[cfg(not(feature = "test-only-skip-proof-aggregation"))]
    fn omits_the_skip_feature_from_a_release_build() {
        assert!(!compiled_features().contains(&"test-only-skip-proof-aggregation"));
    }
}
