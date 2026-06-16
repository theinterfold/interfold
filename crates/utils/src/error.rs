// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use tracing::error;

/// Formats panic errors so they are seen in logs clearly
pub fn major_issue(msg: &str, e: impl Into<anyhow::Error>) -> String {
    error!("\n\n\nMAJOR ISSUE: {msg}.\n\nThe error supplied was: {:?}\n\n As a precaution we are crashing the system.\n\n\n", e.into());
    "System has crashed. Nothing personal. Goodbye.".to_string()
}
