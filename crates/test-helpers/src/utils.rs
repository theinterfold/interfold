// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use tracing::subscriber::DefaultGuard;
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
