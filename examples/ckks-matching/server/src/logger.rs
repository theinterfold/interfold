// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use env_logger::{Builder, Env};
use std::io::Write;

pub fn init_logger() {
    let env = Env::default().filter_or("RUST_LOG", "info,e3_indexer=info");
    Builder::from_env(env)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {}] {}",
                chrono_free_now(),
                record.level(),
                record.args()
            )
        })
        .try_init()
        .ok();
}

/// `HH:MM:SS` from the system clock without pulling chrono in.
fn chrono_free_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}
