#!/usr/bin/env bash
set -euo pipefail
exec cargo build --locked --release --manifest-path /app/crates/support/Cargo.toml
