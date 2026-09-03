#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Build + run only the coordinator server against an already-running stack.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"
node scripts/sync-config.mjs "$@"
cargo build --release -p ckks-salary-survey
exec ./target/release/server
