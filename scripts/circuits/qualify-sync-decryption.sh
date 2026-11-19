#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
if [[ $# != 2 ]]; then echo "Usage: $0 {sync-insecure-64|sync-secure-8192} NEW_EXPORT_DIRECTORY" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/../.." && pwd)
export E3_SYNC_DECRYPTION_EXPORT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
if [[ -e "$E3_SYNC_DECRYPTION_EXPORT" ]]; then echo "Export path already exists" >&2; exit 2; fi
cd "$root"
case "$1" in
  sync-secure-8192) export E3_SYNC_SECURE_QUALIFICATION=1 ;;
  sync-insecure-64) unset E3_SYNC_SECURE_QUALIFICATION ;;
  *) exit 2 ;;
esac
export E3_CUSTOM_BB="$(command -v bb)" E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1
guard=(python3 scripts/circuits/guard-proof-rss.py)
"${guard[@]}" cargo test --locked -p e3-trbfv --test synchronized_dkg threshold_decryption:: -- --ignored --nocapture
"${guard[@]}" pnpm build:circuits decryption-candidate --preset "$1" --committee minimum --output "$E3_SYNC_DECRYPTION_EXPORT"
cd packages/interfold-contracts
E3_SYNC_CANDIDATE_PROFILE="$1" E3_SYNC_CANDIDATE_FIXTURE="$E3_SYNC_DECRYPTION_EXPORT" pnpm exec hardhat test mocha --no-compile test/SynchronizedDecryptionCandidate.spec.ts
