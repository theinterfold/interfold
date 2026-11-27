#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
if [[ $# != 2 && ( $# != 3 || $3 != --signed ) ]]; then
  echo "Usage: $0 {sync-insecure-64|sync-secure-8192} NEW_EXPORT_DIRECTORY [--signed]" >&2
  exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd)
parent=$(cd -- "$(dirname -- "$2")" && pwd -P) || { echo "Export parent must exist: $2" >&2; exit 2; }
export E3_SYNC_DECRYPTION_EXPORT="$parent/$(basename -- "$2")"
if [[ -e "$E3_SYNC_DECRYPTION_EXPORT" || -L "$E3_SYNC_DECRYPTION_EXPORT" ]]; then echo "Export path already exists" >&2; exit 2; fi
if [[ ${3:-} == --signed && $1 == sync-secure-8192 ]]; then
  : "${E3_SYNC_OTHER_PROFILE_EXPORT:?set to the public export from the signed insecure rehearsal}"
  E3_SYNC_OTHER_PROFILE_EXPORT=$(cd -- "$E3_SYNC_OTHER_PROFILE_EXPORT" && pwd -P)
  export E3_SYNC_OTHER_PROFILE_EXPORT
fi
cd "$root"
case "$1" in
  sync-secure-8192) export E3_SYNC_SECURE_QUALIFICATION=1 ;;
  sync-insecure-64) unset E3_SYNC_SECURE_QUALIFICATION ;;
  *) exit 2 ;;
esac
E3_CUSTOM_BB=$(command -v bb) || { echo "bb not found" >&2; exit 2; }
if ! solc --version | grep -q '^Version: 0\.8\.28+'; then echo "solc 0.8.28 required" >&2; exit 2; fi
export E3_CUSTOM_BB E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1
guard=(python3 scripts/circuits/guard-proof-rss.py)
if [[ ${3:-} == --signed ]]; then
  export RUST_MIN_STACK=${RUST_MIN_STACK:-16777216}
  "${guard[@]}" cargo test --locked -p e3-keyshare --lib synchronized_disk_reopen_uses_real_proofs_and_restored_private_inputs -- --ignored --nocapture --test-threads=1
  "${guard[@]}" pnpm build:circuits dkg-candidate --preset "$1" --committee minimum --output "$E3_SYNC_DECRYPTION_EXPORT"
else
  "${guard[@]}" cargo test --locked -p e3-trbfv --test synchronized_dkg threshold_decryption:: -- --ignored --nocapture
fi
"${guard[@]}" pnpm build:circuits decryption-candidate --preset "$1" --committee minimum --output "$E3_SYNC_DECRYPTION_EXPORT"
cd packages/interfold-contracts
E3_SYNC_CANDIDATE_PROFILE="$1" E3_SYNC_CANDIDATE_FIXTURE="$E3_SYNC_DECRYPTION_EXPORT" pnpm exec hardhat --config hardhat.qualification.config.ts test mocha --no-compile test/SynchronizedDecryptionCandidate.spec.ts
