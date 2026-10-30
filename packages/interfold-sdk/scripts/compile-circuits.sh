#!/usr/bin/env bash
# Compile threshold user-data encryption circuits for the SDK.
# Default committee is minimum (matches DEFAULT_E3_CONFIG.committeeSize = CommitteeSize.Minimum).
# `user_data_encryption` is the circuit the SDK proves. No verification key is needed: the SDK
# returns the proof, and nothing it does verifies it inside another circuit.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMITTEE="${CIRCUIT_COMMITTEE:-minimum}"
case "${COMMITTEE}" in
  minimum|micro|small) ;;
    *)
    echo "Error: CIRCUIT_COMMITTEE must be minimum|micro|small (got: ${COMMITTEE})" >&2
    exit 1
    ;;
esac
exec pnpm -C "${REPO_ROOT}" build:circuits \
  --preset insecure-64 \
  --committee "${COMMITTEE}" \
  --group threshold \
  --circuit user_data_encryption \
  --skip-vk \
  --skip-checksums \
  --no-clean-targets
