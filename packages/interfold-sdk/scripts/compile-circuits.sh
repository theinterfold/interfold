#!/usr/bin/env bash
# Compile threshold user-data encryption circuits for the SDK.
# Default committee is minimum (matches DEFAULT_E3_CONFIG.committeeSize = CommitteeSize.Minimum).
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
  --preset insecure-512 \
  --committee "${COMMITTEE}" \
  --group threshold \
  --circuit user_data_encryption \
  --circuit user_data_encryption_ct0 \
  --circuit user_data_encryption_ct1 \
  --skip-vk \
  --skip-checksums \
  --no-clean-targets
