#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Mechanically enforces grep-checkable invariants from agent/invariants/.
# Companion to check-committee.sh (structural sync) and check-doc-sync.sh (doc drift).
#
# Checks:
#   1. do_send ratchet — `.do_send(` is allowed only for best-effort telemetry
#      (agent/ARCHITECTURE.md); the call-site count may only go DOWN. Baseline lives in
#      scripts/invariant-baselines.env.
#   2. skip-proof feature containment — `test-only-skip-proof-aggregation` must never be
#      a default feature and must only be *enabled* (as a dependency feature) by
#      crates/tests. Forwarding declarations in [features] sections are fine.
#   3. runtime proof-skip guard — validate_proof_aggregation_mode must exist and be
#      called in crates/entrypoint (agent/invariants/02_CRYPTO_CIRCUITS.md, C-02).
#   4. ciphernode Docker workspace coverage — every root workspace crate manifest
#      must be present in the dependency-cache stage of crates/Dockerfile.
#   5. l-BFV protocol version sync — the Rust release manifest and Solidity V2
#      verifier must use the same protocol version in the proof-session domain.
#   6. production Compose shutdown grace — every ciphernode service must give the
#      node more than 60 seconds to finish its durability barrier.
#
# Exit 0 when all hold, 1 otherwise.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
baseline_file="scripts/invariant-baselines.env"
DO_SEND_BASELINE="$(sed -nE 's/^DO_SEND_BASELINE=([0-9]+)$/\1/p' "$baseline_file")"
if [[ -z "$DO_SEND_BASELINE" ]]; then
  echo "check-invariants: FAILED — invalid or missing DO_SEND_BASELINE in $baseline_file"
  exit 1
fi

# --- 1. do_send ratchet -----------------------------------------------------------
count=$({ grep -rE '\.do_send\(' crates --include='*.rs' || true; } | wc -l | tr -d ' ')
if ((count > DO_SEND_BASELINE)); then
  echo "check-invariants: FAILED — .do_send( call sites grew: $count > baseline $DO_SEND_BASELINE"
  echo "  do_send is fire-and-forget and allowed only for best-effort telemetry"
  echo "  (agent/ARCHITECTURE.md §Routing). Use an acknowledged, timeout-bounded send"
  echo "  for anything correctness-critical. If the new call site really is telemetry,"
  echo "  raise DO_SEND_BASELINE in $baseline_file in the same PR and say why."
  fail=1
elif ((count < DO_SEND_BASELINE)); then
  echo "check-invariants: do_send count dropped to $count (baseline $DO_SEND_BASELINE)."
  echo "  Please ratchet: set DO_SEND_BASELINE=$count in $baseline_file."
fi

# --- 2. skip-proof feature containment --------------------------------------------
# The containment check parses Cargo.toml with tomllib, which is stdlib only from
# Python 3.11. macOS still ships 3.9 as `python3`, so find an interpreter that has it
# rather than failing the gate on the environment. The check also falls back to the
# tomli package, so accept either module here.
python_bin=""
# 3.10 and 3.9 qualify too when tomli is installed, so their versioned names are
# candidates as well; newest first after the default `python3`.
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c 'import importlib.util as u, sys; sys.exit(0 if u.find_spec("tomllib") or u.find_spec("tomli") else 1)' >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done

if [[ -z "$python_bin" ]]; then
  echo "check-invariants: FAILED — no Python with tomllib (3.11+) found on PATH."
  echo "  The skip-proof feature containment check cannot run, so the invariant is"
  echo "  unverified. Install Python 3.11 or newer, or 'pip install tomli' for python3."
  fail=1
elif ! "$python_bin" scripts/check-cargo-feature-containment.py; then
  fail=1
fi

# --- 3. runtime proof-skip guard --------------------------------------------------
if ! grep -rq 'fn validate_proof_aggregation_mode' crates/entrypoint/src ||
  ! grep -rEq 'validate_proof_aggregation_mode\(config' crates/entrypoint/src; then
  echo "check-invariants: FAILED — validate_proof_aggregation_mode missing or no longer called"
  echo "  in crates/entrypoint/src (agent/invariants/02_CRYPTO_CIRCUITS.md, C-02)."
  fail=1
fi

# --- 4. ciphernode Docker workspace coverage --------------------------------------
if [[ -n "$python_bin" ]] && ! "$python_bin" scripts/check-ciphernode-docker-members.py; then
  fail=1
fi

# --- 5. l-BFV protocol version sync -----------------------------------------------
release_file="crates/config/protocol-release.toml"
verifier_file="packages/interfold-contracts/contracts/verifiers/bfv/BfvPkVerifierV2.sol"
release_match_count=$(grep -Ec '^protocol_version = [0-9]+$' "$release_file" || true)
verifier_match_count=$(grep -Ec '^[[:space:]]*uint256 public constant LBFV_PROTOCOL_VERSION = [0-9]+;$' "$verifier_file" || true)
if ((release_match_count != 1 || verifier_match_count != 1)); then
  echo "check-invariants: FAILED — expected one protocol-version declaration in each source"
  echo "  Rust: $release_file (matches: $release_match_count)"
  echo "  Solidity: $verifier_file (matches: $verifier_match_count)"
  fail=1
else
  release_protocol_version=$(sed -nE 's/^protocol_version = ([0-9]+)$/\1/p' "$release_file")
  verifier_protocol_version=$(sed -nE 's/^[[:space:]]*uint256 public constant LBFV_PROTOCOL_VERSION = ([0-9]+);$/\1/p' "$verifier_file")
  if ((release_protocol_version == 0 || release_protocol_version != verifier_protocol_version)); then
    echo "check-invariants: FAILED — l-BFV protocol versions differ"
    echo "  Rust protocol_version=$release_protocol_version"
    echo "  Solidity LBFV_PROTOCOL_VERSION=$verifier_protocol_version"
    fail=1
  fi
fi

# --- 6. production Compose shutdown grace ----------------------------------------
check_compose_shutdown_grace() {
  local compose_file=$1
  local service_count
  local grace_count
  service_count=$(awk '
    /^services:/ { in_services=1; next }
    in_services && /^[^ ]/ { exit }
    in_services && /^  [[:alnum:]_-]+:/ { count++ }
    END { print count+0 }
  ' "$compose_file")
  grace_count=$(grep -cE '^    stop_grace_period: [0-9]+s$' "$compose_file" || true)
  if ((service_count == 0 || grace_count != service_count)); then
    echo "check-invariants: FAILED — every service in $compose_file must declare stop_grace_period"
    fail=1
    return
  fi
  while IFS= read -r grace_secs; do
    if ((grace_secs <= 60)); then
      echo "check-invariants: FAILED — $compose_file stop_grace_period must exceed 60 seconds"
      fail=1
    fi
  done < <(sed -nE 's/^    stop_grace_period: ([0-9]+)s$/\1/p' "$compose_file")
}

check_compose_shutdown_grace dappnode/docker-compose.yml
check_compose_shutdown_grace deploy/docker-compose.yml

if ((fail == 0)); then
  echo "✓ check:invariants: do_send=$count (≤ $DO_SEND_BASELINE), skip-proof feature contained, runtime guard present, ciphernode Docker workspace complete, l-BFV protocol version=$release_protocol_version, shutdown grace verified"
fi
exit "$fail"
