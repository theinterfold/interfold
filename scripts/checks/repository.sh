#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Check production configuration, the startup proof guard, and the fire-and-forget send ceiling.
# These static checks do not establish runtime delivery or proof-verification behavior.

set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0

# Retain the send ratchet while the acknowledged event pipeline remains incomplete (#2266).
baseline_file="scripts/checks/repository-baselines.env"
DO_SEND_BASELINE="$(sed -nE 's/^DO_SEND_BASELINE=([0-9]+)$/\1/p' "$baseline_file" 2>/dev/null || true)"
if [[ ! "$DO_SEND_BASELINE" =~ ^[0-9]+$ ]]; then
  echo "check-repository: FAILED — invalid or missing DO_SEND_BASELINE in $baseline_file"
  exit 1
fi
count=$({ grep -rE '\.do_send\(' crates --include='*.rs' || true; } | wc -l | tr -d ' ')
if ((count > DO_SEND_BASELINE)); then
  echo "check-repository: FAILED — .do_send( call sites grew: $count > baseline $DO_SEND_BASELINE"
  echo "  Use an acknowledged, timeout-bounded send for correctness-critical delivery."
  echo "  Existing calls include correctness paths; this ceiling does not prove safe delivery."
  echo "  Any baseline increase needs an explicit review of the new call sites."
  fail=1
elif ((count < DO_SEND_BASELINE)); then
  echo "check-repository: do_send count dropped to $count (baseline $DO_SEND_BASELINE)."
  echo "  Please ratchet: set DO_SEND_BASELINE=$count in $baseline_file."
fi

# --- 1. skip-proof feature containment --------------------------------------------
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
  echo "check-repository: FAILED — no Python with tomllib (3.11+) found on PATH."
  echo "  The skip-proof feature containment check cannot run, so the invariant is"
  echo "  unverified. Install Python 3.11 or newer, or 'pip install tomli' for python3."
  fail=1
elif ! "$python_bin" scripts/checks/cargo-feature-containment.py; then
  fail=1
fi

# --- 2. ciphernode Docker workspace coverage --------------------------------------
if [[ -n "$python_bin" ]] && ! "$python_bin" scripts/checks/ciphernode-docker-members.py; then
  fail=1
fi

# --- 3. production Compose shutdown grace ----------------------------------------
check_compose_shutdown_grace() {
  local compose_file=$1
  # Validate each service, not total field counts: duplicate fields on one service cannot
  # compensate for a missing budget on another. This deliberately accepts the maintained layout,
  # not general YAML aliases, quoted names, or every Compose duration notation.
  if ! awk '
    function error(message) {
      print "check-repository: FAILED — " FILENAME " " service ": " message
      failed=1
    }
    function finish() {
      if (service != "" && graces != 1) error("must declare exactly one stop_grace_period")
      service=""
    }
    /^[[:space:]]*#/ { next }
    /^services:$/ { in_services=1; next }
    in_services && /^[^ ]/ { finish(); in_services=0 }
    in_services && /^  [[:alnum:]_-]+:/ {
      finish(); service=$1; graces=0; services++; next
    }
    in_services && /^  [^ ]/ { error("unsupported service layout"); next }
    in_services && /^    stop_grace_period:/ {
      graces++
      if ($0 !~ /^    stop_grace_period: [0-9]+s$/) error("stop_grace_period must be unquoted integer seconds")
      else if (($2+0) <= 60) error("stop_grace_period must exceed 60 seconds")
    }
    END {
      finish()
      if (services == 0) error("no services found in the supported layout")
      exit failed
    }
  ' "$compose_file"; then
    fail=1
  fi
}

check_compose_shutdown_grace dappnode/docker-compose.yml
check_compose_shutdown_grace deploy/docker-compose.yml

# Keep the runtime rejection as well as Cargo feature containment.
if ! grep -rq 'fn validate_proof_aggregation_mode' crates/entrypoint/src ||
  ! grep -rEq 'validate_proof_aggregation_mode\(config' crates/entrypoint/src; then
  echo "check-repository: FAILED — validate_proof_aggregation_mode missing or no longer called"
  echo "  in crates/entrypoint/src; production startup must reject proof-skipping mode."
  fail=1
fi

if ((fail == 0)); then
  echo "✓ check:repository: do_send=$count (≤ $DO_SEND_BASELINE), feature containment, runtime proof guard, Docker coverage, and shutdown grace verified"
fi
exit "$fail"
