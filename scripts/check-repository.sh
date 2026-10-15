#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Check production build and deployment configuration. These checks do not establish runtime
# delivery or proof-verification behavior; those contracts need behavior tests at their owners.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

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
elif ! "$python_bin" scripts/check-cargo-feature-containment.py; then
  fail=1
fi

# --- 2. ciphernode Docker workspace coverage --------------------------------------
if [[ -n "$python_bin" ]] && ! "$python_bin" scripts/check-ciphernode-docker-members.py; then
  fail=1
fi

# --- 3. production Compose shutdown grace ----------------------------------------
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
    echo "check-repository: FAILED — every service in $compose_file must declare stop_grace_period"
    fail=1
    return
  fi
  while IFS= read -r grace_secs; do
    if ((grace_secs <= 60)); then
      echo "check-repository: FAILED — $compose_file stop_grace_period must exceed 60 seconds"
      fail=1
    fi
  done < <(sed -nE 's/^    stop_grace_period: ([0-9]+)s$/\1/p' "$compose_file")
}

check_compose_shutdown_grace dappnode/docker-compose.yml
check_compose_shutdown_grace deploy/docker-compose.yml

if ((fail == 0)); then
  echo "✓ check:repository: feature containment, Docker coverage, and configured shutdown grace verified"
fi
exit "$fail"
