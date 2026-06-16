#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

PROOF_AGGREGATION_ENABLED="${PROOF_AGGREGATION_ENABLED:-false}"
SKIP_PREBUILD=false

parse_integration_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proof-aggregation-enabled)
        shift
        PROOF_AGGREGATION_ENABLED="${1:-true}"
        shift
        ;;
      --no-prebuild)
        SKIP_PREBUILD=true
        shift
        ;;
      *)
        echo "Unknown integration argument: $1" >&2
        echo "Usage: ./test.sh [base|persist|net|restart] [--proof-aggregation-enabled true|false] [--no-prebuild]" >&2
        exit 1
        ;;
    esac
  done
}

export_integration_flags() {
  export PROOF_AGGREGATION_ENABLED
  if [[ "$PROOF_AGGREGATION_ENABLED" == "true" ]]; then
    export ENABLE_ZK_VERIFICATION=true
    export INTEGRATION_DKG_TIMEOUT="${INTEGRATION_DKG_TIMEOUT:-3600}"
  else
    export ENABLE_ZK_VERIFICATION=false
    export INTEGRATION_DKG_TIMEOUT="${INTEGRATION_DKG_TIMEOUT:-1300}"
  fi
}

if [ $# -eq 0 ]; then
  export PROOF_AGGREGATION_ENABLED=false
  export_integration_flags
  "$THIS_DIR/lib/prebuild.sh"
  "$THIS_DIR/persist.sh"
  "$THIS_DIR/base.sh"
  "$THIS_DIR/net.sh"
  "$THIS_DIR/restart.sh"
else
  SCRIPT_NAME="$1"
  shift
  parse_integration_args "$@"
  export_integration_flags

  if [[ "$SKIP_PREBUILD" != "true" ]]; then
    "$THIS_DIR/lib/prebuild.sh"
  fi

  "$THIS_DIR/${SCRIPT_NAME}.sh"
fi
