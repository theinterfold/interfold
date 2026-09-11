#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CIPHERNODE_SKIP_PROOF_AGGREGATION="${CIPHERNODE_SKIP_PROOF_AGGREGATION:-true}"
SKIP_PREBUILD=false

parse_integration_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-proof-aggregation)
        shift
        CIPHERNODE_SKIP_PROOF_AGGREGATION="${1:-true}"
        shift
        ;;
      --no-prebuild)
        SKIP_PREBUILD=true
        shift
        ;;
      *)
        echo "Unknown integration argument: $1" >&2
        echo "Usage: ./test.sh [base|persist|net|prebuild] [--skip-proof-aggregation true|false] [--no-prebuild]" >&2
        exit 1
        ;;
    esac
  done
}

export_integration_flags() {
  if [[ "$CIPHERNODE_SKIP_PROOF_AGGREGATION" == "true" ]]; then
    FULL_PROOF_AGGREGATION=false
  else
    FULL_PROOF_AGGREGATION=true
  fi
  export FULL_PROOF_AGGREGATION
  if [[ "$FULL_PROOF_AGGREGATION" == "true" ]]; then
    export ENABLE_ZK_VERIFICATION=true
    export INTEGRATION_DKG_TIMEOUT="${INTEGRATION_DKG_TIMEOUT:-3600}"
  else
    export ENABLE_ZK_VERIFICATION=false
    export INTEGRATION_DKG_TIMEOUT="${INTEGRATION_DKG_TIMEOUT:-1300}"
  fi
  export CIPHERNODE_SKIP_PROOF_AGGREGATION
  export E3_NODES__CN1__SKIP_PROOF_AGGREGATION="$CIPHERNODE_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN2__SKIP_PROOF_AGGREGATION="$CIPHERNODE_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN3__SKIP_PROOF_AGGREGATION="$CIPHERNODE_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN4__SKIP_PROOF_AGGREGATION="$CIPHERNODE_SKIP_PROOF_AGGREGATION"
  export E3_NODES__CN5__SKIP_PROOF_AGGREGATION="$CIPHERNODE_SKIP_PROOF_AGGREGATION"
}

if [ $# -eq 0 ]; then
  export CIPHERNODE_SKIP_PROOF_AGGREGATION=true
  export_integration_flags
  "$THIS_DIR/lib/prebuild.sh"
  "$THIS_DIR/persist.sh"
  "$THIS_DIR/base.sh"
  "$THIS_DIR/net.sh"
else
  SCRIPT_NAME="$1"
  shift
  case "$SCRIPT_NAME" in
    base|persist|net|prebuild) ;;
    *)
      echo "Unknown integration entry point: $SCRIPT_NAME (expected base, persist, net, or prebuild)" >&2
      exit 1
      ;;
  esac
  parse_integration_args "$@"
  export_integration_flags

  if [[ "$SKIP_PREBUILD" != "true" ]]; then
    "$THIS_DIR/lib/prebuild.sh"
  fi

  "$THIS_DIR/${SCRIPT_NAME}.sh"
fi
