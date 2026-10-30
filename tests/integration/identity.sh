#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# The base scenario under a required identity policy: a mock verifier verifies every bond owner
# before the request, and the round must still decrypt.
IDENTITY_GATE=true "$THIS_DIR/base.sh"
