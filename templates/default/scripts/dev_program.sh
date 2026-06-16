#!/usr/bin/env bash

set -euo pipefail
echo "interfold rev = $(interfold rev)"
echo "Waiting on ciphernodes to be ready..."
pnpm wait-on file:/tmp/interfold_ciphernodes_ready && interfold program start
