#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/dev_config.sh"

load_template_dev_config
cd "${TEMPLATE_ROOT}"

echo "interfold rev = $(interfold rev)"
echo "Waiting on ciphernodes to be ready..."
pnpm wait-on file:/tmp/interfold_ciphernodes_ready && interfold program start
