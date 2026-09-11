#!/usr/bin/env bash

set -e

# Keep this test independent of a developer's server/.env. The voting window must remain open
# through committee formation, DKG, wallet reconnection, and encrypted-vote proof generation.
export E3_DURATION="${CRISP_E2E_DURATION_SECS:-300}"

if [ "$1" == "--ui" ]; then
  PLAYWRIGHT_CMD="pnpm synpress && pnpm playwright test"
else
  # Use xvfb-run only on Linux systems
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLAYWRIGHT_CMD="pnpm synpress --headless && xvfb-run --auto-servernum --server-args=\"-screen 0 1280x960x24\" pnpm playwright test"
  else
    PLAYWRIGHT_CMD="pnpm synpress --headless && pnpm playwright test"
  fi
fi

echo "TEST E2E SCRIPT STARTING..."
# The client starts only after the ciphernodes are running and registered.
pnpm concurrently --kill-others --raw --names dev,tests --success command-tests ./scripts/dev.sh "wait-on tcp:3000 file:./.interfold/ready && ${PLAYWRIGHT_CMD}"
