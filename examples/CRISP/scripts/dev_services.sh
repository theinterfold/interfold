#!/usr/bin/env bash

set -euo pipefail

concurrently -kr \
  "./scripts/dev_cipher.sh ./.interfold/ready" \
  "./scripts/dev_program.sh" \
  "wait-on tcp:13151 && ./scripts/dev_server.sh" \
  "wait-on tcp:4000 && wait-on file:./.interfold/ready && ./scripts/dev_client.sh"
