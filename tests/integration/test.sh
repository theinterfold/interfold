#!/usr/bin/env bash
# `./test.sh` runs the v2 scenario (v2.sh; its header lists the variants). `./test.sh prebuild`
# builds the fixtures that CI's proof jobs download.
set -eu

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-v2}" in
  v2) exec "$THIS_DIR/v2.sh" ;;
  prebuild) exec "$THIS_DIR/lib/prebuild.sh" ;;
  *)
    echo "Usage: ./test.sh [v2|prebuild]" >&2
    exit 1
    ;;
esac
