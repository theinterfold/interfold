#!/usr/bin/env bash
PKG="${E3_SUPPORT_IMAGE_REPOSITORY:-ghcr.io/theinterfold/e3-support}"
GIT_SHA=$(git rev-parse --short=9 HEAD)

# Separate --push from other arguments
PUSH=false
BUILD_ARGS=()

for arg in "$@"; do
  if [ "$arg" = "--push" ]; then
    PUSH=true
  else
    BUILD_ARGS+=("$arg")
  fi
done

# Build with any additional arguments
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
docker build -t "$PKG:$GIT_SHA" -f "$ROOT/crates/support/Dockerfile" "${BUILD_ARGS[@]}" "$ROOT"

# Push if --push was specified
if [ "$PUSH" = true ]; then
  docker push "$PKG:$GIT_SHA"
  echo "Image pushed to: $PKG:$GIT_SHA"
fi
