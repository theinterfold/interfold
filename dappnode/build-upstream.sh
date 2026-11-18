#!/bin/bash
# Build the package's upstream image from this checkout without publishing it.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UPSTREAM_VERSION=$(node -p "require('$ROOT_DIR/dappnode/dappnode_package.json').upstreamVersion")
WORKSPACE_VERSION=$(node -p "require('$ROOT_DIR/package.json').version")
if [ "$UPSTREAM_VERSION" != "$WORKSPACE_VERSION" ]; then
    printf 'Cannot build upstream %s from workspace %s; use a matching checkout or the published image.\n' \
        "$UPSTREAM_VERSION" "$WORKSPACE_VERSION" >&2
    exit 1
fi
REVISION=$(git -C "$ROOT_DIR" rev-parse --short=9 HEAD)
BUILDER_NAME="${BUILDX_BUILDER:-$(docker context show)}"
if ! git -C "$ROOT_DIR" diff --quiet HEAD; then
    REVISION="$REVISION-dirty"
fi

# The Docker driver shares its image store with the SDK's subsequent package build.
docker buildx build \
    --builder "$BUILDER_NAME" \
    --platform linux/amd64 \
    --load \
    --file "$ROOT_DIR/crates/Dockerfile" \
    --build-arg "GIT_SHA=$REVISION" \
    --build-arg "E3_CIRCUITS_ARCHIVE_SHA256=${E3_CIRCUITS_ARCHIVE_SHA256:-}" \
    --tag "ghcr.io/theinterfold/ciphernode:$UPSTREAM_VERSION" \
    "$ROOT_DIR"
