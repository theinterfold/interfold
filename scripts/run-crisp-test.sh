#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_STATUS=$(git -C "$REPO_ROOT" status --porcelain)
if [[ -n "$SOURCE_STATUS" ]]; then
  echo "The isolated CRISP test runs HEAD. Commit pending changes or use a clean checkout." >&2
  exit 1
fi
E3_CUSTOM_BB="${E3_CUSTOM_BB:-$(command -v bb)}"
export E3_CUSTOM_BB
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/interfold-crisp-e2e.XXXXXX")
WORKTREE_DIR="$TEST_ROOT/source"
export CARGO_INSTALL_ROOT="$TEST_ROOT/cli"
export PATH="$CARGO_INSTALL_ROOT/bin:$PATH"

cleanup() {
  local status=$?
  if (( status != 0 )); then
    echo "CRISP test failed. Retained checkout and build files: $TEST_ROOT" >&2
    return "$status"
  fi
  git -C "$REPO_ROOT" worktree remove --force "$WORKTREE_DIR"
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$WORKTREE_DIR" HEAD
git -C "$WORKTREE_DIR" submodule update --init --recursive
cd "$WORKTREE_DIR/examples/CRISP"
pnpm dev:setup
pnpm test:e2e "$@"
