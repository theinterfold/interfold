#!/usr/bin/env bash

echo "This helper script will clean your repository and run end-to-end tests for CRISP."
echo "WARNING: This will reset your current workspace. Ensure all changes are committed before proceeding."
echo "Press any key to continue or Ctrl+C to cancel..."

read

# Use the locally installed bb
export E3_CUSTOM_BB=$(which bb)

echo "Resetting installed interfold"
rm -rf ~/.cargo/bin/interfold

rm -rf * && \
  git reset --hard HEAD && \
  git submodule update --init --recursive && \
  cd examples/CRISP && \
  pnpm dev:setup && \
  pnpm test:e2e "$@"
