#!/usr/bin/env bash

# This script updates all cargo imports from our git monorepo.
# Some of the time we create user facing (mainly) cargo projects that need to depend on a specific branch or git revision to stay in sync.
# This script will go through the monorepo and update the rev key of any imports extracted as a cargo dependency.
GITHUB_REPO_URL="https://github.com/gnosisguild/interfold"
EXCLUDE_PATHS=(
    "*/.interfold/caches/*"
    "*/target/*"
    "*/node_modules/*"
    "*/risc0-ethereum/*"
)

# Build exclude arguments
EXCLUDE_ARGS=()
for path in "${EXCLUDE_PATHS[@]}"; do
    EXCLUDE_ARGS+=(-not -path "$path")
done
CURRENT_HASH=$(git rev-parse HEAD)
echo "Current git hash: $CURRENT_HASH"
echo "Target repository: $GITHUB_REPO_URL"
echo
# Find and display all matches
echo "Found the following dependencies to update:"
find . -name "Cargo.toml" "${EXCLUDE_ARGS[@]}" -exec grep -l "git = \"$GITHUB_REPO_URL" {} \; | while read -r file; do
   echo "File: $file"
   grep -n "git = \"$GITHUB_REPO_URL\|rev = \"" "$file" | grep -E "(git = \"$GITHUB_REPO_URL|rev = \")" | while read -r line; do
       echo "  $line"
   done
   echo
done
echo "Press any key to continue with the update, or Ctrl+C to cancel..."
read -n 1 -s
echo "Updating dependencies..."
# Perform the substitution
find . -name "Cargo.toml" "${EXCLUDE_ARGS[@]}" -exec sed -i "s|rev = \"[^\"]*\"|rev = \"$CURRENT_HASH\"|g" {} \;
echo "Done!"
