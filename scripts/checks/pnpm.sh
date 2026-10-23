#!/usr/bin/env bash

# We were having issues with differences in pnpm-lock so this script just ensures that everyone's
# pnpm version matches the corepack suggested version in package.json

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Extract version from packageManager field (before the + sign)
expected=$(node -p "require('./package.json').packageManager?.split('@')[1]?.split('+')[0] || ''"  )
actual=$(pnpm --version)

if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
  echo "❌ pnpm version mismatch!"
  echo "   Expected: $expected"
  echo "   Actual:   $actual"
  echo ""
  echo "To fix this, run:"
  echo "   corepack install"
  echo ""
  echo "If that doesn't work, try:"
  echo "   corepack enable"
  echo "   corepack install"
  exit 1
fi

echo "✅ pnpm version matches: $actual"
