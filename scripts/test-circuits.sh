#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for package in circuits/lib circuits/bin/recursive_aggregation/decryption_aggregator; do
  (cd "$REPO_ROOT/$package" && nargo test)
done

echo "Noir library and recursive decryption tests passed"
