#!/usr/bin/env bash
set -euo pipefail

cd circuits/lib
nargo test

cd ../bin/recursive_aggregation/dkg_aggregator
nargo test

echo "Noir circuits tested successfully"
