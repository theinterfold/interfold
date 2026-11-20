#!/usr/bin/env bash
set -euo pipefail

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
for shape in vector vector-micro vector-secure-moduli; do
  cargo run --locked -p e3-zk-samples --example sync_prf -- "$shape" "$scratch/$shape"
  (
    cd "$scratch/$shape"
    for input in v*-owner*.toml; do
      echo "Checking native mask: $shape/$input"
      nargo execute -p "${input%.toml}"
    done
  )
done
