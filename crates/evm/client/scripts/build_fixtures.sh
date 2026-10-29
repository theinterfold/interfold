#!/usr/bin/env bash
set -e

echo "Building fixtures for all Solidity files..."

# Folder containing the .sol files
SOLIDITY_DIR="tests/fixtures"

# For each .sol file in the directory
for solidity_file in "$SOLIDITY_DIR"/*.sol; do
    # Extract just the filename without path or extension
    filename=$(basename "$solidity_file" .sol)
    
    echo "Processing $filename.sol..."
    
    # Create the JSON file with ABI and bytecode
    echo "{\"abi\": $(solc --abi "$solidity_file" | tail -n 1), \"bin\": \"$(solc --bin "$solidity_file" | tail -n 1)\"}" | jq '.' > "$SOLIDITY_DIR/$filename.json"
    
    echo "Created $filename.json"
done

echo "All fixtures built successfully."
