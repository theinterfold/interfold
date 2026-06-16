#!/bin/bash
set -e

while [[ $# -gt 0 ]]; do
  case $1 in
    --pinata-jwt)
      export PINATA_JWT="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

PROGRAM_PATH="./target/riscv-guest/methods/guests/riscv32im-risc0-zkvm-elf/release/program.bin"

HASH_FILE="./target/.program_hash"
URL_FILE="./target/.program_url"

if [ ! -f "$PROGRAM_PATH" ]; then
    echo "Error: Program not found at $PROGRAM_PATH"
    echo "Run: interfold program compile"
    exit 1
fi

if [ -z "$PINATA_JWT" ]; then
    echo "Error: PINATA_JWT environment variable not set"
    echo ""
    echo "Please set your Pinata JWT token:"
    echo "  export PINATA_JWT=\"your_jwt_token\""
    echo ""
    echo "Get your JWT from: https://pinata.cloud"
    exit 1
fi

CURRENT_HASH=$(sha256sum "$PROGRAM_PATH" | awk '{print $1}')
HASH_PREFIX="${CURRENT_HASH:0:8}"
TIMESTAMP=$(date +%s)
FILE_SIZE=$(stat -f%z "$PROGRAM_PATH" 2>/dev/null || stat -c%s "$PROGRAM_PATH" 2>/dev/null || du -b "$PROGRAM_PATH" | awk '{print $1}')
FILE_SIZE_MB=$((FILE_SIZE / 1024 / 1024))
FILE_SIZE_KB=$((FILE_SIZE / 1024))
MODIFIED_TIME=$(stat -f%Sm "$PROGRAM_PATH" 2>/dev/null || stat -c%y "$PROGRAM_PATH" 2>/dev/null || date -r "$PROGRAM_PATH" 2>/dev/null || echo "unknown")

FILENAME="program-${HASH_PREFIX}-${TIMESTAMP}.bin"

echo "=========================================="
echo "Program Upload Metadata"
echo "=========================================="
echo "File path:     $PROGRAM_PATH"
echo "File size:     $FILE_SIZE bytes (${FILE_SIZE_MB} MB / ${FILE_SIZE_KB} KB)"
echo "SHA256 hash:   $CURRENT_HASH"
echo "Modified:      $MODIFIED_TIME"
echo "Upload name:   $FILENAME"
echo "=========================================="
echo ""

if [ -f "$HASH_FILE" ] && [ -f "$URL_FILE" ]; then
    STORED_HASH=$(cat "$HASH_FILE")
    if [ "$CURRENT_HASH" = "$STORED_HASH" ]; then
        echo "Program unchanged (hash matches). Existing URL:"
        cat "$URL_FILE"
        exit 0
    else
        echo "Program changed (hash differs). Uploading new version..."
        echo "  Old hash: $STORED_HASH"
        echo "  New hash: $CURRENT_HASH"
        echo ""
    fi
fi

echo "Uploading program to Pinata as '$FILENAME'..."

RESPONSE=$(curl -s -X POST "https://api.pinata.cloud/pinning/pinFileToIPFS" \
    -H "Authorization: Bearer $PINATA_JWT" \
    -F "file=@$PROGRAM_PATH;filename=$FILENAME")

CID=$(echo "$RESPONSE" | grep -o '"IpfsHash":"[^"]*' | cut -d'"' -f4)

if [ -z "$CID" ]; then
    echo "Upload failed:"
    echo "$RESPONSE"
    exit 1
fi

# Save
PROGRAM_URL="https://gateway.pinata.cloud/ipfs/$CID"
echo "$CURRENT_HASH" > "$HASH_FILE"
echo "$PROGRAM_URL" > "$URL_FILE"

echo ""
echo "✅ Upload successful!"
echo ""
echo "=========================================="
echo "Upload Confirmation"
echo "=========================================="
echo "IPFS CID:      $CID"
echo "Program URL:   $PROGRAM_URL"
echo "SHA256 hash:   $CURRENT_HASH"
echo "File size:     $FILE_SIZE bytes (${FILE_SIZE_MB} MB / ${FILE_SIZE_KB} KB)"
echo "Upload name:   $FILENAME"
echo "=========================================="
echo ""
echo "The URL has been saved to .program_url"
echo ""
echo "To use this in production, add to your interfold.config.yaml:"
echo ""
echo "program:"
echo "  risc0:"
echo "    risc0_dev_mode: 0"
echo "    boundless:"
echo "      rpc_url: \"https://sepolia.infura.io/v3/YOUR_KEY\""
echo "      private_key: \"\${PRIVATE_KEY}\""
echo "      pinata_jwt: \"\${PINATA_JWT}\""
echo "      program_url: \"$PROGRAM_URL\""
echo "      onchain: true"