#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
    printf 'usage: %s <candidate-archive> <expected-version> <expected-sha256>\n' "$0" >&2
    exit 2
fi

ARCHIVE=$1
EXPECTED_VERSION=$2
EXPECTED_SHA256=$3
VERIFY_TMP=$(mktemp -d)
trap 'rm -rf "$VERIFY_TMP"' EXIT

fail() {
    printf 'DAppNode candidate verification failed: %s\n' "$1" >&2
    exit 1
}

[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'expected SHA-256 is not 64 lowercase hexadecimal characters'
[[ -f "$ARCHIVE" ]] || fail "candidate archive is missing: $ARCHIVE"

printf '%s  %s\n' "$EXPECTED_SHA256" "$ARCHIVE" | sha256sum --check --strict >/dev/null \
    || fail 'candidate archive checksum does not match'
[[ "$(tar -tzf "$ARCHIVE")" == interfold ]] \
    || fail 'candidate archive must contain exactly one root-level interfold binary'

tar -xzf "$ARCHIVE" -C "$VERIFY_TMP" interfold
chmod 0755 "$VERIFY_TMP/interfold"
[[ "$("$VERIFY_TMP/interfold" --version)" == "interfold $EXPECTED_VERSION" ]] \
    || fail "candidate binary does not report interfold $EXPECTED_VERSION"
grep -aFq '/health/ready' "$VERIFY_TMP/interfold" \
    || fail 'candidate binary does not contain the protocol readiness route'
grep -aFq 'interfold_ready' "$VERIFY_TMP/interfold" \
    || fail 'candidate binary does not contain the protocol readiness metric'

printf 'verified DAppNode candidate binary version %s with SHA-256 %s\n' \
    "$EXPECTED_VERSION" "$EXPECTED_SHA256"
