#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERIFY="$ROOT_DIR/scripts/verify-release-candidate.sh"
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fail() {
    printf 'release candidate ancestry regression failed: %s\n' "$1" >&2
    exit 1
}

git -C "$FIXTURE_DIR" init --quiet --initial-branch=main
git -C "$FIXTURE_DIR" config user.name 'Release Test'
git -C "$FIXTURE_DIR" config user.email 'release-test@example.invalid'

printf 'candidate\n' > "$FIXTURE_DIR/artifact"
git -C "$FIXTURE_DIR" add artifact
git -C "$FIXTURE_DIR" commit --quiet -m candidate
CANDIDATE_SHA=$(git -C "$FIXTURE_DIR" rev-parse HEAD)
git -C "$FIXTURE_DIR" tag --annotate v1.0.0 --message v1.0.0 "$CANDIDATE_SHA"

printf 'main advanced\n' >> "$FIXTURE_DIR/artifact"
git -C "$FIXTURE_DIR" commit --quiet -am 'advance protected branch'

OUTPUT_FILE="$FIXTURE_DIR/github-output"
(
    cd "$FIXTURE_DIR"
    GITHUB_OUTPUT="$OUTPUT_FILE" "$VERIFY" v1.0.0 main "$CANDIDATE_SHA"
)
grep -Fxq "candidate_sha=$CANDIDATE_SHA" "$OUTPUT_FILE" \
    || fail 'verified candidate SHA was not written to GITHUB_OUTPUT'

if (
    cd "$FIXTURE_DIR"
    "$VERIFY" v1.0.0 main main
) 2>/dev/null; then
    fail 'tag was accepted when it did not equal the expected tested commit'
fi

TREE=$(git -C "$FIXTURE_DIR" rev-parse "$CANDIDATE_SHA^{tree}")
DIVERGENT_SHA=$(printf 'divergent candidate\n' | git -C "$FIXTURE_DIR" commit-tree "$TREE")
git -C "$FIXTURE_DIR" tag v2.0.0 "$DIVERGENT_SHA"
if (
    cd "$FIXTURE_DIR"
    "$VERIFY" v2.0.0 main "$DIVERGENT_SHA"
) 2>/dev/null; then
    fail 'divergent tag was accepted outside protected history'
fi

printf 'release candidate ancestry regression passed\n'
