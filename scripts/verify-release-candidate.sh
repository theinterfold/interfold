#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
    printf 'usage: %s <tag-ref> <protected-ref> <expected-ref>\n' "$0" >&2
    exit 2
fi

TAG_REF=$1
PROTECTED_REF=$2
EXPECTED_REF=$3

fail() {
    printf 'release candidate verification failed: %s\n' "$1" >&2
    exit 1
}

resolve_commit() {
    local ref=$1
    git rev-parse --verify "${ref}^{commit}" 2>/dev/null \
        || fail "cannot resolve $ref to a commit"
}

TAG_COMMIT=$(resolve_commit "$TAG_REF")
PROTECTED_COMMIT=$(resolve_commit "$PROTECTED_REF")
EXPECTED_COMMIT=$(resolve_commit "$EXPECTED_REF")

[[ "$TAG_COMMIT" == "$EXPECTED_COMMIT" ]] \
    || fail "tag $TAG_REF resolves to $TAG_COMMIT, not tested commit $EXPECTED_COMMIT"

git merge-base --is-ancestor "$TAG_COMMIT" "$PROTECTED_COMMIT" \
    || fail "tag commit $TAG_COMMIT is not an ancestor of protected ref $PROTECTED_REF"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'candidate_sha=%s\n' "$TAG_COMMIT" >> "$GITHUB_OUTPUT"
fi

printf 'verified release candidate %s at %s on protected history %s\n' \
    "$TAG_REF" "$TAG_COMMIT" "$PROTECTED_REF"
