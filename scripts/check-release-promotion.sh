#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CI_WORKFLOW="$ROOT_DIR/.github/workflows/ci.yml"
RELEASE_WORKFLOW="$ROOT_DIR/.github/workflows/releases.yml"

fail() {
    printf 'release promotion check failed: %s\n' "$1" >&2
    exit 1
}

grep -Fq 'workflow_call:' "$CI_WORKFLOW" \
    || fail 'CI cannot be called by the release candidate workflow'
grep -Fq "FORCE=\"\${{ github.event_name == 'workflow_dispatch' || inputs.release_candidate }}\"" \
    "$CI_WORKFLOW" \
    || fail 'release candidate CI does not force every path-filtered job'
grep -Fq 'uses: ./.github/workflows/ci.yml' "$RELEASE_WORKFLOW" \
    || fail 'release does not validate its exact candidate through CI'
grep -Fq 'release_candidate: true' "$RELEASE_WORKFLOW" \
    || fail 'release does not force the complete candidate CI suite'
grep -Fq './scripts/verify-release-candidate.sh' "$RELEASE_WORKFLOW" \
    || fail 'release tag is not verified against the protected candidate history'
grep -Fq 'candidate_sha: ${{ steps.verify_candidate.outputs.candidate_sha }}' "$RELEASE_WORKFLOW" \
    || fail 'verified candidate commit is not exported to release jobs'
grep -Fq 'group: release-promotion-${{ github.repository }}' "$RELEASE_WORKFLOW" \
    || fail 'release promotions are not serialized'
grep -Fq 'environment: release' "$RELEASE_WORKFLOW" \
    || fail 'registry publication is not protected by the release environment'

if grep -Fq 'continue-on-error: true' "$RELEASE_WORKFLOW"; then
    fail 'a release job is allowed to fail without failing the candidate'
fi

for publisher in \
    build-ciphernode-image-release \
    build-e3-support-release \
    publish-rust-crates \
    publish-npm-packages; do
    job=$(sed -n "/^  ${publisher}:/,/^  [a-zA-Z0-9_-]*:/p" "$RELEASE_WORKFLOW")
    grep -Fq 'release-candidate-gate' <<< "$job" \
        || fail "$publisher can run before the candidate gate"
done

grep -Fq 'candidate-ci,' "$RELEASE_WORKFLOW" \
    || fail 'candidate artifact jobs do not depend on exact candidate CI'
grep -Fq 'Required circuit-artifacts branch is missing' "$RELEASE_WORKFLOW" \
    || fail 'missing release circuits do not fail closed'
grep -Fq 'cargo workspaces publish --from-git --dry-run --yes' "$RELEASE_WORKFLOW" \
    || fail 'Rust packages are not dry-run before release approval'
grep -Fq 'npm publish --dry-run --access public' "$RELEASE_WORKFLOW" \
    || fail 'NPM packages are not dry-run before release approval'
grep -Fq 'build-dappnode-candidate,' "$RELEASE_WORKFLOW" \
    || fail 'protected approval does not require the exact-candidate DAppNode build'
grep -Fq './dappnode/verify-candidate-binary.sh' "$RELEASE_WORKFLOW" \
    || fail 'DAppNode does not verify the exact release candidate binary'
grep -Fq 'dappnodesdk build --skip-save' "$RELEASE_WORKFLOW" \
    || fail 'DAppNode candidate is not built before release approval'
grep -Fq 'cargo workspaces publish --from-git --skip-published --yes' "$RELEASE_WORKFLOW" \
    || fail 'Rust publication cannot roll forward after a partial registry attempt'
grep -Fq './scripts/publish-npm-idempotent.sh' "$RELEASE_WORKFLOW" \
    || fail 'NPM publication cannot verify and resume an existing version'
grep -Fq 'publication-gate,' "$RELEASE_WORKFLOW" \
    || fail 'GitHub release creation does not require the publication gate'
grep -Fq 'At least one required registry publication did not succeed' "$RELEASE_WORKFLOW" \
    || fail 'publication gate does not fail on a partial registry result'
[ -x "$ROOT_DIR/scripts/publish-npm-idempotent.sh" ] \
    || fail 'NPM roll-forward helper is not executable'
[ -x "$ROOT_DIR/scripts/test-publish-npm-idempotent.sh" ] \
    || fail 'NPM publication recovery regression is not executable'
[ -x "$ROOT_DIR/scripts/verify-release-candidate.sh" ] \
    || fail 'release candidate ancestry verifier is not executable'
[ -x "$ROOT_DIR/scripts/test-release-candidate-ancestry.sh" ] \
    || fail 'release candidate ancestry regression is not executable'
[ -x "$ROOT_DIR/dappnode/verify-candidate-binary.sh" ] \
    || fail 'DAppNode candidate verifier is not executable'
grep -Fq 'release-assets/release-provenance.json' "$RELEASE_WORKFLOW" \
    || fail 'release assets do not record the verified candidate commit'
grep -Fq 'REMOTE_STABLE=$(git ls-remote origin refs/tags/stable' "$RELEASE_WORKFLOW" \
    || fail 'stable tag promotion does not verify its remote candidate target'

printf 'release candidate and publication gates are fail closed\n'
