#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RELEASE_WORKFLOW="$ROOT_DIR/.github/workflows/releases.yml"

fail() {
    printf 'release reproducibility check failed: %s\n' "$1" >&2
    exit 1
}

for dockerfile in \
    "$ROOT_DIR/crates/Dockerfile" \
    "$ROOT_DIR/crates/support/Dockerfile" \
    "$ROOT_DIR/dappnode/Dockerfile"; do
    while IFS= read -r from; do
        [[ "$from" =~ @sha256:[0-9a-f]{64}([[:space:]]|$) ]] \
            || fail "$dockerfile contains an unpinned base image: $from"
    done < <(grep -E '^FROM ' "$dockerfile")
    grep -Eq 'DEBIAN_SNAPSHOT=[0-9]{8}T[0-9]{6}Z' "$dockerfile" \
        || fail "$dockerfile does not pin Debian package resolution to a snapshot"
    grep -Eq 'DEBIAN_SECURITY_SNAPSHOT=[0-9]{8}T[0-9]{6}Z' "$dockerfile" \
        || fail "$dockerfile does not pin Debian security packages to a snapshot"
    grep -Fq 'archive/debian/${DEBIAN_SNAPSHOT}' "$dockerfile" \
        || fail "$dockerfile does not use its Debian snapshot pin"
    grep -Fq 'archive/debian-security/${DEBIAN_SECURITY_SNAPSHOT}' "$dockerfile" \
        || fail "$dockerfile does not use its Debian security snapshot pin"
done

while IFS= read -r action; do
    [[ "$action" == *"uses: ./"* ]] && continue
    [[ "$action" =~ @[0-9a-f]{40}([[:space:]]|$) ]] \
        || fail "release workflow contains an action not pinned to a commit: $action"
done < <(grep -E '^[[:space:]]*(- )?uses:' "$RELEASE_WORKFLOW")

if grep -Eq 'runs-on: (ubuntu|macos|windows)-latest' "$RELEASE_WORKFLOW"; then
    fail "release workflow uses a mutable latest runner label"
fi

grep -Fq 'pnpm install --frozen-lockfile' "$ROOT_DIR/crates/Dockerfile" \
    || fail "ciphernode image does not enforce pnpm-lock.yaml"
grep -Fq 'sha256sum --check --strict' "$ROOT_DIR/crates/Dockerfile" \
    || fail "ciphernode image does not checksum downloaded solc"
[[ $(grep -Fc 'sha256sum --check --strict' "$ROOT_DIR/crates/support/Dockerfile") -ge 2 ]] \
    || fail "support image does not checksum every downloaded tool archive"
if grep -Eq 'curl[^|]*\|[[:space:]]*(bash|sh)|wget[^|]*\|[[:space:]]*(bash|sh)' \
    "$ROOT_DIR/crates/Dockerfile" "$ROOT_DIR/crates/support/Dockerfile" "$ROOT_DIR/dappnode/Dockerfile"; then
    fail "Docker build executes an unchecked remote installer"
fi
grep -Fq 'sha256sum --check --strict' "$ROOT_DIR/dappnode/Dockerfile" \
    || fail "DAppNode image does not checksum the staged candidate binary"
grep -Fq 'COPY ${UPSTREAM_BINARY_SOURCE} /tmp/interfold.tar.gz' "$ROOT_DIR/dappnode/Dockerfile" \
    || fail "DAppNode image is not built from the staged candidate archive"
grep -Fq 'npm ci --ignore-scripts --prefix dappnode' "$RELEASE_WORKFLOW" \
    || fail "release workflow does not use the locked DAppNode SDK dependency graph"
node -e '
const lock = require(process.argv[1]);
const sdk = lock.packages["node_modules/@dappnode/dappnodesdk"];
if (!sdk || sdk.version !== "0.3.53" || !sdk.integrity) process.exit(1);
' "$ROOT_DIR/dappnode/package-lock.json" \
    || fail "DAppNode SDK version and integrity are not locked"
grep -Eq '^channel = "[0-9]+\.[0-9]+\.[0-9]+"$' "$ROOT_DIR/rust-toolchain.toml" \
    || fail "rust-toolchain.toml is not pinned to an exact patch release"
grep -Fq 'provenance: mode=max' "$RELEASE_WORKFLOW" \
    || fail "container provenance emission is missing"
grep -Fq 'sbom: true' "$RELEASE_WORKFLOW" \
    || fail "container SBOM emission is missing"
grep -Fq 'Compare isolated OCI outputs' "$RELEASE_WORKFLOW" \
    || fail "isolated image reproducibility comparison is missing"
grep -Fq -- '--provenance=false' "$RELEASE_WORKFLOW" \
    || fail "reproducibility comparison includes generated provenance metadata"
grep -Fq -- '--sbom=false' "$RELEASE_WORKFLOW" \
    || fail "reproducibility comparison includes generated SBOM metadata"
grep -Fq 'gzip -n' "$RELEASE_WORKFLOW" \
    || fail "binary archive gzip headers are not normalized"
grep -Eq '^  NPM_VERSION: [0-9]+\.[0-9]+\.[0-9]+$' "$RELEASE_WORKFLOW" \
    || fail "release workflow does not pin the trusted-publishing npm CLI"

printf 'release reproducibility inputs are pinned\n'
