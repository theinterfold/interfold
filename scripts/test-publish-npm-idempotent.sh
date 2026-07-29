#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/interfold-npm-publish.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT

mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/package"
cat > "$TEST_ROOT/package/package.json" <<'JSON'
{
  "name": "@interfold/release-test",
  "version": "1.2.3"
}
JSON

cat > "$TEST_ROOT/bin/npm" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail

case "$1" in
    pack)
        : > release-test-1.2.3.tgz
        printf '[{"filename":"release-test-1.2.3.tgz","integrity":"sha512-candidate"}]\n'
        ;;
    view)
        if [ "$3" = "dist.integrity" ]; then
            [ "${MOCK_REMOTE_MISSING:-0}" != "1" ] || exit 1
            printf '%s\n' "${MOCK_REMOTE_INTEGRITY:-sha512-candidate}"
        else
            printf '%s\n' "${MOCK_TAG_VERSION:-1.2.3}"
        fi
        ;;
    publish)
        : > "$MOCK_PUBLISH_MARKER"
        ;;
    *)
        printf 'unexpected mocked npm command: %s\n' "$*" >&2
        exit 2
        ;;
esac
MOCK
chmod 0755 "$TEST_ROOT/bin/npm"

export PATH="$TEST_ROOT/bin:$PATH"
export MOCK_PUBLISH_MARKER="$TEST_ROOT/published"

"$ROOT_DIR/scripts/publish-npm-idempotent.sh" "$TEST_ROOT/package" latest
[ ! -e "$MOCK_PUBLISH_MARKER" ] || {
    echo 'matching published bytes were uploaded twice' >&2
    exit 1
}

if MOCK_REMOTE_INTEGRITY=sha512-different \
    "$ROOT_DIR/scripts/publish-npm-idempotent.sh" "$TEST_ROOT/package" latest; then
    echo 'mismatched published bytes were accepted' >&2
    exit 1
fi

MOCK_REMOTE_MISSING=1 \
    "$ROOT_DIR/scripts/publish-npm-idempotent.sh" "$TEST_ROOT/package" next
[ -e "$MOCK_PUBLISH_MARKER" ] || {
    echo 'an unpublished package was not uploaded' >&2
    exit 1
}

printf 'idempotent NPM publication recovery passes\n'
