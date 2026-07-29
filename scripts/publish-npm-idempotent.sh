#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <package-directory> <dist-tag>" >&2
    exit 2
fi

package_dir=$1
dist_tag=$2

case "$dist_tag" in
    latest|next) ;;
    *)
        echo "refusing unsupported release dist-tag: $dist_tag" >&2
        exit 2
        ;;
esac

cd "$package_dir"

metadata_file=$(mktemp)
archive=''
cleanup() {
    rm -f -- "$metadata_file"
    if [ -n "$archive" ]; then
        rm -f -- "$archive"
    fi
}
trap cleanup EXIT

npm pack --json > "$metadata_file"
archive=$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))[0].filename" "$metadata_file")
local_integrity=$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))[0].integrity" "$metadata_file")
package_name=$(node -p "require('./package.json').name")
package_version=$(node -p "require('./package.json').version")
package_spec="${package_name}@${package_version}"

if remote_integrity=$(npm view "$package_spec" dist.integrity 2>/dev/null); then
    if [ "$remote_integrity" != "$local_integrity" ]; then
        echo "published $package_spec has integrity $remote_integrity, expected $local_integrity" >&2
        exit 1
    fi
    tagged_version=$(npm view "${package_name}@${dist_tag}" version 2>/dev/null || true)
    if [ "$tagged_version" != "$package_version" ]; then
        echo "$package_spec exists, but dist-tag $dist_tag does not select it; refusing an ambiguous recovery" >&2
        exit 1
    fi
    echo "$package_spec is already published with the candidate integrity; continuing"
    exit 0
fi

npm publish "./$archive" --access public --tag "$dist_tag" --provenance
