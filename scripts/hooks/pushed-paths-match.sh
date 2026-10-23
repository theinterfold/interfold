#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Usage: pushed-paths-match.sh <filter-file> < <pre-push refs>
#
# Tells the pre-push hook whether a pushed branch changes a path that <filter-file> matches.
# <filter-file> uses the dorny/paths-filter format that CI reads: each `- '<glob>'` line adds a
# pattern, and a `!<glob>` pattern excludes paths. The script compares each pushed branch with its
# merge base with origin/main. Without refs on stdin (a manual run), it compares HEAD.
#
# check:verifiers reads only the checked-out tree, so it covers a pushed branch only when that branch
# matches HEAD in the matching paths.
#
# Exit 0 when a pushed branch changes a matching path and matches HEAD in those paths, and also on
# any error, so that the caller runs its check. Exit 1 when no pushed branch changes a matching path.
# Exit 2 when a pushed branch changes a matching path and differs from HEAD in those paths: the
# caller must stop the push, because its check cannot read that branch.

set -uo pipefail

filter_file="$1"

patterns="$(sed -n "s/^[[:space:]]*- '\([^']*\)'.*/\1/p" "$filter_file")" || exit 0
[[ -n "$patterns" ]] || exit 0

pathspecs=()
while IFS= read -r pattern; do
  case "$pattern" in
    '!'*) pathspecs+=(":(glob,exclude)${pattern#!}") ;;
    *) pathspecs+=(":(glob)$pattern") ;;
  esac
done <<<"$patterns"

head="$(git rev-parse HEAD)" || exit 0
refs="$(cat)"
[[ -n "$refs" ]] || refs="HEAD $head"

match=1
while read -r local_ref local_oid _rest; do
  # Deleting a branch pushes no commits.
  [[ "$local_oid" =~ [^0] ]] || continue
  base="$(git merge-base origin/main "$local_oid" 2>/dev/null)" || exit 0
  changed="$(git diff --name-only "$base" "$local_oid" -- "${pathspecs[@]}")" || exit 0
  [[ -n "$changed" ]] || continue
  git diff --quiet "$head" "$local_oid" -- "${pathspecs[@]}"
  case $? in
    0) ;;
    1)
      echo "pre-push: $local_ref changes a path in $filter_file, but check:verifiers checks only the checked-out tree. Check out $local_ref, then push again." >&2
      exit 2
      ;;
    *) exit 0 ;;
  esac
  match=0
done <<<"$refs"

exit "$match"
