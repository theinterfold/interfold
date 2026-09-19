#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Guards the agent/ harness docs against drift: if a branch changes protocol-bearing
# code (contracts, circuits, or core crates) without touching agent/, the push is
# rejected. agent/RULES.md requires flow-trace and invariant docs to be updated in the
# same PR as the change they describe.
#
# Escape hatches:
#   - include "[skip-doc-sync]" in the commit that contains a non-behavioral change, or
#   - set SKIP_DOC_SYNC=1
# for changes that genuinely do not alter documented behavior (pure refactors,
# test-only changes, dependency bumps).
#
# Run from .husky/pre-push. Exit 0 when consistent or not applicable, 1 on drift.

set -euo pipefail

if [[ "${SKIP_DOC_SYNC:-0}" == "1" ]]; then
  echo "check-doc-sync: skipped via SKIP_DOC_SYNC=1"
  exit 0
fi

# Paths whose changes are expected to be reflected in agent/ docs. Mirrors the
# "When to update" table in agent/RULES.md and the flow-trace area mapping.
WATCHED_REGEX='^(packages/interfold-contracts/(contracts|scripts|tasks)/|circuits/(lib|bin)/|crates/(aggregator|bfv-client|ciphernode-builder|cli|committee-hash|compute-provider|config|crypto|daemon-server|data|entrypoint|events|evm|evm-helpers|fhe|fhe-params|fs|indexer|keyshare|multithread|net|parity-matrix|polynomial|program-server|request|safe|slashing|sortition|sync|trbfv|zk-helpers|zk-prover)/src/)'
DOCS_REGEX='^agent/(RULES|CONTEXT|ARCHITECTURE|CRATES_ARCHITECTURE)\.md$|^agent/invariants/|^agent/flow-trace/'

base_ref="${DOC_SYNC_BASE_REF:-origin/main}"
base="$(git merge-base "$base_ref" HEAD 2>/dev/null || true)"
if [[ -z "$base" ]]; then
  if [[ "${CI:-false}" == "true" ]]; then
    echo "check-doc-sync: FAILED — cannot resolve merge-base for $base_ref" >&2
    exit 1
  fi
  echo "check-doc-sync: skipped because $base_ref is unavailable"
  exit 0
fi

head="$(git rev-parse HEAD)"
if [[ "$base" == "$head" ]]; then
  # Nothing ahead of origin/main.
  exit 0
fi

changed="$(git diff --name-only "$base" "$head")"

watched_hits="$(grep -E "$WATCHED_REGEX" <<<"$changed" || true)"
doc_hits="$(grep -E "$DOCS_REGEX" <<<"$changed" || true)"

if [[ -z "$watched_hits" ]]; then
  exit 0
fi

# A skip tag applies only to the commit that contains it. An old skip tag must not
# exempt later protocol-bearing commits.
unskipped_watched=""
while IFS= read -r commit; do
  if git log -1 --format=%B "$commit" | grep -qF '[skip-doc-sync]'; then
    continue
  fi
  parent_count="$(git rev-list --parents -n 1 "$commit" | awk '{ print NF - 1 }')"
  if ((parent_count > 1)); then
    # A normal diff-tree invocation emits no paths for merge commits. Combined diff
    # catches conflict-resolution changes that exist in neither parent.
    commit_hits="$(git diff-tree --cc --no-commit-id --name-only -r "$commit" | grep -E "$WATCHED_REGEX" || true)"
  else
    commit_hits="$(git diff-tree --no-commit-id --name-only -r "$commit" | grep -E "$WATCHED_REGEX" || true)"
  fi
  if [[ -n "$commit_hits" ]]; then
    unskipped_watched+="${unskipped_watched:+$'\n'}$commit_hits"
  fi
done < <(git rev-list --reverse "$base..$head")

if [[ -z "$unskipped_watched" ]]; then
  echo "check-doc-sync: skipped watched changes via commit-local [skip-doc-sync] tags"
  exit 0
fi

if [[ -n "$doc_hits" ]]; then
  exit 0
fi

unskipped_watched="$(sort -u <<<"$unskipped_watched")"

# A formatter reflow cannot change behavior, so it must not demand an agent/ doc
# update. Every remaining watched path is tested for formatting equivalence, and
# the gate only stands down when ALL of them are equivalent — one behavioral file
# re-arms it for the whole branch.
#
# Every failure mode here (missing formatter, unknown extension, added or deleted
# file, too many paths to check) falls through to "behavioral". The gate staying
# armed costs a commit-message tag, whereas a wrong exemption silently drops the
# protocol-doc requirement.

# Upper bound on formatter invocations. A branch touching more watched files than
# this is not a formatting pass, and running prettier twice per file would stall
# the pre-push hook.
MAX_FORMAT_PROBE_PATHS=40

# Reproduce a blob through the repository's own formatter. Emits nothing and
# returns non-zero when the file type has no configured formatter.
normalize_blob() {
  local spec="$1" path="$2"
  case "${path##*.}" in
    rs)
      command -v rustfmt >/dev/null 2>&1 || return 1
      git show "$spec" 2>/dev/null | rustfmt --emit stdout --quiet 2>/dev/null
      ;;
    sol | ts | tsx | js | jsx | mjs | cjs | json | md | mdx | yml | yaml | css)
      # --stdin-filepath makes prettier resolve the parser and .prettierrc
      # overrides exactly as it would for the file on disk.
      git show "$spec" 2>/dev/null | npx --no-install prettier --stdin-filepath "$path" 2>/dev/null
      ;;
    *) return 1 ;;
  esac
}

# True when base..head changed only the formatting of "$path".
format_only() {
  local path="$1"

  # An added or removed watched file is a structural change, never a reflow.
  git cat-file -e "$base:$path" 2>/dev/null || return 1
  git cat-file -e "$head:$path" 2>/dev/null || return 1

  # Cheap pre-filter: when the two versions differ after removing all whitespace,
  # the change is behavioral and prettier does not need to run. This is a reject
  # test only. It is never used to grant an exemption, because deleting whitespace
  # also equates distinct string literals.
  local base_stripped head_stripped
  base_stripped="$(git show "$base:$path" | tr -d '[:space:]')"
  head_stripped="$(git show "$head:$path" | tr -d '[:space:]')"
  [[ "$base_stripped" == "$head_stripped" ]] || return 1

  local base_fmt head_fmt
  base_fmt="$(normalize_blob "$base:$path" "$path")" || return 1
  head_fmt="$(normalize_blob "$head:$path" "$path")" || return 1
  [[ -n "$base_fmt" ]] || return 1

  [[ "$base_fmt" == "$head_fmt" ]]
}

behavioral_watched=""
formatting_watched=""
path_count="$(grep -c . <<<"$unskipped_watched" || true)"

if ((path_count > MAX_FORMAT_PROBE_PATHS)); then
  behavioral_watched="$unskipped_watched"
else
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    if format_only "$path"; then
      formatting_watched+="${formatting_watched:+$'\n'}$path"
    else
      behavioral_watched+="${behavioral_watched:+$'\n'}$path"
    fi
  done <<<"$unskipped_watched"
fi

if [[ -z "$behavioral_watched" && -n "$formatting_watched" ]]; then
  echo "check-doc-sync: watched changes are formatting-only, no agent/ update required"
  while IFS= read -r path; do
    echo "  - $path"
  done <<<"$formatting_watched"
  exit 0
fi

if [[ -n "$formatting_watched" ]]; then
  echo "check-doc-sync: ignoring formatting-only changes:"
  while IFS= read -r path; do
    echo "  - $path"
  done <<<"$formatting_watched"
  echo
fi

unskipped_watched="$behavioral_watched"

echo "check-doc-sync: FAILED"
echo
echo "This branch changes protocol-bearing code but no file under agent/ was updated:"
echo
while IFS= read -r path; do
  echo "  - $path"
done <<<"$unskipped_watched"
echo
echo "agent/RULES.md requires harness docs (flow-trace, agent/invariants/, architecture docs)"
echo "to be updated in the same PR as the change they describe. Either:"
echo
echo "  1. update the relevant agent/ doc (start from agent/flow-trace/00_INDEX.md), or"
echo "  2. if no documented behavior changed, add \"[skip-doc-sync]\" to a commit message"
echo "     or re-run with SKIP_DOC_SYNC=1."
exit 1
