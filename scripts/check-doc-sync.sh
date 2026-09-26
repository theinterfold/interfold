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
# A watched path stands down automatically when the change provably cannot affect a
# documented statement: a pure formatter reflow, or a diff whose changed lines name
# none of the identifiers the agent/ docs actually mention.
#
# Escape hatches for everything else:
#   - include "[skip-doc-sync]" in the commit that contains a non-behavioral change, or
#   - set SKIP_DOC_SYNC=1
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

# Per-commit collection can name a path the branch later reverted. Such a path has no
# net diff against the base, so it cannot contradict a document and must not be cited.
unskipped_watched="$(sort -u <<<"$unskipped_watched" |
  grep -Fxf <(grep -E "$WATCHED_REGEX" <<<"$changed") || true)"

if [[ -z "$unskipped_watched" ]]; then
  echo "check-doc-sync: watched changes are reverted in this branch, no agent/ update required"
  exit 0
fi

# A change that provably cannot invalidate a documented statement must not demand an
# agent/ doc update. Two probes can stand a watched path down:
#
#   1. relevance — no line the branch changed in that path names any identifier the
#      agent/ docs mention, so no documented statement can be about this change;
#   2. formatting — the file is byte-identical after the repository's own formatter.
#
# The gate only stands down when ALL remaining watched paths are exempt — one
# behavioral file re-arms it for the whole branch.
#
# Every failure mode here (empty symbol set, missing formatter, unknown extension,
# added or deleted file, too many paths to check) falls through to "behavioral". The
# gate staying armed costs a commit-message tag, whereas a wrong exemption silently
# drops the protocol-doc requirement.

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
      # The workspace is edition 2021. rustfmt defaults to 2015, where `async fn`
      # and `dyn` do not parse, so every async file would fail the probe.
      git show "$spec" 2>/dev/null | rustfmt --edition 2021 --emit stdout --quiet 2>/dev/null
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

# Identifiers the agent/ docs actually name, harvested from backticked spans at $head.
# Filtered to structurally specific ones — snake_case, path-qualified, dotted or
# slashed names, and any camelCase with an internal capital — at least 5 characters.
# `[a-z][A-Z]` is what keeps Solidity and TypeScript names such as `publishInput`,
# `gracePeriod`, and `committeeHash`, which a multi-capital-only rule silently drops
# and which are exactly the protocol surface this gate exists to watch. Bare words
# like `new`, `data`, or `Err` are backticked in the docs too, but occur in nearly
# every Rust diff, so keeping them would arm the gate unconditionally and make the
# probe worthless.
symbols_file="$(mktemp)"
trap 'rm -f "$symbols_file"' EXIT
git grep -hoE '`[A-Za-z_][A-Za-z0-9_:./-]{2,}`' "$head" -- 'agent/*.md' 2>/dev/null |
  tr -d '`' |
  grep -E '_|::|[a-z][A-Z]|[A-Z][a-z0-9]*[A-Z]|[./]' |
  awk 'length >= 5' |
  sort -u >"$symbols_file" || true

# True when no line base..head changed in "$path", and no enclosing declaration it sits
# in, names a documented identifier. `-U0` hunk headers carry that enclosing
# declaration, which is what catches a body-only edit inside a documented function.
# -w is what keeps `proof_verification` from matching inside `bb_proof_verification`.
undocumented_only() {
  local path="$1"

  # An added or removed watched file is structural, never irrelevant: undocumented
  # new code in a watched crate is precisely what this gate exists to notice.
  git cat-file -e "$base:$path" 2>/dev/null || return 1
  git cat-file -e "$head:$path" 2>/dev/null || return 1

  [[ -s "$symbols_file" ]] || return 1

  local changed
  changed="$(git diff -U0 "$base" "$head" -- "$path" |
    grep -E '^(@@|[+-])' | grep -vE '^(\+\+\+|---)' || true)"
  [[ -n "$changed" ]] || return 1

  ! grep -qwFf "$symbols_file" <<<"$changed"
}

behavioral_watched=""
exempt_watched=""
path_count="$(grep -c . <<<"$unskipped_watched" || true)"

# The relevance probe is two greps per path, so it always runs. The formatter probe
# shells out to rustfmt/prettier twice per path, so it keeps its cap.
probe_formatting=1
if ((path_count > MAX_FORMAT_PROBE_PATHS)); then
  probe_formatting=0
fi

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  if undocumented_only "$path" || { ((probe_formatting)) && format_only "$path"; }; then
    exempt_watched+="${exempt_watched:+$'\n'}$path"
  else
    behavioral_watched+="${behavioral_watched:+$'\n'}$path"
  fi
done <<<"$unskipped_watched"

if [[ -z "$behavioral_watched" && -n "$exempt_watched" ]]; then
  echo "check-doc-sync: watched changes cannot affect documented behavior, no agent/ update required"
  while IFS= read -r path; do
    echo "  - $path"
  done <<<"$exempt_watched"
  exit 0
fi

if [[ -n "$exempt_watched" ]]; then
  echo "check-doc-sync: ignoring changes that name no documented identifier:"
  while IFS= read -r path; do
    echo "  - $path"
  done <<<"$exempt_watched"
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
