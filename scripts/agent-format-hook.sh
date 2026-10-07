#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Claude Code PostToolUse hook: formats a file just edited by an agent. Reads the hook
# JSON payload on stdin and extracts tool_input.file_path. Formatting is best-effort and
# must never block an edit.

set -u
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

file="$(node -e '
let d = "";
process.stdin.on("data", (c) => (d += c)).on("end", () => {
  try {
    process.stdout.write(JSON.parse(d).tool_input.file_path || "");
  } catch {}
});
' 2>/dev/null)"

[[ -z "$file" || ! -f "$file" ]] && exit 0

case "$file" in
  "$repo_root"/*) ;;
  *)
    echo "agent-format-hook: skip file outside the repository: $file" >&2
    exit 0
    ;;
esac

cd "$repo_root" || exit 0

case "$file" in
  *.rs)
    if ! rustfmt --edition 2021 "$file" >/dev/null 2>&1; then
      echo "agent-format-hook: rustfmt failed for $file" >&2
    fi
    ;;
  *.ts | *.tsx | *.js | *.jsx | *.mjs | *.cjs | *.json | *.md | *.mdx | *.yml | *.yaml | *.css | *.sol)
    # The local binary avoids the pnpm startup cost, which every agent edit pays.
    prettier=(pnpm exec prettier)
    [[ -x node_modules/.bin/prettier ]] && prettier=(node_modules/.bin/prettier)
    if ! "${prettier[@]}" --write "$file" >/dev/null 2>&1; then
      echo "agent-format-hook: prettier failed for $file" >&2
    fi
    ;;
esac

exit 0
