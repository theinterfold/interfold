#!/bin/bash
# Resolve the active committee size (matches the active committee written by
# `pnpm build:circuits --committee <name>`). Reads in priority order:
#
#   1. circuits/bin/.active-preset.json::committee  (canonical, written by build-circuits)
#   2. circuits/lib/src/configs/committee/active.nr (fallback for stamp-less builds)
#   3. "minimum" (final fallback so a fresh clone has sane defaults)
#
# Sets: COMMITTEE_NAME, COMMITTEE_N, COMMITTEE_T, COMMITTEE_H

_load_committee_nt_h() {
    local repo_root="$1"
    local committee_file="${repo_root}/circuits/lib/src/configs/committee/${COMMITTEE_NAME}/mod.nr"
    if [ ! -f "$committee_file" ]; then
        echo "Error: committee config not found: $committee_file" >&2
        return 1
    fi

    COMMITTEE_N=$(rg -N "N_PARTIES: u32 = " "$committee_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -1)
    COMMITTEE_T=$(rg -N "T: u32 = " "$committee_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -1)
    COMMITTEE_H=$(rg -N "H: u32 = " "$committee_file" | sed -E 's/.*= ([0-9]+);/\1/' | head -1)

    if [ -z "$COMMITTEE_N" ] || [ -z "$COMMITTEE_T" ] || [ -z "$COMMITTEE_H" ]; then
        echo "Error: failed to parse N/T/H from $committee_file" >&2
        return 1
    fi

    export COMMITTEE_NAME COMMITTEE_N COMMITTEE_T COMMITTEE_H
}

# Load N/T/H for an explicit committee name (independent of on-disk active selection).
load_committee_by_name() {
    local name="$1"
    local repo_root="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
    COMMITTEE_NAME="$name"
    _load_committee_nt_h "$repo_root"
}

load_default_committee() {
    # First positional arg is legacy (path to default/mod.nr) and is ignored — committee is
    # now plumbed through active.nr / the stamp, not default/mod.nr. Kept so existing callers
    # don't break.
    local _legacy_default_mod="${1:-}"
    local repo_root="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

    local stamp="${repo_root}/circuits/bin/.active-preset.json"
    local active_nr="${repo_root}/circuits/lib/src/configs/committee/active.nr"

    COMMITTEE_NAME=""
    if [ -f "$stamp" ]; then
        COMMITTEE_NAME=$(python3 - "$stamp" <<'PY'
import json, sys
try:
    v = json.load(open(sys.argv[1]))
    print(v.get("committee") or "")
except Exception:
    print("")
PY
)
    fi
    if [ -z "$COMMITTEE_NAME" ] && [ -f "$active_nr" ]; then
        COMMITTEE_NAME=$(python3 - "$active_nr" <<'PY'
import re, sys
try:
    txt = open(sys.argv[1], encoding="utf-8").read()
except Exception:
    print("")
    raise SystemExit(0)
m = re.search(r"crate::configs::committee::([a-zA-Z0-9_]+)::N_PARTIES", txt)
print(m.group(1) if m else "")
PY
)
    fi
    [ -z "$COMMITTEE_NAME" ] && COMMITTEE_NAME="minimum"

    _load_committee_nt_h "$repo_root"
}
