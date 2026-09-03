#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# ckks-timing-report.sh — grep the `ckks_timing` instrumentation emitted by
# the ciphernodes (crates/keyshare/src/threshold_keyshare_ckks/timing.rs)
# into a per-phase table.
#
# Usage:
#   scripts/ckks-timing-report.sh <log> [<log> ...]
#
# Accepts either the nodes' operational JSONL logs
# (`<data_dir>/<node>/ciphernode.jsonl`, one JSON object per line with
# target == "ckks_timing") or a captured console log (lines containing
# `ckks_timing` with `key=value` fields). Multiple files are merged.
#
# Output: one row per (phase, level) with the number of nodes reporting it,
# min/median/max of `t_ms` (ms since CiphernodeSelected or restart) and of
# `dur_ms` (compute wall time, spans only), plus per-node totals.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <log> [<log> ...]" >&2
  exit 2
fi

python3 - "$@" <<'PY'
import json, re, sys, statistics
from collections import defaultdict

KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
rows = []  # dicts with node, e3, party, phase, level, t_ms, dt_ms, dur_ms, bytes, count

def add(node, fields):
    if "phase" not in fields:
        return
    def num(k):
        v = fields.get(k)
        if v in (None, "", "None"):
            return None
        try:
            return float(str(v).strip('"'))
        except ValueError:
            return None
    rows.append({
        "node": node or fields.get("party", "?"),
        "e3": str(fields.get("e3", "?")).strip('"'),
        "party": fields.get("party"),
        "phase": str(fields["phase"]).strip('"'),
        "level": num("level"),
        "t_ms": num("t_ms"),
        "dt_ms": num("dt_ms"),
        "dur_ms": num("dur_ms"),
        "bytes": num("bytes"),
        "count": num("count"),
    })

for path in sys.argv[1:]:
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if "ckks_timing" not in line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("target") != "ckks_timing":
                    continue
                fields = dict(obj.get("fields") or {})
                add(obj.get("node"), fields)
            else:
                fields = {k: v for k, v in KV.findall(line)}
                m = re.match(r"\[(\w+)\]", line)
                add(m.group(1) if m else None, fields)

if not rows:
    print("no ckks_timing lines found", file=sys.stderr)
    sys.exit(1)

def fmt(v):
    return "-" if v is None else (f"{v:.0f}" if v >= 10 else f"{v:.1f}")

def stats(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return ("-", "-", "-")
    return (fmt(min(vals)), fmt(statistics.median(vals)), fmt(max(vals)))

by_phase = defaultdict(list)
for r in rows:
    by_phase[(r["phase"], r["level"])].append(r)

# Order phases by their median t_ms so the table reads as a timeline.
def med_t(rs):
    ts = [r["t_ms"] for r in rs if r["t_ms"] is not None]
    return statistics.median(ts) if ts else float("inf")
keys = sorted(by_phase, key=lambda k: (med_t(by_phase[k]), k[0], k[1] or -1))

e3s = sorted({r["e3"] for r in rows})
nodes = sorted({str(r["node"]) for r in rows})
print(f"ckks_timing report — e3={','.join(e3s)} nodes={','.join(nodes)} events={len(rows)}")
print()
hdr = f"{'phase':36} {'lvl':>4} {'n':>2} | {'t_ms min':>9} {'median':>9} {'max':>9} | {'dur_ms min':>10} {'median':>9} {'max':>9} | {'bytes':>10}"
print(hdr)
print("-" * len(hdr))
for phase, level in keys:
    rs = by_phase[(phase, level)]
    tmin, tmed, tmax = stats([r["t_ms"] for r in rs])
    dmin, dmed, dmax = stats([r["dur_ms"] for r in rs])
    b = [r["bytes"] for r in rs if r["bytes"] is not None]
    bytes_s = fmt(max(b)) if b else "-"
    lvl = "-" if level is None else f"{int(level)}"
    n = len({str(r['node']) for r in rs})
    print(f"{phase:36} {lvl:>4} {n:>2} | {tmin:>9} {tmed:>9} {tmax:>9} | {dmin:>10} {dmed:>9} {dmax:>9} | {bytes_s:>10}")

# Aggregate ceremony compute per node.
print()
print("per-node compute totals (sum of dur_ms over spans):")
for node in nodes:
    rs = [r for r in rows if str(r["node"]) == node]
    total = sum(r["dur_ms"] or 0 for r in rs)
    # Per-level ceremonies mark `ceremony.r1_*`/`ceremony.r2_*`; the hybrid
    # (single-key) ceremony marks `ceremony.hybrid_r1_*`/`ceremony.hybrid_r2_*`.
    r1 = sum(r["dur_ms"] or 0 for r in rs if r["phase"].startswith(("ceremony.r1", "ceremony.hybrid_r1")))
    r2 = sum(r["dur_ms"] or 0 for r in rs if r["phase"].startswith(("ceremony.r2", "ceremony.hybrid_r2")))
    dkg = sum(r["dur_ms"] or 0 for r in rs if r["phase"].startswith("dkg."))
    dec = sum(r["dur_ms"] or 0 for r in rs if r["phase"].startswith("decrypt."))
    last = max((r["t_ms"] for r in rs if r["t_ms"] is not None), default=0)
    print(f"  {node:6} dkg={fmt(dkg):>7}ms  r1={fmt(r1):>7}ms  r2={fmt(r2):>7}ms  decrypt={fmt(dec):>6}ms  total_compute={fmt(total):>7}ms  wall_to_last_mark={fmt(last):>8}ms")
PY
