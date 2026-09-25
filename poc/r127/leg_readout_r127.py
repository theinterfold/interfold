#!/usr/bin/env python3
"""r127 leg log reader: parse the r78 19-node run's journal output (the leg
prints R78-fn/R78-leaf lines via --nocapture to stdout = unit journal) + the
time log. Prints a compact machine block. Rerunnable at any point; exit 0 =
leg terminal (found 'test result'), 3 = still running, 1 = defect."""
import re
import subprocess
import sys

TAG = "r127r78leg.service"
out = subprocess.run(["journalctl", "--user", "-u", TAG, "--no-pager", "-o", "short-iso"],
                     capture_output=True, text=True).stdout
if "test result:" not in out:
    print("status=RUNNING lines=%d" % out.count("\n"))
    raise SystemExit(3)

lines = [l for l in out.splitlines() if "R78-" in l or "test result" in l]
for l in lines:
    print(l.split("]", 1)[-1].strip() if "]" in l else l)

tr = [l for l in out.splitlines() if "test result:" in l]
print("test_result_line:", [t.split("test result:")[1].strip() for t in tr])
print("status=TERMINAL")