#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Run one foreground qualification command under the sampled 32 GiB process-tree RSS guard."""
import os
import signal
import subprocess
import sys
import time


def run(command):
    start = time.monotonic()
    peak = 0
    with subprocess.Popen(command, start_new_session=True) as process:
        try:
            while process.poll() is None:
                rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss="], text=True)
                stats = [tuple(map(int, row.split())) for row in rows.splitlines() if row.strip()]
                family = {process.pid}
                while True:
                    descendants = {pid for pid, parent, _ in stats if parent in family}
                    if descendants <= family:
                        break
                    family |= descendants
                peak = max(peak, sum(rss for pid, _, rss in stats if pid in family))
                if peak >= 32 * 1024**2:
                    print("32 GiB sampled RSS guard reached", file=sys.stderr)
                    return 125
                time.sleep(0.5)
            return process.returncode
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            print(f"{command[0]}: {time.monotonic()-start:.1f}s; peak sampled RSS {peak/1024**2:.2f} GiB", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
