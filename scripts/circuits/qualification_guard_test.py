# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise cancellation and leader exit with a live process-group worker."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import unittest


class GuardTests(unittest.TestCase):
    def test_worker_cannot_outlive_guard(self):
        guard = Path(__file__).with_name("guard-proof-rss.py")
        for cancel in (True, False):
            with self.subTest(cancel=cancel):
                leader = (
                    "import os, subprocess, time; "
                    "subprocess.Popen(['sleep', '30']); "
                    "print(os.getpid(), flush=True); "
                    + ("time.sleep(30)" if cancel else "raise SystemExit(7)")
                )
                with subprocess.Popen(
                    [sys.executable, guard, sys.executable, "-c", leader],
                    stdout=subprocess.PIPE, text=True,
                ) as process:
                    group = int(process.stdout.readline())
                    try:
                        if cancel:
                            process.terminate()
                        # The worker inherits stdout, so EOF also requires worker cleanup.
                        process.communicate(timeout=5)
                        self.assertEqual(process.returncode, 143 if cancel else 7)
                    finally:
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
