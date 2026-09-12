#!/usr/bin/env python3
"""r124 C2a-secure-8192/small compile-leg memory sampler.

CANARY-R124-MEM-SAMPLER-7F3A1 (transport integrity marker, search before trusting).

Polls the box-3 session cgroup (flat /sys/fs/cgroup v2 at the cgroupfs root)
every POLL_S seconds during the compile leg, appending
(t, memory.current, memory.peak, MemAvailable, SwapFree, cpu_cum_ms, uptime)
to mem_samples.csv. memory.peak (cgroup2) is the OOM-proof high-water of the
session cgroup; kernel btime + MemTotal + cpu max from /proc + sysfs.
"""
import os
import time

ROOT = "/sys/fs/cgroup"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "mem_samples.csv")
POLL_S = 2.0
CANARY = "CANARY-R124-MEM-SAMPLER-7F3A1"

def read_all():
    with open(os.path.join(ROOT, "memory.current")) as f:
        cur = int(f.read().strip())
    with open(os.path.join(ROOT, "memory.peak")) as f:
        pk = int(f.read().strip())
    mi = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":")
            mi[k.strip()] = v.strip().split()[0]
    with open("/proc/uptime") as f:
        up = float(f.read().split()[0])
    with open("/proc/stat") as f:
        st = f.readline().split()
    cpu = int(st[1]) + int(st[2])  # user+system, jiffies
    return cur, pk, mi, up, cpu

def main():
    header = "epoch_s,t_since_start_s,mem_cur_kb,mem_peak_kb,mem_avail_mb,swap_free_kb,cpu_cum_jiff,uptime_s\n"
    t0 = time.time()
    up0 = read_all()[3]
    with open(OUT, "w") as out:
        out.write(header + CANARY + "\n")
        out.flush()
        while True:
            cur, pk, mi, up, cpu = read_all()
            out.write("%d,%.1f,%d,%d,%d,%d,%d,%d\n" % (
                int(time.time() - t0), round(time.time() - t0, 1),
                cur // 1024, pk // 1024, mi["MemAvailable"] // 1024,
                mi["SwapFree"] // 1024, cpu, int(up)))
            out.flush()
            time.sleep(POLL_S)

if __name__ == "__main__":
    main()