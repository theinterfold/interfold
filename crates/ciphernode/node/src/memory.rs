// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! How many proofs the node runs at once: no more than the operator asked for, and no more than
//! the machine's memory holds. A prover under the secure parameters can hold 13 GiB, and the node
//! keeps 4 GiB for itself. A container's memory limit counts as the machine's.

use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::warn;

const PROVER_BYTES: u64 = 13 << 30;
const RESERVE_BYTES: u64 = 4 << 30;

/// `requested`, or fewer when the memory holds fewer; at least one, so a small machine still
/// proves.
pub(crate) fn proof_jobs(requested: usize) -> usize {
    let jobs = jobs_for(requested, memory_limit());
    if jobs < requested {
        warn!(
            requested,
            jobs, "running fewer proofs at once, to fit the machine's memory"
        );
    }
    jobs
}

fn jobs_for(requested: usize, memory: Option<u64>) -> usize {
    let fit = memory.map_or(usize::MAX, |bytes| {
        usize::try_from(bytes.saturating_sub(RESERVE_BYTES) / PROVER_BYTES).unwrap_or(usize::MAX)
    });
    requested.min(fit).max(1)
}

/// The smaller of the machine's memory and the limit of each memory cgroup the process is in.
fn memory_limit() -> Option<u64> {
    let host = fs::read_to_string("/proc/meminfo").ok().and_then(|info| {
        info.lines().find_map(|line| {
            let kib = line.strip_prefix("MemTotal:")?.split_whitespace().next()?;
            kib.parse::<u64>().ok()?.checked_mul(1024)
        })
    });
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    cgroup_limits(&membership)
        .iter()
        .filter_map(|path| limit(path))
        .chain(host)
        .min()
}

/// The files that hold the memory limits of the cgroups in `membership` (`/proc/self/cgroup`),
/// under cgroup v2 and v1.
fn cgroup_limits(membership: &str) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/sys/fs/cgroup/memory.max"),
        PathBuf::from("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ];
    for line in membership.lines() {
        let mut fields = line.splitn(3, ':');
        let (hierarchy, controllers) = (fields.next().unwrap_or(""), fields.next().unwrap_or(""));
        let relative = fields.next().unwrap_or("").trim_start_matches('/');
        if hierarchy == "0" && controllers.is_empty() {
            paths.push(
                Path::new("/sys/fs/cgroup")
                    .join(relative)
                    .join("memory.max"),
            );
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            let v1 = Path::new("/sys/fs/cgroup/memory").join(relative);
            paths.push(v1.join("memory.limit_in_bytes"));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// A cgroup's memory limit; none when it has none ("max", or v1's near-infinite value).
fn limit(path: &Path) -> Option<u64> {
    let raw = fs::read_to_string(path).ok()?;
    let value = raw.trim().parse::<u64>().ok()?;
    (value > 0 && value < 1 << 60).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn a_machine_runs_as_many_proofs_as_its_memory_holds_and_at_least_one() {
        assert_eq!(jobs_for(2, Some(32 * GIB)), 2);
        assert_eq!(jobs_for(2, Some(28 * GIB)), 1);
        assert_eq!(jobs_for(2, Some(16 * GIB)), 1);
        assert_eq!(jobs_for(2, None), 2);
        assert_eq!(jobs_for(4, Some(64 * GIB)), 4);
    }

    /// A container's limit lives in its own cgroup's folder, under cgroup v2 or v1.
    #[test]
    fn the_limits_of_the_process_cgroups_are_read() {
        let v2 = cgroup_limits("0::/system.slice/docker-abc.scope\n");
        assert!(v2.contains(&PathBuf::from(
            "/sys/fs/cgroup/system.slice/docker-abc.scope/memory.max"
        )));
        let v1 = cgroup_limits("12:cpu,cpuacct:/docker/abc\n7:memory:/docker/abc\n");
        assert!(v1.contains(&PathBuf::from(
            "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes"
        )));
        assert!(!v1.iter().any(|path| path.starts_with("/sys/fs/cgroup/cpu")));
    }
}
