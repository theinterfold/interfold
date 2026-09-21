// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Memory-aware admission limits for prover work.

use std::fs;
use std::path::{Path, PathBuf};

const GIB: u64 = 1024 * 1024 * 1024;

/// Conservative memory budget for one secure Small `bb prove` process.
///
/// Mainnet incident E3-977 observed one killed proof at approximately 10.9 GiB RSS. The 13 GiB
/// budget leaves headroom for allocator and circuit-shape variance while admitting two jobs on the
/// documented 32 GB host profile.
pub const PROVER_JOB_MEMORY_BYTES: u64 = 13 * GIB;

/// Memory retained for the ciphernode, operating system, RPC, and networking processes.
pub const NODE_MEMORY_RESERVE_BYTES: u64 = 4 * GIB;

/// Result of applying CPU and memory admission limits to a requested job count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeCapacity {
    pub requested_jobs: usize,
    pub cpu_jobs: usize,
    pub memory_jobs: Option<usize>,
    pub effective_jobs: usize,
    pub memory_limit_bytes: Option<u64>,
}

impl ComputeCapacity {
    /// Resolve a safe fixed admission limit for this process.
    pub fn detect(requested_jobs: usize, cpu_jobs: usize) -> Self {
        Self::from_memory_limit(requested_jobs, cpu_jobs, effective_memory_limit_bytes())
    }

    fn from_memory_limit(
        requested_jobs: usize,
        cpu_jobs: usize,
        memory_limit_bytes: Option<u64>,
    ) -> Self {
        let requested_jobs = requested_jobs.max(1);
        let cpu_jobs = cpu_jobs.max(1);
        let memory_jobs = memory_limit_bytes.map(memory_job_limit);
        let effective_jobs = requested_jobs
            .min(cpu_jobs)
            .min(memory_jobs.unwrap_or(usize::MAX))
            .max(1);

        Self {
            requested_jobs,
            cpu_jobs,
            memory_jobs,
            effective_jobs,
            memory_limit_bytes,
        }
    }
}

fn memory_job_limit(limit_bytes: u64) -> usize {
    let usable = limit_bytes.saturating_sub(NODE_MEMORY_RESERVE_BYTES);
    usize::try_from(usable / PROVER_JOB_MEMORY_BYTES)
        .unwrap_or(usize::MAX)
        .max(1)
}

/// Return the tighter of the host and cgroup memory limits.
fn effective_memory_limit_bytes() -> Option<u64> {
    [host_memory_bytes(), cgroup_memory_bytes()]
        .into_iter()
        .flatten()
        .min()
}

fn host_memory_bytes() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo.lines().find_map(|line| {
        let value = line.strip_prefix("MemTotal:")?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    kib.checked_mul(1024)
}

fn cgroup_memory_bytes() -> Option<u64> {
    cgroup_memory_limit_paths(fs::read_to_string("/proc/self/cgroup").ok().as_deref())
        .into_iter()
        .filter_map(|path| read_numeric_limit(&path))
        .min()
}

fn cgroup_memory_limit_paths(membership: Option<&str>) -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/sys/fs/cgroup/memory.max"),
        PathBuf::from("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ];
    for line in membership.unwrap_or_default().lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().unwrap_or_default();
        let relative = fields.next().unwrap_or_default().trim_start_matches('/');
        if hierarchy == "0" && controllers.is_empty() {
            paths.push(
                PathBuf::from("/sys/fs/cgroup")
                    .join(relative)
                    .join("memory.max"),
            );
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            paths.push(
                PathBuf::from("/sys/fs/cgroup/memory")
                    .join(relative)
                    .join("memory.limit_in_bytes"),
            );
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn read_numeric_limit(path: &Path) -> Option<u64> {
    let raw = fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw == "max" {
        return None;
    }
    let value = raw.parse::<u64>().ok()?;
    // Some cgroup v1 hosts represent "unlimited" with a value close to u64::MAX.
    (value > 0 && value < (1_u64 << 60)).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_thirty_two_gb_host_supports_the_two_job_default() {
        let capacity = ComputeCapacity::from_memory_limit(2, 30, Some(31 * GIB));

        assert_eq!(capacity.memory_jobs, Some(2));
        assert_eq!(capacity.effective_jobs, 2);
    }

    #[test]
    fn sixteen_gib_reduces_the_default_to_one_job() {
        let capacity = ComputeCapacity::from_memory_limit(2, 30, Some(16 * GIB));

        assert_eq!(capacity.memory_jobs, Some(1));
        assert_eq!(capacity.effective_jobs, 1);
    }

    #[test]
    fn memory_caps_an_unsafe_explicit_override() {
        let capacity = ComputeCapacity::from_memory_limit(31, 31, Some(122 * GIB));

        assert_eq!(capacity.memory_jobs, Some(9));
        assert_eq!(capacity.effective_jobs, 9);
    }

    #[test]
    fn unknown_memory_uses_the_cpu_and_requested_limits() {
        let capacity = ComputeCapacity::from_memory_limit(4, 2, None);

        assert_eq!(capacity.memory_jobs, None);
        assert_eq!(capacity.effective_jobs, 2);
    }

    #[test]
    fn cgroup_paths_cover_namespaced_and_host_relative_layouts() {
        let paths = cgroup_memory_limit_paths(Some(
            "0::/system.slice/interfold.service\n7:cpu,memory:/docker/node-a\n",
        ));

        assert!(paths.contains(&PathBuf::from(
            "/sys/fs/cgroup/system.slice/interfold.service/memory.max"
        )));
        assert!(paths.contains(&PathBuf::from(
            "/sys/fs/cgroup/memory/docker/node-a/memory.limit_in_bytes"
        )));
    }
}
