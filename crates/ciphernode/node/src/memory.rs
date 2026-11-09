// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the machine can run at once: no more proofs than the operator asked for and its memory
//! holds, and no more threads than its cores less those kept for the node's own loops. A prover
//! under the secure parameters can hold 13 GiB, and the node keeps 4 GiB for itself. A container's
//! memory limit counts as the machine's.

use std::{
    fs,
    path::{Path, PathBuf},
    thread,
};
use tracing::warn;

const PROVER_BYTES: u64 = 13 << 30;
const RESERVE_BYTES: u64 = 4 << 30;

/// What the node's work may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capacity {
    /// Proofs at once.
    pub(crate) proofs: usize,
    /// Threads for checks and threshold cryptography.
    pub(crate) threads: usize,
    /// Threads each `bb` may use, so running proofs together stay within the threads.
    pub(crate) bb_threads: usize,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "this machine has {} GiB of memory for the node, and a prover needs {} GiB with {} GiB kept \
     for the node; give it more memory",
    .memory >> 30, PROVER_BYTES >> 30, RESERVE_BYTES >> 30
)]
pub(crate) struct HostTooSmall {
    memory: u64,
}

/// The node's capacity on this machine for `requested` proofs at once and `reserved` threads kept
/// for its own loops.
pub(crate) fn capacity(requested: usize, reserved: usize) -> Result<Capacity, HostTooSmall> {
    let cores = thread::available_parallelism().map_or(1, usize::from);
    let capacity = capacity_of(requested, reserved, cores, memory_limit())?;
    if capacity.proofs < requested {
        warn!(
            requested,
            proofs = capacity.proofs,
            "running fewer proofs at once, to fit the machine's memory"
        );
    }
    Ok(capacity)
}

/// The capacity of a node that makes no real proofs, which needs no prover's memory.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn threads_for_placeholders(reserved: usize) -> usize {
    let cores = thread::available_parallelism().map_or(1, usize::from);
    cores.saturating_sub(reserved).max(1)
}

fn capacity_of(
    requested: usize,
    reserved: usize,
    cores: usize,
    memory: Option<u64>,
) -> Result<Capacity, HostTooSmall> {
    let fit = match memory {
        Some(bytes) => usize::try_from(bytes.saturating_sub(RESERVE_BYTES) / PROVER_BYTES)
            .unwrap_or(usize::MAX),
        None => usize::MAX,
    };
    if fit == 0 {
        return Err(HostTooSmall {
            memory: memory.unwrap_or_default(),
        });
    }
    let proofs = requested.max(1).min(fit);
    let threads = cores.saturating_sub(reserved).max(1);
    Ok(Capacity {
        proofs,
        threads,
        bb_threads: (threads / proofs).max(1),
    })
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
        // A parent's limit binds its children, so every cgroup on the way up counts.
        let ancestors = Path::new(relative).ancestors();
        if hierarchy == "0" && controllers.is_empty() {
            paths.extend(
                ancestors.map(|cgroup| Path::new("/sys/fs/cgroup").join(cgroup).join("memory.max")),
            );
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            paths.extend(ancestors.map(|cgroup| {
                Path::new("/sys/fs/cgroup/memory")
                    .join(cgroup)
                    .join("memory.limit_in_bytes")
            }));
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
    fn a_machine_runs_as_many_proofs_as_its_memory_holds() {
        let proofs = |requested, memory| {
            capacity_of(requested, 2, 12, memory)
                .expect("the host fits a prover")
                .proofs
        };
        assert_eq!(proofs(2, Some(32 * GIB)), 2);
        assert_eq!(proofs(2, Some(28 * GIB)), 1);
        assert_eq!(proofs(2, Some(17 * GIB)), 1);
        assert_eq!(proofs(2, None), 2);
        assert_eq!(proofs(4, Some(64 * GIB)), 4);
    }

    #[test]
    fn a_machine_too_small_for_one_prover_is_refused() {
        assert!(capacity_of(2, 2, 12, Some(16 * GIB)).is_err());
    }

    /// Threads kept for the node are not given to work, and proofs running together share the
    /// rest.
    #[test]
    fn work_stays_within_the_threads_left_for_it() {
        let capacity = capacity_of(2, 2, 12, Some(64 * GIB)).unwrap();
        assert_eq!(capacity.threads, 10);
        assert_eq!(capacity.bb_threads, 5);
        assert_eq!(capacity_of(1, 8, 4, None).unwrap().threads, 1);
    }

    /// A container's limit lives in its own cgroup's folder, under cgroup v2 or v1.
    #[test]
    fn the_limits_of_the_process_cgroups_are_read() {
        let v2 = cgroup_limits("0::/system.slice/docker-abc.scope\n");
        assert!(v2.contains(&PathBuf::from(
            "/sys/fs/cgroup/system.slice/docker-abc.scope/memory.max"
        )));
        // A limit on the slice above a service binds the service.
        assert!(v2.contains(&PathBuf::from("/sys/fs/cgroup/system.slice/memory.max")));
        let v1 = cgroup_limits("12:cpu,cpuacct:/docker/abc\n7:memory:/docker/abc\n");
        assert!(v1.contains(&PathBuf::from(
            "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes"
        )));
        assert!(!v1.iter().any(|path| path.starts_with("/sys/fs/cgroup/cpu")));
    }
}
