// SPDX-License-Identifier: LGPL-3.0-only

use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum BenchmarkInstant {
    NodeHrtime(Duration),
    ProcessLocal(Instant),
}

impl BenchmarkInstant {
    pub fn now() -> Self {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(time) = node_hrtime() {
            return Self::NodeHrtime(time);
        }
        Self::ProcessLocal(Instant::now())
    }

    /// Accept a Node hrtime reading only if it falls inside the observed child invocation.
    pub fn child_hrtime(self, nanoseconds: Option<&str>) -> Option<Self> {
        let reading = Self::NodeHrtime(Duration::from_nanos(nanoseconds?.parse().ok()?));
        reading.seconds_since(self)?;
        Self::now().seconds_since(reading)?;
        Some(reading)
    }

    pub fn seconds_since(self, earlier: Self) -> Option<f64> {
        let elapsed = match (self, earlier) {
            (Self::NodeHrtime(end), Self::NodeHrtime(start)) => end.checked_sub(start)?,
            (Self::ProcessLocal(end), Self::ProcessLocal(start)) => {
                end.checked_duration_since(start)?
            }
            _ => return None,
        };
        Some(elapsed.as_secs_f64())
    }
}

// Node's process.hrtime.bigint() uses libuv's precise clock: CLOCK_MONOTONIC on Linux
// and mach_continuous_time (CLOCK_MONOTONIC_RAW, including sleep) on current macOS Node.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn node_hrtime() -> Option<Duration> {
    #[cfg(target_os = "linux")]
    let clock = libc::CLOCK_MONOTONIC;
    #[cfg(target_os = "macos")]
    let clock = libc::CLOCK_MONOTONIC_RAW;
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes a timespec to the supplied valid pointer.
    if unsafe { libc::clock_gettime(clock, &mut time) } != 0 {
        return None;
    }
    Some(Duration::new(
        time.tv_sec.try_into().ok()?,
        time.tv_nsec.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_dispatch_does_not_invalidate_local_phases() {
        let invoked = BenchmarkInstant::now();
        for ns in [
            None,
            Some("invalid"),
            Some("0"),
            Some("18446744073709551615"),
        ] {
            assert!(invoked.child_hrtime(ns).is_none());
        }
        assert!(BenchmarkInstant::now().seconds_since(invoked).is_some());
        assert!(BenchmarkInstant::NodeHrtime(Duration::ZERO)
            .seconds_since(BenchmarkInstant::ProcessLocal(Instant::now()))
            .is_none());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[ignore = "requires node on PATH"]
    fn node_dispatch_is_between_parent_observations() {
        let invoked = BenchmarkInstant::now();
        let child = std::process::Command::new("node")
            .args(["-p", "process.hrtime.bigint().toString()"])
            .output()
            .unwrap();
        assert!(child.status.success());
        let dispatch = invoked
            .child_hrtime(Some(std::str::from_utf8(&child.stdout).unwrap().trim()))
            .unwrap();
        let receipt = BenchmarkInstant::now();
        assert!(receipt.seconds_since(dispatch).unwrap() < receipt.seconds_since(invoked).unwrap());
    }
}
