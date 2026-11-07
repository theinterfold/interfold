// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain reader's heartbeat for the operator's health check, `dappnode/healthcheck.sh`. A
//! reader that cannot reach its chain node retries and logs, but nothing outside the process sees
//! that its ingestion stopped. So each successful read rewrites one small file per chain: when the
//! reader last read the chain, and when the chain's head or the reader's position last moved. An
//! `expected` file says how many chain readers the node starts, and when, so a reader that never
//! reads fails the check after a grace period instead of passing as one still starting.

use e3_protocol::UnixSecs;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use tracing::{info, warn};

pub(crate) struct Heartbeat {
    file: PathBuf,
    chain_id: u64,
    /// The head and the position of the last read, and when either last changed.
    last: Option<(u64, u64)>,
    progressed_at: UnixSecs,
    failing: bool,
}

impl Heartbeat {
    /// Records at `now` that the node starts one chain reader, and removes an earlier run's
    /// heartbeat, which would pass the check for a reader that has not read yet.
    pub(crate) fn start(dir: &Path, chain_id: u64, now: UnixSecs) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = dir.join(format!("chain-{chain_id}.heartbeat"));
        match fs::remove_file(&file) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        write(
            &dir.join("expected"),
            &format!("chains=1\nstarted_at={now}\n"),
        )?;
        Ok(Self {
            file,
            chain_id,
            last: None,
            progressed_at: now,
            failing: false,
        })
    }

    /// A read at `now` found the chain's head at `head`, with its logs read up to `read_to`.
    pub(crate) fn beat(&mut self, now: UnixSecs, head: u64, read_to: u64) {
        if self.last != Some((head, read_to)) {
            self.last = Some((head, read_to));
            self.progressed_at = now;
        }
        let content = format!(
            "chain_id={}\nhead={head}\ncursor={read_to}\npolled_at={now}\nprogressed_at={}\n",
            self.chain_id, self.progressed_at
        );
        match write(&self.file, &content) {
            Ok(()) if self.failing => {
                self.failing = false;
                info!("the ingestion heartbeat is written again");
            }
            Err(error) if !self.failing => {
                self.failing = true;
                warn!(%error, file = %self.file.display(), "writing the ingestion heartbeat failed");
            }
            _ => {}
        }
    }
}

/// Writes `file` whole or not at all, so the health check never reads half of it.
fn write(file: &Path, content: &str) -> io::Result<()> {
    let partial = file.with_extension("partial");
    fs::write(&partial, content)?;
    fs::rename(partial, file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fields(file: &Path) -> BTreeMap<String, String> {
        fs::read_to_string(file)
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    }

    /// The health check finds a stalled reader by a progress time that stops moving while the
    /// poll time moves on.
    #[test]
    fn progress_counts_only_when_the_head_or_the_reader_moves() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("chain-7.heartbeat");
        fs::write(&file, "polled_at=1\nprogressed_at=1\n").unwrap();
        let mut heartbeat = Heartbeat::start(dir.path(), 7, 100).unwrap();
        assert!(!file.exists(), "an earlier run's heartbeat stays");
        assert_eq!(fields(&dir.path().join("expected"))["started_at"], "100");

        heartbeat.beat(110, 50, 47);
        heartbeat.beat(120, 50, 47);
        let read = fields(&file);
        assert_eq!(
            (&*read["polled_at"], &*read["progressed_at"]),
            ("120", "110")
        );

        heartbeat.beat(130, 51, 47);
        assert_eq!(fields(&file)["progressed_at"], "130");
    }
}
