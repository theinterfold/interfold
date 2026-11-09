// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The node's notes for its operator: each one logged, and kept in a bounded feed on disk that
//! `interfold node events` reads. Losing the feed loses nothing the node needs.

use e3_protocol::{node::Note, UnixSecs};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use tracing::{info, warn};

/// The feed keeps its current file and the one before it.
const LARGEST_FILE: u64 = 4 * 1024 * 1024;
const CURRENT: &str = "notes.jsonl";
const PREVIOUS: &str = "notes.old.jsonl";

/// One line of the feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub sequence: u64,
    pub at: UnixSecs,
    pub note: Note,
}

/// Where the node writes its notes.
pub struct NoteFeed {
    dir: PathBuf,
    file: File,
    size: u64,
    next: u64,
}

impl NoteFeed {
    /// The feed in `dir`, numbering on from what it holds.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let next = lines(dir)?
            .last()
            .map_or(1, |entry| entry.sequence.saturating_add(1));
        let file = append_to(&dir.join(CURRENT))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            size: file.metadata()?.len(),
            file,
            next,
        })
    }

    /// Logs `note` and keeps it. A feed that cannot be written does not stop the node.
    pub fn record(&mut self, at: UnixSecs, note: Note) {
        let (e3, event) = (note.e3, note.event.to_string());
        match note.event.is_warning() {
            true => warn!(%e3, "{event}"),
            false => info!(%e3, "{event}"),
        }
        let entry = Entry {
            sequence: self.next,
            at,
            note,
        };
        self.next += 1;
        if let Err(error) = self.append(&entry) {
            warn!(%error, "keeping a note failed");
        }
    }

    fn append(&mut self, entry: &Entry) -> io::Result<()> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        if self.size + line.len() as u64 > LARGEST_FILE {
            fs::rename(self.dir.join(CURRENT), self.dir.join(PREVIOUS))?;
            self.file = append_to(&self.dir.join(CURRENT))?;
            self.size = 0;
        }
        self.file.write_all(&line)?;
        self.size += line.len() as u64;
        Ok(())
    }
}

fn append_to(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Up to `limit` notes after `since`, oldest first. Reading needs no lock: a line being written is
/// not a whole line yet, and is left out.
pub fn read(dir: &Path, since: u64, limit: usize) -> io::Result<Vec<Entry>> {
    Ok(lines(dir)?
        .into_iter()
        .filter(|entry| entry.sequence > since)
        .take(limit)
        .collect())
}

fn lines(dir: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for name in [PREVIOUS, CURRENT] {
        let file = match File::open(dir.join(name)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in BufReader::new(file).lines() {
            if let Ok(entry) = serde_json::from_str(&line?) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use e3_protocol::{node::Noted, proof::ProofType, E3Id};

    fn note() -> Note {
        Note {
            e3: E3Id {
                chain_id: 1,
                number: U256::from(7),
            },
            event: Noted::ProofFailed {
                member: Address::repeat_byte(1),
                proof_type: ProofType::C0PkBfv,
            },
        }
    }

    #[test]
    fn notes_are_read_after_a_cursor_up_to_a_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut feed = NoteFeed::open(dir.path()).unwrap();
        for at in 0..5 {
            feed.record(at, note());
        }
        let sequences = |since, limit| -> Vec<u64> {
            let entries = read(dir.path(), since, limit).unwrap();
            entries.iter().map(|entry| entry.sequence).collect()
        };
        assert_eq!(sequences(0, 10), [1, 2, 3, 4, 5]);
        assert_eq!(sequences(2, 2), [3, 4]);
    }

    #[test]
    fn a_restart_numbers_on() {
        let dir = tempfile::tempdir().unwrap();
        NoteFeed::open(dir.path()).unwrap().record(0, note());
        NoteFeed::open(dir.path()).unwrap().record(0, note());
        let entries = read(dir.path(), 0, 10).unwrap();
        assert_eq!(entries.last().unwrap().sequence, 2);
    }

    #[test]
    fn a_half_written_line_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        NoteFeed::open(dir.path()).unwrap().record(0, note());
        let mut file = append_to(&dir.path().join(CURRENT)).unwrap();
        file.write_all(b"{\"sequence\":2,").unwrap();
        assert_eq!(read(dir.path(), 0, 10).unwrap().len(), 1);
    }

    /// However long the node runs, the feed holds two files' worth of notes.
    #[test]
    fn the_feed_keeps_the_newest_notes_in_a_bounded_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut feed = NoteFeed::open(dir.path()).unwrap();
        let written = 3 * LARGEST_FILE / serde_json::to_vec(&note()).unwrap().len() as u64;
        for at in 0..written {
            feed.record(at, note());
        }
        let size = |name| fs::metadata(dir.path().join(name)).unwrap().len();
        assert!(size(CURRENT) <= LARGEST_FILE && size(PREVIOUS) <= LARGEST_FILE);
        let entries = read(dir.path(), 0, usize::MAX).unwrap();
        assert_eq!(entries.last().unwrap().sequence, written);
        assert!(entries[0].sequence > 1, "the oldest notes went");
    }
}
