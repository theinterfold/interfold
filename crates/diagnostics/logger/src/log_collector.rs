// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded operational-log store used by the local node dashboard.
//!
//! Protocol events do not live here: their authoritative, durable source is
//! the EventStore. This collector is for `tracing` diagnostics such as RPC,
//! networking, startup, and resource warnings.

use serde::Serialize;
use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_CAPACITY: usize = 20_000;
const DEFAULT_QUERY_LIMIT: usize = 500;
const MAX_QUERY_LIMIT: usize = 2_000;
const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
const ROTATED_FILES: usize = 4;

#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
    pub node: String,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogQueryResult {
    pub entries: Vec<LogEntry>,
    pub next_cursor: u64,
    pub oldest_cursor: u64,
    pub total_stored: usize,
}

pub struct LogCollector {
    entries: Mutex<VecDeque<LogEntry>>,
    writer: Mutex<Option<RollingJsonWriter>>,
    capacity: usize,
    next_seq: AtomicU64,
    node: String,
}

impl LogCollector {
    /// Initialize the process-local collector. Repeated calls return the first
    /// initialized instance, matching tracing's process-global subscriber.
    pub fn init(node: &str, path: Option<PathBuf>) -> &'static Self {
        INSTANCE.get_or_init(|| Self::new(node, path, DEFAULT_CAPACITY))
    }

    pub fn global() -> Option<&'static Self> {
        INSTANCE.get()
    }

    fn new(node: &str, path: Option<PathBuf>, capacity: usize) -> Self {
        let writer = path.and_then(|path| match RollingJsonWriter::open(path) {
            Ok(writer) => Some(writer),
            Err(error) => {
                eprintln!("failed to open ciphernode operational log: {error}");
                None
            }
        });
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            writer: Mutex::new(writer),
            capacity,
            next_seq: AtomicU64::new(0),
            node: node.to_owned(),
        }
    }

    pub fn record(&self, level: &str, target: &str, message: String, fields: Map<String, Value>) {
        let mut entry = LogEntry {
            // Assigned under the entries lock below so the deque stays ordered
            // by seq; query()'s cursor pagination relies on that invariant.
            seq: 0,
            timestamp_ms: now_ms(),
            level: level.to_owned(),
            target: target.to_owned(),
            message,
            node: self.node.clone(),
            fields,
        };

        {
            // Recover from a poisoned lock rather than silently dropping every
            // subsequent log line after a single panic-while-holding-lock.
            let mut entries = match self.entries.lock() {
                Ok(entries) => entries,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Stamp seq while holding the lock so increment and push are atomic
            // relative to other writers (no out-of-order insertion).
            entry.seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            if entries.len() == self.capacity {
                entries.pop_front();
            }
            entries.push_back(entry.clone());
        }

        let mut writer_guard = match self.writer.lock() {
            Ok(writer_guard) => writer_guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let failed = writer_guard
            .as_mut()
            .and_then(|writer| writer.write(&entry).err());
        if let Some(error) = failed {
            eprintln!("failed to write ciphernode operational log: {error}");
            *writer_guard = None;
        }
    }

    pub fn query(
        &self,
        since: Option<u64>,
        limit: Option<usize>,
        level: Option<&str>,
        target: Option<&str>,
        text: Option<&str>,
    ) -> LogQueryResult {
        let entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        let oldest_cursor = entries
            .front()
            .map(|entry| entry.seq)
            .unwrap_or_else(|| self.next_seq.load(Ordering::Relaxed));
        let head_cursor = self.next_seq.load(Ordering::Relaxed);
        let limit = limit
            .unwrap_or(DEFAULT_QUERY_LIMIT)
            .clamp(1, MAX_QUERY_LIMIT);
        let needle = text.map(str::to_lowercase);
        let matches = |entry: &LogEntry| {
            level.is_none_or(|value| entry.level.eq_ignore_ascii_case(value))
                && target.is_none_or(|value| entry.target.contains(value))
                && needle.as_ref().is_none_or(|value| {
                    entry.message.to_lowercase().contains(value)
                        || entry.target.to_lowercase().contains(value)
                        || serde_json::to_string(&entry.fields)
                            .unwrap_or_default()
                            .to_lowercase()
                            .contains(value)
                })
        };

        let selected: Vec<LogEntry> = if let Some(since) = since {
            entries
                .iter()
                .filter(|entry| entry.seq >= since.max(oldest_cursor))
                .filter(|entry| matches(entry))
                .take(limit)
                .cloned()
                .collect()
        } else {
            let mut latest: Vec<_> = entries
                .iter()
                .rev()
                .filter(|entry| matches(entry))
                .take(limit)
                .cloned()
                .collect();
            latest.reverse();
            latest
        };
        let next_cursor = if selected.len() == limit {
            selected
                .last()
                .map(|entry| entry.seq.saturating_add(1))
                .unwrap_or(head_cursor)
        } else {
            head_cursor
        };

        LogQueryResult {
            entries: selected,
            next_cursor,
            oldest_cursor,
            total_stored: entries.len(),
        }
    }

    pub fn flush(&self) {
        let mut writer = match self.writer.lock() {
            Ok(writer) => writer,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(writer) = writer.as_mut() {
            let _ = writer.flush();
        }
    }
}

static INSTANCE: OnceLock<LogCollector> = OnceLock::new();

struct RollingJsonWriter {
    path: PathBuf,
    file: Option<BufWriter<File>>,
    bytes_written: u64,
    pending_lines: usize,
}

impl RollingJsonWriter {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let bytes_written = file.metadata()?.len();
        Ok(Self {
            path,
            file: Some(BufWriter::new(file)),
            bytes_written,
            pending_lines: 0,
        })
    }

    fn write(&mut self, entry: &LogEntry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
        line.push(b'\n');
        if self.bytes_written.saturating_add(line.len() as u64) > MAX_FILE_BYTES {
            self.rotate()?;
        }
        if let Some(file) = self.file.as_mut() {
            file.write_all(&line)?;
            self.pending_lines += 1;
            if self.pending_lines >= 64 {
                file.flush()?;
                self.pending_lines = 0;
            }
        }
        self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        for index in (1..ROTATED_FILES).rev() {
            let from = rotated_path(&self.path, index);
            let to = rotated_path(&self.path, index + 1);
            if from.exists() {
                let _ = fs::remove_file(&to);
                fs::rename(from, to)?;
            }
        }
        if self.path.exists() {
            let first = rotated_path(&self.path, 1);
            let _ = fs::remove_file(&first);
            fs::rename(&self.path, first)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.file = Some(BufWriter::new(file));
        self.bytes_written = 0;
        self.pending_lines = 0;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        self.pending_lines = 0;
        Ok(())
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_store_remains_in_sequence_order() {
        let collector = LogCollector::new("node", None, 2);
        collector.record("INFO", "a", "one".into(), Map::new());
        collector.record("WARN", "b", "two".into(), Map::new());
        collector.record("ERROR", "c", "three".into(), Map::new());

        let result = collector.query(None, None, None, None, None);
        assert_eq!(result.oldest_cursor, 1);
        assert_eq!(
            result
                .entries
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn filters_structured_logs() {
        let collector = LogCollector::new("node", None, 4);
        let mut fields = Map::new();
        fields.insert("e3_id".into(), Value::String("1:9".into()));
        collector.record("INFO", "e3::worker", "proof complete".into(), fields);

        let result = collector.query(None, None, Some("info"), Some("worker"), Some("1:9"));
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn query_without_cursor_returns_the_newest_window() {
        let collector = LogCollector::new("node", None, 5);
        for value in 0..5 {
            collector.record("INFO", "test", value.to_string(), Map::new());
        }

        let result = collector.query(None, Some(2), None, None, None);
        assert_eq!(
            result
                .entries
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(result.next_cursor, 5);
    }

    #[test]
    fn exhausted_filter_advances_cursor_to_the_log_head() {
        let collector = LogCollector::new("node", None, 5);
        collector.record("INFO", "test", "one".into(), Map::new());
        collector.record("DEBUG", "test", "two".into(), Map::new());

        let result = collector.query(Some(0), Some(5), Some("error"), None, None);
        assert!(result.entries.is_empty());
        assert_eq!(result.next_cursor, 2);
    }
}
