// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum log lines retained per individual node.
const MAX_PER_NODE: usize = 2_000;

/// Maximum log lines retained in the merged global buffer.
const MAX_GLOBAL: usize = 10_000;

// ─── Log line ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct LogLine {
    /// Global monotonic sequence number — used as a polling cursor.
    pub seq: u64,
    /// Node that produced this line.
    pub node: String,
    /// Detected log level (ERROR / WARN / INFO / DEBUG / TRACE).
    pub level: String,
    /// ISO timestamp extracted from the tracing output (empty string if absent).
    pub ts: String,
    /// Rust module/crate target extracted from the tracing log line, e.g.
    /// `e3_keyshare::threshold_keyshare`.  Empty if the format is unrecognised.
    pub target: String,
    /// Original raw line (trimmed), kept for client-side full-text search.
    pub raw: String,
}

fn detect_level(s: &str) -> &'static str {
    // tracing-subscriber fmt format: "TIMESTAMP  LEVEL target: message"
    // Check for the level keyword surrounded by whitespace or at line start.
    if s.contains(" ERROR") || s.starts_with("ERROR") {
        "ERROR"
    } else if s.contains(" WARN") || s.starts_with("WARN") {
        "WARN"
    } else if s.contains(" INFO") || s.starts_with("INFO") {
        "INFO"
    } else if s.contains(" DEBUG") || s.starts_with("DEBUG") {
        "DEBUG"
    } else if s.contains(" TRACE") || s.starts_with("TRACE") {
        "TRACE"
    } else {
        "INFO"
    }
}

fn extract_ts(s: &str) -> String {
    // The first whitespace-delimited token is the timestamp when it looks like
    // an ISO 8601 value (contains 'T' or starts with a 4-digit year).
    let trimmed = s.trim();
    if let Some(end) = trimmed.find(|c: char| c.is_ascii_whitespace()) {
        let candidate = &trimmed[..end];
        if candidate.len() >= 10 && candidate.contains('T') {
            return candidate.to_string();
        }
    }
    String::new()
}

/// Extract the tracing `target` (module path) from a log line.
///
/// tracing-subscriber compact/full format:
///   `TIMESTAMP  LEVEL target::path: message field=val …`
///
/// Returns an empty string when the format is not recognised.
fn extract_target(s: &str) -> String {
    let trimmed = s.trim();
    // Skip past the double-space that separates the timestamp from the rest.
    let after_sep = trimmed
        .find("  ")
        .filter(|&p| p < 36)
        .map(|p| trimmed[p + 2..].trim_start())
        .unwrap_or(trimmed);
    // Skip past the level keyword (single word, e.g. "INFO").
    let after_level = after_sep
        .find(' ')
        .map(|p| after_sep[p + 1..].trim_start())
        .unwrap_or("");
    // Target is everything up to the first ": ".
    after_level
        .find(": ")
        .map(|p| after_level[..p].to_string())
        .unwrap_or_default()
}

// ─── Buffer ───────────────────────────────────────────────────────────────────

/// Thread-safe, bounded log buffer shared between the process manager (writers)
/// and the HTTP server (readers).
#[derive(Clone, Debug)]
pub struct LogBuffer {
    per_node: Arc<Mutex<HashMap<String, VecDeque<Arc<LogLine>>>>>,
    global: Arc<Mutex<VecDeque<Arc<LogLine>>>>,
    seq: Arc<AtomicU64>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            per_node: Arc::new(Mutex::new(HashMap::new())),
            global: Arc::new(Mutex::new(VecDeque::new())),
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Ingest a raw log line from `node`.  Parsing (level, timestamp) happens here.
    pub async fn push(&self, node: &str, raw: &str) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let line = Arc::new(LogLine {
            seq,
            node: node.to_string(),
            level: detect_level(trimmed).to_string(),
            ts: extract_ts(trimmed),
            target: extract_target(trimmed),
            raw: trimmed.to_string(),
        });

        {
            let mut nodes = self.per_node.lock().await;
            let buf = nodes.entry(node.to_string()).or_default();
            buf.push_back(line.clone());
            if buf.len() > MAX_PER_NODE {
                buf.pop_front();
            }
        }

        {
            let mut global = self.global.lock().await;
            global.push_back(line);
            if global.len() > MAX_GLOBAL {
                global.pop_front();
            }
        }
    }

    /// Return up to `limit` lines whose `seq >= since_seq`, optionally filtered
    /// to a single node.  Pass `None` or `Some("all")` to get all nodes merged.
    pub async fn recent(
        &self,
        node: Option<&str>,
        since_seq: u64,
        limit: usize,
    ) -> Vec<Arc<LogLine>> {
        let limit = limit.min(1_000);
        match node {
            None | Some("all") => {
                let global = self.global.lock().await;
                global
                    .iter()
                    .filter(|l| l.seq >= since_seq)
                    .take(limit)
                    .cloned()
                    .collect()
            }
            Some(n) => {
                let nodes = self.per_node.lock().await;
                nodes
                    .get(n)
                    .map(|buf| {
                        buf.iter()
                            .filter(|l| l.seq >= since_seq)
                            .take(limit)
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default()
            }
        }
    }

    /// List every node name that has produced at least one log line.
    pub async fn nodes(&self) -> Vec<String> {
        let mut names: Vec<String> = self.per_node.lock().await.keys().cloned().collect();
        names.sort();
        names
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}
