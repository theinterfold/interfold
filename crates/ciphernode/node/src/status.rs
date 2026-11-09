// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A read-only page of what the node is doing, on `dashboard_port` of the operator's own machine.
//! It only shows what the node already holds, and a failure here never touches the node.

use crate::notes::{self, Entry};
use alloy_primitives::Address;
use e3_protocol::{node::Node, UnixSecs};
use serde::Serialize;
use std::{
    fmt::Write as _,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tracing::{info, warn};

const MAX_CONNECTIONS: usize = 8;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const ANSWER_LIMIT: Duration = Duration::from_secs(5);
const RECENT_NOTES: usize = 50;

/// What the page shows, kept current by the node.
#[derive(Clone)]
pub(crate) struct Board {
    operator: Address,
    chain_id: u64,
    head: Arc<AtomicU64>,
    read_to: Arc<AtomicU64>,
    peers: Arc<AtomicUsize>,
    machine: Arc<Mutex<Machine>>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Machine {
    active: bool,
    enabled: bool,
    e3s: Vec<HeldE3>,
}

#[derive(Clone, Debug, Serialize)]
struct HeldE3 {
    id: String,
    stage: String,
    owes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct Status {
    operator: String,
    chain_id: u64,
    head: u64,
    read_to: u64,
    peers: usize,
    active: bool,
    enabled: bool,
    e3s: Vec<HeldE3>,
    notes: Vec<Entry>,
}

impl Board {
    pub(crate) fn new(operator: Address, chain_id: u64) -> Self {
        Self {
            operator,
            chain_id,
            head: Arc::default(),
            read_to: Arc::default(),
            peers: Arc::default(),
            machine: Arc::default(),
        }
    }

    pub(crate) fn chain_read(&self, head: u64, read_to: u64) {
        self.head.store(head, Ordering::Relaxed);
        self.read_to.store(read_to, Ordering::Relaxed);
    }

    pub(crate) fn peers(&self, peers: usize) {
        self.peers.store(peers, Ordering::Relaxed);
    }

    pub(crate) fn machine(&self, node: &Node) {
        let (active, enabled) = node.standing(self.chain_id);
        let e3s = node
            .held()
            .filter_map(|id| {
                let state = node.e3(id)?;
                Some(HeldE3 {
                    id: id.to_string(),
                    stage: format!("{:?}", state.stage),
                    owes: state.owes(),
                })
            })
            .collect();
        *self.lock() = Machine {
            active,
            enabled,
            e3s,
        };
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Machine> {
        self.machine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn status(&self, notes: Vec<Entry>) -> Status {
        let machine = self.lock().clone();
        Status {
            operator: self.operator.to_string(),
            chain_id: self.chain_id,
            head: self.head.load(Ordering::Relaxed),
            read_to: self.read_to.load(Ordering::Relaxed),
            peers: self.peers.load(Ordering::Relaxed),
            active: machine.active,
            enabled: machine.enabled,
            e3s: machine.e3s,
            notes,
        }
    }
}

/// Serves the page on `port` of this machine until the node stops. A port in use costs the page.
pub(crate) async fn serve(port: u16, board: Board, notes: PathBuf) {
    match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(listener) => {
            info!(port, "node status at http://127.0.0.1:{port}");
            answer_on(listener, board, notes).await;
        }
        Err(error) => warn!(port, %error, "the status page could not start"),
    }
}

async fn answer_on(listener: TcpListener, board: Board, notes: PathBuf) {
    let places = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let Ok(place) = places.clone().try_acquire_owned() else {
            continue;
        };
        let (board, notes) = (board.clone(), notes.clone());
        tokio::spawn(async move {
            let _ = tokio::time::timeout(ANSWER_LIMIT, answer(socket, board, notes)).await;
            drop(place);
        });
    }
}

async fn answer(mut socket: TcpStream, board: Board, notes: PathBuf) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket.read(&mut buffer).await?;
        if read == 0 || request.len() + read > MAX_REQUEST_BYTES {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let first = request.split(|byte| *byte == b'\r').next().unwrap_or(&[]);
    let response = match first.split(|byte| *byte == b' ').collect::<Vec<_>>()[..] {
        [b"GET", path, _] => respond(path, &board, notes).await,
        _ => reply("405 Method Not Allowed", "text/plain", "only GET".into()),
    };
    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await
}

async fn respond(path: &[u8], board: &Board, notes: PathBuf) -> String {
    let recent = tokio::task::spawn_blocking(move || recent_notes(&notes))
        .await
        .unwrap_or_default();
    let status = board.status(recent);
    match path {
        b"/" => reply("200 OK", "text/html; charset=utf-8", page(&status)),
        b"/status.json" => {
            let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".into());
            reply("200 OK", "application/json", json)
        }
        _ => reply("404 Not Found", "text/plain", "not found".into()),
    }
}

fn recent_notes(dir: &std::path::Path) -> Vec<Entry> {
    let mut entries = notes::read(dir, 0, usize::MAX).unwrap_or_default();
    let skip = entries.len().saturating_sub(RECENT_NOTES);
    entries.drain(..skip);
    entries
}

fn reply(status: &str, content: &str, body: String) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content}\r\ncontent-length: {}\r\nconnection: \
         close\r\n\r\n{body}",
        body.len()
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn at(time: UnixSecs) -> String {
    time.to_string()
}

fn page(status: &Status) -> String {
    let mut held = String::new();
    for e3 in &status.e3s {
        let _ = write!(
            held,
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&e3.id),
            escape(&e3.stage),
            escape(&e3.owes.join(", "))
        );
    }
    if held.is_empty() {
        held.push_str("<tr><td colspan=3>none</td></tr>");
    }
    let mut noted = String::new();
    for entry in status.notes.iter().rev() {
        let _ = write!(
            noted,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            entry.sequence,
            at(entry.at),
            escape(&entry.note.e3.to_string()),
            escape(&entry.note.event.to_string())
        );
    }
    if noted.is_empty() {
        noted.push_str("<tr><td colspan=4>none</td></tr>");
    }
    let yes = |value: bool| if value { "yes" } else { "no" };
    format!(
        "<!doctype html><html><head><meta charset=utf-8><meta http-equiv=refresh content=5>\
         <title>Interfold node</title><style>\
         body{{font:15px system-ui,sans-serif;margin:24px;max-width:960px;color:#111;background:#fff}}\
         table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}\
         td,th{{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}\
         @media(prefers-color-scheme:dark){{body{{color:#eee;background:#16181c}}td,th{{border-color:#333}}}}\
         </style></head><body><h1>Interfold node</h1><table>\
         <tr><th>Operator</th><td>{operator}</td></tr>\
         <tr><th>Chain</th><td>{chain}, read to block {read_to} of {head}</td></tr>\
         <tr><th>Peers connected</th><td>{peers}</td></tr>\
         <tr><th>Active</th><td>{active}</td></tr>\
         <tr><th>Listed by the registry</th><td>{enabled}</td></tr></table>\
         <h2>E3s this node holds: {count}</h2><table><tr><th>E3</th><th>Stage</th>\
         <th>What it still owes</th></tr>{held}</table>\
         <h2>Recent notes</h2><table><tr><th>#</th><th>Time</th><th>E3</th><th>What happened</th>\
         </tr>{noted}</table></body></html>",
        operator = escape(&status.operator),
        chain = status.chain_id,
        read_to = status.read_to,
        head = status.head,
        peers = status.peers,
        active = yes(status.active),
        enabled = yes(status.enabled),
        count = status.e3s.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::NoteFeed;
    use alloy_primitives::U256;
    use e3_protocol::{
        node::{Note, Noted},
        proof::ProofType,
        E3Id,
    };
    use tokio::io::AsyncReadExt;

    async fn started(board: Board, notes: PathBuf) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(answer_on(listener, board, notes));
        port
    }

    async fn get(port: u16, request: &str) -> String {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        response
    }

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

    #[tokio::test]
    async fn the_page_shows_the_node_and_its_notes() {
        let dir = tempfile::tempdir().unwrap();
        NoteFeed::open(dir.path()).unwrap().record(5, note());
        let board = Board::new(Address::repeat_byte(9), 1);
        board.chain_read(100, 97);
        board.peers(4);
        let port = started(board, dir.path().to_path_buf()).await;
        let page = get(port, "GET / HTTP/1.1\r\n\r\n").await;
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert!(page.contains("read to block 97 of 100"), "{page}");
        assert!(page.contains("failing C0PkBfv proof"), "{page}");
        let json = get(port, "GET /status.json HTTP/1.1\r\n\r\n").await;
        let body = json.split("\r\n\r\n").nth(1).unwrap();
        let status: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(status["peers"], 4);
        assert_eq!(status["notes"][0]["sequence"], 1);
    }

    /// The page reads and changes nothing, whatever a client asks for.
    #[tokio::test]
    async fn only_reads_of_known_paths_are_answered() {
        let dir = tempfile::tempdir().unwrap();
        let port = started(Board::new(Address::ZERO, 1), dir.path().to_path_buf()).await;
        assert!(get(port, "POST / HTTP/1.1\r\n\r\n").await.contains("405"));
        assert!(get(port, "GET /elsewhere HTTP/1.1\r\n\r\n")
            .await
            .contains("404"));
    }

    #[test]
    fn what_a_note_says_cannot_write_markup() {
        assert_eq!(escape("<b>&"), "&lt;b&gt;&amp;");
    }
}
