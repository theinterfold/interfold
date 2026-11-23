// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, bail, Result};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use serde::Serialize;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{tcp::OwnedReadHalf, TcpStream};
use tokio::time::timeout;
use tracing::error;

const TCP_ADDRESS: &str = "127.0.0.1"; // using localhost specifically so that it is not mounted
                                       // externally. We might change this if we need to control
                                       // externally and add authentication or TLS

/// The CLI sends a few short headers and one small serialized command. These bounds sit far above
/// that, so a stuck or oversized local client cannot hold a connection task or the node's memory.
const MAX_HEAD_BYTES: u64 = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const READ_LIMIT: Duration = Duration::from_secs(10);

pub struct ServerInfo {
    pub port: u16,
}

pub async fn connect_daemon(maybe_config: Option<&NodeConfig>) -> Option<ServerInfo> {
    let config = maybe_config?;
    let port = config.ctrl_port();
    let url = format!("http://{}:{}", TCP_ADDRESS, port);
    reqwest::Client::new()
        .head(&url)
        .timeout(std::time::Duration::from_secs(1))
        .send()
        .await
        .ok()?;
    Some(ServerInfo { port })
}

pub async fn run_on_daemon<T: Serialize>(
    out: Console,
    server: ServerInfo,
    cli: T,
) -> anyhow::Result<()> {
    let url = format!("http://{}:{}", TCP_ADDRESS, server.port);
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&cli).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    // The node answers an error with its message, which says more than the status code.
    if !status.is_success() {
        bail!("The running node could not run the command: {text}");
    }
    for line in text.lines() {
        log!(out, "{}", line);
    }
    Ok(())
}

pub async fn start_daemon_server<F, Fut>(tcp_port: u16, handler: F)
where
    F: Fn(String) -> Fut + 'static,
    Fut: Future<Output = Result<String>> + 'static,
{
    let addr = format!("{}:{}", TCP_ADDRESS, tcp_port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind socket: {e}");
            return;
        }
    };
    let handler = Arc::new(handler);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let handler = Arc::clone(&handler);
                tokio::task::spawn_local(async move {
                    if let Err(e) = handle_http(stream, &handler.as_ref()).await {
                        error!("Connection error: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_http<F, Fut>(stream: TcpStream, handler: &F) -> Result<()>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    // We do manual http parsing as actix-web requires running on a separate thread and is too heavy
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let (status, response_body) = match timeout(READ_LIMIT, read_body(&mut reader)).await {
        Err(_) => (
            "408 Request Timeout",
            "the request took too long".to_string(),
        ),
        Ok(Err(e)) => ("400 Bad Request", e.to_string()),
        Ok(Ok(body)) => match handler(body).await {
            Ok(output) => ("200 OK", output),
            Err(e) => ("500 Internal Server Error", e.to_string()),
        },
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    writer.write_all(response.as_bytes()).await?;
    writer.shutdown().await?;
    Ok(())
}

/// Reads the headers up to the blank line, then the body their content length names. Both are
/// bounded before anything is allocated for them.
async fn read_body(reader: &mut BufReader<OwnedReadHalf>) -> Result<String> {
    let mut content_length: usize = 0;
    let mut head = (&mut *reader).take(MAX_HEAD_BYTES);
    loop {
        let mut line = String::new();
        head.read_line(&mut line).await?;
        if !line.ends_with('\n') && head.limit() == 0 {
            bail!("the request's headers are longer than {MAX_HEAD_BYTES} bytes");
        }
        if line.trim().is_empty() {
            break;
        }
        if let Some(val) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = val
                .trim()
                .parse()
                .map_err(|_| anyhow!("the request's content length is not a number"))?;
        }
    }
    if content_length > MAX_BODY_BYTES {
        bail!("the request's body is longer than {MAX_BODY_BYTES} bytes");
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;
    Ok(String::from_utf8(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tokio::net::TcpListener;

    /// Serves one connection on a loopback port with a handler that echoes the command, and counts
    /// how often the handler ran.
    async fn serve_once(listener: TcpListener, calls: &Cell<usize>) {
        let (stream, _) = listener.accept().await.unwrap();
        let echo = |body: String| {
            calls.set(calls.get() + 1);
            async move { Ok(format!("ran {body}")) }
        };
        handle_http(stream, &echo).await.unwrap();
    }

    async fn listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind((TCP_ADDRESS, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Sends `request` as it is and returns the whole response.
    async fn send_raw(port: u16, request: &[u8]) -> String {
        let mut stream = TcpStream::connect((TCP_ADDRESS, port)).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn a_command_reaches_the_handler_and_its_output_the_client() {
        let (listener, port) = listener().await;
        let calls = Cell::new(0);
        let (out, mut lines) = Console::channel();
        let client = run_on_daemon(out, ServerInfo { port }, "status");
        let ((), sent) = tokio::join!(serve_once(listener, &calls), client);
        sent.unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(lines.recv().await.unwrap(), "ran \"status\"");
    }

    #[tokio::test]
    async fn a_body_past_the_limit_is_refused_before_it_is_read() {
        let (listener, port) = listener().await;
        let calls = Cell::new(0);
        let request = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let ((), response) = tokio::join!(
            serve_once(listener, &calls),
            send_raw(port, request.as_bytes())
        );
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
        assert_eq!(calls.get(), 0);
    }

    #[tokio::test]
    async fn headers_past_the_limit_are_refused() {
        let (listener, port) = listener().await;
        let calls = Cell::new(0);
        let request = vec![b'a'; MAX_HEAD_BYTES as usize];
        let ((), response) = tokio::join!(serve_once(listener, &calls), send_raw(port, &request));
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
        assert_eq!(calls.get(), 0);
    }
}
