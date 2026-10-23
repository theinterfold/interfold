// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use e3_config::AppConfig;
use e3_console::{log, Console};
use serde::Serialize;
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::error;

const TCP_ADDRESS: &str = "127.0.0.1"; // using localhost specifically so that it is not mounted
                                       // externally. We might change this if we need to control
                                       // externally and add authentication or TLS

pub struct ServerInfo {
    pub port: u16,
}

pub async fn connect_daemon(maybe_config: Option<&AppConfig>) -> Option<ServerInfo> {
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
    let mut buf_reader = BufReader::new(reader);

    // Read headers until blank line
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        if let Some(val) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    // Read body
    let mut body = vec![0u8; content_length];
    tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;
    let body = String::from_utf8(body)?;

    // Run the existing logic
    let (status, response_body) = match handler(body).await {
        Ok(output) => ("200 OK", output),
        Err(e) => ("500 Internal Server Error", e.to_string()),
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
