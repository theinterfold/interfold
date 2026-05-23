// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{error, info};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Start the dashboard HTTP server on the given port, proxying API calls to the daemon server.
/// `node_name` and `config_path` are included in proxied requests so the daemon loads the correct config.
pub async fn start_dashboard(
    dashboard_port: u16,
    ctrl_port: u16,
    node_name: String,
    config_path: Option<String>,
) {
    let mut port = dashboard_port;
    let listener = loop {
        let addr = format!("0.0.0.0:{}", port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(_) if port < dashboard_port + 10 => {
                port += 1;
            }
            Err(e) => {
                error!(
                    "Failed to bind dashboard socket (tried ports {}–{}): {}",
                    dashboard_port, port, e
                );
                return;
            }
        }
    };

    info!("Dashboard listening on http://0.0.0.0:{}", port);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ctrl = ctrl_port;
                let name = node_name.clone();
                let cfg = config_path.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = handle_request(stream, ctrl, &name, cfg.as_deref()).await {
                        error!("Dashboard connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Dashboard accept error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
}

fn parse_request_line(line: &str) -> Option<HttpRequest> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_uppercase();
    let raw_path = parts[1];

    let (path, query) = if let Some(idx) = raw_path.find('?') {
        let p = &raw_path[..idx];
        let q = parse_query_string(&raw_path[idx + 1..]);
        (p.to_string(), q)
    } else {
        (raw_path.to_string(), HashMap::new())
    };

    Some(HttpRequest {
        method,
        path,
        query,
    })
}

fn parse_query_string(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in qs.split('&') {
        if let Some(idx) = pair.find('=') {
            let key = &pair[..idx];
            let value = &pair[idx + 1..];
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

async fn handle_request(
    stream: TcpStream,
    ctrl_port: u16,
    node_name: &str,
    config_path: Option<&str>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read the request line
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let req = match parse_request_line(request_line.trim()) {
        Some(r) => r,
        None => {
            let resp = http_response("400 Bad Request", "text/plain", "Bad Request");
            writer.write_all(resp.as_bytes()).await?;
            writer.shutdown().await?;
            return Ok(());
        }
    };

    // Read remaining headers (we don't need them but must consume them)
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Handle OPTIONS for CORS preflight
    if req.method == "OPTIONS" {
        let resp = cors_preflight_response();
        writer.write_all(resp.as_bytes()).await?;
        writer.shutdown().await?;
        return Ok(());
    }

    let (status, content_type, body) = route(&req, ctrl_port, node_name, config_path).await;

    let resp = http_response_with_cors(&status, &content_type, &body);
    writer.write_all(resp.as_bytes()).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn route(
    req: &HttpRequest,
    ctrl_port: u16,
    node_name: &str,
    config_path: Option<&str>,
) -> (String, String, String) {
    if req.method == "GET" && req.path == "/" {
        return (
            "200 OK".to_string(),
            "text/html; charset=utf-8".to_string(),
            DASHBOARD_HTML.to_string(),
        );
    }

    if req.method != "GET" {
        return (
            "405 Method Not Allowed".to_string(),
            "text/plain".to_string(),
            "Method Not Allowed".to_string(),
        );
    }

    let command = match req.path.as_str() {
        "/api/events" => {
            let since = req.query.get("since").and_then(|v| v.parse::<u64>().ok());
            let limit = req.query.get("limit").and_then(|v| v.parse::<u64>().ok());
            let agg = req.query.get("agg").and_then(|v| v.parse::<usize>().ok());
            serde_json::json!({ "EventsQuery": { "agg": agg, "since": since, "limit": limit } })
        }
        "/api/config" => {
            let param = req.query.get("param").cloned();
            serde_json::json!({ "ConfigGet": { "param": param } })
        }
        "/api/status" => {
            let chain = req.query.get("chain").cloned();
            serde_json::json!({ "CiphernodeStatus": { "chain": { "chain": chain } } })
        }
        "/api/noir" => serde_json::json!("NoirStatus"),
        "/api/wallet" => serde_json::json!("WalletGet"),
        "/api/peer-id" => serde_json::json!("NetGetPeerId"),
        _ => {
            return (
                "404 Not Found".to_string(),
                "text/plain".to_string(),
                "Not Found".to_string(),
            );
        }
    };

    let json_body = serde_json::json!({
        "name": node_name,
        "config": config_path,
        "command": command,
        "verbose": 0,
        "quiet": false
    });

    match proxy_to_daemon(ctrl_port, &json_body).await {
        Ok(response) => (
            "200 OK".to_string(),
            "application/json".to_string(),
            response,
        ),
        Err(e) => (
            "502 Bad Gateway".to_string(),
            "text/plain".to_string(),
            format!("Failed to reach daemon: {}", e),
        ),
    }
}

async fn proxy_to_daemon(ctrl_port: u16, body: &serde_json::Value) -> anyhow::Result<String> {
    let url = format!("http://127.0.0.1:{}", ctrl_port);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    // Don't use error_for_status() — return the body even on 500
    // so the dashboard can display the actual error message.
    let text = resp.text().await?;
    Ok(text)
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    )
}

fn http_response_with_cors(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    )
}

fn cors_preflight_response() -> String {
    "HTTP/1.1 204 No Content\r\n\
     Access-Control-Allow-Origin: *\r\n\
     Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
     Access-Control-Allow-Headers: Content-Type\r\n\
     Access-Control-Max-Age: 86400\r\n\
     Connection: close\r\n\r\n"
        .to_string()
}
