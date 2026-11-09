// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The one place that opens a connection to a chain node. A connection never decides that the chain
//! is gone: it keeps trying, and each caller's own time limit decides how long that caller waits.

use crate::RpcError;
use alloy::{
    pubsub::{ConnectionHandle, PubSubConnect},
    rpc::client::{ClientBuilder, RpcClient},
    transports::{
        http::reqwest::{
            header::{HeaderMap, HeaderValue, AUTHORIZATION},
            Client, Url,
        },
        ws::{WebSocketConfig, WsConnect},
        Authorization, TransportErrorKind, TransportResult,
    },
};
use std::time::Duration;

/// A frame or message larger than this ends the connection. A log request's window and a key chunk
/// stay far below it, and it stops one reply from taking the node's memory.
const LARGEST_WS_MESSAGE: usize = 32 * 1024 * 1024;

/// The longest one attempt to open a WebSocket may take. A handshake that never finishes would
/// otherwise hold the reconnection for good.
const CONNECT_LIMIT: Duration = Duration::from_secs(30);

/// The wait between attempts to reopen a WebSocket.
#[cfg(not(test))]
const RECONNECT_EVERY: Duration = Duration::from_secs(3);
#[cfg(test)]
const RECONNECT_EVERY: Duration = Duration::from_millis(5);

/// The longest an HTTP request may take. A chain node can hold a request without ever answering; a
/// send or a read then fails, and its caller tries again.
const HTTP_ANSWER: Duration = Duration::from_secs(60);

/// Where a chain node is and how to reach it.
#[derive(Clone)]
pub struct Endpoint {
    url: String,
    auth: Option<Authorization>,
    poll: Duration,
}

impl Endpoint {
    /// `url` is `http(s)://` or `ws(s)://`. `auth` is sent with every request, and clients made
    /// here poll every `poll`.
    pub fn new(url: impl Into<String>, auth: Option<Authorization>, poll: Duration) -> Self {
        Self {
            url: url.into(),
            auth,
            poll,
        }
    }

    /// A connection in the URL's own transport, for reading.
    pub async fn connect(&self) -> Result<RpcClient, RpcError> {
        if !self.url.starts_with("ws://") && !self.url.starts_with("wss://") {
            return self.http();
        }
        let limits = WebSocketConfig::default()
            .max_frame_size(Some(LARGEST_WS_MESSAGE))
            .max_message_size(Some(LARGEST_WS_MESSAGE));
        let connect = WsConnect::new(self.url.clone())
            .with_config(limits)
            .with_auth_opt(self.auth.clone())
            .with_max_retries(u32::MAX)
            .with_retry_interval(RECONNECT_EVERY);
        let client = ClientBuilder::default()
            .pubsub(Limited(connect))
            .await
            .map_err(RpcError::new)?;
        Ok(client.with_poll_interval(self.poll))
    }

    /// A connection over HTTP to the same node, which serves HTTP where it serves a WebSocket, for
    /// sending. Over a WebSocket, a receipt wait would keep a new-block subscription open for good;
    /// over HTTP it polls only while a transaction is unmined.
    pub fn http(&self) -> Result<RpcClient, RpcError> {
        let url = http_url(&self.url)?;
        let mut headers = HeaderMap::new();
        if let Some(auth) = &self.auth {
            let mut value = HeaderValue::from_str(&auth.to_string()).map_err(RpcError::new)?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        let client = Client::builder()
            .default_headers(headers)
            .timeout(HTTP_ANSWER)
            .build()
            .map_err(RpcError::new)?;
        Ok(ClientBuilder::default()
            .http_with_client(client, url)
            .with_poll_interval(self.poll))
    }
}

/// The HTTP form of `url`, keeping TLS and the path, which often carries the provider's key.
fn http_url(url: &str) -> Result<Url, RpcError> {
    let mut url: Url = url.parse().map_err(RpcError::new)?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => return Ok(url),
    };
    if url.set_scheme(scheme).is_err() {
        return Err(RpcError("the RPC URL has no HTTP form".into()));
    }
    Ok(url)
}

/// A WebSocket whose every attempt to open has a time limit.
struct Limited(WsConnect);

impl PubSubConnect for Limited {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    async fn connect(&self) -> TransportResult<ConnectionHandle> {
        tokio::time::timeout(CONNECT_LIMIT, self.0.connect())
            .await
            .map_err(|_| TransportErrorKind::custom_str("opening the WebSocket timed out"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::providers::{Provider, ProviderBuilder};
    use futures::{SinkExt, StreamExt};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };
    use tokio_tungstenite::tungstenite::Message;

    const POLL: Duration = Duration::from_millis(250);

    /// Answers every WebSocket request with chain ID 31337, on `listener`, until aborted.
    fn serve_websocket(listener: TcpListener) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut sockets = Vec::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                sockets.push(tokio::spawn(async move {
                    let Ok(mut socket) = tokio_tungstenite::accept_async(socket).await else {
                        return;
                    };
                    while let Some(Ok(message)) = socket.next().await {
                        let Message::Text(text) = message else {
                            continue;
                        };
                        let request: Value = serde_json::from_str(&text).unwrap();
                        let answer =
                            json!({"jsonrpc": "2.0", "id": request["id"], "result": "0x7a69"});
                        if socket
                            .send(Message::Text(answer.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }));
                sockets.retain(|socket| !socket.is_finished());
            }
        })
    }

    async fn local_websocket() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        (listener.local_addr().unwrap(), serve_websocket(listener))
    }

    /// An outage far longer than alloy's default of 10 attempts leaves the connection usable.
    #[tokio::test]
    async fn a_websocket_comes_back_after_a_long_outage() {
        let (address, server) = local_websocket().await;
        let endpoint = Endpoint::new(format!("ws://{address}"), None, POLL);
        let provider = ProviderBuilder::new().connect_client(endpoint.connect().await.unwrap());
        assert_eq!(provider.get_chain_id().await.unwrap(), 31337);

        server.abort();
        let _ = server.await;
        // Long enough for 40 attempts or so to fail.
        tokio::time::sleep(RECONNECT_EVERY * 40).await;

        let listener = TcpListener::bind(address).await.unwrap();
        let _server = serve_websocket(listener);
        let answered = tokio::time::timeout(Duration::from_secs(20), provider.get_block_number());
        // The server answers every method alike, so the hex is the block number too.
        assert_eq!(answered.await.unwrap().unwrap(), 31337);
    }

    /// A server that takes the connection and never finishes the handshake does not hold the node.
    #[tokio::test(start_paused = true)]
    async fn a_handshake_that_never_finishes_fails_in_time() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let _silent = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let endpoint = Endpoint::new(format!("ws://{address}"), None, POLL);
        assert!(endpoint.connect().await.is_err());
    }

    /// An RPC node that asks for credentials gets them with each request.
    #[tokio::test]
    async fn the_rpc_node_gets_the_configured_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let node = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            let body = loop {
                let read = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some((_, body)) = text.split_once("\r\n\r\n") {
                    if let Ok(body) = serde_json::from_str::<Value>(body) {
                        break body;
                    }
                }
            };
            let answer =
                json!({ "jsonrpc": "2.0", "id": body["id"], "result": "0x7a69" }).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{answer}",
                answer.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request).to_lowercase()
        });
        let endpoint = Endpoint::new(url, Some(Authorization::bearer("secret")), POLL);
        let client = endpoint.connect().await.unwrap();
        let chain_id = ProviderBuilder::new()
            .connect_client(client)
            .get_chain_id()
            .await
            .unwrap();
        assert_eq!(chain_id, 31337);
        assert!(node.await.unwrap().contains("authorization: bearer secret"));
    }

    /// The wallet sends over HTTP to the RPC node the reader reads over a WebSocket, still over
    /// TLS and on the same path.
    #[test]
    fn a_websocket_url_s_http_form_keeps_tls_and_the_path() {
        let form = |url: &str| http_url(url).unwrap().to_string();
        assert_eq!(form("ws://127.0.0.1:8545"), "http://127.0.0.1:8545/");
        assert_eq!(
            form("wss://eth.example/v2/key?x=1"),
            "https://eth.example/v2/key?x=1"
        );
        assert_eq!(
            form("https://eth.example/v2/key"),
            "https://eth.example/v2/key"
        );
    }
}
