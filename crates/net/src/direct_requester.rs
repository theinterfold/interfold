// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fmt, marker::PhantomData, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use e3_events::CorrelationId;
use e3_utils::{retry_with_backoff, to_retry};
use tokio::sync::{broadcast, mpsc};

use crate::events::{
    call_and_await_response, NetCommand, NetEvent, OutgoingRequest, OutgoingRequestFailed,
    OutgoingRequestSucceeded, PeerTarget, ProtocolResponse,
};

pub trait DirectRequesterOutput: TryFrom<Vec<u8>> + Send + Sync + 'static {}

pub trait DirectRequesterInput:
    TryInto<Vec<u8>> + Clone + Send + Sync + fmt::Debug + 'static
{
}

impl<T> DirectRequesterOutput for T where T: TryFrom<Vec<u8>> + Send + Sync + 'static {}

impl<T> DirectRequesterInput for T where
    T: TryInto<Vec<u8>> + Clone + Send + Sync + fmt::Debug + 'static
{
}

pub struct WithoutPeer;
pub struct WithPeer(#[allow(dead_code)] PeerTarget);

/// DirectRequester is used to send direct requests to a specific peer.
///
/// # Example
///
/// ```ignore
/// use crate::net::direct_requester::DirectRequester;
/// use crate::events::PeerTarget;
/// use libp2p::PeerId;
///
/// // Create a requester with default settings
/// let requester = DirectRequester::builder(net_cmds, net_events)
///     .request_timeout(Duration::from_secs(30))
///     .max_retries(4)
///     .build();
///
/// // Target a specific peer (use Random to pick a random peer)
/// let peer_id: PeerId = "12D3KooWEZiPVmEZkwCFEWYxPL6xts6LnPHRFqsSEDGmt1vQ17By".parse().unwrap();
/// let peer_requester = requester.to(PeerTarget::Specific(peer_id));
///
/// // Make a request (any type implementing TryInto<Vec<u8>> and TryFrom<Vec<u8>> works)
/// let response: MyResponse = peer_requester.request(my_request).await?;
/// ```
pub struct DirectRequester<State> {
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    request_timeout: Duration,
    max_retries: u32,
    retry_timeout: Duration,
    peer: PeerTarget,
    _state: PhantomData<State>,
}

impl DirectRequester<WithoutPeer> {
    /// Creates a new DirectRequester builder.
    ///
    /// Default settings:
    /// - request_timeout: 30 seconds
    /// - max_retries: 4
    /// - retry_timeout: 5 seconds
    pub fn builder(
        net_cmds: mpsc::Sender<NetCommand>,
        net_events: Arc<broadcast::Receiver<NetEvent>>,
    ) -> DirectRequesterBuilder {
        DirectRequesterBuilder {
            net_cmds: Some(net_cmds),
            net_events: Some(net_events),
            request_timeout: Some(Duration::from_secs(30)),
            max_retries: Some(4),
            retry_timeout: Some(Duration::from_millis(5000)),
        }
    }

    /// Sets the target peer for requests.
    ///
    /// Use `PeerTarget::Random` to send to a random peer, or
    /// `PeerTarget::Specific(peer_id)` to target a specific peer.
    pub fn to(&self, peer: PeerTarget) -> DirectRequester<WithPeer> {
        DirectRequester {
            net_cmds: self.net_cmds.clone(),
            net_events: self.net_events.clone(),
            request_timeout: self.request_timeout,
            max_retries: self.max_retries,
            retry_timeout: self.retry_timeout,
            peer,
            _state: PhantomData,
        }
    }
}

impl DirectRequester<WithPeer> {
    /// Sends a direct request to the peer and waits for a response.
    ///
    /// The request type must implement `TryInto<Vec<u8>>` with `Clone + Send + Sync + Debug`.
    /// The response type must implement `TryFrom<Vec<u8>>`.
    ///
    /// # Errors
    ///
    /// Returns an error if request serialization fails, the peer responds with an error,
    /// or if the request times out after retries.
    pub async fn request<T, R>(&self, request: R) -> Result<T>
    where
        T: DirectRequesterOutput,
        R: DirectRequesterInput,
    {
        let payload: Vec<u8> = request
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Request serialization failed for request: {:?}", request))?;

        let response = self.request_with_retry(payload).await?;

        match response {
            ProtocolResponse::Ok(data) => Ok(data
                .try_into()
                .map_err(|_| anyhow!("Could not deserialize ProtocolResponse"))?),
            ProtocolResponse::BadRequest(msg) => Err(anyhow!("BadRequest: {}", msg)),
            ProtocolResponse::Error(msg) => Err(anyhow!("ProtocolError: {}", msg)),
        }
    }

    async fn request_with_retry(&self, payload: Vec<u8>) -> Result<ProtocolResponse> {
        let request_timeout = self.request_timeout;
        let peer = self.peer;
        retry_with_backoff(
            || {
                let net_cmds = self.net_cmds.clone();
                let net_events = self.net_events.clone();
                let payload = payload.clone();
                async move {
                    do_request(net_cmds, net_events, peer, payload, request_timeout)
                        .await
                        .map_err(to_retry)
                }
            },
            self.max_retries,
            self.retry_timeout.as_millis() as u64,
        )
        .await
    }
}

pub struct DirectRequesterBuilder {
    net_cmds: Option<mpsc::Sender<NetCommand>>,
    net_events: Option<Arc<broadcast::Receiver<NetEvent>>>,
    request_timeout: Option<Duration>,
    max_retries: Option<u32>,
    retry_timeout: Option<Duration>,
}

impl DirectRequesterBuilder {
    /// Sets the timeout for each request attempt.
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = Some(request_timeout);
        self
    }

    /// Sets the maximum number of retry attempts.
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Sets the timeout between retry attempts.
    pub fn retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.retry_timeout = Some(retry_timeout);
        self
    }

    pub fn build(self) -> DirectRequester<WithoutPeer> {
        DirectRequester {
            net_cmds: self.net_cmds.expect("net_cmds is required"),
            net_events: self.net_events.expect("net_events is required"),
            request_timeout: self.request_timeout.unwrap_or(Duration::from_secs(30)),
            max_retries: self.max_retries.unwrap_or(4),
            retry_timeout: self.retry_timeout.unwrap_or(Duration::from_millis(5000)),
            peer: PeerTarget::Random,
            _state: PhantomData,
        }
    }
}

async fn do_request(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    target: PeerTarget,
    payload: Vec<u8>,
    timeout: Duration,
) -> Result<ProtocolResponse> {
    let correlation_id = CorrelationId::new();

    let response = call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::OutgoingRequest(OutgoingRequest {
            correlation_id,
            payload,
            target,
        }),
        |e| match e {
            NetEvent::OutgoingRequestSucceeded(value) => {
                if value.correlation_id == correlation_id {
                    Some(Ok(value.payload.clone()))
                } else {
                    None
                }
            }
            NetEvent::OutgoingRequestFailed(value) => {
                if value.correlation_id == correlation_id {
                    Some(Err(anyhow!("Request failed: {}", value.error)))
                } else {
                    None
                }
            }
            _ => None,
        },
        timeout,
    )
    .await
    .map_err(|e| anyhow!("Request failed: {}", e))?;

    Ok(response)
}

#[allow(dead_code)]
struct Expectation {
    expected_request: Vec<u8>,
    response: Result<Vec<u8>, String>,
}

#[allow(dead_code)]
pub(crate) struct DirectRequesterTester {
    net_cmds_rx: mpsc::Receiver<NetCommand>,
    net_events_tx: broadcast::Sender<NetEvent>,
    respond_with: Option<Vec<u8>>,
    responses: Vec<Vec<u8>>,
    expectations: Vec<Expectation>,
    error_on: Option<String>,
    num_requests: Option<usize>,
}

#[allow(dead_code)]
pub(crate) struct ExpectationBuilder {
    tester: DirectRequesterTester,
    expected_request: Vec<u8>,
}

impl ExpectationBuilder {
    #[allow(dead_code)]
    pub fn respond_with<T: TryInto<Vec<u8>>>(mut self, payload: T) -> DirectRequesterTester
    where
        <T as TryInto<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.tester.expectations.push(Expectation {
            expected_request: self.expected_request,
            response: Ok(payload.try_into().unwrap()),
        });
        self.tester
    }

    #[allow(dead_code)]
    pub fn error_with(mut self, error: impl Into<String>) -> DirectRequesterTester {
        self.tester.expectations.push(Expectation {
            expected_request: self.expected_request,
            response: Err(error.into()),
        });
        self.tester
    }
}

#[allow(dead_code)]
impl DirectRequesterTester {
    pub fn new(
        net_cmds_rx: mpsc::Receiver<NetCommand>,
        net_events_tx: broadcast::Sender<NetEvent>,
    ) -> Self {
        Self {
            net_cmds_rx,
            net_events_tx,
            respond_with: None,
            responses: Vec::new(),
            expectations: Vec::new(),
            error_on: None,
            num_requests: None,
        }
    }

    pub fn expect_request<T: TryInto<Vec<u8>>>(self, payload: T) -> ExpectationBuilder
    where
        <T as TryInto<Vec<u8>>>::Error: std::fmt::Debug,
    {
        ExpectationBuilder {
            tester: self,
            expected_request: payload.try_into().unwrap(),
        }
    }

    pub fn respond_with<T: TryInto<Vec<u8>>>(mut self, payload: T) -> Self
    where
        <T as TryInto<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.respond_with = Some(payload.try_into().unwrap());
        self
    }

    pub fn respond_with_each<T: TryInto<Vec<u8>>>(
        mut self,
        payloads: impl IntoIterator<Item = T>,
    ) -> Self
    where
        <T as TryInto<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.responses = payloads
            .into_iter()
            .map(|p| p.try_into().unwrap())
            .collect();
        self
    }

    pub fn error_with(mut self, error: impl Into<String>) -> Self {
        self.error_on = Some(error.into());
        self
    }

    pub fn num_requests(mut self, n: usize) -> Self {
        self.num_requests = Some(n);
        self
    }

    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        let num_requests = self.num_requests.unwrap_or({
            if !self.expectations.is_empty() {
                self.expectations.len()
            } else {
                usize::MAX
            }
        });
        // Reverse expectations so we can pop from the back in order.
        self.expectations.reverse();
        self.responses.reverse();

        tokio::spawn(async move {
            let mut remaining = num_requests;
            while remaining > 0 {
                if let Some(cmd) = self.net_cmds_rx.recv().await {
                    if let NetCommand::OutgoingRequest(req) = cmd {
                        remaining -= 1;
                        let response = if let Some(expectation) = self.expectations.pop() {
                            assert_eq!(
                                req.payload, expectation.expected_request,
                                "DirectRequesterTester: expected request {:?} but got {:?}",
                                expectation.expected_request, req.payload,
                            );
                            match expectation.response {
                                Ok(payload) => {
                                    NetEvent::OutgoingRequestSucceeded(OutgoingRequestSucceeded {
                                        payload: ProtocolResponse::Ok(payload),
                                        correlation_id: req.correlation_id,
                                    })
                                }
                                Err(error) => {
                                    NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
                                        error,
                                        correlation_id: req.correlation_id,
                                    })
                                }
                            }
                        } else if let Some(payload) = self.respond_with.clone() {
                            NetEvent::OutgoingRequestSucceeded(OutgoingRequestSucceeded {
                                payload: ProtocolResponse::Ok(payload),
                                correlation_id: req.correlation_id,
                            })
                        } else if let Some(payload) = self.responses.pop() {
                            NetEvent::OutgoingRequestSucceeded(OutgoingRequestSucceeded {
                                payload: ProtocolResponse::Ok(payload),
                                correlation_id: req.correlation_id,
                            })
                        } else if let Some(error) = self.error_on.clone() {
                            NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
                                error,
                                correlation_id: req.correlation_id,
                            })
                        } else {
                            panic!("DirectRequesterTester: no response configured");
                        };
                        let _ = self.net_events_tx.send(response);
                    }
                } else {
                    break;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::PeerTarget;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_successful_request() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .respond_with(b"world".to_vec())
            .num_requests(1)
            .spawn();

        let response: Vec<u8> = requester
            .to(PeerTarget::Random)
            .request(b"hello".to_vec())
            .await
            .unwrap();

        handle.await.unwrap();

        assert_eq!(response, b"world");
    }

    #[tokio::test]
    async fn test_request_with_peer_target() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .respond_with(b"pong".to_vec())
            .num_requests(1)
            .spawn();

        let _: Vec<u8> = requester
            .to(PeerTarget::Random)
            .request(b"ping".to_vec())
            .await
            .unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_peer_requester_reuse_across_requests() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events)
            .request_timeout(Duration::from_secs(10))
            .max_retries(3)
            .retry_timeout(Duration::from_secs(5))
            .build();

        let peer_requester = requester.to(PeerTarget::Random);

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .respond_with(b"ok".to_vec())
            .num_requests(2)
            .spawn();

        let response1: Vec<u8> = peer_requester.request(b"first".to_vec()).await.unwrap();
        let response2: Vec<u8> = peer_requester.request(b"second".to_vec()).await.unwrap();

        handle.await.unwrap();

        assert_eq!(response1, b"ok");
        assert_eq!(response2, b"ok");
    }

    #[tokio::test]
    async fn test_expect_request() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .expect_request(b"hello".to_vec())
            .respond_with(b"world".to_vec())
            .expect_request(b"ping".to_vec())
            .respond_with(b"pong".to_vec())
            .spawn();

        let peer = requester.to(PeerTarget::Random);

        let r1: Vec<u8> = peer.request(b"hello".to_vec()).await.unwrap();
        let r2: Vec<u8> = peer.request(b"ping".to_vec()).await.unwrap();

        handle.await.unwrap();

        assert_eq!(r1, b"world");
        assert_eq!(r2, b"pong");
    }

    #[tokio::test]
    async fn test_request_failure() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events)
            .max_retries(0)
            .build();

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .error_with("connection refused")
            .num_requests(1)
            .spawn();

        let result: std::result::Result<Vec<u8>, _> = requester
            .to(PeerTarget::Random)
            .request(b"hello".to_vec())
            .await;

        handle.await.unwrap();

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("connection refused"));
    }

    #[tokio::test]
    async fn test_respond_with_each() {
        let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
        let (net_events_tx, net_events_rx) = broadcast::channel::<NetEvent>(16);
        let net_events = Arc::new(net_events_rx);

        let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

        let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
            .respond_with_each(vec![
                b"first_response".to_vec(),
                b"second_response".to_vec(),
                b"third_response".to_vec(),
            ])
            .num_requests(3)
            .spawn();

        let peer = requester.to(PeerTarget::Random);

        let r1: Vec<u8> = peer.request(b"req1".to_vec()).await.unwrap();
        let r2: Vec<u8> = peer.request(b"req2".to_vec()).await.unwrap();
        let r3: Vec<u8> = peer.request(b"req3".to_vec()).await.unwrap();

        handle.await.unwrap();

        assert_eq!(r1, b"first_response");
        assert_eq!(r2, b"second_response");
        assert_eq!(r3, b"third_response");
    }
}
