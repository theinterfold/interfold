// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::events::{IncomingResponse, NetCommand, ProtocolResponse};
use anyhow::{anyhow, Context, Result};
use e3_utils::OnceTake;
use libp2p::request_response::{InboundRequestId, ResponseChannel};
use tokio::sync::mpsc;

/// Helper trait to extract id from libp2p things like InboundRequestId
pub trait IntoId {
    fn into_id(self) -> u64;
}

impl IntoId for u64 {
    fn into_id(self) -> u64 {
        self
    }
}

impl IntoId for InboundRequestId {
    fn into_id(self) -> u64 {
        format!("{:?}", self)
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .expect("Failed to extract u64 from InboundRequestId")
    }
}

#[derive(Debug)]
pub enum ChannelType {
    Test(String),                               // For testing
    Channel(ResponseChannel<ProtocolResponse>), // actual libp2p response channel
}

#[derive(Debug, Clone)]
/// DirectResponder is used to respond to incoming libp2p requests.
///
/// # Example
///
/// ```
/// # use tokio::sync::mpsc;
/// use e3_net::direct_responder::DirectResponder;
/// # use e3_net::direct_responder::ChannelType;
/// # fn main() -> anyhow::Result<()> {
/// # let request_id = 6;
/// # let channel_orig = ChannelType::Test("channel".to_string());
/// # let channel = ChannelType::Test("channel".to_string());
/// # let (cmd_tx, _rx) = mpsc::channel(400);
///
/// // We create a responder and send it over our event channel
/// let responder = DirectResponder::new(
///   // request_id comes from libp2p anything that looks like a u64 will work
///   request_id,
///   // Likely ResponseChannel<ProtocolResponse> from libp2p event but does not matter will just get passed on
///   channel,
///   // Our NetCommand channel Sender
///   &cmd_tx
/// );
///
/// // Now in our handlers we can respond with ok() or bad_request() this will consume the responder
/// responder.ok(String::from("Something that implements TryInto<Vec<u8>>"))?;
/// # let responder = DirectResponder::new(request_id, channel_orig, &cmd_tx);
/// // or
/// responder.bad_request("It was pretty bad.")?;
/// # Ok(())
/// # }
/// ```
pub struct DirectResponder {
    id: u64,
    request: Vec<u8>,
    response: Option<ProtocolResponse>,
    channel: OnceTake<ChannelType>,
    net_cmds: mpsc::Sender<NetCommand>,
}

impl DirectResponder {
    /// Creates a new responder for an incoming request.
    ///
    /// * `id` - is the request identifier used for debugging (e.g., `InboundRequestId` or `u64`).
    /// * `channel` - is usually the response channel provided by libp2p but can be anything that is passed along with the response
    /// * `net_cmds` - sender is used to send the response back to the net interface.
    pub fn new(id: impl IntoId, channel: ChannelType, net_cmds: &mpsc::Sender<NetCommand>) -> Self {
        Self {
            id: id.into_id(),
            request: Vec::new(),
            response: None,
            channel: OnceTake::new(channel),
            net_cmds: net_cmds.clone(),
        }
    }

    /// Sets the request data on the responder.
    ///
    /// This should be called when creating a responder for an incoming request,
    /// passing the raw request bytes.
    pub fn with_request(mut self, request: Vec<u8>) -> Self {
        self.request = request;
        self
    }

    /// Get the request data
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Get the request data
    pub fn try_request_into<T>(&self) -> Result<T>
    where
        T: TryFrom<Vec<u8>>,
    {
        self.request
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Could not serialize request bytes"))
    }

    /// Extract the payload information to send to swarm
    pub fn to_response(mut self) -> Result<(ChannelType, ProtocolResponse)> {
        let channel = self.channel.try_take()?;
        let response = self
            .response
            .take()
            .context("No response found on responder")?;
        Ok((channel, response))
    }

    /// Consumes self and responds
    pub fn respond(mut self, value: ProtocolResponse) -> Result<()> {
        let response = value;
        self.response = Some(response);
        let cmds = self.net_cmds.clone();
        let incoming = IncomingResponse::new(self);
        cmds.clone()
            .try_send(NetCommand::IncomingResponse(incoming))
            .map_err(|e| anyhow!("Failed to send response command {:?}", e))
    }

    /// Request is ok returning response
    pub fn ok<T: TryInto<Vec<u8>>>(self, data: T) -> Result<()> {
        let bytes: Vec<u8> = data
            .try_into()
            .map_err(|_| anyhow!("Could not serialize response."))?;
        self.respond(ProtocolResponse::Ok(bytes))
    }

    /// Return a bad request
    pub fn bad_request(self, reason: impl Into<String>) -> Result<()> {
        self.respond(ProtocolResponse::BadRequest(reason.into()))
    }

    /// Get the id (for logging purposes)
    pub fn id(&self) -> u64 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use tokio::sync::mpsc;

    fn make_responder() -> (DirectResponder, mpsc::Receiver<NetCommand>) {
        let (tx, rx) = mpsc::channel::<NetCommand>(16);
        let responder =
            DirectResponder::new(42u64, ChannelType::Test("test_channel".to_string()), &tx);
        (responder, rx)
    }

    fn extract_response(rx: &mut mpsc::Receiver<NetCommand>) -> Result<(String, ProtocolResponse)> {
        let cmd = rx.try_recv().unwrap();
        match cmd {
            NetCommand::IncomingResponse(incoming) => {
                let (channel, response) = incoming.responder.to_response().unwrap();
                let ChannelType::Test(channel) = channel else {
                    bail!("bad channel");
                };
                Ok((channel, response))
            }

            other => panic!("Expected IncomingResponse, got {:?}", other),
        }
    }

    #[test]
    fn to_response_fails_without_response_set() {
        let (responder, _rx) = make_responder();
        assert!(responder.to_response().is_err());
    }

    #[test]
    fn channel_can_only_be_taken_once() {
        let (mut responder, _rx) = make_responder();
        responder.response = Some(ProtocolResponse::Ok(Vec::new()));
        let cloned = responder.clone();
        let _ = responder.to_response().unwrap();
        assert!(cloned.to_response().is_err());
    }

    #[test]
    fn ok_sends_serialized_payload() {
        let (responder, mut rx) = make_responder();
        responder.ok(b"foo".to_vec()).unwrap();
        let (channel, response) = extract_response(&mut rx).unwrap();
        assert_eq!(channel, "test_channel");
        assert!(matches!(response, ProtocolResponse::Ok(v) if v == b"foo"));
    }

    #[test]
    fn respond_sends_bad_request() {
        let (responder, mut rx) = make_responder();
        responder.bad_request("bad").unwrap();
        let (channel, response) = extract_response(&mut rx).unwrap();
        assert_eq!(channel, "test_channel");
        assert!(matches!(response, ProtocolResponse::BadRequest(r) if r == "bad"));
    }

    #[test]
    fn respond_fails_when_receiver_dropped() {
        let (responder, rx) = make_responder();
        drop(rx);
        assert!(responder.respond(ProtocolResponse::Ok(vec![])).is_err());
    }
}
