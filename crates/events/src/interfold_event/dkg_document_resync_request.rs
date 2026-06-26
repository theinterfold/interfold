// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Gossiped by a node resuming an in-flight DKG after a restart, asking committee peers to
/// re-announce the DKG documents (BFV encryption keys, threshold shares, decryption-key shares)
/// they already published for `e3_id`.
///
/// DKG share documents travel over the Kademlia DHT, announced once via an ephemeral
/// `DocumentPublishedNotification` gossip. A node that was down when a peer first announced its
/// document never learned the (content-addressed) DHT key and cannot recompute it, so it can never
/// fetch that share — the document re-broadcast in `resume_in_flight_work` only re-emits a node's
/// *own* outputs, not the inbound peers' shares. This request closes that gap: alive committee
/// members re-announce their documents for `e3_id` (the DHT records are still present), letting the
/// rejoining node fetch the shares it missed. Re-announcing is idempotent (content-addressed DHT,
/// receivers dedup by sender `party_id`).
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DkgDocumentResyncRequest {
    pub e3_id: E3id,
    /// Address of the requesting node — informational, for logging / future targeting.
    pub requester: String,
}

impl Display for DkgDocumentResyncRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DkgDocumentResyncRequest {{ e3_id: {}, requester: {} }}",
            self.e3_id, self.requester
        )
    }
}
