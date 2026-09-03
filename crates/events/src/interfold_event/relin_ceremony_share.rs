// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// CKKS multiparty relinearization-key ceremony broadcast: ONE fixed-size
/// chunk of one party's round-1 or round-2 share for ONE multiplication
/// level. The two-round CRP protocol (eprint 2020/304 Protocol 2) runs
/// after the DKG converges; every party aggregates the same broadcasts,
/// so all honest parties derive identical joint keys.
///
/// Shares are chunked at the SEND side because a single per-level share
/// scales with the parameter set (~180 MiB at N=32768, L=20) and must
/// traverse gossip/DHT wire limits (10 MiB / 25 MiB). The receiver
/// buffers chunks per (party, round, level), verifies `payload_keccak`
/// over the complete reassembled payload, and only then ingests it.
#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct RelinCeremonyShare {
    pub e3_id: E3id,
    /// The sender's party_id (1-based Shamir id).
    pub party_id: u64,
    /// The sender's node address.
    pub node: String,
    /// Ceremony round this share belongs to (1 or 2).
    pub round: u8,
    /// Multiplication level this share is for.
    pub level: u32,
    /// 0-based index of this chunk within the per-(round, level) payload.
    pub chunk_index: u32,
    /// Total number of chunks the payload was split into (>= 1).
    pub chunk_count: u32,
    /// keccak256 of the COMPLETE reassembled per-(round, level) payload:
    /// integrity check after reassembly + dedupe key for re-deliveries.
    pub payload_keccak: [u8; 32],
    /// This chunk's bytes.
    #[derivative(Debug = "ignore")]
    pub chunk: ArcBytes,
    /// Whether this was received from the network.
    pub external: bool,
}

impl Display for RelinCeremonyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelinCeremonyShare(e3_id: {}, party: {}, round: {}, level: {}, chunk: {}/{})",
            self.e3_id,
            self.party_id,
            self.round,
            self.level,
            self.chunk_index + 1,
            self.chunk_count
        )
    }
}
