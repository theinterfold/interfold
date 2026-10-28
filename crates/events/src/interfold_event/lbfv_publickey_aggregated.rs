// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, OrderedSet, Proof};
use actix::Message;
use alloy::primitives::Address;
use derivative::Derivative;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};

/// Secure-16384 public-key publication intent.
///
/// Like [`crate::PublicKeyAggregated`], it is forwarded to peers only when its key envelope fits
/// one gossip message or sync reply (9 MiB). The set-7 envelope does not, so its members take the
/// key from the confirmed on-chain key chunks, which are checked against the chain commitment.
#[derive(Derivative, Message, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
#[rtype(result = "()")]
pub struct LbfvPublicKeyAggregated {
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pubkey: ArcBytes,
    pub e3_id: E3id,
    pub nodes: OrderedSet<String>,
    pub committee_addresses: Vec<Address>,
    pub honest_committee_addresses: Vec<Address>,
    pub pk_commitment: [u8; 32],
    pub dkg_aggregator_v2_proof: Proof,
    #[serde(default)]
    pub dkg_attestation_bundle: Option<ArcBytes>,
}
