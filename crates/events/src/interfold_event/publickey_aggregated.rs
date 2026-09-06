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
use std::fmt::{self, Display};

#[derive(Derivative, Message, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
#[rtype(result = "()")]
/// Durable intent to publish the aggregated public key on-chain and distribute it to the committee.
///
/// This event is not a canonical key-publication fact. Committee members need its key and honest
/// subset to produce decryption shares, so it is forwarded to peers. Only the originating node can
/// submit it on-chain. The confirmed `CommitteePublished` chain event advances the request to the
/// published-key stage.
pub struct PublicKeyAggregated {
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pubkey: ArcBytes, // TODO: ArcBytes ?
    pub e3_id: E3id,
    pub nodes: OrderedSet<String>,
    /// Full registered committee (`topNodes`) addresses in ascending `party_id` (address) order.
    /// Length `N`. Used by `DecryptionAggregator` for `committee_hash_*` public-input binding.
    pub committee_addresses: Vec<Address>,
    /// Honest subset of the committee (size `H ≤ N`) in ascending `party_id` order.
    /// These are the parties whose C1/NodeFold proofs were accepted; downstream actors
    /// must gate decryption-share collection on this set rather than full `topNodes`.
    pub honest_committee_addresses: Vec<Address>,
    /// Hash-based aggregated PK commitment (last public signal of the C5 proof).
    /// Passed as `pkCommitment` to `publishCommittee`.
    pub pk_commitment: [u8; 32],
    /// EVM DKG recursive proof (`CircuitName::DkgAggregator`) carrying node folds + C5
    /// for on-chain verification. Test/CI skip mode carries a non-empty C5
    /// placeholder accepted only by mock verifiers.
    pub dkg_aggregator_proof: Option<Proof>,
    /// ABI-encoded `(Attestation[], PartySlotBinding[])` for on-chain fold attestation verify.
    /// Test/CI skip mode carries a non-empty placeholder accepted only by its mock verifier.
    pub dkg_attestation_bundle: Option<ArcBytes>,
    /// CKKS ONLY: the pre-encoded `CkksPkVerifier` blob
    /// `abi.encode(bytes[] partyProofs, bytes32[][] partyPublicInputs, bytes aggregatePublicKey)`
    /// built by `e3_evm::helpers::encode_ckks_pk_proofs` from every committee
    /// member's C1-CKKS proof.
    ///
    /// CKKS has no recursive pk-aggregation circuit, so `dkg_aggregator_proof`
    /// (which the BFV path fills with a single folded proof) cannot carry the
    /// CKKS evidence. When this is `Some`, `publish_committee_to_registry`
    /// sends it verbatim instead of re-encoding `dkg_aggregator_proof`.
    /// `None` on every BFV E3.
    pub ckks_pk_proof_blob: Option<ArcBytes>,
}

impl Display for PublicKeyAggregated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
