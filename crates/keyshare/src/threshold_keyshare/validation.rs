// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Admission rules for inputs that peers and the chain send to the threshold keyshare. These
//! functions read only their arguments: no actor state, storage, or clock.

use super::*;
use crate::canonical_key::CanonicalPublicKey;
use e3_events::CommitteePublished;

/// Why a peer `DecryptionKeyShared` is not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecryptionKeyShareRejection {
    /// The finalized committee member of the dealer slot did not sign the message.
    UnsignedDealer,
    /// The dealer was expelled.
    ExpelledDealer,
    /// The dealer slot is outside the committee or is this node's own slot.
    InvalidSender,
    /// The dealer is not in the honest committee of the accepted roster.
    OutsideHonestCommittee,
    /// C4 collection is complete, so the share changes nothing.
    CollectionComplete,
}

/// Admit a peer's C4 share. `dealer` is the finalized committee member of the share's dealer slot.
/// `collector_running` says whether a C4 collector exists for the E3.
pub(crate) fn admit_peer_decryption_key_share(
    share: &DecryptionKeyShared,
    dealer: Option<Address>,
    state: &ThresholdKeyshareState,
    recovery: &ThresholdKeyshareRecoveryState,
    collector_running: bool,
) -> Result<(), DecryptionKeyShareRejection> {
    use DecryptionKeyShareRejection as Rejection;
    match dealer {
        Some(address)
            if share.recover_address().ok() == Some(address)
                && share.node.parse::<Address>().ok() == Some(address) => {}
        _ => return Err(Rejection::UnsignedDealer),
    }
    if state.expelled_parties.contains(&share.party_id) {
        return Err(Rejection::ExpelledDealer);
    }
    if share.party_id >= state.threshold_n || share.party_id == state.party_id {
        return Err(Rejection::InvalidSender);
    }
    if state
        .honest_parties
        .as_ref()
        .is_some_and(|parties| !parties.contains(&share.party_id))
    {
        return Err(Rejection::OutsideHonestCommittee);
    }
    if matches!(state.state, KeyshareState::ReadyForDecryption(_)) && !collector_running {
        let collection_complete = state.keyshare_published
            || recovery.decryption_verification_complete.is_some()
            || state.honest_parties.as_ref().is_some_and(|parties| {
                parties
                    .iter()
                    .filter(|&&party_id| party_id != state.party_id)
                    .all(|party_id| recovery.decryption_key_shares.contains_key(party_id))
            });
        if collection_complete {
            return Err(Rejection::CollectionComplete);
        }
    }
    Ok(())
}

/// Whether a chain `CommitteePublished` names the canonical committee and carries a key that
/// matches the canonical commitment.
pub(crate) fn committee_publication_matches(
    key: &CanonicalPublicKey,
    publication: &CommitteePublished,
) -> bool {
    let nodes: Result<Vec<Address>, _> =
        publication.nodes.iter().map(|node| node.parse()).collect();
    nodes.as_ref().ok() == Some(&key.committee) && key.validate_key(&publication.public_key).is_ok()
}
