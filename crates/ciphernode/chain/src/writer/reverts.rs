// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What each contract function's reverts mean for the node. A call is finished only when the chain
//! says so. A revert no function lists here says nothing of the kind, so the call goes on for as
//! long as the node owes it.

use alloy_sol_types::SolInterface;
use e3_evm_contracts::{
    E3Stage,
    IBondingRegistry::IBondingRegistryErrors as BondingError,
    ICiphernodeRegistry::ICiphernodeRegistryErrors as RegistryError,
    IInterfold::{IInterfoldErrors as InterfoldError, InvalidStage},
    ISlashingManager::ISlashingManagerErrors as SlashingError,
};

/// What a revert says about the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// It is too early, or the operator's chain node has not seen that it is time.
    Retry,
    /// The chain has what the call asks for, from this node or another.
    Applied,
    /// The chain can no longer take the call or anything that follows it.
    Obsolete,
}
use Verdict::{Applied, Obsolete, Retry};

/// Reads one function's reverts; `None` for one it cannot place.
pub(super) type Reading = fn(&[u8]) -> Option<Verdict>;

/// An E3 stage before the one the call needs: the operator's chain node has not seen the change.
fn early(stage: &InvalidStage) -> bool {
    stage.actual < stage.expected
}

pub(super) fn ticket(revert: &[u8]) -> Option<Verdict> {
    use RegistryError::*;
    Some(match RegistryError::abi_decode(revert).ok()? {
        // An operator that is not eligible now, or whose activation a lagging chain node has not
        // seen, can be eligible before the deadline.
        CommitteeNotRequested(_) | SortitionSeedUnavailable(_) | NodeNotEligible(_) => Retry,
        NodeAlreadySubmitted(_) => Applied,
        CommitteeAlreadyFinalized(_) | CommitteeDeadlineReached(_) | InvalidTicketNumber(_) => {
            Obsolete
        }
        _ => return None,
    })
}

pub(super) fn finalize_committee(revert: &[u8]) -> Option<Verdict> {
    use RegistryError::*;
    Some(match RegistryError::abi_decode(revert).ok()? {
        CommitteeNotRequested(_) | SubmissionWindowNotClosed(_) => Retry,
        // A finalized committee and a failed one both refuse this way.
        CommitteeAlreadyFinalized(_) | CommitteeObligationsAlreadyReleased(_) => Applied,
        _ => return None,
    })
}

pub(super) fn publish_committee(revert: &[u8]) -> Option<Verdict> {
    use RegistryError::*;
    if let Ok(error) = RegistryError::abi_decode(revert) {
        return Some(match error {
            CommitteeNotFinalized(_) => Retry,
            // Another aggregator's equal commitment landed first; the key's chunks still go.
            CommitteeAlreadyPublished(_) => Applied,
            ThresholdNotMet(_)
            | PkCommitmentRequired(_)
            | DkgProofRequired(_)
            | InvalidDkgProof(_)
            | FoldAttestationsRequired(_)
            | FoldAttestationVerifierNotSet(_)
            | InvalidFoldAttestation(_)
            | PartyIdNotInProof(_)
            | AttestationBindingCountMismatch(_)
            | PartyIdOutOfBounds(_)
            | InvalidProof(_)
            | InvalidPublicInputsLength(_)
            | VkHashMismatch(_)
            | PkCommitmentMismatch(_)
            | DomainBindingMismatch(_)
            | InvalidPublicKeyLength(_) => Obsolete,
            _ => return None,
        });
    }
    Some(match InterfoldError::abi_decode(revert).ok()? {
        InterfoldError::InvalidStage(stage) if early(&stage) => Retry,
        InterfoldError::InvalidStage(_) | InterfoldError::DKGDeadlinePassed(_) => Obsolete,
        _ => return None,
    })
}

pub(super) fn key_chunk(revert: &[u8]) -> Option<Verdict> {
    use RegistryError::*;
    if let Ok(error) = RegistryError::abi_decode(revert) {
        return Some(match error {
            CommitteeNotPublished(_) => Retry,
            InvalidPublicKeyChunk(_) | PublicKeyPublisherNotCommitteeMember(_) => Obsolete,
            _ => return None,
        });
    }
    Some(match InterfoldError::abi_decode(revert).ok()? {
        InterfoldError::InvalidStage(stage) if early(&stage) => Retry,
        // Chunks are only taken while the key is the E3's latest stage.
        InterfoldError::InvalidStage(_) => Obsolete,
        _ => return None,
    })
}

pub(super) fn plaintext(revert: &[u8]) -> Option<Verdict> {
    use InterfoldError::*;
    Some(match InterfoldError::abi_decode(revert).ok()? {
        E3DoesNotExist(_) => Retry,
        InvalidStage(stage) if early(&stage) => Retry,
        InvalidStage(stage) if stage.actual == E3Stage::Complete as u8 => Applied,
        InvalidStage(_) | CommitteeDutiesCompleted(_) => Obsolete,
        _ => return None,
    })
}

pub(super) fn mark_failed(revert: &[u8]) -> Option<Verdict> {
    use InterfoldError::*;
    Some(match InterfoldError::abi_decode(revert).ok()? {
        FailureConditionNotMet(_) | MarkE3FailedInGracePeriod(_) | InvalidStage(_) => Retry,
        E3AlreadyFailed(_) => Applied,
        E3AlreadyComplete(_) => Obsolete,
        _ => return None,
    })
}

pub(super) fn settle_failure(revert: &[u8]) -> Option<Verdict> {
    use InterfoldError::*;
    Some(match InterfoldError::abi_decode(revert).ok()? {
        E3NotFailed(_) | SettlementBlocked(_) => Retry,
        NoPaymentToRefund(_) => Applied,
        _ => return None,
    })
}

pub(super) fn propose_slash(revert: &[u8]) -> Option<Verdict> {
    use SlashingError::*;
    Some(match SlashingError::abi_decode(revert).ok()? {
        // A bounded clock skew: the chain's time reaches the window.
        AccusationIssuedInFuture(_) => Retry,
        DuplicateEvidence(_) => Applied,
        ZeroAddress(_)
        | ProofRequired(_)
        | OperatorNotInCommittee(_)
        | ChainIdMismatch(_)
        | InvalidProof(_)
        | InsufficientAttestations(_)
        | DuplicateVoter(_)
        | VoterNotInCommittee(_)
        | InvalidVoteSignature(_)
        | VoterIsAccused(_)
        | EquivocationDetected(_)
        | SignatureExpired(_)
        | InvalidAccusationWindow(_)
        | SlashSubmissionDeadlinePassed(_)
        | SlashReasonDisabled(_)
        | AccusationSlashingDisabled(_) => Obsolete,
        _ => return None,
    })
}

pub(super) fn refresh(revert: &[u8]) -> Option<Verdict> {
    match BondingError::abi_decode(revert).ok()? {
        BondingError::NotRegistered(_) => Some(Obsolete),
    }
}
