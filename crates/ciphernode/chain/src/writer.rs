// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, RpcError};
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolError, SolValue};
use e3_blobs::{BlobError, BlobStore, Blobs};
use e3_data_availability::public_key::ChunkLayout;
use e3_evm_contracts::{
    IBondingRegistry, ICiphernodeRegistry as Registry, IInterfold, ISlashingManager,
};
use e3_protocol::{
    accusation::{disputed_proof, slash_evidence, EvidenceError},
    dkg::SignedAttestation,
    node::{Submission, Transaction},
    proof::{verifier_calldata, ZkProof},
};
use std::{fmt::Display, future::Future, iter, time::Duration};
use tracing::{debug, info, warn};

/// What the shared bindings do not carry.
mod extra {
    alloy_sol_types::sol! {
        /// `DkgFoldAttestationLib.Attestation`.
        struct Attestation {
            uint256 partyId;
            bytes32 skAggCommit;
            bytes32 esmAggCommit;
            bytes signature;
        }

        /// `DkgFoldAttestationLib.PartySlotBinding`.
        struct PartySlotBinding {
            uint256 partyId;
            address node;
        }
    }
}

/// The wait after a call's first failed attempt; each later wait doubles, up to ten minutes. The
/// errors a call waits out come from a chain node that is behind or down, or a block time behind
/// the node's clock.
const FIRST_RETRY: Duration = Duration::from_secs(30);
const LONGEST_RETRY: Duration = Duration::from_secs(600);

/// Tickets estimated at the same time land one after another, and a later insertion into the top
/// N can cost more than its estimate.
const TICKET_GAS_MULTIPLIER: u64 = 2;

/// A refresh writes the registries' checkpoints at `block.timestamp`, which can cost more than at
/// the block it was estimated in.
const REFRESH_GAS_MULTIPLIER: u64 = 2;

/// One contract call for the operator to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The function, for logs.
    pub label: &'static str,
    pub to: Address,
    pub data: Bytes,
    /// The gas limit as a multiple of the estimate.
    pub gas_multiplier: u64,
    /// Errors that mean the operator's chain node has not seen what the call needs yet.
    pub(crate) not_yet: &'static [[u8; 4]],
}

impl Call {
    /// Whether `revert` only means "not yet": one of the call's waiting errors, or an E3 stage
    /// before the one the call needs, because the node acted on a stage change that its chain node
    /// has not seen.
    fn waits_out(&self, revert: &[u8]) -> bool {
        let listed = revert
            .get(..4)
            .is_some_and(|selector| self.not_yet.iter().any(|error| error == selector));
        listed
            || IInterfold::InvalidStage::abi_decode(revert)
                .is_ok_and(|stage| stage.actual < stage.expected)
    }
}

/// The gas a call takes now, or the revert it hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Estimate {
    Gas(u64),
    Reverts(Bytes),
}

/// What the writer needs from the chain: the operator's account.
pub trait Account {
    /// `call` from the operator against the newest block.
    fn estimate(&self, call: &Call) -> impl Future<Output = Result<Estimate, RpcError>> + Send;

    /// Sends `call` with the gas limit `gas` and waits for its receipt: whether it succeeded.
    fn send(&self, call: &Call, gas: u64) -> impl Future<Output = Result<bool, RpcError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error(transparent)]
    Blob(#[from] BlobError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("the committee public key has {0} bytes")]
    KeySize(usize),
}

/// Sends the node's submissions from the operator's account.
pub struct Writer<A, B> {
    account: A,
    blobs: B,
    contracts: Contracts,
}

enum Progress {
    Done,
    NotYet(String),
}

impl<A: Account, B: BlobStore> Writer<A, B> {
    pub fn new(account: A, blobs: B, contracts: Contracts) -> Self {
        Self {
            account,
            blobs,
            contracts,
        }
    }

    /// Sends `submission`'s calls in order. A call is done when it succeeds, or when it reverts
    /// with an error it does not wait out: then the chain has its effect already, or can no longer
    /// take it. Until then it tries again; the node stops the calls of an E3 it no longer holds.
    pub async fn submit(&self, submission: &Submission) -> Result<(), WriteError> {
        let blobs = self.blobs.of(submission.e3);
        for call in calls(&self.contracts, &blobs, submission)? {
            self.deliver(&submission.e3, &call).await;
        }
        Ok(())
    }

    /// Refreshes `operator`'s activity and owner capacity. Under a required identity policy an
    /// owner's capacity reads zero from the start of each 30-day window until its operators
    /// refresh. An unregistered operator's call reverts, so nothing is sent.
    pub async fn refresh_operator(&self, operator: Address) {
        let data = IBondingRegistry::refreshOperatorStatusCall { operator };
        let call = Call {
            label: "refreshOperatorStatus",
            to: self.contracts.bonding,
            data: data.abi_encode().into(),
            gas_multiplier: REFRESH_GAS_MULTIPLIER,
            not_yet: &[],
        };
        self.deliver(&operator, &call).await;
    }

    /// `of` names what the call is for, in logs.
    async fn deliver(&self, of: &(dyn Display + Sync), call: &Call) {
        let mut wait = FIRST_RETRY;
        loop {
            match self.attempt(of, call).await {
                Ok(Progress::Done) => return,
                Ok(Progress::NotYet(reason)) => debug!(%of, call = call.label, %reason, "not yet"),
                Err(error) => warn!(%of, call = call.label, %error, "the attempt failed"),
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(LONGEST_RETRY);
        }
    }

    async fn attempt(&self, of: &(dyn Display + Sync), call: &Call) -> Result<Progress, RpcError> {
        let gas = match self.account.estimate(call).await? {
            Estimate::Gas(gas) => gas,
            Estimate::Reverts(revert) if call.waits_out(&revert) => {
                return Ok(Progress::NotYet(format!("reverts with {revert}")));
            }
            Estimate::Reverts(revert) => {
                info!(%of, call = call.label, %revert, "nothing to send: the call reverts");
                return Ok(Progress::Done);
            }
        };
        let gas = gas.saturating_mul(call.gas_multiplier);
        if !self.account.send(call, gas).await? {
            return Ok(Progress::NotYet("reverted on chain".into()));
        }
        info!(%of, call = call.label, "landed");
        Ok(Progress::Done)
    }
}

/// The calls that carry out `submission`, in order.
fn calls(
    contracts: &Contracts,
    blobs: &impl Blobs,
    submission: &Submission,
) -> Result<Vec<Call>, WriteError> {
    use IInterfold::{
        E3NotFailed, FailureConditionNotMet, MarkE3FailedInGracePeriod, SettlementBlocked,
    };
    use Registry::{
        CommitteeNotFinalized, CommitteeNotPublished, CommitteeNotRequested,
        SortitionSeedUnavailable, SubmissionWindowNotClosed,
    };
    let e3 = submission.e3.number;
    let call = |to, label, data: Vec<u8>, not_yet: &'static [[u8; 4]]| Call {
        label,
        to,
        data: data.into(),
        gas_multiplier: 1,
        not_yet,
    };
    let registry = |label, data, not_yet| call(contracts.registry, label, data, not_yet);
    let interfold = |label, data, not_yet| call(contracts.interfold, label, data, not_yet);
    Ok(match &submission.transaction {
        Transaction::SubmitTicket { ticket } => {
            let data = Registry::submitTicketCall {
                e3Id: e3,
                ticketNumber: U256::from(*ticket),
            };
            let not_yet = &[
                CommitteeNotRequested::SELECTOR,
                SortitionSeedUnavailable::SELECTOR,
            ];
            vec![Call {
                gas_multiplier: TICKET_GAS_MULTIPLIER,
                ..registry("submitTicket", data.abi_encode(), not_yet)
            }]
        }
        Transaction::FinalizeCommittee => {
            let data = Registry::finalizeCommitteeCall { e3Id: e3 };
            let not_yet = &[
                SubmissionWindowNotClosed::SELECTOR,
                CommitteeNotRequested::SELECTOR,
            ];
            vec![registry("finalizeCommittee", data.abi_encode(), not_yet)]
        }
        // The key's chunks are only logs, from which readers assemble any complete copy that
        // matches the commitment. So they go out even when another aggregator's equal commitment
        // landed first and `publishCommittee` reverts.
        Transaction::PublishCommittee(publication) => {
            let key = blobs.get(&publication.public_key)?;
            let layout = ChunkLayout::new(key.len()).map_err(|_| WriteError::KeySize(key.len()))?;
            let publish = Registry::publishCommitteeCall {
                e3Id: e3,
                pkCommitment: publication.commitment,
                proof: proof_calldata(blobs, &publication.proof)?,
                dkgAttestationBundle: attestation_bundle(&publication.attestations),
            };
            let candidate = keccak256(&key);
            let chunks = (0..layout.chunk_count()).map(|index| {
                let range = layout.range(index).expect("an index below the count");
                let chunk = Registry::publishCommitteePublicKeyCall {
                    e3Id: e3,
                    candidateHash: candidate,
                    chunkIndex: index,
                    chunkCount: layout.chunk_count(),
                    totalLength: layout.total_length(),
                    chunk: Bytes::copy_from_slice(&key[range]),
                };
                let not_yet = &[CommitteeNotPublished::SELECTOR];
                registry("publishCommitteePublicKey", chunk.abi_encode(), not_yet)
            });
            let not_yet = &[CommitteeNotFinalized::SELECTOR];
            iter::once(registry("publishCommittee", publish.abi_encode(), not_yet))
                .chain(chunks)
                .collect()
        }
        Transaction::PublishPlaintext(publication) => {
            let data = IInterfold::publishPlaintextOutputCall {
                e3Id: e3,
                plaintextOutput: blobs.get(&publication.plaintext)?.into(),
                proof: proof_calldata(blobs, &publication.proof)?,
            };
            vec![interfold("publishPlaintextOutput", data.abi_encode(), &[])]
        }
        // Before its grace period ends, the contract takes the call only from committee members.
        Transaction::MarkFailed => {
            let data = IInterfold::markE3FailedCall { e3Id: e3 };
            let not_yet = &[
                FailureConditionNotMet::SELECTOR,
                MarkE3FailedInGracePeriod::SELECTOR,
            ];
            vec![interfold("markE3Failed", data.abi_encode(), not_yet)]
        }
        // With a committee, settlement opens a day after the E3's lifecycle deadline, once no
        // accusation is open.
        Transaction::SettleFailure => {
            let data = IInterfold::processE3FailureCall { e3Id: e3 };
            let not_yet = &[E3NotFailed::SELECTOR, SettlementBlocked::SELECTOR];
            vec![interfold("processE3Failure", data.abi_encode(), not_yet)]
        }
        // Each of the first voters can send it in turn; the contract takes one proposal for the
        // proof, and a later one reverts, which means nothing to send. A window that starts
        // further past the newest block's time than the clock skew waits for the chain to catch
        // up.
        Transaction::ProposeSlash {
            manager,
            accused,
            proof_type,
            proof,
            votes,
        } => {
            let disputed = disputed_proof(&blobs.get(&proof.data)?, &proof.public_inputs);
            let data = ISlashingManager::proposeSlashCall {
                e3Id: e3,
                operator: *accused,
                proof: slash_evidence(*proof_type, votes, &disputed)?,
            };
            let not_yet = &[ISlashingManager::AccusationIssuedInFuture::SELECTOR];
            vec![call(*manager, "proposeSlash", data.abi_encode(), not_yet)]
        }
    })
}

fn proof_calldata(blobs: &impl Blobs, proof: &ZkProof) -> Result<Bytes, BlobError> {
    Ok(verifier_calldata(
        &blobs.get(&proof.data)?,
        &proof.public_inputs,
    ))
}

/// The bundle `DkgFoldAttestationVerifier` decodes: `abi.encode(Attestation[], PartySlotBinding[])`,
/// each ascending by party ID, as the publication lists them.
fn attestation_bundle(attestations: &[SignedAttestation]) -> Bytes {
    let signed: Vec<extra::Attestation> = attestations
        .iter()
        .map(|attestation| extra::Attestation {
            partyId: U256::from(attestation.party_id),
            skAggCommit: attestation.sk_agg_commit,
            esmAggCommit: attestation.esm_agg_commit,
            signature: attestation.signature.clone(),
        })
        .collect();
    let bindings: Vec<extra::PartySlotBinding> = attestations
        .iter()
        .map(|attestation| extra::PartySlotBinding {
            partyId: U256::from(attestation.party_id),
            node: attestation.node,
        })
        .collect();
    (signed, bindings).abi_encode_params().into()
}

#[cfg(test)]
mod tests;
