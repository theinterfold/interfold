// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod reverts;

use crate::{Contracts, RpcError};
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolValue};
use e3_blobs::{BlobError, BlobStore, Blobs};
use e3_data_availability::public_key::ChunkLayout;
use e3_evm::error_decoder::decode_error;
use e3_evm_contracts::{
    IBondingRegistry, ICiphernodeRegistry as Registry, IInterfold, ISlashingManager,
};
use e3_protocol::{
    accusation::{disputed_proof, slash_evidence, EvidenceError},
    dkg::SignedAttestation,
    node::{Submission, Transaction},
    proof::{verifier_calldata, ZkProof},
};
use reverts::{Reading, Verdict};
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

        /// `NodeReleaseRegistry`: an acknowledgement of a release that names no version.
        error InvalidNodeRelease();

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

/// The longest one refresh may take, from its estimate through broadcast and receipt. The cycle
/// must go on to its next refresh, which a stuck one would block.
const REFRESH_LIMIT: Duration = Duration::from_secs(30 * 60);

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
}

/// One call of a submission and how to read its reverts.
struct Step {
    call: Call,
    reverts: Reading,
}

/// What the chain says about a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Estimate {
    /// The confirmed state takes the call, and the call takes this gas at the newest block.
    Gas(u64),
    /// The confirmed state refuses the call.
    Reverts(Bytes),
    /// The confirmed state takes the call and the newest blocks refuse it. They can still be
    /// replaced, so what they show counts once they are confirmed.
    NotYet(Bytes),
}

/// What the writer needs from the chain: the operator's account.
pub trait Account {
    /// Whether the confirmed state takes `call` from the operator, and the gas it takes where it
    /// will run: the two can differ for as long as the newest blocks are unconfirmed.
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

/// How a delivered step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivered {
    /// The chain has what the call asks for.
    Done,
    /// The chain can no longer take it, nor what follows it.
    Obsolete,
}

impl<A: Account, B: BlobStore> Writer<A, B> {
    pub fn new(account: A, blobs: B, contracts: Contracts) -> Self {
        Self {
            account,
            blobs,
            contracts,
        }
    }

    /// Sends `submission`'s calls in order, each until the chain says it is finished; a call the
    /// chain can no longer take ends the submission. The node stops the calls of an E3 it no longer
    /// owes.
    pub async fn submit(&self, submission: &Submission) -> Result<(), WriteError> {
        let blobs = self.blobs.of(submission.e3);
        for step in calls(&self.contracts, &blobs, submission)? {
            if deliver(&self.account, &submission.e3, &step).await == Delivered::Obsolete {
                break;
            }
        }
        Ok(())
    }

    /// Refreshes `operator`'s activity and owner capacity. Under a required identity policy an
    /// owner's capacity reads zero from the start of each 30-day window until its operators
    /// refresh. A refresh that does not finish in time is left to the next one.
    pub async fn refresh_operator(&self, operator: Address) {
        let data = IBondingRegistry::refreshOperatorStatusCall { operator };
        let step = Step {
            call: Call {
                label: "refreshOperatorStatus",
                to: self.contracts.bonding,
                data: data.abi_encode().into(),
                gas_multiplier: REFRESH_GAS_MULTIPLIER,
            },
            reverts: reverts::refresh,
        };
        let refresh = deliver(&self.account, &operator, &step);
        if tokio::time::timeout(REFRESH_LIMIT, refresh).await.is_err() {
            warn!(%operator, "the refresh did not finish in time; the next one tries again");
        }
    }
}

/// Sends the operator's acknowledgement of this node's release until the chain has it: whether
/// the chain can take it at all.
pub async fn acknowledge<A: Account>(account: &A, call: &Call) -> bool {
    let step = Step {
        call: call.clone(),
        reverts: reverts::acknowledge,
    };
    deliver(account, &"the node's release", &step).await == Delivered::Done
}

/// `of` names what the call is for, in logs.
async fn deliver<A: Account>(account: &A, of: &(dyn Display + Sync), step: &Step) -> Delivered {
    let (label, mut wait) = (step.call.label, FIRST_RETRY);
    loop {
        match attempt(account, of, step).await {
            Ok(Some(delivered)) => return delivered,
            Ok(None) => {}
            Err(error) => warn!(%of, call = label, %error, "the attempt failed"),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(LONGEST_RETRY);
    }
}

/// One try at `step`: how it ended, or `None` when it goes again.
async fn attempt<A: Account>(
    account: &A,
    of: &(dyn Display + Sync),
    step: &Step,
) -> Result<Option<Delivered>, RpcError> {
    let call = &step.call;
    let gas = match account.estimate(call).await? {
        Estimate::Gas(gas) => gas,
        Estimate::Reverts(revert) => return Ok(read_revert(of, step, &revert)),
        Estimate::NotYet(revert) => {
            let error = decode_error(&revert).unwrap_or_else(|| revert.to_string());
            debug!(%of, call = call.label, %error, "the newest blocks refuse the call; not yet");
            return Ok(None);
        }
    };
    let gas = gas.saturating_mul(call.gas_multiplier);
    if !account.send(call, gas).await? {
        warn!(%of, call = call.label, "the transaction reverted on chain; checking it again");
        return Ok(None);
    }
    info!(%of, call = call.label, "landed");
    Ok(Some(Delivered::Done))
}

/// What `step`'s `revert` means, in the log and for the delivery.
fn read_revert(of: &(dyn Display + Sync), step: &Step, revert: &Bytes) -> Option<Delivered> {
    let call = step.call.label;
    let error = decode_error(revert).unwrap_or_else(|| revert.to_string());
    match (step.reverts)(revert) {
        Some(Verdict::Retry) => {
            debug!(%of, call, %error, "not yet");
            None
        }
        Some(Verdict::Applied) => {
            info!(%of, call, %error, "nothing to send: the chain has it already");
            Some(Delivered::Done)
        }
        Some(Verdict::Obsolete) => {
            warn!(%of, call, %error, "the chain can no longer take this call");
            Some(Delivered::Obsolete)
        }
        None => {
            warn!(%of, call, %error, "the call reverts for a reason the node cannot place; trying again");
            None
        }
    }
}

/// The calls that carry out `submission`, in order.
fn calls(
    contracts: &Contracts,
    blobs: &impl Blobs,
    submission: &Submission,
) -> Result<Vec<Step>, WriteError> {
    let e3 = submission.e3.number;
    let step = |to, label, data: Vec<u8>, reverts: Reading| Step {
        call: Call {
            label,
            to,
            data: data.into(),
            gas_multiplier: 1,
        },
        reverts,
    };
    let registry = |label, data, reverts| step(contracts.registry, label, data, reverts);
    let interfold = |label, data, reverts| step(contracts.interfold, label, data, reverts);
    Ok(match &submission.transaction {
        Transaction::SubmitTicket { ticket } => {
            let data = Registry::submitTicketCall {
                e3Id: e3,
                ticketNumber: U256::from(*ticket),
            };
            let mut ticket = registry("submitTicket", data.abi_encode(), reverts::ticket);
            ticket.call.gas_multiplier = TICKET_GAS_MULTIPLIER;
            vec![ticket]
        }
        Transaction::FinalizeCommittee => {
            let data = Registry::finalizeCommitteeCall { e3Id: e3 };
            vec![registry(
                "finalizeCommittee",
                data.abi_encode(),
                reverts::finalize_committee,
            )]
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
                registry(
                    "publishCommitteePublicKey",
                    chunk.abi_encode(),
                    reverts::key_chunk,
                )
            });
            iter::once(registry(
                "publishCommittee",
                publish.abi_encode(),
                reverts::publish_committee,
            ))
            .chain(chunks)
            .collect()
        }
        Transaction::PublishPlaintext(publication) => {
            let data = IInterfold::publishPlaintextOutputCall {
                e3Id: e3,
                plaintextOutput: blobs.get(&publication.plaintext)?.into(),
                proof: proof_calldata(blobs, &publication.proof)?,
            };
            vec![interfold(
                "publishPlaintextOutput",
                data.abi_encode(),
                reverts::plaintext,
            )]
        }
        // Before its grace period ends, the contract takes the call only from committee members.
        Transaction::MarkFailed => {
            let data = IInterfold::markE3FailedCall { e3Id: e3 };
            vec![interfold(
                "markE3Failed",
                data.abi_encode(),
                reverts::mark_failed,
            )]
        }
        // With a committee, settlement opens a day after the E3's lifecycle deadline, once no
        // accusation is open.
        Transaction::SettleFailure => {
            let data = IInterfold::processE3FailureCall { e3Id: e3 };
            vec![interfold(
                "processE3Failure",
                data.abi_encode(),
                reverts::settle_failure,
            )]
        }
        // Each of the first voters can send it in turn; the contract takes one proposal for the
        // proof. A window that starts further past the newest block's time than the clock skew
        // waits for the chain to catch up.
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
            vec![step(
                *manager,
                "proposeSlash",
                data.abi_encode(),
                reverts::propose_slash,
            )]
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
