// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, RpcError};
use alloy_primitives::{keccak256, Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolError, SolValue};
use e3_blobs::{BlobError, Blobs};
use e3_data_availability::public_key::ChunkLayout;
use e3_evm_contracts::{ICiphernodeRegistry as Registry, IInterfold};
use e3_protocol::{
    dkg::SignedAttestation,
    node::{Submission, Transaction},
    proof::{verifier_calldata, ZkProof},
    E3Id,
};
use std::{future::Future, iter, time::Duration};
use tracing::info;

/// What the shared bindings do not carry.
mod extra {
    alloy_sol_types::sol! {
        error SortitionSeedUnavailable(uint256 e3Id, uint256 requestId);

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

/// Attempts per call, 30 seconds apart. The errors a call waits out come from an RPC node behind
/// the chain or a block time behind the node's clock, which clear within minutes; a publication
/// that cannot land by then is left to the next aggregator.
const ATTEMPTS: u32 = 20;
const RETRY_AFTER: Duration = Duration::from_secs(30);

/// Tickets estimated at the same time land one after another, and a later insertion into the top
/// N can cost more than its estimate.
const TICKET_GAS_MULTIPLIER: u64 = 2;

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
    #[error("the committee public key has {0} bytes")]
    KeySize(usize),
    #[error("{label} failed {ATTEMPTS} times; last: {last}")]
    GaveUp { label: &'static str, last: String },
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

impl<A: Account, B: Blobs> Writer<A, B> {
    pub fn new(account: A, blobs: B, contracts: Contracts) -> Self {
        Self {
            account,
            blobs,
            contracts,
        }
    }

    /// Sends `submission`'s calls in order. A call is done when it succeeds, or when it reverts
    /// with an error it does not wait out: then the chain has its effect already, or can no longer
    /// take it.
    pub async fn submit(&self, submission: &Submission) -> Result<(), WriteError> {
        for call in calls(&self.contracts, &self.blobs, submission)? {
            self.deliver(submission.e3, &call).await?;
        }
        Ok(())
    }

    async fn deliver(&self, e3: E3Id, call: &Call) -> Result<(), WriteError> {
        let mut last = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(RETRY_AFTER).await;
            }
            match self.attempt(e3, call).await {
                Ok(Progress::Done) => return Ok(()),
                Ok(Progress::NotYet(reason)) => last = reason,
                Err(error) => last = error.to_string(),
            }
        }
        Err(WriteError::GaveUp {
            label: call.label,
            last,
        })
    }

    async fn attempt(&self, e3: E3Id, call: &Call) -> Result<Progress, RpcError> {
        let gas = match self.account.estimate(call).await? {
            Estimate::Gas(gas) => gas,
            Estimate::Reverts(revert) if call.waits_out(&revert) => {
                return Ok(Progress::NotYet(format!("reverts with {revert}")));
            }
            Estimate::Reverts(revert) => {
                info!(%e3, call = call.label, %revert, "nothing to send: the call reverts");
                return Ok(Progress::Done);
            }
        };
        let gas = gas.saturating_mul(call.gas_multiplier);
        if !self.account.send(call, gas).await? {
            return Ok(Progress::NotYet("reverted on chain".into()));
        }
        info!(%e3, call = call.label, "landed");
        Ok(Progress::Done)
    }
}

/// The calls that carry out `submission`, in order.
fn calls(
    contracts: &Contracts,
    blobs: &impl Blobs,
    submission: &Submission,
) -> Result<Vec<Call>, WriteError> {
    use Registry::{
        CommitteeNotFinalized, CommitteeNotPublished, CommitteeNotRequested,
        SubmissionWindowNotClosed,
    };
    let e3 = submission.e3.number;
    let registry = |label, data: Vec<u8>, not_yet: &'static [[u8; 4]]| Call {
        label,
        to: contracts.registry,
        data: data.into(),
        gas_multiplier: 1,
        not_yet,
    };
    Ok(match &submission.transaction {
        Transaction::SubmitTicket { ticket } => {
            let data = Registry::submitTicketCall {
                e3Id: e3,
                ticketNumber: U256::from(*ticket),
            };
            let not_yet = &[
                CommitteeNotRequested::SELECTOR,
                extra::SortitionSeedUnavailable::SELECTOR,
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
            vec![Call {
                label: "publishPlaintextOutput",
                to: contracts.interfold,
                data: data.abi_encode().into(),
                gas_multiplier: 1,
                not_yet: &[],
            }]
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
