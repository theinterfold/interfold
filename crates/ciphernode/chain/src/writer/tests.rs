// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::testing::contracts;
use alloy_primitives::{address, bytes, B256};
use alloy_sol_types::SolError;
use e3_blobs::{BlobStore, Blobs, MemoryBlobs};
use e3_evm_contracts::E3Stage;
use e3_protocol::{
    accusation::{SignedVote, Vote},
    decryption::PlaintextPublication,
    dkg::KeyPublication,
    proof::ProofType,
    E3Id,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const GAS: u64 = 50_000;

#[derive(Default)]
struct Script {
    /// What each estimate returns, in order; gas once the script runs out.
    estimates: VecDeque<Result<Estimate, &'static str>>,
    /// Whether each send succeeds on chain, in order; success once the script runs out.
    sends: VecDeque<bool>,
    /// Estimates get no answer.
    stuck: bool,
    estimated: usize,
    /// Each sent call with its gas limit.
    sent: Vec<(Call, u64)>,
}

#[derive(Clone, Default)]
struct FakeAccount(Arc<Mutex<Script>>);

impl FakeAccount {
    fn script(&self, change: impl FnOnce(&mut Script)) {
        change(&mut self.0.lock().unwrap());
    }

    fn sent(&self) -> Vec<(Call, u64)> {
        self.0.lock().unwrap().sent.clone()
    }

    fn labels(&self) -> Vec<&'static str> {
        self.sent().iter().map(|(call, _)| call.label).collect()
    }
}

impl Account for FakeAccount {
    async fn estimate(&self, _: &Call) -> Result<Estimate, RpcError> {
        if self.0.lock().unwrap().stuck {
            std::future::pending::<()>().await;
        }
        let mut script = self.0.lock().unwrap();
        script.estimated += 1;
        match script.estimates.pop_front() {
            Some(Ok(estimate)) => Ok(estimate),
            Some(Err(message)) => Err(RpcError(message.into())),
            None => Ok(Estimate::Gas(GAS)),
        }
    }

    async fn send(&self, call: &Call, gas: u64) -> Result<bool, RpcError> {
        let mut script = self.0.lock().unwrap();
        script.sent.push((call.clone(), gas));
        Ok(script.sends.pop_front().unwrap_or(true))
    }
}

fn reverts(error: impl SolError) -> Result<Estimate, &'static str> {
    Ok(Estimate::Reverts(error.abi_encode().into()))
}

fn writer(account: &FakeAccount, blobs: &MemoryBlobs) -> Writer<FakeAccount, MemoryBlobs> {
    Writer::new(account.clone(), blobs.clone(), contracts())
}

const E3: E3Id = E3Id {
    chain_id: 1,
    number: U256::from_limbs([7, 0, 0, 0]),
};

fn submission(transaction: Transaction) -> Submission {
    Submission {
        e3: E3,
        transaction,
    }
}

fn plaintext(blobs: &MemoryBlobs) -> Submission {
    submission(Transaction::PublishPlaintext(PlaintextPublication {
        plaintext: blobs.of(E3).put(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        proof: ZkProof {
            data: blobs.of(E3).put(b"proof").unwrap(),
            public_inputs: vec![B256::repeat_byte(1)],
        },
    }))
}

fn stage(expected: u8, actual: u8) -> IInterfold::InvalidStage {
    IInterfold::InvalidStage {
        e3Id: U256::from(7),
        expected,
        actual,
    }
}

#[tokio::test]
async fn a_call_the_chain_takes_is_sent_once() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let finalize = submission(Transaction::FinalizeCommittee);
    writer(&account, &blobs).submit(&finalize).await.unwrap();
    let [(call, gas)] = account.sent().try_into().unwrap();
    assert_eq!(call.to, contracts().registry);
    assert_eq!(
        call.data,
        Bytes::from(
            Registry::finalizeCommitteeCall {
                e3Id: U256::from(7)
            }
            .abi_encode()
        )
    );
    assert_eq!(gas, GAS);
}

#[tokio::test]
async fn a_call_that_reverts_for_good_sends_nothing() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .push_back(reverts(Registry::CommitteeAlreadyFinalized {}));
    });
    let finalize = submission(Transaction::FinalizeCommittee);
    writer(&account, &blobs).submit(&finalize).await.unwrap();
    assert!(account.sent().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_call_waits_out_the_errors_of_a_chain_node_that_is_behind() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script.estimates.extend([
            reverts(Registry::SubmissionWindowNotClosed {}),
            Err("connection refused"),
            reverts(Registry::SubmissionWindowNotClosed {}),
        ]);
    });
    let finalize = submission(Transaction::FinalizeCommittee);
    writer(&account, &blobs).submit(&finalize).await.unwrap();
    assert_eq!(account.labels(), ["finalizeCommittee"]);
}

#[tokio::test(start_paused = true)]
async fn an_earlier_stage_is_waited_out_and_a_later_one_ends_the_call() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| script.estimates.push_back(reverts(stage(4, 3))));
    writer(&account, &blobs)
        .submit(&plaintext(&blobs))
        .await
        .unwrap();
    assert_eq!(account.labels(), ["publishPlaintextOutput"]);

    let account = FakeAccount::default();
    account.script(|script| script.estimates.push_back(reverts(stage(4, 5))));
    writer(&account, &blobs)
        .submit(&plaintext(&blobs))
        .await
        .unwrap();
    assert!(account.sent().is_empty());
}

/// A plaintext that landed and one that no longer can both end the call, with nothing sent.
#[tokio::test(start_paused = true)]
async fn a_plaintext_the_chain_has_or_refuses_for_good_sends_nothing() {
    let blobs = MemoryBlobs::default();
    let (complete, failed) = (E3Stage::Complete as u8, E3Stage::Failed as u8);
    let expired = reverts(IInterfold::CommitteeDutiesCompleted {
        e3Id: U256::from(7),
        expiration: U256::from(1),
    });
    for revert in [
        reverts(stage(4, complete)),
        reverts(stage(4, failed)),
        expired,
    ] {
        let account = FakeAccount::default();
        account.script(|script| script.estimates.push_back(revert));
        writer(&account, &blobs)
            .submit(&plaintext(&blobs))
            .await
            .unwrap();
        assert!(account.sent().is_empty());
    }
}

/// A revert the node cannot place is no answer: a lagging RPC or a paused contract can pass, so
/// the call goes on while the node owes it.
#[tokio::test(start_paused = true)]
async fn a_call_goes_on_through_a_revert_it_cannot_place() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        let paused = bytes!("9e87fac8");
        script.estimates.push_back(Ok(Estimate::Reverts(paused)));
    });
    writer(&account, &blobs)
        .submit(&submission(Transaction::FinalizeCommittee))
        .await
        .unwrap();
    assert_eq!(account.labels(), ["finalizeCommittee"]);
}

fn committee_publication(blobs: &MemoryBlobs) -> Submission {
    submission(Transaction::PublishCommittee(KeyPublication {
        commitment: B256::repeat_byte(0xc0),
        public_key: blobs.of(E3).put(&[1; 200 * 1024]).unwrap(),
        proof: ZkProof {
            data: blobs.of(E3).put(b"proof").unwrap(),
            public_inputs: vec![B256::repeat_byte(1)],
        },
        attestations: Vec::new(),
    }))
}

/// Another aggregator's equal commitment landed first: this one's chunks can still complete the
/// key's copy on chain.
#[tokio::test]
async fn a_published_key_still_sends_its_chunks() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .push_back(reverts(Registry::CommitteeAlreadyPublished {}));
    });
    writer(&account, &blobs)
        .submit(&committee_publication(&blobs))
        .await
        .unwrap();
    assert_eq!(
        account.labels(),
        [
            "publishCommitteePublicKey",
            "publishCommitteePublicKey",
            "publishCommitteePublicKey"
        ]
    );
}

/// A committee that can no longer publish has no key for chunks to follow.
#[tokio::test]
async fn a_committee_that_cannot_publish_sends_no_chunks() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .push_back(reverts(Registry::ThresholdNotMet {}));
    });
    writer(&account, &blobs)
        .submit(&committee_publication(&blobs))
        .await
        .unwrap();
    assert!(account.sent().is_empty());
}

/// A refresh that never gets an answer must not hold the refresh cycle.
#[tokio::test(start_paused = true)]
async fn a_stuck_refresh_ends_at_its_limit() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| script.stuck = true);
    let started = tokio::time::Instant::now();
    writer(&account, &blobs)
        .refresh_operator(address!("0x00000000000000000000000000000000000000aa"))
        .await;
    assert_eq!(started.elapsed(), REFRESH_LIMIT);
}

/// A ticket the chain already has, or one too late for the committee, ends the call.
#[tokio::test(start_paused = true)]
async fn a_ticket_the_chain_has_or_cannot_take_sends_nothing() {
    let blobs = MemoryBlobs::default();
    for revert in [
        reverts(Registry::NodeAlreadySubmitted {}),
        reverts(Registry::CommitteeDeadlineReached {}),
    ] {
        let account = FakeAccount::default();
        account.script(|script| script.estimates.push_back(revert));
        writer(&account, &blobs)
            .submit(&submission(Transaction::SubmitTicket { ticket: 3 }))
            .await
            .unwrap();
        assert!(account.sent().is_empty());
    }
}

/// An operator that is not eligible now can be before the deadline, so its ticket waits.
#[tokio::test(start_paused = true)]
async fn a_ticket_waits_out_an_operator_that_is_not_eligible_yet() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .push_back(reverts(Registry::NodeNotEligible {}));
    });
    writer(&account, &blobs)
        .submit(&submission(Transaction::SubmitTicket { ticket: 3 }))
        .await
        .unwrap();
    assert_eq!(account.labels(), ["submitTicket"]);
}

/// With slashing off for this reason, nothing the node waits for turns it on.
#[tokio::test(start_paused = true)]
async fn a_slash_of_a_disabled_reason_sends_nothing() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .push_back(reverts(ISlashingManager::SlashReasonDisabled {}));
    });
    let (slash, ..) = slash(&blobs);
    writer(&account, &blobs).submit(&slash).await.unwrap();
    assert!(account.sent().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_call_that_reverts_on_chain_is_tried_again() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| script.sends.push_back(false));
    writer(&account, &blobs)
        .submit(&plaintext(&blobs))
        .await
        .unwrap();
    assert_eq!(account.sent().len(), 2);
}

/// A chain node down for over an hour does not lose the call: it lands once the node answers,
/// and the waits between attempts grow, so a long outage costs few requests.
#[tokio::test(start_paused = true)]
async fn a_call_lands_after_a_long_outage_with_growing_waits() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        script
            .estimates
            .extend((0..12).map(|_| Err("connection refused")));
    });
    let started = tokio::time::Instant::now();
    let finalize = submission(Transaction::FinalizeCommittee);
    writer(&account, &blobs).submit(&finalize).await.unwrap();
    assert_eq!(account.labels(), ["finalizeCommittee"]);
    assert_eq!(account.0.lock().unwrap().estimated, 13);
    let waited = started.elapsed();
    assert!(waited > Duration::from_secs(60 * 60), "{waited:?}");
}

/// A node outside the committee marks a failure only after the grace period, and settlement
/// stays closed while accusations can come.
#[tokio::test(start_paused = true)]
async fn failure_calls_wait_out_the_grace_period_and_closed_settlement() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let e3 = U256::from(7);
    account.script(|script| {
        script.estimates.extend([
            reverts(IInterfold::FailureConditionNotMet { e3Id: e3 }),
            reverts(IInterfold::MarkE3FailedInGracePeriod {
                e3Id: e3,
                gracePeriodEnds: U256::from(3_600),
            }),
            Ok(Estimate::Gas(GAS)),
            reverts(IInterfold::E3NotFailed { e3Id: e3 }),
            reverts(IInterfold::SettlementBlocked {}),
        ]);
    });
    let writer = writer(&account, &blobs);
    writer
        .submit(&submission(Transaction::MarkFailed))
        .await
        .unwrap();
    writer
        .submit(&submission(Transaction::SettleFailure))
        .await
        .unwrap();
    assert_eq!(account.labels(), ["markE3Failed", "processE3Failure"]);
    let interfold = contracts().interfold;
    assert!(account.sent().iter().all(|(call, _)| call.to == interfold));
}

#[tokio::test]
async fn an_operator_refresh_goes_to_the_bonding_registry() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let operator = address!("0x00000000000000000000000000000000000000aa");
    writer(&account, &blobs).refresh_operator(operator).await;
    let [(call, gas)] = account.sent().try_into().unwrap();
    assert_eq!(call.to, contracts().bonding);
    let refresh = IBondingRegistry::refreshOperatorStatusCall { operator };
    assert_eq!(call.data, Bytes::from(refresh.abi_encode()));
    assert_eq!(gas, 2 * GAS);
}

#[tokio::test]
async fn a_ticket_gets_twice_its_estimated_gas() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let ticket = submission(Transaction::SubmitTicket { ticket: 3 });
    writer(&account, &blobs).submit(&ticket).await.unwrap();
    let [(_, gas)] = account.sent().try_into().unwrap();
    assert_eq!(gas, 2 * GAS);
}

#[tokio::test]
async fn a_committee_publishes_its_proof_then_its_key_in_chunks() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let key: Vec<u8> = (0..200 * 1024).map(|n| n as u8).collect();
    let publication = KeyPublication {
        commitment: B256::repeat_byte(0xc0),
        public_key: blobs.of(E3).put(&key).unwrap(),
        proof: ZkProof {
            data: blobs.of(E3).put(b"proof").unwrap(),
            public_inputs: vec![B256::repeat_byte(1)],
        },
        attestations: Vec::new(),
    };
    let publish = submission(Transaction::PublishCommittee(publication));
    writer(&account, &blobs).submit(&publish).await.unwrap();
    assert_eq!(
        account.labels(),
        [
            "publishCommittee",
            "publishCommitteePublicKey",
            "publishCommitteePublicKey",
            "publishCommitteePublicKey"
        ]
    );
    let chunks: Vec<Registry::publishCommitteePublicKeyCall> = account.sent()[1..]
        .iter()
        .map(|(call, _)| Registry::publishCommitteePublicKeyCall::abi_decode(&call.data).unwrap())
        .collect();
    let indices: Vec<u16> = chunks.iter().map(|chunk| chunk.chunkIndex).collect();
    assert_eq!(indices, [0, 1, 2]);
    assert!(chunks.iter().all(|chunk| chunk.chunkCount == 3
        && chunk.totalLength == key.len() as u32
        && chunk.candidateHash == keccak256(&key)));
    let joined: Vec<u8> = chunks
        .iter()
        .flat_map(|chunk| chunk.chunk.to_vec())
        .collect();
    assert_eq!(joined, key);
}

const MANAGER: Address = address!("0x00000000000000000000000000000000000000bb");
const ACCUSED: Address = address!("0x00000000000000000000000000000000000000cc");

/// A slash of `ACCUSED` with its proof and the one vote it carries.
fn slash(blobs: &MemoryBlobs) -> (Submission, ZkProof, SignedVote) {
    let proof = ZkProof {
        data: blobs.of(E3).put(b"bad proof").unwrap(),
        public_inputs: vec![B256::repeat_byte(2)],
    };
    let vote = SignedVote {
        vote: Vote {
            e3: E3,
            accusation_id: B256::repeat_byte(3),
            voter: address!("0x00000000000000000000000000000000000000dd"),
            data_hash: B256::repeat_byte(4),
            issued_at: 1,
            deadline: 2,
        },
        signature: Bytes::from(vec![5; 65]),
    };
    let slash = submission(Transaction::ProposeSlash {
        manager: MANAGER,
        accused: ACCUSED,
        proof_type: ProofType::C2aSkShareComputation,
        proof: proof.clone(),
        votes: vec![vote.clone()],
    });
    (slash, proof, vote)
}

#[tokio::test]
async fn a_slash_goes_to_the_e3_s_manager_with_the_accused_proof_s_bytes_as_evidence() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    let (slash, proof, vote) = slash(&blobs);
    writer(&account, &blobs).submit(&slash).await.unwrap();
    let [(call, _)] = account.sent().try_into().unwrap();
    assert_eq!(call.to, MANAGER);
    let sent = ISlashingManager::proposeSlashCall::abi_decode(&call.data).unwrap();
    assert_eq!((sent.e3Id, sent.operator), (U256::from(7), ACCUSED));
    let disputed = disputed_proof(b"bad proof", &proof.public_inputs);
    let evidence = slash_evidence(ProofType::C2aSkShareComputation, &[vote], &disputed).unwrap();
    assert_eq!(sent.proof, evidence);
}

/// The voters' window can start past the newest block's time, beyond the clock skew, when the
/// operator's chain node lags their clocks: the slash waits for the chain instead of going.
#[tokio::test(start_paused = true)]
async fn a_slash_whose_window_starts_after_the_newest_block_waits_for_the_chain() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| {
        let early = reverts(ISlashingManager::AccusationIssuedInFuture {});
        script.estimates.push_back(early);
    });
    let (slash, ..) = slash(&blobs);
    writer(&account, &blobs).submit(&slash).await.unwrap();
    assert_eq!(account.labels(), ["proposeSlash"]);
}

/// The bytes that the mainnet node's encoder (`encode_dkg_attestation_bundle` in `e3-zk-prover`)
/// makes for two parties signed with the first two Anvil keys.
#[test]
fn the_attestation_bundle_matches_the_mainnet_encoder() {
    let attestation = |party_id: u64, node: Address, signature: Bytes| SignedAttestation {
        party_id,
        node,
        sk_agg_commit: B256::repeat_byte(party_id as u8),
        esm_agg_commit: B256::repeat_byte(0x10 + party_id as u8),
        signature,
    };
    let attestations = [
        attestation(
            1,
            address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            bytes!("595bcb07d0e7e25e2c26338b959805028f65b8e21f38555af76280666d60aeed7a9f0c948e948f73c3a374918bc2583bfa15db993f0b8ebbcd09140f6216cac11c"),
        ),
        attestation(
            3,
            address!("70997970c51812dc3a010c7d01b50e0d17dc79c8"),
            bytes!("366bb5aabb85c0b2515b4c3e32b8d2d7c1b0a9e7060c51fe63da672e3c53b58648ab68f405cd87c85df74750683256e1013b6cdae54572afb271e4f9ee85af8b1c"),
        ),
    ];
    let expected = bytes!("000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010101111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041595bcb07d0e7e25e2c26338b959805028f65b8e21f38555af76280666d60aeed7a9f0c948e948f73c3a374918bc2583bfa15db993f0b8ebbcd09140f6216cac11c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030303030303030303030303030303030303030303030303030303030303030303131313131313131313131313131313131313131313131313131313131313131300000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041366bb5aabb85c0b2515b4c3e32b8d2d7c1b0a9e7060c51fe63da672e3c53b58648ab68f405cd87c85df74750683256e1013b6cdae54572afb271e4f9ee85af8b1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000000300000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8");
    assert_eq!(attestation_bundle(&attestations), expected);
}
