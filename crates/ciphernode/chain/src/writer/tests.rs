// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::testing::contracts;
use alloy_primitives::{address, bytes, B256};
use e3_blobs::MemoryBlobs;
use e3_protocol::{decryption::PlaintextPublication, dkg::KeyPublication, E3Id};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const GAS: u64 = 50_000;

#[derive(Default)]
struct Script {
    /// What each estimate returns, in order; gas once the script runs out.
    estimates: VecDeque<Result<Estimate, &'static str>>,
    /// Every request fails, as with a chain node that is down.
    down: bool,
    /// Whether each send succeeds on chain, in order; success once the script runs out.
    sends: VecDeque<bool>,
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
        let mut script = self.0.lock().unwrap();
        script.estimated += 1;
        if script.down {
            return Err(RpcError("connection refused".into()));
        }
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

fn submission(transaction: Transaction) -> Submission {
    Submission {
        e3: E3Id {
            chain_id: 1,
            number: U256::from(7),
        },
        transaction,
    }
}

fn plaintext(blobs: &MemoryBlobs) -> Submission {
    submission(Transaction::PublishPlaintext(PlaintextPublication {
        plaintext: blobs.put(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
        proof: ZkProof {
            data: blobs.put(b"proof").unwrap(),
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

/// A call that keeps failing is retried for minutes, to wait out a chain node that is behind,
/// and given up within ten, by when the next aggregator has taken over a publication.
#[tokio::test(start_paused = true)]
async fn the_writer_gives_up_on_a_call_that_keeps_failing_within_ten_minutes() {
    let (account, blobs) = (FakeAccount::default(), MemoryBlobs::default());
    account.script(|script| script.down = true);
    let started = tokio::time::Instant::now();
    let finalize = submission(Transaction::FinalizeCommittee);
    let result = writer(&account, &blobs).submit(&finalize).await;
    assert!(matches!(
        result,
        Err(WriteError::GaveUp {
            label: "finalizeCommittee",
            ..
        })
    ));
    let waited = started.elapsed();
    assert!(waited > Duration::from_secs(5 * 60), "{waited:?}");
    assert!(waited <= Duration::from_secs(10 * 60), "{waited:?}");
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
        public_key: blobs.put(&key).unwrap(),
        proof: ZkProof {
            data: blobs.put(b"proof").unwrap(),
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
