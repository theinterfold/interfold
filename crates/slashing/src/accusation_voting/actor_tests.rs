// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::primitives::{keccak256, FixedBytes, U256};
use alloy::sol_types::SolValue;
use e3_events::{VOTE_DOMAIN_NAME, VOTE_DOMAIN_VERSION, VOTE_TYPEHASH_STR};
use e3_utils::ArcBytes;

/// Default clock-skew allowance when validating peer-stamped accusation
/// deadlines (mirrors the production extension default).
const DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS: u64 = 30;

/// Independent re-derivation of the EIP-712 vote digest, mirroring exactly
/// what `SlashingManager._verifyVotes` computes on chain.
#[allow(clippy::too_many_arguments)]
fn reference_vote_digest(
    chain_id: u64,
    verifying_contract: Address,
    e3_id: u64,
    accusation_id: [u8; 32],
    voter: Address,
    data_hash: [u8; 32],
    issued_at: u64,
    deadline: u64,
) -> [u8; 32] {
    let domain_typehash: [u8; 32] = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
    .into();
    let name_hash: [u8; 32] = keccak256(VOTE_DOMAIN_NAME).into();
    let version_hash: [u8; 32] = keccak256(VOTE_DOMAIN_VERSION).into();
    let domain_separator: [u8; 32] = keccak256(
        (
            domain_typehash,
            name_hash,
            version_hash,
            U256::from(chain_id),
            verifying_contract,
        )
            .abi_encode(),
    )
    .into();

    let typehash: [u8; 32] = keccak256(VOTE_TYPEHASH_STR).into();
    let struct_hash: [u8; 32] = keccak256(
        (
            typehash,
            U256::from(e3_id),
            FixedBytes::<32>::from(accusation_id),
            voter,
            FixedBytes::<32>::from(data_hash),
            U256::from(issued_at),
            U256::from(deadline),
        )
            .abi_encode(),
    )
    .into();

    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(&struct_hash);
    keccak256(&buf).into()
}

/// The actor's `vote_digest` must equal the reference digest byte-for-byte.
#[test]
fn vote_digest_matches_reference() {
    let chain_id = 31337u64;
    let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let voter: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let accusation_id = [0xab; 32];
    let data_hash = [0xcd; 32];
    let issued_at = 1_699_999_000;
    let deadline: u64 = 1_700_000_000;

    let vote = AccusationVote {
        e3_id: E3id::new("42", chain_id),
        accusation_id,
        voter,
        data_hash,
        issued_at,
        deadline,
        signature: ArcBytes::default(),
    };

    let actor = AccusationManager::vote_digest(&vote, verifying_contract);
    let reference = reference_vote_digest(
        chain_id,
        verifying_contract,
        42,
        accusation_id,
        voter,
        data_hash,
        issued_at,
        deadline,
    );

    assert_eq!(
        actor, reference,
        "AccusationManager::vote_digest drifted from the reference EIP-712 \
             computation. Check VOTE_TYPEHASH_STR / VOTE_DOMAIN_NAME against \
             SlashingManager.sol — these MUST stay byte-equal across crates."
    );
}

/// The accusation digest must include `deadline`.
#[test]
fn accusation_digest_binds_deadline() {
    let make = |deadline: u64| ProofFailureAccusation {
        e3_id: E3id::new("9", 31337),
        accuser: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
        accused: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .unwrap(),
        accused_party_id: 1,
        proof_type: ProofType::C1PkGeneration,
        data_hash: [0x42; 32],
        issued_at: 1_699_999_000,
        deadline,
        signed_payload: None,
        signature: ArcBytes::default(),
    };
    let a = AccusationVoting::accusation_digest(&make(1_700_000_000));
    let b = AccusationVoting::accusation_digest(&make(1_700_000_001));
    assert_ne!(a, b, "deadline must be part of the accusation digest");
}

#[test]
fn peer_deadline_acceptance_enforces_local_window() {
    let now = 1_700_000_000u64;
    let validity = 1_800u64;
    let skew = DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS;
    let issued_at = now + skew;
    let max_ok = issued_at + validity;

    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(now, now, now, validity, skew),
        "deadline equal to now must be rejected"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(
            now - validity,
            now - 1,
            now,
            validity,
            skew
        ),
        "expired deadline must be rejected"
    );
    assert!(
        AccusationVoting::is_peer_deadline_acceptable(issued_at, max_ok, now, validity, skew),
        "deadline at upper bound must be accepted"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(issued_at, max_ok + 1, now, validity, skew),
        "far-future deadline must be rejected"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(now, now + 10, now, 0, skew),
        "vote_validity_secs=0 must reject peer accusations"
    );
}

/// A slash that does not expel leaves the operator a voter, so its vote still completes the
/// quorum. An expulsion removes the voter.
#[actix::test]
async fn only_an_expulsion_removes_a_voter() -> anyhow::Result<()> {
    use alloy::signers::SignerSync;
    use e3_events::{
        AccusationQuorumReached, AggregateConfig, AggregateId, CommitmentConsistencyViolation,
        CommitteeMemberExpelled, Event, EventConstructorWithTimestamp, EventSource, GetEvents,
        SlashExecuted, Unsequenced,
    };

    for expelled in [false, true] {
        let system = e3_event_system::EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                AggregateId::from_chain_id(Some(31337)),
                std::time::Duration::ZERO,
            )])));
        let bus = system.handle()?.enable("expulsion-removes-voter");
        let history = bus.history();
        let me = PrivateKeySigner::random();
        let voter = PrivateKeySigner::random();
        let accused = Address::repeat_byte(0x33);
        let slashing_manager = Address::repeat_byte(0x44);
        let e3_id = E3id::new("5", 31337);
        // T = 1 and N = 3 give the quorum H = 2: this node's vote and the voter's.
        let manager = AccusationManager::new(
            &bus,
            e3_id.clone(),
            me.clone(),
            slashing_manager,
            vec![me.address(), voter.address(), accused],
            1,
            300,
            DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS,
            e3_fhe_params::BfvPreset::InsecureThreshold64,
        )
        .start();
        let event = |data: InterfoldEventData, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                data,
                None,
                seq as u128,
                None,
                EventSource::Evm,
            )
            .into_sequenced(seq)
        };
        let removal: InterfoldEventData = if expelled {
            CommitteeMemberExpelled {
                e3_id: e3_id.clone(),
                node: voter.address(),
                reason: [0; 32],
                active_count_after: 2,
                party_id: None,
            }
            .into()
        } else {
            SlashExecuted {
                e3_id: e3_id.clone(),
                proposal_id: 1,
                operator: voter.address(),
                reason: [0; 32],
                ticket_amount: 1,
                ciphernode_bond_amount: 0,
            }
            .into()
        };
        manager.send(event(removal, 1)).await?;
        manager
            .send(event(
                CommitmentConsistencyViolation {
                    e3_id: e3_id.clone(),
                    accused_address: accused,
                    accused_party_id: 2,
                    proof_type: ProofType::C1PkGeneration,
                    data_hash: [7; 32],
                    evidence: Default::default(),
                }
                .into(),
                2,
            ))
            .await?;
        let accusation = actix::clock::timeout(std::time::Duration::from_secs(5), async {
            loop {
                for event in history.send(GetEvents::new()).await? {
                    if let InterfoldEventData::ProofFailureAccusation(accusation) =
                        event.into_data()
                    {
                        return Ok::<_, anyhow::Error>(accusation);
                    }
                }
                actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await??;

        let mut vote = AccusationVote {
            e3_id: e3_id.clone(),
            accusation_id: AccusationVoting::accusation_id(&accusation),
            voter: voter.address(),
            data_hash: accusation.data_hash,
            issued_at: accusation.issued_at,
            deadline: accusation.deadline,
            signature: ArcBytes::default(),
        };
        let digest = AccusationVoting::vote_digest(&vote, slashing_manager);
        let signature = voter.sign_hash_sync(&digest.into())?;
        vote.signature = ArcBytes::from_bytes(&signature.as_bytes());
        manager.send(event(vote.into(), 3)).await?;
        actix::clock::sleep(std::time::Duration::from_millis(200)).await;

        let quorum = history
            .send(GetEvents::new())
            .await?
            .into_iter()
            .any(|event| {
                matches!(
                    event.get_data(),
                    InterfoldEventData::AccusationQuorumReached(AccusationQuorumReached { .. })
                )
            });
        assert_eq!(quorum, !expelled, "expelled={expelled}");
    }
    Ok(())
}
