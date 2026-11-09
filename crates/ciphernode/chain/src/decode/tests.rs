// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::testing::{contracts, e3_requested, CONFIG, RANDOMNESS};

/// `event` as the contract at `address` logs it in block 10, in transaction `transaction`.
fn log(address: Address, event: &impl SolEvent, transaction: u8, index: u64) -> RawLog {
    crate::testing::log(address, event, 10, transaction, index)
}

/// The facts in `logs`, decoded as one batch.
fn facts(logs: &[RawLog]) -> Vec<ChainFact> {
    decode(&contracts(), logs)
        .unwrap()
        .into_iter()
        .filter_map(|decoded| match decoded {
            Decoded::Fact(event) => Some(event.fact),
            Decoded::Read(_) => None,
        })
        .collect()
}

/// The logs of one request transaction: the registry's parts, then `E3Requested`.
fn request(config: B256) -> Vec<RawLog> {
    let c = contracts();
    let attestation = ICiphernodeRegistry::DkgFoldAttestationContextEstablished {
        e3Id: U256::from(7),
        registry: c.registry,
        dkgFoldAttestationVerifier: Address::repeat_byte(0x5f),
    };
    let cap = ICiphernodeRegistry::CommitteeBondOwnerCapEnabled {
        e3Id: U256::from(7),
    };
    vec![
        log(c.registry, &attestation, 1, 0),
        log(c.registry, &cap, 1, 1),
        log(c.interfold, &e3_requested(config), 1, 2),
    ]
}

#[test]
fn a_request_is_read_with_the_parts_its_transaction_logged_first() {
    let decoded = decode(&contracts(), &request(CONFIG)).unwrap();
    let [Decoded::Read(PendingRead::Request {
        time,
        params,
        interfold,
        attestation,
        owner_cap,
        ..
    })] = decoded.as_slice()
    else {
        panic!("a request read, got {decoded:?}");
    };
    let expected = CryptoParams {
        param_set: 1,
        committee_size: CiphernodesCommitteeSize::Minimum,
        seed: B256::from(U256::from(42)),
    };
    assert_eq!(*params, expected);
    assert_eq!(*time, request(CONFIG)[2].time);
    assert_eq!(*interfold, contracts().interfold);
    assert_eq!(attestation.verifier, Address::repeat_byte(0x5f));
    assert!(*owner_cap);
}

#[test]
fn a_request_for_another_crypto_configuration_is_skipped() {
    let other = request(B256::repeat_byte(0xdd));
    assert!(decode(&contracts(), &other).unwrap().is_empty());
}

/// `finalizeCommittee` calls the Interfold, which logs `CommitteeFinalized`, before the registry
/// logs the committee.
#[test]
fn a_finalized_committee_reads_its_dkg_timing() {
    let c = contracts();
    let members = vec![Address::repeat_byte(1), Address::repeat_byte(2)];
    let sortition = ICiphernodeRegistry::SortitionCommitteeFinalized {
        e3Id: U256::from(7),
        committee: members.clone(),
        scores: vec![U256::from(1), U256::from(2)],
    };
    let finalized = IInterfold::CommitteeFinalized {
        e3Id: U256::from(7),
    };
    let logs = [
        log(c.interfold, &finalized, 2, 0),
        log(c.registry, &sortition, 2, 1),
    ];
    let decoded = decode(&c, &logs).unwrap();
    let [Decoded::Read(PendingRead::DkgTiming { members: read, .. })] = decoded.as_slice() else {
        panic!("a DKG timing read, got {decoded:?}");
    };
    assert_eq!(*read, members);
}

/// A restarted reader has not seen the request; the proof alone names the roster.
#[test]
fn the_key_proof_names_the_roster_by_committee_slot() {
    let c = contracts();
    let committee: Vec<Address> = (1..=3).map(Address::repeat_byte).collect();
    let commitment = B256::repeat_byte(0x99);
    let h = 2;
    let mut inputs = vec![B256::ZERO; 6 + 3 * h];
    inputs[2] = B256::from(U256::from(0));
    inputs[3] = B256::from(U256::from(2));
    *inputs.last_mut().unwrap() = commitment;
    let proof = (Bytes::from(vec![1, 2, 3]), inputs).abi_encode_params();
    let published = ICiphernodeRegistry::CommitteeProofPublished {
        e3Id: U256::from(7),
        nodes: committee.clone(),
        pkCommitment: commitment,
        proof: proof.into(),
    };
    let decoded = decode(&c, &[log(c.registry, &published, 3, 0)]).unwrap();
    let [Decoded::Read(PendingRead::Key { roster, .. })] = decoded.as_slice() else {
        panic!("a published key, got {decoded:?}");
    };
    assert_eq!(*roster, vec![committee[0], committee[2]]);
}

#[test]
fn only_the_slashing_manager_releases_an_e3() {
    let c = contracts();
    let released = ISlashingManager::E3DependenciesReleased {
        e3Id: U256::from(7),
    };
    let e3 = E3Id {
        chain_id: 1,
        number: U256::from(7),
    };
    let manager = *c.slashing.first().unwrap();
    let from_manager = facts(&[log(manager, &released, 8, 0)]);
    assert_eq!(from_manager, vec![ChainFact::DependenciesReleased { e3 }]);
    assert!(facts(&[log(c.interfold, &released, 8, 0)]).is_empty());
}

#[test]
fn an_unknown_stage_stops_ingestion() {
    let c = contracts();
    let changed = IInterfold::E3StageChanged {
        e3Id: U256::from(7),
        previousStage: 1,
        newStage: 9,
    };
    assert!(matches!(
        decode(&c, &[log(c.interfold, &changed, 4, 0)]),
        Err(DecodeError::UnknownEnum {
            kind: "stage",
            value: 9
        })
    ));
}

#[test]
fn only_eligibility_parameters_reset_activity() {
    let c = contracts();
    let updated = |name: &str| IBondingRegistry::ConfigurationUpdated {
        parameter: B256::right_padding_from(name.as_bytes()),
        oldValue: U256::ZERO,
        newValue: U256::from(1),
    };
    let reset = facts(&[log(c.bonding, &updated("ticketPrice"), 5, 0)]);
    assert_eq!(reset, vec![ChainFact::EligibilityReset]);
    assert!(facts(&[log(c.bonding, &updated("exitDelay"), 5, 1)]).is_empty());
}

#[test]
fn only_a_known_randomness_provider_readies_a_seed() {
    let c = contracts();
    let fulfilled = IRandomnessProvider::RandomnessFulfilled {
        requestId: U256::from(1),
        e3Id: U256::from(7),
        randomWord: U256::from(3),
        fulfilledAt: U256::from(1_000),
    };
    let known = decode(&c, &[log(RANDOMNESS, &fulfilled, 6, 0)]).unwrap();
    assert!(matches!(
        known.as_slice(),
        [Decoded::Read(PendingRead::Seed { .. })]
    ));
    let unknown = decode(&c, &[log(Address::repeat_byte(0x6b), &fulfilled, 6, 1)]).unwrap();
    assert!(unknown.is_empty());
}

#[test]
fn a_ciphertext_reference_reads_its_decryption_deadline() {
    let c = contracts();
    let published = IInterfold::CiphertextOutputReferencePublished {
        e3Id: U256::from(7),
        contentHash: B256::repeat_byte(0xc7),
        ciphertextCommitment: B256::repeat_byte(0xcc),
        availabilityBlock: 70,
        availabilityLeafIndex: 3,
    };
    let decoded = decode(&c, &[log(c.interfold, &published, 7, 0)]).unwrap();
    let [Decoded::Read(PendingRead::Ciphertext { ciphertext, .. })] = decoded.as_slice() else {
        panic!("a ciphertext read, got {decoded:?}");
    };
    let expected = DataRef {
        hash: B256::repeat_byte(0xc7),
        block: 70,
        leaf: 3,
    };
    assert_eq!(*ciphertext, expected);
}

#[test]
fn the_registry_s_add_and_remove_logs_say_whether_an_operator_is_enabled() {
    let node = Address::repeat_byte(0x71);
    let (index, count) = (U256::from(1), U256::from(2));
    let c = contracts();
    let added = ICiphernodeRegistry::CiphernodeAdded {
        node,
        index,
        numNodes: count,
        size: count,
    };
    let removed = ICiphernodeRegistry::CiphernodeRemoved {
        node,
        index,
        numNodes: count,
        size: count,
    };
    let logs = [
        log(c.registry, &added, 5, 0),
        log(c.registry, &removed, 6, 0),
    ];
    let enabled: Vec<bool> = decode(&c, &logs)
        .unwrap()
        .into_iter()
        .map(|decoded| match decoded {
            Decoded::Fact(ChainEvent {
                fact: ChainFact::OperatorEnabled { operator, enabled },
                ..
            }) if operator == node => enabled,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(enabled, [true, false]);
}

/// A stage field the node does not use still says the contracts changed under it.
#[test]
fn an_unknown_value_in_an_unused_stage_field_stops_ingestion() {
    let c = contracts();
    let changed = IInterfold::E3StageChanged {
        e3Id: U256::from(7),
        previousStage: 9,
        newStage: 2,
    };
    let failed = IInterfold::E3Failed {
        e3Id: U256::from(7),
        failedAtStage: 9,
        reason: 3,
    };
    for logs in [
        [log(c.interfold, &changed, 5, 0)],
        [log(c.interfold, &failed, 5, 0)],
    ] {
        assert!(matches!(
            decode(&c, &logs),
            Err(DecodeError::UnknownEnum {
                kind: "stage",
                value: 9
            })
        ));
    }
}
