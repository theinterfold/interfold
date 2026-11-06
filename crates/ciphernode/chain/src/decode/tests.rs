// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy_sol_types::SolEvent;

const CONFIG: B256 = B256::repeat_byte(0xcc);

fn contracts() -> Contracts {
    Contracts {
        chain_id: 1,
        interfold: Address::repeat_byte(0x1f),
        registry: Address::repeat_byte(0x2e),
        bonding: Address::repeat_byte(0x3b),
        randomness: BTreeSet::from([Address::repeat_byte(0x4a)]),
        crypto_config: CONFIG,
    }
}

/// `event` as the contract at `address` logs it in transaction `transaction`, at `index`.
fn log(address: Address, event: &impl SolEvent, transaction: u8, index: u64) -> RawLog {
    let data = event.encode_log_data();
    RawLog {
        address,
        topics: data.topics().to_vec(),
        data: data.data,
        at: LogPosition {
            chain_id: 1,
            block: 10,
            log_index: index,
        },
        time: 1_000,
        transaction: B256::repeat_byte(transaction),
    }
}

fn facts(decoded: Vec<Decoded>) -> Vec<ChainFact> {
    decoded
        .into_iter()
        .filter_map(|decoded| match decoded {
            Decoded::Fact(event) => Some(event.fact),
            Decoded::Read(_) => None,
        })
        .collect()
}

fn e3_requested(config: B256) -> IInterfold::E3Requested {
    IInterfold::E3Requested {
        e3Id: U256::from(7),
        e3: IInterfold::E3 {
            seed: U256::from(42),
            committeeSize: 0,
            requestBlock: U256::from(999),
            inputWindow: [U256::ZERO; 2],
            encryptionSchemeId: B256::ZERO,
            e3Program: Address::ZERO,
            paramSet: 1,
            customParams: Bytes::new(),
            decryptionVerifier: Address::ZERO,
            pkVerifier: Address::ZERO,
            committeePublicKey: B256::ZERO,
            ciphertextOutput: B256::ZERO,
            plaintextOutput: Bytes::new(),
            requester: Address::ZERO,
            ciphertextCommitment: B256::ZERO,
        },
        cryptoConfigId: config,
    }
}

/// The logs of one request transaction: the registry's parts, then `E3Requested`.
fn request(decoder: &mut Decoder, config: B256) -> Vec<ChainFact> {
    let c = contracts();
    let attestation = ICiphernodeRegistry::DkgFoldAttestationContextEstablished {
        e3Id: U256::from(7),
        registry: c.registry,
        dkgFoldAttestationVerifier: Address::repeat_byte(0x5f),
    };
    let requested = ICiphernodeRegistry::CommitteeRequested {
        e3Id: U256::from(7),
        entropyBlock: U256::ZERO,
        threshold: [1, 3],
        requestBlock: U256::from(999),
        committeeDeadline: U256::from(2_000),
        ticketPrice: U256::from(5),
    };
    let cap = extra::CommitteeBondOwnerCapEnabled {
        e3Id: U256::from(7),
    };
    let mut all = Vec::new();
    for raw in [
        log(c.registry, &attestation, 1, 0),
        log(c.registry, &requested, 1, 1),
        log(c.registry, &cap, 1, 2),
        log(c.interfold, &e3_requested(config), 1, 3),
    ] {
        all.extend(facts(decoder.decode(&raw).unwrap()));
    }
    all
}

#[test]
fn a_request_becomes_one_fact_with_the_parts_its_transaction_logged_first() {
    let mut decoder = Decoder::new(contracts());
    let facts = request(&mut decoder, CONFIG);
    let expected = ChainFact::E3Requested {
        e3: E3Id {
            chain_id: 1,
            number: U256::from(7),
        },
        params: CryptoParams {
            param_set: 1,
            committee_size: CiphernodesCommitteeSize::Minimum,
            seed: B256::from(U256::from(42)),
        },
        interfold: contracts().interfold,
        attestation: AttestationContext {
            registry: contracts().registry,
            verifier: Address::repeat_byte(0x5f),
        },
        request: CommitteeRequest {
            time: 999,
            ticket_price: U256::from(5),
            owner_cap: true,
        },
    };
    assert_eq!(facts, vec![expected]);
}

#[test]
fn a_request_for_another_crypto_configuration_is_skipped() {
    let mut decoder = Decoder::new(contracts());
    assert!(request(&mut decoder, B256::repeat_byte(0xdd)).is_empty());
}

#[test]
fn finalization_reads_the_dkg_timing_for_the_committee_its_transaction_logged() {
    let c = contracts();
    let mut decoder = Decoder::new(c.clone());
    let members = vec![Address::repeat_byte(1), Address::repeat_byte(2)];
    let sortition = ICiphernodeRegistry::SortitionCommitteeFinalized {
        e3Id: U256::from(7),
        committee: members.clone(),
        scores: vec![U256::from(1), U256::from(2)],
    };
    assert!(decoder
        .decode(&log(c.registry, &sortition, 2, 0))
        .unwrap()
        .is_empty());
    let finalized = IInterfold::CommitteeFinalized {
        e3Id: U256::from(7),
    };
    let decoded = decoder.decode(&log(c.interfold, &finalized, 2, 1)).unwrap();
    let [Decoded::Read(PendingRead::DkgTiming { members: read, .. })] = decoded.as_slice() else {
        panic!("a DKG timing read, got {decoded:?}");
    };
    assert_eq!(*read, members);
}

#[test]
fn the_key_proof_names_the_roster_by_committee_slot() {
    let c = contracts();
    let mut decoder = Decoder::new(c.clone());
    request(&mut decoder, CONFIG);
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
    let facts = facts(decoder.decode(&log(c.registry, &published, 3, 0)).unwrap());
    let [ChainFact::KeyPublished { roster, .. }] = facts.as_slice() else {
        panic!("a published key, got {facts:?}");
    };
    assert_eq!(*roster, vec![committee[0], committee[2]]);
}

#[test]
fn an_unknown_stage_stops_ingestion() {
    let c = contracts();
    let changed = IInterfold::E3StageChanged {
        e3Id: U256::from(7),
        previousStage: 1,
        newStage: 9,
    };
    let mut decoder = Decoder::new(c.clone());
    assert!(matches!(
        decoder.decode(&log(c.interfold, &changed, 4, 0)),
        Err(DecodeError::UnknownEnum {
            kind: "stage",
            value: 9
        })
    ));
}

#[test]
fn only_eligibility_parameters_reset_activity() {
    let c = contracts();
    let mut decoder = Decoder::new(c.clone());
    let updated = |name: &str| IBondingRegistry::ConfigurationUpdated {
        parameter: B256::right_padding_from(name.as_bytes()),
        oldValue: U256::ZERO,
        newValue: U256::from(1),
    };
    let reset = facts(
        decoder
            .decode(&log(c.bonding, &updated("ticketPrice"), 5, 0))
            .unwrap(),
    );
    assert_eq!(reset, vec![ChainFact::EligibilityReset]);
    assert!(decoder
        .decode(&log(c.bonding, &updated("exitDelay"), 5, 1))
        .unwrap()
        .is_empty());
}

#[test]
fn only_a_known_randomness_provider_readies_a_seed() {
    let c = contracts();
    let mut decoder = Decoder::new(c.clone());
    let fulfilled = IRandomnessProvider::RandomnessFulfilled {
        requestId: U256::from(1),
        e3Id: U256::from(7),
        randomWord: U256::from(3),
        fulfilledAt: U256::from(1_000),
    };
    let known = decoder
        .decode(&log(Address::repeat_byte(0x4a), &fulfilled, 6, 0))
        .unwrap();
    assert!(matches!(
        known.as_slice(),
        [Decoded::Read(PendingRead::Seed { .. })]
    ));
    let unknown = decoder
        .decode(&log(Address::repeat_byte(0x6b), &fulfilled, 6, 1))
        .unwrap();
    assert!(unknown.is_empty());
}
