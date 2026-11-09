// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A Minimum committee through every job with real threshold-BFV math: keys, shares, decryption
//! keys, the committee key, encryption, decryption shares, and the plaintext.

use crate::{
    trbfv, Attempt, BlobStore, Blobs, JobError, JobLimits, JobRunner, MemoryBlobs, Proofs,
};
use alloy_primitives::{Address, B256, U256};
use e3_committee::CiphernodesCommitteeSize;
use e3_crypto::Cipher;
use e3_fhe_params::BfvPreset;
use e3_protocol::{
    accusation::Verdict,
    decryption::{DecryptionWork, DecryptionWorkResult, SharesMessage as DecryptionShares},
    dkg::{DkgWork, DkgWorkResult, KeyshareMessage, OwnKey, OwnShares, SharesMessage},
    node::{CryptoParams, Job, Work, WorkResult},
    proof::SignedProof,
    BlobRef, E3Id,
};
use std::collections::BTreeMap;

fn params() -> CryptoParams {
    let param_set = (0..=u8::MAX)
        .find(|set| {
            BfvPreset::from_on_chain_param_set(*set) == Some(BfvPreset::InsecureThreshold64)
        })
        .expect("development chains support the insecure set");
    CryptoParams {
        param_set,
        committee_size: CiphernodesCommitteeSize::Minimum,
        seed: B256::ZERO,
    }
}

const E3: E3Id = E3Id {
    chain_id: 1,
    number: U256::ZERO,
};

fn job(work: Work) -> Job {
    Job {
        e3: E3,
        params: params(),
        work,
    }
}

fn dkg(runner: &JobRunner<MemoryBlobs>, work: DkgWork) -> DkgWorkResult {
    match runner
        .run(&job(Work::Dkg(work)), &Attempt::default())
        .unwrap()
    {
        WorkResult::Dkg(result) => result,
        other => panic!("a DKG result, got {other:?}"),
    }
}

fn decryption(runner: &JobRunner<MemoryBlobs>, work: DecryptionWork) -> DecryptionWorkResult {
    match runner
        .run(&job(Work::Decryption(work)), &Attempt::default())
        .unwrap()
    {
        WorkResult::Decryption(result) => result,
        other => panic!("a decryption result, got {other:?}"),
    }
}

fn unsigned(proof: e3_protocol::proof::ZkProof) -> SignedProof {
    SignedProof {
        proof,
        signature: Default::default(),
    }
}

/// Tests share one store between nodes, as a network would carry their blobs.
fn runner(blobs: MemoryBlobs, cipher: Cipher, node: u8) -> JobRunner<MemoryBlobs> {
    let limits = JobLimits {
        threads: 2,
        scope: B256::repeat_byte(node),
    };
    JobRunner::new(blobs, cipher, Proofs::Placeholder, limits).unwrap()
}

/// A job that runs again after a restart must use the inputs it drew before: its finished proofs
/// are only valid for those.
#[tokio::test]
async fn a_repeated_job_has_the_same_random_inputs() {
    let cipher = Cipher::from_password("node").await.unwrap();
    let runner = runner(MemoryBlobs::default(), cipher, 1);
    let key = || match dkg(&runner, DkgWork::MakeEncryptionKey) {
        DkgWorkResult::EncryptionKeyMade(own) => own,
        other => panic!("{other:?}"),
    };
    let (first, second) = (key(), key());
    assert_eq!(first.public, second.public);
    assert_eq!(first.proof, second.proof);

    let member = Address::repeat_byte(1);
    let committee = vec![member, Address::repeat_byte(2), Address::repeat_byte(3)];
    let keys = BTreeMap::from([(committee[1], first.public), (committee[2], first.public)]);
    let shares = || {
        let work = DkgWork::MakeShares {
            dealer: member,
            committee: committee.clone(),
            own_key: first.public,
            keys: keys.clone(),
        };
        match dkg(&runner, work) {
            DkgWorkResult::SharesMade(made) => made,
            other => panic!("{other:?}"),
        }
    };
    let (first, second) = (shares(), shares());
    assert_eq!(first.pk_share, second.pk_share);
    assert_eq!(first.c1, second.c1);
    assert_eq!(first.recipients, second.recipients);
}

/// The seed comes from the operating system: two nodes never draw the same key.
#[tokio::test]
async fn nodes_draw_different_keys() {
    let cipher = || Cipher::from_password("node");
    let (one, other) = (
        runner(MemoryBlobs::default(), cipher().await.unwrap(), 1),
        runner(MemoryBlobs::default(), cipher().await.unwrap(), 1),
    );
    let key = |runner: &JobRunner<MemoryBlobs>| match dkg(runner, DkgWork::MakeEncryptionKey) {
        DkgWorkResult::EncryptionKeyMade(own) => own.public,
        other => panic!("{other:?}"),
    };
    assert_ne!(key(&one), key(&other));
}

#[tokio::test]
async fn a_cancelled_job_does_not_run() {
    let cipher = Cipher::from_password("node").await.unwrap();
    let runner = runner(MemoryBlobs::default(), cipher, 1);
    let attempt = Attempt::default();
    attempt.cancel.cancel();
    let result = runner.run(&job(Work::Dkg(DkgWork::MakeEncryptionKey)), &attempt);
    assert!(matches!(result, Err(JobError::Cancelled)));
}

#[tokio::test]
async fn a_committee_s_jobs_decrypt_what_its_key_encrypts() {
    let blobs = MemoryBlobs::default();
    let mut members: Vec<Address> = (1..=3).map(Address::repeat_byte).collect();
    members.sort();
    let mut runners = Vec::new();
    for member in &members {
        let cipher = Cipher::from_password(&format!("node {member}"))
            .await
            .unwrap();
        runners.push(runner(blobs.clone(), cipher, member.0[0]));
    }

    let keys: Vec<OwnKey> = runners
        .iter()
        .map(|runner| match dkg(runner, DkgWork::MakeEncryptionKey) {
            DkgWorkResult::EncryptionKeyMade(own) => own,
            other => panic!("{other:?}"),
        })
        .collect();
    for (runner, key) in runners.iter().zip(&keys) {
        let checked = dkg(
            runner,
            DkgWork::CheckEncryptionKey {
                sender: members[0],
                key: keys[0].public,
                proof: keys[0].proof.clone(),
            },
        );
        assert_eq!(
            checked,
            DkgWorkResult::EncryptionKeyChecked {
                sender: members[0],
                verdict: Verdict::Valid
            }
        );
        let _ = key;
    }

    let dealt: Vec<OwnShares> = (0..3)
        .map(|dealer| {
            let others = (0..3)
                .filter(|other| *other != dealer)
                .map(|other| (members[other], keys[other].public))
                .collect();
            match dkg(
                &runners[dealer],
                DkgWork::MakeShares {
                    dealer: members[dealer],
                    committee: members.clone(),
                    own_key: keys[dealer].public,
                    keys: others,
                },
            ) {
                DkgWorkResult::SharesMade(made) => made,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    let message = |dealer: usize, recipient: usize| {
        let shares = &dealt[dealer].recipients[&members[recipient]];
        SharesMessage {
            recipient: members[recipient],
            pk_share: dealt[dealer].pk_share,
            shares: shares.shares.expect("every member has a key"),
            c2a: unsigned(dealt[dealer].c2a.clone()),
            c2b: unsigned(dealt[dealer].c2b.clone()),
            c3a: shares.c3a.iter().cloned().map(unsigned).collect(),
            c3b: shares.c3b.iter().cloned().map(unsigned).collect(),
        }
    };
    let checked = dkg(
        &runners[1],
        DkgWork::CheckShares {
            dealer: members[0],
            committee: members.clone(),
            secret: keys[1].secret,
            own_key: keys[1].proof.clone(),
            message: Box::new(message(0, 1)),
        },
    );
    assert_eq!(
        checked,
        DkgWorkResult::SharesChecked {
            dealer: members[0],
            verdict: Verdict::Valid
        }
    );
    let swapped = SharesMessage {
        shares: message(0, 2).shares,
        ..message(0, 1)
    };
    let tampered = dkg(
        &runners[1],
        DkgWork::CheckShares {
            dealer: members[0],
            committee: members.clone(),
            secret: keys[1].secret,
            own_key: keys[1].proof.clone(),
            message: Box::new(swapped),
        },
    );
    assert_eq!(
        tampered,
        DkgWorkResult::SharesChecked {
            dealer: members[0],
            verdict: Verdict::Invalid
        }
    );

    // The roster is the first two members; each sums the other's shares and its own.
    let roster = [0, 1];
    let decryption_keys: Vec<e3_protocol::SealedRef> = roster
        .iter()
        .map(|&member| {
            let other = roster
                .iter()
                .copied()
                .find(|other| *other != member)
                .unwrap();
            let shares = BTreeMap::from([(members[other], message(other, member).shares)]);
            match dkg(
                &runners[member],
                DkgWork::MakeDecryptionKey {
                    member: members[member],
                    committee: members.clone(),
                    secret: keys[member].secret,
                    own_share: dealt[member].own_share,
                    shares,
                    c2: BTreeMap::new(),
                },
            ) {
                DkgWorkResult::DecryptionKeyMade(made) => made.key,
                other => panic!("{other:?}"),
            }
        })
        .collect();

    let keyshares: Vec<KeyshareMessage> = roster
        .iter()
        .map(|&member| KeyshareMessage {
            pk_share: dealt[member].pk_share,
            c1: unsigned(dealt[member].c1.clone()),
        })
        .collect();
    for keyshare in &keyshares {
        let checked = dkg(
            &runners[2],
            DkgWork::CheckKeyshare {
                member: members[0],
                committee: members.clone(),
                keyshare: Box::new(keyshare.clone()),
            },
        );
        assert_eq!(
            checked,
            DkgWorkResult::KeyshareChecked {
                member: members[0],
                verdict: Verdict::Valid
            }
        );
    }
    let key = match dkg(
        &runners[2],
        DkgWork::AggregateKey {
            committee: members.clone(),
            roster: roster.iter().map(|member| members[*member]).collect(),
            keyshares,
            folds: Vec::new(),
        },
    ) {
        DkgWorkResult::KeyAggregated(key) => key,
        other => panic!("{other:?}"),
    };

    let message_values = vec![7u64, 11, 13];
    let ciphertext =
        crate::encrypt(&blobs.of(E3), &params(), &key.public_key, &message_values).unwrap();

    let domain = B256::repeat_byte(0xd0);
    let shares: BTreeMap<Address, DecryptionShares> = roster
        .iter()
        .zip(&decryption_keys)
        .map(|(&member, key)| {
            match decryption(
                &runners[member],
                DecryptionWork::MakeShares {
                    key: *key,
                    ciphertext,
                    domain,
                },
            ) {
                DecryptionWorkResult::SharesMade(made) => (
                    members[member],
                    DecryptionShares {
                        shares: made.shares,
                        c6: made.c6.into_iter().map(unsigned).collect(),
                    },
                ),
                other => panic!("{other:?}"),
            }
        })
        .collect();
    for (member, message) in &shares {
        let checked = decryption(
            &runners[2],
            DecryptionWork::CheckShares {
                member: *member,
                committee: members.clone(),
                ciphertext,
                domain,
                anchor: None,
                message: Box::new(message.clone()),
            },
        );
        assert_eq!(
            checked,
            DecryptionWorkResult::SharesChecked {
                member: *member,
                verdict: Verdict::Valid
            }
        );
    }
    let published = match decryption(
        &runners[2],
        DecryptionWork::AggregatePlaintext {
            committee: members.clone(),
            ciphertext,
            domain,
            shares,
        },
    ) {
        DecryptionWorkResult::PlaintextMade(published) => published,
        other => panic!("{other:?}"),
    };
    let decrypted = blobs.of(E3).get(&published.plaintext).unwrap();
    let values: Vec<u64> = decrypted
        .chunks(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    assert_eq!(values[..3], message_values[..]);
}

#[tokio::test]
async fn a_secret_is_stored_sealed_and_a_key_that_does_not_decode_fails_its_check() {
    let blobs = MemoryBlobs::default();
    let cipher = Cipher::from_password("node").await.unwrap();
    let runner = runner(blobs.clone(), cipher, 1);
    let DkgWorkResult::EncryptionKeyMade(own) = dkg(&runner, DkgWork::MakeEncryptionKey) else {
        panic!("a key");
    };
    let dkg_params = trbfv::dkg_params(&params()).unwrap();
    let stored = blobs.of(E3).get_sealed(&own.secret).unwrap();
    assert!(e3_trbfv::helpers::deserialize_secret_key(&stored, &dkg_params).is_err());
    assert!(e3_trbfv::helpers::deserialize_secret_key(
        &runner
            .jobs(
                &job(Work::Dkg(DkgWork::MakeEncryptionKey)),
                &Attempt::default()
            )
            .unwrap()
            .unseal(&own.secret)
            .unwrap(),
        &dkg_params
    )
    .is_ok());

    let garbage = blobs.of(E3).put(b"not a key").unwrap();
    let proof = crate::placeholder::proof(
        &blobs.of(E3),
        e3_protocol::proof::ProofType::C0PkBfv,
        b"not a key",
    )
    .unwrap();
    let checked = dkg(
        &runner,
        DkgWork::CheckEncryptionKey {
            sender: Address::ZERO,
            key: garbage,
            proof,
        },
    );
    assert_eq!(
        checked,
        DkgWorkResult::EncryptionKeyChecked {
            sender: Address::ZERO,
            verdict: Verdict::Invalid
        }
    );
}

#[test]
fn a_node_runs_at_most_its_limit_of_proofs_at_once() {
    use crate::Circuits;
    use e3_zk_prover::{BBPath, ZkBackend, ZkProver};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Duration,
    };

    let backend = ZkBackend::new(
        BBPath::Custom("bb".into()),
        "circuits".into(),
        "work".into(),
    );
    let circuits = Circuits::new(ZkProver::new(&backend), 2, 1).unwrap();
    let attempt = crate::Attempt::default();
    let prover = circuits.for_attempt(&attempt);
    let (running, most) = (AtomicUsize::new(0), AtomicUsize::new(0));
    thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                prover
                    .proving(|_| {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok::<_, JobError>(())
                    })
                    .unwrap()
            });
        }
    });
    assert_eq!(most.load(Ordering::SeqCst), 2);
}

/// A dealer's C3 proofs count only when each names this node's key and the row the dealer's C2
/// commits to for this node's slot, one per row.
#[test]
fn c3_proofs_must_name_this_node_s_key_and_its_rows() {
    use e3_protocol::proof::ZkProof;
    let (rows, party) = (2, 1);
    let word = B256::repeat_byte;
    let proof = |inputs: Vec<B256>| ZkProof {
        data: BlobRef::of(&[0]),
        public_inputs: inputs,
    };
    let own_key = proof(vec![word(0xc0)]);
    // C2: the secret's commitment, then three parties' row commitments.
    let c2 = |base: u8| proof((0..1 + 3 * rows as u8).map(|i| word(base + i)).collect());
    let (c2a, c2b) = (c2(0x10), c2(0x40));
    let row = |c2: &ZkProof, party: usize, row: usize| c2.public_inputs[1 + party * rows + row];
    // C3: this key and that message as its inputs, the ciphertext's commitment as its output.
    let c3 = |key: u8, message: B256| unsigned(proof(vec![word(key), message, word(0xee)]));
    let rows_for = |c2: &ZkProof| -> Vec<SignedProof> {
        (0..rows).map(|n| c3(0xc0, row(c2, party, n))).collect()
    };
    let checks = |c3a: Vec<SignedProof>, c3b: Vec<SignedProof>| {
        let message = SharesMessage {
            recipient: Address::repeat_byte(1),
            pk_share: BlobRef::of(&[1]),
            shares: BlobRef::of(&[2]),
            c2a: unsigned(c2a.clone()),
            c2b: unsigned(c2b.clone()),
            c3a,
            c3b,
        };
        crate::dkg::c3_names_this_node(&own_key, party, rows, &message)
    };
    assert!(checks(rows_for(&c2a), rows_for(&c2b)));

    let mut another_key = rows_for(&c2a);
    another_key[0] = c3(0xc1, row(&c2a, party, 0));
    assert!(!checks(another_key, rows_for(&c2b)));

    let mut another_slot = rows_for(&c2b);
    another_slot[1] = c3(0xc0, row(&c2b, 0, 1));
    assert!(!checks(rows_for(&c2a), another_slot));

    let mut missing = rows_for(&c2a);
    missing.pop();
    assert!(!checks(missing, rows_for(&c2b)));
}
