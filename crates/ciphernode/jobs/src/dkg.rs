// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DKG's jobs: BFV keys (C0), threshold shares (C1-C3), the decryption key (C4), the node
//! fold, and the committee key (C5 and the DKG aggregation), with the same library calls as the
//! current node.

use crate::{
    placeholder,
    proofs::{self, Priority, Prover},
    trbfv, Attempt, BlobStore, Blobs, JobError, Jobs, OwnShareRows, Prefolds, RecipientCiphertexts,
    SealedDecryptionKey,
};
use alloy_primitives::{keccak256, Address, B256};
use e3_crypto::SensitiveBytes;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_protocol::{
    accusation::Verdict,
    dkg::{
        AggregatedKey, DecryptionKeyMessage, DkgProofs, DkgWork, DkgWorkResult, KeyshareMessage,
        NodeFold, OwnDecryptionKey, OwnKey, OwnShares, RecipientShares, SharesMessage,
    },
    node::CryptoParams,
    proof::{ProofType, SignedProof, ZkProof},
    BlobRef, E3Id, SealedRef,
};
use e3_trbfv::{
    calculate_decryption_key::{calculate_decryption_key, CalculateDecryptionKeyRequest},
    gen_esi_sss::{gen_esi_sss, GenEsiSssRequest},
    gen_pk_share_and_sk_sss::{
        gen_pk_share_and_sk_sss, GenPkShareAndSkSssRequest, GenPkShareAndSkSssResponse,
    },
    helpers::{
        deserialize_secret_key, serialize_secret_key, try_poly_ntt_from_bytes,
        try_poly_pb_from_bytes,
    },
    shares::{
        BfvEncryptedShare, BfvEncryptedShares, BfvEncryptionWitness, Encrypted, ShamirShare,
        SharedSecret,
    },
};
use e3_zk_config::{CircuitName, CircuitVariant, DkgInputType};
use e3_zk_prover::{
    extract_node_fold_agg_commits, generate_c3_fold_step, generate_nodes_fold_step,
    prove_c2ab_fold, prove_c3ab_fold, prove_c4ab_fold, prove_dkg_aggregation,
    prove_node_fold_final, DkgAggregationInput, DkgShareDecryptionCircuit, PkAggregationCircuit,
    PkCircuit, PkGenerationCircuit, Provable, ShareComputationCircuit, ShareEncryptionCircuit,
};
use e3_zk_witness::{
    compute_dkg_pk_commitment_from_public_key_bytes, compute_pk_commitment_from_keyshare_bytes,
    compute_share_encryption_commitment_from_message,
    dkg::{
        share_computation::ShareComputationCircuitData,
        share_decryption::ShareDecryptionCircuitData, share_encryption::ShareEncryptionCircuitData,
    },
    threshold::{pk_aggregation::PkAggregationCircuitData, pk_generation::PkGenerationCircuitData},
};
use fhe::{
    bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
};
use fhe_traits::{DeserializeParametrized, FheEncoder, Serialize};
use ndarray::Array2;
use num_bigint::BigInt;
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, PoisonError,
    },
    thread,
};

struct PrefoldDoneGuard {
    prefolds: Arc<Prefolds>,
    e3: E3Id,
    done: Arc<(Mutex<bool>, Condvar)>,
}

impl Drop for PrefoldDoneGuard {
    fn drop(&mut self) {
        self.prefolds.mark_finished(self.e3, &self.done);
    }
}

enum MakeSharesTask {
    C1(PkGenerationCircuitData),
    C2a(ShareComputationCircuitData),
    C2b(ShareComputationCircuitData),
    C3 {
        recipient_index: usize,
        is_c3a: bool,
        slot: usize,
        row: usize,
        witness: Box<BfvEncryptionWitness>,
    },
}

enum MakeSharesOutput {
    C1(ZkProof),
    C2a(ZkProof),
    C2b(ZkProof),
    C3 {
        recipient_index: usize,
        is_c3a: bool,
        row: usize,
        proof: ZkProof,
    },
}

impl<B: Blobs, S: BlobStore> Jobs<'_, B, S> {
    pub(crate) fn run_dkg(
        &self,
        params: &CryptoParams,
        work: &DkgWork,
    ) -> Result<DkgWorkResult, JobError> {
        Ok(match work {
            DkgWork::MakeEncryptionKey => {
                DkgWorkResult::EncryptionKeyMade(self.make_encryption_key(params)?)
            }
            DkgWork::CheckEncryptionKey { sender, key, proof } => {
                DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    verdict: self.check_encryption_key(params, key, proof)?,
                }
            }
            DkgWork::MakeShares {
                dealer,
                committee,
                own_key,
                keys,
            } => DkgWorkResult::SharesMade(
                self.make_shares(params, *dealer, committee, own_key, keys)?,
            ),
            DkgWork::CheckShares {
                dealer,
                committee,
                secret,
                own_key,
                message,
            } => DkgWorkResult::SharesChecked {
                dealer: *dealer,
                verdict: self.check_shares(params, committee, secret, own_key, message)?,
            },
            DkgWork::MakeDecryptionKey {
                member,
                secret,
                own_share,
                shares,
                ..
            } => DkgWorkResult::DecryptionKeyMade(
                self.make_decryption_key(params, *member, secret, own_share, shares)?,
            ),
            DkgWork::CheckDecryptionKey {
                member,
                committee,
                c2,
                message,
            } => DkgWorkResult::DecryptionKeyChecked {
                member: *member,
                verdict: self.check_decryption_key(params, *member, committee, c2, message)?,
            },
            DkgWork::FoldProofs {
                member,
                committee,
                proofs,
            } => DkgWorkResult::ProofsFolded(self.fold_proofs(params, *member, committee, proofs)?),
            DkgWork::CheckKeyshare {
                member, keyshare, ..
            } => DkgWorkResult::KeyshareChecked {
                member: *member,
                verdict: self.check_keyshare(params, keyshare)?,
            },
            DkgWork::FoldRoster {
                slot,
                slots,
                fold,
                accumulator,
            } => DkgWorkResult::RosterFolded {
                slot: *slot,
                accumulator: self.fold_roster(params, *slot, *slots, fold, accumulator.as_ref())?,
            },
            DkgWork::AggregateKey {
                committee,
                roster,
                keyshares,
                folds,
                accumulator,
            } => DkgWorkResult::KeyAggregated(self.aggregate_key(
                params,
                committee,
                roster,
                keyshares,
                folds,
                accumulator,
            )?),
        })
    }

    pub(crate) fn make_encryption_key(&self, params: &CryptoParams) -> Result<OwnKey, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let mut rng = self.rng("encryption key")?;
        let secret = SecretKey::random(&bfv, &mut rng);
        let public = PublicKey::new(&secret, &mut rng);
        let proof = self.prove_encryption_key(params, &public)?;
        let secret = serialize_secret_key(&secret).map_err(JobError::crypto)?;
        Ok(OwnKey {
            public: self.blobs.put(&public.to_bytes())?,
            secret: self.seal(&secret)?,
            proof,
        })
    }

    /// C0: the key is a BFV public key under the request's DKG parameters.
    fn prove_encryption_key(
        &self,
        params: &CryptoParams,
        public: &PublicKey,
    ) -> Result<ZkProof, JobError> {
        let Some(prover) = self.prover() else {
            return placeholder::proof(&self.blobs, ProofType::C0PkBfv, &public.to_bytes());
        };
        let dkg = trbfv::dkg_params(params)?;
        let config = e3_zk_config::dkg::pk::Configs::new(&dkg).map_err(JobError::crypto)?;
        self.prove(prover, params, PkCircuit, &config, public, "c0")
    }

    /// A key counts when its C0 proof holds, and the key decodes under the request's DKG
    /// parameters and is the one the proof commits to.
    pub(crate) fn check_encryption_key(
        &self,
        params: &CryptoParams,
        key: &BlobRef,
        proof: &ZkProof,
    ) -> Result<Verdict, JobError> {
        let bfv = trbfv::dkg_params(params)?;
        let bytes = self.blobs.get(key)?;
        let decodes = PublicKey::from_bytes(&bytes, &bfv).is_ok();
        let Some(prover) = self.prover() else {
            let committed = decodes && placeholder::commits_to(proof, &bytes);
            return Ok(placeholder::verdict(committed));
        };
        self.checked(prover, params, [(ProofType::C0PkBfv, proof)], || {
            let commitment = compute_dkg_pk_commitment_from_public_key_bytes(
                &bytes,
                trbfv::threshold_preset(params)?,
            )
            .ok()
            .map(B256::from);
            Ok(decodes
                && commitment.is_some()
                && proofs::field(proof, CircuitName::PkBfv, "pk_commitment") == commitment)
        })
    }

    /// Generate this dealer's public-key share and its secret-key and smudging-noise shares, and
    /// encrypt each member's shares to that member's C0 key. A member without a key keeps a slot
    /// encrypted under this dealer's own key, which it never receives; the dealer's own slot stays
    /// in plaintext, sealed, for its decryption key.
    fn make_shares(
        &self,
        params: &CryptoParams,
        dealer: Address,
        committee: &[Address],
        own_key: &BlobRef,
        keys: &BTreeMap<Address, BlobRef>,
    ) -> Result<OwnShares, JobError> {
        let party = trbfv::party(committee, dealer)?;
        let config = trbfv::config(params)?;
        let dkg = trbfv::dkg_params(params)?;
        let mut rng = self.rng("shares")?;
        let (generated, sk_sss, esi_sss) = self.check_pool.install(|| {
            let generated = gen_pk_share_and_sk_sss(
                &mut rng,
                self.cipher,
                GenPkShareAndSkSssRequest {
                    trbfv_config: config.clone(),
                    crp: trbfv::crp(params)?,
                    lambda: trbfv::lambda(params)?,
                    num_ciphertexts: trbfv::ciphertexts(params)?,
                },
            )
            .map_err(JobError::crypto)?;
            let smudging = gen_esi_sss(
                &mut rng,
                self.cipher,
                GenEsiSssRequest {
                    trbfv_config: config,
                    e_sm_raw: generated.e_sm_raw.clone(),
                },
            )
            .map_err(JobError::crypto)?;
            let sk_sss = generated
                .sk_sss
                .clone()
                .decrypt(self.cipher)
                .map_err(JobError::crypto)?;
            let esi_sss: Vec<_> = smudging
                .esi_sss
                .into_iter()
                .map(|shares| shares.decrypt(self.cipher))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?;
            Ok::<_, JobError>((generated, sk_sss, esi_sss))
        })?;

        let own_public =
            PublicKey::from_bytes(&self.blobs.get(own_key)?, &dkg).map_err(JobError::crypto)?;
        let recipient_keys = committee
            .iter()
            .map(|member| match keys.get(member) {
                Some(key) => {
                    PublicKey::from_bytes(&self.blobs.get(key)?, &dkg).map_err(JobError::crypto)
                }
                None => Ok(own_public.clone()),
            })
            .collect::<Result<Vec<_>, JobError>>()?;
        let slots: Vec<usize> = (0..committee.len()).collect();
        let encrypt = |purpose: String, secret| {
            let mut purpose_rng = self.rng(&purpose)?;
            self.check_pool.install(|| {
                BfvEncryptedShares::encrypt_all_extended_for_share_indices(
                    secret,
                    &recipient_keys,
                    &slots,
                    &dkg,
                    &mut purpose_rng,
                    Some(party),
                )
                .map_err(JobError::crypto)
            })
        };
        let (sk_encrypted, mut sk_witnesses) = encrypt("sk encryption".into(), &sk_sss)?;
        let (esi_encrypted, mut esi_witnesses): (Vec<_>, Vec<_>) = esi_sss
            .iter()
            .enumerate()
            .map(|(index, shares)| encrypt(format!("esi encryption {index}"), shares))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();

        // Serialize and store every recipient's ciphertexts first so `sk_encrypted` and
        // `esi_encrypted` can be dropped before proving begins.
        let other_members: Vec<(usize, Address)> = committee
            .iter()
            .enumerate()
            .filter(|(_, member)| **member != dealer)
            .map(|(slot, member)| (slot, *member))
            .collect();
        let keep_bytes = self.prover().is_none();
        let recipient_blobs: Vec<(Option<BlobRef>, Option<Vec<u8>>)> =
            self.check_pool.install(|| {
                other_members
                    .par_iter()
                    .map(|(slot, member)| {
                        let ciphertexts = RecipientCiphertexts {
                            sk: sk_encrypted
                                .clone_share(*slot)
                                .ok_or(JobError::crypto("no share for a slot"))?,
                            esi: esi_encrypted
                                .iter()
                                .map(|shares| {
                                    shares
                                        .clone_share(*slot)
                                        .ok_or(JobError::crypto("no share for a slot"))
                                })
                                .collect::<Result<_, _>>()?,
                        };
                        let bytes = bincode::serialize(&ciphertexts).map_err(JobError::crypto)?;
                        let shares = match keys.contains_key(member) {
                            true => Some(self.blobs.put(&bytes)?),
                            false => None,
                        };
                        Ok((shares, keep_bytes.then_some(bytes)))
                    })
                    .collect::<Result<Vec<_>, JobError>>()
            })?;
        drop(sk_encrypted);
        drop(esi_encrypted);

        let (recipients, c1, c2a, c2b) = if let Some(prover) = self.prover() {
            let (c1_data, c2a_data, c2b_data, c1_config, c2_config) =
                self.prepare_dealing_witnesses(params, &generated, &sk_sss, &esi_sss)?;
            let c3_config = e3_zk_config::dkg::share_encryption::Configs::new(&dkg)
                .map_err(JobError::crypto)?;

            let mut tasks = VecDeque::new();
            tasks.push_back(MakeSharesTask::C1(c1_data));
            tasks.push_back(MakeSharesTask::C2a(c2a_data));
            tasks.push_back(MakeSharesTask::C2b(c2b_data));

            let mut c3a_counts = vec![0usize; other_members.len()];
            let mut c3b_counts = vec![0usize; other_members.len()];
            for (recipient_index, (slot, _)) in other_members.iter().enumerate() {
                let sk_rows = std::mem::take(&mut sk_witnesses[*slot]);
                c3a_counts[recipient_index] = sk_rows.len();
                for (row, witness) in sk_rows.into_iter().enumerate() {
                    tasks.push_back(MakeSharesTask::C3 {
                        recipient_index,
                        is_c3a: true,
                        slot: *slot,
                        row,
                        witness: Box::new(witness),
                    });
                }
                let mut row = 0usize;
                for esi in &mut esi_witnesses {
                    for witness in std::mem::take(&mut esi[*slot]) {
                        tasks.push_back(MakeSharesTask::C3 {
                            recipient_index,
                            is_c3a: false,
                            slot: *slot,
                            row,
                            witness: Box::new(witness),
                        });
                        row += 1;
                    }
                }
                c3b_counts[recipient_index] = row;
            }
            drop(sk_witnesses);
            drop(esi_witnesses);

            let worker_count = prover.max_concurrent().min(tasks.len()).max(1);
            let queue = Mutex::new(tasks);
            let outputs: Mutex<Vec<MakeSharesOutput>> = Mutex::new(Vec::new());
            let first_err: Mutex<Option<JobError>> = Mutex::new(None);
            let failed = AtomicBool::new(false);

            thread::scope(|scope| {
                for _ in 0..worker_count {
                    scope.spawn(|| {
                        while !failed.load(Ordering::Acquire) {
                            let task = {
                                queue
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .pop_front()
                            };
                            let Some(task) = task else {
                                break;
                            };
                            let result = match task {
                                MakeSharesTask::C1(data) => self
                                    .prove(
                                        prover,
                                        params,
                                        PkGenerationCircuit,
                                        &c1_config,
                                        &data,
                                        "c1",
                                    )
                                    .map(MakeSharesOutput::C1),
                                MakeSharesTask::C2a(data) => self
                                    .prove(
                                        prover,
                                        params,
                                        ShareComputationCircuit,
                                        &c2_config,
                                        &data,
                                        "c2a",
                                    )
                                    .map(MakeSharesOutput::C2a),
                                MakeSharesTask::C2b(data) => self
                                    .prove(
                                        prover,
                                        params,
                                        ShareComputationCircuit,
                                        &c2_config,
                                        &data,
                                        "c2b",
                                    )
                                    .map(MakeSharesOutput::C2b),
                                MakeSharesTask::C3 {
                                    recipient_index,
                                    is_c3a,
                                    slot,
                                    row,
                                    witness,
                                } => {
                                    let proof_type = if is_c3a {
                                        ProofType::C3aSkShareEncryption
                                    } else {
                                        ProofType::C3bESmShareEncryption
                                    };
                                    let work = format!("{proof_type:?}-{slot}-{row}");
                                    let witness = *witness;
                                    let built = Plaintext::try_encode(
                                        &witness.share_row,
                                        Encoding::poly(),
                                        &dkg,
                                    )
                                    .map_err(JobError::crypto)
                                    .map(|plaintext| ShareEncryptionCircuitData {
                                        plaintext,
                                        ciphertext: witness.ciphertext,
                                        public_key: recipient_keys[slot].clone(),
                                        u_rns: witness.u_rns,
                                        e0_rns: witness.e0_rns,
                                        e1_rns: witness.e1_rns,
                                    });
                                    built
                                        .and_then(|data| {
                                            self.prove(
                                                prover,
                                                params,
                                                ShareEncryptionCircuit,
                                                &c3_config,
                                                &data,
                                                &work,
                                            )
                                        })
                                        .map(|proof| MakeSharesOutput::C3 {
                                            recipient_index,
                                            is_c3a,
                                            row,
                                            proof,
                                        })
                                }
                            };
                            match result {
                                Ok(output) => {
                                    outputs
                                        .lock()
                                        .unwrap_or_else(PoisonError::into_inner)
                                        .push(output);
                                }
                                Err(error) => {
                                    failed.store(true, Ordering::Release);
                                    let mut slot =
                                        first_err.lock().unwrap_or_else(PoisonError::into_inner);
                                    if slot.is_none() {
                                        *slot = Some(error);
                                    }
                                    break;
                                }
                            }
                        }
                    });
                }
            });

            if let Some(error) = first_err
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
            {
                return Err(error);
            }

            let mut c1 = None;
            let mut c2a = None;
            let mut c2b = None;
            let mut c3a_slots: Vec<Vec<Option<ZkProof>>> =
                c3a_counts.iter().map(|&n| vec![None; n]).collect();
            let mut c3b_slots: Vec<Vec<Option<ZkProof>>> =
                c3b_counts.iter().map(|&n| vec![None; n]).collect();

            for output in outputs.into_inner().unwrap_or_else(PoisonError::into_inner) {
                match output {
                    MakeSharesOutput::C1(p) => c1 = Some(p),
                    MakeSharesOutput::C2a(p) => c2a = Some(p),
                    MakeSharesOutput::C2b(p) => c2b = Some(p),
                    MakeSharesOutput::C3 {
                        recipient_index,
                        is_c3a,
                        row,
                        proof,
                    } => {
                        if is_c3a {
                            c3a_slots[recipient_index][row] = Some(proof);
                        } else {
                            c3b_slots[recipient_index][row] = Some(proof);
                        }
                    }
                }
            }

            let mut recipients = BTreeMap::new();
            for (index, ((_, member), (shares, _))) in
                other_members.iter().zip(recipient_blobs).enumerate()
            {
                let c3a = c3a_slots[index]
                    .drain(..)
                    .map(|p| p.ok_or_else(|| JobError::crypto("missing C3a proof")))
                    .collect::<Result<Vec<_>, _>>()?;
                let c3b = c3b_slots[index]
                    .drain(..)
                    .map(|p| p.ok_or_else(|| JobError::crypto("missing C3b proof")))
                    .collect::<Result<Vec<_>, _>>()?;
                recipients.insert(*member, RecipientShares { shares, c3a, c3b });
            }
            let c1 = c1.ok_or_else(|| JobError::crypto("missing C1 proof"))?;
            let c2a = c2a.ok_or_else(|| JobError::crypto("missing C2a proof"))?;
            let c2b = c2b.ok_or_else(|| JobError::crypto("missing C2b proof"))?;

            // Speculatively pre-fold C2ab and C3a/C3b -> C3ab in the background only when the host
            // has spare prover concurrency (`max_concurrent >= 2`). On a single-prover host,
            // launching a multi-second fold before roster formation blocks foreground `C4` proofs
            // and spends the only prover slot on non-roster observers until the roster forms.
            if prover.max_concurrent() >= 2 {
                self.spawn_dkg_prefold(params, committee, &c2a, &c2b, &recipients);
            }

            (recipients, c1, c2a, c2b)
        } else {
            let mut recipients = BTreeMap::new();
            for ((slot, member), (shares, bytes)) in other_members.iter().zip(recipient_blobs) {
                let bytes = bytes.as_deref().unwrap_or(&[]);
                let c3a = (0..sk_witnesses[*slot].len())
                    .map(|_| {
                        placeholder::proof(&self.blobs, ProofType::C3aSkShareEncryption, bytes)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let esi_rows: usize = esi_witnesses.iter().map(|esi| esi[*slot].len()).sum();
                let c3b = (0..esi_rows)
                    .map(|_| {
                        placeholder::proof(&self.blobs, ProofType::C3bESmShareEncryption, bytes)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                recipients.insert(*member, RecipientShares { shares, c3a, c3b });
            }
            let bound =
                |proof_type| placeholder::proof(&self.blobs, proof_type, &generated.pk_share);
            (
                recipients,
                bound(ProofType::C1PkGeneration)?,
                bound(ProofType::C2aSkShareComputation)?,
                bound(ProofType::C2bESmShareComputation)?,
            )
        };

        let pk_share = self.blobs.put(&generated.pk_share)?;
        let own = OwnShareRows {
            sk: sk_sss
                .extract_party_share(party)
                .map_err(JobError::crypto)?,
            esi: esi_sss
                .iter()
                .map(|shares| shares.extract_party_share(party))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?,
        };
        let own = bincode::serialize(&own).map_err(JobError::crypto)?;
        Ok(OwnShares {
            pk_share,
            own_share: self.seal(&own)?,
            c1,
            c2a,
            c2b,
            recipients,
        })
    }

    fn spawn_dkg_prefold(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        c2a: &ZkProof,
        c2b: &ZkProof,
        recipients: &BTreeMap<Address, RecipientShares>,
    ) {
        let (Some(store), Some(circuits), Some(prefolds)) =
            (self.blob_store, self.circuits.as_ref(), self.prefolds)
        else {
            return;
        };
        let (cancel, stop_launching, done) = prefolds.register(self.e3);
        let store = store.clone();
        let circuits = circuits.clone();
        let prefolds = Arc::clone(prefolds);
        let e3 = self.e3;
        let scope = self.scope;
        let params = *params;
        let committee = committee.to_vec();
        let c2a = c2a.clone();
        let c2b = c2b.clone();
        let c3a: BTreeMap<Address, Vec<ZkProof>> = recipients
            .iter()
            .map(|(member, shares)| (*member, shares.c3a.clone()))
            .collect();
        let c3b: BTreeMap<Address, Vec<ZkProof>> = recipients
            .iter()
            .map(|(member, shares)| (*member, shares.c3b.clone()))
            .collect();

        let prefolds_thread = Arc::clone(&prefolds);
        let done_thread = Arc::clone(&done);
        let spawned = thread::Builder::new()
            .name(format!("prefold-{}", e3.number))
            .spawn(move || {
                let _guard = PrefoldDoneGuard {
                    prefolds: prefolds_thread,
                    e3,
                    done: done_thread,
                };
                let attempt = Attempt { number: 0, cancel };
                let prover = circuits.for_attempt(&attempt);
                let blobs = store.of(e3);
                let _ = run_dkg_prefold_steps(
                    &blobs,
                    &prover,
                    scope,
                    e3,
                    &params,
                    &committee,
                    &c2a,
                    &c2b,
                    &c3a,
                    &c3b,
                    Priority::Background,
                    Some(&stop_launching),
                );
            });
        if spawned.is_err() {
            prefolds.mark_finished(e3, &done);
        }
    }

    /// Build C1, C2a, and C2b witness data + circuit configs.
    #[allow(clippy::type_complexity)]
    fn prepare_dealing_witnesses(
        &self,
        params: &CryptoParams,
        generated: &GenPkShareAndSkSssResponse,
        sk_sss: &SharedSecret,
        esi_sss: &[SharedSecret],
    ) -> Result<
        (
            PkGenerationCircuitData,
            ShareComputationCircuitData,
            ShareComputationCircuitData,
            e3_zk_config::threshold::pk_generation::Configs,
            e3_zk_config::dkg::share_computation::Configs,
        ),
        JobError,
    > {
        let preset = trbfv::threshold_preset(params)?;
        let threshold = trbfv::threshold_params(params)?;
        let raw = |bytes: &SensitiveBytes| bytes.access_raw(self.cipher).map_err(JobError::crypto);
        let sk = try_poly_pb_from_bytes(&raw(&generated.sk_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let eek = try_poly_ntt_from_bytes(&raw(&generated.eek_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let e_sm = try_poly_pb_from_bytes(&raw(&generated.e_sm_raw)?, &threshold)
            .map_err(JobError::crypto)?;
        let pk0_share = try_poly_ntt_from_bytes(&generated.pk0_share_raw, &threshold)
            .map_err(JobError::crypto)?;
        let [esi_sss] = esi_sss else {
            return Err(JobError::crypto("C2b proves one smudging-noise sharing"));
        };

        let c1 = PkGenerationCircuitData {
            pk0_share: CrtPolynomial::from_fhe_polynomial(&pk0_share),
            eek: CrtPolynomial::from_fhe_polynomial(&eek),
            e_sm: CrtPolynomial::from_fhe_polynomial(&e_sm),
            e_sm_lifted: Polynomial::from_fhe_polynomial(&e_sm),
            sk: CrtPolynomial::from_fhe_polynomial(&sk),
        };
        let mut centered_sk = CrtPolynomial::from_fhe_polynomial(&sk);
        centered_sk
            .center(threshold.moduli())
            .map_err(JobError::crypto)?;
        let shares = |secret: &SharedSecret| -> Vec<Array2<BigInt>> {
            let moduli = secret.moduli_data();
            moduli.iter().map(|rows| rows.mapv(BigInt::from)).collect()
        };
        let c2a = ShareComputationCircuitData {
            dkg_input_type: DkgInputType::SecretKey,
            secret: centered_sk,
            secret_sss: shares(sk_sss),
        };
        let c2b = ShareComputationCircuitData {
            dkg_input_type: DkgInputType::SmudgingNoise,
            secret: CrtPolynomial::from_fhe_polynomial(&e_sm),
            secret_sss: shares(esi_sss),
        };
        let committee = params.committee_size;
        let c1_config =
            e3_zk_config::threshold::pk_generation::Configs::new(preset, &threshold, committee)
                .map_err(JobError::crypto)?;
        let c2_config =
            e3_zk_config::dkg::share_computation::Configs::new(preset, &threshold, committee)
                .map_err(JobError::crypto)?;
        Ok((c1, c2a, c2b, c1_config, c2_config))
    }

    /// Shares count when their C2 and C3 proofs hold, they decrypt under this node's C0 secret to
    /// the rows the dealer's C2 proofs commit to for this node's slot, and each C3 encrypts such
    /// a row to this node's key.
    fn check_shares(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        secret: &SealedRef,
        own_key: &ZkProof,
        message: &SharesMessage,
    ) -> Result<Verdict, JobError> {
        let bytes = self.blobs.get(&message.shares)?;
        let dkg = trbfv::dkg_params(params)?;
        let key = self.secret_key(&dkg, secret)?;
        let decrypted = || {
            let ciphertexts = bincode::deserialize::<RecipientCiphertexts>(&bytes).ok()?;
            decrypt_shares(&key, &dkg, &ciphertexts).ok()
        };
        let c3 = message
            .c3a
            .iter()
            .map(|c3| (ProofType::C3aSkShareEncryption, &c3.proof))
            .chain(
                message
                    .c3b
                    .iter()
                    .map(|c3| (ProofType::C3bESmShareEncryption, &c3.proof)),
            );
        let Some(prover) = self.prover() else {
            let committed = decrypted().is_some()
                && c3
                    .into_iter()
                    .all(|(_, proof)| placeholder::commits_to(proof, &bytes));
            return Ok(placeholder::verdict(committed));
        };
        let c2 = [
            (ProofType::C2aSkShareComputation, &message.c2a.proof),
            (ProofType::C2bESmShareComputation, &message.c2b.proof),
        ];
        self.checked(prover, params, c2.into_iter().chain(c3), || {
            let Some(shares) = decrypted() else {
                return Ok(false);
            };
            let party = trbfv::party(committee, message.recipient)?;
            let rows = trbfv::threshold_params(params)?.moduli().len();
            Ok(self.dealt_as_committed(params, party, &shares, message)?
                && c3_names_this_node(own_key, party, rows, message))
        })
    }

    /// Whether the shares this node decrypted are the ones the dealer's C2 proofs commit to for
    /// this node's slot, committed as this node's C4 will commit them. BFV decryption under
    /// another key yields noise, not an error, so this is what shows that the dealer encrypted
    /// the right shares to this node's key.
    fn dealt_as_committed(
        &self,
        params: &CryptoParams,
        party: usize,
        shares: &OwnShareRows,
        message: &SharesMessage,
    ) -> Result<bool, JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let dkg = trbfv::dkg_params(params)?;
        let msg_bit = e3_zk_config::dkg::share_decryption::Configs::new(&threshold, &dkg)
            .map_err(JobError::crypto)?
            .bits
            .msg_bit;
        let rows = threshold.moduli().len();
        // C2's public inputs: the secret's commitment, then each party's row commitments.
        let committed = |share: &ShamirShare, c2: &ZkProof| {
            share.nrows() == rows
                && share
                    .rows()
                    .into_iter()
                    .enumerate()
                    .all(|(row, coefficients)| {
                        let reversed = coefficients.iter().rev().map(|c| BigInt::from(*c));
                        let commitment = compute_share_encryption_commitment_from_message(
                            &Polynomial::new(reversed.collect()),
                            msg_bit,
                        );
                        let commitment = proofs::word(&commitment);
                        commitment.is_some()
                            && c2.public_inputs.get(1 + party * rows + row) == commitment.as_ref()
                    })
        };
        let [esi] = shares.esi.as_slice() else {
            return Ok(false);
        };
        Ok(committed(&shares.sk, &message.c2a.proof) && committed(esi, &message.c2b.proof))
    }

    /// Sum the roster dealers' shares for this node, its own included, into its decryption key.
    fn make_decryption_key(
        &self,
        params: &CryptoParams,
        member: Address,
        secret: &SealedRef,
        own_share: &SealedRef,
        shares: &BTreeMap<Address, BlobRef>,
    ) -> Result<OwnDecryptionKey, JobError> {
        let own: OwnShareRows =
            bincode::deserialize(&self.unseal(own_share)?).map_err(JobError::crypto)?;
        let dkg = trbfv::dkg_params(params)?;
        let secret = self.secret_key(&dkg, secret)?;
        let dealt = shares
            .iter()
            .map(|(dealer, blob)| Ok((*dealer, self.recipient_ciphertexts(blob)?)))
            .collect::<Result<BTreeMap<_, _>, JobError>>()?;
        let decrypted_rows: Vec<OwnShareRows> = self.check_pool.install(|| {
            let ciphertexts: Vec<&RecipientCiphertexts> = dealt.values().collect();
            ciphertexts
                .par_iter()
                .map(|ct| decrypt_shares(&secret, &dkg, ct))
                .collect::<Result<Vec<_>, JobError>>()
        })?;
        let mut sk_collected = vec![own.sk.clone()];
        let mut esi_collected: Vec<Vec<ShamirShare>> =
            own.esi.iter().map(|esi| vec![esi.clone()]).collect();
        for rows in decrypted_rows {
            sk_collected.push(rows.sk);
            for (collected, esi) in esi_collected.iter_mut().zip(rows.esi) {
                collected.push(esi);
            }
        }
        let encrypt = |shares: Vec<ShamirShare>| {
            shares
                .into_iter()
                .map(|share| Encrypted::new(share, self.cipher))
                .collect::<Result<Vec<_>, _>>()
                .map_err(JobError::crypto)
        };
        let key = calculate_decryption_key(
            self.cipher,
            CalculateDecryptionKeyRequest {
                trbfv_config: trbfv::config(params)?,
                sk_sss_collected: encrypt(sk_collected)?,
                esi_sss_collected: esi_collected
                    .into_iter()
                    .map(encrypt)
                    .collect::<Result<_, _>>()?,
            },
        )
        .map_err(JobError::crypto)?;
        let sealed = SealedDecryptionKey {
            sk_poly_sum: key
                .sk_poly_sum
                .access_raw(self.cipher)
                .map_err(JobError::crypto)?,
            es_poly_sum: key
                .es_poly_sum
                .iter()
                .map(|sum| sum.access_raw(self.cipher))
                .collect::<Result<_, _>>()
                .map_err(JobError::crypto)?,
        };
        let sealed = bincode::serialize(&sealed).map_err(JobError::crypto)?;
        let key = self.seal(&sealed)?;
        let (c4a, c4b) = match self.prover() {
            Some(prover) => {
                self.prove_decryption_key(prover, params, &dkg, member, &secret, &own, &dealt)?
            }
            None => (
                placeholder::proof(
                    &self.blobs,
                    ProofType::C4aSkShareDecryption,
                    key.hash.as_slice(),
                )?,
                vec![placeholder::proof(
                    &self.blobs,
                    ProofType::C4bESmShareDecryption,
                    key.hash.as_slice(),
                )?],
            ),
        };
        Ok(OwnDecryptionKey { key, c4a, c4b })
    }

    /// C4a and C4b: this node decrypted the roster dealers' shares for it with its C0 key. Each
    /// proof takes the roster in party order, with this node's own share in plaintext. `dkg` is
    /// the parameters `secret` was read with: decryption needs the ciphertexts to share them.
    #[allow(clippy::too_many_arguments)]
    fn prove_decryption_key(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        dkg: &Arc<BfvParameters>,
        member: Address,
        secret: &SecretKey,
        own: &OwnShareRows,
        dealt: &BTreeMap<Address, RecipientCiphertexts>,
    ) -> Result<(ZkProof, Vec<ZkProof>), JobError> {
        let threshold = trbfv::threshold_params(params)?;
        let config = e3_zk_config::dkg::share_decryption::Configs::new(&threshold, dkg)
            .map_err(JobError::crypto)?;
        let mut roster: Vec<Address> = dealt.keys().copied().chain([member]).collect();
        roster.sort();
        let data = |share: fn(&RecipientCiphertexts) -> &BfvEncryptedShare, own: &ShamirShare| {
            let honest_ciphertexts = self.check_pool.install(|| {
                roster
                    .par_iter()
                    .map(|dealer| {
                        let Some(dealt) = dealt.get(dealer) else {
                            return Ok(None);
                        };
                        let ciphertexts = share(dealt).ciphertext_bytes();
                        ciphertexts
                            .iter()
                            .map(|bytes| {
                                Ciphertext::from_bytes(bytes, dkg).map_err(JobError::crypto)
                            })
                            .collect::<Result<_, _>>()
                            .map(Some)
                    })
                    .collect::<Result<_, JobError>>()
            })?;
            Ok::<_, JobError>(ShareDecryptionCircuitData {
                secret_key: secret.clone(),
                honest_ciphertexts,
                own_plaintext_share: own.rows().into_iter().map(|row| row.to_vec()).collect(),
            })
        };
        let [own_esi] = own.esi.as_slice() else {
            return Err(JobError::crypto("C4b proves one smudging-noise sharing"));
        };
        let c4a = data(|dealt| &dealt.sk, &own.sk)?;
        let c4b = data(
            |dealt| {
                dealt
                    .esi
                    .first()
                    .expect("a dealer's shares hold one smudging sharing")
            },
            own_esi,
        )?;
        let (c4a, c4b) = thread::scope(|scope| {
            let a = scope.spawn(|| {
                self.prove(
                    prover,
                    params,
                    DkgShareDecryptionCircuit,
                    &config,
                    &c4a,
                    "c4a",
                )
            });
            let b = scope.spawn(|| {
                self.prove(
                    prover,
                    params,
                    DkgShareDecryptionCircuit,
                    &config,
                    &c4b,
                    "c4b",
                )
            });
            (
                a.join().expect("c4a worker panicked"),
                b.join().expect("c4b worker panicked"),
            )
        });
        Ok((c4a?, vec![c4b?]))
    }

    /// One recursive proof of this member's C0-C4 proofs. Its last public inputs commit to the
    /// member's secret-key and smudging-noise shares, which the member attests for its slot.
    fn fold_proofs(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        proofs: &DkgProofs,
    ) -> Result<NodeFold, JobError> {
        let Some(prover) = self.prover() else {
            let statements = placeholder::statements(proofs);
            return Ok(NodeFold {
                proof: placeholder::proof(&self.blobs, ProofType::C5PkAggregation, &[])?,
                sk_agg_commit: keccak256(&statements),
                esm_agg_commit: keccak256(statements.repeat(2)),
            });
        };
        // Hand over any remaining pre-fold steps to foreground priority while allowing any
        // currently running background step to finish and share its result via single-flight.
        if let Some(prefolds) = self.prefolds {
            prefolds.pause_new_steps(self.e3);
        }
        let size = params.committee_size.values();
        let rows = trbfv::threshold_params(params)?.moduli().len();
        let [c4b] = proofs.c4b.as_slice() else {
            return Err(JobError::crypto("the fold takes one smudging-noise C4"));
        };
        let party_id = trbfv::party(committee, member)? as u64;
        let artifacts = self.artifacts(params)?;

        let (prefold_res, c4ab_res) = thread::scope(|scope| {
            let prefold = scope.spawn(|| {
                run_dkg_prefold_steps(
                    &self.blobs,
                    prover,
                    self.scope,
                    self.e3,
                    params,
                    committee,
                    &proofs.c2a,
                    &proofs.c2b,
                    &proofs.c3a,
                    &proofs.c3b,
                    Priority::Foreground,
                    None,
                )
            });
            let c4ab = scope.spawn(|| {
                let c4ab_key = proofs::step_key(
                    self.scope,
                    "c4ab",
                    &[params.config, proofs.c4a.data.hash, c4b.data.hash],
                );
                let work = self.work("fold-c4ab");
                proofs::prove_kept_step(&self.blobs, prover, c4ab_key, Priority::Foreground, |zk| {
                    let c4a_loaded = proofs::load(
                        &self.blobs,
                        &proofs.c4a,
                        proofs::circuit(ProofType::C4aSkShareDecryption),
                    )
                    .map_err(|e| e.to_string())?;
                    let c4b_loaded = proofs::load(
                        &self.blobs,
                        c4b,
                        proofs::circuit(ProofType::C4bESmShareDecryption),
                    )
                    .map_err(|e| e.to_string())?;
                    prove_c4ab_fold(zk, &c4a_loaded, &c4b_loaded, &work, &artifacts)
                        .map_err(|e| e.to_string())
                })
            });
            (
                prefold.join().expect("prefold worker panicked"),
                c4ab.join().expect("c4ab worker panicked"),
            )
        });

        let (c2ab, c3ab) = prefold_res?.expect("foreground prefold runs to completion");
        let c4ab = c4ab_res?;

        let node_fold_key = proofs::step_key(
            self.scope,
            &format!("nodefold-{party_id}"),
            &[
                params.config,
                proofs.c0.data.hash,
                proofs.c1.data.hash,
                c2ab.data.hash,
                c3ab.data.hash,
                c4ab.data.hash,
            ],
        );
        let work = self.work("fold");
        let fold_zk = proofs::prove_kept_step(
            &self.blobs,
            prover,
            node_fold_key,
            Priority::Foreground,
            |zk| {
                let c0 = proofs::load(&self.blobs, &proofs.c0, proofs::circuit(ProofType::C0PkBfv))
                    .map_err(|e| e.to_string())?;
                let c1 = proofs::load(
                    &self.blobs,
                    &proofs.c1,
                    proofs::circuit(ProofType::C1PkGeneration),
                )
                .map_err(|e| e.to_string())?;
                let c2ab_loaded = proofs::load(&self.blobs, &c2ab, CircuitName::C2abFold)
                    .map_err(|e| e.to_string())?;
                let c3ab_loaded = proofs::load(&self.blobs, &c3ab, CircuitName::C3abFold)
                    .map_err(|e| e.to_string())?;
                let c4ab_loaded = proofs::load(&self.blobs, &c4ab, CircuitName::C4abFold)
                    .map_err(|e| e.to_string())?;
                prove_node_fold_final(
                    zk,
                    &c0,
                    &c1,
                    &c2ab_loaded,
                    &c3ab_loaded,
                    &c4ab_loaded,
                    party_id,
                    &work,
                    &artifacts,
                )
                .map_err(|e| e.to_string())
            },
        )?;
        let fold = proofs::load(&self.blobs, &fold_zk, CircuitName::NodeFold)?;
        let (_, commits) =
            extract_node_fold_agg_commits(&fold, size.n, size.h, rows).map_err(JobError::crypto)?;
        Ok(NodeFold {
            proof: fold_zk,
            sk_agg_commit: B256::from(commits.sk_agg_commit),
            esm_agg_commit: B256::from(commits.esm_agg_commit),
        })
    }

    /// A roster member's decryption key counts when its C4 proofs hold and take the roster
    /// dealers' shares.
    fn check_decryption_key(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        c2: &BTreeMap<Address, (ZkProof, ZkProof)>,
        message: &DecryptionKeyMessage,
    ) -> Result<Verdict, JobError> {
        let Some(prover) = self.prover() else {
            return Ok(Verdict::Valid);
        };
        let c4b = message
            .c4b
            .iter()
            .map(|c4b| (ProofType::C4bESmShareDecryption, &c4b.proof));
        let c4a = (ProofType::C4aSkShareDecryption, &message.c4a.proof);
        self.checked(prover, params, std::iter::once(c4a).chain(c4b), || {
            self.sums_committed_shares(params, member, committee, c2, message)
        })
    }

    /// Whether a member's C4 proofs take, for each roster dealer, the share commitments that
    /// dealer's C2 proofs made for the member's slot.
    fn sums_committed_shares(
        &self,
        params: &CryptoParams,
        member: Address,
        committee: &[Address],
        c2: &BTreeMap<Address, (ZkProof, ZkProof)>,
        message: &DecryptionKeyMessage,
    ) -> Result<bool, JobError> {
        let [c4b] = message.c4b.as_slice() else {
            return Ok(false);
        };
        let rows = trbfv::threshold_params(params)?.moduli().len();
        let party = trbfv::party(committee, member)?;
        // C4's public inputs: each roster dealer's row commitments, in roster order.
        let takes = |c4: &ZkProof, dealt: fn(&(ZkProof, ZkProof)) -> &ZkProof| {
            c2.values().enumerate().all(|(dealer, proofs)| {
                (0..rows).all(|row| {
                    let committed = dealt(proofs).public_inputs.get(1 + party * rows + row);
                    committed.is_some() && c4.public_inputs.get(dealer * rows + row) == committed
                })
            })
        };
        Ok(takes(&message.c4a.proof, |proofs| &proofs.0) && takes(&c4b.proof, |proofs| &proofs.1))
    }

    /// A keyshare counts when its C1 proof holds, and its public-key share decodes and is the one
    /// the proof commits to.
    fn check_keyshare(
        &self,
        params: &CryptoParams,
        keyshare: &KeyshareMessage,
    ) -> Result<Verdict, JobError> {
        let bytes = self.blobs.get(&keyshare.pk_share)?;
        let bfv = trbfv::threshold_params(params)?;
        let crp = trbfv::crp_poly(params)?;
        let decodes = PublicKeyShare::deserialize(&bytes, &bfv, crp.clone()).is_ok();
        let c1 = &keyshare.c1.proof;
        let Some(prover) = self.prover() else {
            let committed = decodes && placeholder::commits_to(c1, &bytes);
            return Ok(placeholder::verdict(committed));
        };
        self.checked(prover, params, [(ProofType::C1PkGeneration, c1)], || {
            let commitment = compute_pk_commitment_from_keyshare_bytes(&bytes, &bfv, &crp)
                .ok()
                .map(B256::from);
            Ok(decodes
                && commitment.is_some()
                && proofs::field(c1, CircuitName::PkGeneration, "pk_commitment") == commitment)
        })
    }

    /// One step of the roster's fold: `fold` goes into `slot` of the accumulator.
    fn fold_roster(
        &self,
        params: &CryptoParams,
        slot: u32,
        slots: usize,
        fold: &ZkProof,
        accumulator: Option<&ZkProof>,
    ) -> Result<ZkProof, JobError> {
        let Some(prover) = self.prover() else {
            return placeholder::proof(
                &self.blobs,
                ProofType::C5PkAggregation,
                &slot.to_be_bytes(),
            );
        };
        let acc_hash = accumulator.map(|p| p.data.hash).unwrap_or(B256::ZERO);
        let key = proofs::step_key(
            self.scope,
            &format!("roster-fold-{slot}-{slots}"),
            &[params.config, fold.data.hash, acc_hash],
        );
        let (work, artifacts) = (
            self.work(&format!("roster-fold-{slot}")),
            self.artifacts(params)?,
        );
        proofs::prove_kept_step(&self.blobs, prover, key, Priority::Foreground, |zk| {
            let fold = proofs::load(&self.blobs, fold, CircuitName::NodeFold)
                .map_err(|e| e.to_string())?;
            // Slot 0 goes into the kernel on its own, so the accumulator of slot 1 is a kernel
            // proof, which the step verifies with the kernel's key. Every later accumulator is a
            // fold step's.
            let previous = match slot {
                1 => CircuitName::NodesFoldKernel,
                _ => CircuitName::NodesFold,
            };
            let accumulator = accumulator
                .map(|proof| proofs::load(&self.blobs, proof, previous))
                .transpose()
                .map_err(|e| e.to_string())?;
            generate_nodes_fold_step(
                zk,
                &fold,
                accumulator.as_ref(),
                slot,
                slots,
                &work,
                &artifacts,
            )
            .map_err(|e| e.to_string())
        })
    }

    /// Sum the roster's public-key shares into the committee key. Its proof, which
    /// `publishCommittee` verifies, folds C5 with the roster members' node folds, and its last
    /// public input is the key commitment.
    fn aggregate_key(
        &self,
        params: &CryptoParams,
        committee: &[Address],
        roster: &[Address],
        keyshares: &[KeyshareMessage],
        folds: &[NodeFold],
        accumulator: &ZkProof,
    ) -> Result<AggregatedKey, JobError> {
        let bfv = trbfv::threshold_params(params)?;
        let crp = trbfv::crp_poly(params)?;
        let shares = self.check_pool.install(|| {
            keyshares
                .par_iter()
                .map(|keyshare| {
                    let bytes = self.blobs.get(&keyshare.pk_share)?;
                    PublicKeyShare::deserialize(&bytes, &bfv, crp.clone()).map_err(JobError::crypto)
                })
                .collect::<Result<Vec<_>, JobError>>()
        })?;
        let pk0_shares = shares
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(&share.p0_share()))
            .collect();
        let key: PublicKey = shares.into_iter().aggregate().map_err(JobError::crypto)?;
        let bytes = key.to_bytes();
        let public_key = self.blobs.put(&bytes)?;
        let Some(prover) = self.prover() else {
            let commitment = keccak256(&bytes);
            return Ok(AggregatedKey {
                public_key,
                commitment,
                proof: placeholder::key_aggregation(&self.blobs, committee, roster, commitment)?,
            });
        };
        let artifacts = self.artifacts(params)?;
        let c5_config =
            e3_zk_config::threshold::pk_aggregation::Configs::new(&bfv, params.committee_size)
                .map_err(JobError::crypto)?;
        let c5_data = PkAggregationCircuitData {
            public_key: key,
            pk0_shares,
        };
        // C5 takes the variant the DKG aggregation verifies inside it.
        let c5_key = proofs::step_key(self.scope, "c5", &[params.config, public_key.hash]);
        let c5_work = self.work("c5");
        let c5_zk =
            proofs::prove_kept_step(&self.blobs, prover, c5_key, Priority::Foreground, |zk| {
                let variant = CircuitVariant::Default;
                PkAggregationCircuit
                    .prove_with_variant(zk, &c5_config, &c5_data, &c5_work, variant, &artifacts)
            })?;
        let party_ids = roster
            .iter()
            .map(|member| Ok(trbfv::party(committee, *member)? as u64))
            .collect::<Result<Vec<_>, JobError>>()?;
        let mut agg_inputs = vec![params.config, c5_zk.data.hash, accumulator.data.hash];
        for fold in folds {
            agg_inputs.push(fold.proof.data.hash);
        }
        let dkg_key = proofs::step_key(self.scope, "dkg-agg", &agg_inputs);
        let dkg_work = self.work("dkg");
        let proof =
            proofs::prove_kept_step(&self.blobs, prover, dkg_key, Priority::Foreground, |zk| {
                let c5 = proofs::load(&self.blobs, &c5_zk, CircuitName::PkAggregation)
                    .map_err(|e| e.to_string())?;
                let folds = folds
                    .iter()
                    .map(|fold| proofs::load(&self.blobs, &fold.proof, CircuitName::NodeFold))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?;
                let accumulator = proofs::load(&self.blobs, accumulator, CircuitName::NodesFold)
                    .map_err(|e| e.to_string())?;
                let input = DkgAggregationInput {
                    node_fold_proofs: &folds,
                    nodes_fold_proof: Some(&accumulator),
                    c5_proof: &c5,
                    party_ids: &party_ids,
                    committee_addresses: committee,
                };
                prove_dkg_aggregation(zk, &input, &dkg_work, &artifacts, params.committee_size)
                    .map_err(|e| e.to_string())
            })?;
        let commitment = *proof.public_inputs.last().ok_or(JobError::crypto(
            "the DKG aggregation proof has no public inputs",
        ))?;
        Ok(AggregatedKey {
            public_key,
            commitment,
            proof,
        })
    }

    fn recipient_ciphertexts(&self, blob: &BlobRef) -> Result<RecipientCiphertexts, JobError> {
        bincode::deserialize(&self.blobs.get(blob)?).map_err(JobError::crypto)
    }

    /// This node's C0 secret key, unsealed.
    fn secret_key(
        &self,
        dkg: &Arc<BfvParameters>,
        secret: &SealedRef,
    ) -> Result<SecretKey, JobError> {
        deserialize_secret_key(&self.unseal(secret)?, dkg).map_err(JobError::crypto)
    }
}

/// Shared implementation of `C2abFold || (C3aFold chain || C3bFold chain) -> C3abFold` used by
/// both speculative background pre-folding (right after `MakeShares`) and foreground `FoldProofs`.
///
/// Every step is individually checkpointed in `blobs.kept` and deduplicated via single-flight so
/// foreground `FoldProofs` immediately reuses completed steps and joins in-flight steps.
#[allow(clippy::too_many_arguments)]
fn run_dkg_prefold_steps<B: Blobs>(
    blobs: &B,
    prover: &Prover<'_>,
    scope: B256,
    e3: E3Id,
    params: &CryptoParams,
    committee: &[Address],
    c2a: &ZkProof,
    c2b: &ZkProof,
    c3a: &BTreeMap<Address, Vec<ZkProof>>,
    c3b: &BTreeMap<Address, Vec<ZkProof>>,
    priority: Priority,
    stop_launching: Option<&AtomicBool>,
) -> Result<Option<(ZkProof, ZkProof)>, JobError> {
    let should_stop = || stop_launching.is_some_and(|flag| flag.load(Ordering::Acquire));
    if should_stop() {
        return Ok(None);
    }
    let size = params.committee_size.values();
    let rows = trbfv::threshold_params(params)?.moduli().len();
    let total_slots = size.n * rows;
    let artifacts = proofs::artifacts_dir(params)?;

    let collect_c3 =
        |map: &BTreeMap<Address, Vec<ZkProof>>| -> Result<Vec<(u32, ZkProof)>, JobError> {
            let mut items = Vec::new();
            for (recipient, row_proofs) in map {
                let party = trbfv::party(committee, *recipient)?;
                for (row, proof) in row_proofs.iter().enumerate() {
                    let slot = u32::try_from(party * rows + row).map_err(JobError::crypto)?;
                    items.push((slot, proof.clone()));
                }
            }
            Ok(items)
        };
    let c3a_items = collect_c3(c3a)?;
    let c3b_items = collect_c3(c3b)?;

    let (c2ab_res, c3ab_res) = thread::scope(|s| {
        let c2ab_handle = s.spawn(|| -> Result<Option<ZkProof>, JobError> {
            if should_stop() {
                return Ok(None);
            }
            let key = proofs::step_key(
                scope,
                "c2ab",
                &[params.config, c2a.data.hash, c2b.data.hash],
            );
            let work = proofs::work_dir(e3, "fold-c2ab");
            let proof = proofs::prove_kept_step(blobs, prover, key, priority, |zk| {
                let c2a_loaded = proofs::load(
                    blobs,
                    c2a,
                    proofs::circuit(ProofType::C2aSkShareComputation),
                )
                .map_err(|e| e.to_string())?;
                let c2b_loaded = proofs::load(
                    blobs,
                    c2b,
                    proofs::circuit(ProofType::C2bESmShareComputation),
                )
                .map_err(|e| e.to_string())?;
                prove_c2ab_fold(zk, &c2a_loaded, &c2b_loaded, &work, &artifacts)
                    .map_err(|e| e.to_string())
            })?;
            Ok(Some(proof))
        });

        let c3ab_handle = s.spawn(|| -> Result<Option<ZkProof>, JobError> {
            let (c3a_res, c3b_res) = thread::scope(|inner| {
                let a = inner.spawn(|| {
                    run_c3_fold_chain(
                        blobs,
                        prover,
                        scope,
                        e3,
                        params.config,
                        "a",
                        &c3a_items,
                        total_slots,
                        &artifacts,
                        priority,
                        stop_launching,
                    )
                });
                let b = inner.spawn(|| {
                    run_c3_fold_chain(
                        blobs,
                        prover,
                        scope,
                        e3,
                        params.config,
                        "b",
                        &c3b_items,
                        total_slots,
                        &artifacts,
                        priority,
                        stop_launching,
                    )
                });
                (
                    a.join().expect("c3a chain panicked"),
                    b.join().expect("c3b chain panicked"),
                )
            });
            let (Some((c3a_folded, c3a_circuit)), Some((c3b_folded, c3b_circuit))) =
                (c3a_res?, c3b_res?)
            else {
                return Ok(None);
            };
            if should_stop() {
                return Ok(None);
            }
            let key = proofs::step_key(
                scope,
                "c3ab",
                &[params.config, c3a_folded.data.hash, c3b_folded.data.hash],
            );
            let work = proofs::work_dir(e3, "fold-c3ab");
            let proof = proofs::prove_kept_step(blobs, prover, key, priority, |zk| {
                let a_loaded =
                    proofs::load(blobs, &c3a_folded, c3a_circuit).map_err(|e| e.to_string())?;
                let b_loaded =
                    proofs::load(blobs, &c3b_folded, c3b_circuit).map_err(|e| e.to_string())?;
                prove_c3ab_fold(zk, &a_loaded, &b_loaded, &work, &artifacts)
                    .map_err(|e| e.to_string())
            })?;
            Ok(Some(proof))
        });

        (
            c2ab_handle.join().expect("c2ab thread panicked"),
            c3ab_handle.join().expect("c3ab thread panicked"),
        )
    });

    match (c2ab_res?, c3ab_res?) {
        (Some(c2ab), Some(c3ab)) => Ok(Some((c2ab, c3ab))),
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_c3_fold_chain<B: Blobs>(
    blobs: &B,
    prover: &Prover<'_>,
    scope: B256,
    e3: E3Id,
    config: B256,
    tag: &str,
    items: &[(u32, ZkProof)],
    total_slots: usize,
    artifacts: &str,
    priority: Priority,
    stop_launching: Option<&AtomicBool>,
) -> Result<Option<(ZkProof, CircuitName)>, JobError> {
    if items.is_empty() {
        return Err(JobError::crypto(
            "C3 fold requires at least one inner proof",
        ));
    }
    let mut prior: Option<(ZkProof, CircuitName)> = None;
    for (step, (slot, inner_zk)) in items.iter().enumerate() {
        if stop_launching.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Ok(None);
        }
        let prior_hash = prior
            .as_ref()
            .map(|(p, _)| p.data.hash)
            .unwrap_or(B256::ZERO);
        let key = proofs::step_key(
            scope,
            &format!("c3-{tag}-{step}-{slot}-{total_slots}"),
            &[config, prior_hash, inner_zk.data.hash],
        );
        let work = proofs::work_dir(e3, &format!("fold-c3{tag}-{step}"));
        let prior_ref = prior.as_ref();
        let next = proofs::prove_kept_step(blobs, prover, key, priority, |zk| {
            let inner_loaded = proofs::load(blobs, inner_zk, CircuitName::ShareEncryption)
                .map_err(|e| e.to_string())?;
            let prior_loaded = prior_ref
                .map(|(p, circuit)| proofs::load(blobs, p, *circuit))
                .transpose()
                .map_err(|e| e.to_string())?;
            generate_c3_fold_step(
                zk,
                &inner_loaded,
                prior_loaded.as_ref(),
                *slot,
                total_slots,
                &work,
                artifacts,
            )
            .map_err(|e| e.to_string())
        })?;
        let circuit = if step == 0 {
            CircuitName::C3FoldKernel
        } else {
            CircuitName::C3Fold
        };
        prior = Some((next, circuit));
    }
    Ok(prior)
}

/// A dealer's shares for this node, decrypted with its C0 secret key.
fn decrypt_shares(
    key: &SecretKey,
    dkg: &Arc<BfvParameters>,
    ciphertexts: &RecipientCiphertexts,
) -> Result<OwnShareRows, JobError> {
    let degree = dkg.degree();
    let decrypt = |share: &BfvEncryptedShare| {
        share
            .clone()
            .decrypt(key, dkg, degree)
            .map_err(JobError::crypto)
    };
    Ok(OwnShareRows {
        sk: decrypt(&ciphertexts.sk)?,
        esi: ciphertexts
            .esi
            .iter()
            .map(decrypt)
            .collect::<Result<_, _>>()?,
    })
}

/// Whether the dealer's C3 proofs are the ones this node's fold can use: one per share row, each
/// encrypting to this node's key (as its C0 proof commits to it) the row that the dealer's C2
/// commits to for this node's slot. C4 binds those same row commitments, so a C3 made for
/// another slot or row would not count.
pub(crate) fn c3_names_this_node(
    own_key: &ZkProof,
    party: usize,
    rows: usize,
    message: &SharesMessage,
) -> bool {
    let Some(key) = proofs::field(own_key, CircuitName::PkBfv, "pk_commitment") else {
        return false;
    };
    let names = |c3s: &[SignedProof], c2: &ZkProof| {
        c3s.len() == rows
            && c3s.iter().enumerate().all(|(row, c3)| {
                let field = |name| proofs::field(&c3.proof, CircuitName::ShareEncryption, name);
                field("expected_pk_commitment") == Some(key)
                    && field("expected_message_commitment")
                        == c2.public_inputs.get(1 + party * rows + row).copied()
            })
    };
    names(&message.c3a, &message.c2a.proof) && names(&message.c3b, &message.c2b.proof)
}
