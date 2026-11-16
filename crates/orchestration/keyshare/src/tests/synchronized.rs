// SPDX-License-Identifier: LGPL-3.0-only

//! Synchronized DKG scenarios sharing actor/recovery fixtures with the parent `tests` module.
//!
//! Production native generation, encrypted work plans and prover preparation. Synthetic signed
//! statements test admission/recovery, not proof validity; the ignored test below uses real Honk.

use super::*;
use crate::domain::{build_decryption_key_plan, build_shares_generated_plan, DecryptionKeyPlan};
use crate::synchronized::{
    commitment_field, proof_context, setup_binding, SynchronizedDkgRecovery,
};
use alloy::{primitives::keccak256, signers::local::PrivateKeySigner};
use anyhow::ensure;
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    DkgShareDecryptionProofRequest, ShareEncryptionProofRequest, ThresholdSharePending,
};
use e3_fhe_params::{create_deterministic_crp_from_default_seed, BfvProfile};
use e3_polynomial::Polynomial;
use e3_trbfv::{
    calculate_decryption_key::calculate_decryption_key,
    gen_pk_share_and_sk_sss::{
        gen_pk_share_and_sk_sss, GenPkShareAndSkSssRequest, SynchronizedDkgGeneration,
    },
    helpers::{serialize_secret_key, try_poly_from_sensitive_bytes, try_poly_ntt_from_bytes},
    shares::SharedSecret,
    synchronized::pack_key,
};
use e3_zk_config::synchronized::{public_signals::PublicSignals, Configs};
use e3_zk_prover::synchronized::{
    prepare_pk_generation, prepare_share_computation, prepare_share_decryption,
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{DeserializeParametrized, FheEncoder};
use num_bigint::BigInt;
use rand::SeedableRng;
use std::collections::BTreeMap;

#[path = "synchronized/recovery.rs"]
mod recovery;

const PROFILE: BfvProfile = BfvProfile::SyncDecInsecure64;
const COMMITTEE: CiphernodesCommitteeSize = CiphernodesCommitteeSize::Minimum;
const DEALERS: [u64; 2] = [0, 2];

struct Setup {
    cipher: Arc<Cipher>,
    ciphers: Vec<Arc<Cipher>>,
    config: Configs,
    selected: Vec<CiphernodeSelected>,
    signers: Vec<PrivateKeySigner>,
    material: Vec<SynchronizedDkgRecovery>,
    pending: Vec<ThresholdSharePending>,
    sk_bfv: Vec<SensitiveBytes>,
    c2: BTreeMap<u64, SignedProofPayload>,
    responses: Vec<GenPkShareAndSkSssResponse>,
    encryption_keys: Vec<Arc<EncryptionKey>>,
}

fn signed(
    setup: &Setup,
    owner: usize,
    kind: ProofType,
    fields: Vec<[u8; 32]>,
) -> Result<SignedProofPayload> {
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: setup.selected[owner].e3_id.clone(),
            proof_type: kind,
            proof: Proof::new(
                kind.circuit_names()[0],
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&fields.concat()),
            ),
        },
        &setup.signers[owner],
    )
}

fn scalar(value: impl Into<BigInt>) -> Result<[u8; 32]> {
    commitment_field(&value.into())
}

impl Setup {
    async fn new() -> Result<Self> {
        let cipher = Arc::new(Cipher::from_password("test-password").await?);
        Self::with_ciphers(vec![cipher; 3]).await
    }

    async fn with_ciphers(ciphers: Vec<Arc<Cipher>>) -> Result<Self> {
        ensure!(ciphers.len() == 3);
        let cipher = ciphers[0].clone();
        let config = Configs::for_profile(PROFILE, COMMITTEE)?;
        let mut rngs: Vec<_> = (0..3)
            .map(|owner| rand_chacha::ChaCha20Rng::seed_from_u64(245603 + owner))
            .collect();
        let mut signers: Vec<_> = (0..3).map(|_| PrivateKeySigner::random()).collect();
        signers.sort_by_key(|signer| signer.address());
        let committee: Vec<_> = signers
            .iter()
            .map(|signer| signer.address().to_string())
            .collect();
        let selected: Vec<_> = (0..3)
            .map(|owner| CiphernodeSelected {
                e3_id: E3id::new("245603", 31337),
                party_id: owner,
                threshold_m: 1,
                threshold_n: 3,
                params_profile: PROFILE,
                crypto_config_id: PROFILE.crypto_config_id(COMMITTEE).unwrap().into(),
                params: ArcBytes::from_bytes(&encode_bfv_params(&config.threshold)),
                committee: committee.clone(),
                ..Default::default()
            })
            .collect();
        let secrets: Vec<_> = rngs
            .iter_mut()
            .map(|rng| SecretKey::random(&config.transport, rng))
            .collect();
        let public: Vec<_> = secrets
            .iter()
            .enumerate()
            .map(|(id, secret)| {
                Arc::new(EncryptionKey::new(
                    id as u64,
                    ArcBytes::from_bytes(&PublicKey::new(secret, &mut rngs[id]).to_bytes()),
                ))
            })
            .collect();
        let sk_bfv = secrets
            .iter()
            .enumerate()
            .map(|(owner, secret)| {
                SensitiveBytes::new(serialize_secret_key(secret)?, &ciphers[owner])
            })
            .collect::<Result<Vec<_>>>()?;
        let mut material = Vec::new();
        let mut pending = Vec::new();
        let mut responses = Vec::new();
        for selection in &selected {
            let owner = selection.party_id as usize;
            let cipher = &ciphers[owner];
            let context = proof_context(selection, Address::repeat_byte(0x11))?;
            let output = gen_pk_share_and_sk_sss(
                &mut rngs[owner],
                cipher,
                GenPkShareAndSkSssRequest {
                    trbfv_config: TrBFVConfig::new(selection.params.clone(), 3, 1),
                    crp: ArcBytes::from_bytes(
                        &create_deterministic_crp_from_default_seed(&config.threshold).to_bytes(),
                    ),
                    lambda: PROFILE.threshold_preset().lambda_config(),
                    num_ciphertexts: 1,
                    synchronized: Some(SynchronizedDkgGeneration {
                        profile: PROFILE,
                        committee: COMMITTEE,
                        owner: context.party_id,
                        setup_binding: setup_binding(&context, &selection.e3_id)?,
                    }),
                },
            )?;
            ensure!(output.e_sm_raw.is_none());
            responses.push(output.clone());
            let saved = SynchronizedDkgRecovery {
                context,
                generation_response_hash: keccak256(bincode::serialize(&output)?).into(),
                outgoing_keys: output
                    .outgoing_keys
                    .clone()
                    .context("missing outgoing keys")?,
                incoming_keys: None,
                dealer_ids: vec![],
                sk_commitment: None,
                key_bundle: None,
                c2_statements: Default::default(),
            };
            saved.validate(selection, Address::repeat_byte(0x11), cipher)?;
            let plan = build_shares_generated_plan(
                cipher,
                PROFILE,
                selection.party_id,
                COMMITTEE,
                output.pk_share,
                output.sk_sss.decrypt(cipher)?,
                vec![],
                None,
                ProofRequestData {
                    pk0_share_raw: output.pk0_share_raw,
                    sk_raw: output.sk_raw,
                    eek_raw: output.eek_raw,
                },
                &public,
                &selection.e3_id,
                Some(&saved),
            )?;
            let event = ThresholdSharePending {
                e3_id: selection.e3_id.clone(),
                full_share: Arc::new(plan.full_share),
                proof_request: plan.proof_request,
                sk_share_computation_request: plan.sk_share_computation_request,
                e_sm_share_computation_request: plan.e_sm_share_computation_request,
                sk_share_encryption_requests: plan.sk_share_encryption_requests,
                e_sm_share_encryption_requests: plan.e_sm_share_encryption_requests,
                recipient_party_ids: plan.recipient_party_ids,
                own_sk_share_raw: plan.own_sk_share_raw,
                own_esi_shares_raw: plan.own_esi_shares_raw,
            };
            saved.validate_pending(selection, &event, cipher)?;
            material.push(saved);
            pending.push(event);
        }
        let mut setup = Self {
            cipher,
            ciphers,
            config,
            selected,
            signers,
            material,
            pending,
            sk_bfv,
            responses,
            encryption_keys: public,
            c2: BTreeMap::new(),
        };
        for owner in 0..3 {
            let inputs = prepare_share_computation(
                &setup.config,
                &setup.pending[owner].sk_share_computation_request,
                &setup.selected[owner].e3_id,
                &setup.ciphers[owner],
            )?;
            let binding =
                setup_binding(&setup.material[owner].context, &setup.selected[owner].e3_id)?;
            let mut fields = vec![
                scalar(binding[0])?,
                scalar(binding[1])?,
                scalar(owner)?,
                commitment_field(inputs.expected_secret_commitment())?,
            ];
            let shares: SharedSecret = bincode::deserialize(
                &setup.pending[owner]
                    .sk_share_computation_request
                    .secret_sss_raw
                    .access(&setup.ciphers[owner])?,
            )?;
            let keys = setup.material[owner].outgoing_keys.open(
                PROFILE,
                binding,
                owner as u32,
                3,
                &setup.ciphers[owner],
            )?;
            for (recipient, key) in keys.iter().enumerate() {
                let packed = pack_key(PROFILE, &shares.extract_party_share(recipient)?, key)?;
                for row in packed.rows() {
                    fields.push(commitment_field(
                        &e3_zk_witness::compute_share_encryption_commitment_from_message(
                            &Polynomial::new(row.iter().rev().copied().map(BigInt::from).collect()),
                            setup.config.share_encryption.bits.msg_bit,
                        ),
                    )?);
                }
            }
            fields.push(commitment_field(
                &e3_zk_witness::synchronized::commitments::outgoing_root(
                    &setup.config,
                    binding,
                    owner as u32,
                    &keys.iter().map(|key| *key.as_bytes()).collect::<Vec<_>>(),
                )?,
            )?);
            setup.c2.insert(
                owner as u64,
                signed(&setup, owner, ProofType::C2aSkShareComputation, fields)?,
            );
        }
        Ok(setup)
    }

    fn plan(&self, owner: usize) -> Result<DecryptionKeyPlan> {
        let plan = &self.pending[owner];
        let current = AggregatingDecryptionKey {
            pk_share: plan.full_share.pk_share.clone(),
            sk_bfv: self.sk_bfv[owner].clone(),
            own_sk_share_raw: plan.own_sk_share_raw.clone(),
            own_esi_shares_raw: vec![],
            signed_pk_generation_proof: None,
            signed_sk_share_computation_proof: Some(self.c2[&(owner as u64)].clone()),
            signed_e_sm_share_computation_proof: None,
            signed_sk_share_encryption_proofs: vec![],
            signed_e_sm_share_encryption_proofs: vec![],
        };
        build_decryption_key_plan(
            &self.ciphers[owner],
            PROFILE,
            owner as u64,
            COMMITTEE,
            TrBFVConfig::new(self.selected[owner].params.clone(), 3, 1),
            &current,
            DEALERS
                .iter()
                .filter(|&&dealer| dealer != owner as u64)
                .map(|&dealer| self.pending[dealer as usize].full_share.clone())
                .collect(),
            None,
            &DEALERS.into(),
            &self.selected[owner].e3_id,
            Some(&self.material[owner]),
            &self.c2,
        )
    }

    fn c3_data(
        &self,
        owner: usize,
        request: &ShareEncryptionProofRequest,
    ) -> Result<e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData> {
        let params = &self.config.transport;
        let cipher = &self.ciphers[owner];
        let row: Vec<u64> = bincode::deserialize(&request.share_row_raw.access(cipher)?)?;
        Ok(
            e3_zk_witness::dkg::share_encryption::ShareEncryptionCircuitData {
                plaintext: Plaintext::try_encode(&row, Encoding::poly(), params)?,
                ciphertext: Ciphertext::from_bytes(&request.ciphertext_raw, params)?,
                public_key: PublicKey::from_bytes(&request.recipient_pk_raw, params)?,
                u_rns: try_poly_ntt_from_bytes(&request.u_rns_raw.access(cipher)?, params)?,
                e0_rns: try_poly_ntt_from_bytes(&request.e0_rns_raw.access(cipher)?, params)?,
                e1_rns: try_poly_ntt_from_bytes(&request.e1_rns_raw.access(cipher)?, params)?,
            },
        )
    }

    fn message(&self, dealer: usize, recipient: usize) -> Result<ThresholdShareCreated> {
        let plan = &self.pending[dealer];
        let proofs = plan
            .sk_share_encryption_requests
            .iter()
            .filter(|request| request.recipient_party_id == recipient)
            .map(|request| {
                let inputs = e3_zk_witness::dkg::share_encryption::Inputs::compute(
                    &self.config.share_encryption,
                    &self.c3_data(dealer, request)?,
                )?;
                signed(
                    self,
                    dealer,
                    ProofType::C3aSkShareEncryption,
                    vec![
                        commitment_field(&inputs.pk_commitment)?,
                        commitment_field(&inputs.msg_commitment)?,
                        commitment_field(&e3_zk_witness::compute_ciphertext_commitment(
                            &inputs.ct0is,
                            &inputs.ct1is,
                            self.config.share_encryption.bits.ct_bit,
                        ))?,
                    ],
                )
            })
            .collect::<Result<Vec<_>>>()?;
        ThresholdShareCreated {
            e3_id: plan.e3_id.clone(),
            target_party_id: recipient as u64,
            external: true,
            share: Arc::new(ThresholdShare {
                party_id: dealer as u64,
                pk_share: plan.full_share.pk_share.clone(),
                sk_sss: plan
                    .full_share
                    .sk_sss
                    .extract_for_party(recipient)
                    .context("missing recipient")?,
                esi_sss: vec![],
            }),
            signed_c2a_proof: Some(self.c2[&(dealer as u64)].clone()),
            signed_c2b_proof: None,
            signed_c3a_proofs: proofs,
            signed_c3b_proofs: vec![],
            signature: Default::default(),
        }
        .sign(&self.signers[dealer])
    }
}

fn c4_fields(
    request: &DkgShareDecryptionProofRequest,
    saved: &SynchronizedDkgRecovery,
    e3: &E3id,
) -> Result<Vec<[u8; 32]>> {
    let binding = setup_binding(&saved.context, e3)?;
    let sync = request
        .synchronized
        .as_ref()
        .context("missing C4 context")?;
    let mut fields = vec![
        scalar(binding[0])?,
        scalar(binding[1])?,
        scalar(sync.context.party_id)?,
    ];
    fields.extend(
        sync.dealer_ids
            .iter()
            .map(|&id| scalar(id))
            .collect::<Result<Vec<_>>>()?,
    );
    fields.push(sync.expected_outgoing_root);
    fields.extend(sync.expected_commitments.iter().flatten().copied());
    fields.push(saved.sk_commitment.context("missing SK commitment")?);
    fields.push(saved.key_bundle.context("missing key bundle")?);
    Ok(fields)
}

#[actix::test]
async fn synchronized_native_plans_restore_authenticated_keys_for_nonprefix_h_and_outside_recipient(
) -> Result<()> {
    let setup = Setup::new().await?;
    let mut aggregate_shares = Vec::new();
    for owner in 0..3 {
        let DecryptionKeyPlan::Proceed {
            calc_request,
            sk_request,
            esm_requests,
            honest_party_ids,
            synchronized: Some(saved),
        } = setup.plan(owner)?
        else {
            anyhow::bail!("missing synchronized plan");
        };
        assert_eq!(honest_party_ids, DEALERS.into());
        assert!(esm_requests.is_empty() && calc_request.esi_sss_collected.is_empty());
        assert_eq!(
            sk_request.own_plaintext_idx,
            [Some(0), None, Some(1)][owner]
        );
        prepare_share_decryption(
            &setup.config,
            &sk_request,
            &setup.selected[owner].e3_id,
            &setup.cipher,
        )?;
        let generated = calculate_decryption_key(&setup.cipher, calc_request)?;
        assert!(generated.es_poly_sum.is_empty());
        let polynomial = try_poly_from_sensitive_bytes(
            generated.sk_poly_sum,
            setup.config.threshold.clone(),
            &setup.cipher,
        )?;
        let normalized = e3_zk_witness::encoding::fhe_poly_to_crt_centered(
            &polynomial,
            setup.config.threshold.moduli(),
        )?;
        assert_eq!(
            saved.sk_commitment,
            Some(commitment_field(
                &e3_zk_witness::compute_aggregated_shares_commitment(
                    &normalized,
                    setup.config.aggregate_bit
                )
            )?)
        );
        aggregate_shares.push(polynomial);
        let root = ThresholdKeyshareRecoveryState {
            synchronized: Some(saved.clone()),
            ..Default::default()
        };
        let restored: ThresholdKeyshareRecoveryState =
            bincode::deserialize(&bincode::serialize(&root)?)?;
        let restored = restored.synchronized.context("missing saved keys")?;
        restored.validate(
            &setup.selected[owner],
            Address::repeat_byte(0x11),
            &setup.cipher,
        )?;
        let binding = setup_binding(&saved.context, &setup.selected[owner].e3_id)?;
        let incoming = restored.incoming_keys.as_ref().unwrap().open(
            PROFILE,
            binding,
            owner as u32,
            2,
            &setup.cipher,
        )?;
        for (row, &dealer) in DEALERS.iter().enumerate() {
            let outgoing = setup.material[dealer as usize].outgoing_keys.open(
                PROFILE,
                binding,
                dealer as u32,
                3,
                &setup.cipher,
            )?;
            assert!(incoming[row].as_bytes() == outgoing[owner].as_bytes());
        }
        for change in 0..5 {
            let mut altered = restored.clone();
            match change {
                0 => altered.context.party_id = (owner as u32 + 1) % 3,
                1 => altered.context.setup.crypto_config_id = [9; 32].into(),
                2 => altered.dealer_ids.reverse(),
                3 => altered.key_bundle = Some([0; 32]),
                _ => {
                    altered.c2_statements.remove(&0);
                }
            }
            assert!(altered
                .validate(
                    &setup.selected[owner],
                    Address::repeat_byte(0x11),
                    &setup.cipher
                )
                .is_err());
        }
        let mut altered_request = sk_request.clone();
        altered_request
            .synchronized
            .as_mut()
            .unwrap()
            .expected_commitments[0][0][31] ^= 1;
        assert!(prepare_share_decryption(
            &setup.config,
            &altered_request,
            &setup.selected[owner].e3_id,
            &setup.cipher
        )
        .is_err());
        let mut altered_request = sk_request;
        altered_request
            .synchronized
            .as_mut()
            .unwrap()
            .context
            .setup
            .interfold_address = Address::repeat_byte(0x12);
        assert!(prepare_share_decryption(
            &setup.config,
            &altered_request,
            &setup.selected[owner].e3_id,
            &setup.cipher
        )
        .is_err());
    }
    // Independent T=1 interpolation at x=0. Recipient IDs 0,1,2 name coordinates 1,2,3;
    // compare every T+1 pair with the original dealers' SKs, not another native aggregate.
    assert_eq!(COMMITTEE.values().threshold, 1);
    let secrets = DEALERS
        .iter()
        .map(|&dealer| {
            try_poly_from_sensitive_bytes(
                setup.responses[dealer as usize].sk_raw.clone(),
                setup.config.threshold.clone(),
                &setup.cipher,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for (limb, &modulus) in setup.config.threshold.moduli().iter().enumerate() {
        let q = u128::from(modulus);
        for (x1, x2) in [(1usize, 2usize), (1, 3), (2, 3)] {
            let inverse = if x2 - x1 == 1 { 1 } else { (q + 1) / 2 };
            for coefficient in 0..setup.config.threshold.degree() {
                let a = u128::from(aggregate_shares[x1 - 1].coefficients()[(limb, coefficient)]);
                let b = u128::from(aggregate_shares[x2 - 1].coefficients()[(limb, coefficient)]);
                let reconstructed = ((x2 as u128 * a + q - x1 as u128 * b % q) % q) * inverse % q;
                let expected = secrets
                    .iter()
                    .map(|secret| u128::from(secret.coefficients()[(limb, coefficient)]))
                    .sum::<u128>()
                    % q;
                assert!(
                    reconstructed == expected,
                    "SK reconstruction mismatch at coordinates {x1},{x2}, limb {limb}, coefficient {coefficient}"
                );
            }
        }
    }
    Ok(())
}

#[actix::test]
async fn synchronized_work_plan_restart_preserves_exact_randomized_bytes_and_rejects_substitution(
) -> Result<()> {
    let setup = Setup::new().await?;
    let owner = 2;
    let event = TypedEvent::new(setup.pending[owner].clone(), test_ec(1));
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let payloads = ThresholdKeyshareRecoveryPayloads::new(store.clone());
    let root = ThresholdKeyshareRecoveryState {
        threshold_share_pending_ref: Some(payloads.write_pending(&event, event.get_ctx())?),
        synchronized: Some(setup.material[owner].clone()),
        ..Default::default()
    };
    let restored = ThresholdKeyshareRecoveryPayloads::load(store, &root).await?;
    let pending = restored.pending().unwrap();
    assert_eq!(bincode::serialize(pending)?, bincode::serialize(&event)?);
    setup.material[owner].validate_pending(&setup.selected[owner], pending, &setup.cipher)?;
    for change in 0..5 {
        let mut altered = pending.clone().into_inner();
        match change {
            0 => altered.proof_request.params_profile = BfvProfile::SsInsecure64,
            1 => altered.sk_share_encryption_requests.swap(0, 1),
            2 => altered.own_sk_share_raw = setup.pending[0].own_sk_share_raw.clone(),
            3 => {
                altered
                    .proof_request
                    .synchronized
                    .as_mut()
                    .unwrap()
                    .party_id = 0
            }
            _ => {
                altered
                    .sk_share_computation_request
                    .synchronized
                    .as_mut()
                    .unwrap()
                    .outgoing_keys = setup.material[0].outgoing_keys.clone()
            }
        }
        assert!(setup.material[owner]
            .validate_pending(&setup.selected[owner], &altered, &setup.cipher)
            .is_err());
    }
    let mut wrong_selection = setup.selected[owner].clone();
    wrong_selection.params = ArcBytes::default();
    assert!(proof_context(&wrong_selection, Address::repeat_byte(0x11)).is_err());
    let input = prepare_pk_generation(
        &setup.config,
        &setup.pending[owner].proof_request,
        &setup.selected[owner].e3_id,
        &setup.cipher,
    )?;
    assert!(!input.to_json().is_null());
    Ok(())
}

#[actix::test]
async fn synchronized_authenticated_rejection_does_not_consume_the_dealers_valid_replacement(
) -> Result<()> {
    let setup = Setup::new().await?;
    let e3 = &setup.selected[2].e3_id;
    let (mut actor, _, recovery_repo, _) =
        build_actor(e3, generating_threshold_share_state(e3), 7200, 7200, &[]).await?;
    actor.params_profile = PROFILE;
    actor.interfold_address = Address::repeat_byte(0x11);
    actor.cipher = setup.cipher.clone();
    actor.signer = setup.signers[2].clone();
    actor.state.try_mutate_without_context(|mut state| {
        state.party_id = 2;
        state.params = setup.selected[2].params.clone();
        Ok(state)
    })?;
    actor.recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(setup.selected[2].clone(), test_ec(0)));
        Ok(recovery)
    })?;
    let (parent, _, _, _) = build_actor(e3, KeyshareState::Init, 7200, 7200, &[]).await?;
    let parent = parent.start();
    let valid = setup.message(0, 2)?;
    for change in 0..4 {
        let mut rejected = valid.clone();
        match change {
            0 => rejected.signature = Default::default(),
            1 => {
                rejected.signed_c3a_proofs.swap(0, 1);
                rejected = rejected.sign(&setup.signers[0])?;
            }
            2 => {
                rejected.signed_c2a_proof = Some(setup.c2[&2].clone());
                rejected = rejected.sign(&setup.signers[0])?;
            }
            _ => {
                rejected.signed_c3b_proofs = rejected.signed_c3a_proofs.clone();
                rejected = rejected.sign(&setup.signers[0])?;
            }
        }
        actor.handle_threshold_share_created(
            TypedEvent::new(rejected, test_ec(1 + change)),
            parent.clone(),
        )?;
        assert!(actor.recovery.try_get()?.threshold_share_refs.is_empty());
        assert!(actor.recovery_payloads.shares().is_empty());
    }
    actor.handle_threshold_share_created(TypedEvent::new(valid.clone(), test_ec(5)), parent)?;
    assert!(recovery_repo
        .read()
        .await?
        .unwrap()
        .threshold_share_refs
        .contains_key(&0));
    assert!(actor
        .recovery_payloads
        .share(0)
        .is_some_and(|saved| **saved == valid));
    Ok(())
}

#[actix::test]
async fn synchronized_c4_claims_match_every_dealer_row_and_the_owner_outgoing_root() -> Result<()> {
    let setup = Setup::new().await?;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(recipient),
        ..
    } = setup.plan(2)?
    else {
        anyhow::bail!("missing recipient");
    };
    let DecryptionKeyPlan::Proceed {
        sk_request,
        synchronized: Some(owner),
        ..
    } = setup.plan(0)?
    else {
        anyhow::bail!("missing owner");
    };
    let fields = c4_fields(&sk_request, &owner, &setup.selected[0].e3_id)?;
    let proof = signed(&setup, 0, ProofType::C4aSkShareDecryption, fields.clone())?;
    recipient.validate_c4(&setup.config, &setup.selected[0].e3_id, 0, &proof)?;
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        let mut changed = fields.clone();
        changed[index][31] ^= 1;
        let proof = signed(&setup, 0, ProofType::C4aSkShareDecryption, changed)?;
        assert!(
            recipient
                .validate_c4(&setup.config, &setup.selected[0].e3_id, 0, &proof)
                .is_err(),
            "accepted altered C4 field {index}"
        );
    }
    // Missing authenticated C2 is a local provenance failure, not evidence against that dealer.
    let mut incomplete = recipient;
    incomplete.c2_statements.remove(&0);
    assert!(incomplete
        .validate_c4(&setup.config, &setup.selected[0].e3_id, 0, &proof)
        .is_err());
    Ok(())
}

#[actix::test]
async fn synchronized_missing_c2_provenance_does_not_accuse_or_reserve_a_c4_slot() -> Result<()> {
    let setup = Setup::new().await?;
    let e3 = &setup.selected[1].e3_id;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(mut recipient),
        ..
    } = setup.plan(1)?
    else {
        anyhow::bail!("missing recipient");
    };
    let mut messages = Vec::new();
    for &dealer in &DEALERS {
        let DecryptionKeyPlan::Proceed {
            sk_request,
            synchronized: Some(material),
            ..
        } = setup.plan(dealer as usize)?
        else {
            anyhow::bail!("missing dealer");
        };
        messages.push(
            DecryptionKeyShared {
                e3_id: e3.clone(),
                party_id: dealer,
                node: setup.signers[dealer as usize].address().to_string(),
                signed_sk_decryption_proof: signed(
                    &setup,
                    dealer as usize,
                    ProofType::C4aSkShareDecryption,
                    c4_fields(&sk_request, &material, e3)?,
                )?,
                signed_e_sm_decryption_proofs: vec![],
                external: true,
                signature: Default::default(),
            }
            .sign(&setup.signers[dealer as usize])?,
        );
    }
    let provenance = recipient.c2_statements.remove(&0).unwrap();
    let mut ready = ready_for_c4_test();
    ready.es_poly_sum.clear();
    let (mut actor, _, recovery_repo, history) = build_actor(
        e3,
        KeyshareState::ReadyForDecryption(ready),
        7200,
        7200,
        &[],
    )
    .await?;
    actor.params_profile = PROFILE;
    actor.interfold_address = Address::repeat_byte(0x11);
    actor.state.try_mutate_without_context(|mut state| {
        state.party_id = 1;
        state.honest_parties = Some(DEALERS.into());
        Ok(state)
    })?;
    actor.recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(setup.selected[1].clone(), test_ec(0)));
        recovery.synchronized = Some(recipient);
        Ok(recovery)
    })?;
    let (parent, _, _, _) = build_actor(e3, KeyshareState::Init, 7200, 7200, &[]).await?;
    actor.handle_decryption_key_shared(messages[0].clone(), test_ec(1), parent.start());
    assert!(actor.recovery.try_get()?.decryption_key_shares.is_empty());
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    // Restore only local provenance, then redeliver the same signed peer bytes.
    actor.recovery.try_mutate_without_context(|mut recovery| {
        recovery
            .synchronized
            .as_mut()
            .unwrap()
            .c2_statements
            .insert(0, provenance);
        Ok(recovery)
    })?;
    actor.effects_enabled = true;
    let actor = actor.start();
    for (index, message) in messages.iter().enumerate() {
        actor
            .send(keyshare_event(
                message.clone(),
                2 + index as u64,
                EventSource::Net,
            ))
            .await?;
    }
    let dispatched = next_event(&history).await?;
    let InterfoldEventData::ShareVerificationDispatched(dispatched) = dispatched.get_data() else {
        anyhow::bail!("restored provenance did not complete C4 collection");
    };
    assert!(dispatched.pre_dishonest.is_empty());
    assert_eq!(
        dispatched
            .decryption_proofs
            .iter()
            .map(|proof| proof.sender_party_id)
            .collect::<BTreeSet<_>>(),
        DEALERS.into()
    );
    assert!(recovery_repo
        .read()
        .await?
        .unwrap()
        .decryption_key_shares
        .get(&0)
        .is_some_and(|saved| **saved == messages[0]));
    Ok(())
}

#[actix::test]
async fn synchronized_conflicting_success_cannot_replace_recovered_randomized_generation(
) -> Result<()> {
    let setup = Setup::new().await?;
    let owner = 0;
    let e3 = &setup.selected[owner].e3_id;
    let (mut actor, _, _, _) =
        build_actor(e3, generating_threshold_share_state(e3), 7200, 7200, &[]).await?;
    actor.params_profile = PROFILE;
    actor.recovery.try_mutate_without_context(|mut recovery| {
        recovery.synchronized = Some(setup.material[owner].clone());
        Ok(recovery)
    })?;
    actor.state.try_mutate_without_context(|mut state| {
        let KeyshareState::GeneratingThresholdShare(current) = &mut state.state else {
            unreachable!()
        };
        current.pk_share = Some(setup.responses[owner].pk_share.clone());
        Ok(state)
    })?;
    let response = |output| {
        TypedEvent::new(
            ComputeResponse::trbfv(
                e3_trbfv::TrBFVResponse::GenPkShareAndSkSss(output),
                CorrelationId::new(),
                e3.clone(),
            ),
            test_ec(1),
        )
    };
    actor.handle_gen_pk_share_and_sk_sss_response(response(setup.responses[owner].clone()))?;
    let mut changed = setup.responses[owner].clone();
    changed.pk_share = setup.responses[2].pk_share.clone();
    assert!(actor
        .handle_gen_pk_share_and_sk_sss_response(response(changed))
        .is_err());
    assert_eq!(
        actor.recovery.try_get()?.synchronized,
        Some(setup.material[owner].clone())
    );
    Ok(())
}

#[actix::test]
async fn synchronized_early_c4_is_rechecked_before_it_can_reserve_a_recovered_slot() -> Result<()> {
    let setup = Setup::new().await?;
    let e3 = &setup.selected[1].e3_id;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(recipient),
        ..
    } = setup.plan(1)?
    else {
        anyhow::bail!("missing recipient");
    };
    let DecryptionKeyPlan::Proceed {
        sk_request,
        synchronized: Some(owner),
        ..
    } = setup.plan(0)?
    else {
        anyhow::bail!("missing owner");
    };
    let fields = c4_fields(&sk_request, &owner, e3)?;
    let valid = DecryptionKeyShared {
        e3_id: e3.clone(),
        party_id: 0,
        node: setup.signers[0].address().to_string(),
        signed_sk_decryption_proof: signed(
            &setup,
            0,
            ProofType::C4aSkShareDecryption,
            fields.clone(),
        )?,
        signed_e_sm_decryption_proofs: vec![],
        external: true,
        signature: Default::default(),
    }
    .sign(&setup.signers[0])?;
    let mut wrong_fields = fields;
    wrong_fields[6][31] ^= 1;
    let mut early = valid.clone();
    early.signed_sk_decryption_proof =
        signed(&setup, 0, ProofType::C4aSkShareDecryption, wrong_fields)?;
    early = early.sign(&setup.signers[0])?;
    let DecryptionKeyPlan::Proceed {
        sk_request: other_request,
        synchronized: Some(other_material),
        ..
    } = setup.plan(2)?
    else {
        anyhow::bail!("missing other dealer");
    };
    let retained = DecryptionKeyShared {
        party_id: 2,
        node: setup.signers[2].address().to_string(),
        signed_sk_decryption_proof: signed(
            &setup,
            2,
            ProofType::C4aSkShareDecryption,
            c4_fields(&other_request, &other_material, e3)?,
        )?,
        ..valid.clone()
    }
    .sign(&setup.signers[2])?;
    let (mut actor, _, recovery_repo, history) = build_actor(
        e3,
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
        7200,
        7200,
        &[],
    )
    .await?;
    actor.params_profile = PROFILE;
    actor.interfold_address = Address::repeat_byte(0x11);
    actor.state.try_mutate_without_context(|mut state| {
        state.party_id = 1;
        state.honest_parties = Some(DEALERS.into());
        Ok(state)
    })?;
    actor.recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(setup.selected[1].clone(), test_ec(0)));
        recovery
            .decryption_key_shares
            .insert(0, TypedEvent::new(early.clone(), test_ec(1)));
        recovery
            .decryption_key_shares
            .insert(2, TypedEvent::new(retained.clone(), test_ec(1)));
        recovery.synchronized = Some(recipient);
        Ok(recovery)
    })?;
    actor.handle_early_decryption_key_share(early.clone(), test_ec(1))?;
    actor.state.try_mutate_without_context(|mut state| {
        let mut ready = ready_for_c4_test();
        ready.es_poly_sum.clear();
        state.state = KeyshareState::ReadyForDecryption(ready);
        Ok(state)
    })?;
    actor.effects_enabled = true;
    let actor = actor.start();
    actor
        .send(TypedEvent::new(
            AllDecryptionKeySharesCollected {
                shares: HashMap::from([(0, early), (2, retained)]),
            },
            test_ec(2),
        ))
        .await?;
    let recovery = recovery_repo.read().await?.unwrap();
    assert_eq!(
        recovery
            .decryption_key_shares
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![2]
    );
    actor
        .send(keyshare_event(valid.clone(), 3, EventSource::Net))
        .await?;
    let dispatched = next_event(&history).await?;
    let InterfoldEventData::ShareVerificationDispatched(dispatched) = dispatched.get_data() else {
        anyhow::bail!("replacement did not complete the retained C4 batch");
    };
    assert_eq!(
        dispatched
            .decryption_proofs
            .iter()
            .map(|proof| proof.sender_party_id)
            .collect::<BTreeSet<_>>(),
        DEALERS.into()
    );
    assert!(dispatched.pre_dishonest.is_empty());
    assert!(recovery_repo
        .read()
        .await?
        .unwrap()
        .decryption_key_shares
        .get(&0)
        .is_some_and(|saved| **saved == valid));
    Ok(())
}

fn run(command: &mut std::process::Command) -> Result<std::process::Output> {
    let output = command
        .output()
        .with_context(|| format!("start {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn prove_prepared<C: e3_zk_prover::Provable>(
    circuit: &C,
    prover: &e3_zk_prover::ZkProver,
    config: &C::Config,
    inputs: &C::Input,
    owner: u64,
) -> Result<Proof> {
    let proof = circuit.prove(
        prover,
        config,
        inputs,
        "sync-runtime-definition",
        "sync-insecure-64/minimum",
    )?;
    ensure!(circuit.verify(
        prover,
        &proof,
        "sync-runtime-definition",
        owner,
        "sync-insecure-64/minimum"
    )?);
    let mut altered = proof.clone();
    let mut signals = altered.public_signals.to_vec();
    *signals.last_mut().context("missing public signals")? ^= 1;
    altered.public_signals = ArcBytes::from_bytes(&signals);
    ensure!(!circuit.verify(
        prover,
        &altered,
        "sync-runtime-definition",
        owner,
        "sync-insecure-64/minimum"
    )?);
    Ok(proof)
}

fn real_prover(circuits: &[CircuitName]) -> Result<(tempfile::TempDir, e3_zk_prover::ZkProver)> {
    use e3_zk_prover::{BBPath, ZkBackend, ZkProver};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let bb = PathBuf::from(
        std::env::var_os("E3_CUSTOM_BB").context("set E3_CUSTOM_BB to the pinned bb executable")?,
    );
    let nargo = run(Command::new("nargo").arg("--version"))?;
    let expected = e3_zk_build::pinned_noir_version(&fs::read_to_string(
        root.join("crates/zk/prover/Cargo.toml"),
    )?)?;
    ensure!(e3_zk_build::reports_version(
        &String::from_utf8_lossy(&nargo.stdout),
        &expected
    ));
    let versions: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("crates/zk/prover/versions.json"))?)?;
    let version = run(Command::new(&bb).arg("--version"))?;
    ensure!(e3_zk_build::reports_version(
        &String::from_utf8_lossy(&version.stdout),
        versions["required_bb_version"]
            .as_str()
            .context("missing bb pin")?
    ));
    let directory = tempfile::tempdir()?;
    let artifact_root = directory.path().join("artifacts");
    // Explicit proof variants in private temporary artifacts, not an installable archive.
    for circuit in circuits {
        let package = directory.path().join(circuit.as_str());
        fs::create_dir_all(package.join("src"))?;
        let source = root.join("circuits/bin").join(
            circuit
                .source_path(PROFILE)
                .context("missing sync source")?,
        );
        let mut manifest: toml::Value =
            toml::from_str(&fs::read_to_string(source.join("Nargo.toml"))?)?;
        manifest["package"]["name"] = toml::Value::String("sync_runtime_leaf".into());
        manifest["dependencies"]["lib"]["path"] =
            toml::Value::String(root.join("circuits/lib").to_string_lossy().into());
        fs::write(package.join("Nargo.toml"), toml::to_string(&manifest)?)?;
        fs::copy(source.join("src/main.nr"), package.join("src/main.nr"))?;
        run(Command::new("nargo").arg("compile").current_dir(&package))?;
        // Explicit variants for this private qualification, not a release/staging variant table.
        let variant = match circuit {
            CircuitName::NodeFold | CircuitName::NodesFold | CircuitName::PkAggregation => {
                e3_zk_config::CircuitVariant::Default
            }
            CircuitName::DkgAggregator => e3_zk_config::CircuitVariant::Evm,
            _ => e3_zk_config::CircuitVariant::Recursive,
        };
        let target = artifact_root
            .join(PROFILE.artifacts_dir_for_committee(COMMITTEE)?)
            .join(variant.as_str())
            .join(circuit.dir_path());
        fs::create_dir_all(&target)?;
        let json = target.join(format!("{}.json", circuit.as_str()));
        fs::copy(package.join("target/sync_runtime_leaf.json"), &json)?;
        run(Command::new(&bb)
            .args(["write_vk", "-t", variant.verifier_target(), "-b"])
            .arg(&json)
            .arg("-o")
            .arg(package.join("keys")))?;
        for suffix in ["vk", "vk_hash"] {
            fs::copy(
                package.join("keys").join(suffix),
                target.join(format!("{}.{suffix}", circuit.as_str())),
            )?;
        }
    }
    let prover = ZkProver::new(&ZkBackend::new(
        BBPath::Custom(bb),
        artifact_root,
        directory.path().join("work"),
    ));
    Ok((directory, prover))
}

#[actix::test]
#[ignore = "requires pinned nargo and E3_CUSTOM_BB; proves production sync DKG preparation, not recursive/runtime admission"]
async fn synchronized_prepared_runtime_requests_prove_with_real_crypto() -> Result<()> {
    use e3_zk_prover::synchronized as adapters;
    let (_directory, prover) = real_prover(&[
        CircuitName::PkGeneration,
        CircuitName::SkShareComputation,
        CircuitName::ShareEncryption,
        CircuitName::DkgShareDecryption,
    ])?;
    let mut setup = Setup::new().await?;
    for owner in 0..3 {
        let e3 = &setup.selected[owner].e3_id;
        let generation = prepare_pk_generation(
            &setup.config,
            &setup.pending[owner].proof_request,
            e3,
            &setup.cipher,
        )?;
        let c1 = prove_prepared(
            &adapters::PkGenerationCircuit,
            &prover,
            &setup.config,
            &generation,
            owner as u64,
        )?;
        let computation = prepare_share_computation(
            &setup.config,
            &setup.pending[owner].sk_share_computation_request,
            e3,
            &setup.cipher,
        )?;
        let c2 = prove_prepared(
            &adapters::ShareComputationCircuit,
            &prover,
            &setup.config,
            &computation,
            owner as u64,
        )?;
        let public = PublicSignals::decode(&setup.config, c1.circuit, &c1.public_signals)?;
        assert_eq!(
            public.sk_commitment(),
            Some(commitment_field(computation.expected_secret_commitment())?)
        );
        assert_eq!(
            c2.public_signals,
            setup.c2[&(owner as u64)].payload.proof.public_signals
        );
        setup.c2.insert(
            owner as u64,
            SignedProofPayload::sign(
                ProofPayload {
                    e3_id: e3.clone(),
                    proof_type: ProofType::C2aSkShareComputation,
                    proof: c2,
                },
                &setup.signers[owner],
            )?,
        );
    }
    let encryption = setup.pending[0]
        .sk_share_encryption_requests
        .iter()
        .find(|request| request.recipient_party_id == 2 && request.row_index == 0)
        .unwrap();
    prove_prepared(
        &e3_zk_prover::ShareEncryptionCircuit,
        &prover,
        &setup.config.share_encryption,
        &setup.c3_data(0, encryption)?,
        0,
    )?;
    for owner in 0..3 {
        let DecryptionKeyPlan::Proceed {
            sk_request,
            synchronized: Some(saved),
            ..
        } = setup.plan(owner)?
        else {
            anyhow::bail!("missing C4");
        };
        let e3 = &setup.selected[owner].e3_id;
        let input = prepare_share_decryption(&setup.config, &sk_request, e3, &setup.cipher)?;
        let c4 = prove_prepared(
            &adapters::ShareDecryptionCircuit,
            &prover,
            &setup.config,
            &input,
            owner as u64,
        )?;
        assert_eq!(
            &*c4.public_signals,
            c4_fields(&sk_request, &saved, e3)?.concat()
        );
        let signed = SignedProofPayload::sign(
            ProofPayload {
                e3_id: e3.clone(),
                proof_type: ProofType::C4aSkShareDecryption,
                proof: c4,
            },
            &setup.signers[owner],
        )?;
        saved.validate_c4(&setup.config, e3, owner as u32, &signed)?;
    }
    assert!(!PROFILE.admission_enabled());
    Ok(())
}
