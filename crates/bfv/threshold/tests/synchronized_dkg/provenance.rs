// SPDX-License-Identifier: LGPL-3.0-only

//! Real native contributions and independently verified mismatched children. Temporary artifacts
//! exercise the production preparation/prover API and isolated publication verifier, not admission.

use super::*;
use e3_events::{E3id, Proof, SynchronizedProofContext};
use e3_zk_config::{synchronized::public_signals::PublicSignals, CircuitVariant};
use e3_zk_prover::{
    inputs_json_to_input_map,
    synchronized::{provenance::*, request_binding},
    BBPath, CompiledCircuit, WitnessGenerator, ZkBackend, ZkProver,
};

fn field(value: &BigInt) -> [u8; 32] {
    let (_, bytes) = value.to_bytes_be();
    let mut result = [0; 32];
    result[32 - bytes.len()..].copy_from_slice(&bytes);
    result
}

fn variant(role: CircuitName) -> CircuitVariant {
    if matches!(
        role,
        CircuitName::NodeFold | CircuitName::NodesFold | CircuitName::PkAggregation
    ) {
        CircuitVariant::Default
    } else if role == CircuitName::DkgAggregator {
        CircuitVariant::Evm
    } else {
        CircuitVariant::Recursive
    }
}

// This is an isolated, explicitly selected proof variant, not an installable archive or a copy of
// the release variant/marker table. Source manifests retain their canonical dependency pins.
fn stage(job: &CircuitJob, prover: &ZkProver, bb: &Path, role: CircuitName) -> Result<PathBuf> {
    run(Command::new("nargo")
        .arg("compile")
        .current_dir(job.directory.path()))?;
    let namespace = PROFILE.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum)?;
    let destination = prover
        .circuits_dir(variant(role), &namespace)
        .join(role.dir_path());
    fs::create_dir_all(&destination)?;
    let compiled = destination.join(format!("{}.json", role.as_str()));
    fs::copy(
        job.directory.path().join("target/sync_leaf.json"),
        &compiled,
    )?;
    let key = job.directory.path().join("key");
    run(Command::new(bb)
        .args(["write_vk", "-b"])
        .arg(&compiled)
        .args(["-t", variant(role).verifier_target(), "-o"])
        .arg(&key))?;
    for suffix in ["vk", "vk_hash"] {
        fs::copy(
            key.join(suffix),
            destination.join(format!("{}.{suffix}", role.as_str())),
        )?;
    }
    Ok(compiled)
}

fn prove_json(prover: &ZkProver, role: CircuitName, input: &Value, job: &str) -> Result<Proof> {
    let namespace = PROFILE.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum)?;
    let path = prover
        .circuits_dir(variant(role), &namespace)
        .join(role.dir_path())
        .join(format!("{}.json", role.as_str()));
    let compiled = CompiledCircuit::from_file(&path)?;
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, inputs_json_to_input_map(input)?)
        .with_context(|| format!("Witness for {role} / {job}"))?;
    let proof =
        prover.generate_proof_with_variant(role, &witness, job, variant(role), &namespace)?;
    ensure!(prover.verify_proof_with_variant(&proof, job, 0, variant(role), &namespace)?);
    Ok(proof)
}

fn reject_join(compiled: &Path, input: &Value, expected: &str) -> Result<()> {
    let compiled = CompiledCircuit::from_file(compiled)?;
    let error = WitnessGenerator::new()
        .generate_witness(&compiled, inputs_json_to_input_map(input)?)
        .expect_err("mismatched independently valid children must not join");
    ensure!(
        matches!(&error, e3_zk_prover::ZkError::WitnessGenerationFailed(message)
            if message.contains("Cannot satisfy constraint") || message == "Failed assertion"),
        "{expected} did not reach a completed constraint rejection: {error}"
    );
    Ok(())
}

fn replace_child(input: &mut Value, prefix: &str, proof: &Proof) -> Result<()> {
    input[format!("{prefix}_proof")] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &proof.data
    )?);
    input[format!("{prefix}_public")] = json!(
        e3_zk_prover::test_utils::fold_witness_field_strings(&proof.public_signals)?
    );
    Ok(())
}

#[test]
fn c5_preparation_requires_complete_threshold_shares_and_the_profile_crs() -> Result<()> {
    use e3_zk_prover::synchronized::publication::prepare_c5;
    use e3_zk_witness::threshold::pk_aggregation::PkAggregationCircuitData;

    let fixture = Fixture::native()?;
    let selected: Vec<_> = DEALERS
        .iter()
        .map(|&id| fixture.threshold_shares[id as usize].clone())
        .collect();
    let data = PkAggregationCircuitData {
        public_key: PublicKey::from_shares(selected.clone())?,
        pk0_shares: selected
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(share.p0_share()))
            .collect(),
    };
    prepare_c5(&fixture.config, &data)?;
    let mut incomplete = data.clone();
    incomplete.pk0_shares.pop();
    ensure!(prepare_c5(&fixture.config, &incomplete).is_err());
    let mut other_crs = data.clone();
    other_crs.public_key.c[1] = other_crs.public_key.c[0].clone();
    ensure!(prepare_c5(&fixture.config, &other_crs).is_err());
    let other_profile = PkAggregationCircuitData {
        public_key: fixture.recipient_public[0].clone(),
        ..data
    };
    ensure!(prepare_c5(&fixture.config, &other_profile).is_err());
    Ok(())
}

#[test]
#[ignore = "requires pinned nargo/bb, solc 0.8.28 and pnpm; isolated publication, not registry/runtime admission"]
fn real_dealer_and_recipient_joins_reject_valid_but_unrelated_children() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let bb = check_tools(&root)?;
    let temp = tempfile::tempdir()?;
    let backend = ZkBackend::new(
        BBPath::Custom(bb.clone()),
        temp.path().join("artifacts"),
        temp.path().join("work"),
    );
    let prover = ZkProver::new(&backend);
    let context = SynchronizedProofContext {
        setup: e3_committee_hash::DkgSetupContext {
            interfold_address: [0x11; 20].into(),
            committee_hash: e3_committee_hash::hash_committee_addresses(&[
                [1; 20].into(),
                [2; 20].into(),
                [3; 20].into(),
            ]),
            crypto_config_id: PROFILE.crypto_config_id(CiphernodesCommitteeSize::Minimum)?,
        },
        party_id: 0,
    };
    let e3_id = E3id::new("245904", 31337);
    let config = Configs::for_profile(PROFILE, CiphernodesCommitteeSize::Minimum)?;
    let binding = request_binding(&config, &context, &e3_id)?;
    let fixture = Fixture::native_at(binding)?;
    let config = fixture.config.clone();
    let mut jobs = BTreeMap::new();
    let mut compiled = BTreeMap::new();
    for role in CircuitName::SYNCHRONIZED_DKG {
        let job = CircuitJob::new(&root, role)?;
        eprintln!("Preparing {role}");
        compiled.insert(role.dir_path(), stage(&job, &prover, &bb, role)?);
        jobs.insert(role.dir_path(), job);
    }
    let mut leaves = Vec::new();
    let l = config.threshold.moduli().len();
    for leaf in &fixture.leaves {
        let required = match leaf.role {
            CircuitName::PkGeneration => {
                DEALERS.contains(&(leaf.inputs["dealer_id"].as_u64().unwrap() as u32))
            }
            CircuitName::ShareEncryption => {
                let (dealer, recipient, _) = leaf.transport_slot.unwrap();
                dealer != recipient
            }
            _ => true,
        };
        if required {
            let proof = prove_json(&prover, leaf.role, &leaf.inputs, "native-leaf")?;
            let public = PublicSignals::decode(&config, leaf.role, &proof.public_signals)?;
            let outputs = &public.fields()[public.fields().len() - leaf.outputs.len()..];
            ensure!(outputs == leaf.outputs.iter().map(field).collect::<Vec<_>>());
            leaves.push((leaf, proof));
        }
    }
    let get = |role, id| -> &Proof {
        leaves
            .iter()
            .filter(|(leaf, _)| leaf.role == role)
            .find(|(leaf, _)| {
                let key = if role == CircuitName::DkgShareDecryption {
                    "recipient_id"
                } else {
                    "dealer_id"
                };
                leaf.inputs[key].as_u64() == Some(id as u64)
            })
            .map(|(_, proof)| proof)
            .unwrap()
    };
    let c0: Vec<_> = leaves
        .iter()
        .filter(|(leaf, _)| leaf.role == CircuitName::PkBfv)
        .map(|(_, proof)| proof)
        .collect();
    let mut nodes = Vec::new();
    let mut dealer_inputs = Vec::new();
    for &dealer in &DEALERS {
        let mut transport: Vec<_> = leaves
            .iter()
            .filter_map(|(leaf, proof)| {
                leaf.transport_slot
                    .filter(|&(id, recipient, _)| id == dealer && recipient != dealer)
                    .map(|(_, recipient, limb)| ((recipient, limb), proof.clone()))
            })
            .collect();
        transport.sort_by_key(|(slot, _)| *slot);
        let transport: Vec<_> = transport.into_iter().map(|(_, proof)| proof).collect();
        ensure!(transport.len() == (config.committee.values().n - 1) * l);
        let local = SynchronizedProofContext {
            party_id: dealer,
            ..context.clone()
        };
        let input = DealerJoin {
            c1: get(CircuitName::PkGeneration, dealer),
            c2: get(CircuitName::SkShareComputation, dealer),
            c3: &transport,
        };
        dealer_inputs.push(prepare_dealer(&prover, &config, &local, &e3_id, &input)?);
        eprintln!("Proving dealer {dealer}");
        let proof = prove_dealer(&prover, &config, &local, &e3_id, &input, "dealer")?;
        ensure!(prover.verify_fold_proof(
            &proof,
            "dealer",
            dealer as u64,
            &PROFILE.artifacts_dir_for_committee(config.committee)?
        )?);
        nodes.push(proof);
    }

    // Every replacement below is independently verified, not a bit-flipped public statement.
    let c1 = leaves
        .iter()
        .find(|(leaf, _)| leaf.role == CircuitName::PkGeneration)
        .unwrap()
        .0;
    let mut foreign = c1.inputs.clone();
    foreign["setup_binding"] = json!(["1", "2"]);
    let foreign = prove_json(&prover, CircuitName::PkGeneration, &foreign, "foreign-c1")?;
    let mut changed = dealer_inputs[0].clone();
    replace_child(&mut changed, "c1", &foreign)?;
    reject_join(
        &compiled[&CircuitName::NodeFold.dir_path()],
        &changed,
        "Assertion",
    )?;
    let mut changed = dealer_inputs[0].clone();
    replace_child(&mut changed, "c1", get(CircuitName::PkGeneration, 2))?;
    reject_join(
        &compiled[&CircuitName::NodeFold.dir_path()],
        &changed,
        "Assertion",
    )?;
    // Same dealer and context, independently valid C1 but a different SK contribution.
    // Dealer 2's native secret/public contribution, consistently relabelled to dealer 0.
    let alternate_c1 = fixture
        .leaves
        .iter()
        .find(|leaf| {
            leaf.role == CircuitName::PkGeneration && leaf.inputs["dealer_id"].as_u64() == Some(2)
        })
        .unwrap();
    let mut changed_c1 = alternate_c1.inputs.clone();
    changed_c1["dealer_id"] = json!(0);
    let alternate = prove_json(&prover, CircuitName::PkGeneration, &changed_c1, "other-sk")?;
    let mut changed = dealer_inputs[0].clone();
    replace_child(&mut changed, "c1", &alternate)?;
    reject_join(
        &compiled[&CircuitName::NodeFold.dir_path()],
        &changed,
        "C1/C2 secret differs",
    )?;
    let mut changed = dealer_inputs[0].clone();
    changed["c3_proofs"].as_array_mut().unwrap().swap(0, 1);
    changed["c3_public"].as_array_mut().unwrap().swap(0, 1);
    reject_join(
        &compiled[&CircuitName::NodeFold.dir_path()],
        &changed,
        "C2/C3 message differs",
    )?;
    // A valid C3 uses the exact message of row 1 but another recipient key. It must not inherit
    // limb zero's key merely because the exported key is limb zero's.
    let packed = ShamirShare::new(Array2::from_shape_vec(
        (l, config.threshold.degree()),
        fixture.openings[1].packed_shares[0].concat(),
    )?);
    let mut rng = ChaCha8Rng::seed_from_u64(24590499);
    let (_, witnesses) = BfvEncryptedShare::encrypt_extended(
        &packed,
        &fixture.recipient_public[2],
        &config.transport,
        &mut rng,
    )?;
    let witness = witnesses.into_iter().nth(1).unwrap();
    let wrong_key = share_encryption::Inputs::compute(
        &config.share_encryption,
        &share_encryption::ShareEncryptionCircuitData {
            plaintext: Plaintext::try_encode(
                &witness.share_row,
                Encoding::poly(),
                &config.transport,
            )?,
            ciphertext: witness.ciphertext,
            public_key: fixture.recipient_public[2].clone(),
            u_rns: witness.u_rns,
            e0_rns: witness.e0_rns,
            e1_rns: witness.e1_rns,
        },
    )?;
    let wrong = prove_json(
        &prover,
        CircuitName::ShareEncryption,
        &wrong_key.to_json(),
        "wrong-crt-key",
    )?;
    let mut changed = dealer_inputs[0].clone();
    changed["c3_proofs"][1] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &wrong.data
    )?);
    changed["c3_public"][1] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &wrong.public_signals
    )?);
    reject_join(
        &compiled[&CircuitName::NodeFold.dir_path()],
        &changed,
        "C3 recipient key differs across CRT rows",
    )?;

    let mut recipient_inputs = Vec::new();
    let mut recipients = Vec::new();
    let batch = e3_zk_witness::synchronized::provenance::dealer_batch(
        &config,
        binding,
        &DEALERS,
        &nodes
            .iter()
            .map(|proof| e3_zk_witness::synchronized::provenance::Child {
                circuit: proof.circuit,
                proof: &proof.data,
                public_signals: &proof.public_signals,
            })
            .collect::<Vec<_>>(),
    )?;
    for recipient in 0..config.committee.values().n as u32 {
        let local = SynchronizedProofContext {
            party_id: recipient,
            ..context.clone()
        };
        let input = RecipientJoin {
            dealer_ids: &DEALERS,
            c0: c0[recipient as usize],
            own_c2: get(CircuitName::SkShareComputation, recipient),
            c4: get(CircuitName::DkgShareDecryption, recipient),
            nodes: &nodes,
        };
        recipient_inputs.push(prepare_recipient(&prover, &config, &local, &e3_id, &input)?);
        eprintln!("Proving recipient {recipient}");
        let proof = prove_recipient(&prover, &config, &local, &e3_id, &input, "recipient")?;
        let opening = PublicSignals::decode(&config, input.c4.circuit, &input.c4.public_signals)?;
        let threshold_keys = DEALERS
            .iter()
            .map(|&id| {
                PublicSignals::decode(
                    &config,
                    CircuitName::PkGeneration,
                    &get(CircuitName::PkGeneration, id).public_signals,
                )
                .unwrap()
                .pk_commitment()
                .unwrap()
            })
            .collect::<Vec<_>>();
        let expected = ExpectedSetup {
            dealers: &DEALERS,
            threshold_keys: &threshold_keys,
            dealer_batch: batch,
            sk_commitment: opening.sk_commitment().unwrap(),
            key_bundle: opening.key_bundle().unwrap(),
        };
        let commitments = verify_recipient(
            &prover,
            &config,
            &local,
            &e3_id,
            &expected,
            &proof,
            "verify-recipient",
        )?
        .context("valid setup rejected")?;
        ensure!(commitments.binding() == binding);
        ensure!(commitments.recipient() == recipient);
        ensure!(commitments.dealers() == DEALERS);
        ensure!(commitments.sk_commitment() == opening.sk_commitment().unwrap());
        ensure!(commitments.key_bundle() == opening.key_bundle().unwrap());
        ensure!(commitments.threshold_keys() == threshold_keys);
        ensure!(commitments.dealer_batch() == batch);
        ensure!(verify_recipient(
            &prover,
            &config,
            &local,
            &e3_id,
            &ExpectedSetup {
                dealers: &[1, 2],
                ..expected
            },
            &proof,
            "wrong-roster"
        )?
        .is_none());
        ensure!(verify_recipient(
            &prover,
            &config,
            &local,
            &E3id::new("245905", 31337),
            &expected,
            &proof,
            "wrong-e3"
        )?
        .is_none());
        for field in 0..4 {
            let mut expected = expected;
            let mut keys = threshold_keys.clone();
            match field {
                0 => {
                    keys[1][31] ^= 1;
                    expected.threshold_keys = &keys;
                }
                1 => expected.sk_commitment[31] ^= 1,
                2 => expected.key_bundle[31] ^= 1,
                _ => expected.dealer_batch[31] ^= 1,
            }
            ensure!(verify_recipient(
                &prover,
                &config,
                &local,
                &e3_id,
                &expected,
                &proof,
                "wrong-admitted-anchor"
            )?
            .is_none());
        }
        recipients.push(proof);
    }

    use e3_zk_prover::synchronized::publication::*;
    use e3_zk_witness::threshold::pk_aggregation::PkAggregationCircuitData;
    let selected_shares: Vec<_> = DEALERS
        .iter()
        .map(|&id| fixture.threshold_shares[id as usize].clone())
        .collect();
    let public_key = PublicKey::from_shares(selected_shares.clone())?;
    let data = PkAggregationCircuitData {
        public_key: public_key.clone(),
        pk0_shares: selected_shares
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(share.p0_share()))
            .collect(),
    };
    let c5 = prove_c5(&prover, &config, &data, "publication-c5")?;
    ensure!(prover.verify_proof_with_variant(
        &c5,
        "c5",
        0,
        CircuitVariant::Default,
        &PROFILE.artifacts_dir_for_committee(config.committee)?
    )?);
    let selected_setups: Vec<_> = DEALERS
        .iter()
        .map(|&id| recipients[id as usize].clone())
        .collect();
    let join = PublicationJoin {
        dealers: &DEALERS,
        recipients: &selected_setups,
        c5: &c5,
    };
    let publication_input = prepare_publication(&prover, &config, &context, &e3_id, &join)?;
    let publication = prove_publication(&prover, &config, &context, &e3_id, &join, "publication")?;
    let threshold_keys: Vec<_> = DEALERS
        .iter()
        .map(|&id| {
            PublicSignals::decode(
                &config,
                CircuitName::PkGeneration,
                &get(CircuitName::PkGeneration, id).public_signals,
            )
            .unwrap()
            .pk_commitment()
            .unwrap()
        })
        .collect();
    let openings: Vec<_> = DEALERS
        .iter()
        .map(|&id| {
            PublicSignals::decode(
                &config,
                CircuitName::DkgShareDecryption,
                &get(CircuitName::DkgShareDecryption, id).public_signals,
            )
            .unwrap()
        })
        .collect();
    let sk: Vec<_> = openings
        .iter()
        .map(|public| public.sk_commitment().unwrap())
        .collect();
    let bundles: Vec<_> = openings
        .iter()
        .map(|public| public.key_bundle().unwrap())
        .collect();
    let expected = ExpectedPublication {
        dealers: &DEALERS,
        threshold_keys: &threshold_keys,
        dealer_batch: batch,
        sk_commitments: &sk,
        key_bundles: &bundles,
        public_key: &public_key,
    };
    let verified = verify_publication(
        &prover,
        &config,
        &context,
        &e3_id,
        &expected,
        &publication,
        "admit-publication",
    )?
    .context("valid publication rejected")?;
    ensure!(verified.binding() == binding && verified.dealers() == DEALERS);
    ensure!(verified.threshold_keys() == threshold_keys && verified.dealer_batch() == batch);
    ensure!(verified.sk_commitments() == sk && verified.key_bundles() == bundles);
    let mut corrupted = publication.data.to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let corrupted = Proof::new(
        CircuitName::DkgAggregator,
        e3_utils::utility_types::ArcBytes::from_bytes(&corrupted),
        publication.public_signals.clone(),
    );
    // An off-curve encoding fails BB parsing, not its completed invalid-proof verdict.
    // Keep that local error distinct from a cryptographically rejected statement.
    ensure!(verify_publication(
        &prover,
        &config,
        &context,
        &e3_id,
        &expected,
        &corrupted,
        "invalid-publication-proof",
    )
    .is_err());
    let mut altered_signals = publication.public_signals.to_vec();
    altered_signals[(5 + DEALERS.len()) * 32 + 31] ^= 1;
    let altered = Proof::new(
        CircuitName::DkgAggregator,
        publication.data.clone(),
        e3_utils::utility_types::ArcBytes::from_bytes(&altered_signals),
    );
    let mut altered_keys = threshold_keys.clone();
    altered_keys[0][31] ^= 1;
    ensure!(verify_publication(
        &prover,
        &config,
        &context,
        &e3_id,
        &ExpectedPublication {
            threshold_keys: &altered_keys,
            ..expected
        },
        &altered,
        "completed-invalid-publication",
    )?
    .is_none());
    let mut malformed_key = public_key.clone();
    let mut components = public_key.c.to_vec();
    components.push(components[0].clone());
    malformed_key.c = fhe::bfv::Ciphertext::new(components, &config.threshold)?;
    ensure!(verify_publication(
        &prover,
        &config,
        &context,
        &e3_id,
        &ExpectedPublication {
            public_key: &malformed_key,
            ..expected
        },
        &publication,
        "malformed-local-authority",
    )
    .is_err());
    // Outside-H setup can now use the verified publication's batch/key authority, not its own outputs.
    let outside = PublicSignals::decode(
        &config,
        CircuitName::DkgShareDecryption,
        &get(CircuitName::DkgShareDecryption, 1).public_signals,
    )?;
    ensure!(verify_recipient(
        &prover,
        &config,
        &SynchronizedProofContext {
            party_id: 1,
            ..context.clone()
        },
        &e3_id,
        &ExpectedSetup {
            dealers: verified.dealers(),
            threshold_keys: verified.threshold_keys(),
            dealer_batch: verified.dealer_batch(),
            sk_commitment: outside.sk_commitment().unwrap(),
            key_bundle: outside.key_bundle().unwrap(),
        },
        &recipients[1],
        "publication-handoff"
    )?
    .is_some());
    ensure!(verify_publication(
        &prover,
        &config,
        &context,
        &E3id::new("245905", 31337),
        &expected,
        &publication,
        "other-request"
    )?
    .is_none());
    ensure!(verify_publication(
        &prover,
        &config,
        &context,
        &E3id::new("245904", 1),
        &expected,
        &publication,
        "other-chain",
    )?
    .is_none());
    let other_public_key = PublicKey::from_shares(vec![
        fixture.threshold_shares[0].clone(),
        fixture.threshold_shares[1].clone(),
    ])?;
    for slot in 0..6 {
        let mut keys = threshold_keys.clone();
        let mut sk = sk.clone();
        let mut bundles = bundles.clone();
        let mut expected = ExpectedPublication { ..expected };
        match slot {
            0 => {
                keys[1][31] ^= 1;
                expected.threshold_keys = &keys;
            }
            1 => expected.dealer_batch[31] ^= 1,
            2 => {
                sk[1][31] ^= 1;
                expected.sk_commitments = &sk;
            }
            3 => {
                bundles[1][31] ^= 1;
                expected.key_bundles = &bundles;
            }
            4 => expected.dealers = &[1, 2],
            _ => expected.public_key = &other_public_key,
        }
        let result = verify_publication(
            &prover,
            &config,
            &context,
            &e3_id,
            &expected,
            &publication,
            "wrong-admitted-publication",
        );
        ensure!(result?.is_none());
    }
    let mut changed = publication_input.clone();
    changed["setup_proofs"].as_array_mut().unwrap().swap(0, 1);
    changed["setup_public"].as_array_mut().unwrap().swap(0, 1);
    reject_join(
        &compiled[&CircuitName::DkgAggregator.dir_path()],
        &changed,
        "Recipient slot differs",
    )?;
    let mut different_data = data.clone();
    different_data.pk0_shares.reverse();
    let different_c5 = prove_c5(&prover, &config, &different_data, "reordered-c5")?;
    ensure!(prover.verify_proof_with_variant(
        &different_c5,
        "reordered-c5",
        0,
        CircuitVariant::Default,
        &PROFILE.artifacts_dir_for_committee(config.committee)?
    )?);
    let mut changed = publication_input.clone();
    replace_child(&mut changed, "c5", &different_c5)?;
    reject_join(
        &compiled[&CircuitName::DkgAggregator.dir_path()],
        &changed,
        "C5 contribution differs",
    )?;

    // A fresh, valid C3 encryption of the *same* packed message changes no threshold PK or key.
    // Both recipient setup proofs remain independently valid under the canonical VK/tree. Only
    // the batch anchor prevents a publication from combining different successful fan-outs.
    let packed = ShamirShare::new(Array2::from_shape_vec(
        (l, config.threshold.degree()),
        fixture.openings[1].packed_shares[0].concat(),
    )?);
    let (_, witnesses) = BfvEncryptedShare::encrypt_extended(
        &packed,
        &fixture.recipient_public[1],
        &config.transport,
        &mut ChaCha8Rng::seed_from_u64(245906),
    )?;
    let fresh = witnesses.into_iter().next().unwrap();
    let fresh_input = share_encryption::Inputs::compute(
        &config.share_encryption,
        &share_encryption::ShareEncryptionCircuitData {
            plaintext: Plaintext::try_encode(
                &fresh.share_row,
                Encoding::poly(),
                &config.transport,
            )?,
            ciphertext: fresh.ciphertext,
            public_key: fixture.recipient_public[1].clone(),
            u_rns: fresh.u_rns,
            e0_rns: fresh.e0_rns,
            e1_rns: fresh.e1_rns,
        },
    )?;
    let fresh = prove_json(
        &prover,
        CircuitName::ShareEncryption,
        &fresh_input.to_json(),
        "fresh-c3",
    )?;
    let mut fresh_dealer = dealer_inputs[0].clone();
    fresh_dealer["c3_proofs"][0] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &fresh.data
    )?);
    fresh_dealer["c3_public"][0] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &fresh.public_signals
    )?);
    let fresh_dealer = prove_json(
        &prover,
        CircuitName::NodeFold,
        &fresh_dealer,
        "fresh-dealer",
    )?;
    let mut fresh_recipient = recipient_inputs[2].clone();
    fresh_recipient["node_proofs"][0] = json!(
        e3_zk_prover::test_utils::fold_witness_field_strings(&fresh_dealer.data)?
    );
    fresh_recipient["node_public"][0] = json!(
        e3_zk_prover::test_utils::fold_witness_field_strings(&fresh_dealer.public_signals)?
    );
    let fresh_recipient = prove_json(
        &prover,
        CircuitName::NodesFold,
        &fresh_recipient,
        "fresh-recipient",
    )?;
    let fresh_public = PublicSignals::decode(
        &config,
        CircuitName::NodesFold,
        &fresh_recipient.public_signals,
    )?;
    let original_public = PublicSignals::decode(
        &config,
        CircuitName::NodesFold,
        &recipients[2].public_signals,
    )?;
    ensure!(fresh_public.dealer_batch() != original_public.dealer_batch());
    ensure!(fresh_public.threshold_keys() == original_public.threshold_keys());
    ensure!(fresh_public.sk_commitment() == original_public.sk_commitment());
    ensure!(fresh_public.key_bundle() == original_public.key_bundle());
    let mut changed = publication_input.clone();
    changed["setup_proofs"][1] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &fresh_recipient.data
    )?);
    changed["setup_public"][1] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
        &fresh_recipient.public_signals
    )?);
    reject_join(
        &compiled[&CircuitName::DkgAggregator.dir_path()],
        &changed,
        "Dealer batch differs",
    )?;
    if let Err(error) = verify_publication_contract(
        &root,
        &bb,
        temp.path(),
        &prover,
        &config,
        &context,
        &e3_id,
        &publication_input,
        &publication,
        &verified,
    ) {
        let evidence = temp.keep();
        return Err(error.context(format!(
            "Publication qualification retained at {}",
            evidence.display()
        )));
    }

    let setup_path = &compiled[&CircuitName::NodesFold.dir_path()];
    let mut changed = recipient_inputs[1].clone(); // Recipient outside H.
    replace_child(&mut changed, "c0", c0[2])?;
    reject_join(setup_path, &changed, "C3 key differs from recipient C0")?;
    let mut changed = recipient_inputs[1].clone();
    replace_child(&mut changed, "c4", get(CircuitName::DkgShareDecryption, 2))?;
    reject_join(setup_path, &changed, "Assertion")?;
    let mut changed = recipient_inputs[1].clone();
    changed["node_proofs"].as_array_mut().unwrap().swap(0, 1);
    changed["node_public"].as_array_mut().unwrap().swap(0, 1);
    reject_join(setup_path, &changed, "Dealer slot differs")?;
    // Consistently relabelled C4 is valid in isolation but cannot replace the accepted H-roster.
    let c4 = fixture
        .leaves
        .iter()
        .find(|leaf| {
            leaf.role == CircuitName::DkgShareDecryption
                && leaf.inputs["recipient_id"].as_u64() == Some(2)
        })
        .unwrap();
    let mut input = c4.inputs.clone();
    input["dealer_ids"] = json!([1, 2]);
    let other_roster = prove_json(
        &prover,
        CircuitName::DkgShareDecryption,
        &input,
        "other-roster",
    )?;
    let mut changed = recipient_inputs[2].clone();
    replace_child(&mut changed, "c4", &other_roster)?;
    reject_join(setup_path, &changed, "C4 roster differs")?;
    let mut data = copy_opening(&fixture.openings[1]);
    data.packed_shares[0][1][0] = (data.packed_shares[0][1][0] + 1) % config.threshold.moduli()[1];
    let polynomial = Polynomial::new(
        data.packed_shares[0][1]
            .iter()
            .rev()
            .copied()
            .map(BigInt::from)
            .collect(),
    );
    data.expected_commitments[0][1] = compute_share_encryption_commitment_from_message(
        &polynomial,
        config.share_encryption.bits.msg_bit,
    );
    let different_message = share_decryption::Inputs::compute(&config, binding, data)?;
    let different_message = prove_json(
        &prover,
        CircuitName::DkgShareDecryption,
        &different_message.to_json(),
        "different-c4-message",
    )?;
    let mut changed = recipient_inputs[1].clone();
    replace_child(&mut changed, "c4", &different_message)?;
    reject_join(setup_path, &changed, "C2/C4 message differs")?;
    let mut data = copy_opening(&fixture.openings[1]);
    data.outgoing_keys[0][0] ^= 1;
    data.expected_outgoing_root =
        commitments::outgoing_root(&config, binding, 1, &data.outgoing_keys)?;
    let different_root = share_decryption::Inputs::compute(&config, binding, data)?;
    let different_root = prove_json(
        &prover,
        CircuitName::DkgShareDecryption,
        &different_root.to_json(),
        "different-outgoing-root",
    )?;
    let mut changed = recipient_inputs[1].clone();
    replace_child(&mut changed, "c4", &different_root)?;
    reject_join(
        setup_path,
        &changed,
        "C4 outgoing root differs from owner's C2",
    )?;

    // A different, valid C2 VK proves the exact same public statements. Both dealer joins still
    // verify under the canonical NodeFold VK; only their descendant hash differs. Replacing *all*
    // H rows avoids relying merely on the mixed-tree check and exercises the final external pin.
    let alternate = CircuitJob::new(&root, CircuitName::SkShareComputation)?;
    let source = alternate.directory.path().join("src/main.nr");
    let source_text = fs::read_to_string(&source)?
        .replacen("fn main(\n", "fn main(\n    guard: Field,\n", 1)
        .replacen(
            "    execute::<",
            "    assert(guard == 0);\n    execute::<",
            1,
        );
    fs::write(&source, source_text)?;
    let alternate_backend = ZkBackend::new(
        BBPath::Custom(bb.clone()),
        temp.path().join("alternate"),
        temp.path().join("alternate-work"),
    );
    let alternate_prover = ZkProver::new(&alternate_backend);
    stage(
        &alternate,
        &alternate_prover,
        &bb,
        CircuitName::SkShareComputation,
    )?;
    let namespace = PROFILE.artifacts_dir_for_committee(config.committee)?;
    let key = e3_zk_prover::test_utils::load_vk_artifacts(
        &alternate_prover.circuits_dir(CircuitVariant::Recursive, &namespace),
        CircuitName::SkShareComputation,
    )?;
    ensure!(key.key_hash != dealer_inputs[0]["c2_key_hash"].as_str().unwrap());
    let mut changed = recipient_inputs[1].clone();
    for (row, &dealer) in DEALERS.iter().enumerate() {
        let mut input = fixture
            .leaves
            .iter()
            .find(|leaf| {
                leaf.role == CircuitName::SkShareComputation
                    && leaf.inputs["dealer_id"].as_u64() == Some(dealer as u64)
            })
            .unwrap()
            .inputs
            .clone();
        input["guard"] = json!("0");
        let proof = prove_json(
            &alternate_prover,
            CircuitName::SkShareComputation,
            &input,
            "alternate-c2",
        )?;
        ensure!(
            proof.public_signals == get(CircuitName::SkShareComputation, dealer).public_signals
        );
        let mut input = dealer_inputs[row].clone();
        replace_child(&mut input, "c2", &proof)?;
        input["c2_vk"] = json!(key.verification_key);
        input["c2_key_hash"] = json!(key.key_hash);
        let node = prove_json(
            &prover,
            CircuitName::NodeFold,
            &input,
            "alternate-descendants",
        )?;
        let node_public =
            PublicSignals::decode(&config, CircuitName::NodeFold, &node.public_signals)?;
        let original =
            PublicSignals::decode(&config, CircuitName::NodeFold, &nodes[row].public_signals)?;
        ensure!(node_public.tree_hash() != original.tree_hash());
        ensure!(node_public.fields()[4..] == original.fields()[4..]);
        changed["node_proofs"][row] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
            &node.data
        )?);
        changed["node_public"][row] = json!(e3_zk_prover::test_utils::fold_witness_field_strings(
            &node.public_signals
        )?);
    }
    reject_join(setup_path, &changed, "Unanchored DKG descendant VK")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_publication_contract(
    root: &Path,
    bb: &Path,
    directory: &Path,
    prover: &ZkProver,
    config: &Configs,
    context: &SynchronizedProofContext,
    e3: &E3id,
    prepared: &Value,
    proof: &Proof,
    verified: &e3_zk_prover::synchronized::publication::PublicationCommitments,
) -> Result<()> {
    let namespace = PROFILE.artifacts_dir_for_committee(config.committee)?;
    let vk = prover
        .circuits_dir(CircuitVariant::Evm, &namespace)
        .join(CircuitName::DkgAggregator.dir_path())
        .join("dkg_aggregator.vk");
    let c5 = e3_zk_prover::test_utils::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &namespace),
        CircuitName::PkAggregation,
    )?;
    let encode = |field: &[u8; 32]| {
        format!(
            "0x{}",
            field
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    let fixture = directory.join("publication.json");
    fs::write(
        &fixture,
        serde_json::to_vec(&json!({
            "vk": vk,
            "interfold": context.setup.interfold_address.to_string(),
            "crypto_config_id": context.setup.crypto_config_id.to_string(),
            "setup_tree": prepared["expected_tree_hash"],
            "c5_key_hash": c5.key_hash,
            "e3_id": e3.e3_id(),
            "committee": [
                "0x0101010101010101010101010101010101010101",
                "0x0202020202020202020202020202020202020202",
                "0x0303030303030303030303030303030303030303",
            ],
            "dealers": DEALERS,
            "dealer_batch": encode(&verified.dealer_batch()),
            "pk_commitment": encode(&verified.pk_commitment()),
            "sk_commitments": verified.sk_commitments().iter().map(encode).collect::<Vec<_>>(),
            "key_bundles": verified.key_bundles().iter().map(encode).collect::<Vec<_>>(),
            "proof": format!("0x{}", proof.data.iter().map(|byte| format!("{byte:02x}")).collect::<String>()),
            "public_inputs": proof.public_signals.chunks_exact(32)
                .map(|bytes| encode(bytes.try_into().unwrap())).collect::<Vec<_>>(),
        }))?,
    )?;
    // Resolve a selected path before the child changes directory; bare names still use PATH.
    let bb = if bb.parent().is_some_and(|path| !path.as_os_str().is_empty()) {
        bb.canonicalize()?
    } else {
        bb.to_path_buf()
    };
    let mut command = Command::new("pnpm");
    command
        .arg("test:sync-dkg:contract")
        .arg(&fixture)
        .env("E3_CUSTOM_BB", bb)
        .current_dir(root);
    run(&mut command)?;
    Ok(())
}
