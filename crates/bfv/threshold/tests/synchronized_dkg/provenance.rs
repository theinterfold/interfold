// SPDX-License-Identifier: LGPL-3.0-only

//! Real native contributions and independently verified mismatched children. Temporary artifacts
//! exercise the production preparation/prover API; no runtime admission, release stamp or C5.

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
    if matches!(role, CircuitName::NodeFold | CircuitName::NodesFold) {
        CircuitVariant::Default
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
#[ignore = "requires pinned nargo/bb; real sync DKG joins, not C5/contract/runtime admission"]
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
            committee_hash: [0x22; 32].into(),
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
        for field in 0..3 {
            let mut expected = expected;
            let mut keys = threshold_keys.clone();
            match field {
                0 => {
                    keys[1][31] ^= 1;
                    expected.threshold_keys = &keys;
                }
                1 => expected.sk_commitment[31] ^= 1,
                _ => expected.key_bundle[31] ^= 1,
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
