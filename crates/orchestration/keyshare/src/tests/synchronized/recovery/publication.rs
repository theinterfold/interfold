// SPDX-License-Identifier: LGPL-3.0-only

//! Join the real proofs and sealed material recovered by the actor fixture, not another native
//! sample. This remains below disabled hydration/worker/publication admission.

use super::*;
use e3_events::{
    SynchronizedDkgProofJob, SynchronizedDkgProofRequest, SynchronizedDkgProofResponse,
    SynchronizedPublicationExpectation, SynchronizedSetupAnchors,
};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::CircuitVariant;
use e3_zk_prover::synchronized::execution::execute_definition;
use e3_zk_prover::synchronized::{provenance::*, publication::*};
use e3_zk_witness::{
    synchronized::provenance::{dealer_batch, Child},
    threshold::pk_aggregation::PkAggregationCircuitData,
};
use fhe::mbfv::{Aggregate as _, PublicKeyShare};
use serde_json::json;
use std::{fs, process::Command};

pub(super) type Recovered = (ThresholdKeyshareRecoveryState, crate::ReadyForDecryption);

fn authenticated(
    selected: &CiphernodeSelected,
    owner: u32,
    kind: ProofType,
    signed: &SignedProofPayload,
) -> Result<Proof> {
    ensure!(signed.payload.e3_id == selected.e3_id && signed.payload.proof_type == kind);
    ensure!(signed.payload.proof.circuit == kind.circuit_names()[0]);
    ensure!(signed.verify_address(&selected.committee[owner as usize].parse::<Address>()?)?);
    Ok(signed.payload.proof.clone())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    format!(
        "0x{}",
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

pub(super) async fn qualify(
    recovered: &[Recovered],
    local_c4: &[DecryptionKeyShared],
    prover: &ZkProver,
    directory: &Path,
    chain: &super::chain::Chain,
    signers: &[PrivateKeySigner],
) -> Result<()> {
    let selected = recovered[0]
        .0
        .ciphernode_selected
        .as_ref()
        .context("lost selection")?;
    let config = Configs::for_profile(selected.params_profile, COMMITTEE)?;
    let context = proof_context(selected, chain.controller)?;
    let e3 = &selected.e3_id;
    let binding = setup_binding(&context, e3)?;
    let ids: Vec<_> = DEALERS.iter().map(|&id| id as u32).collect();
    let roster = recovered[0]
        .0
        .dkg_roster
        .as_ref()
        .context("lost accepted roster")?;
    ensure!(roster.e3_id == *e3 && roster.interfold_address == chain.controller);
    ensure!(
        roster.kind == DkgCoordinationKind::Roster && roster.has_canonical_dealers(recovered.len())
    );
    ensure!(
        roster.recover_address()?
            == selected.committee[roster.party_id as usize].parse::<Address>()?
    );
    let contributions = ids
        .iter()
        .map(|&id| {
            let state = &recovered[id as usize].1;
            crate::domain::dealer_identity_for_profile(
                PROFILE,
                e3,
                id as u64,
                &state.pk_share,
                state
                    .signed_sk_share_computation_proof
                    .as_ref()
                    .context("lost C2")?,
                None,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(roster.dealers == contributions);
    let namespace = PROFILE.artifacts_dir_for_committee(COMMITTEE)?;
    let mut c0 = Vec::new();
    let mut c2 = Vec::new();
    let mut c4 = Vec::new();
    let mut material = Vec::new();
    let mut shares = Vec::new();
    let crp = create_deterministic_crp_from_default_seed(&config.threshold);
    for (owner, (root, state)) in recovered.iter().enumerate() {
        let selection = root
            .ciphernode_selected
            .as_ref()
            .context("lost selection")?;
        ensure!(selection.committee == selected.committee && selection.e3_id == *e3);
        ensure!(root.dkg_roster.as_ref() == Some(roster));
        let saved = root.synchronized.as_ref().context("lost sealed material")?;
        ensure!(saved.context == proof_context(selection, chain.controller)?);
        let key = root.encryption_keys[&(owner as u64)]
            .key
            .signed_payload
            .as_ref()
            .context("lost C0")?;
        c0.push(authenticated(
            selection,
            owner as u32,
            ProofType::C0PkBfv,
            key,
        )?);
        c2.push(authenticated(
            selection,
            owner as u32,
            ProofType::C2aSkShareComputation,
            state
                .signed_sk_share_computation_proof
                .as_ref()
                .context("lost C2")?,
        )?);
        // Selected C4 artifacts come from peers' reopened snapshots. The outside-H C4 was
        // produced from its disk-restored request and has no publication slot in the H-roster.
        let persisted = recovered
            .iter()
            .find_map(|(root, _)| root.decryption_key_shares.get(&(owner as u64)));
        ensure!(!DEALERS.contains(&(owner as u64)) || persisted.is_some());
        let message = persisted
            .map(|message| &**message)
            .unwrap_or(&local_c4[owner]);
        crate::synchronized::validate_c4_message(
            selection,
            chain.controller,
            message,
            Some(&DEALERS.into()),
            Some(saved),
        )?;
        c4.push(message.signed_sk_decryption_proof.payload.proof.clone());
        shares.push(PublicKeyShare::deserialize(
            &state.pk_share,
            &config.threshold,
            crp.clone(),
        )?);
        material.push(saved);
    }
    // Check pair agreement using only the newly opened stores/ciphers, not the original setup.
    let mut outgoing = Vec::new();
    for (owner, saved) in material.iter().enumerate() {
        outgoing.push(saved.outgoing_keys.open(
            PROFILE,
            binding,
            owner as u32,
            3,
            &*cipher(owner).await?,
        )?);
    }
    for (owner, saved) in material.iter().enumerate() {
        let incoming = saved
            .incoming_keys
            .as_ref()
            .context("lost incoming keys")?
            .open(
                PROFILE,
                binding,
                owner as u32,
                ids.len(),
                &*cipher(owner).await?,
            )?;
        for (row, &dealer) in ids.iter().enumerate() {
            ensure!(
                incoming[row].as_bytes() == outgoing[dealer as usize][owner].as_bytes(),
                "reopened directed keys disagree for dealer {dealer}, recipient {owner}"
            );
        }
    }
    let mut nodes = Vec::new();
    for &id in &ids {
        let (root, state) = &recovered[id as usize];
        let selection = root.ciphernode_selected.as_ref().unwrap();
        let c1 = authenticated(
            selection,
            id,
            ProofType::C1PkGeneration,
            state
                .signed_pk_generation_proof
                .as_ref()
                .context("lost C1")?,
        )?;
        let c3 = state
            .signed_sk_share_encryption_proofs
            .iter()
            .map(|proof| authenticated(selection, id, ProofType::C3aSkShareEncryption, proof))
            .collect::<Result<Vec<_>>>()?;
        let local = material[id as usize].context.clone();
        let request = SynchronizedDkgProofRequest {
            params_profile: PROFILE,
            committee_size: COMMITTEE,
            context: local,
            job: SynchronizedDkgProofJob::Dealer {
                c1,
                c2: c2[id as usize].clone(),
                c3,
            },
        };
        let SynchronizedDkgProofResponse::Dealer { proof } =
            execute_definition(prover, e3, &request, &format!("restored-dealer-{id}"))?
        else {
            anyhow::bail!("wrong synchronized dealer response");
        };
        ensure!(prover.verify_fold_proof(&proof, "restored-dealer", id as u64, &namespace)?);
        nodes.push(proof);
    }
    let batch = dealer_batch(
        &config,
        binding,
        &ids,
        &nodes
            .iter()
            .map(|proof| Child {
                circuit: proof.circuit,
                proof: &proof.data,
                public_signals: &proof.public_signals,
            })
            .collect::<Vec<_>>(),
    )?;
    let selected_shares: Vec<_> = ids.iter().map(|&id| shares[id as usize].clone()).collect();
    let public_key = PublicKey::from_shares(selected_shares.clone())?;
    let data = PkAggregationCircuitData {
        public_key: public_key.clone(),
        pk0_shares: selected_shares
            .iter()
            .map(|share| CrtPolynomial::from_fhe_polynomial(share.p0_share()))
            .collect(),
    };
    let native = prepare_c5(&config, &data)?;
    let keys = native
        .expected_threshold_pk_commitments
        .iter()
        .map(commitment_field)
        .collect::<Result<Vec<_>>>()?;
    let sk = material
        .iter()
        .map(|saved| saved.sk_commitment.context("lost SK"))
        .collect::<Result<Vec<_>>>()?;
    let bundles = material
        .iter()
        .map(|saved| saved.key_bundle.context("lost bundle"))
        .collect::<Result<Vec<_>>>()?;
    let mut recipients = Vec::new();
    let mut setups = Vec::new();
    for owner in 0..recovered.len() {
        let request = SynchronizedDkgProofRequest {
            params_profile: PROFILE,
            committee_size: COMMITTEE,
            context: material[owner].context.clone(),
            job: SynchronizedDkgProofJob::Recipient {
                c0: c0[owner].clone(),
                own_c2: c2[owner].clone(),
                c4: c4[owner].clone(),
                dealers: nodes.clone(),
                expected: SynchronizedSetupAnchors {
                    binding,
                    recipient: owner as u32,
                    dealers: ids.clone(),
                    threshold_keys: keys.clone(),
                    dealer_batch: batch,
                    sk_commitment: sk[owner],
                    key_bundle: bundles[owner],
                },
            },
        };
        // Exercise the typed local request contract without enabling the production profile gate.
        let request = bincode::deserialize(&bincode::serialize(&request)?)?;
        let SynchronizedDkgProofResponse::Recipient {
            proof,
            setup: result,
        } = execute_definition(prover, e3, &request, &format!("restored-recipient-{owner}"))?
        else {
            anyhow::bail!("wrong synchronized recipient response");
        };
        let setup = verify_recipient(
            prover,
            &config,
            &material[owner].context,
            e3,
            &ExpectedSetup {
                dealers: &ids,
                threshold_keys: &keys,
                dealer_batch: batch,
                sk_commitment: sk[owner],
                key_bundle: bundles[owner],
            },
            &proof,
            "restored-recipient",
        )?
        .context("recovered recipient setup rejected")?;
        ensure!(result == SynchronizedSetupAnchors::from(&setup));
        setups.push(result);
        recipients.push(proof);
    }
    let c5 = prove_c5(prover, &config, &data, "restored-c5")?;
    ensure!(prover.verify_fold_proof(&c5, "restored-c5", 0, &namespace)?);
    let selected_recipients: Vec<_> = ids
        .iter()
        .map(|&id| recipients[id as usize].clone())
        .collect();
    let join = PublicationJoin {
        dealers: &ids,
        recipients: &selected_recipients,
        c5: &c5,
    };
    let prepared = prepare_publication(prover, &config, &context, e3, &join)?;
    let selected_sk: Vec<_> = ids.iter().map(|&id| sk[id as usize]).collect();
    let selected_bundles: Vec<_> = ids.iter().map(|&id| bundles[id as usize]).collect();
    let request = SynchronizedDkgProofRequest {
        params_profile: PROFILE,
        committee_size: COMMITTEE,
        context: context.clone(),
        job: SynchronizedDkgProofJob::Publication {
            recipients: selected_recipients,
            c5,
            expected: SynchronizedPublicationExpectation {
                dealers: ids.clone(),
                threshold_keys: keys.clone(),
                dealer_batch: batch,
                sk_commitments: selected_sk.clone(),
                key_bundles: selected_bundles.clone(),
                public_key: ArcBytes::from_bytes(&public_key.to_bytes()),
            },
        },
    };
    let SynchronizedDkgProofResponse::Publication { proof: publication } =
        execute_definition(prover, e3, &request, "restored-publication")?
    else {
        anyhow::bail!("wrong synchronized publication response");
    };
    let verified = verify_publication(
        prover,
        &config,
        &context,
        e3,
        &ExpectedPublication {
            dealers: &ids,
            threshold_keys: &keys,
            dealer_batch: batch,
            sk_commitments: &selected_sk,
            key_bundles: &selected_bundles,
            public_key: &public_key,
        },
        &publication,
        "restored-publication",
    )?
    .context("restored publication rejected")?;
    ensure!(verified.binding() == binding && verified.dealers() == ids);
    ensure!(verified.sk_commitments() == selected_sk && verified.key_bundles() == selected_bundles);
    ensure!(verify_recipient(
        prover,
        &config,
        &material[1].context,
        e3,
        &ExpectedSetup {
            dealers: verified.dealers(),
            threshold_keys: verified.threshold_keys(),
            dealer_batch: verified.dealer_batch(),
            sk_commitment: sk[1],
            key_bundle: bundles[1],
        },
        &recipients[1],
        "restored-outside-h-handoff"
    )?
    .is_some());
    let public = PublicSignals::decode(
        &config,
        CircuitName::DkgAggregator,
        &publication.public_signals,
    )?;
    let fixture = directory.join("publication.json");
    fs::write(
        &fixture,
        serde_json::to_vec(&json!({
            "vk": prover.circuits_dir(CircuitVariant::Evm, &namespace)
                .join(CircuitName::DkgAggregator.dir_path()).join("dkg_aggregator.vk"),
            "interfold": context.setup.interfold_address.to_string(),
            "crypto_config_id": context.setup.crypto_config_id.to_string(),
            "setup_tree": prepared["expected_tree_hash"],
            "c5_key_hash": prepared["c5_key_hash"],
            "e3_id": e3.e3_id(), "committee": selected.committee, "dealers": ids,
            "dealer_batch": hex(verified.dealer_batch()), "pk_commitment": hex(verified.pk_commitment()),
            "sk_commitments": selected_sk.iter().map(hex).collect::<Vec<_>>(),
            "key_bundles": selected_bundles.iter().map(hex).collect::<Vec<_>>(),
            "proof": hex(&*publication.data),
            "public_inputs": public.fields().iter().map(hex).collect::<Vec<_>>(),
        }))?,
    )?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    // Use the same executable as native proving, resolved before the child changes directory.
    let bb = prover.bb_binary();
    let bb = if bb.parent().is_some_and(|path| !path.as_os_str().is_empty()) {
        bb.canonicalize()?
    } else {
        bb.to_path_buf()
    };
    let mut command = Command::new("pnpm");
    command
        .arg("test:sync-dkg:contract")
        .arg(fixture)
        .env("E3_CUSTOM_BB", bb)
        .current_dir(root);
    let output = run(&mut command)?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    chain
        .qualify(
            recovered,
            &setups,
            &public_key,
            &publication,
            directory,
            signers,
        )
        .await?;
    Ok(())
}
