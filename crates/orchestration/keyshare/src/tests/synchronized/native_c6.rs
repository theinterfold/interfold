// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::synchronized::{ContributionWorker, LocalContribution};
use e3_task_pool::TaskPool;
use e3_zk_prover::{BBPath, ZkBackend, ZkProver};

fn local_setup(setup: &Setup, owner: usize) -> Result<(SynchronizedSetupIntent, SensitiveBytes)> {
    let DecryptionKeyPlan::Proceed {
        calc_request,
        synchronized: Some(material),
        ..
    } = setup.plan(owner)?
    else {
        anyhow::bail!("missing native DKG plan");
    };
    let verdict = super::super::publication::result(setup, &material, owner)?;
    let intent = SynchronizedSetupIntent::new(
        setup.selected[owner].clone(),
        material,
        TypedEvent::new(verdict, test_ec(30)),
        setup.interfold,
        &setup.cipher,
    )?;
    Ok((
        intent,
        calculate_decryption_key(&setup.cipher, calc_request)?.sk_poly_sum,
    ))
}

fn store(
    setup: &Setup,
    data: &DataStore,
    inputs: &Inputs,
    saved: &SynchronizedSetupIntent,
) -> Result<ContributionStore> {
    let selected = saved.selected();
    let plan = inputs
        .keys
        .synchronized_decryption_definition(
            &selected.e3_id,
            selected.params_profile,
            &inputs.ciphertext,
        )?
        .context("missing plan")?;
    ContributionStore::for_definition(
        &data.repositories(),
        plan,
        &saved.confirmed_setup(setup.interfold, &inputs.keys, &setup.cipher)?,
        setup.signers[selected.party_id as usize].address(),
        &setup.cipher,
    )
}

fn unavailable(dir: &std::path::Path) -> ContributionWorker {
    ContributionWorker {
        pool: TaskPool::new(1, 1),
        task_scope: "owner".into(),
        prover: ZkProver::new(&ZkBackend::new(
            BBPath::Custom(dir.join("absent-bb")),
            dir.join("absent-circuits"),
            dir.join("work"),
        )),
    }
}

#[actix::test]
async fn synchronized_worker_rejects_other_context_and_retains_native_share_on_local_failure(
) -> Result<()> {
    let setup = Setup::new().await?;
    let inputs = inputs(&setup)?;
    let (outside, wrong_sk) = local_setup(&setup, 1)?;
    let data = DataStore::from_in_mem(&InMemStore::new(false).start());
    assert!(store(&setup, &data, &inputs, &outside).is_err());
    let (saved, sk) = local_setup(&setup, 2)?;
    let store = store(&setup, &data, &inputs, &saved)?;
    let dir = tempfile::tempdir()?;
    let worker = unavailable(dir.path());
    let ct = &inputs.ciphertext[0];
    assert!(worker
        .run_definition(&store, &inputs.keys, ct, &sk)
        .await
        .is_err());
    assert!(
        store.resume().await.is_err(),
        "worker created an allocation"
    );
    store.reserve().await?;
    for (bytes, secret) in [(&inputs.alternate, &sk), (ct, &wrong_sk)] {
        assert!(worker
            .run_definition(&store, &inputs.keys, bytes, secret)
            .await
            .is_err());
        assert!(matches!(
            store.resume().await?,
            ContributionProgress::Reserved(_)
        ));
    }
    worker.pool.cancel_group(&e3_task_pool::scoped_task_group(
        &worker.task_scope,
        &saved.selected().e3_id,
    ));
    let error = worker
        .run_definition(&store, &inputs.keys, ct, &sk)
        .await
        .err()
        .context("cancelled E3 ran native work")?;
    assert!(matches!(
        error.downcast_ref::<e3_task_pool::TaskPoolError>(),
        Some(e3_task_pool::TaskPoolError::Cancelled(_))
    ));
    assert!(matches!(
        store.resume().await?,
        ContributionProgress::Reserved(_)
    ));
    let worker = unavailable(dir.path());
    let mut first = None;
    for _ in 0..2 {
        let error = worker
            .run_definition(&store, &inputs.keys, ct, &sk)
            .await
            .err()
            .context("missing local artifacts accepted")?;
        assert!(matches!(
            error.downcast_ref::<e3_zk_prover::ZkError>(),
            Some(e3_zk_prover::ZkError::CircuitNotFound(_))
        ));
        let ContributionProgress::Generated { share, noise } = store.resume().await? else {
            anyhow::bail!("missing native share after local prover failure");
        };
        let pair = (share, noise.coefficients()?);
        if let Some(ref expected) = first {
            assert!(&pair == expected);
        }
        first = Some(pair);
    }
    Ok(())
}

#[actix::test]
#[ignore = "requires pinned nargo and E3_CUSTOM_BB; proves both worker C6s and decrypts with the retained shares"]
async fn synchronized_native_worker_real_c6_and_signed_reuse() -> Result<()> {
    use fhe::trbfv::{DecryptionShare, SynchronizedDecryptor};
    use fhe_traits::FheDecoder;
    let _exclusive = super::super::recovery::DISK_RECOVERY.lock().await;
    let (dir, prover) = real_prover(&[CircuitName::ThresholdShareDecryption])?;
    let setup = Setup::new().await?;
    let inputs = inputs(&setup)?;
    let ct_bytes = &inputs.ciphertext[0];
    let params = &setup.config.threshold;
    let ct = Ciphertext::from_bytes(ct_bytes, params)?;
    let mut parts = Vec::new();
    let (bus, _) = test_bus();
    for owner in [0, 2] {
        let disk = dir.path().join(format!("checkpoint-{owner}"));
        let reopen =
            || -> Result<_> { Ok(DataStore::from_sled_store(&SledStore::new(&bus, &disk)?)) };
        let data = reopen()?;
        let (saved, sk) = local_setup(&setup, owner)?;
        let open = |data: &DataStore| store(&setup, data, &inputs, &saved);
        let initial = open(&data)?;
        initial.reserve().await?;
        let mut worker = unavailable(dir.path());
        assert!(worker
            .run_definition(&initial, &inputs.keys, ct_bytes, &sk)
            .await
            .is_err());
        let ContributionProgress::Generated {
            share: checkpoint, ..
        } = initial.resume().await?
        else {
            anyhow::bail!("share was not flushed before prover I/O")
        };
        drop(initial);
        data.shutdown().await?;
        drop(data);
        SledDb::close_all_connections();
        let data = reopen()?;
        let store = open(&data)?;
        worker.prover = prover.clone();
        if owner == 0 {
            let role = CircuitName::ThresholdShareDecryption;
            let pin = prover
                .circuits_dir(
                    e3_zk_config::CircuitVariant::Recursive,
                    &PROFILE.artifacts_dir_for_committee(COMMITTEE)?,
                )
                .join(role.dir_path())
                .join(format!("{}.vk_hash", role.as_str()));
            let installed = std::fs::read(&pin)?;
            std::fs::write(&pin, [0x02; 32])?;
            let error = worker
                .run_definition(&store, &inputs.keys, ct_bytes, &sk)
                .await
                .err()
                .context("proved with mismatched child VK")?;
            assert!(
                error.to_string().contains("qualified request pin"),
                "{error:#}"
            );
            std::fs::write(pin, installed)?;
        }
        let LocalContribution::ReadyToSign { share, mut proof } = worker
            .run_definition(&store, &inputs.keys, ct_bytes, &sk)
            .await?
        else {
            anyhow::bail!("unexpected signed result")
        };
        assert_eq!(share, checkpoint);
        let row = PublicSignals::decode(
            &setup.config,
            CircuitName::ThresholdShareDecryption,
            &proof.public_signals,
        )?;
        let plan = inputs
            .keys
            .synchronized_decryption_definition(
                &saved.selected().e3_id,
                PROFILE,
                &inputs.ciphertext,
            )?
            .unwrap();
        assert!(plan.matches_c6(owner as u32, &row));
        let poly = e3_trbfv::helpers::try_poly_pb_from_bytes(&share, params)?;
        assert_eq!(
            row.decryption_share_commitment(),
            Some(commitment_field(
                &e3_zk_witness::compute_threshold_decryption_share_commitment(
                    &CrtPolynomial::from_fhe_polynomial(&poly),
                    setup.config.share_bit,
                    params.degree()
                )
            )?)
        );
        parts.push(DecryptionShare::from_parts(
            poly,
            owner + 1,
            vec![1, 3],
            &ct,
        )?);

        if owner == 0 {
            // A valid owner signature and exact statement do not make an invalid proof reusable.
            let mut bad = proof.data.to_vec();
            bad[31] ^= 1;
            proof.data = ArcBytes::from_bytes(&bad);
        }
        let bundle = DecryptionshareCreated {
            e3_id: saved.selected().e3_id.clone(),
            party_id: owner as u64,
            node: saved.selected().committee[owner].clone(),
            decryption_share: vec![share],
            signed_decryption_proofs: vec![SignedProofPayload::sign(
                ProofPayload {
                    e3_id: saved.selected().e3_id.clone(),
                    proof_type: ProofType::C6ThresholdShareDecryption,
                    proof,
                },
                &setup.signers[owner],
            )?],
        };
        store.record_signed(&bundle).await?;
        // Both signed checkpoints must reach verification using only the VK, without re-proving.
        let circuit = CircuitName::ThresholdShareDecryption;
        let bytecode = prover
            .circuits_dir(
                e3_zk_config::CircuitVariant::Recursive,
                &PROFILE.artifacts_dir_for_committee(COMMITTEE)?,
            )
            .join(circuit.dir_path())
            .join(format!("{}.json", circuit.as_str()));
        let hidden = bytecode.with_extension("disabled");
        std::fs::rename(&bytecode, &hidden)?;
        let cached = worker
            .run_definition(&store, &inputs.keys, ct_bytes, &sk)
            .await;
        std::fs::rename(hidden, bytecode)?;
        if owner == 0 {
            let error = cached.err().context("tampered signed C6 proof accepted")?;
            assert_eq!(
                error.to_string(),
                "local C6 proof failed verification",
                "{error:#}"
            );
        } else {
            assert!(matches!(cached?, LocalContribution::Signed(saved) if saved == bundle));
            inputs.keys.retire_synchronized_output(&bundle.e3_id);
            assert!(worker
                .run_definition(&store, &inputs.keys, ct_bytes, &sk)
                .await
                .is_err());
        }
        drop(store);
        data.shutdown().await?;
        drop(data);
        SledDb::close_all_connections();
    }
    let plaintext =
        SynchronizedDecryptor::new(3, 1, params.clone())?.decrypt_from_shares(&parts, &ct)?;
    let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly())?;
    assert_eq!(decoded[0], 1);
    assert!(decoded[1..].iter().all(|&x| x == 0));
    Ok(())
}
