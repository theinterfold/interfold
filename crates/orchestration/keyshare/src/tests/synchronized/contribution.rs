// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::synchronized::{ContributionProgress, ContributionStore, SynchronizedSetupIntent};
use e3_committee_hash::decryption_domain_limbs;
use e3_data::{SledDb, SledStore};
use e3_events::{DecryptionshareCreated, SynchronizedDkgContext};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::{
    CanonicalDkgAnchors, CanonicalPublicKey, CanonicalPublicKeys, SynchronizedDkgAuthority,
};

// Fail exactly when the target checkpoint is visible, so the test hits the gap between
// insertion and durability rather than an earlier predecessor reflush.
struct RefuseCheckpointFlush(DataStore);
impl Actor for RefuseCheckpointFlush {
    type Context = actix::Context<Self>;
}
impl Handler<e3_events::Flush> for RefuseCheckpointFlush {
    type Result = actix::ResponseFuture<Result<()>>;
    fn handle(&mut self, _: e3_events::Flush, _: &mut Self::Context) -> Self::Result {
        let target = self.0.clone();
        Box::pin(async move {
            ensure!(
                target.read_checked::<SensitiveBytes>().await?.is_none(),
                "checkpoint flush refused"
            );
            target.flush_sync().await
        })
    }
}

struct Inputs {
    keys: CanonicalPublicKeys,
    saved: SynchronizedSetupIntent,
    ciphertext: [ArcBytes; 1],
    alternate: ArcBytes,
    bundle: DecryptionshareCreated,
    wrong_row: DecryptionshareCreated,
}

// Real native DKG openings and signer; synthetic C6 body. Proof verification belongs to the worker.
fn inputs(setup: &Setup) -> Result<Inputs> {
    let owner = 2;
    let selected = &setup.selected[owner];
    let id = &selected.e3_id;
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(material),
        ..
    } = setup.plan(owner)?
    else {
        unreachable!()
    };
    let verdict = super::publication::result(setup, &material, owner)?;
    let a = &verdict.setup;
    let pk = material.publication_key(selected, a)?.to_bytes();
    let params = &setup.config.threshold;
    let context = SynchronizedDkgContext {
        registry: Address::repeat_byte(1),
        verifying_contract: Address::repeat_byte(2),
        crypto_config_id: selected.crypto_config_id,
    };
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(id.clone(), context)?;
    let committee: Vec<_> = setup.signers.iter().map(|s| s.address()).collect();
    let DecryptionKeyPlan::Proceed {
        synchronized: Some(other_material),
        ..
    } = setup.plan(0)?
    else {
        unreachable!()
    };
    let key = CanonicalPublicKey {
        pk_commitment: e3_bfv_client::compute_pk_commitment(
            pk.clone(),
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )?,
        honest_committee: vec![committee[0], committee[2]],
        committee,
        params_profile: PROFILE,
        committee_size: COMMITTEE,
        interfold_address: setup.interfold,
        dkg_anchors: CanonicalDkgAnchors::Synchronized(SynchronizedDkgAuthority {
            version: 1,
            context,
            setup_binding: [a.binding[0].to_be_bytes(), a.binding[1].to_be_bytes()]
                .concat()
                .try_into()
                .unwrap(),
            dealer_batch: a.dealer_batch,
            party_ids: a.dealers.clone(),
            threshold_pk_commits: a.threshold_keys.clone(),
            sk_agg_commits: vec![other_material.sk_commitment.unwrap(), a.sk_commitment],
            key_bundle_commits: vec![other_material.key_bundle.unwrap(), a.key_bundle],
        }),
    };
    keys.insert_synchronized_dkg_authority(id.clone(), key.clone())?;
    keys.remember_dkg_key(id, ArcBytes::from_bytes(&pk))?;
    let ct = e3_bfv_client::bfv_encrypt(
        vec![1u64],
        pk,
        params.degree(),
        params.plaintext(),
        params.moduli(),
    )?;
    let hash = keccak256(&ct);
    let commitment = e3_bfv_client::compute_ct_commitment_with_params(&ct, params)?;
    keys.remember_synchronized_output(id, hash, commitment)?;
    keys.remember_synchronized_ciphertext_ready(id);
    let bytes = [ArcBytes::from_bytes(&ct)];
    let domain = decryption_domain_limbs(
        id.chain_id(),
        id.clone().try_into()?,
        key.domain(setup.interfold),
        hash,
    );
    let native = Ciphertext::from_bytes(&ct, params)?;
    let poly = native[1].clone().into_power_basis();
    let share = ArcBytes::from_bytes(&poly.to_bytes());
    let share_hash = e3_zk_witness::compute_threshold_decryption_share_commitment(
        &CrtPolynomial::from_fhe_polynomial(&poly),
        setup.config.share_bit,
        params.degree(),
    );
    let fields = vec![
        scalar(a.binding[0])?,
        scalar(a.binding[1])?,
        scalar(owner)?,
        scalar(0)?,
        scalar(2)?,
        scalar(domain.hi)?,
        scalar(domain.lo)?,
        a.sk_commitment,
        a.key_bundle,
        commitment,
        scalar(share_hash)?,
        e3_bfv_client::client::validate_synchronized_ciphertext(&ct, params, commitment)?,
    ];
    let signed_bundle = DecryptionshareCreated {
        e3_id: id.clone(),
        party_id: owner as u64,
        node: selected.committee[owner].clone(),
        decryption_share: vec![share.clone()],
        signed_decryption_proofs: vec![signed(
            setup,
            owner,
            ProofType::C6ThresholdShareDecryption,
            fields.clone(),
        )?],
    };
    let saved = SynchronizedSetupIntent::new(
        selected.clone(),
        material,
        TypedEvent::new(verdict, test_ec(30)),
        setup.interfold,
        &setup.cipher,
    )?;
    let mut wrong = fields;
    wrong[9] = scalar(3)?;
    let mut wrong_row = signed_bundle.clone();
    wrong_row.signed_decryption_proofs = vec![signed(
        setup,
        owner,
        ProofType::C6ThresholdShareDecryption,
        wrong,
    )?];
    Ok(Inputs {
        keys,
        saved,
        ciphertext: bytes,
        alternate: ArcBytes::from_bytes(&native[0].clone().into_power_basis().to_bytes()),
        bundle: signed_bundle,
        wrong_row,
    })
}

#[actix::test]
async fn synchronized_contribution_reopens_each_flushed_phase_and_rejects_resampling() -> Result<()>
{
    let _exclusive = super::recovery::DISK_RECOVERY.lock().await;
    let setup = Setup::new().await?;
    let Inputs {
        keys,
        saved,
        ciphertext,
        alternate,
        bundle: signed_bundle,
        wrong_row,
    } = inputs(&setup)?;
    let id = &signed_bundle.e3_id;
    let plan = || {
        keys.synchronized_decryption_definition(id, PROFILE, &ciphertext)?
            .context("missing plan")
    };
    let signer = setup.signers[signed_bundle.party_id as usize].address();
    let share = signed_bundle.decryption_share[0].clone();
    let confirmed = saved.confirmed_setup(setup.interfold, &keys, &setup.cipher)?;
    let open = |data: &DataStore| {
        ContributionStore::for_definition(
            &data.repositories(),
            plan()?,
            &confirmed,
            signer,
            &setup.cipher,
        )
    };

    let memory = InMemStore::new(false).start();
    let data = DataStore::from_in_mem(&memory);
    let root = data
        .repositories()
        .threshold_keyshare_recovery_payloads(id)
        .scope("synchronized-contribution-v1");
    let live = crate::synchronized::LiveReservation::default();
    keys.remember_synchronized_opening(id, &ciphertext, &test_ec(42), true)?;
    // A local read error before insertion cannot justify a new seed or a second authorization.
    root.scope("share").write_sync(0xffu8).await?;
    assert!(live
        .reserve_if_authorized(&open(&data)?, &keys, true)
        .await
        .is_err());
    assert!(root
        .scope("allocation")
        .read_checked::<SensitiveBytes>()
        .await?
        .is_none());
    root.scope("share").remove_sync().await?;
    let replacement = crate::synchronized::LiveReservation::default();
    replacement
        .reserve_if_authorized(&open(&data)?, &keys, true)
        .await?;
    assert!(open(&data)?.resume().await.is_err());
    let broken = DataStore::from_in_mem(&memory).with_flush_recipient(
        FailFirstFlush {
            store: memory.clone(),
            failed: false,
        }
        .start()
        .recipient(),
    );
    let fenced = open(&broken)?;
    assert!(fenced.resume().await.is_err());
    assert!(live
        .reserve_if_authorized(&fenced, &keys, true)
        .await
        .is_err());
    live.reserve_if_authorized(&fenced, &keys, true).await?;
    let ContributionProgress::Reserved(retry) = fenced.resume().await? else {
        panic!()
    };
    let ContributionProgress::Reserved(again) = open(&broken)?.reserve().await? else {
        panic!()
    };
    assert!(retry.coefficients()? == again.coefficients()?);
    let memory = DataStore::from_in_mem(&memory);
    let refuse = |slot| {
        memory
            .clone()
            .with_flush_recipient(RefuseCheckpointFlush(root.scope(slot)).start().recipient())
    };
    let share_failure = open(&refuse("share"))?;
    assert!(share_failure.record_generated(&share).await.is_err());
    assert!(share_failure.resume().await.is_err());
    assert!(matches!(
        open(&memory)?.resume().await?,
        ContributionProgress::Generated { .. }
    ));
    let signature_failure = open(&refuse("signed"))?;
    assert!(signature_failure
        .record_signed(&signed_bundle)
        .await
        .is_err());
    assert!(signature_failure.resume().await.is_err());
    assert!(
        matches!(open(&memory)?.resume().await?, ContributionProgress::Signed(value) if value == signed_bundle)
    );
    let selected = &setup.selected[signed_bundle.party_id as usize];
    let (node, _, _) = super::publication::actor(
        &memory,
        ThresholdKeyshareRecoveryState {
            ciphernode_selected: Some(TypedEvent::new(selected.clone(), test_ec(1))),
            ..Default::default()
        },
        setup.signers[signed_bundle.party_id as usize].clone(),
        setup.cipher.clone(),
        setup.interfold,
        keys.clone(),
    )
    .await?;
    node.send(keyshare_event(
        E3RequestComplete { e3_id: id.clone() },
        50,
        EventSource::Evm,
    ))
    .await?;
    assert!(node.send(Die).await.is_err());
    for slot in ["allocation", "share", "signed"] {
        assert!(
            root.scope(slot)
                .read_checked::<SensitiveBytes>()
                .await?
                .is_none(),
            "{slot} survived terminal cleanup"
        );
    }
    live.reserve_if_authorized(&fenced, &keys, true).await?;
    assert!(fenced.resume().await.is_err());

    let dir = tempfile::tempdir()?;
    let (bus, _) = test_bus();
    let mut first = None;
    for phase in 0..4 {
        let data = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
        let store = open(&data)?;
        assert!(ContributionStore::for_definition(
            &data.repositories(),
            plan()?,
            &confirmed,
            setup.signers[1].address(),
            &setup.cipher
        )
        .is_err());
        let progress = if phase == 0 {
            store.reserve().await?
        } else {
            store.resume().await?
        };
        match (phase, progress) {
            (0, ContributionProgress::Reserved(noise)) => {
                let coefficients = noise.coefficients()?;
                assert_eq!(coefficients.len(), setup.config.threshold.degree());
                assert!(coefficients
                    .iter()
                    .all(|x| x.magnitude() <= &setup.config.pk_generation.bounds.e_sm_bound));
                first = Some(coefficients);
                assert!(store.record_signed(&signed_bundle).await.is_err());
            }
            (1, ContributionProgress::Reserved(noise)) => {
                assert!(Some(noise.coefficients()?) == first);
                store.record_generated(&share).await?;
            }
            (
                2,
                ContributionProgress::Generated {
                    noise,
                    share: recovered,
                },
            ) => {
                assert!(Some(noise.coefficients()?) == first);
                assert_eq!(recovered, share);
                assert!(store.record_generated(&alternate).await.is_err());
                assert!(store.record_signed(&wrong_row).await.is_err());
                store.record_signed(&signed_bundle).await?;
            }
            (3, ContributionProgress::Signed(bundle)) => {
                assert_eq!(bundle, signed_bundle);
                store.record_signed(&bundle).await?;
                let scope = data
                    .repositories()
                    .threshold_keyshare_recovery_payloads(id)
                    .scope("synchronized-contribution-v1");
                scope.scope("allocation").remove_sync().await?;
                assert!(store.resume().await.is_err());
                assert!(store.reserve().await.is_err());
                assert!(scope
                    .scope("allocation")
                    .read_checked::<SensitiveBytes>()
                    .await?
                    .is_none());
            }
            _ => anyhow::bail!("wrong contribution after reopen at phase {phase}"),
        }
        drop(store);
        data.shutdown().await?;
        drop(data);
        SledDb::close_all_connections();
    }
    Ok(())
}

#[path = "native_c6.rs"]
mod native_c6;
