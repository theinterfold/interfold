// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::Result;
use e3_committee::CiphernodesCommitteeSize;
use e3_data::RepositoriesFactory;
use e3_event_system::EventSystem;
use e3_events::{
    AggregateConfig, AggregateId, E3Requested, E3id, EventPublisher, FlushPendingSnapshots,
    GetEvents, InterfoldEvent, Seed,
};
use e3_fhe_params::{encode_bfv_params, BfvProfile};
use e3_request::{
    ContextRepositoryFactory, E3Meta, E3Router, MetaRepositoryFactory, RouterRepositoryFactory,
};
use e3_utils::ArcBytes;
use std::{collections::HashMap, time::Duration};

#[test]
fn request_configuration_survives_disk_restart_and_rejects_a_changed_id() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let profile = BfvProfile::SsSecure8192;
    let committee = CiphernodesCommitteeSize::Micro;
    let shape = committee.values();
    let (params, _) = profile.build_pair()?;
    let request = E3Requested {
        e3_id: E3id::new("7", 31_337),
        threshold_m: shape.threshold,
        threshold_n: shape.n,
        seed: Seed([7; 32]),
        params_profile: profile,
        crypto_config_id: profile.crypto_config_id(committee)?.into(),
        params: ArcBytes::from_bytes(&encode_bfv_params(&params)),
        ..Default::default()
    };

    for boot in 0..3 {
        let root = directory.path().to_owned();
        let request = request.clone();
        // Each runtime closes every actor and store handle before the next boot.
        std::thread::spawn(move || {
            actix::System::new().block_on(async move {
                let config = AggregateConfig::new(HashMap::from([(
                    AggregateId::new(31_337),
                    Duration::ZERO,
                )]));
                let system = EventSystem::persisted(root.join("log"), root.join("sled"))
                    .with_fresh_bus()
                    .with_aggregate_config(config.clone());
                let bus = system.handle()?.enable("request-profile-restart");
                let store = system.store()?;
                let repositories = store.repositories();
                e3_sync::preflight_schema_version(
                    &repositories,
                    &config,
                    &system.eventstore_reader()?.seq(),
                )
                .await?;
                let metadata = repositories
                    .router()
                    .repositories()
                    .context(&request.e3_id)
                    .repositories()
                    .meta(&request.e3_id);
                let history = bus.history();
                let recovered = E3Router::builder(&bus, store.clone()).build().await;
                let mut expected = E3Meta::from(&request);
                if boot == 2 {
                    recovered.expect_err("changed configuration ID must fail disk recovery");
                    expected.crypto_config_id = [42; 32];
                    assert_eq!(metadata.read().await?, Some(expected));
                } else {
                    let _router = recovered?;
                    if boot == 0 {
                        bus.publish_without_context(request.clone())?;
                    }
                    bus.flush_event_pipeline().await?;
                    system.buffer()?.send(FlushPendingSnapshots).await??;
                    assert_eq!(metadata.read().await?, Some(expected.clone()));
                    if boot == 1 {
                        expected.crypto_config_id = [42; 32];
                        metadata.write_sync(&expected).await?;
                    }
                }
                if boot > 0 {
                    assert!(
                        history
                            .send(GetEvents::<InterfoldEvent>::new())
                            .await?
                            .is_empty(),
                        "recovery manufactured a protocol event"
                    );
                }
                let checkpoint = repositories
                    .request_router_checkpoint()
                    .read()
                    .await?
                    .unwrap();
                assert_eq!(checkpoint.contexts, vec![request.e3_id]);
                store.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            })
        })
        .join()
        .expect("restart runtime panicked")?;
    }
    Ok(())
}
