// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn schema_six_logs_remain_readable_but_cannot_start_schema_seven() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    let repositories = Repositories::from(&store);
    repositories.schema_version().write_sync(&6_u32).await?;
    let bus = system.handle()?.enable("schema-six-history");
    bus.publish_without_context(e3_events::OperatorActivationChanged {
        operator: "0xaaa".into(),
        active: true,
        chain_id: 1,
    })?;
    bus.publish_without_context(e3_events::BondOwnerSet {
        operator: "0xaaa".into(),
        bond_owner: "0xbbb".into(),
        chain_id: 1,
    })?;
    bus.flush_event_pipeline().await?;
    let eventstore = system.eventstore_reader()?.seq();
    let error = preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("schema version 6 is older"));
    assert_eq!(repositories.schema_version().read().await?, Some(6));
    Ok(())
}

#[actix::test]
async fn schema_preflight_rejects_unversioned_snapshot_state() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    store.scope("legacy").write_sync(7_u64).await?;
    let repositories = Repositories::from(&store);
    let eventstore = system.eventstore_reader()?.seq();

    let error = preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("no schema marker"));
    Ok(())
}

#[actix::test]
async fn schema_preflight_initializes_store_with_only_bootstrap_identity() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    let private_key = vec![1_u8, 2, 3];
    let network_key = vec![4_u8, 5, 6];
    store
        .write_batch_sync([
            (StoreKeys::eth_private_key(), private_key.clone()),
            (StoreKeys::libp2p_keypair(), network_key.clone()),
        ])
        .await?;
    let repositories = Repositories::from(&store);
    let eventstore = system.eventstore_reader()?.seq();

    assert!(!has_schema_governed_kv_state(&repositories).await?);
    preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore).await?;

    assert_eq!(
        repositories.schema_version().read().await?,
        Some(super::SCHEMA_VERSION)
    );
    assert_eq!(
        store
            .scope(StoreKeys::eth_private_key())
            .read::<Vec<u8>>()
            .await?,
        Some(private_key)
    );
    assert_eq!(
        store
            .scope(StoreKeys::libp2p_keypair())
            .read::<Vec<u8>>()
            .await?,
        Some(network_key)
    );
    Ok(())
}

#[actix::test]
async fn schema_preflight_rejects_bootstrap_identity_plus_protocol_state() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    store
        .write_batch_sync([
            (StoreKeys::eth_private_key(), vec![1_u8]),
            (StoreKeys::libp2p_keypair(), vec![2_u8]),
        ])
        .await?;
    store
        .scope(StoreKeys::sortition())
        .write_sync(7_u64)
        .await?;
    let repositories = Repositories::from(&store);
    let eventstore = system.eventstore_reader()?.seq();

    assert!(has_schema_governed_kv_state(&repositories).await?);
    let error = preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("no schema marker"));
    assert_eq!(repositories.schema_version().read().await?, None);
    Ok(())
}

#[actix::test]
async fn schema_preflight_rejects_partial_bootstrap_identity() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    store
        .scope(StoreKeys::eth_private_key())
        .write_sync(vec![1_u8])
        .await?;
    let repositories = Repositories::from(&store);
    let eventstore = system.eventstore_reader()?.seq();

    let error = preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("no schema marker"));
    assert_eq!(repositories.schema_version().read().await?, None);
    Ok(())
}

#[actix::test]
async fn schema_preflight_rejects_unversioned_event_log() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let store = system.store()?;
    let repositories = Repositories::from(&store);
    let bus = system.handle()?.enable("unversioned-event-log");
    bus.publish_without_context(e3_events::TestEvent::new("legacy", 1))?;
    bus.flush_event_pipeline().await?;
    let eventstore = system.eventstore_reader()?.seq();

    let error = preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("no schema marker"));
    Ok(())
}
