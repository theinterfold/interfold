// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn node_role_preflight_stamps_a_new_directory_and_refuses_the_other_role(
) -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let repositories = Repositories::from(&system.store()?);
    let eventstore = system.eventstore_reader()?.seq();
    let aggregate_config = system.aggregate_config();

    let new_directory =
        preflight_schema_version(&repositories, &aggregate_config, &eventstore).await?;
    assert!(new_directory);
    preflight_node_role(&repositories, new_directory, NodeRole::Bootstrap).await?;
    assert_eq!(
        repositories.node_role().read().await?,
        Some(NodeRole::Bootstrap)
    );

    // The next start finds a stamped directory.
    let new_directory =
        preflight_schema_version(&repositories, &aggregate_config, &eventstore).await?;
    assert!(!new_directory);
    let error = preflight_node_role(&repositories, new_directory, NodeRole::Full)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("belongs to a bootstrap node"));
    assert_eq!(
        repositories.node_role().read().await?,
        Some(NodeRole::Bootstrap)
    );
    preflight_node_role(&repositories, new_directory, NodeRole::Bootstrap).await?;
    Ok(())
}

#[actix::test]
async fn node_role_preflight_treats_an_unmarked_directory_as_a_full_node() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let repositories = Repositories::from(&system.store()?);
    // A release without the role marker left a schema marker and a chain cursor, but no events.
    repositories
        .schema_version()
        .write_sync(&SCHEMA_VERSION)
        .await?;
    repositories
        .aggregate_block(AggregateId::new(1))
        .write_sync(&42)
        .await?;
    let eventstore = system.eventstore_reader()?.seq();

    let new_directory =
        preflight_schema_version(&repositories, &system.aggregate_config(), &eventstore).await?;
    assert!(!new_directory);
    let error = preflight_node_role(&repositories, new_directory, NodeRole::Bootstrap)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("belongs to a full node"));
    assert_eq!(repositories.node_role().read().await?, None);

    preflight_node_role(&repositories, new_directory, NodeRole::Full).await?;
    assert_eq!(repositories.node_role().read().await?, Some(NodeRole::Full));
    Ok(())
}
