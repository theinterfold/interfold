// SPDX-License-Identifier: LGPL-3.0-only

//! Durable schema admission before runtime state is loaded.

use super::*;
use e3_data::DataStore;

/// Validate or initialize the durable schema marker before runtime actors can write state.
///
/// Returns whether this call stamped the marker, which happens only for a new data directory.
pub async fn preflight_schema_version(
    repositories: &Repositories,
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<bool> {
    let repo = repositories.schema_version();
    let persisted = repo.read().await?;
    let has_existing_state = if persisted.is_none() {
        has_schema_governed_kv_state(repositories).await?
            || event_logs_have_events(aggregate_config, eventstore).await?
    } else {
        false
    };
    match decide_schema_version(persisted, SCHEMA_VERSION, has_existing_state) {
        SchemaVersionDecision::Proceed => Ok(false),
        SchemaVersionDecision::WriteCurrent => {
            info!("Stamping on-disk schema version {SCHEMA_VERSION}.");
            repo.write_sync(&SCHEMA_VERSION).await?;
            Ok(true)
        }
        SchemaVersionDecision::Halt(reason) => {
            bail!("Schema version check failed: {reason}");
        }
    }
}

/// Stamp the node role on a new data directory, or refuse a directory that another role wrote.
///
/// Run this right after schema admission, before runtime actors can write state. `new_directory`
/// is the result of `preflight_schema_version`: true only when that call stamped the directory.
pub async fn preflight_node_role(
    repositories: &Repositories,
    new_directory: bool,
    role: NodeRole,
) -> Result<()> {
    let repo = repositories.node_role();
    // A storage error must not read as an absent marker, or a failed read could let a full node
    // restamp a bootstrap node's directory.
    let persisted = DataStore::from(&repo).read_checked::<NodeRole>().await?;
    match decide_node_role(persisted, role, new_directory) {
        NodeRoleDecision::Proceed => Ok(()),
        NodeRoleDecision::Write => {
            info!("Stamping node role {role} on the data directory.");
            repo.write_sync(&role).await?;
            Ok(())
        }
        NodeRoleDecision::Halt(reason) => {
            bail!("Node role check failed: {reason}");
        }
    }
}

/// Return whether the key/value store contains state whose interpretation requires a schema
/// marker. The complete operator/libp2p bootstrap identity pair is the only fresh exception.
pub async fn has_schema_governed_kv_state(repositories: &Repositories) -> Result<bool> {
    if repositories.store.is_empty().await? {
        return Ok(false);
    }

    let bootstrap_identity_keys = [StoreKeys::eth_private_key(), StoreKeys::libp2p_keypair()];
    Ok(!repositories
        .store
        .has_exact_keys(bootstrap_identity_keys)
        .await?)
}

async fn event_logs_have_events(
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<bool> {
    let query = aggregate_config
        .aggregates()
        .into_iter()
        .map(|aggregate_id| (aggregate_id, 1))
        .collect();
    let (response, receiver) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
    eventstore
        .send(EventStoreQueryBy::<SeqAgg>::new(CorrelationId::new(), query, response).with_limit(1))
        .await
        .context("event-store router stopped during schema preflight")?;
    Ok(!receiver
        .await
        .context("event-store query stopped during schema preflight")?
        .into_events()
        .context("event-store query failed during schema preflight")?
        .is_empty())
}
