// SPDX-License-Identifier: LGPL-3.0-only

//! Durable schema admission before runtime state is loaded.

use super::*;
use e3_data::{CommitLogEventLog, DataStore, SledDb};
use e3_events::Get;
use std::path::PathBuf;

/// Inspect the schema through the raw key/value store before logs or snapshots are opened.
/// This does not stamp a fresh store; startup stamps it after creating the storage actors.
pub fn inspect_persisted_schema_version(
    db_path: &PathBuf,
    log_paths: impl IntoIterator<Item = PathBuf>,
) -> Result<SchemaVersionDecision> {
    let db = SledDb::new(db_path, "datastore")?;
    let persisted = db
        .get(Get::new(StoreKeys::schema_version()))?
        .map(|bytes| e3_utils::deserialize_exact::<u32>(&bytes))
        .transpose()
        .context("failed to decode the storage schema marker")?;
    let mut has_existing_state = false;
    if persisted.is_none() {
        let identity_keys = bootstrap_identity_keys().map(String::into_bytes);
        has_existing_state = !db.has_exact_keys(&[])? && !db.has_exact_keys(&identity_keys)?;
        if !has_existing_state {
            for path in log_paths {
                if CommitLogEventLog::has_records(&path)? {
                    has_existing_state = true;
                    break;
                }
            }
        }
    }
    Ok(decide_schema_version(
        persisted,
        SCHEMA_VERSION,
        has_existing_state,
    ))
}

/// Validate or initialize the durable schema marker before runtime actors can write state.
///
/// Returns whether this call stamped the marker, which happens only for a new data directory.
pub async fn preflight_schema_version(
    repositories: &Repositories,
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<bool> {
    let repo = repositories.schema_version();
    let persisted = DataStore::from(&repo).read_checked::<u32>().await?;
    let has_existing_state = if persisted.is_none() {
        has_schema_governed_kv_state(repositories).await?
            || event_logs_have_events(aggregate_config, eventstore).await?
    } else {
        false
    };
    let decision = decide_schema_version(persisted, SCHEMA_VERSION, has_existing_state);
    decision.ensure_compatible()?;
    if decision == SchemaVersionDecision::WriteCurrent {
        info!("Stamping on-disk schema version {SCHEMA_VERSION}.");
        repo.write_sync(&SCHEMA_VERSION).await?;
        Ok(true)
    } else {
        Ok(false)
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

    Ok(!repositories
        .store
        .has_exact_keys(bootstrap_identity_keys())
        .await?)
}

fn bootstrap_identity_keys() -> [String; 2] {
    [StoreKeys::eth_private_key(), StoreKeys::libp2p_keypair()]
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
