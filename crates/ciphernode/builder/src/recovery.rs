// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart-state backfill across the sortition and slashing-writer stores.

use anyhow::Result;
use e3_evm::SlashingWriterBackfill;
use e3_sortition::{CommitteeFinalizerRecoveryState, SortitionRestartBackfill};

/// Fills missing restart stores from one event-log scan. Every store is validated before any
/// missing store is written; the identity-policy catch-up of existing projections is written during
/// load. The checked log prefixes advance only after all recovered inputs are durable.
pub(crate) async fn backfill_restart_state(
    repositories: &e3_data::Repositories,
    eventstore: &actix::Recipient<e3_events::EventStoreQueryBy<e3_events::SeqAgg>>,
    chain_ids: &[u64],
    slashing_manager_enabled: bool,
) -> Result<CommitteeFinalizerRecoveryState> {
    let sortition = SortitionRestartBackfill::load(repositories, eventstore, chain_ids).await?;
    let slashing = if slashing_manager_enabled {
        SlashingWriterBackfill::load(repositories, chain_ids).await?
    } else {
        SlashingWriterBackfill::default()
    };
    let (slash_intents, checkpoint) = sortition
        .backfill(eventstore, &slashing.missing_chains())
        .await?;
    slashing.write(slash_intents).await?;
    checkpoint.commit().await
}
