// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Restart backfill of missing slashing-writer recovery stores.

use super::slashing_manager_sol_writer::{
    SlashingWriterRecoveryState, SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
};
use crate::SlashingWriterRepositoryFactory;
use anyhow::{ensure, Result};
use e3_data::{Repositories, Repository};
use e3_events::AccusationQuorumReached;
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// Slashing-writer stores that restart must rebuild from the event log.
///
/// Stores that predate the slashing-writer repository kept pending slash submissions only in the
/// event log. An existing store is authoritative and is never rewritten here.
#[derive(Default)]
pub struct SlashingWriterBackfill {
    missing: HashMap<
        u64,
        (
            Repository<SlashingWriterRecoveryState>,
            SlashingWriterRecoveryState,
        ),
    >,
}

impl SlashingWriterBackfill {
    /// Validates every chain's store and keeps the missing ones.
    pub async fn load(repositories: &Repositories, chain_ids: &[u64]) -> Result<Self> {
        let mut missing = HashMap::new();
        for chain_id in chain_ids.iter().copied().collect::<HashSet<_>>() {
            let store = repositories.slashing_writer_recovery(chain_id);
            let persisted = store.read().await?;
            let was_missing = persisted.is_none();
            let state = persisted.unwrap_or_default();
            ensure!(
                state.schema_version == SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
                "unsupported slashing-writer recovery schema {} for chain {}",
                state.schema_version,
                chain_id
            );
            if was_missing {
                missing.insert(chain_id, (store, state));
            }
        }
        Ok(Self { missing })
    }

    pub fn missing_chains(&self) -> HashSet<u64> {
        self.missing.keys().copied().collect()
    }

    /// Records the recovered intents for the missing chains and writes those stores.
    pub async fn write(mut self, intents: Vec<AccusationQuorumReached>) -> Result<()> {
        for intent in intents {
            let chain_id = intent.e3_id.chain_id();
            let Some((_, state)) = self.missing.get_mut(&chain_id) else {
                continue;
            };
            if let Err(error) = state.record(intent) {
                warn!(chain_id, %error, "Ignored malformed slash intent during restart backfill");
            }
        }
        for (store, state) in self.missing.values() {
            store.write_sync(state).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes};
    use e3_event_system::EventSystem;
    use e3_events::{AccusationOutcome, E3id, ProofType};

    fn intent(e3_id: E3id) -> AccusationQuorumReached {
        AccusationQuorumReached {
            e3_id,
            accuser: Address::repeat_byte(1),
            accused: Address::repeat_byte(2),
            proof_type: ProofType::C1PkGeneration,
            votes_for: Vec::new(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::new(),
        }
    }

    #[actix::test]
    async fn fills_only_missing_stores_and_rejects_unknown_schemas() -> Result<()> {
        let system = EventSystem::new();
        let repositories = Repositories::from(system.store()?);
        let mut existing = SlashingWriterRecoveryState::default();
        existing.record(intent(E3id::new("8", 2)))?;
        repositories
            .slashing_writer_recovery(2)
            .write_sync(&existing)
            .await?;

        let backfill = SlashingWriterBackfill::load(&repositories, &[1, 2, 1]).await?;
        assert_eq!(backfill.missing_chains(), HashSet::from([1]));
        backfill
            .write(vec![
                intent(E3id::new("7", 1)),
                intent(E3id::new("not-a-number", 1)),
                intent(E3id::new("9", 2)),
            ])
            .await?;
        let filled = repositories.slashing_writer_recovery(1).read().await?;
        assert_eq!(filled.expect("missing store is written").pending_count(), 1);
        let kept = repositories.slashing_writer_recovery(2).read().await?;
        assert_eq!(kept.expect("existing store").pending_count(), 1);

        existing.schema_version += 1;
        repositories
            .slashing_writer_recovery(2)
            .write_sync(&existing)
            .await?;
        let error = SlashingWriterBackfill::load(&repositories, &[1, 2])
            .await
            .err()
            .expect("unknown schema fails closed");
        assert!(error
            .to_string()
            .contains("unsupported slashing-writer recovery schema"));
        Ok(())
    }
}
