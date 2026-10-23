// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The protocol extensions of the E3 router, and the compute and ZK actors that they use.

use super::{
    chain_parameters::ChainParameters,
    restart::{compute_gate_stages, fail_on_restart, terminal_e3s},
    startup::{Live, Protocol, Restart, Storage},
    CiphernodeBuilder, NodeProfile,
};
use crate::recovery::recovered_ciphernode_selections;
use actix::Addr;
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
#[cfg(feature = "test-helpers")]
use anyhow::ensure;
use anyhow::Result;
use e3_aggregator::ext::{
    AggregatorRoleExtension, PublicKeyAggregatorExtension, ThresholdPlaintextAggregatorExtension,
};
use e3_data::Repositories;
use e3_events::{AggregateId, BusHandle, Committee, E3Stage, E3id};
use e3_evm::{read_canonical_dkg_timing, slashing_managers_by_chain, Chains};
use e3_fhe::ext::FheExtension;
use e3_keyshare::{ext::ThresholdKeyshareExtension, DkgTimingReader};
use e3_multithread::Multithread;
use e3_request::{canonical_key::CanonicalPublicKeys, E3Router, E3RouterBuilder};
use e3_slashing::{AccusationManagerExtension, CommitmentConsistencyCheckerExtension};
use e3_sortition::{CiphernodeSelectorFactory, FinalizedCommitteesRepositoryFactory};
use e3_task_pool::TaskPool;
use e3_zk_prover::{setup_zk_actors, ZkActorRecovery, ZkBackend};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{info, warn};

impl CiphernodeBuilder {
    /// Build the request router with the restart gates of the restored E3s, hydrate the ZK actor
    /// recovery, and add the protocol extensions of a full node.
    pub(super) async fn setup_extensions(
        &self,
        storage: &Storage,
        restart: &Restart,
        live: &mut Live,
        protocol: &Protocol,
        chain_parameters: &ChainParameters,
    ) -> Result<e3_request::E3RouterBuilder> {
        let Live {
            addr,
            bus,
            provider_cache,
        } = live;
        let canonical_keys = &protocol.canonical_keys;
        let mut e3_builder =
            router_builder(bus, addr, storage, restart, protocol, chain_parameters)?;
        let effect_stages = compute_gate_stages(&restart.lifecycle_stages, &restart.kept_failures);
        let repositories = &storage.repositories;
        let (zk_recovery, persisted_committees) =
            recover_zk_actors(&effect_stages, storage, restart).await?;

        // A bootstrap node verifies no proofs and must not sign accusation votes, so it gets
        // no protocol extension.
        let NodeProfile::Full { zk_backend } = &self.profile else {
            return Ok(e3_builder);
        };

        // ── Threshold keyshare + ZK actors ──
        let (_multithread, task_pool) =
            self.start_multithread(bus, addr, &effect_stages, canonical_keys, zk_backend);
        zk_backend.ensure_installed().await?;
        let signer = provider_cache.ensure_signer().await?;
        let (interfold_addresses, dkg_timing_reader) = self.dkg_timing(&storage.chains)?;

        info!("Setting up ThresholdKeyshareExtension");
        e3_builder = e3_builder.with_recipient(
            "threshold_keyshare",
            ThresholdKeyshareExtension::create(
                bus,
                &self.cipher,
                addr,
                interfold_addresses,
                dkg_timing_reader,
                signer.clone(),
                canonical_keys.clone(),
            ),
        );

        info!("Setting up ZK actors");
        setup_zk_actors(
            bus,
            zk_backend,
            signer,
            chain_parameters.dkg_fold_context_by_chain.clone(),
            zk_recovery.with_canonical_keys(canonical_keys.clone()),
            self.proof_aggregation_enabled,
            Repositories::clone(repositories),
            task_pool,
            addr.to_owned(),
        );

        // ── Public key aggregation ──
        info!("Setting up FheExtension");
        e3_builder = e3_builder.with(FheExtension::create(bus, &self.rng));
        info!("Setting up PublicKeyAggregationExtension");
        e3_builder =
            e3_builder.with_recipient("publickey", PublicKeyAggregatorExtension::create(bus));

        // ── Threshold plaintext aggregation ──
        info!("Setting up ThresholdPlaintextAggregatorExtension");
        e3_builder = e3_builder.with_recipient(
            "plaintext",
            ThresholdPlaintextAggregatorExtension::create(
                bus,
                &protocol.sortition,
                self.proof_aggregation_enabled,
                canonical_keys.clone(),
                storage.seq_eventstore.clone(),
            ),
        );

        // ── Accusation manager ──
        let signer = provider_cache.ensure_signer().await?;
        e3_builder = e3_builder.with_recipient(
            "accusation_manager",
            accusation_manager(
                bus,
                signer,
                storage,
                protocol,
                chain_parameters,
                persisted_committees,
            )?,
        );

        // ── Commitment consistency checker ──
        info!("Setting up CommitmentConsistencyCheckerExtension");
        e3_builder = e3_builder.with_recipient(
            "commitment_consistency_checker",
            CommitmentConsistencyCheckerExtension::create(
                bus,
                &repositories.store,
                e3_zk_prover::default_links,
            ),
        );

        Ok(e3_builder)
    }

    /// The Interfold address of every configured chain, and the reader of the canonical DKG timing
    /// of an E3 from its enabled chain.
    fn dkg_timing(&self, chains: &Chains) -> Result<(HashMap<u64, Address>, DkgTimingReader)> {
        let mut interfold_addresses = HashMap::new();
        let mut dkg_chain_readers = HashMap::new();
        for chain in chains.enabled() {
            let contract_address = chain.config.contracts.interfold.address()?;
            interfold_addresses.insert(chain.chain_id, contract_address);
            dkg_chain_readers.insert(chain.chain_id, (chain.provider.clone(), contract_address));
        }
        for chain in chains.disabled() {
            if let Some(chain_id) = chain.chain_id {
                interfold_addresses.insert(chain_id, chain.contracts.interfold.address()?);
            }
        }

        let dkg_timing_reader: DkgTimingReader = Arc::new(move |e3_id| {
            let chain = dkg_chain_readers.get(&e3_id.chain_id()).cloned();
            Box::pin(async move {
                let (provider, contract_address) = chain.ok_or_else(|| {
                    anyhow::anyhow!("no DKG timing reader for chain {}", e3_id.chain_id())
                })?;
                let timing = read_canonical_dkg_timing(&provider, contract_address, &e3_id).await?;
                Ok((timing.deadline_unix_secs, timing.window_secs))
            })
        });
        #[cfg(feature = "test-helpers")]
        let dkg_timing_reader = match &self.dkg_timing_reader_override {
            Some(reader) => {
                ensure!(
                    chains.enabled().next().is_none(),
                    "test DKG timing reader requires all chain providers to be disabled"
                );
                reader.clone()
            }
            None => dkg_timing_reader,
        };
        Ok((interfold_addresses, dkg_timing_reader))
    }

    fn start_multithread(
        &self,
        bus: &BusHandle,
        task_scope: &str,
        lifecycle_stages: &HashMap<E3id, E3Stage>,
        canonical_keys: &CanonicalPublicKeys,
        zk_backend: &ZkBackend,
    ) -> (Addr<Multithread>, TaskPool) {
        info!("Setting up multithread actor with ZK prover");
        let task_pool = self.task_pool.clone().unwrap_or_else(|| {
            let pool_threads = self.threads.unwrap_or(1);
            let concurrent_jobs = self.multithread_concurrent_jobs.unwrap_or(1);
            Multithread::create_taskpool(pool_threads, concurrent_jobs)
        });
        let worker = Multithread::attach_with_zk(
            bus,
            self.rng.clone(),
            self.cipher.clone(),
            task_pool.clone(),
            task_scope.to_owned(),
            self.multithread_report.clone(),
            zk_backend,
            lifecycle_stages.clone(),
            canonical_keys.clone(),
        );
        (worker, task_pool)
    }
}

/// The request router with the recovered selections of this node, the teardown grace, the restart
/// gates of the restored E3s, and the aggregator-role extension.
fn router_builder(
    bus: &BusHandle,
    addr: &str,
    storage: &Storage,
    restart: &Restart,
    protocol: &Protocol,
    chain_parameters: &ChainParameters,
) -> Result<E3RouterBuilder> {
    let selector_state = &protocol.selector_state;
    let recovered_selections = recovered_ciphernode_selections(selector_state, addr)?;
    // A slashably-failed context also outlives the longest accusation vote.
    let max_vote_validity = chain_parameters
        .accusation_vote_validity_by_chain
        .values()
        .max()
        .copied();
    let teardown_grace = e3_request::SLASHABLE_FAILURE_GRACE
        .saturating_add(Duration::from_secs(max_vote_validity.unwrap_or_default()));
    Ok(E3Router::builder(bus, storage.store.clone())
        .with_recovered_selections(recovered_selections)
        .with_teardown_grace(teardown_grace)
        .with_complete_on_restart(terminal_e3s(&restart.lifecycle_stages))
        .with_fail_on_restart(fail_on_restart(
            &restart.lifecycle_stages,
            &restart.kept_failures,
        ))
        .with(AggregatorRoleExtension::create(
            selector_state.is_aggregator.clone(),
        )))
}

/// Hydrate the ZK actor recovery from the persisted committees and E3 metadata. Also returns the
/// persisted committees, which the accusation manager uses.
async fn recover_zk_actors(
    effect_stages: &HashMap<E3id, E3Stage>,
    storage: &Storage,
    restart: &Restart,
) -> Result<(ZkActorRecovery, HashMap<E3id, Committee>)> {
    let Storage {
        event_system,
        repositories,
        ..
    } = storage;
    let persisted_committees = repositories
        .finalized_committees()
        .read()
        .await?
        .unwrap_or_default();
    let persisted_e3_metadata = repositories
        .ciphernode_selector()
        .read()
        .await?
        .map(|state| state.e3_cache)
        .unwrap_or_default();
    let mut zk_recovery = ZkActorRecovery::new(
        persisted_committees.clone(),
        persisted_e3_metadata,
        restart.dkg_fold_contexts_by_e3.clone(),
    );
    Box::pin(
        zk_recovery.hydrate(
            repositories,
            // A failed E3 kept for accusation work is Failed here, so its C0 inputs do not
            // resume.
            effect_stages,
            &event_system.eventstore_reader()?.seq(),
            &event_system
                .aggregate_config()
                .indexed_ids()
                .into_iter()
                .map(AggregateId::new)
                .collect::<Vec<_>>(),
        ),
    )
    .await?;
    Ok((zk_recovery, persisted_committees))
}

/// The accusation manager, which signs accusation votes for the SlashingManager of each chain.
fn accusation_manager(
    bus: &BusHandle,
    signer: PrivateKeySigner,
    storage: &Storage,
    protocol: &Protocol,
    chain_parameters: &ChainParameters,
    persisted_committees: HashMap<E3id, Committee>,
) -> Result<Box<AccusationManagerExtension>> {
    let accusation_deadline_skew_secs = parse_env_u64("ACCUSATION_DEADLINE_SKEW_SECS", 30);
    let slashing_managers_by_chain =
        slashing_managers_by_chain(&storage.chains, &protocol.slashing_managers);
    if slashing_managers_by_chain.is_empty() {
        anyhow::bail!(
            "`slashing_manager` contract address is required in chain config — \
             it is the EIP-712 `verifyingContract` for accusation vote signatures"
        );
    }
    let vote_validity_by_chain = &chain_parameters.accusation_vote_validity_by_chain;
    info!(
        chains = vote_validity_by_chain.len(),
        slashing_manager_chains = slashing_managers_by_chain.len(),
        accusation_deadline_skew_secs,
        "Setting up AccusationManagerExtension"
    );
    Ok(AccusationManagerExtension::create(
        bus,
        signer,
        slashing_managers_by_chain,
        vote_validity_by_chain.clone(),
        accusation_deadline_skew_secs,
        persisted_committees,
        &storage.repositories.store,
    ))
}

/// Parse a `u64` env var, returning `default_val` on any error.
fn parse_env_u64(name: &str, default_val: u64) -> u64 {
    let Ok(raw) = std::env::var(name) else {
        return default_val;
    };
    raw.parse().unwrap_or_else(|err| {
        warn!(value = %raw, error = %err, "invalid {name}; falling back to default ({default_val})");
        default_val
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        chain_parameters::ChainParameters,
        sortition::setup_sortition,
        startup::{Live, Protocol, Restart, Storage},
        CiphernodeBuilder,
    };
    use alloy::primitives::Address;
    use e3_events::E3id;
    use e3_evm::{Chains, ProviderCache};
    use std::collections::{HashMap, HashSet};

    #[actix::test]
    async fn bootstrap_router_keeps_no_protocol_backlog() -> anyhow::Result<()> {
        use e3_data::RepositoriesFactory;
        use e3_events::{
            E3Requested, EventConstructorWithTimestamp, EventSource, InterfoldEvent, TestEvent,
            Unsequenced,
        };
        use e3_request::{E3Context, E3ContextSnapshot, E3Extension};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct ObserveRecipients(Arc<AtomicUsize>, Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl E3Extension for ObserveRecipients {
            fn on_event(&self, context: &mut E3Context, _: &InterfoldEvent) {
                self.0.fetch_max(context.recipients.len(), Ordering::SeqCst);
                self.1.fetch_add(1, Ordering::SeqCst);
            }
            async fn hydrate(
                &self,
                _: &mut E3Context,
                _: &E3ContextSnapshot,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let system = e3_event_system::EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("bootstrap-routing");
        let store = system.store()?;
        let cipher =
            Arc::new(e3_crypto::Cipher::from_password("test-only-bootstrap-router").await?);
        let builder =
            CiphernodeBuilder::bootstrap(e3_test_helpers::derive_shared_rng(1, 1), cipher.clone());
        let addr = Address::from([0xab; 20]).to_string();
        let repositories = Arc::new(store.repositories());
        let (sortition, selector_state) = setup_sortition(&bus, &repositories, &addr).await?;
        let eventstore = system.eventstore_reader()?;
        let storage = Storage {
            chains: Chains::resolve(&[], &mut ProviderCache::new()).await?,
            seq_eventstore: eventstore.seq(),
            eventstore,
            store,
            repositories: repositories.clone(),
            aggregate_config: system.aggregate_config(),
            eventstore_aggregate_config: system.aggregate_config(),
            event_system: system,
        };
        let mut live = Live {
            addr,
            bus,
            provider_cache: ProviderCache::new().with_write_support(cipher, repositories),
        };
        let protocol = Protocol {
            canonical_keys: e3_request::canonical_key::CanonicalPublicKeys::default(),
            terminal_plaintext_e3s: HashSet::new(),
            sortition,
            selector_state,
            selected_party_ids: HashMap::new(),
            slashing_managers: Vec::new(),
        };
        let observed = Arc::new(AtomicUsize::new(0));
        let routed = Arc::new(AtomicUsize::new(0));
        let router = builder
            .setup_extensions(
                &storage,
                &Restart::default(),
                &mut live,
                &protocol,
                &ChainParameters {
                    dkg_fold_context_by_chain: HashMap::new(),
                    accusation_vote_validity_by_chain: HashMap::new(),
                },
            )
            .await?
            .with(Box::new(ObserveRecipients(
                observed.clone(),
                routed.clone(),
            )))
            .build()
            .await?;
        let e3_id = E3id::new("701", 1);
        let admission = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            E3Requested {
                e3_id: e3_id.clone(),
                ..Default::default()
            }
            .into(),
            None,
            1,
            None,
            EventSource::Evm,
        )
        .into_sequenced(1);
        router.send(admission).await?;
        for sequence in 2..2_050 {
            let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                TestEvent::new("history", sequence)
                    .with_e3_id(e3_id.clone())
                    .into(),
                None,
                sequence.into(),
                None,
                EventSource::Evm,
            )
            .into_sequenced(sequence);
            router.send(event).await?;
        }
        assert_eq!(routed.load(Ordering::SeqCst), 2_049);
        assert_eq!(
            observed.load(Ordering::SeqCst),
            0,
            "a bootstrap context must have no deferred protocol recipients"
        );
        Ok(())
    }
}
