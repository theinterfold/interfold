// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The contract readers and writers of each enabled chain.

use super::{
    restart::work_ended_on_restart,
    startup::{Live, Protocol, Restart, Storage},
    CiphernodeBuilder,
};
use alloy::primitives::Address;
use anyhow::{ensure, Context as _, Result};
use e3_config::chain_config::ChainConfig;
use e3_events::{BusHandle, DkgFoldAttestationContext, E3Stage, E3id, EvmEventConfig};
use e3_evm::{
    fetch_randomness_providers, ingestion_heartbeat_files, BondingRegistrySolReader,
    CiphernodeRegistrySol, CiphernodeRegistrySolReader, ConcreteReadProvider,
    DataAvailabilityCoordinator, DataAvailabilityRepositoryFactory, EnabledChain,
    EvmChainGatewayHandle, EvmSystemChainBuilder, IngestionProgressSink, InterfoldSolReader,
    InterfoldSolWriter, ProviderCache, ProviderConfig, ProviderFactory,
    RandomnessProviderSolReader, SlashingManagerSolReader, SlashingManagerSolWriter,
    SlashingWriterRepositoryFactory, WriteEnabled,
};
use e3_sync::NodeRole;
use std::collections::{HashMap, HashSet};
use tracing::{error, info};

/// One enabled chain, and the reader system that its contracts register with.
struct ChainReaders<'a> {
    bus: &'a BusHandle,
    chain: &'a ChainConfig,
    chain_id: u64,
    provider: &'a e3_evm::EthProvider<ConcreteReadProvider>,
    provider_factory: ProviderFactory<ConcreteReadProvider>,
    /// Confirmations that the CiphernodeRegistry reader waits for before it ingests an event.
    ingestion_confirmations: u64,
    max_log_window: u64,
    system: EvmSystemChainBuilder<ConcreteReadProvider>,
}

impl CiphernodeBuilder {
    /// Attach the data-availability coordinator and the configured contract readers and writers of
    /// each enabled chain. A bootstrap node reads only the Interfold contract.
    pub(super) async fn setup_evm_system(
        &self,
        storage: &Storage,
        restart: &Restart,
        live: &mut Live,
        protocol: &Protocol,
    ) -> Result<(EvmEventConfig, Vec<EvmChainGatewayHandle>)> {
        let Live {
            bus,
            provider_cache,
            ..
        } = live;
        let progress = self
            .ingestion_heartbeat_dir
            .clone()
            .map(ingestion_heartbeat_files)
            .transpose()
            .context("ingestion heartbeat directory")?;
        let mut evm_config = EvmEventConfig::new();
        let mut gateways = Vec::new();
        let finished = work_ended_on_restart(&restart.lifecycle_stages, &restart.kept_failures);
        for (enabled, slashing_manager) in storage
            .chains
            .iter()
            .zip(protocol.slashing_managers.iter().copied())
            .filter_map(|(chain, slashing_manager)| Some((chain.as_enabled()?, slashing_manager)))
        {
            let mut readers = self
                .chain_readers(enabled, bus, storage, &finished, &progress, &mut evm_config)
                .await?;
            if self.role() == NodeRole::Full {
                attach_interfold(&mut readers, provider_cache, storage, restart, protocol).await?;
                readers.system.with_contract(
                    readers.chain.contracts.bonding_registry.address()?,
                    move |next| BondingRegistrySolReader::setup(&next).recipient(),
                );
                attach_ciphernode_registry(&mut readers, provider_cache, restart).await?;
                attach_slashing_manager(&mut readers, provider_cache, storage, slashing_manager)
                    .await?;
            } else {
                readers
                    .system
                    .with_contract(readers.chain.contracts.interfold.address()?, move |next| {
                        InterfoldSolReader::setup(&next).recipient()
                    });
            }
            gateways.push(readers.system.build()?);
        }

        Ok((evm_config, gateways))
    }

    /// Check the chain, attach its data-availability coordinator, add its event configuration, and
    /// start its reader system.
    async fn chain_readers<'a>(
        &self,
        enabled: &'a EnabledChain,
        bus: &'a BusHandle,
        storage: &Storage,
        finished: &HashSet<E3id>,
        progress: &Option<IngestionProgressSink>,
        evm_config: &mut EvmEventConfig,
    ) -> Result<ChainReaders<'a>> {
        let EnabledChain {
            config: chain,
            chain_id,
            provider,
        } = enabled;
        let chain_id = *chain_id;
        let full = self.role() == NodeRole::Full;
        if full && chain.data_availability.is_none() {
            anyhow::bail!(
                "chain '{}' has Interfold enabled but no data_availability reader; this protocol release must retrieve proof-backed ciphertext outputs",
                chain.name
            );
        }
        DataAvailabilityCoordinator::attach(
            bus,
            chain_id,
            chain.data_availability.as_ref(),
            storage.repositories.data_availability_recovery(chain_id),
            finished,
        )
        .await?;
        if full {
            validate_vrf_chain_id(chain_id)?;
        }
        // Delay ingestion until the configured number of confirmations is present.
        let ingestion_confirmations = chain.ingestion_confirmations()?;
        evm_config.insert(chain_id, chain.try_into()?);

        let provider_factory = ProviderConfig::for_chain(chain)?.into_read_provider_factory();

        let max_log_window = chain.rpc_log_range_blocks()?;
        let mut system = EvmSystemChainBuilder::new(bus, provider);
        system
            .with_provider_factory(provider_factory.clone())
            .with_buffer_limit(self.max_buffered_evm_events)
            .with_max_log_window(max_log_window);
        if let Some(progress) = progress {
            system.with_progress_sink(progress.clone());
        }
        Ok(ChainReaders {
            bus,
            chain,
            chain_id,
            provider,
            provider_factory,
            ingestion_confirmations,
            max_log_window,
            system,
        })
    }
}

/// Attach the Interfold writer with the restored E3s of the chain, then the Interfold reader.
async fn attach_interfold(
    readers: &mut ChainReaders<'_>,
    provider_cache: &mut ProviderCache<WriteEnabled>,
    storage: &Storage,
    restart: &Restart,
    protocol: &Protocol,
) -> Result<()> {
    let chain_id = readers.chain_id;
    let interfold = &readers.chain.contracts.interfold;
    let write_provider = provider_cache.ensure_write_provider(readers.chain).await?;
    let chain_failure_stages = on_chain(&restart.lifecycle_stages, chain_id)
        .filter(|(_, stage)| {
            matches!(
                stage,
                E3Stage::Requested
                    | E3Stage::CommitteeFinalized
                    | E3Stage::KeyPublished
                    | E3Stage::CiphertextReady
            )
        })
        .map(|(e3_id, stage)| (e3_id.clone(), stage.clone()))
        .collect();
    let chain_failure_settlements = on_chain(&restart.lifecycle_stages, chain_id)
        .filter(|(_, stage)| **stage == E3Stage::Failed)
        .map(|(e3_id, _)| e3_id.clone())
        .collect();
    InterfoldSolWriter::attach_with_recovery(
        readers.bus,
        write_provider,
        interfold.address()?,
        on_chain(&protocol.selected_party_ids, chain_id)
            .map(|(e3_id, party_id)| (e3_id.clone(), *party_id))
            .collect(),
        request_registries(&restart.dkg_fold_contexts_by_e3, chain_id),
        chain_failure_stages,
        chain_failure_settlements,
        protocol
            .terminal_plaintext_e3s
            .iter()
            .filter(|id| id.chain_id() == chain_id)
            .cloned()
            .collect(),
        protocol.canonical_keys.clone(),
        storage.seq_eventstore.clone(),
    );
    readers
        .system
        .with_contract(interfold.address()?, move |next| {
            InterfoldSolReader::setup(&next).recipient()
        });
    Ok(())
}

/// Attach the CiphernodeRegistry reader, a reader for each randomness provider of the registry,
/// and the registry writer with the restored committee tickets of the chain.
async fn attach_ciphernode_registry(
    readers: &mut ChainReaders<'_>,
    provider_cache: &mut ProviderCache<WriteEnabled>,
    restart: &Restart,
) -> Result<()> {
    let chain_id = readers.chain_id;
    let registry = &readers.chain.contracts.ciphernode_registry;
    let registry_address = registry.address()?;
    let registry_provider = readers.provider.clone();
    let registry_provider_factory = readers.provider_factory.clone();
    let ingestion_confirmations = readers.ingestion_confirmations;
    readers.system.with_contract(registry_address, move |next| {
        CiphernodeRegistrySolReader::setup_with_factory(
            &next,
            registry_provider,
            Some(registry_provider_factory),
            ingestion_confirmations,
        )
        .recipient()
    });

    let randomness_addresses = fetch_randomness_providers(
        readers.provider.provider(),
        registry_address,
        registry.deploy_block().unwrap_or(0),
        readers.max_log_window,
    )
    .await?;
    ensure!(
        !randomness_addresses.is_empty(),
        "ciphernode registry {registry_address} has no randomness provider configured"
    );
    for randomness_address in randomness_addresses {
        let randomness_read_provider = readers.provider.clone();
        let randomness_provider_factory = readers.provider_factory.clone();
        readers
            .system
            .with_contract(randomness_address, move |next| {
                RandomnessProviderSolReader::setup_with_factory(
                    &next,
                    randomness_read_provider,
                    Some(randomness_provider_factory),
                    registry_address,
                )
                .recipient()
            });
    }

    // TODO: Should we not let this pass and just use '?'?
    // Above if we include interfold in the config and we don't have a wallet it will fail
    match provider_cache.ensure_write_provider(readers.chain).await {
        Ok(write_provider) => {
            CiphernodeRegistrySol::attach_writer_with_recovery(
                readers.bus,
                write_provider,
                registry_address,
                request_registries(&restart.dkg_fold_contexts_by_e3, chain_id),
                on_chain(&restart.committee_finalizer.tickets, chain_id)
                    .map(|(e3_id, ticket)| (e3_id.clone(), ticket.clone()))
                    .collect(),
            );
            info!("CiphernodeRegistrySolWriter attached for publishing committees");
        }
        Err(e) => error!(
            "Failed to create write provider (likely no wallet configured), skipping writer attachment: {}",
            e
        ),
    }
    Ok(())
}

/// Attach the SlashingManager reader and the writer that submits slash proposals.
async fn attach_slashing_manager(
    readers: &mut ChainReaders<'_>,
    provider_cache: &mut ProviderCache<WriteEnabled>,
    storage: &Storage,
    slashing_manager: Option<Address>,
) -> Result<()> {
    let slashing_manager = slashing_manager.with_context(|| {
        format!(
            "Chain {} has no SlashingManager: Interfold.slashingManager() could not be read or \
             is not set. A full node needs the live manager to sign accusation votes and submit \
             slash proposals",
            readers.chain.name
        )
    })?;
    readers.system.with_contract(slashing_manager, move |next| {
        SlashingManagerSolReader::setup(&next).recipient()
    });
    readers.system.with_slashing_manager(slashing_manager);
    match provider_cache.ensure_write_provider(readers.chain).await {
        Ok(write_provider) => match SlashingManagerSolWriter::attach_with_recovery(
            readers.bus,
            write_provider,
            slashing_manager,
            storage
                .repositories
                .slashing_writer_recovery(readers.chain_id),
            storage
                .repositories
                .slashing_writer_intent_times(readers.chain_id),
        )
        .await
        {
            Ok(_) => info!("SlashingManagerSolWriter attached for fault submission"),
            Err(e) => error!("Failed to attach SlashingManagerSolWriter, skipping: {}", e),
        },
        Err(e) => error!(
            "Failed to create write provider for SlashingManager, skipping: {}",
            e
        ),
    }
    Ok(())
}

/// The entries of `by_e3` whose E3 belongs to `chain_id`.
fn on_chain<V>(by_e3: &HashMap<E3id, V>, chain_id: u64) -> impl Iterator<Item = (&E3id, &V)> {
    by_e3
        .iter()
        .filter(move |(e3_id, _)| e3_id.chain_id() == chain_id)
}

/// The request-time CiphernodeRegistry of each restored E3 of `chain_id`.
fn request_registries(
    dkg_fold_contexts_by_e3: &HashMap<E3id, DkgFoldAttestationContext>,
    chain_id: u64,
) -> HashMap<E3id, Address> {
    on_chain(dkg_fold_contexts_by_e3, chain_id)
        .map(|(e3_id, context)| (e3_id.clone(), context.registry))
        .collect()
}

fn validate_vrf_chain_id(chain_id: u64) -> Result<()> {
    ensure!(
        matches!(chain_id, 1 | 1_337 | 31_337 | 11_155_111),
        "VRF sortition supports Ethereum mainnet, Sepolia, and local development chains only; received chain_id {chain_id}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_vrf_chain_id;

    #[test]
    fn supports_ethereum_vrf_chains() {
        for chain_id in [1, 11_155_111, 31_337, 1_337] {
            assert!(validate_vrf_chain_id(chain_id).is_ok());
        }
    }

    #[test]
    fn rejects_arbitrum_vrf_chains() {
        let error = validate_vrf_chain_id(42_161).expect_err("Arbitrum must be rejected");

        assert!(error.to_string().contains("Ethereum mainnet"));
    }
}
