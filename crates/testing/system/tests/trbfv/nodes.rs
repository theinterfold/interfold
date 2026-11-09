// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Node construction and synthetic registry/sortition setup for the trBFV scenarios.

use crate::ciphernode_system::CiphernodeSystem;
use crate::common::AddToCommittee;
use actix::{Actor, Addr};
use alloy::primitives::{Address, FixedBytes, I256, U256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Result};
use e3_ciphernode_builder::{CiphernodeBuilder, CiphernodeHandle};
use e3_crypto::Cipher;
use e3_events::{
    prelude::*, AggregateConfig, BusHandle, ConfigurationUpdated, E3id, EventType, Seed,
    TicketBalanceUpdated,
};
use e3_multithread::{MultithreadReport, TaskPool};
use e3_sortition::{calculate_buffer_size, RegisteredNode, ScoreSortition, Ticket};
use e3_test_support::derive_shared_rng;
use e3_zk_prover::ZkBackend;
use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Fold attestation verifier the scenarios sign against (no live registry supplies one).
pub const DKG_FOLD_ATTESTATION_VERIFIER: &str = "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0";
/// Slashing manager used as the EIP-712 `verifyingContract` of accusation votes.
const SLASHING_MANAGER: &str = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707";

/// Everything the nodes of one run share. [`NodeFactory::build`] is the only place a node is
/// assembled.
pub struct NodeFactory {
    pub rng_base: u64,
    pub cipher: Arc<Cipher>,
    pub zk_backend: ZkBackend,
    pub task_pool: TaskPool,
    pub concurrent_jobs: usize,
    pub multithread_report: Addr<MultithreadReport>,
    pub aggregate_config: AggregateConfig,
    pub dkg_timing_reader: e3_keyshare::DkgTimingReader,
    pub proof_aggregation_enabled: bool,
    /// Stands in for the chain: its events reach every node's own durable event pipeline.
    pub trigger: BusHandle,
    pub next_salt: AtomicU64,
}

impl NodeFactory {
    /// Builds one node with its own RNG stream, signer and address, and connects it to the
    /// trigger bus. `role` only labels the log line.
    pub async fn build(&self, role: &str) -> Result<CiphernodeHandle> {
        let salt = self.next_salt.fetch_add(1, Ordering::Relaxed);
        let rng = derive_shared_rng(self.rng_base, salt);
        // The address comes from the node's seeded RNG, so a seeded run gives each node the
        // same one.
        let addr = Address::from_slice(&rng.lock().unwrap().random::<[u8; 20]>()).to_string();
        println!("Building {role} {addr}");

        let mut builder =
            CiphernodeBuilder::full(rng, self.cipher.clone(), self.zk_backend.clone())
                .with_history_collector()
                .with_shared_taskpool(&self.task_pool)
                .with_multithread_concurrent_jobs(self.concurrent_jobs)
                .with_shared_multithread_report(&self.multithread_report)
                .with_signer(PrivateKeySigner::random())
                .with_eventstore_aggregate_config_for_testing(self.aggregate_config.clone())
                .with_dkg_timing_reader_for_testing(self.dkg_timing_reader.clone())
                .with_chains(std::slice::from_ref(&self.chain_config()))
                .with_logging();
        if !self.proof_aggregation_enabled {
            builder = builder.with_proof_aggregation_disabled_for_testing();
        }
        let node = builder.build().await?;

        // Chain observations must pass through each node's durable event pipeline.
        let pipe = e3_events::BusHandlePipe::new(node.bus().clone(), |_| true)
            .start()
            .recipient();
        self.trigger.subscribe(EventType::All, pipe);
        Ok(node)
    }

    /// A chain config for in-process runs: no RPC is used. It supplies the slashing manager and
    /// fold attestation verifier addresses that nodes sign against.
    fn chain_config(&self) -> e3_evm_config::ChainConfig {
        let address_only = |address: &str| e3_evm_config::Contract::AddressOnly(address.into());
        e3_evm_config::ChainConfig {
            enabled: Some(false),
            name: "scenario".into(),
            rpc_url: "http://localhost:8545".into(),
            rpc_auth: Default::default(),
            contracts: e3_evm_config::ContractAddresses {
                interfold: address_only("0x0000000000000000000000000000000000000000"),
                ciphernode_registry: address_only("0x0000000000000000000000000000000000000000"),
                bonding_registry: address_only("0x0000000000000000000000000000000000000000"),
                e3_program: None,
                fee_token: None,
                slashing_manager: Some(address_only(SLASHING_MANAGER)),
                dkg_fold_attestation_verifier: self
                    .proof_aggregation_enabled
                    .then(|| address_only(DKG_FOLD_ATTESTATION_VERIFIER)),
                faucet: None,
            },
            finalization_ms: None,
            chain_id: Some(1),
            ingestion_confirmations: Some(0),
            rpc_poll_interval_ms: Some(250),
            rpc_log_range_blocks: None,
            data_availability: None,
        }
    }
}

/// Registers every address as an active operator with the same ticket balance, as the registry
/// events would.
pub async fn setup_score_sortition_environment(
    bus: &BusHandle,
    eth_addrs: &[String],
    chain_id: u64,
) -> Result<()> {
    bus.publish_without_context(e3_events::ConfigurationUpdatedAt {
        configuration: ConfigurationUpdated {
            parameter: "ticketPrice".to_string(),
            old_value: U256::ZERO,
            new_value: U256::from(10_000_000u64),
            chain_id,
        },
        position: e3_events::ChainPosition::new(1, 0),
    })?;

    let mut adder = AddToCommittee::new(bus, chain_id);
    for addr in eth_addrs {
        adder.add(addr).await?;

        bus.publish_without_context(e3_events::TicketBalanceUpdatedAt {
            balance: TicketBalanceUpdated {
                operator: addr.clone(),
                delta: I256::try_from(1_000_000_000u64).unwrap(),
                new_balance: U256::from(1_000_000_000u64),
                reason: FixedBytes::ZERO,
                chain_id,
            },
            position: e3_events::ChainPosition::new(1, 1),
        })?;

        bus.publish_without_context(e3_events::OperatorActivationChangedAt {
            activation: e3_events::OperatorActivationChanged {
                operator: addr.clone(),
                active: true,
                chain_id,
            },
            position: e3_events::ChainPosition::new(1, 2),
        })?;
    }

    Ok(())
}

/// Runs the sortition the nodes run, so the committee matches what they will compute.
///
/// Returns the committee addresses, their scores, and the buffer addresses. Fails if the
/// collector was selected: it is never registered for sortition.
pub fn determine_committee(
    e3_id: &E3id,
    seed: Seed,
    threshold_m: usize,
    threshold_n: usize,
    registered_addrs: &[String],
    collector_addr: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let buffer = calculate_buffer_size(threshold_m, threshold_n);
    let total_selection_size = threshold_n + buffer;

    // Same balance/ticket_price ratio as production: 1_000_000_000 / 10_000_000 tickets each.
    const TICKET_PRICE: u64 = 10_000_000;
    const BALANCE: u64 = 1_000_000_000;
    let num_tickets = BALANCE / TICKET_PRICE;

    let registered_nodes: Vec<RegisteredNode> = registered_addrs
        .iter()
        .map(|addr| {
            let address: Address = addr.parse().unwrap();
            let tickets: Vec<Ticket> = (0..num_tickets)
                .map(|ticket_id| Ticket { ticket_id })
                .collect();
            RegisteredNode { address, tickets }
        })
        .collect();

    let winners = ScoreSortition::new(total_selection_size).get_committee(
        e3_id.clone(),
        seed,
        &registered_nodes,
    )?;

    let committee: Vec<String> = winners
        .iter()
        .take(threshold_n)
        .map(|w| w.address.to_string())
        .collect();
    let committee_scores: Vec<String> = winners
        .iter()
        .take(threshold_n)
        .map(|w| U256::from_be_slice(&w.score.to_bytes_be()).to_string())
        .collect();
    let buffer_nodes: Vec<String> = winners
        .iter()
        .skip(threshold_n)
        .map(|w| w.address.to_string())
        .collect();

    if committee
        .iter()
        .any(|addr| addr.eq_ignore_ascii_case(collector_addr))
    {
        bail!("the collector was selected for the committee but is not registered for sortition");
    }

    Ok((committee, committee_scores, buffer_nodes))
}

pub fn find_node_index_by_address(nodes: &CiphernodeSystem, address: &str) -> Result<usize> {
    nodes
        .iter()
        .position(|node| node.address().eq_ignore_ascii_case(address))
        .ok_or_else(|| anyhow::anyhow!("could not find node index for address {address}"))
}
