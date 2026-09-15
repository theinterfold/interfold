// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of thin actors stored with their EVM capabilities.

#[path = "bonding_registry/actor.rs"]
mod bonding_registry_sol;
#[path = "ciphernode_registry/actor.rs"]
mod ciphernode_registry_sol;
#[path = "data_availability/actor.rs"]
mod data_availability;
#[path = "chain_gateway/actor.rs"]
mod evm_chain_gateway;
#[path = "chain_hub.rs"]
mod evm_hub;
#[path = "event_decoding/actor.rs"]
mod evm_parser;
#[path = "chain_reader/actor.rs"]
mod evm_read_interface;
#[path = "event_router.rs"]
mod evm_router;
#[path = "historical_order/actor.rs"]
mod fix_historical_order;
#[path = "interfold/reader.rs"]
mod interfold_sol_reader;
#[path = "interfold_writing/actor.rs"]
mod interfold_sol_writer;
#[path = "randomness_provider/actor.rs"]
mod randomness_provider_sol;
#[path = "slashing/reader.rs"]
mod slashing_manager_sol_reader;
#[path = "slashing_writing/actor.rs"]
mod slashing_manager_sol_writer;
#[path = "chain_sync/start_extractor.rs"]
mod sync_start_extractor;

pub use bonding_registry_sol::BondingRegistrySolReader;
pub use ciphernode_registry_sol::{
    fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier, fetch_randomness_provider,
    fetch_randomness_providers, CiphernodeRegistrySol, CiphernodeRegistrySolReader,
    CiphernodeRegistrySolWriter,
};
pub use data_availability::{
    DataAvailabilityCoordinator, DataAvailabilityRecoveryState,
    DATA_AVAILABILITY_RECOVERY_SCHEMA_VERSION,
};
pub use evm_chain_gateway::*;
pub use evm_hub::*;
pub use evm_parser::*;
pub use evm_read_interface::*;
pub use evm_router::*;
pub use fix_historical_order::*;
pub use interfold_sol_reader::InterfoldSolReader;
pub use interfold_sol_writer::InterfoldSolWriter;
pub use randomness_provider_sol::RandomnessProviderSolReader;
pub use slashing_manager_sol_reader::SlashingManagerSolReader;
pub use slashing_manager_sol_writer::{
    SlashingManagerSolWriter, SlashingWriterRecoveryState, SLASHING_WRITER_RECOVERY_SCHEMA_VERSION,
};
pub use sync_start_extractor::*;
