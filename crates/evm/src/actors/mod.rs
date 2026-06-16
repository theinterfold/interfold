// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Thin actix message-passing shells wrapping the pure services in `domain`
//! and performing the EVM/provider I/O (transport).

mod bonding_registry_sol;
mod ciphernode_registry_sol;
mod evm_chain_gateway;
mod evm_hub;
mod evm_parser;
mod evm_read_interface;
mod evm_router;
mod fix_historical_order;
mod interfold_sol_reader;
mod interfold_sol_writer;
mod log_fetcher;
mod slashing_manager_sol_reader;
mod slashing_manager_sol_writer;
mod sync_start_extractor;

pub use bonding_registry_sol::BondingRegistrySolReader;
pub use ciphernode_registry_sol::{
    fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier, CiphernodeRegistrySol,
    CiphernodeRegistrySolReader, CiphernodeRegistrySolWriter,
};
pub use evm_chain_gateway::*;
pub use evm_hub::*;
pub use evm_parser::*;
pub use evm_read_interface::*;
pub use evm_router::*;
pub use fix_historical_order::*;
pub use interfold_sol_reader::InterfoldSolReader;
pub use interfold_sol_writer::InterfoldSolWriter;
pub use slashing_manager_sol_reader::SlashingManagerSolReader;
pub use slashing_manager_sol_writer::SlashingManagerSolWriter;
pub use sync_start_extractor::*;
