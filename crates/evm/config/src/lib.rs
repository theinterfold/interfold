// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! EVM connection and chain settings, independent of node configuration and provider I/O.

mod chain_config;
mod contract;
mod rpc;

pub use chain_config::{
    ChainConfig, DataAvailabilityConfig, DataAvailabilityMode, DEFAULT_RPC_LOG_RANGE_BLOCKS,
};
pub use contract::{Contract, ContractAddresses};
pub use rpc::{RpcAuth, RpcProtocol, RPC};
