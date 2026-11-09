// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's chain adapter. The reader turns each chain's confirmed contract logs into the
//! protocol's chain facts, in order, and reads the contract state that some facts carry. The writer
//! turns the node's submissions into the operator's transactions.

mod decode;
mod link;
mod reader;
mod release;
mod rpc;
#[cfg(test)]
mod testing;
mod wallet;
mod writer;

use decode::{decode, Decoded, PendingRead};
pub use decode::{Contracts, DecodeError, RawLog};
pub use link::Endpoint;
pub use reader::{Deadlines, LogsError, ReadError, Reader, Rpc, Sortition};
pub use release::{standing, Release, Standing, Unsupported};
pub use rpc::ChainNode;
pub use wallet::Wallet;
pub use writer::{Account, Call, Estimate, WriteError, Writer};

/// A chain node request that failed.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct RpcError(pub Box<dyn std::error::Error + Send + Sync>);

impl RpcError {
    fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}
