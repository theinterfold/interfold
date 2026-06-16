// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::actors::evm_parser::EvmParser;
use crate::domain::interfold_events::extractor;
use crate::messages::EvmEventProcessor;
use actix::{Actor, Addr};

/// Connects to Interfold.sol converting EVM events to InterfoldEvents
pub struct InterfoldSolReader;

impl InterfoldSolReader {
    pub fn setup(next: &EvmEventProcessor) -> Addr<EvmParser> {
        EvmParser::new(next, extractor).start()
    }
}
