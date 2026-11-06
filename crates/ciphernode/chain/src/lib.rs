// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's chain adapter. The decoder turns confirmed contract logs into the protocol's
//! chain facts; a fact that needs contract state from its block comes out as a read for the
//! ingestion loop to finish.

mod decode;

pub use decode::{Contracts, DecodeError, Decoded, Decoder, PendingRead, RawLog};
