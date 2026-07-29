// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bincode::Error;
use serde::de::DeserializeOwned;

pub(crate) const MAX_GOSSIP_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_DIRECT_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_DHT_DOCUMENT_BYTES: usize = 25 * 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], max_bytes: usize) -> Result<T, Error> {
    let max_bytes =
        u64::try_from(max_bytes).map_err(|_| Box::new(bincode::ErrorKind::SizeLimit))?;
    e3_utils::deserialize_bounded(bytes, max_bytes)
}
