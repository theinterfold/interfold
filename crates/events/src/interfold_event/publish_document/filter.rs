// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};

/// PartialOrd Filter. Can filter based on our rank in the committee (party_id) incase a payload is split between documents.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Filter<T> {
    /// Range is inclusive but means nothing for non PartialOrd T
    Range(Option<T>, Option<T>),
    /// Single item specifier
    Item(T),
}

impl<T: PartialOrd> Filter<T> {
    pub fn matches(&self, item: &T) -> bool {
        match self {
            Filter::Range(Some(start), Some(end)) => item >= start && item <= end,
            Filter::Range(Some(start), None) => item >= start,
            Filter::Range(None, Some(end)) => item <= end,
            Filter::Range(None, None) => true,
            Filter::Item(value) => item == value,
        }
    }
}
