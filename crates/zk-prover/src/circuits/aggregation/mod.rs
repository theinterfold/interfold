// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Recursive proof aggregation (Noir fold / `recursive_aggregation` binaries).

pub mod c2_chunk_batch;
pub(crate) mod c2_chunk_config;
pub mod c2_chunk_layout;
pub mod c2_terminal_validation;
pub mod c3_accumulator;
pub mod c6_accumulator;
pub mod helpers;
pub mod node_dkg_fold;
pub mod nodes_fold_accumulator;
