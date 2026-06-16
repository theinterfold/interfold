// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Thin actix shells that translate [`InterfoldEvent`]s into pure-domain calls
//! and perform the I/O those domain services request.
//!
//! [`InterfoldEvent`]: e3_events::InterfoldEvent

pub mod accusation_manager;
pub mod commitment_consistency_checker;
