// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Plain, synchronous domain services. These own all protocol state and
//! business logic; they perform **no** I/O (no event bus, no actix context,
//! no timers). The thin actors in [`crate::actors`] drive them and execute the
//! decisions/data they return.

pub(crate) mod accusation_voting;
pub(crate) mod commitment_consistency;
