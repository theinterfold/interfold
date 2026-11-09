// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Full-proof multi-node trBFV scenarios. [`runner::run`] is the one scenario runner: the named
//! `#[actix::test]` functions in `integration.rs` pick a [`runner::Scenario`], and
//! [`benchmark`] reuses the same runner to report timings.

pub mod benchmark;
mod history;
mod nodes;
pub mod runner;
mod zk_fixture;
