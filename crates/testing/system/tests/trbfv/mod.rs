// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Full-proof multi-node trBFV scenarios, in four parts. A [`scenario::Scenario`] is the injected
//! fault and the expected outcome. [`runner::run`] executes it and returns the
//! [`runner::Observations`]. [`assertions::check`] evaluates the expectation over them. The
//! [`benchmark`] adapter formats and exports the same observations. The named `#[actix::test]`
//! functions in `integration.rs` call [`run_and_check`].

mod assertions;
pub mod benchmark;
mod history;
mod nodes;
mod runner;
pub mod scenario;
mod zk_fixture;

use anyhow::Result;
use runner::Observations;
use scenario::Scenario;

/// Runs the scenario, then panics if the run missed what the scenario expects.
pub async fn run_and_check(scenario: &Scenario) -> Result<Observations> {
    let observed = runner::run(scenario).await?;
    assertions::check(scenario, &observed);
    Ok(observed)
}
