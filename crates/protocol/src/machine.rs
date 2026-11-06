// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{de::DeserializeOwned, Serialize};

/// Seconds since the Unix epoch, as recorded with each input.
pub type UnixSecs = u64;

/// The input a machine receives when the time it asked for has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick;

/// A deterministic state machine: the same inputs at the same times always produce the same state
/// and the same effects. It reads no clock and draws no randomness.
pub trait Machine: Serialize + DeserializeOwned {
    type Input: Serialize + DeserializeOwned + From<Tick>;
    type Effect: Serialize + DeserializeOwned;

    fn step(&mut self, now: UnixSecs, input: Self::Input) -> Vec<Self::Effect>;

    /// When the machine next needs a [`Tick`], if ever.
    fn next_deadline(&self) -> Option<UnixSecs>;
}
