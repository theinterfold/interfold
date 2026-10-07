// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::{Arc, Mutex, PoisonError};

use thiserror::Error;

use crate::hlc::{Hlc, HlcError, HlcMethods, HlcTimestamp};

#[derive(Debug, Error)]
pub enum HlcFactoryError {
    #[error(transparent)]
    Hlc(#[from] HlcError),

    #[error("HLC not initialized")]
    NotReady,

    #[error("lock poisoned: {0}")]
    LockPoisoned(String),
}

impl<T> From<PoisonError<T>> for HlcFactoryError {
    fn from(e: PoisonError<T>) -> Self {
        HlcFactoryError::LockPoisoned(e.to_string())
    }
}

enum HlcState {
    Init,
    Ready(Hlc),
}

impl HlcState {
    pub fn ready(&mut self, hlc: Hlc) {
        if let HlcState::Init = self {
            *self = HlcState::Ready(hlc);
        }
    }

    pub fn is_ready(&self) -> bool {
        !matches!(self, HlcState::Init)
    }
}

impl HlcMethods for HlcState {
    type Error = HlcFactoryError;
    fn receive(&self, remote: &HlcTimestamp) -> Result<HlcTimestamp, Self::Error> {
        let HlcState::Ready(hlc) = self else {
            return Err(HlcFactoryError::NotReady);
        };

        Ok(hlc.receive(remote)?)
    }
    fn tick(&self) -> Result<HlcTimestamp, Self::Error> {
        let HlcState::Ready(hlc) = self else {
            return Err(HlcFactoryError::NotReady);
        };

        Ok(hlc.tick()?)
    }
    fn latest_admissible(&self) -> Result<HlcTimestamp, Self::Error> {
        let HlcState::Ready(hlc) = self else {
            return Err(HlcFactoryError::NotReady);
        };

        Ok(hlc.latest_admissible()?)
    }
}

/// This solves an issue where Hlc needs a node_id which is derived from the address but the
/// address is located in the store but the store needs the handle but the handle needs the hlc
/// which needs the node_id.
#[derive(Clone)]
pub struct HlcFactory {
    hlc: Arc<Mutex<HlcState>>,
}

impl Default for HlcFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl HlcFactory {
    pub fn new() -> Self {
        Self {
            hlc: Arc::new(Mutex::new(HlcState::Init)),
        }
    }

    pub fn enable(&self, hlc: Hlc) {
        let mut guard = self.hlc.lock().unwrap();
        guard.ready(hlc);
    }

    pub fn is_ready(&self) -> bool {
        match self.hlc.lock() {
            Err(_) => false,
            Ok(g) => g.is_ready(),
        }
    }

    /// Restore the underlying clock's durable ordering floor.
    ///
    /// Startup must not silently continue if the clock is unavailable: doing so can create event
    /// timestamps behind already-persisted history after a wall-clock rollback.
    pub fn seed_from_history(&self, timestamp: HlcTimestamp) -> Result<(), HlcFactoryError> {
        let guard = self.hlc.lock()?;
        let HlcState::Ready(hlc) = &*guard else {
            return Err(HlcFactoryError::NotReady);
        };
        hlc.seed_from_history(timestamp);
        Ok(())
    }
}

impl HlcMethods for HlcFactory {
    type Error = HlcFactoryError;
    fn tick(&self) -> Result<HlcTimestamp, HlcFactoryError> {
        let guard = self.hlc.lock()?;
        guard.tick()
    }
    fn receive(&self, remote: &HlcTimestamp) -> Result<HlcTimestamp, HlcFactoryError> {
        let guard = self.hlc.lock()?;
        guard.receive(remote)
    }
    fn latest_admissible(&self) -> Result<HlcTimestamp, HlcFactoryError> {
        let guard = self.hlc.lock()?;
        guard.latest_admissible()
    }
}
