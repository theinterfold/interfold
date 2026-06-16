// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use e3_utils::major_issue;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    future::Future,
    pin::Pin,
};

use crate::{BusHandle, ErrorDispatcher};

use super::{InterfoldEvent, Unsequenced};

pub trait FromError {
    fn from_error(err_type: EType, error: impl Into<String>) -> Self;
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct InterfoldError {
    pub err_type: EType,
    pub message: String,
}

impl Display for InterfoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EType {
    Evm,
    KeyGeneration,
    PublickeyAggregation,
    IO,
    Net,
    PlaintextAggregation,
    Decryption,
    Sortition,
    Sync,
    Data,
    Event,
    Computation,
    DocumentPublishing,
}

impl InterfoldError {
    pub fn new(err_type: EType, message: impl Into<anyhow::Error>) -> Self {
        Self {
            err_type,
            message: message.into().to_string(),
        }
    }
}

impl FromError for InterfoldError {
    fn from_error(err_type: EType, error: impl Into<String>) -> Self {
        Self {
            err_type,
            message: error.into(),
        }
    }
}

/// Function to run a closure that returns a result. If result is an Err variant it is trapped and
/// sent to the bus as an ErrorEvent
pub fn trap<F>(err_type: EType, bus: &dyn ErrorDispatcher<InterfoldEvent<Unsequenced>>, runner: F)
where
    F: FnOnce() -> anyhow::Result<()>,
{
    match runner() {
        Ok(_) => (),
        Err(e) => bus.err(err_type, e),
    }
}

/// Function to accept a future that resolves to a result. If result is an Err variant it is trapped and
/// sent to the bus as an ErrorEvent
pub fn trap_fut<F>(
    err_type: EType,
    bus: &BusHandle,
    fut: F,
) -> Pin<Box<dyn Future<Output = ()> + Send>>
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let bus = bus.clone();
    Box::pin(async move {
        if let Err(e) = fut.await {
            bus.err(err_type, e);
        }
    })
}

// The following dispatchers should be used where you don't have the BusHandle available.

// A struct that panics on errors
pub struct PanicDispatcher;

impl Default for PanicDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicDispatcher {
    pub fn new() -> Self {
        Self {}
    }
}

impl ErrorDispatcher<InterfoldEvent<Unsequenced>> for PanicDispatcher {
    fn err(&self, _: EType, error: anyhow::Error) {
        panic!("{}", major_issue("Failure!", error));
    }
}

// A struct that warns on errors
pub struct WarningDispatcher;

impl Default for WarningDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl WarningDispatcher {
    pub fn new() -> Self {
        Self {}
    }
}
impl ErrorDispatcher<InterfoldEvent<Unsequenced>> for WarningDispatcher {
    fn err(&self, err_type: EType, error: anyhow::Error) {
        tracing::warn!("{:?} Failure! {}", err_type, error);
    }
}

// A struct that logs errors on errors
// Avoid using this over BusHandle
pub struct LogErrorDispatcher;

impl Default for LogErrorDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl LogErrorDispatcher {
    pub fn new() -> Self {
        Self {}
    }
}

impl ErrorDispatcher<InterfoldEvent<Unsequenced>> for LogErrorDispatcher {
    fn err(&self, err_type: EType, error: anyhow::Error) {
        tracing::error!("{:?} Failure! {}", err_type, error);
    }
}
