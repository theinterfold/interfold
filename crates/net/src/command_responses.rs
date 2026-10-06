// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Correlation of network command results with the callers that wait for them.
//!
//! A caller registers the correlation id of its command before it sends the command. The event
//! channel then gives the result event to that caller through a oneshot channel, in addition to
//! its broadcast. A caller that reads its result this way cannot lose it to broadcast lag.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
};

use anyhow::{anyhow, bail, Result};
use e3_events::CorrelationId;
use tokio::sync::oneshot;

use crate::events::NetEvent;

/// The callers that wait for a command result, by the correlation id of the command.
#[derive(Debug, Default)]
pub(crate) struct PendingResponses {
    waiters: Mutex<HashMap<CorrelationId, oneshot::Sender<NetEvent>>>,
}

impl PendingResponses {
    /// Registers a caller for the result of the command with this correlation id.
    pub(crate) fn register(self: &Arc<Self>, id: CorrelationId) -> Result<PendingResponse> {
        let (sender, receiver) = oneshot::channel();
        let mut waiters = self.waiters();
        if waiters.contains_key(&id) {
            bail!("a caller already waits for the result of command {id}");
        }
        waiters.insert(id, sender);
        Ok(PendingResponse {
            id,
            pending: Arc::downgrade(self),
            receiver,
        })
    }

    /// Gives a copy of the event to the caller that waits for its correlation id. Returns true
    /// when a caller took the event.
    pub(crate) fn deliver(&self, event: &NetEvent) -> bool {
        let Some(id) = event.correlation_id() else {
            return false;
        };
        let Some(waiter) = self.waiters().remove(&id) else {
            return false;
        };
        waiter.send(event.clone()).is_ok()
    }

    fn waiters(&self) -> MutexGuard<'_, HashMap<CorrelationId, oneshot::Sender<NetEvent>>> {
        // The lock guards only map operations, which cannot leave the map inconsistent.
        self.waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The result of one command. Dropping it before the result arrives removes the registration.
#[derive(Debug)]
pub(crate) struct PendingResponse {
    id: CorrelationId,
    pending: Weak<PendingResponses>,
    receiver: oneshot::Receiver<NetEvent>,
}

impl PendingResponse {
    /// Waits for the result event. Fails when the event channel closes first.
    pub(crate) async fn recv(mut self) -> Result<NetEvent> {
        (&mut self.receiver).await.map_err(|_| {
            anyhow!(
                "network event channel closed before the result of command {}",
                self.id
            )
        })
    }
}

impl Drop for PendingResponse {
    fn drop(&mut self) {
        // Close first, so the check below removes only this registration and never a later one
        // for the same id.
        self.receiver.close();
        let Some(pending) = self.pending.upgrade() else {
            return;
        };
        let mut waiters = pending.waiters();
        if waiters
            .get(&self.id)
            .is_some_and(|sender| sender.is_closed())
        {
            waiters.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::OutgoingRequestFailed;

    fn result_of(correlation_id: CorrelationId) -> NetEvent {
        NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
            correlation_id,
            error: "refused".to_owned(),
        })
    }

    #[test]
    fn an_abandoned_wait_takes_no_result_and_frees_its_id() -> Result<()> {
        let pending = Arc::new(PendingResponses::default());
        let id = CorrelationId::new();

        let first = pending.register(id)?;
        assert!(pending.register(id).is_err(), "one caller per command");
        drop(first);

        assert!(!pending.deliver(&result_of(id)));
        let _second = pending.register(id)?;
        assert!(pending.deliver(&result_of(id)));
        Ok(())
    }
}
