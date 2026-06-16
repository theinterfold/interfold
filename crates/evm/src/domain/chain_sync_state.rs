// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure state machine coordinating event flow through the `EvmChainGateway`.
//!
//! `Init -> ForwardToSyncActor -> BufferUntilLive -> Live`
//!
//! The machine is generic over the sync-actor sender type `S` so it stays free
//! of any actix runtime types; the owning actor performs the actual sends.

use std::mem::take;

use crate::messages::HistoricalSyncComplete;
use anyhow::{bail, Result};
use e3_events::{InterfoldEvent, Unsequenced};

#[derive(Clone, Debug)]
pub(crate) struct ForwardToSyncActorData<S> {
    pub(crate) sender: Option<S>,
    pub(crate) buffer: Vec<InterfoldEvent<Unsequenced>>,
}

impl<S> Default for ForwardToSyncActorData<S> {
    fn default() -> Self {
        Self {
            sender: None,
            buffer: Vec::new(),
        }
    }
}

impl<S> ForwardToSyncActorData<S> {
    pub(crate) fn add_event(&mut self, event: InterfoldEvent<Unsequenced>) {
        self.buffer.push(event);
    }
}

/// State machine coordinating event flow through the `EvmChainGateway`.
#[derive(Clone, Debug)]
pub(crate) enum SyncStatus<S> {
    /// Buffers events until `HistoricalEvmSyncStart` arrives.
    Init {
        buffer: Vec<InterfoldEvent<Unsequenced>>,
        pending_sync_complete: Option<HistoricalSyncComplete>,
    },
    /// Forward events to the sync actor for ordering.
    ForwardToSyncActor(ForwardToSyncActorData<S>),
    /// Once the chain has completed historical sync then we buffer all "live"
    /// events until sync is complete.
    BufferUntilLive(Vec<InterfoldEvent<Unsequenced>>),
    /// Forward all events directly to the bus.
    Live,
}

impl<S> Default for SyncStatus<S> {
    fn default() -> Self {
        Self::Init {
            buffer: Vec::new(),
            pending_sync_complete: None,
        }
    }
}

impl<S: std::fmt::Debug> SyncStatus<S> {
    pub(crate) fn forward_to_sync_actor(
        &mut self,
        sender: S,
    ) -> Result<(
        Vec<InterfoldEvent<Unsequenced>>,
        Option<HistoricalSyncComplete>,
    )> {
        let Self::Init {
            buffer,
            pending_sync_complete,
        } = self
        else {
            bail!(
                "Cannot change state to ForwardToSyncActor when state is {:?}",
                self
            );
        };

        let buffer = std::mem::take(buffer);
        let pending = pending_sync_complete.take();
        *self = SyncStatus::ForwardToSyncActor(ForwardToSyncActorData {
            sender: Some(sender),
            buffer: Vec::new(),
        });
        Ok((buffer, pending))
    }

    pub(crate) fn buffer_until_live(&mut self) -> Result<ForwardToSyncActorData<S>> {
        let Self::ForwardToSyncActor(sender) = self else {
            bail!(
                "Cannot change state to BufferUntilLive when state is {:?}",
                self
            );
        };

        let state_data = take(sender);
        *self = SyncStatus::BufferUntilLive(vec![]);
        Ok(state_data)
    }

    pub(crate) fn live(&mut self) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
        let Self::BufferUntilLive(buffer) = self else {
            bail!("Cannot change state to Live when state is {:?}", self);
        };
        let buffer = std::mem::take(buffer);
        *self = SyncStatus::Live;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trivial sender stand-in so the state machine can be exercised without actix.
    #[derive(Clone, Debug, PartialEq)]
    struct FakeSender(u32);

    #[test]
    fn test_happy_path_transitions() {
        let mut status: SyncStatus<FakeSender> = SyncStatus::default();
        assert!(matches!(status, SyncStatus::Init { .. }));

        let (buffer, pending) = status.forward_to_sync_actor(FakeSender(7)).unwrap();
        assert!(buffer.is_empty());
        assert!(pending.is_none());
        assert!(matches!(status, SyncStatus::ForwardToSyncActor(_)));

        let data = status.buffer_until_live().unwrap();
        assert_eq!(data.sender, Some(FakeSender(7)));
        assert!(matches!(status, SyncStatus::BufferUntilLive(_)));

        let buffered = status.live().unwrap();
        assert!(buffered.is_empty());
        assert!(matches!(status, SyncStatus::Live));
    }

    #[test]
    fn test_invalid_transition_from_init_to_live_errors() {
        let mut status: SyncStatus<FakeSender> = SyncStatus::default();
        assert!(status.live().is_err());
        assert!(status.buffer_until_live().is_err());
    }

    #[test]
    fn test_forward_drains_init_buffer_and_pending() {
        let pending = HistoricalSyncComplete::new(1, None);
        let mut status: SyncStatus<FakeSender> = SyncStatus::Init {
            buffer: Vec::new(),
            pending_sync_complete: Some(pending.clone()),
        };
        let (_buffer, returned_pending) = status.forward_to_sync_actor(FakeSender(1)).unwrap();
        assert_eq!(returned_pending, Some(pending));
    }
}
