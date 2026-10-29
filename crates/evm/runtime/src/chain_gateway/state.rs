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
    /// A buffer or transition invariant failed. This state is terminal.
    Failed { reason: String },
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
    pub(crate) fn add_buffered_event(
        &mut self,
        event: InterfoldEvent<Unsequenced>,
        limit: usize,
    ) -> Result<()> {
        let (state, buffered) = match self {
            Self::Init { buffer, .. } => ("Init", buffer.len()),
            Self::ForwardToSyncActor(data) => ("ForwardToSyncActor", data.buffer.len()),
            Self::BufferUntilLive(buffer) => ("BufferUntilLive", buffer.len()),
            Self::Live => bail!("Cannot buffer an EVM event after the gateway is Live"),
            Self::Failed { reason } => bail!("EVM chain gateway already failed: {reason}"),
        };

        if buffered >= limit {
            let reason = format!(
                "EVM chain gateway {state} buffer reached its limit of {limit} events; capacity \
                 was exhausted before accepting the next event, so startup is stopping before \
                 Live and chain history must be replayed"
            );
            *self = Self::Failed {
                reason: reason.clone(),
            };
            bail!(reason);
        }

        match self {
            Self::Init { buffer, .. } | Self::BufferUntilLive(buffer) => buffer.push(event),
            Self::ForwardToSyncActor(data) => data.buffer.push(event),
            Self::Live | Self::Failed { .. } => {
                bail!("EVM chain gateway changed state while buffering an event")
            }
        }
        Ok(())
    }

    pub(crate) fn fail(&mut self, reason: impl Into<String>) {
        *self = Self::Failed {
            reason: reason.into(),
        };
    }

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
    use e3_events::InterfoldEvent;

    // A trivial sender stand-in so the state machine can be exercised without actix.
    #[derive(Clone, Debug, PartialEq)]
    struct FakeSender(u32);

    fn event(id: u64) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::test_event("buffer-boundary")
            .id(id)
            .build()
    }

    fn assert_overflow_fails_closed(status: &mut SyncStatus<FakeSender>, state: &str) {
        status.add_buffered_event(event(1), 2).unwrap();
        status.add_buffered_event(event(2), 2).unwrap();

        let error = status.add_buffered_event(event(3), 2).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(state), "{message}");
        assert!(message.contains("limit of 2 events"), "{message}");
        assert!(matches!(status, SyncStatus::Failed { .. }));

        let live_error = status.live().unwrap_err().to_string();
        assert!(live_error.contains("Cannot change state to Live"));
        assert!(matches!(status, SyncStatus::Failed { .. }));
    }

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

    #[test]
    fn init_accepts_the_boundary_then_overflow_prevents_live() {
        let mut status: SyncStatus<FakeSender> = SyncStatus::default();
        assert_overflow_fails_closed(&mut status, "Init");
    }

    #[test]
    fn forward_to_sync_accepts_the_boundary_then_overflow_prevents_live() {
        let mut status: SyncStatus<FakeSender> = SyncStatus::default();
        status.forward_to_sync_actor(FakeSender(1)).unwrap();
        assert_overflow_fails_closed(&mut status, "ForwardToSyncActor");
    }

    #[test]
    fn buffer_until_live_accepts_the_boundary_then_overflow_prevents_live() {
        let mut status: SyncStatus<FakeSender> = SyncStatus::default();
        status.forward_to_sync_actor(FakeSender(1)).unwrap();
        status.buffer_until_live().unwrap();
        assert_overflow_fails_closed(&mut status, "BufferUntilLive");
    }
}
