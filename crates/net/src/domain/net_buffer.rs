// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};

use crate::events::NetEvent;

/// Decision returned when a [`NetEventBufferState`] observes an incoming network event.
#[derive(Debug)]
pub(crate) enum BufferDecision {
    /// The event was buffered until syncing completes.
    Buffered,
    /// The event should be forwarded immediately.
    Forward(NetEvent),
}

/// Pure state machine controlling whether incoming [`NetEvent`]s are buffered while the node is
/// syncing or forwarded immediately once syncing has ended.
///
/// This holds no actix/bus/channel state — the owning actor performs the actual forwarding I/O
/// based on the decisions returned here.
#[derive(Debug)]
pub(crate) enum NetEventBufferState {
    Running,
    Syncing(Vec<NetEvent>),
}

impl NetEventBufferState {
    /// Create a new buffer in the syncing state.
    pub fn syncing() -> Self {
        Self::Syncing(Vec::new())
    }

    /// Observe an incoming event, deciding whether to buffer or forward it.
    pub fn observe(&mut self, event: NetEvent) -> BufferDecision {
        match self {
            Self::Syncing(buffer) => {
                buffer.push(event);
                BufferDecision::Buffered
            }
            Self::Running => BufferDecision::Forward(event),
        }
    }

    /// Transition to the running state, returning the events buffered while syncing so the
    /// caller can flush them.
    pub fn run(&mut self) -> Result<Vec<NetEvent>> {
        let Self::Syncing(buffer) = self else {
            bail!("Cannot change state to Running when state is {:?}", self);
        };
        let buffer = std::mem::take(buffer);
        *self = Self::Running;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::GossipData;

    fn event(byte: u8) -> NetEvent {
        NetEvent::GossipData(GossipData::GossipBytes(vec![byte]))
    }

    #[test]
    fn buffers_events_while_syncing() {
        let mut state = NetEventBufferState::syncing();
        assert!(matches!(state.observe(event(1)), BufferDecision::Buffered));
        assert!(matches!(state.observe(event(2)), BufferDecision::Buffered));
        let flushed = state.run().unwrap();
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn forwards_events_after_running() {
        let mut state = NetEventBufferState::syncing();
        state.run().unwrap();
        assert!(matches!(
            state.observe(event(7)),
            BufferDecision::Forward(_)
        ));
    }

    #[test]
    fn run_twice_is_an_error() {
        let mut state = NetEventBufferState::syncing();
        state.run().unwrap();
        assert!(state.run().is_err());
    }
}
