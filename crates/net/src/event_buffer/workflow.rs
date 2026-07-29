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
    Forward(Box<NetEvent>),
}

/// Pure state machine controlling whether incoming [`NetEvent`]s are buffered while the node is
/// syncing or forwarded immediately once syncing has ended.
///
/// This holds no actix/bus/channel state — the owning actor performs the actual forwarding I/O
/// based on the decisions returned here.
#[derive(Debug)]
pub(crate) enum NetEventBufferState {
    Running,
    Syncing {
        events: Vec<NetEvent>,
        buffered_bytes: usize,
    },
    Failed(String),
}

impl NetEventBufferState {
    /// Create a new buffer in the syncing state.
    pub fn syncing() -> Self {
        Self::Syncing {
            events: Vec::new(),
            buffered_bytes: 0,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Observe an incoming event, deciding whether to buffer or forward it.
    pub fn observe(
        &mut self,
        event: NetEvent,
        event_bytes: usize,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<BufferDecision> {
        match self {
            Self::Syncing {
                events,
                buffered_bytes,
            } => {
                let next_bytes = buffered_bytes.checked_add(event_bytes).ok_or_else(|| {
                    anyhow::anyhow!("network startup buffer byte accounting overflowed")
                })?;
                if events.len() >= max_events || next_bytes > max_bytes {
                    let reason = format!(
                        "network startup buffer limit exceeded before accepting the next event: \
                         events={}/{max_events}, bytes={}/{max_bytes}, next_event_bytes={event_bytes}",
                        events.len(), buffered_bytes
                    );
                    *self = Self::Failed(reason.clone());
                    bail!(reason);
                }
                events.push(event);
                *buffered_bytes = next_bytes;
                Ok(BufferDecision::Buffered)
            }
            Self::Running => Ok(BufferDecision::Forward(Box::new(event))),
            Self::Failed(reason) => bail!("network startup buffer already failed: {reason}"),
        }
    }

    /// Transition to the running state, returning the events buffered while syncing so the
    /// caller can flush them.
    pub fn run(&mut self) -> Result<Vec<NetEvent>> {
        let Self::Syncing { events, .. } = self else {
            bail!("Cannot change state to Running when state is {:?}", self)
        };
        let buffer = std::mem::take(events);
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
        assert!(matches!(
            state.observe(event(1), 1, 2, 2).unwrap(),
            BufferDecision::Buffered
        ));
        assert!(matches!(
            state.observe(event(2), 1, 2, 2).unwrap(),
            BufferDecision::Buffered
        ));
        let flushed = state.run().unwrap();
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn forwards_events_after_running() {
        let mut state = NetEventBufferState::syncing();
        state.run().unwrap();
        assert!(matches!(
            state.observe(event(7), 1, 1, 1).unwrap(),
            BufferDecision::Forward(_)
        ));
    }

    #[test]
    fn run_twice_is_an_error() {
        let mut state = NetEventBufferState::syncing();
        state.run().unwrap();
        assert!(state.run().is_err());
    }

    #[test]
    fn event_count_overflow_is_terminal() {
        let mut state = NetEventBufferState::syncing();
        state.observe(event(1), 1, 1, 10).unwrap();
        let error = state.observe(event(2), 1, 1, 10).unwrap_err().to_string();
        assert!(error.contains("events=1/1"), "{error}");
        assert!(matches!(state, NetEventBufferState::Failed(_)));
        assert!(state.run().is_err());
    }

    #[test]
    fn byte_overflow_rejects_event_before_retaining_it() {
        let mut state = NetEventBufferState::syncing();
        state.observe(event(1), 4, 10, 5).unwrap();
        let error = state.observe(event(2), 2, 10, 5).unwrap_err().to_string();
        assert!(error.contains("bytes=4/5"), "{error}");
        assert!(error.contains("next_event_bytes=2"), "{error}");
        assert!(matches!(state, NetEventBufferState::Failed(_)));
    }
}
