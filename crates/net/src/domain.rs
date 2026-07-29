// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure services stored with their network capabilities.
//!
//! These contain all decision/state logic that the actix actors and transport layer rely on.
//! Nothing here touches actix, the event bus, channels, or libp2p directly.

#[path = "network_sync/correlator.rs"]
pub(crate) mod correlator;
#[path = "document_publishing/workflow.rs"]
pub(crate) mod document_publishing;
#[path = "event_conversion/workflow.rs"]
pub(crate) mod event_conversion;
#[path = "event_translation/workflow.rs"]
pub(crate) mod event_translation;
#[path = "event_buffer/workflow.rs"]
pub(crate) mod net_buffer;
#[path = "event_buffer/model.rs"]
pub(crate) mod net_event_batch;
#[path = "network_status.rs"]
mod network_status;
#[path = "peer_failure_tracker.rs"]
pub(crate) mod peer_failure_tracker;
#[path = "network_sync/workflow.rs"]
pub(crate) mod sync_coordinator;
#[path = "network_sync/wire.rs"]
pub(crate) mod wire;

pub use document_publishing::{datetime_to_instant_from_now, DocumentPublishingService};
pub use event_conversion::{EventConversionService, IncomingDocument};
pub use event_translation::EventTranslationService;
pub use network_status::{AuthenticatedPeer, ConnectedPeer, NetworkSnapshot, NetworkStatus};
pub use sync_coordinator::{build_sync_batch, NetReadiness, ReadinessDecision, SyncBatchOutcome};
