// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous, unit-testable domain services for the net crate.
//!
//! These contain all decision/state logic that the actix actors and transport layer rely on.
//! Nothing here touches actix, the event bus, channels, or libp2p directly.

pub(crate) mod correlator;
pub(crate) mod document_publishing;
pub(crate) mod event_conversion;
pub(crate) mod event_translation;
pub(crate) mod net_buffer;
pub(crate) mod net_event_batch;
pub(crate) mod peer_failure_tracker;
pub(crate) mod sync_coordinator;

pub use document_publishing::{datetime_to_instant_from_now, DocumentPublishingService};
pub use event_conversion::{EventConversionService, IncomingDocument};
pub use event_translation::EventTranslationService;
pub use sync_coordinator::{build_sync_batch, NetReadiness, ReadinessDecision, SyncBatchOutcome};
