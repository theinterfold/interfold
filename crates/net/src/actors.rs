// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of thin actors stored with their network capabilities.

#[path = "document_publishing/actor.rs"]
mod document_publisher;
#[path = "event_conversion/actor.rs"]
mod event_converter;
#[path = "event_buffer/actor.rs"]
mod net_event_buffer;
#[path = "event_translation/actor.rs"]
mod net_event_translator;
#[path = "network_sync/actor.rs"]
mod net_sync_manager;

pub use document_publisher::{
    handle_document_published_notification, handle_publish_document_requested,
    recover_document_state, DocumentPublisher, RecoveredDocumentState,
};
pub use event_converter::EventConverter;
pub use net_event_buffer::{
    NetEventBufferHandle, DEFAULT_MAX_BUFFERED_NET_BYTES, DEFAULT_MAX_BUFFERED_NET_EVENTS,
};
pub use net_event_translator::NetEventTranslator;

// Internal wiring helpers used by `setup_net`; not part of the public API.
pub(crate) use net_event_buffer::NetEventBuffer;
pub(crate) use net_sync_manager::NetSyncManager;
