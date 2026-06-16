// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Thin actix actor shells. These contain no business logic — they wire bus/network events to the
//! pure services in [`crate::domain`] and perform the resulting I/O.

mod document_publisher;
mod net_event_buffer;
mod net_event_translator;
mod net_sync_manager;

pub use document_publisher::{
    handle_document_published_notification, handle_publish_document_requested, DocumentPublisher,
    EventConverter,
};
pub use net_event_translator::NetEventTranslator;

// Internal wiring helpers used by `setup_net`; not part of the public API.
pub(crate) use net_event_buffer::NetEventBuffer;
pub(crate) use net_sync_manager::NetSyncManager;
