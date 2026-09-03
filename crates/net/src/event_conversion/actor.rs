// SPDX-License-Identifier: LGPL-3.0-only

//! Translate between typed protocol artifacts and network documents.

use crate::domain::{EventConversionService, IncomingDocument};
use actix::prelude::*;
use anyhow::Result;
use e3_events::{
    prelude::*, trap, BusHandle, DecryptionKeyShared, DocumentReceived, EType,
    EncryptionKeyCreated, EventType, InterfoldEvent, InterfoldEventData, RelinCeremonyShare,
    ThresholdShareCreated, TypedEvent,
};
use e3_utils::NotifySync;

/// Converts between internal events and network documents.
///
/// Responsibilities:
/// - Outgoing: Converts ThresholdShareCreated → party-filtered PublishDocumentRequested
/// - Incoming: Converts DocumentReceived → ThresholdShareCreated/EncryptionKeyCreated
///
/// The conversion logic lives in [`EventConversionService`]; this actor only publishes the
/// resulting events on the bus.
pub struct EventConverter {
    bus: BusHandle,
}

impl EventConverter {
    pub fn new(bus: &BusHandle) -> Self {
        Self { bus: bus.clone() }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        let addr = Self::new(bus).start();
        bus.subscribe(EventType::ThresholdShareCreated, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyCreated, addr.clone().into());
        bus.subscribe(EventType::DecryptionKeyShared, addr.clone().into());
        bus.subscribe(EventType::RelinCeremonyShare, addr.clone().into());
        bus.subscribe(EventType::DocumentReceived, addr.clone().into());
        addr
    }

    fn handle_threshold_share_created(&self, msg: TypedEvent<ThresholdShareCreated>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::threshold_share_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    fn handle_encryption_key_created(&self, msg: TypedEvent<EncryptionKeyCreated>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::encryption_key_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    fn handle_decryption_key_shared(&self, msg: TypedEvent<DecryptionKeyShared>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::decryption_key_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    fn handle_relin_ceremony_share(&self, msg: TypedEvent<RelinCeremonyShare>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::relin_share_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    /// Convert received document to internal events.
    /// Note: Filtering already happened in DocumentPublisher before DHT fetch.
    fn handle_document_received(&self, msg: TypedEvent<DocumentReceived>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        match EventConversionService::decode_received(&msg.meta, &msg.value)? {
            IncomingDocument::ThresholdShare(evt) => {
                self.bus.publish(evt, ctx)?;
            }
            IncomingDocument::EncryptionKey(evt) => {
                self.bus.publish(evt, ctx)?;
            }
            IncomingDocument::DecryptionKey(evt) => {
                self.bus.publish(evt, ctx)?;
            }
            IncomingDocument::RelinShare(evt) => {
                self.bus.publish(evt, ctx)?;
            }
        }
        Ok(())
    }
}

impl Actor for EventConverter {
    type Context = actix::Context<Self>;
}

impl Handler<InterfoldEvent> for EventConverter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        match data {
            InterfoldEventData::ThresholdShareCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DecryptionKeyShared(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::RelinCeremonyShare(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DocumentReceived(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ThresholdShareCreated>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_threshold_share_created(msg),
        )
    }
}

impl Handler<TypedEvent<EncryptionKeyCreated>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_encryption_key_created(msg),
        )
    }
}

impl Handler<TypedEvent<DecryptionKeyShared>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionKeyShared>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_decryption_key_shared(msg),
        )
    }
}

impl Handler<TypedEvent<DocumentReceived>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DocumentReceived>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_document_received(msg),
        )
    }
}

impl Handler<TypedEvent<RelinCeremonyShare>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<RelinCeremonyShare>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_relin_ceremony_share(msg),
        )
    }
}
