// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod channel;

use actix::{Actor, Handler, Message};

/// Extension trait for synchronous message handling
pub trait NotifySync<M>
where
    M: Message,
    Self: Actor + Handler<M>,
{
    /// Handles a message immediately without queuing.
    /// Drop-in replacement for `ctx.notify(msg)` without interleaving other events.
    fn notify_sync(&mut self, ctx: &mut Self::Context, msg: M) -> <Self as Handler<M>>::Result {
        <Self as Handler<M>>::handle(self, msg, ctx)
    }
}

// Blanket implementation for all actors that handle the message
impl<A, M> NotifySync<M> for A
where
    A: Actor + Handler<M>,
    M: Message,
{
}
