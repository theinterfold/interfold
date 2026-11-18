// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Stops the node when an actor panics.
//!
//! The node starts all its actors on the thread that runs the actix system. When a handler panics,
//! the runtime ends only that actor, and the node keeps running without it. Actix supervision does
//! not help here: it restarts an actor that stops itself, but a panic also ends the supervisor.
//!
//! [`ActorPanics::watch`] installs a panic hook that records the first panic on that thread. The
//! start command waits for it, then stops the node with the normal shutdown barrier and exits with
//! an error. The event log stays, so the node recovers from it when its process manager starts it
//! again. A panic on another thread, such as a compute pool thread or a worker of the dashboard's
//! web server, is left to the code that runs that thread. The compute pool, for example, returns it
//! as an error of its job.

use std::panic::PanicHookInfo;
use std::thread::ThreadId;

use tokio::sync::watch;

/// The first panic on the thread that runs the node's actors.
pub struct ActorPanics(watch::Receiver<Option<String>>);

impl ActorPanics {
    /// Install the panic hook for the current thread. Call it one time per process, on the thread
    /// that runs the actix system, before the node starts actors. The hook calls the previous hook
    /// first, so the panic message is still printed.
    pub fn watch() -> Self {
        let (signal, panics) = watch::channel(None);
        let actor_thread = std::thread::current().id();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            previous(info);
            if !on_thread(actor_thread) {
                return;
            }
            let failure = describe(info);
            signal.send_if_modified(|first| {
                if first.is_some() {
                    return false;
                }
                *first = Some(failure);
                true
            });
        }));
        Self(panics)
    }

    /// Wait for the first panic on the thread that runs the node's actors, and describe it.
    pub async fn first(&mut self) -> String {
        match self.0.wait_for(Option::is_some).await {
            Ok(failure) => failure.clone().unwrap_or_default(),
            // The hook owns the sender for the lifetime of the process. If other code removes the
            // hook, no panic is reported.
            Err(_) => std::future::pending().await,
        }
    }
}

fn on_thread(thread: ThreadId) -> bool {
    std::thread::current().id() == thread
}

fn describe(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_owned());
    match info.location() {
        Some(location) => format!("{message} (at {location})"),
        None => message,
    }
}
