// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The start command stops the node when an actor panics. The panic hook is process-wide, so this
//! binary has one test.

use std::time::Duration;

use actix::prelude::*;
use e3_entrypoint::actor_panics::ActorPanics;

struct FailingActor;

impl Actor for FailingActor {
    type Context = Context<Self>;
}

#[derive(Message)]
#[rtype(result = "()")]
struct Fail;

impl Handler<Fail> for FailingActor {
    type Result = ();

    fn handle(&mut self, _: Fail, _: &mut Self::Context) -> Self::Result {
        panic!("the handler failed on purpose");
    }
}

#[actix::test]
async fn a_panic_in_an_actor_is_reported_but_a_panic_on_another_thread_is_not() {
    let mut panics = ActorPanics::watch();

    // Another thread, like a compute pool thread, handles its own panics.
    let worker = std::thread::spawn(|| panic!("the worker failed on purpose"));
    assert!(worker.join().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), panics.first())
            .await
            .is_err(),
        "a panic on another thread must not stop the node"
    );

    let actor = FailingActor.start();
    assert!(
        actor.send(Fail).await.is_err(),
        "the handler panics before it replies"
    );
    let failure = tokio::time::timeout(Duration::from_secs(10), panics.first())
        .await
        .expect("the actor panic is reported");
    assert!(
        failure.contains("the handler failed on purpose"),
        "unexpected description: {failure}"
    );
    assert!(
        failure.contains("actor_panic_stop.rs"),
        "no location: {failure}"
    );

    // Without the hook nothing else notices: the runtime caught the panic and ended only the actor.
    assert!(!actor.connected());
}
