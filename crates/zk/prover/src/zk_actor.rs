// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Serial verification adapter over the node's shared bounded executor.

use actix::{Actor, AtomicResponse, Context, Handler, WrapFuture};
use e3_events::TypedEvent;
use e3_task_pool::{scoped_task_group, TaskPool, TaskPoolError, TaskTimeouts};
use tracing::{debug, error};

use crate::{ZkBackend, ZkProver};

use super::proof_verification::{
    ZkVerificationOutcome, ZkVerificationRequest, ZkVerificationResponse,
};

/// Coordinates verification without running blocking proof work on the actor runtime.
pub struct ZkActor {
    prover: ZkProver,
    task_pool: TaskPool,
    task_scope: String,
}

impl ZkActor {
    /// Use the same pool and scope as the node's compute dispatcher; no private pool is created.
    pub fn new(backend: &ZkBackend, task_pool: TaskPool, task_scope: String) -> Self {
        Self {
            prover: ZkProver::new(backend),
            task_pool,
            task_scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkBackend;
    use actix::{Message, Recipient};
    use e3_config::BBPath;
    use e3_events::{
        CircuitName, E3id, EncryptionKey, EventContext, InterfoldEventData, Proof, TestEvent,
        Unsequenced,
    };
    use e3_utils::ArcBytes;
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicBool, Ordering},
        time::Instant,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;

    struct Results(mpsc::UnboundedSender<ZkVerificationResponse>);

    impl Actor for Results {
        type Context = Context<Self>;
    }

    impl Handler<TypedEvent<ZkVerificationResponse>> for Results {
        type Result = ();

        fn handle(&mut self, msg: TypedEvent<ZkVerificationResponse>, _: &mut Self::Context) {
            self.0.send(msg.into_components().0).unwrap();
        }
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    struct Barrier;

    impl Handler<Barrier> for ZkActor {
        type Result = ();
        fn handle(&mut self, _: Barrier, _: &mut Self::Context) {}
    }

    fn request(
        sender: Recipient<TypedEvent<ZkVerificationResponse>>,
        party: u64,
    ) -> TypedEvent<ZkVerificationRequest> {
        let ec = EventContext::<Unsequenced>::from(InterfoldEventData::TestEvent(TestEvent::new(
            "verify", 0,
        )))
        .sequence(0);
        TypedEvent::new(
            ZkVerificationRequest {
                proof: Proof::new(
                    CircuitName::PkBfv,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&[2]),
                ),
                e3_id: E3id::new("7", 1),
                key: Arc::new(EncryptionKey::new(party, ArcBytes::from_bytes(&[3]))),
                sender,
                artifacts_dir: "test".to_owned(),
            },
            ec,
        )
    }

    #[actix::test]
    async fn verification_shares_admission_and_preserves_serial_barriers() {
        let temp = tempfile::tempdir().unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(temp.path().join("absent-bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );
        let pool = TaskPool::new(1, 1);
        let (release, released) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let blocker = {
            let pool = pool.clone();
            actix::spawn(async move {
                pool.spawn(
                    "other compute".to_owned(),
                    TaskTimeouts::default(),
                    move || {
                        let _ = started.send(());
                        let _ = released.recv();
                    },
                )
                .await
            })
        };
        running.await.unwrap();
        let actor = ZkActor::new(&backend, pool, "node".to_owned()).start();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let results = Results(tx).start().recipient();
        let first = actor.send(request(results.clone(), 1));
        let second = actor.send(request(results, 2));
        let barrier = actor.send(Barrier);
        tokio::pin!(barrier);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut barrier)
                .await
                .is_err()
        );
        assert!(
            rx.try_recv().is_err(),
            "C0 bypassed the shared pool's occupied permit"
        );
        release.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), barrier)
            .await
            .unwrap()
            .unwrap();
        first.await.unwrap();
        second.await.unwrap();
        for party in [1, 2] {
            let response = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.e3_id, E3id::new("7", 1));
            assert_eq!(response.key.party_id, party);
            assert!(matches!(
                response.outcome,
                ZkVerificationOutcome::InfrastructureError(_)
            ));
        }
        assert!(rx.try_recv().is_err());
    }

    #[actix::test]
    async fn queued_verification_cancellation_is_node_scoped_and_not_peer_failure() {
        let temp = tempfile::tempdir().unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(temp.path().join("absent-bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );
        let pool = TaskPool::new(1, 1);
        let (release, released) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let blocker = {
            let pool = pool.clone();
            actix::spawn(async move {
                pool.spawn(
                    "other compute".to_owned(),
                    TaskTimeouts::default(),
                    move || {
                        let _ = started.send(());
                        let _ = released.recv();
                    },
                )
                .await
            })
        };
        running.await.unwrap();
        let alice = ZkActor::new(&backend, pool.clone(), "alice".to_owned()).start();
        let bob = ZkActor::new(&backend, pool.clone(), "bob".to_owned()).start();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let results = Results(tx).start().recipient();
        let alice_request = alice.send(request(results.clone(), 1));
        let bob_request = bob.send(request(results, 2));
        pool.cancel_group(&scoped_task_group("alice", E3id::new("7", 1)));
        tokio::time::timeout(Duration::from_secs(2), alice.send(Barrier))
            .await
            .unwrap()
            .unwrap();
        alice_request.await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.key.party_id, 1);
        assert!(matches!(response.outcome, ZkVerificationOutcome::Cancelled));
        assert!(
            rx.try_recv().is_err(),
            "another node bypassed shared admission"
        );
        release.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), bob.send(Barrier))
            .await
            .unwrap()
            .unwrap();
        bob_request.await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.key.party_id, 2);
        assert!(
            matches!(response.outcome, ZkVerificationOutcome::InfrastructureError(ref error) if error.contains("Barretenberg binary not found"))
        );
    }

    #[cfg(unix)]
    #[actix::test]
    async fn verification_does_not_block_the_actor_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let started = temp.path().join("started");
        let release = temp.path().join("release");
        let bb = temp.path().join("bb");
        fs::write(
            &bb,
            format!(
                "#!/bin/sh\ntouch '{}'\nwhile [ ! -f '{}' ]; do sleep 0.01; done\n",
                started.display(),
                release.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bb, fs::Permissions::from_mode(0o755)).unwrap();
        let circuits = temp.path().join("circuits/test/recursive/dkg/pk");
        fs::create_dir_all(&circuits).unwrap();
        fs::write(circuits.join("pk.vk"), [1]).unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(bb),
            temp.path().join("circuits"),
            temp.path().join("work"),
        )
        .with_bb_timeout(Duration::from_secs(5));
        let actor = ZkActor::new(&backend, TaskPool::new(1, 1), "test-node".to_owned()).start();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let results = Results(tx).start();

        // An independent failsafe also releases the old blocking handler, so a regression fails
        // an assertion rather than hanging the Actix runtime and its timeout future forever.
        let watchdog_released = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let release = release.clone();
            let watchdog_released = watchdog_released.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !release.exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !release.exists() {
                    watchdog_released.store(true, Ordering::SeqCst);
                    fs::write(release, []).unwrap();
                }
            })
        };
        let verification = actor.send(request(results.recipient(), 0));
        tokio::time::timeout(Duration::from_secs(6), async {
            while !started.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        fs::write(release, []).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(6), rx.recv())
            .await
            .unwrap()
            .unwrap();
        verification.await.unwrap();
        watchdog.join().unwrap();
        assert!(matches!(response.outcome, ZkVerificationOutcome::Valid));
        assert!(
            !watchdog_released.load(Ordering::SeqCst),
            "proof verification blocked other actor-runtime futures"
        );
    }
}

impl Actor for ZkActor {
    type Context = Context<Self>;
}

impl Handler<TypedEvent<ZkVerificationRequest>> for ZkActor {
    type Result = AtomicResponse<Self, ()>;

    fn handle(
        &mut self,
        msg: TypedEvent<ZkVerificationRequest>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        debug!(
            "Verifying proof for circuit: {} (party {})",
            msg.proof.circuit, msg.key.party_id
        );

        let prover = self.prover.clone();
        let pool = self.task_pool.clone();
        let group = scoped_task_group(&self.task_scope, &msg.e3_id);
        // Preserve this actor's serial completion/barrier contract without blocking other actors.
        AtomicResponse::new(Box::pin(
            async move {
                let e3_id_str = msg.e3_id.to_string();
                let proof = msg.proof;
                let party_id = msg.key.party_id;
                let artifacts_dir = msg.artifacts_dir;
                let result = pool
                    .spawn_in_group(
                        group,
                        format!("C0 verification {e3_id_str}/{party_id}"),
                        TaskTimeouts::default(),
                        move || prover.verify_proof(&proof, &e3_id_str, party_id, &artifacts_dir),
                    )
                    .await;
                let response = TypedEvent::new(
                    match result {
                        Ok(Ok(true)) => {
                            debug!("Proof verification successful");
                            ZkVerificationResponse {
                                outcome: ZkVerificationOutcome::Valid,
                                e3_id: msg.e3_id,
                                key: msg.key,
                            }
                        }
                        Ok(Ok(false)) => {
                            error!("Proof verification failed");
                            ZkVerificationResponse {
                                outcome: ZkVerificationOutcome::Invalid,
                                e3_id: msg.e3_id,
                                key: msg.key,
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Proof verification error: {}", e);
                            ZkVerificationResponse {
                                outcome: ZkVerificationOutcome::InfrastructureError(e.to_string()),
                                e3_id: msg.e3_id,
                                key: msg.key,
                            }
                        }
                        Err(TaskPoolError::Cancelled(_)) => ZkVerificationResponse {
                            outcome: ZkVerificationOutcome::Cancelled,
                            e3_id: msg.e3_id,
                            key: msg.key,
                        },
                        Err(error) => ZkVerificationResponse {
                            outcome: ZkVerificationOutcome::InfrastructureError(error.to_string()),
                            e3_id: msg.e3_id,
                            key: msg.key,
                        },
                    },
                    ec,
                );

                // Send response back to the sender
                msg.sender.do_send(response);
            }
            .into_actor(self),
        ))
    }
}
