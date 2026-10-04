// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! IO actor for ZK proof generation and verification.
//! This actor handles actual disk-based operations for proving and verifying.
//!
//! This is an IO actor - it performs file system operations.

use actix::{Actor, Context, Handler};
use e3_events::TypedEvent;
use tracing::{debug, error};

use crate::{ZkBackend, ZkProver};

use super::proof_verification::{
    ZkVerificationOutcome, ZkVerificationRequest, ZkVerificationResponse,
};

/// IO actor that handles ZK proof generation and verification.
pub struct ZkActor {
    prover: ZkProver,
}

impl ZkActor {
    pub fn new(backend: &ZkBackend) -> Self {
        Self {
            prover: ZkProver::new(backend),
        }
    }
}

impl Actor for ZkActor {
    type Context = Context<Self>;
}

impl Handler<TypedEvent<ZkVerificationRequest>> for ZkActor {
    type Result = ();

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

        let e3_id_str = msg.e3_id.to_string();
        let result =
            self.prover
                .verify_proof(&msg.proof, &e3_id_str, msg.key.party_id, &msg.artifacts_dir);

        let response = TypedEvent::new(
            match result {
                Ok(true) => {
                    debug!("Proof verification successful");
                    ZkVerificationResponse {
                        outcome: ZkVerificationOutcome::Valid,
                        e3_id: msg.e3_id,
                        key: msg.key,
                    }
                }
                Ok(false) => {
                    error!("Proof verification failed");
                    ZkVerificationResponse {
                        outcome: ZkVerificationOutcome::Invalid,
                        e3_id: msg.e3_id,
                        key: msg.key,
                    }
                }
                Err(e) => {
                    debug!("Proof verification error: {}", e);
                    ZkVerificationResponse {
                        outcome: ZkVerificationOutcome::InfrastructureError(e.to_string()),
                        e3_id: msg.e3_id,
                        key: msg.key,
                    }
                }
            },
            ec,
        );

        // Send response back to the sender
        msg.sender.do_send(response);
    }
}
