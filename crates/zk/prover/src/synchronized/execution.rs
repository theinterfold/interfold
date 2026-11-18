// SPDX-License-Identifier: LGPL-3.0-only

//! Explicit definition execution shared by guarded workers and isolated qualification. This API
//! does not admit a request/profile or authenticate the actor's expected context and child proofs.

use super::{
    provenance::{
        prove_dealer, prove_recipient, verify_recipient_result, DealerJoin, ExpectedSetup,
        RecipientJoin, Rejection,
    },
    publication::{
        prove_publication, verify_publication_result, ExpectedPublication, PublicationJoin,
    },
    request_binding,
};
use crate::ZkProver;
use anyhow::anyhow;
use e3_events::{
    E3id, SynchronizedDkgProofJob, SynchronizedDkgProofRequest, SynchronizedDkgProofResponse,
};
use e3_zk_config::synchronized::Configs;
use fhe::bfv::PublicKey;
use fhe_traits::DeserializeParametrized;

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error(transparent)]
    InvalidParams(anyhow::Error),
    #[error(transparent)]
    Local(anyhow::Error),
}

impl From<anyhow::Error> for ExecutionError {
    fn from(error: anyhow::Error) -> Self {
        match error.downcast_ref::<e3_zk_witness::WitnessError>() {
            Some(e3_zk_witness::WitnessError::VerificationKey(_)) | None => Self::Local(error),
            Some(_) => Self::InvalidParams(error),
        }
    }
}

fn generated_rejection(rejection: Rejection, mismatch: &'static str) -> ExecutionError {
    match rejection {
        Rejection::Expectations => ExecutionError::InvalidParams(anyhow!(mismatch)),
        Rejection::VerificationKey => ExecutionError::Local(anyhow!(
            "locally generated synchronized proof differs from the local verifier keys"
        )),
        Rejection::Proof => ExecutionError::Local(anyhow!(
            "locally generated synchronized proof was cryptographically rejected"
        )),
    }
}

/// Runtime callers must admit the profile before invoking this definition API. The expected rows
/// and authenticated children remain the actor's responsibility; an infrastructure error is never
/// a peer-invalid verdict.
pub fn execute_definition(
    prover: &ZkProver,
    id: &E3id,
    request: &SynchronizedDkgProofRequest,
    job: &str,
) -> Result<SynchronizedDkgProofResponse, ExecutionError> {
    let config = Configs::for_profile(request.params_profile, request.committee_size)
        .map_err(|error| ExecutionError::InvalidParams(error.into()))?;
    let binding =
        request_binding(&config, &request.context, id).map_err(ExecutionError::InvalidParams)?;
    let namespace = request
        .params_profile
        .artifacts_dir_for_committee(request.committee_size)
        .map_err(|error| ExecutionError::InvalidParams(error.into()))?;
    match &request.job {
        SynchronizedDkgProofJob::Dealer { c1, c2, c3 } => {
            let proof = prove_dealer(
                prover,
                &config,
                &request.context,
                id,
                &DealerJoin { c1, c2, c3 },
                job,
            )?;
            let verified = prover
                .verify_fold_proof(&proof, job, request.context.party_id as u64, &namespace)
                .map_err(|error| ExecutionError::Local(error.into()))?;
            if !verified {
                return Err(ExecutionError::Local(anyhow!(
                    "locally generated synchronized dealer proof was rejected"
                )));
            }
            Ok(SynchronizedDkgProofResponse::Dealer { proof })
        }
        SynchronizedDkgProofJob::Recipient {
            c0,
            own_c2,
            c4,
            dealers,
            expected,
        } => {
            if expected.binding != binding || expected.recipient != request.context.party_id {
                return Err(ExecutionError::InvalidParams(anyhow!(
                    "recipient expectations belong to another setup or owner"
                )));
            }
            let proof = prove_recipient(
                prover,
                &config,
                &request.context,
                id,
                &RecipientJoin {
                    dealer_ids: &expected.dealers,
                    c0,
                    own_c2,
                    c4,
                    nodes: dealers,
                },
                job,
            )?;
            let setup = verify_recipient_result(
                prover,
                &config,
                &request.context,
                id,
                &ExpectedSetup {
                    dealers: &expected.dealers,
                    threshold_keys: &expected.threshold_keys,
                    dealer_batch: expected.dealer_batch,
                    sk_commitment: expected.sk_commitment,
                    key_bundle: expected.key_bundle,
                },
                &proof,
                job,
            )
            .map_err(ExecutionError::Local)?
            .map_err(|rejection| {
                generated_rejection(
                    rejection,
                    "locally generated recipient setup differs from admitted expectations",
                )
            })?;
            Ok(SynchronizedDkgProofResponse::Recipient {
                proof,
                setup: (&setup).into(),
            })
        }
        SynchronizedDkgProofJob::Publication {
            recipients,
            c5,
            expected,
        } => {
            let public_key = PublicKey::from_bytes(&expected.public_key, &config.threshold)
                .map_err(|error| ExecutionError::InvalidParams(error.into()))?;
            if public_key.c.len() != 2 {
                return Err(ExecutionError::InvalidParams(anyhow!(
                    "publication key has another component count"
                )));
            }
            let proof = prove_publication(
                prover,
                &config,
                &request.context,
                id,
                &PublicationJoin {
                    dealers: &expected.dealers,
                    recipients,
                    c5,
                },
                job,
            )?;
            verify_publication_result(
                prover,
                &config,
                &request.context,
                id,
                &ExpectedPublication {
                    dealers: &expected.dealers,
                    threshold_keys: &expected.threshold_keys,
                    dealer_batch: expected.dealer_batch,
                    sk_commitments: &expected.sk_commitments,
                    key_bundles: &expected.key_bundles,
                    public_key: &public_key,
                },
                &proof,
                job,
            )
            .map_err(ExecutionError::Local)?
            .map_err(|rejection| {
                generated_rejection(
                    rejection,
                    "locally generated publication differs from admitted native/setup expectations",
                )
            })?;
            Ok(SynchronizedDkgProofResponse::Publication { proof })
        }
    }
}
