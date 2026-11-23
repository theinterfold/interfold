// SPDX-License-Identifier: LGPL-3.0-only

//! Public contribution admission and reconstruction from exactly the admitted polynomial openings.
use crate::ZkProver;
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use e3_events::{DecryptionshareCreated, E3id, Proof, ProofType};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::SynchronizedDecryptionPlan;
use e3_task_pool::TaskPool;
use e3_utils::ArcBytes;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName,
};
use num_bigint::{BigInt, Sign};
use std::{future::Future, pin::Pin, sync::Arc};

type ChainTiming =
    Arc<dyn Fn(E3id) -> Pin<Box<dyn Future<Output = Result<(u64, u64)>> + Send>> + Send + Sync>;

/// Shared execution capacity; the reader returns (frozen deadline, latest block time).
#[derive(Clone)]
pub struct DecryptionRuntime {
    pub prover: ZkProver,
    pub pool: TaskPool,
    pub task_scope: String,
    pub timing: ChainTiming,
}

impl DecryptionRuntime {
    pub async fn open_deadline(&self, id: &E3id, frozen: Option<u64>) -> Result<u64> {
        let (deadline, now) = (self.timing)(id.clone()).await?;
        ensure!(
            deadline != 0 && frozen.is_none_or(|d| d == deadline),
            "decryption deadline missing or changed"
        );
        ensure!(now <= deadline, "decryption deadline expired");
        Ok(deadline)
    }
}

pub fn validate_row(
    plan: &SynchronizedDecryptionPlan,
    owner: u32,
    proof: &Proof,
    share: &ArcBytes,
) -> Result<()> {
    ensure!(
        proof.circuit == CircuitName::ThresholdShareDecryption,
        "expected C6"
    );
    let cfg = Configs::for_profile(plan.profile(), plan.committee())?;
    let row = PublicSignals::decode(&cfg, proof.circuit, &proof.public_signals)?;
    ensure!(
        plan.matches_c6(owner, &row),
        "C6 differs from confirmed row"
    );
    let poly = e3_trbfv::helpers::try_poly_pb_from_bytes(share, &cfg.threshold)?;
    let commitment = e3_zk_witness::compute_threshold_decryption_share_commitment(
        &CrtPolynomial::from_fhe_polynomial(&poly),
        cfg.share_bit,
        cfg.threshold.degree(),
    );
    ensure!(
        row.decryption_share_commitment()
            .map(|f| BigInt::from_bytes_be(Sign::Plus, &f))
            == Some(commitment),
        "C6 differs from full polynomial"
    );
    Ok(())
}

pub fn authenticate(
    plan: &SynchronizedDecryptionPlan,
    bundle: &DecryptionshareCreated,
) -> Result<()> {
    let owner = u32::try_from(bundle.party_id)?;
    let signer = plan.signer(owner)?;
    let ([share], [signed]) = (
        bundle.decryption_share.as_slice(),
        bundle.signed_decryption_proofs.as_slice(),
    ) else {
        anyhow::bail!("expected one share and one signed proof")
    };
    ensure!(
        bundle.e3_id == *plan.e3_id()
            && bundle.node.parse::<Address>()? == signer
            && signed.payload.e3_id == bundle.e3_id
            && signed.payload.proof_type == ProofType::C6ThresholdShareDecryption
            && signed.verify_address(&signer)?,
        "wrong C6 signer, request or phase"
    );
    validate_row(plan, owner, &signed.payload.proof, share)
}
