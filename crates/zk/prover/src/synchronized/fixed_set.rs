// SPDX-License-Identifier: LGPL-3.0-only

//! Public contribution admission and reconstruction from exactly the admitted polynomial openings.
use super::{
    decryption::{prove_decryption, verify_decryption, ExpectedDecryption},
    provenance::prove,
};
use crate::ZkProver;
use alloy::primitives::Address;
use anyhow::{ensure, Context, Result};
use e3_events::{DecryptionshareCreated, E3id, PlaintextAggregated, Proof, ProofType};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_request::canonical_key::SynchronizedDecryptionPlan;
use e3_task_pool::TaskPool;
use e3_utils::ArcBytes;
use e3_zk_config::{
    synchronized::{public_signals::PublicSignals, Configs},
    CircuitName, CircuitVariant, MAX_MSG_NON_ZERO_COEFFS,
};
use e3_zk_witness::synchronized::plaintext_aggregation::{prepare, Contribution};
use fhe::{
    bfv::{Ciphertext, Encoding},
    trbfv::{DecryptionShare, SynchronizedDecryptor},
};
use fhe_traits::{DeserializeParametrized, FheDecoder};
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

/// A completed invalid verification frees the slot; backend errors leave the candidate retryable.
pub fn verify_contribution(
    prover: &ZkProver,
    plan: &SynchronizedDecryptionPlan,
    bundle: &DecryptionshareCreated,
    job: &str,
) -> Result<bool> {
    if authenticate(plan, bundle).is_err() {
        return Ok(false);
    }
    super::decryption::child_key(
        prover,
        &Configs::for_profile(plan.profile(), plan.committee())?,
        CircuitName::ThresholdShareDecryption,
    )?;
    let namespace = plan
        .profile()
        .artifacts_dir_for_committee(plan.committee())?;
    Ok(prover.verify_proof(
        &bundle.signed_decryption_proofs[0].payload.proof,
        job,
        bundle.party_id,
        &namespace,
    )?)
}

pub fn verify_saved_result(
    prover: &ZkProver,
    plan: &SynchronizedDecryptionPlan,
    bundles: &[DecryptionshareCreated],
    saved: &PlaintextAggregated,
    job: &str,
) -> Result<bool> {
    let ([proof], [bytes]) = (
        saved.decryption_aggregator_proofs.as_slice(),
        saved.decrypted_output.as_slice(),
    ) else {
        return Ok(false);
    };
    if saved.e3_id != *plan.e3_id()
        || bytes.len() != 8 * MAX_MSG_NON_ZERO_COEFFS
        || bundles.len() != plan.designated().len()
    {
        return Ok(false);
    }
    let mut offset = 64;
    for (bundle, owner) in bundles.iter().zip(plan.designated()) {
        let [signed] = bundle.signed_decryption_proofs.as_slice() else {
            return Ok(false);
        };
        let row = &*signed.payload.proof.public_signals;
        if bundle.party_id != u64::from(*owner)
            || proof.public_signals.get(offset..offset + row.len()) != Some(row)
        {
            return Ok(false);
        }
        offset += row.len();
    }
    let message: Vec<_> = bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let a = plan.authority();
    let expected = ExpectedDecryption {
        setup: plan.setup_binding(),
        domain: plan.domain(),
        ciphertext_commitment: plan.ciphertext_commitment(),
        roster: &a.party_ids,
        sk_commitments: &a.sk_agg_commits,
        key_bundles: &a.key_bundle_commits,
        message: &message,
    };
    verify_decryption(
        prover,
        &Configs::for_profile(plan.profile(), plan.committee())?,
        &expected,
        proof,
        job,
    )
}

/// Called only with independently verified C6s. The outer circuit also verifies their bodies.
pub fn reconstruct(
    prover: &ZkProver,
    plan: &SynchronizedDecryptionPlan,
    bytes: &ArcBytes,
    bundles: &[DecryptionshareCreated],
    job: &str,
) -> Result<PlaintextAggregated> {
    ensure!(
        bundles
            .iter()
            .map(|b| b.party_id)
            .eq(plan.designated().iter().copied().map(u64::from)),
        "incomplete or unordered designated set"
    );
    let cfg = Configs::for_profile(plan.profile(), plan.committee())?;
    super::decryption::child_key(prover, &cfg, CircuitName::ThresholdShareDecryption)?;
    super::decryption::child_key(prover, &cfg, CircuitName::DecryptedSharesAggregation)?;
    let ct = Ciphertext::from_bytes(bytes, &cfg.threshold)?;
    let coords: Vec<_> = plan.designated().iter().map(|&i| i as usize + 1).collect();
    let mut shares = Vec::new();
    let mut proofs = Vec::new();
    for (b, coordinate) in bundles.iter().zip(&coords) {
        authenticate(plan, b)?;
        let poly =
            e3_trbfv::helpers::try_poly_pb_from_bytes(&b.decryption_share[0], &cfg.threshold)?;
        shares.push(DecryptionShare::from_parts(
            poly,
            *coordinate,
            coords.clone(),
            &ct,
        )?);
        proofs.push(b.signed_decryption_proofs[0].payload.proof.clone());
    }
    let v = plan.committee().values();
    let pt = SynchronizedDecryptor::new(v.n, v.threshold, cfg.threshold.clone())?
        .decrypt_from_shares(&shares, &ct)?;
    let decoded = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
    let message = decoded
        .get(..MAX_MSG_NON_ZERO_COEFFS)
        .context("short plaintext")?;
    ensure!(
        decoded[MAX_MSG_NON_ZERO_COEFFS..].iter().all(|&v| v == 0),
        "plaintext exceeds C7 message width"
    );
    let parts: Vec<_> = shares.into_iter().map(|s| s.into_parts().0).collect();
    let contributions: Vec<_> = proofs
        .iter()
        .zip(&parts)
        .map(|(p, share)| Contribution {
            public_signals: &p.public_signals,
            share,
        })
        .collect();
    let a = plan.authority();
    let input = prepare(
        &cfg,
        plan.setup_binding(),
        plan.domain(),
        &a.party_ids,
        &ct,
        &contributions,
        message,
    )?;
    let c7 = prove(
        prover,
        &cfg,
        CircuitName::DecryptedSharesAggregation,
        input,
        job,
        CircuitVariant::Recursive,
        None,
    )?;
    let outer = prove_decryption(prover, &cfg, &proofs, &c7, job)?;
    let expected = ExpectedDecryption {
        setup: plan.setup_binding(),
        domain: plan.domain(),
        ciphertext_commitment: plan.ciphertext_commitment(),
        roster: &a.party_ids,
        sk_commitments: &a.sk_agg_commits,
        key_bundles: &a.key_bundle_commits,
        message,
    };
    ensure!(
        verify_decryption(prover, &cfg, &expected, &outer, job)?,
        "final proof failed local verification"
    );
    Ok(PlaintextAggregated {
        e3_id: plan.e3_id().clone(),
        decrypted_output: vec![ArcBytes::from_bytes(
            &message
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )],
        decryption_aggregator_proofs: vec![outer],
    })
}
