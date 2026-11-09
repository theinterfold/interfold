// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The proofs of the node's work: circuits proved with `bb`, which the deployed verifiers and
//! peers check, or placeholders, which only the mock verifiers of a test deployment accept.

use crate::{trbfv, Attempt, Blobs, JobError, Jobs};
use alloy_primitives::{keccak256, B256};
use e3_fhe_params::BfvPreset;
use e3_protocol::{
    accusation::{disputed_proof, Fault, Verdict},
    node::CryptoParams,
    proof::{ProofType, ZkProof},
    E3Id,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_config::CircuitName;
use e3_zk_prover::Proof;
use e3_zk_prover::{Cancel, Provable, ZkProver};
use num_bigint::BigInt;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{fmt::Display, fs, io};

pub enum Proofs {
    /// Proofs only the mock verifiers of a test deployment accept.
    #[cfg(any(test, feature = "testing"))]
    Placeholder,
    Circuits(Box<Circuits>),
}

/// The compiled circuits and `bb`. A proof and its witness can hold gigabytes under the secure
/// parameters, so proofs run on their own pool of `limit` threads: at most `limit` run at once.
/// A thread that waits for the pool keeps working for its own, and a proof's inner joins run on
/// this pool, so no proof waits for a thread that waits for it.
pub struct Circuits {
    prover: ZkProver,
    pool: ThreadPool,
}

impl Circuits {
    /// `threads` is how many threads each `bb` may use.
    pub fn new(prover: ZkProver, limit: usize, threads: usize) -> Result<Self, JobError> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(limit.max(1))
            .thread_name(|index| format!("proof-{index}"))
            .build()
            .map_err(JobError::crypto)?;
        let prover = prover.with_threads(threads);
        Ok(Self { prover, pool })
    }

    /// The circuits as one attempt at a job uses them: it stops with the attempt's token, and
    /// after a failed attempt `bb` trades speed for a smaller memory peak.
    pub(crate) fn for_attempt<'a>(&'a self, attempt: &'a Attempt) -> Prover<'a> {
        let zk = self.prover.with_cancel(attempt.cancel.clone());
        let zk = match attempt.number {
            0 => zk,
            _ => zk.with_slow_low_memory(),
        };
        Prover {
            zk,
            pool: &self.pool,
            cancel: &attempt.cancel,
        }
    }

    pub(crate) fn close(&self, e3: E3Id) -> io::Result<()> {
        match fs::remove_dir_all(self.prover.work_dir().join(directory(e3))) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// One attempt's view of the circuits.
pub(crate) struct Prover<'a> {
    zk: ZkProver,
    pool: &'a ThreadPool,
    cancel: &'a Cancel,
}

impl Prover<'_> {
    fn stop_if_cancelled(&self) -> Result<(), JobError> {
        match self.cancel.is_cancelled() {
            true => Err(JobError::Cancelled),
            false => Ok(()),
        }
    }

    /// An error of cancelled work says so, whatever failed first.
    fn outcome<T>(&self, result: Result<T, impl Display>) -> Result<T, JobError> {
        self.stop_if_cancelled()?;
        result.map_err(JobError::crypto)
    }

    /// Runs `prove` on the proof pool, once one of its threads is free.
    pub(crate) fn proving<T: Send, E: Display + Send>(
        &self,
        prove: impl FnOnce(&ZkProver) -> Result<T, E> + Send,
    ) -> Result<T, JobError> {
        self.stop_if_cancelled()?;
        self.pool.install(|| {
            self.stop_if_cancelled()?;
            self.outcome(prove(&self.zk))
        })
    }

    fn verify(&self, proof: &Proof, work: &str, artifacts: &str) -> Result<bool, JobError> {
        self.stop_if_cancelled()?;
        self.outcome(self.zk.verify_proof(proof, work, 0, artifacts))
    }

    fn artifacts(&self, preset: BfvPreset, committee: &str) -> String {
        self.zk.resolve_artifacts_dir(preset, committee)
    }
}

/// A failing proof stays the verdict: `bound` runs only once every proof holds.
fn settle(
    verdict: Verdict,
    bound: impl FnOnce() -> Result<bool, JobError>,
) -> Result<Verdict, JobError> {
    match verdict {
        Verdict::Valid if !bound()? => Ok(Verdict::Invalid),
        verdict => Ok(verdict),
    }
}

/// Each E3's proofs run `bb` in a directory of its own, which goes when the E3's work ends.
fn directory(e3: E3Id) -> String {
    format!("{}-{}", e3.chain_id, e3.number)
}

impl<B: Blobs> Jobs<'_, B> {
    /// The circuits, or none where placeholders stand in.
    pub(crate) fn prover(&self) -> Option<&Prover<'_>> {
        self.prover.as_ref()
    }

    /// Prove `input` with the request's compiled `circuit` and store the proof. `work` names it
    /// among this job's proofs, since every proof runs `bb` in its own directory. A repeated job
    /// has the same inputs (its random ones come from its kept seed), so a proof it finished
    /// before is taken as it is; a release with other circuits does not find it.
    pub(crate) fn prove<C: Provable>(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        circuit: C,
        config: &C::Config,
        input: &C::Input,
        work: &str,
    ) -> Result<ZkProof, JobError> {
        let key = self.proof_key(work);
        if let Some(kept) = self.blobs.kept(&key)? {
            return bincode::deserialize(&kept).map_err(JobError::crypto);
        }
        let (work, artifacts) = (self.work(work), self.artifacts(prover, params)?);
        let proof = prover.proving(|zk| circuit.prove(zk, config, input, &work, &artifacts))?;
        let proof = store(&self.blobs, &proof)?;
        let encoded = bincode::serialize(&proof).map_err(JobError::crypto)?;
        self.blobs.keep(&key, &encoded)?;
        Ok(proof)
    }

    fn proof_key(&self, work: &str) -> B256 {
        keccak256([self.scope.as_slice(), self.job.as_slice(), work.as_bytes()].concat())
    }

    /// The verdict on proofs a member signed: the first that fails, or valid. A verifier that
    /// cannot run is an error, not a failing proof.
    pub(crate) fn verdict<'a>(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        proofs: impl IntoIterator<Item = (ProofType, &'a ZkProof)>,
    ) -> Result<Verdict, JobError> {
        let artifacts = self.artifacts(prover, params)?;
        for (proof_type, proof) in proofs {
            let loaded = load(&self.blobs, proof, circuit(proof_type))?;
            let valid = prover.verify(&loaded, &self.work("verify"), &artifacts)?;
            if !valid {
                return Ok(Verdict::Fails(Fault {
                    proof_type,
                    proof: proof.clone(),
                    data_hash: self.data_hash(proof)?,
                }));
            }
        }
        Ok(Verdict::Valid)
    }

    /// The verdict on a member's message: a signed proof that fails is an accusation whatever
    /// else is wrong with the message, and only once every proof holds does `bound` say whether
    /// they are about this message's bytes.
    pub(crate) fn checked<'a>(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
        proofs: impl IntoIterator<Item = (ProofType, &'a ZkProof)>,
        bound: impl FnOnce() -> Result<bool, JobError>,
    ) -> Result<Verdict, JobError> {
        settle(self.verdict(prover, params, proofs)?, bound)
    }

    /// The hash of the evidence that a slash of `proof` carries, which votes sign.
    pub(crate) fn data_hash(&self, proof: &ZkProof) -> Result<B256, JobError> {
        let bytes = self.blobs.get(&proof.data)?;
        Ok(keccak256(disputed_proof(&bytes, &proof.public_inputs)))
    }

    /// The directory of the request's compiled circuits.
    pub(crate) fn artifacts(
        &self,
        prover: &Prover<'_>,
        params: &CryptoParams,
    ) -> Result<String, JobError> {
        let preset = trbfv::threshold_preset(params)?;
        Ok(prover.artifacts(preset, params.committee_size.as_str()))
    }

    pub(crate) fn work(&self, name: &str) -> String {
        format!("{}/{name}", directory(self.e3))
    }
}

/// The circuit that proves `proof_type`'s statement.
pub(crate) fn circuit(proof_type: ProofType) -> CircuitName {
    match proof_type {
        ProofType::C0PkBfv => CircuitName::PkBfv,
        ProofType::C1PkGeneration => CircuitName::PkGeneration,
        ProofType::C2aSkShareComputation => CircuitName::SkShareComputation,
        ProofType::C2bESmShareComputation => CircuitName::ESmShareComputation,
        ProofType::C3aSkShareEncryption | ProofType::C3bESmShareEncryption => {
            CircuitName::ShareEncryption
        }
        ProofType::C4aSkShareDecryption | ProofType::C4bESmShareDecryption => {
            CircuitName::DkgShareDecryption
        }
        ProofType::C5PkAggregation => CircuitName::PkAggregation,
        ProofType::C6ThresholdShareDecryption => CircuitName::ThresholdShareDecryption,
        ProofType::C7DecryptedSharesAggregation => CircuitName::DecryptedSharesAggregation,
    }
}

/// The proof's bytes go to the blob store; its public signals, field elements of 32 bytes each,
/// become its public inputs.
pub(crate) fn store(blobs: &impl Blobs, proof: &Proof) -> Result<ZkProof, JobError> {
    let signals = &proof.public_signals[..];
    if !signals.len().is_multiple_of(32) {
        return Err(JobError::crypto(
            "public signals are not whole field elements",
        ));
    }
    Ok(ZkProof {
        data: blobs.put(&proof.data[..])?,
        public_inputs: signals.chunks(32).map(B256::from_slice).collect(),
    })
}

/// The public field `name` of a proof of `circuit`: one of its outputs, or of its leading inputs.
pub(crate) fn field(proof: &ZkProof, circuit: CircuitName, name: &str) -> Option<B256> {
    let signals: Vec<u8> = proof
        .public_inputs
        .iter()
        .flat_map(|input| input.0)
        .collect();
    let field = circuit
        .output_layout()
        .extract_field(&signals, name)
        .or_else(|| circuit.input_layout().extract_field(&signals, name))?;
    Some(B256::from_slice(field))
}

/// A commitment as a proof carries it: one field element, 32 big-endian bytes.
pub(crate) fn word(commitment: &BigInt) -> Option<B256> {
    let (_, bytes) = commitment.to_bytes_be();
    (bytes.len() <= 32).then(|| B256::left_padding_from(&bytes))
}

/// A stored proof of `circuit`, as the prover takes it.
pub(crate) fn load(
    blobs: &impl Blobs,
    proof: &ZkProof,
    circuit: CircuitName,
) -> Result<Proof, JobError> {
    let signals: Vec<u8> = proof
        .public_inputs
        .iter()
        .flat_map(|input| input.0)
        .collect();
    let data = ArcBytes::from_bytes(&blobs.get(&proof.data)?);
    Ok(Proof::new(circuit, data, ArcBytes::from_bytes(&signals)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use e3_protocol::BlobRef;

    fn failing() -> Verdict {
        Verdict::Fails(Fault {
            proof_type: ProofType::C4aSkShareDecryption,
            proof: ZkProof {
                data: BlobRef::of(b"proof"),
                public_inputs: Vec::new(),
            },
            data_hash: B256::ZERO,
        })
    }

    /// A signed proof that fails must reach accusation even if the message's bytes are wrong too.
    #[test]
    fn a_failing_proof_is_the_verdict_whatever_the_bytes_say() {
        let bound = || panic!("the bytes are compared only once every proof holds");
        assert_eq!(settle(failing(), bound).unwrap(), failing());
    }

    #[test]
    fn proofs_that_hold_for_other_bytes_make_the_message_invalid() {
        assert_eq!(
            settle(Verdict::Valid, || Ok(false)).unwrap(),
            Verdict::Invalid
        );
        assert_eq!(settle(Verdict::Valid, || Ok(true)).unwrap(), Verdict::Valid);
    }
}
