// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The proofs of the node's work: circuits proved with `bb`, which the deployed verifiers and
//! peers check, or placeholders, which only the mock verifiers of a test deployment accept.

use crate::{trbfv, Blobs, JobError, Jobs};
use alloy_primitives::{keccak256, B256};
use e3_protocol::{
    accusation::{disputed_proof, Fault, Verdict},
    node::CryptoParams,
    proof::{ProofType, ZkProof},
    E3Id,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_config::CircuitName;
use e3_zk_prover::Proof;
use e3_zk_prover::{Provable, ZkProver};
use num_bigint::BigInt;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{fs, io};

pub enum Proofs {
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
    pub fn new(prover: ZkProver, limit: usize) -> Result<Self, JobError> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(limit.max(1))
            .thread_name(|index| format!("proof-{index}"))
            .build()
            .map_err(JobError::crypto)?;
        Ok(Self { prover, pool })
    }

    /// Runs `prove` on the proof pool, once one of its threads is free.
    pub(crate) fn proving<T: Send>(&self, prove: impl FnOnce(&ZkProver) -> T + Send) -> T {
        self.pool.install(|| prove(&self.prover))
    }

    pub(crate) fn close(&self, e3: E3Id) -> io::Result<()> {
        match fs::remove_dir_all(self.prover.work_dir().join(directory(e3))) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// Each E3's proofs run `bb` in a directory of its own, which goes when the E3's work ends.
fn directory(e3: E3Id) -> String {
    format!("{}-{}", e3.chain_id, e3.number)
}

impl<B: Blobs> Jobs<'_, B> {
    /// The circuits, or none where placeholders stand in.
    pub(crate) fn prover(&self) -> Option<&Circuits> {
        match self.proofs {
            Proofs::Placeholder => None,
            Proofs::Circuits(circuits) => Some(circuits),
        }
    }

    /// Prove `input` with the request's compiled `circuit` and store the proof. `work` names it
    /// among this E3's proofs, since every proof runs `bb` in its own directory.
    pub(crate) fn prove<C: Provable>(
        &self,
        prover: &Circuits,
        params: &CryptoParams,
        circuit: C,
        config: &C::Config,
        input: &C::Input,
        work: &str,
    ) -> Result<ZkProof, JobError> {
        let (work, artifacts) = (self.work(work), self.artifacts(prover, params)?);
        let proof = prover
            .proving(|zk| circuit.prove(zk, config, input, &work, &artifacts))
            .map_err(JobError::crypto)?;
        store(&self.blobs, &proof)
    }

    /// The verdict on proofs a member signed: the first that fails, or valid. A verifier that
    /// cannot run is an error, not a failing proof.
    pub(crate) fn verdict<'a>(
        &self,
        prover: &Circuits,
        params: &CryptoParams,
        proofs: impl IntoIterator<Item = (ProofType, &'a ZkProof)>,
    ) -> Result<Verdict, JobError> {
        let artifacts = self.artifacts(prover, params)?;
        for (proof_type, proof) in proofs {
            let loaded = load(&self.blobs, proof, circuit(proof_type))?;
            let valid = prover
                .prover
                .verify_proof(&loaded, &self.work("verify"), 0, &artifacts)
                .map_err(JobError::crypto)?;
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

    /// The hash of the evidence that a slash of `proof` carries, which votes sign.
    pub(crate) fn data_hash(&self, proof: &ZkProof) -> Result<B256, JobError> {
        let bytes = self.blobs.get(&proof.data)?;
        Ok(keccak256(disputed_proof(&bytes, &proof.public_inputs)))
    }

    /// The directory of the request's compiled circuits.
    pub(crate) fn artifacts(
        &self,
        prover: &Circuits,
        params: &CryptoParams,
    ) -> Result<String, JobError> {
        let preset = trbfv::threshold_preset(params)?;
        Ok(prover
            .prover
            .resolve_artifacts_dir(preset, params.committee_size.as_str()))
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
