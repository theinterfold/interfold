// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The proofs of the node's work: circuits proved with `bb`, which the deployed verifiers and
//! peers check, or placeholders, which only the mock verifiers of a test deployment accept.

use crate::{trbfv, Attempt, Blobs, JobError, Jobs};
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
use e3_zk_prover::{Cancel, Provable, ZkProver};
use num_bigint::BigInt;
use rayon::prelude::*;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
    fs, io,
    sync::{Arc, Condvar, Mutex, PoisonError},
    time::Duration,
};

const WAIT_POLL: Duration = Duration::from_millis(25);

pub enum Proofs {
    /// Proofs only the mock verifiers of a test deployment accept.
    #[cfg(any(test, feature = "testing"))]
    Placeholder,
    Circuits(Box<Circuits>),
}

/// Priority on [`ProveGate`]: foreground protocol proofs always acquire permits before background
/// speculative pre-folding steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Priority {
    Foreground,
    Background,
}

struct GateState {
    active: usize,
    high_waiters: usize,
}

struct ProveGate {
    max_concurrent: usize,
    total_threads: usize,
    state: Mutex<GateState>,
    ready: Condvar,
}

struct Permit<'a> {
    gate: &'a ProveGate,
    threads: usize,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        self.gate.ready.notify_all();
    }
}

impl ProveGate {
    fn new(max_concurrent: usize, total_threads: usize) -> Self {
        Self {
            max_concurrent: max_concurrent.max(1),
            total_threads: total_threads.max(1),
            state: Mutex::new(GateState {
                active: 0,
                high_waiters: 0,
            }),
            ready: Condvar::new(),
        }
    }

    fn acquire<'a>(&'a self, priority: Priority, cancel: &Cancel) -> Result<Permit<'a>, JobError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if priority == Priority::Foreground {
            state.high_waiters += 1;
            let result = loop {
                if cancel.is_cancelled() {
                    state.high_waiters -= 1;
                    self.ready.notify_all();
                    break Err(JobError::Cancelled);
                }
                if state.active < self.max_concurrent {
                    state.high_waiters -= 1;
                    state.active += 1;
                    let planned = (state.active + state.high_waiters).clamp(1, self.max_concurrent);
                    let threads = (self.total_threads / planned).max(1);
                    break Ok(Permit {
                        gate: self,
                        threads,
                    });
                }
                let (guard, _) = self
                    .ready
                    .wait_timeout(state, WAIT_POLL)
                    .unwrap_or_else(PoisonError::into_inner);
                state = guard;
            };
            result
        } else {
            loop {
                if cancel.is_cancelled() {
                    return Err(JobError::Cancelled);
                }
                if state.active < self.max_concurrent && state.high_waiters == 0 {
                    state.active += 1;
                    let planned = state.active.clamp(1, self.max_concurrent);
                    let threads = (self.total_threads / planned).max(1);
                    return Ok(Permit {
                        gate: self,
                        threads,
                    });
                }
                let (guard, _) = self
                    .ready
                    .wait_timeout(state, WAIT_POLL)
                    .unwrap_or_else(PoisonError::into_inner);
                state = guard;
            }
        }
    }
}

enum InFlightState {
    Running,
    Ready(ZkProof),
    Failed,
}

struct InFlight {
    state: Mutex<InFlightState>,
    done: Condvar,
}

impl InFlight {
    fn new() -> Self {
        Self {
            state: Mutex::new(InFlightState::Running),
            done: Condvar::new(),
        }
    }

    fn finish(&self, outcome: Option<ZkProof>) {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = match outcome {
            Some(proof) => InFlightState::Ready(proof),
            None => InFlightState::Failed,
        };
        self.done.notify_all();
    }

    fn wait(&self, cancel: &Cancel) -> Result<Option<ZkProof>, JobError> {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match &*guard {
                InFlightState::Ready(proof) => return Ok(Some(proof.clone())),
                InFlightState::Failed => return Ok(None),
                InFlightState::Running => {
                    if cancel.is_cancelled() {
                        return Err(JobError::Cancelled);
                    }
                    let (next, _) = self
                        .done
                        .wait_timeout(guard, WAIT_POLL)
                        .unwrap_or_else(PoisonError::into_inner);
                    guard = next;
                }
            }
        }
    }
}

struct InFlightGuard<'a> {
    map: &'a Mutex<HashMap<B256, Arc<InFlight>>>,
    key: B256,
    entry: Arc<InFlight>,
    completed: bool,
}

impl InFlightGuard<'_> {
    fn complete(mut self, proof: ZkProof) {
        self.completed = true;
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
        self.entry.finish(Some(proof));
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.map
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.key);
            self.entry.finish(None);
        }
    }
}

struct CircuitsInner {
    prover: ZkProver,
    verify_threads: usize,
    gate: ProveGate,
    in_flight: Mutex<HashMap<B256, Arc<InFlight>>>,
}

/// The compiled circuits and `bb`. A proof and its witness can hold gigabytes under the secure
/// parameters, so proving runs behind a bounded priority gate of `limit` concurrent `bb`
/// invocations with dynamic per-proof thread allocation across the machine's thread budget.
#[derive(Clone)]
pub struct Circuits {
    inner: Arc<CircuitsInner>,
}

impl Circuits {
    /// `threads` is how many threads each `bb` may use when `limit` run concurrently.
    pub fn new(prover: ZkProver, limit: usize, threads: usize) -> Result<Self, JobError> {
        let total_threads = threads.max(1).saturating_mul(limit.max(1));
        Self::with_thread_budget(prover, limit, total_threads)
    }

    /// `limit` is the maximum concurrent `bb` provers; `total_threads` is the total thread budget
    /// dynamically divided across currently active/queued proofs so solo proofs use all threads.
    pub fn with_thread_budget(
        prover: ZkProver,
        limit: usize,
        total_threads: usize,
    ) -> Result<Self, JobError> {
        let total = total_threads.max(1);
        let verify_threads = (total / 4).clamp(1, 2);
        Ok(Self {
            inner: Arc::new(CircuitsInner {
                prover: prover.with_threads(verify_threads),
                verify_threads,
                gate: ProveGate::new(limit, total),
                in_flight: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The circuits as one attempt at a job uses them: it stops with the attempt's token, and
    /// after a failed attempt `bb` trades speed for a smaller memory peak.
    pub(crate) fn for_attempt<'a>(&'a self, attempt: &'a Attempt) -> Prover<'a> {
        let zk = self.inner.prover.with_cancel(attempt.cancel.clone());
        let zk = match attempt.number {
            0 => zk,
            _ => zk.with_slow_low_memory(),
        };
        Prover {
            zk,
            inner: &self.inner,
            cancel: &attempt.cancel,
        }
    }

    pub(crate) fn close(&self, e3: E3Id) -> io::Result<()> {
        match fs::remove_dir_all(self.inner.prover.work_dir().join(directory(e3))) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

/// One attempt's view of the circuits.
pub(crate) struct Prover<'a> {
    zk: ZkProver,
    inner: &'a CircuitsInner,
    cancel: &'a Cancel,
}

impl Prover<'_> {
    pub(crate) fn max_concurrent(&self) -> usize {
        self.inner.gate.max_concurrent
    }

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

    /// Runs `prove` behind the priority proof gate at foreground priority.
    #[cfg(test)]
    pub(crate) fn proving<T: Send, E: Display + Send>(
        &self,
        prove: impl FnOnce(&ZkProver) -> Result<T, E> + Send,
    ) -> Result<T, JobError> {
        self.proving_with_priority(Priority::Foreground, prove)
    }

    /// Runs `prove` behind the priority proof gate, dynamically sizing `bb`'s thread count to the
    /// live concurrency so solo proofs get the full budget while concurrent proofs share it cleanly.
    pub(crate) fn proving_with_priority<T: Send, E: Display + Send>(
        &self,
        priority: Priority,
        prove: impl FnOnce(&ZkProver) -> Result<T, E> + Send,
    ) -> Result<T, JobError> {
        self.stop_if_cancelled()?;
        let permit = self.inner.gate.acquire(priority, self.cancel)?;
        self.stop_if_cancelled()?;
        let zk = self.zk.with_threads(permit.threads);
        self.outcome(prove(&zk))
    }

    fn verify(&self, proof: &Proof, work: &str, artifacts: &str) -> Result<bool, JobError> {
        self.stop_if_cancelled()?;
        let zk = self.zk.with_threads(self.inner.verify_threads);
        self.outcome(zk.verify_proof(proof, work, 0, artifacts))
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
pub(crate) fn directory(e3: E3Id) -> String {
    format!("{}-{}", e3.chain_id, e3.number)
}

/// Deterministic work subdirectory for `name` under `e3`'s work directory.
pub(crate) fn work_dir(e3: E3Id, name: &str) -> String {
    format!("{}/{name}", directory(e3))
}

/// Directory of compiled circuits for `params`.
pub(crate) fn artifacts_dir(params: &CryptoParams) -> Result<String, JobError> {
    let profile = trbfv::profile(params)?;
    Ok(profile.artifacts_dir_for_committee(params.committee_size)?)
}

/// Content-addressed checkpoint key for a single proof step.
pub(crate) fn step_key(scope: B256, label: &str, inputs: &[B256]) -> B256 {
    let mut buf = Vec::with_capacity(32 + label.len() + inputs.len() * 32);
    buf.extend_from_slice(scope.as_slice());
    buf.extend_from_slice(label.as_bytes());
    for input in inputs {
        buf.extend_from_slice(input.as_slice());
    }
    keccak256(&buf)
}

/// Single-flight, checkpointed proving step shared between speculative background pre-folding
/// and foreground fold/aggregation jobs.
pub(crate) fn prove_kept_step<B: Blobs, E: Display + Send>(
    blobs: &B,
    prover: &Prover<'_>,
    key: B256,
    priority: Priority,
    prove: impl FnOnce(&ZkProver) -> Result<Proof, E> + Send,
) -> Result<ZkProof, JobError> {
    let mut prove = Some(prove);
    loop {
        prover.stop_if_cancelled()?;
        if let Some(kept) = blobs.kept(&key)? {
            return bincode::deserialize(&kept).map_err(JobError::crypto);
        }
        let existing = {
            let mut map = prover
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = map.get(&key) {
                Some(Arc::clone(entry))
            } else {
                let entry = Arc::new(InFlight::new());
                map.insert(key, Arc::clone(&entry));
                drop(map);
                let guard = InFlightGuard {
                    map: &prover.inner.in_flight,
                    key,
                    entry,
                    completed: false,
                };
                if let Some(kept) = blobs.kept(&key)? {
                    let proof: ZkProof = bincode::deserialize(&kept).map_err(JobError::crypto)?;
                    guard.complete(proof.clone());
                    return Ok(proof);
                }
                let prove_fn = prove.take().expect("single-flight runs closure once");
                let raw = prover.proving_with_priority(priority, prove_fn)?;
                let proof = store(blobs, &raw)?;
                let encoded = bincode::serialize(&proof).map_err(JobError::crypto)?;
                blobs.keep(&key, &encoded)?;
                guard.complete(proof.clone());
                return Ok(proof);
            }
        };
        if let Some(entry) = existing {
            if let Some(proof) = entry.wait(prover.cancel)? {
                return Ok(proof);
            }
        }
    }
}

impl<B: Blobs, S: Sync> Jobs<'_, B, S> {
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
        let (work, artifacts) = (self.work(work), self.artifacts(params)?);
        prove_kept_step(&self.blobs, prover, key, Priority::Foreground, |zk| {
            circuit.prove(zk, config, input, &work, &artifacts)
        })
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
        let artifacts = self.artifacts(params)?;
        // A message can repeat one proof to make the node verify it many times.
        let mut seen = BTreeSet::new();
        let unique: Vec<(ProofType, &ZkProof)> = proofs
            .into_iter()
            .filter(|(proof_type, proof)| seen.insert((*proof_type, *proof)))
            .collect();
        if unique.is_empty() {
            return Ok(Verdict::Valid);
        }
        if unique.len() == 1 {
            let (proof_type, proof) = unique[0];
            let loaded = load(&self.blobs, proof, circuit(proof_type))?;
            if !prover.verify(&loaded, &self.work("verify"), &artifacts)? {
                return Ok(Verdict::Fails(Fault {
                    proof_type,
                    proof: proof.clone(),
                    data_hash: self.data_hash(proof)?,
                }));
            }
            return Ok(Verdict::Valid);
        }
        // Verify distinct proofs in parallel on the CPU check pool while returning the first
        // failing proof in deterministic input order.
        let results: Vec<Result<bool, JobError>> = self.check_pool.install(|| {
            unique
                .par_iter()
                .map(|(proof_type, proof)| {
                    let loaded = load(&self.blobs, proof, circuit(*proof_type))?;
                    prover.verify(&loaded, &self.work("verify"), &artifacts)
                })
                .collect()
        });
        for ((proof_type, proof), valid) in unique.into_iter().zip(results) {
            if !valid? {
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
    pub(crate) fn artifacts(&self, params: &CryptoParams) -> Result<String, JobError> {
        let profile = trbfv::profile(params)?;
        Ok(profile.artifacts_dir_for_committee(params.committee_size)?)
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

    #[test]
    fn foreground_proof_preempts_background_prefold_waiters() {
        use std::{
            sync::{Arc, Barrier},
            thread,
        };

        let gate = Arc::new(ProveGate::new(1, 4));
        let cancel = Cancel::default();
        let holder = gate.acquire(Priority::Foreground, &cancel).unwrap();
        assert_eq!(holder.threads, 4);

        let bg_waiting = Arc::new(Barrier::new(2));
        let fg_waiting = Arc::new(Barrier::new(2));
        let order = Arc::new(Mutex::new(Vec::new()));

        let g1 = Arc::clone(&gate);
        let b1 = Arc::clone(&bg_waiting);
        let o1 = Arc::clone(&order);
        let c1 = cancel.clone();
        let bg = thread::spawn(move || {
            b1.wait();
            let _p = g1.acquire(Priority::Background, &c1).unwrap();
            o1.lock().unwrap().push("background");
        });
        bg_waiting.wait();
        thread::sleep(Duration::from_millis(15));

        let g2 = Arc::clone(&gate);
        let f2 = Arc::clone(&fg_waiting);
        let o2 = Arc::clone(&order);
        let c2 = cancel.clone();
        let fg = thread::spawn(move || {
            f2.wait();
            let _p = g2.acquire(Priority::Foreground, &c2).unwrap();
            o2.lock().unwrap().push("foreground");
        });
        fg_waiting.wait();
        thread::sleep(Duration::from_millis(15));

        drop(holder);
        fg.join().unwrap();
        bg.join().unwrap();
        assert_eq!(*order.lock().unwrap(), vec!["foreground", "background"]);
    }
}
