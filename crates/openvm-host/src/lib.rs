// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Proves an E3 program's Secure Process with the OpenVM worker.
//!
//! The host runs the program natively first, with the same `SecureProcess` the guest runs. That
//! gives it the output ciphertext, the journal the guest must reveal and the inputs the guest reads
//! in its second pass. It then runs the separate worker executable, which proves the guest, checks
//! the proof against that journal and writes a seal.
//!
//! The worker is chosen at startup. A CUDA worker is used when one is configured and can open a
//! GPU; otherwise the CPU worker proves. Every worker run has a deadline, after which the worker is
//! stopped, so a hung proof fails its round instead of holding the service.

use anyhow::{bail, ensure, Context, Result};
use e3_compute_provider::{
    Batching, ComputeInput, FHEInputs, FHEProcessor, InputPolicy, PublishedData,
};
use e3_openvm_types::{write_items, ComputeJournal, GuestHeader};
pub use e3_openvm_types::{ComputeDomain, JOURNAL_BYTES};
use std::ffi::OsStr;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// The length of the seal the worker writes: `abi.encode(uint8 version, bytes proofData)`.
pub const SEAL_BYTES: usize = 1856;

/// How long a CUDA worker gets to open a GPU.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Commitments recomputed per thread-pool task. At least 2, or the run is sequential.
const COMMITMENT_BATCH: usize = 4;

/// Which worker proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Cpu,
    Cuda,
}

/// The operator's choice of worker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendChoice {
    /// The CUDA worker when one is configured and can open a GPU, otherwise the CPU worker.
    #[default]
    Auto,
    Cpu,
    /// The CUDA worker. Startup fails when it cannot open a GPU.
    Cuda,
}

impl FromStr for BackendChoice {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "" | "auto" => Ok(Self::Auto),
            "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda),
            other => bail!("unknown OpenVM backend {other:?}; use auto, cpu or cuda"),
        }
    }
}

/// Where the workers and their configuration are, and how long they may run.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// The CPU worker, `OPENVM_PROVER_BIN`.
    pub cpu: Option<PathBuf>,
    /// The CUDA worker, `OPENVM_PROVER_BIN_CUDA`.
    pub cuda: Option<PathBuf>,
    /// The worker configuration file, `OPENVM_PROVER_CONFIG`.
    pub config: PathBuf,
    /// `OPENVM_BACKEND`: `auto` (the default), `cpu` or `cuda`.
    pub backend: BackendChoice,
    /// `OPENVM_CHECK_TIMEOUT_SECS`, 30 minutes by default. The check loads every proving key.
    pub check_timeout: Duration,
    /// `OPENVM_PROVE_TIMEOUT_SECS`, 24 hours by default.
    pub prove_timeout: Duration,
}

fn absolute_file(name: &str, value: Option<String>) -> Result<Option<PathBuf>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute() && path.is_file(),
        "{name} must name an existing absolute file path"
    );
    Ok(Some(path))
}

fn seconds(name: &str, default: u64) -> Result<Duration> {
    let seconds = match std::env::var(name) {
        Ok(value) if !value.is_empty() => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be a whole number of seconds"))?,
        _ => default,
    };
    ensure!(seconds > 0, "{name} must be greater than zero");
    Ok(Duration::from_secs(seconds))
}

impl WorkerConfig {
    /// Reads the configuration from the environment the support scripts set.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| std::env::var(name).ok();
        let config = absolute_file("OPENVM_PROVER_CONFIG", var("OPENVM_PROVER_CONFIG"))?
            .context("Set OPENVM_PROVER_CONFIG to the worker configuration file")?;
        let worker = Self {
            cpu: absolute_file("OPENVM_PROVER_BIN", var("OPENVM_PROVER_BIN"))?,
            cuda: absolute_file("OPENVM_PROVER_BIN_CUDA", var("OPENVM_PROVER_BIN_CUDA"))?,
            config,
            backend: var("OPENVM_BACKEND").unwrap_or_default().parse()?,
            check_timeout: seconds("OPENVM_CHECK_TIMEOUT_SECS", 30 * 60)?,
            prove_timeout: seconds("OPENVM_PROVE_TIMEOUT_SECS", 24 * 60 * 60)?,
        };
        ensure!(
            worker.cpu.is_some() || worker.cuda.is_some(),
            "Set OPENVM_PROVER_BIN to the CPU worker, OPENVM_PROVER_BIN_CUDA to the CUDA worker, or both"
        );
        Ok(worker)
    }
}

/// Runs the worker and waits for it, stopping it at the deadline.
///
/// The worker leads its own process group, and the deadline stops the whole group. A wrapper script
/// that starts the prover as a child, for example to set `LD_LIBRARY_PATH` for CUDA, therefore
/// cannot leave the prover running and holding the GPU.
async fn run_worker(worker: &Path, args: &[&OsStr], timeout: Duration, action: &str) -> Result<()> {
    let mut command = tokio::process::Command::new(worker);
    command.args(args).kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot start the OpenVM worker {}", worker.display()))?;
    let mut group = WorkerGroup(child.id());
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            // The worker has exited and been reaped, so its id may be reused: stop tracking it.
            group.0 = None;
            let status = status.context("cannot wait for the OpenVM worker")?;
            ensure!(status.success(), "OpenVM {action} failed ({status})");
            Ok(())
        }
        Err(_) => {
            group.stop();
            // `kill` also reaps the worker, so a stopped worker leaves no zombie behind.
            let _ = child.kill().await;
            bail!(
                "OpenVM {action} did not finish within {} seconds; the worker was stopped",
                timeout.as_secs()
            )
        }
    }
}

/// The process group of a running worker. Dropping it, as a cancelled request does, stops the
/// whole group, not only the worker that `kill_on_drop` reaches.
struct WorkerGroup(Option<u32>);

impl WorkerGroup {
    fn stop(&mut self) {
        #[cfg(unix)]
        if let Some(id) = self.0.take() {
            // The worker was started with `process_group(0)`, so its id is the group's id, and the
            // group exists while the worker runs. The return value is ignored: an empty group is
            // already stopped.
            unsafe {
                libc::killpg(id as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

impl Drop for WorkerGroup {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Picks the worker for this machine.
async fn select_worker(config: &WorkerConfig) -> Result<(PathBuf, Backend)> {
    let cpu = || {
        config
            .cpu
            .clone()
            .map(|worker| (worker, Backend::Cpu))
            .context("Set OPENVM_PROVER_BIN to the CPU worker")
    };
    let probe = |worker: PathBuf| async move {
        run_worker(&worker, &[OsStr::new("probe")], PROBE_TIMEOUT, "GPU probe")
            .await
            .map(|()| (worker, Backend::Cuda))
    };

    match config.backend {
        BackendChoice::Cpu => cpu(),
        BackendChoice::Cuda => {
            let worker = config
                .cuda
                .clone()
                .context("OPENVM_BACKEND=cuda needs OPENVM_PROVER_BIN_CUDA")?;
            probe(worker)
                .await
                .context("The CUDA worker cannot use a GPU on this machine")
        }
        BackendChoice::Auto => match config.cuda.clone() {
            None => {
                println!("OpenVM: no CUDA worker is configured; proving on the CPU");
                cpu()
            }
            Some(worker) => match probe(worker).await {
                Ok(selected) => Ok(selected),
                Err(error) => {
                    println!(
                        "OpenVM: the CUDA worker cannot use a GPU ({error:#}); proving on the CPU"
                    );
                    cpu()
                }
            },
        },
    }
}

/// The selected worker, checked against its configuration.
#[derive(Clone, Debug)]
pub struct Prover {
    worker: PathBuf,
    backend: Backend,
    config: PathBuf,
    prove_timeout: Duration,
}

impl Prover {
    /// Picks the worker and checks it, its keys and its verifier before any work is accepted.
    pub async fn start(config: WorkerConfig) -> Result<Self> {
        let (worker, backend) = select_worker(&config).await?;
        println!(
            "OpenVM: checking the {backend:?} worker {} and its artifacts",
            worker.display()
        );
        run_worker(
            &worker,
            &[OsStr::new("check"), config.config.as_os_str()],
            config.check_timeout,
            "configuration check",
        )
        .await?;
        println!("OpenVM: proving with the {backend:?} worker");
        Ok(Self {
            worker,
            backend,
            config: config.config,
            prove_timeout: config.prove_timeout,
        })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Proves one round and returns the proof envelope the E3 program verifies and the output
    /// ciphertext it publishes.
    pub async fn prove(
        &self,
        inputs: FHEInputs,
        published: Vec<PublishedData>,
        domain: ComputeDomain,
        processor: FHEProcessor,
        policy: InputPolicy,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let job = tempfile::Builder::new()
            .prefix("interfold-openvm-")
            .tempdir()
            .context("cannot create the OpenVM job directory")?;
        let input_path = job.path().join("input.bin");
        let journal_path = job.path().join("journal.bin");
        let seal_path = job.path().join("seal.bin");

        let guest_input = input_path.clone();
        let (journal, ciphertext) = tokio::task::spawn_blocking(move || {
            run_natively(inputs, published, domain, processor, policy, &guest_input)
        })
        .await
        .context("the native computation stopped")??;
        fs::write(&journal_path, journal.abi_bytes())?;

        run_worker(
            &self.worker,
            &[
                OsStr::new("prove"),
                self.config.as_os_str(),
                input_path.as_os_str(),
                journal_path.as_os_str(),
                seal_path.as_os_str(),
            ],
            self.prove_timeout,
            "proof generation",
        )
        .await?;

        let seal = fs::read(&seal_path).context("the OpenVM worker did not write a seal")?;
        Ok((encode_compute_proof(&seal, &journal)?, ciphertext))
    }
}

/// Runs the Secure Process natively and writes the guest's input items.
fn run_natively(
    inputs: FHEInputs,
    published: Vec<PublishedData>,
    domain: ComputeDomain,
    processor: FHEProcessor,
    policy: InputPolicy,
    guest_input: &Path,
) -> Result<(ComputeJournal, Vec<u8>)> {
    let input = ComputeInput {
        fhe_inputs: inputs,
        published,
    };
    let (result, ciphertext, selected) = input
        .run_selected(
            processor,
            policy,
            Batching::Parallel {
                batch_size: COMMITMENT_BATCH,
            },
        )
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let journal = ComputeJournal::new(&domain, &result).map_err(anyhow::Error::msg)?;

    let ComputeInput {
        fhe_inputs,
        published,
    } = input;
    let header = GuestHeader {
        domain,
        params: fhe_inputs.params,
        indices: fhe_inputs
            .ciphertexts
            .iter()
            .map(|(_, index)| *index)
            .collect(),
        published,
    }
    .encode()
    .map_err(anyhow::Error::msg)?;

    // The order the guest reads: the header, every input, then the selected inputs again.
    let ciphertexts = &fhe_inputs.ciphertexts;
    let items: Vec<&[u8]> = std::iter::once(header.as_slice())
        .chain(ciphertexts.iter().map(|(bytes, _)| bytes.as_slice()))
        .chain(
            selected
                .iter()
                .map(|&index| ciphertexts[index].0.as_slice()),
        )
        .collect();
    let file = fs::File::create(guest_input).context("cannot write the guest input")?;
    write_items(BufWriter::new(file), items.into_iter()).context("cannot write the guest input")?;

    Ok((journal, ciphertext))
}

/// Encodes `abi.encode(bytes seal, bytes32 paramsHash, bytes32 inputRoot)`, the envelope the
/// receipt verifier decodes.
pub fn encode_compute_proof(seal: &[u8], journal: &ComputeJournal) -> Result<Vec<u8>> {
    ensure!(
        seal.len() == SEAL_BYTES,
        "the OpenVM seal must be {SEAL_BYTES} bytes, not {}",
        seal.len()
    );
    let mut envelope = Vec::with_capacity(128 + SEAL_BYTES.div_ceil(32) * 32);
    let mut offset = [0; 32];
    offset[31] = 0x60;
    envelope.extend_from_slice(&offset);
    envelope.extend_from_slice(&journal.params_hash);
    envelope.extend_from_slice(&journal.merkle_root);
    let mut length = [0; 32];
    length[24..].copy_from_slice(&(seal.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&length);
    envelope.extend_from_slice(seal);
    envelope.resize(envelope.len().next_multiple_of(32), 0);
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_compute_provider::ComputeResult;

    fn journal() -> ComputeJournal {
        ComputeJournal::new(
            &ComputeDomain {
                chain_id: 1,
                verifying_contract: [2; 20],
                e3_id: [3; 32],
                encryption_scheme_id: [4; 32],
                committee_public_key_hash: [5; 32],
            },
            &ComputeResult {
                ciphertext_hash: vec![6; 32],
                ciphertext_commitment: vec![7; 32],
                params_hash: vec![8; 32],
                merkle_root: vec![9; 32],
            },
        )
        .unwrap()
    }

    #[test]
    fn the_envelope_carries_the_seal_and_the_hashes_the_verifier_reads() {
        let seal = vec![0xaa; SEAL_BYTES];
        let envelope = encode_compute_proof(&seal, &journal()).unwrap();

        assert_eq!(envelope.len(), 1984);
        assert_eq!(envelope[31], 0x60);
        assert_eq!(&envelope[32..64], &[8; 32]);
        assert_eq!(&envelope[64..96], &[9; 32]);
        assert_eq!(&envelope[120..128], &(SEAL_BYTES as u64).to_be_bytes());
        assert_eq!(&envelope[128..], seal.as_slice());
        assert!(encode_compute_proof(&[], &journal()).is_err());
    }

    #[test]
    fn the_backend_choice_parses_and_defaults_to_auto() {
        assert_eq!("".parse::<BackendChoice>().unwrap(), BackendChoice::Auto);
        assert_eq!(
            "auto".parse::<BackendChoice>().unwrap(),
            BackendChoice::Auto
        );
        assert_eq!("cpu".parse::<BackendChoice>().unwrap(), BackendChoice::Cpu);
        assert_eq!(
            "cuda".parse::<BackendChoice>().unwrap(),
            BackendChoice::Cuda
        );
        assert!("gpu".parse::<BackendChoice>().is_err());
    }

    /// A stand-in worker: a shell script that behaves as the test needs.
    ///
    /// A child process writes it. Tests in this process fork while others run, and a forked child
    /// keeps a copy of any file this process has open for writing until it executes. Executing the
    /// script while such a copy is open fails with ETXTBSY.
    #[cfg(unix)]
    fn worker(directory: &Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        let status = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "printf '%s' \"$2\" > \"$1\" && chmod 755 \"$1\"",
                "sh",
            ])
            .arg(&path)
            .arg(format!("#!/bin/sh\n{body}\n"))
            .status()
            .unwrap();
        assert!(status.success(), "cannot write the stand-in worker");
        path
    }

    #[cfg(unix)]
    fn config(directory: &Path, cpu: Option<PathBuf>, cuda: Option<PathBuf>) -> WorkerConfig {
        WorkerConfig {
            cpu,
            cuda,
            config: directory.join("prover.json"),
            backend: BackendChoice::Auto,
            check_timeout: Duration::from_secs(5),
            prove_timeout: Duration::from_secs(5),
        }
    }

    /// A machine without a usable GPU proves on the CPU, and one with a GPU uses it.
    #[cfg(unix)]
    #[tokio::test]
    async fn auto_uses_the_gpu_only_when_the_probe_passes() {
        let directory = tempfile::tempdir().unwrap();
        let cpu = worker(directory.path(), "cpu", "exit 0");
        let no_gpu = worker(
            directory.path(),
            "cuda-without-gpu",
            "[ \"$1\" = probe ] && exit 1; exit 0",
        );
        let gpu = worker(directory.path(), "cuda", "exit 0");

        let without = config(directory.path(), Some(cpu.clone()), Some(no_gpu));
        assert_eq!(
            select_worker(&without).await.unwrap(),
            (cpu.clone(), Backend::Cpu)
        );

        let with = config(directory.path(), Some(cpu.clone()), Some(gpu.clone()));
        assert_eq!(select_worker(&with).await.unwrap(), (gpu, Backend::Cuda));

        let cpu_only = config(directory.path(), Some(cpu.clone()), None);
        assert_eq!(select_worker(&cpu_only).await.unwrap(), (cpu, Backend::Cpu));
    }

    /// Forcing CUDA on a machine without a GPU is a startup error, not a silent CPU fallback.
    #[cfg(unix)]
    #[tokio::test]
    async fn forced_cuda_without_a_gpu_fails() {
        let directory = tempfile::tempdir().unwrap();
        let no_gpu = worker(directory.path(), "cuda", "exit 1");
        let mut forced = config(directory.path(), None, Some(no_gpu));
        forced.backend = BackendChoice::Cuda;
        assert!(select_worker(&forced).await.is_err());
    }

    /// A worker that hangs is stopped at the deadline, so the round fails instead of holding the
    /// service's only slot.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hung_worker_is_stopped_at_the_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let hung = worker(directory.path(), "hung", "sleep 30");
        let started = std::time::Instant::now();

        let error = run_worker(&hung, &[], Duration::from_millis(300), "proof generation")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("did not finish"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A wrapper script that starts the prover as a child does not leave it running after the
    /// deadline: the whole process group is stopped.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_deadline_also_stops_a_wrapper_scripts_prover() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("prover.pid");
        let script = directory.path().join("wrapper.sh");
        let body = format!("sleep 30 &\necho $! > {}\nwait\n", pid_file.display());
        fs::write(&script, body).unwrap();

        // /bin/sh reads the script, so the test does not execute a file it has just written:
        // that can fail with ETXTBSY while another test in this process forks.
        let error = run_worker(
            Path::new("/bin/sh"),
            &[script.as_os_str()],
            Duration::from_millis(500),
            "proof generation",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("did not finish"), "{error}");

        let pid: libc::pid_t = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        // A stopped process can stay a zombie until init reaps it, so wait for it to disappear.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the prover {pid} outlived its wrapper"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
