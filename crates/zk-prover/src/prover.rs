// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::backend::ZkBackend;
use crate::error::ZkError;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Environment override for the `bb` wall-clock cap, in seconds.
pub const BB_TIMEOUT_ENV: &str = "INTERFOLD_BB_TIMEOUT_SECS";

/// Default wall-clock cap for one `bb` invocation.
///
/// Matches the DKG window (`E3_DKG_WINDOW_SECS`, 7200 s): a proof that has not finished by
/// then cannot be used by the E3 it was for. Without a cap a hung `bb` (seen with a bad
/// witness on some platforms, and under memory pressure) occupies a job slot for the life
/// of the process and, with `max_concurrent_jobs` slots, a handful of hangs stops the node
/// from proving anything.
pub const DEFAULT_BB_TIMEOUT: Duration = Duration::from_secs(7200);

/// How often the waiter polls the child between checks of the deadline.
const BB_POLL_INTERVAL: Duration = Duration::from_millis(250);

fn bb_timeout() -> Duration {
    std::env::var(BB_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BB_TIMEOUT)
}

/// Run `bb` with the given arguments, killing it if it exceeds the wall-clock cap.
///
/// Equivalent to `Command::output()` on the happy path. On timeout the child is killed and
/// reaped so it cannot linger as a zombie or keep its job slot, and a `ZkError::Timeout`
/// names the operation that hung.
fn run_bb_with_timeout(
    bb_binary: &PathBuf,
    args: &[&str],
    operation: &str,
    timeout: Duration,
) -> Result<Output, ZkError> {
    let mut child = StdCommand::new(bb_binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Drain the pipes on threads so a chatty `bb` cannot block on a full pipe while we
    // wait — that would look exactly like the hang we are guarding against.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = stderr_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if started.elapsed() >= timeout => {
                warn!(
                    operation,
                    timeout_secs = timeout.as_secs(),
                    "bb exceeded its wall-clock cap; killing it"
                );
                let _ = child.kill();
                let _ = child.wait();
                return Err(ZkError::Timeout(format!(
                    "bb {operation} exceeded {}s (set {BB_TIMEOUT_ENV} to change the cap)",
                    timeout.as_secs()
                )));
            }
            None => std::thread::sleep(BB_POLL_INTERVAL),
        }
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Unique bb job directories — shared [`ZkBackend::work_dir`] must not reuse the same paths
/// when prove/verify runs concurrently (integration harness + `multithread_concurrent_jobs` > 1).
static BB_WORK_JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_bb_work_subdir(prefix: &str) -> String {
    let id = BB_WORK_JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{id}")
}

pub struct ZkProver {
    bb_binary: PathBuf,
    circuits_dir: PathBuf,
    work_dir: PathBuf,
}

impl ZkProver {
    pub fn new(backend: &ZkBackend) -> Self {
        Self {
            bb_binary: backend.bb_binary.clone(),
            circuits_dir: backend.circuits_dir.clone(),
            work_dir: backend.work_dir.clone(),
        }
    }

    pub fn circuits_dir(&self, variant: CircuitVariant, artifacts_dir: &str) -> PathBuf {
        self.circuits_dir.join(artifacts_dir).join(variant.as_str())
    }

    pub fn resolve_artifacts_dir(&self, preset: BfvPreset, committee: &str) -> String {
        preset.artifacts_dir_for_committee(committee)
    }

    pub fn work_dir(&self) -> &PathBuf {
        &self.work_dir
    }

    pub fn bb_binary(&self) -> &PathBuf {
        &self.bb_binary
    }

    pub fn generate_proof(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.generate_proof_with_variant(
            circuit,
            witness_data,
            e3_id,
            CircuitVariant::Recursive,
            artifacts_dir,
        )
    }

    pub fn generate_evm_proof(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.generate_proof_with_variant(
            circuit,
            witness_data,
            e3_id,
            CircuitVariant::Evm,
            artifacts_dir,
        )
    }

    pub fn generate_proof_with_variant(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.generate_proof_impl(
            circuit,
            witness_data,
            e3_id,
            &circuit.dir_path(),
            variant,
            artifacts_dir,
        )
    }

    /// Proof for a `recursive_aggregation/*` bin circuit (Default / `noir-recursive-no-zk`).
    pub fn generate_recursive_aggregation_bin_proof(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.generate_proof_impl(
            circuit,
            witness_data,
            e3_id,
            &circuit.dir_path(),
            CircuitVariant::Default,
            artifacts_dir,
        )
    }

    fn generate_proof_impl(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        dir_path: &str,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.generate_proof_impl_with_dir(
            circuit,
            witness_data,
            e3_id,
            dir_path,
            variant,
            self.circuits_dir(variant, artifacts_dir),
        )
    }

    fn generate_proof_impl_with_dir(
        &self,
        circuit: CircuitName,
        witness_data: &[u8],
        e3_id: &str,
        dir_path: &str,
        variant: CircuitVariant,
        base_dir: std::path::PathBuf,
    ) -> Result<Proof, ZkError> {
        if !self.bb_binary.exists() {
            return Err(ZkError::BbNotInstalled);
        }

        let verifier_target = variant.verifier_target();

        let circuit_dir = base_dir.join(dir_path);
        let circuit_path = circuit_dir.join(format!("{}.json", circuit.as_str()));
        let vk_path = circuit_dir.join(format!("{}.vk", circuit.as_str()));

        if !circuit_path.exists() {
            return Err(ZkError::CircuitNotFound(format!(
                "Circuit not found: {} (expected at {})",
                circuit.as_str(),
                circuit_path.display()
            )));
        }
        if !vk_path.exists() {
            return Err(ZkError::CircuitNotFound(format!(
                "VK not found: {}",
                vk_path.display()
            )));
        }

        let job_dir = self
            .work_dir
            .join(e3_id)
            .join(next_bb_work_subdir(&format!("prove_{}", circuit.as_str())));
        let witness_path = job_dir.join("witness.gz");
        let output_dir = job_dir.join("out");
        fs::create_dir_all(&job_dir)?;

        fs::write(&witness_path, witness_data)?;

        debug!(
            "generating proof for circuit {} using circuit: {}, vk: {}",
            circuit.as_str(),
            circuit_path.display(),
            vk_path.display()
        );

        let circuit_path_s = circuit_path.to_string_lossy();
        let witness_path_s = witness_path.to_string_lossy();
        let vk_path_s = vk_path.to_string_lossy();
        let output_dir_s = output_dir.to_string_lossy();

        let args = vec![
            "prove",
            "-b",
            circuit_path_s.as_ref(),
            "-w",
            witness_path_s.as_ref(),
            "-k",
            vk_path_s.as_ref(),
            "-o",
            output_dir_s.as_ref(),
            "-v",
            "-t",
            verifier_target,
        ];

        let output = run_bb_with_timeout(&self.bb_binary, &args, "prove", bb_timeout())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(ZkError::ProveFailed(format!(
                "bb prove failed:\nstderr: {}\nstdout: {}",
                stderr, stdout
            )));
        }

        let proof_path = output_dir.join("proof");
        let public_inputs_path = output_dir.join("public_inputs");
        let proof_data = fs::read(&proof_path).map_err(|e| {
            ZkError::OutputReadError(format!(
                "bb output {}: {} (if bb exited 0, check bb version / prover flags)",
                proof_path.display(),
                e
            ))
        })?;
        let public_signals = fs::read(&public_inputs_path).map_err(|e| {
            ZkError::OutputReadError(format!("bb output {}: {}", public_inputs_path.display(), e))
        })?;

        info!(
            "generated proof ({} bytes) for {} / {}",
            proof_data.len(),
            circuit.as_str(),
            e3_id
        );

        let _ = fs::remove_dir_all(&job_dir);

        Ok(Proof::new(
            circuit,
            ArcBytes::from_bytes(&proof_data),
            ArcBytes::from_bytes(&public_signals),
        ))
    }

    /// Verifies a proof (Recursive variant, matching `prove()`).
    pub fn verify_proof(
        &self,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        self.verify_proof_with_variant(
            proof,
            e3_id,
            party_id,
            CircuitVariant::Recursive,
            artifacts_dir,
        )
    }

    pub fn verify_proof_with_variant(
        &self,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        self.verify_proof_impl(
            proof.circuit,
            &proof.data,
            &proof.public_signals,
            proof.circuit.dir_path(),
            e3_id,
            party_id,
            variant,
            artifacts_dir,
        )
    }

    pub fn verify_evm_proof(
        &self,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        self.verify_proof_with_variant(proof, e3_id, party_id, CircuitVariant::Evm, artifacts_dir)
    }

    /// Verifies a recursive-aggregation bin proof (Default variant).
    pub fn verify_fold_proof(
        &self,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        self.verify_proof_with_variant(
            proof,
            e3_id,
            party_id,
            CircuitVariant::Default,
            artifacts_dir,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_proof_impl(
        &self,
        circuit: CircuitName,
        proof_data: &[u8],
        public_signals: &[u8],
        dir_path: String,
        e3_id: &str,
        party_id: u64,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        if !self.bb_binary.exists() {
            return Err(ZkError::BbNotInstalled);
        }

        let verifier_target = variant.verifier_target();
        let vk_path = self
            .circuits_dir(variant, artifacts_dir)
            .join(&dir_path)
            .join(format!("{}.vk", circuit.as_str()));
        if !vk_path.exists() {
            return Err(ZkError::CircuitNotFound(format!(
                "VK not found: {}",
                vk_path.display()
            )));
        }

        debug!(
            "verifying proof for circuit {} (party {}) using VK: {}",
            circuit.as_str(),
            party_id,
            vk_path.display()
        );

        let job_dir = self.work_dir.join(e3_id).join(next_bb_work_subdir(&format!(
            "verify_party_{party_id}_{}",
            circuit.as_str()
        )));
        let out_dir = job_dir.join("out");
        fs::create_dir_all(&out_dir)?;

        let proof_path = job_dir.join("proof");
        let public_inputs_path = out_dir.join("public_inputs");

        fs::write(&proof_path, proof_data)?;
        fs::write(&public_inputs_path, public_signals)?;

        let public_inputs_s = public_inputs_path.to_string_lossy();
        let proof_s = proof_path.to_string_lossy();
        let vk_s = vk_path.to_string_lossy();

        let args = vec![
            "verify",
            "--scheme",
            "ultra_honk",
            "-i",
            public_inputs_s.as_ref(),
            "-p",
            proof_s.as_ref(),
            "-k",
            vk_s.as_ref(),
            "-t",
            verifier_target,
        ];

        let output = run_bb_with_timeout(&self.bb_binary, &args, "verify", bb_timeout())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            warn!(
                "bb verification failed for {}:\nVK: {}\nstderr: {}\nstdout: {}",
                circuit.as_str(),
                vk_path.display(),
                stderr,
                stdout
            );
        }

        let _ = fs::remove_dir_all(&job_dir);

        Ok(output.status.success())
    }

    pub fn cleanup(&self, e3_id: &str) -> Result<(), ZkError> {
        let job_dir = self.work_dir.join(e3_id);
        if job_dir.exists() {
            fs::remove_dir_all(&job_dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_tempdir;
    use e3_config::BBPath;

    #[test]
    fn test_prover_requires_bb() {
        let temp = get_tempdir().unwrap();
        let temp_path = temp.path();
        let noir_dir = temp_path.join("noir");
        let bb_binary = noir_dir.join("bin").join("bb");
        let circuits_dir = noir_dir.join("circuits");
        let work_dir = noir_dir.join("work").join("test_node");
        let backend = ZkBackend::new(BBPath::Default(bb_binary), circuits_dir, work_dir);
        let prover = ZkProver::new(&backend);

        let result = prover.generate_proof(CircuitName::PkBfv, b"witness", "e3-1", "insecure-512");
        assert!(matches!(result, Err(ZkError::BbNotInstalled)));
    }

    /// A hung `bb` must be killed at the cap, not left holding a job slot forever. `sleep`
    /// stands in for a hung `bb`; the cap is well under its duration.
    #[test]
    fn a_hung_bb_is_killed_at_the_wall_clock_cap() {
        let sleep = PathBuf::from("/bin/sleep");
        if !sleep.exists() {
            return;
        }
        let started = Instant::now();
        let result = run_bb_with_timeout(&sleep, &["30"], "prove", Duration::from_millis(600));
        let elapsed = started.elapsed();

        let err = result.expect_err("a bb that outlives the cap must be reported as a timeout");
        assert!(matches!(err, ZkError::Timeout(_)), "got {err}");
        assert!(err.to_string().contains("prove"));
        assert!(err.to_string().contains(BB_TIMEOUT_ENV));
        assert!(
            elapsed < Duration::from_secs(5),
            "the child must be killed at the cap, not waited for; took {elapsed:?}"
        );
    }

    /// The happy path is unchanged: output and exit status come back as with `output()`.
    #[test]
    fn a_finishing_bb_returns_its_output() {
        let echo = PathBuf::from("/bin/echo");
        if !echo.exists() {
            return;
        }
        let output = run_bb_with_timeout(&echo, &["proof-ok"], "verify", DEFAULT_BB_TIMEOUT)
            .expect("echo must succeed");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "proof-ok");
    }
}
