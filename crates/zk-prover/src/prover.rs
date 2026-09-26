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
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// Unique bb job directories — shared [`ZkBackend::work_dir`] must not reuse the same paths
/// when prove/verify runs concurrently (integration harness + `multithread_concurrent_jobs` > 1).
static BB_WORK_JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

const PROCESS_OUTPUT_LIMIT: usize = 4 * 1024;

struct JobDirGuard(PathBuf);

impl Drop for JobDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare_job_dir(job_dir: &Path) -> Result<JobDirGuard, std::io::Error> {
    // A process-level kill cannot run `JobDirGuard::drop`. The per-process counter restarts at
    // zero, so remove only this deterministic attempt directory before a recovered job reuses it.
    if job_dir.exists() {
        fs::remove_dir_all(job_dir)?;
    }
    fs::create_dir_all(job_dir)?;
    Ok(JobDirGuard(job_dir.to_path_buf()))
}

fn bounded_process_output(output: &[u8]) -> String {
    let value = String::from_utf8_lossy(output);
    if value.len() <= PROCESS_OUTPUT_LIMIT {
        return value.into_owned();
    }

    let mut end = PROCESS_OUTPUT_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n... truncated {} byte(s)",
        &value[..end],
        value.len() - end
    )
}

fn verifier_reported_invalid_proof(stderr: &str, stdout: &str) -> bool {
    stderr.contains("Proof verification failed") || stdout.contains("Proof verification failed")
}

fn next_bb_work_subdir(prefix: &str) -> String {
    let id = BB_WORK_JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{id}")
}

#[derive(Clone)]
pub struct ZkProver {
    bb_binary: PathBuf,
    circuits_dir: PathBuf,
    work_dir: PathBuf,
    slow_low_memory: bool,
}

impl ZkProver {
    pub fn new(backend: &ZkBackend) -> Self {
        Self {
            bb_binary: backend.bb_binary.clone(),
            circuits_dir: backend.circuits_dir.clone(),
            work_dir: backend.work_dir.clone(),
            slow_low_memory: false,
        }
    }

    /// Return a prover that asks Barretenberg to trade speed for a smaller memory peak.
    pub fn with_slow_low_memory(&self) -> Self {
        Self {
            slow_low_memory: true,
            ..self.clone()
        }
    }

    pub fn circuits_dir(&self, variant: CircuitVariant, artifacts_dir: &str) -> PathBuf {
        self.circuits_dir.join(artifacts_dir).join(variant.as_str())
    }

    pub(crate) fn circuits_root(&self) -> &std::path::Path {
        &self.circuits_dir
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
        let _job_dir_guard = JobDirGuard(job_dir.clone());

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

        let mut args = vec![
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
        if self.slow_low_memory {
            args.push("--slow_low_memory");
        }

        let output = StdCommand::new(&self.bb_binary).args(&args).output()?;

        if !output.status.success() {
            let stderr = bounded_process_output(&output.stderr);
            let stdout = bounded_process_output(&output.stdout);
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
        let _job_dir_guard = prepare_job_dir(&job_dir)?;
        fs::create_dir_all(&out_dir)?;
        let _job_dir_guard = JobDirGuard(job_dir.clone());

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

        let output = StdCommand::new(&self.bb_binary).args(&args).output()?;

        if !output.status.success() {
            let stderr = bounded_process_output(&output.stderr);
            let stdout = bounded_process_output(&output.stdout);
            if !verifier_reported_invalid_proof(&stderr, &stdout) {
                return Err(ZkError::VerifyFailed(format!(
                    "bb verification process failed without an invalid-proof result:\n\
                     stderr: {stderr}\nstdout: {stdout}"
                )));
            }
            warn!(
                "bb verification failed for {}:\nVK: {}\nstderr: {}\nstdout: {}",
                circuit.as_str(),
                vk_path.display(),
                stderr,
                stdout
            );
        }

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

        let result = prover.generate_proof(CircuitName::PkBfv, b"witness", "e3-1", "insecure");
        assert!(matches!(result, Err(ZkError::BbNotInstalled)));
    }

    #[test]
    fn process_output_is_bounded() {
        let input = vec![b'x'; PROCESS_OUTPUT_LIMIT + 100];
        let output = bounded_process_output(&input);

        assert!(output.contains("truncated 100 byte(s)"));
        assert!(output.len() < input.len());
    }

    #[test]
    fn low_memory_retry_enables_the_barretenberg_option() {
        let temp = get_tempdir().unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(temp.path().join("bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );

        let prover = ZkProver::new(&backend).with_slow_low_memory();

        assert!(prover.slow_low_memory);
    }

    #[test]
    fn job_directory_guard_removes_failed_attempt_files() {
        let temp = get_tempdir().unwrap();
        let job_dir = temp.path().join("job");
        fs::create_dir_all(&job_dir).unwrap();
        fs::write(job_dir.join("partial-proof"), b"partial").unwrap();

        {
            let _guard = JobDirGuard(job_dir.clone());
        }

        assert!(!job_dir.exists());
    }

    #[test]
    fn recovered_job_removes_a_stale_attempt_directory() {
        let temp = get_tempdir().unwrap();
        let job_dir = temp.path().join("job");
        fs::create_dir_all(&job_dir).unwrap();
        fs::write(job_dir.join("partial-proof"), b"partial").unwrap();

        let guard = prepare_job_dir(&job_dir).unwrap();

        assert!(job_dir.exists());
        assert!(!job_dir.join("partial-proof").exists());
        drop(guard);
        assert!(!job_dir.exists());
    }

    #[test]
    fn only_an_explicit_verifier_result_is_an_invalid_proof() {
        assert!(verifier_reported_invalid_proof(
            "Proof verification failed",
            ""
        ));
        assert!(verifier_reported_invalid_proof(
            "",
            "Proof verification failed: invalid proof size"
        ));
        assert!(!verifier_reported_invalid_proof("std::bad_alloc", ""));
        assert!(!verifier_reported_invalid_proof(
            "Cannot allocate memory",
            ""
        ));
        assert!(!verifier_reported_invalid_proof(
            "failed to write temporary file",
            ""
        ));
    }
}
