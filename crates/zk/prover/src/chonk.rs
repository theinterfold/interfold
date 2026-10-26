// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Proves a Chonk stack through `bb msgpack run`, the only bb interface that accumulates a stack
//! from witnesses generated in process. Each message is a 4-byte little-endian length and a
//! msgpack `[[command, fields]]`; each response is a length and a msgpack `[response, fields]`.

use crate::error::ZkError;
use crate::witness::CompiledCircuit;
use base64::{engine::general_purpose, Engine as _};
use e3_events::CircuitName;
use flate2::read::GzDecoder;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, info};

/// The prover's tracing target and messages, so a stack is timed like a `bb prove` run.
const TRACE_TARGET: &str = "e3_zk_prover::prover";

/// One circuit of a Chonk stack, in accumulation order.
pub(crate) struct ChonkStackCircuit<'a> {
    pub circuit: CircuitName,
    pub compiled: &'a CompiledCircuit,
    /// The circuit's Mega key as `write_vk --scheme chonk` writes it.
    pub verification_key: &'a [u8],
    /// The witness stack as [`crate::witness::WitnessGenerator`] returns it (gzipped).
    pub witness: &'a [u8],
}

#[derive(Serialize)]
struct ChonkStart {
    num_circuits: u32,
}

#[derive(Serialize)]
struct CircuitInput<'a> {
    name: &'a str,
    bytecode: ByteBuf,
    verification_key: ByteBuf,
}

#[derive(Serialize)]
struct ChonkLoad<'a> {
    circuit: CircuitInput<'a>,
}

#[derive(Serialize)]
struct ChonkAccumulate {
    witness: ByteBuf,
}

#[derive(Serialize)]
struct ChonkProve {}

#[derive(Deserialize)]
struct ChonkProveResponse {
    proof: ChonkProof,
}

#[derive(Deserialize)]
struct ChonkProof {
    hiding_oink_proof: Vec<ByteBuf>,
    merge_proof: Vec<ByteBuf>,
    eccvm_proof: Vec<ByteBuf>,
    ipa_proof: Vec<ByteBuf>,
    joint_proof: Vec<ByteBuf>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    message: String,
}

struct Session {
    child: Arc<Mutex<Child>>,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Session {
    fn start(bb: &Path) -> Result<Self, ZkError> {
        let mut child = Command::new(bb)
            .args(["msgpack", "run"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            stdin,
            stdout,
        })
    }

    fn call<C: Serialize, R: DeserializeOwned>(
        &mut self,
        command: &str,
        fields: &C,
    ) -> Result<R, ZkError> {
        let request = rmp_serde::to_vec_named(&[(command, fields)])
            .map_err(|e| ZkError::SerializationError(format!("{command}: {e}")))?;
        self.stdin
            .write_all(&(request.len() as u32).to_le_bytes())?;
        self.stdin.write_all(&request)?;
        self.stdin.flush()?;

        let mut length = [0u8; 4];
        self.stdout.read_exact(&mut length).map_err(|e| {
            ZkError::ProveFailed(format!("bb msgpack gave no response to {command}: {e}"))
        })?;
        let mut response = vec![0u8; u32::from_le_bytes(length) as usize];
        self.stdout.read_exact(&mut response)?;
        let (name, _): (String, IgnoredAny) = rmp_serde::from_slice(&response)
            .map_err(|e| ZkError::SerializationError(format!("{command} response: {e}")))?;
        if name == "ErrorResponse" {
            let (_, error): (String, ErrorResponse) = rmp_serde::from_slice(&response)
                .map_err(|e| ZkError::SerializationError(format!("{command} error: {e}")))?;
            return Err(ZkError::ProveFailed(format!(
                "bb {command}: {}",
                error.message
            )));
        }
        let (_, result): (String, R) = rmp_serde::from_slice(&response)
            .map_err(|e| ZkError::SerializationError(format!("{name}: {e}")))?;
        Ok(result)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, ZkError> {
    let mut out = Vec::new();
    GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .map_err(|e| ZkError::SerializationError(format!("gunzip: {e}")))?;
    Ok(out)
}

/// Accumulates `stack` and proves it. Returns the Chonk proof's fields with its public inputs
/// first, as one byte string of 32-byte fields. A run longer than `timeout` is killed.
pub(crate) fn prove_stack(
    bb: &Path,
    stack: &[ChonkStackCircuit<'_>],
    job_id: &str,
    timeout: Duration,
) -> Result<Vec<u8>, ZkError> {
    if !bb.exists() {
        return Err(ZkError::BbNotInstalled);
    }
    let label = stack
        .first()
        .map_or("chonk", |entry| entry.circuit.as_str());
    debug!(target: TRACE_TARGET, "generating proof for circuit {label} (Chonk stack)");
    let mut session = Session::start(bb)?;
    let (done, finished) = mpsc::channel::<()>();
    let child = Arc::clone(&session.child);
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(timeout).is_err() {
            if let Ok(mut child) = child.lock() {
                let _ = child.kill();
            }
        }
    });

    let result = (|| {
        let _: IgnoredAny = session.call(
            "ChonkStart",
            &ChonkStart {
                num_circuits: stack.len() as u32,
            },
        )?;
        for entry in stack {
            let bytecode = general_purpose::STANDARD
                .decode(&entry.compiled.bytecode)
                .map_err(|e| ZkError::SerializationError(format!("base64 decode: {e}")))?;
            let _: IgnoredAny = session.call(
                "ChonkLoad",
                &ChonkLoad {
                    circuit: CircuitInput {
                        name: entry.circuit.as_str(),
                        bytecode: ByteBuf::from(gunzip(&bytecode)?),
                        verification_key: ByteBuf::from(entry.verification_key.to_vec()),
                    },
                },
            )?;
            let _: IgnoredAny = session.call(
                "ChonkAccumulate",
                &ChonkAccumulate {
                    witness: ByteBuf::from(gunzip(entry.witness)?),
                },
            )?;
        }
        let response: ChonkProveResponse = session.call("ChonkProve", &ChonkProve {})?;
        let proof = response.proof;
        let mut flat = Vec::new();
        for part in [
            proof.hiding_oink_proof,
            proof.merge_proof,
            proof.eccvm_proof,
            proof.ipa_proof,
            proof.joint_proof,
        ] {
            for field in part {
                if field.len() != 32 {
                    return Err(ZkError::SerializationError(format!(
                        "Chonk proof field of {} bytes",
                        field.len()
                    )));
                }
                flat.extend_from_slice(&field);
            }
        }
        Ok(flat)
    })();

    let _ = done.send(());
    let _ = watchdog.join();
    if let Ok(flat) = &result {
        info!(
            target: TRACE_TARGET,
            "generated proof ({} bytes) for {label} / {job_id}",
            flat.len()
        );
    }
    result
}
