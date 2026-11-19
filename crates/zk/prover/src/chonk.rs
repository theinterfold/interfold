// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The input of `bb prove --scheme chonk` for one Chonk stack. bb reads the stack from a msgpack
//! file (`--ivc_inputs_path`) of steps in accumulation order, each with its gzipped bytecode,
//! gzipped witness stack, Mega verification key and Chonk circuit kind. The prover writes that
//! file from witnesses generated in process and runs bb through
//! [`crate::prover::ZkProver::generate_chonk_proof`].

use crate::error::ZkError;
use crate::witness::CompiledCircuit;
use base64::{engine::general_purpose, Engine as _};
use e3_zk_config::CircuitName;
use serde::Serialize;
use serde_bytes::ByteBuf;

/// A Chonk circuit's Mega flavor, as bb 6 numbers it (`CircuitKind`).
#[derive(Clone, Copy)]
pub(crate) enum ChonkKind {
    App = 0,
    Kernel = 1,
    Hiding = 2,
}

/// One circuit of a Chonk stack, in accumulation order.
pub(crate) struct ChonkStackCircuit<'a> {
    pub circuit: CircuitName,
    pub kind: ChonkKind,
    pub compiled: &'a CompiledCircuit,
    /// The circuit's Mega key as `write_vk --scheme chonk` writes it.
    pub verification_key: &'a [u8],
    /// The witness stack as [`crate::witness::WitnessGenerator`] returns it (gzipped).
    pub witness: &'a [u8],
}

#[derive(Serialize)]
struct Step<'a> {
    bytecode: ByteBuf,
    witness: &'a serde_bytes::Bytes,
    vk: &'a serde_bytes::Bytes,
    #[serde(rename = "functionName")]
    function_name: &'a str,
    kind: u8,
}

/// Encodes `stack` as the file `bb prove --scheme chonk --ivc_inputs_path` reads.
pub(crate) fn ivc_inputs(stack: &[ChonkStackCircuit<'_>]) -> Result<Vec<u8>, ZkError> {
    let steps = stack
        .iter()
        .map(|entry| {
            Ok(Step {
                bytecode: ByteBuf::from(
                    general_purpose::STANDARD
                        .decode(&entry.compiled.bytecode)
                        .map_err(|e| ZkError::SerializationError(format!("base64 decode: {e}")))?,
                ),
                witness: serde_bytes::Bytes::new(entry.witness),
                vk: serde_bytes::Bytes::new(entry.verification_key),
                function_name: entry.circuit.as_str(),
                kind: entry.kind as u8,
            })
        })
        .collect::<Result<Vec<_>, ZkError>>()?;
    rmp_serde::to_vec_named(&steps).map_err(|e| ZkError::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stack_file_carries_each_step_in_order_with_its_kind() {
        let compiled = CompiledCircuit::from_json(
            r#"{"bytecode":"AQID","abi":{"parameters":[],"return_type":null,"error_types":{}}}"#,
        )
        .unwrap();
        let stack = [
            (CircuitName::C3ChonkApp, ChonkKind::App),
            (CircuitName::C3ChonkHidingKernel, ChonkKind::Hiding),
        ]
        .map(|(circuit, kind)| ChonkStackCircuit {
            circuit,
            kind,
            compiled: &compiled,
            verification_key: b"vk",
            witness: b"witness",
        });

        #[derive(serde::Deserialize)]
        struct Decoded {
            bytecode: ByteBuf,
            vk: ByteBuf,
            witness: ByteBuf,
            #[serde(rename = "functionName")]
            function_name: String,
            kind: u8,
        }
        let steps: Vec<Decoded> = rmp_serde::from_slice(&ivc_inputs(&stack).unwrap()).unwrap();

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].function_name, "c3_chonk_app");
        assert_eq!(steps[0].kind, 0);
        assert_eq!(steps[1].function_name, "c3_chonk_hiding_kernel");
        assert_eq!(steps[1].kind, 2);
        assert_eq!(steps[0].bytecode.as_ref(), [1, 2, 3]);
        assert_eq!(steps[0].vk.as_ref(), b"vk");
        assert_eq!(steps[0].witness.as_ref(), b"witness");
    }
}
