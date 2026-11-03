// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Key trees of the chunked circuits. A final C2 or C4 proof verifies its chunk proofs against
//! keys the prover passes and exposes their hash as its last public field, so the proof alone does
//! not pin them. `c2ab_fold` and `c4ab_fold` anchor the hash in the VK tree for the on-chain path;
//! a peer verifying a C2 or C4 directly compares it here.

use crate::circuits::utils::bytes_to_field_strings;
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use e3_events::{CircuitName, CircuitVariant, Proof};

/// The chunk circuits a final circuit verifies, in the order its key tree hashes their keys.
pub fn chunk_circuits(final_circuit: CircuitName) -> Option<&'static [CircuitName]> {
    match final_circuit {
        CircuitName::SkShareComputation => Some(&[
            CircuitName::SkShareComputationChain,
            CircuitName::SkShareComputationChainLast,
        ]),
        CircuitName::ESmShareComputation => Some(&[
            CircuitName::ESmShareComputationChain,
            CircuitName::ESmShareComputationChainLast,
        ]),
        CircuitName::DkgShareDecryption => Some(&[
            CircuitName::DkgShareDecryptionLimb0,
            CircuitName::DkgShareDecryptionLimb1,
            CircuitName::DkgShareDecryptionLimb2,
        ]),
        _ => None,
    }
}

/// The key tree `circuit`'s final proof must expose last, from this node's chunk keys.
pub fn expected_key_tree(
    prover: &ZkProver,
    circuit: CircuitName,
    artifacts_dir: &str,
) -> Result<Fr, ZkError> {
    let chunks = chunk_circuits(circuit)
        .ok_or_else(|| ZkError::InvalidInput(format!("{circuit} is not a chunked circuit")))?;
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let hashes = chunks
        .iter()
        .map(|chunk| hex_to_field(&vk::load_vk_artifacts(&default_dir, *chunk)?.key_hash))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(e3_zk_witness::compute_vk_hash(hashes))
}

/// Checks a verified final proof was built from this node's chunk circuits.
pub fn check_key_tree(
    prover: &ZkProver,
    proof: &Proof,
    artifacts_dir: &str,
) -> Result<bool, ZkError> {
    let publics = bytes_to_field_strings(&proof.public_signals)?;
    let Some(last) = publics.last() else {
        return Ok(false);
    };
    Ok(hex_to_field(last)? == expected_key_tree(prover, proof.circuit, artifacts_dir)?)
}

fn hex_to_field(value: &str) -> Result<Fr, ZkError> {
    let digits = value.trim_start_matches("0x");
    let bytes = hex::decode(if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits.to_string()
    })
    .map_err(|e| ZkError::InvalidInput(format!("key hash {value}: {e}")))?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ZkBackend;
    use crate::test_utils::get_tempdir;
    use ark_ff::BigInteger;
    use e3_config::BBPath;
    use e3_utils::ArcBytes;

    fn field_bytes(value: Fr) -> Vec<u8> {
        let repr = value.into_bigint().to_bytes_be();
        let mut out = vec![0; 32 - repr.len()];
        out.extend(repr);
        out
    }

    /// A chunked proof passes only when its last public field is the hash of this node's chunk keys
    /// for its circuit.
    #[test]
    fn key_tree_check_pins_the_chain_keys() {
        let temp = get_tempdir().unwrap();
        let backend = ZkBackend::new(
            BBPath::Default(temp.path().join("bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
        );
        let prover = ZkProver::new(&backend);
        let artifacts_dir = "insecure-64/minimum";
        let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        for (i, circuit) in [
            CircuitName::SkShareComputationChain,
            CircuitName::SkShareComputationChainLast,
        ]
        .into_iter()
        .enumerate()
        {
            let dir = default_dir.join(circuit.dir_path());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{}.vk", circuit.as_str())), [0u8; 32]).unwrap();
            std::fs::write(
                dir.join(format!("{}.vk_hash", circuit.as_str())),
                field_bytes(Fr::from(i as u64 + 1)),
            )
            .unwrap();
        }
        let tree = e3_zk_witness::compute_vk_hash(vec![Fr::from(1u64), Fr::from(2u64)]);
        let proof = |last: Fr| {
            let mut signals = field_bytes(Fr::from(7u64));
            signals.extend(field_bytes(last));
            Proof::new(
                CircuitName::SkShareComputation,
                ArcBytes::from_bytes(&[0u8; 8]),
                ArcBytes::from_bytes(&signals),
            )
        };

        assert!(check_key_tree(&prover, &proof(tree), artifacts_dir).unwrap());
        assert!(!check_key_tree(&prover, &proof(tree + Fr::from(1u64)), artifacts_dir).unwrap());
        let other = Proof::new(
            CircuitName::ShareEncryption,
            ArcBytes::from_bytes(&[0u8; 8]),
            ArcBytes::from_bytes(&field_bytes(tree)),
        );
        assert!(check_key_tree(&prover, &other, artifacts_dir).is_err());
    }
}
