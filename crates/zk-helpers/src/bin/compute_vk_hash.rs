// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combine any number of Barretenberg `vk_hash` blobs (32 bytes each, big-endian field) with the
//! same SAFE sponge as Noir `lib::math::commitments::compute_vk_hash` (`DS_VK_HASH`).
//!
//! Input order is preserved — e.g. CRISP fold uses:
//! `user_data_encryption`, `crisp`, `ct0`, `ct1`.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use clap::Parser;
use e3_zk_helpers::compute_vk_hash;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "compute-vk-hash")]
#[command(about = "Hash N vk_hash files with compute_vk_hash (SAFE / DS_VK_HASH), order preserved")]
struct Args {
    /// Paths to 32-byte `vk_hash` files from `bb write_vk ... -o <dir>` (use one dir per circuit).
    #[arg(required_unless_present = "bfv_tree", conflicts_with = "bfv_tree")]
    vk_hash_files: Vec<PathBuf>,
    /// Artifact-pair directory with the complete BFV recursive verification-key tree.
    #[arg(long)]
    bfv_tree: Option<PathBuf>,
}

fn field_from_vk_hash_file(path: &std::path::Path) -> Result<Fr> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("{}: expected 32 bytes, got {}", path.display(), bytes.len());
    }
    let limbs = std::array::from_fn(|i| {
        let start = (3 - i) * 8;
        u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap())
    });
    let bigint = ark_ff::BigInt::<4>::new(limbs);
    Fr::from_bigint(bigint).ok_or_else(|| {
        anyhow::anyhow!(
            "{}: vk_hash is not in the canonical range [0, p)",
            path.display()
        )
    })
}

fn field_to_padded_be_hex(fr: Fr) -> String {
    let repr = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(repr.len());
    out[start..].copy_from_slice(&repr);
    format!("0x{}", hex::encode(out))
}

fn bfv_tree_hashes(root: &std::path::Path) -> Result<(Fr, Fr)> {
    let load = |variant: &str, group: &str, name: &str| {
        field_from_vk_hash_file(
            &root
                .join(variant)
                .join(group)
                .join(name)
                .join(format!("{name}.vk_hash")),
        )
    };
    let fold = |name| load("default", "recursive_aggregation", name);
    let c2_tree = compute_vk_hash(vec![
        load("recursive", "dkg", "sk_share_computation")?,
        load("recursive", "dkg", "e_sm_share_computation")?,
    ]);
    let c3_chain = compute_vk_hash(vec![
        fold("c3_fold")?,
        fold("c3_fold_kernel")?,
        load("recursive", "dkg", "share_encryption")?,
    ]);
    let c3_tree = compute_vk_hash(vec![c3_chain, c3_chain]);
    let c4 = load("recursive", "dkg", "share_decryption")?;
    let c4_tree = compute_vk_hash(vec![c4, c4]);
    let node_tree = compute_vk_hash(vec![
        load("recursive", "dkg", "pk")?,
        load("recursive", "threshold", "pk_generation")?,
        fold("c2ab_fold")?,
        c2_tree,
        fold("c3ab_fold")?,
        c3_tree,
        fold("c4ab_fold")?,
        c4_tree,
    ]);
    let nodes_tree = compute_vk_hash(vec![
        fold("nodes_fold")?,
        fold("nodes_fold_kernel")?,
        fold("node_fold")?,
        node_tree,
    ]);
    let c6_tree = compute_vk_hash(vec![
        fold("c6_fold")?,
        fold("c6_fold_kernel")?,
        load("recursive", "threshold", "share_decryption")?,
    ]);
    Ok((nodes_tree, c6_tree))
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(root) = args.bfv_tree {
        let (nodes_fold, c6_fold) = bfv_tree_hashes(&root)?;
        println!(
            "{}",
            serde_json::json!({
                "nodes_fold": field_to_padded_be_hex(nodes_fold),
                "c6_fold": field_to_padded_be_hex(c6_fold),
            })
        );
        return Ok(());
    }
    let mut fields = Vec::with_capacity(args.vk_hash_files.len());
    for path in &args.vk_hash_files {
        fields.push(field_from_vk_hash_file(path).with_context(|| path.display().to_string())?);
    }
    let combined = compute_vk_hash(fields);
    println!("{}", field_to_padded_be_hex(combined));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[(&str, &str, &str)] = &[
        ("recursive", "dkg", "sk_share_computation"),
        ("recursive", "dkg", "e_sm_share_computation"),
        ("default", "recursive_aggregation", "c3_fold"),
        ("default", "recursive_aggregation", "c3_fold_kernel"),
        ("recursive", "dkg", "share_encryption"),
        ("recursive", "dkg", "share_decryption"),
        ("recursive", "dkg", "pk"),
        ("recursive", "threshold", "pk_generation"),
        ("default", "recursive_aggregation", "c2ab_fold"),
        ("default", "recursive_aggregation", "c3ab_fold"),
        ("default", "recursive_aggregation", "c4ab_fold"),
        ("default", "recursive_aggregation", "nodes_fold"),
        ("default", "recursive_aggregation", "nodes_fold_kernel"),
        ("default", "recursive_aggregation", "node_fold"),
        ("default", "recursive_aggregation", "c6_fold"),
        ("default", "recursive_aggregation", "c6_fold_kernel"),
        ("recursive", "threshold", "share_decryption"),
    ];

    fn key_path(root: &std::path::Path, index: usize) -> PathBuf {
        let (variant, group, name) = KEYS[index];
        root.join(variant)
            .join(group)
            .join(name)
            .join(format!("{name}.vk_hash"))
    }

    fn write_field(path: &std::path::Path, value: Fr) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            hex::decode(&field_to_padded_be_hex(value)[2..]).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn bfv_tree_covers_every_descendant_with_the_circuit_order() {
        let temp = tempfile::tempdir().unwrap();
        let keys: Vec<_> = (1..=KEYS.len()).map(|i| Fr::from(i as u64)).collect();
        for (i, key) in keys.iter().enumerate() {
            write_field(&key_path(temp.path(), i), *key);
        }
        let c2 = compute_vk_hash(vec![keys[0], keys[1]]);
        let c3_chain = compute_vk_hash(vec![keys[2], keys[3], keys[4]]);
        let c3 = compute_vk_hash(vec![c3_chain, c3_chain]);
        let c4 = compute_vk_hash(vec![keys[5], keys[5]]);
        let node = compute_vk_hash(vec![
            keys[6], keys[7], keys[8], c2, keys[9], c3, keys[10], c4,
        ]);
        let expected = (
            compute_vk_hash(vec![keys[11], keys[12], keys[13], node]),
            compute_vk_hash(vec![keys[14], keys[15], keys[16]]),
        );
        assert_eq!(bfv_tree_hashes(temp.path()).unwrap(), expected);
        for (i, key) in keys.iter().enumerate() {
            let path = key_path(temp.path(), i);
            write_field(&path, Fr::from(99u64));
            let changed = bfv_tree_hashes(temp.path()).unwrap();
            if i < 14 {
                assert_ne!(changed.0, expected.0, "unbound DKG VK: {}", path.display());
                assert_eq!(changed.1, expected.1);
            } else {
                assert_eq!(changed.0, expected.0);
                assert_ne!(changed.1, expected.1, "unbound C6 VK: {}", path.display());
            }
            write_field(&path, *key);
        }
    }

    #[test]
    fn bfv_tree_rejects_missing_and_noncanonical_keys() {
        let temp = tempfile::tempdir().unwrap();
        for i in 0..KEYS.len() {
            write_field(&key_path(temp.path(), i), Fr::from(1u64));
        }
        let path = key_path(temp.path(), 0);
        fs::write(&path, [0xff; 32]).unwrap();
        assert!(bfv_tree_hashes(temp.path())
            .unwrap_err()
            .to_string()
            .contains("canonical range"));
        fs::write(&path, [0; 31]).unwrap();
        assert!(bfv_tree_hashes(temp.path())
            .unwrap_err()
            .to_string()
            .contains("expected 32 bytes"));
        fs::remove_file(&path).unwrap();
        assert!(bfv_tree_hashes(temp.path()).is_err());
    }
}
