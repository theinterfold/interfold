// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_witness::compute_vk_hash;
use std::{fs, path::Path};

fn load(root: &Path, variant: &str, group: &str, name: &str) -> Result<Fr> {
    let path = root
        .join(variant)
        .join(group)
        .join(name)
        .join(format!("{name}.vk_hash"));
    let bytes = fs::read(&path).with_context(|| format!("Read {}", path.display()))?;
    validate_field(&bytes).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
}

pub fn validate_field(bytes: &[u8]) -> Result<Fr> {
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    let limbs = std::array::from_fn(|i| {
        u64::from_be_bytes(bytes[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
    });
    Fr::from_bigint(ark_ff::BigInt::<4>::new(limbs))
        .context("vk_hash is not in the canonical range [0, p)")
}

pub fn hashes(root: &Path) -> Result<[(&'static str, [u8; 32]); 2]> {
    let fold = |name| load(root, "default", "recursive_aggregation", name);
    let c2 = compute_vk_hash(vec![
        load(root, "recursive", "dkg", "sk_share_computation")?,
        load(root, "recursive", "dkg", "e_sm_share_computation")?,
    ]);
    let c3_chain = compute_vk_hash(vec![
        fold("c3_fold")?,
        fold("c3_fold_kernel")?,
        load(root, "recursive", "dkg", "share_encryption")?,
    ]);
    let c3 = compute_vk_hash(vec![c3_chain, c3_chain]);
    let c4_key = load(root, "recursive", "dkg", "share_decryption")?;
    let c4 = compute_vk_hash(vec![c4_key, c4_key]);
    let node = compute_vk_hash(vec![
        load(root, "recursive", "dkg", "pk")?,
        load(root, "recursive", "threshold", "pk_generation")?,
        fold("c2ab_fold")?,
        c2,
        fold("c3ab_fold")?,
        c3,
        fold("c4ab_fold")?,
        c4,
    ]);
    let nodes = compute_vk_hash(vec![
        fold("nodes_fold")?,
        fold("nodes_fold_kernel")?,
        fold("node_fold")?,
        node,
    ]);
    let c6 = compute_vk_hash(vec![
        fold("c6_fold")?,
        fold("c6_fold_kernel")?,
        load(root, "recursive", "threshold", "share_decryption")?,
    ]);
    let encode = |value: Fr| {
        let repr = value.into_bigint().to_bytes_be();
        let mut bytes = [0; 32];
        bytes[32 - repr.len()..].copy_from_slice(&repr);
        bytes
    };
    Ok([("nodes_fold", encode(nodes)), ("c6_fold", encode(c6))])
}
