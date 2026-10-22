// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_witness::compute_vk_hash;
use std::{fs, path::Path};

#[derive(Debug, Clone)]
pub enum Component {
    Vk(&'static str, &'static str, &'static str),
    Tree(&'static str),
}

#[derive(Debug)]
pub struct Commitment {
    pub name: &'static str,
    pub dependencies: Vec<Component>,
    pub value: [u8; 32],
}

fn load(root: &Path, variant: &str, group: &str, name: &str) -> Result<Fr> {
    let path = root
        .join(variant)
        .join(group)
        .join(name)
        .join(format!("{name}.vk_hash"));
    field_from_file(&path)
}

fn field_from_file(path: &Path) -> Result<Fr> {
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

pub fn commitments(root: &Path) -> Result<Vec<Commitment>> {
    use Component::{Tree, Vk};
    let fold = |name| Vk("default", "recursive_aggregation", name);
    let topology = [
        (
            "c2_tree",
            vec![
                Vk("recursive", "dkg", "sk_share_computation"),
                Vk("recursive", "dkg", "e_sm_share_computation"),
            ],
        ),
        (
            "c3_chain",
            vec![
                fold("c3_fold"),
                fold("c3_fold_kernel"),
                Vk("recursive", "dkg", "share_encryption"),
            ],
        ),
        ("c3_tree", vec![Tree("c3_chain"), Tree("c3_chain")]),
        (
            "c4_tree",
            vec![
                Vk("recursive", "dkg", "share_decryption"),
                Vk("recursive", "dkg", "share_decryption"),
            ],
        ),
        (
            "node_tree",
            vec![
                Vk("recursive", "dkg", "pk"),
                Vk("recursive", "threshold", "pk_generation"),
                fold("c2ab_fold"),
                Tree("c2_tree"),
                fold("c3ab_fold"),
                Tree("c3_tree"),
                fold("c4ab_fold"),
                Tree("c4_tree"),
            ],
        ),
        (
            "nodes_fold",
            vec![
                fold("nodes_fold"),
                fold("nodes_fold_kernel"),
                fold("node_fold"),
                Tree("node_tree"),
            ],
        ),
        (
            "c6_fold",
            vec![
                fold("c6_fold"),
                fold("c6_fold_kernel"),
                Vk("recursive", "threshold", "share_decryption"),
            ],
        ),
    ];
    let encode = |value: Fr| {
        let repr = value.into_bigint().to_bytes_be();
        let mut bytes = [0; 32];
        bytes[32 - repr.len()..].copy_from_slice(&repr);
        bytes
    };
    let mut values = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    for (name, dependencies) in topology {
        let fields = dependencies
            .iter()
            .map(|dependency| match dependency {
                Vk(variant, group, circuit) => load(root, variant, group, circuit),
                Tree(child) => values
                    .get(child)
                    .copied()
                    .with_context(|| format!("Missing or cyclic tree dependency {child}")),
            })
            .collect::<Result<Vec<_>>>()?;
        let value = compute_vk_hash(fields);
        values.insert(name, value);
        out.push(Commitment {
            name,
            dependencies,
            value: encode(value),
        });
    }
    Ok(out)
}

pub fn hashes(root: &Path) -> Result<[(&'static str, [u8; 32]); 2]> {
    let trees = commitments(root)?;
    let get = |name| {
        trees
            .iter()
            .find(|tree| tree.name == name)
            .map(|tree| (tree.name, tree.value))
            .context("Missing final VK-tree anchor")
    };
    Ok([get("nodes_fold")?, get("c6_fold")?])
}
