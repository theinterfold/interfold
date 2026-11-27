// SPDX-License-Identifier: LGPL-3.0-only

//! Source-built synchronized Minimum candidates, never release/archive stamps.
use crate::{artifacts, identity, run, write_json, CommitteeSelection, Operation, Request};
use alloy_primitives::{Bytes, B256};
use anyhow::{ensure, Context, Result};
use e3_zk_config::CircuitName;
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, fs, path::Path, process::Command};

#[derive(Deserialize)]
struct Publication {
    proof: Bytes,
    public_inputs: Vec<B256>,
    crypto_config_id: B256,
}

type BuiltKeys = HashMap<CircuitName, (Vec<u8>, [u8; 32])>;

impl Operation {
    pub(super) fn candidate_roles(self) -> Option<&'static [CircuitName]> {
        match self {
            Self::DkgCandidate => Some(&CircuitName::SYNCHRONIZED_DKG),
            Self::DecryptionCandidate => Some(&CircuitName::SYNCHRONIZED_DECRYPTION),
            _ => None,
        }
    }
}

fn publication_pins(keys: &BuiltKeys) -> Result<[[u8; 32]; 2]> {
    use e3_zk_witness::synchronized::{provenance, publication};
    use CircuitName::*;
    let key = |role| -> Result<provenance::VerificationKey<'_>> {
        let (fields, hash) = keys
            .get(&role)
            .context("missing synchronized DKG descendant")?;
        let key = provenance::VerificationKey {
            fields,
            hash: *hash,
        };
        key.validate_recursive_honk()?;
        Ok(key)
    };
    let descendants = provenance::VerificationKeys {
        c0: key(PkBfv)?,
        c1: key(PkGeneration)?,
        c2: key(SkShareComputation)?,
        c3: key(ShareEncryption)?,
        c4: key(DkgShareDecryption)?,
        node: key(NodeFold)?,
    }
    .setup_tree()?;
    let publication = publication::VerificationKeys {
        setup: key(NodesFold)?,
        descendants,
        c5: key(PkAggregation)?,
    };
    Ok([publication.tree()?, publication.c5.hash])
}

pub(super) fn build(root: &Path, request: &Request) -> Result<()> {
    let profile = request.single_profile()?;
    let CommitteeSelection::Single(committee) = request.committee else {
        anyhow::bail!("single committee required");
    };
    let export = fs::canonicalize(request.output.as_ref().context("missing proof directory")?)?;
    let dkg = request.operation == Operation::DkgCandidate;
    let destination = export.join(if dkg { "dkg-candidate" } else { "candidate" });
    ensure!(!destination.exists(), "candidate directory already exists");
    let evidence = tempfile::tempdir_in(&export)?;
    let roles = request
        .operation
        .candidate_roles()
        .context("missing candidate graph")?;
    let outer = *roles.last().context("empty candidate graph")?;
    let proof_dir = if dkg {
        let publication: Publication =
            serde_json::from_slice(&fs::read(export.join("publication.json"))?)?;
        ensure!(
            publication.crypto_config_id == profile.crypto_config_id(committee)?,
            "publication belongs to a different profile or committee"
        );
        fs::write(evidence.path().join("proof"), &publication.proof)?;
        fs::write(
            evidence.path().join("public_inputs"),
            publication
                .public_inputs
                .iter()
                .flat_map(|v| v.0)
                .collect::<Vec<_>>(),
        )?;
        evidence.path()
    } else {
        &export
    };
    let fields = fs::read(proof_dir.join("public_inputs"))?;
    let config = e3_zk_config::synchronized::Configs::for_profile(profile, committee)?;
    e3_zk_config::synchronized::public_signals::PublicSignals::decode(&config, outer, &fields)?;
    identity::check_tools(root, true, true)?;
    let (noir, bb) = identity::toolchain(root)?;
    let source_hash = identity::source_hash(
        root,
        request,
        Some(profile.artifacts_namespace()),
        Some(committee.as_str()),
    )?;
    let circuits = artifacts::discover(root, request)?;
    let tmp = tempfile::tempdir_in(&export)?;
    let mut records = Vec::new();
    let mut keys = HashMap::new();
    for (i, &role) in roles.iter().enumerate() {
        let variant = role
            .synchronized_variant()
            .context("not a synchronized proof role")?;
        let circuit = circuits
            .iter()
            .find(|c| c.group == role.group() && c.name == role.as_str())
            .context("missing profile-specific definition")?;
        let target = variant.verifier_target();
        let subdir = format!("{}/{}", variant.as_str(), role.dir_path());
        let dir = tmp.path().join(&subdir);
        fs::create_dir_all(&dir)?;
        run(Command::new("nargo")
            .args(["compile", "--package", &circuit.package])
            .current_dir(&circuit.path))?;
        let name = format!("{}.json", circuit.package);
        let acir = dir.join(&name);
        fs::copy(artifacts::target_dir(root, circuit)?.join(&name), &acir)?;
        artifacts::sanitize_paths(&acir)?;
        let gates: serde_json::Value = serde_json::from_str(&run(Command::new("bb")
            .args(["gates", "-t", target, "-b"])
            .arg(&acir))?)?;
        let count = gates
            .pointer("/functions/0/circuit_size")
            .and_then(|v| v.as_u64())
            .context("missing bb circuit size")?;
        run(Command::new("bb")
            .args(["write_vk", "-t", target, "-b"])
            .arg(&acir)
            .arg("-o")
            .arg(&dir))?;
        let pin = fs::read(dir.join("vk_hash"))?;
        ensure!(pin.len() == 32, "invalid BB VK hash");
        let vk = acir.with_extension("vk");
        fs::rename(dir.join("vk"), &vk)?;
        fs::rename(dir.join("vk_hash"), acir.with_extension("vk_hash"))?;
        let mut record = json!({"role":role.as_str(),"path":subdir,"target":target,"gates":count,"circuitSha256":identity::checksum(&acir)?,
            "vkSha256":identity::checksum(&vk)?,"vkHash":format!("0x{}",hex::encode(&pin))});
        if role != outer && dkg {
            keys.insert(role, (fs::read(&vk)?, pin.try_into().unwrap()));
        } else if role != outer {
            ensure!(
                pin[..] == fields[i * 32..(i + 1) * 32],
                "qualified proof does not pin {role}"
            );
        } else {
            if dkg {
                let pins = publication_pins(&keys)?;
                ensure!(
                    pins.concat() == fields[..64],
                    "DKG proof does not pin the independently built setup tree and C5"
                );
            }
            run(Command::new("bb")
                .args(["verify", "-t", target, "-k"])
                .arg(&vk)
                .arg("-p")
                .arg(proof_dir.join("proof"))
                .arg("-i")
                .arg(proof_dir.join("public_inputs")))?;
            run(Command::new("pnpm")
                .args(["exec", "tsx", "scripts/circuits/render-sync-honk.ts"])
                .arg(&dir)
                .arg(outer.as_str())
                .env("E3_CUSTOM_BB", "bb")
                .current_dir(root))?;
            record["soliditySha256"] =
                json!(identity::checksum(&dir.join("SynchronizedHonk.sol"))?);
            if dkg {
                ensure!(
                    fs::read(export.join("DkgHonk.sol"))?
                        == fs::read(dir.join("SynchronizedHonk.sol"))?,
                    "DKG verifier differs from the signed rehearsal"
                );
            }
        }
        records.push(record);
    }
    let mut manifest = json!({"formatVersion":1,"scope":if dkg { "dkg-publication" } else { "decryption-only" },"admissionEnabled":false,
        "profile":profile.name(),"committee":committee.as_str(),"cryptoConfigId":profile.crypto_config_id(committee)?.to_string(),
        "sourceHash":source_hash,"nargo":noir,"bb":bb,"circuits":records});
    if dkg {
        manifest["setupTreeHash"] = json!(format!("0x{}", hex::encode(&fields[..32])));
        manifest["c5KeyHash"] = json!(format!("0x{}", hex::encode(&fields[32..64])));
    }
    write_json(&tmp.path().join("manifest.json"), &manifest)?;
    fs::rename(tmp.path(), &destination)?;
    println!("Verified candidate: {}", destination.display());
    Ok(())
}
