// SPDX-License-Identifier: LGPL-3.0-only

//! Source-built decryption candidates, never a complete release/archive stamp.
use crate::{
    artifacts, identity, run, write_json, CommitteeSelection, Group, GroupSelection, Request,
};
use anyhow::{ensure, Context, Result};
use e3_zk_config::{CircuitName, CircuitVariant};
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub(super) fn build(root: &Path, request: &Request) -> Result<()> {
    let profile = request.single_profile()?;
    let CommitteeSelection::Single(committee) = request.committee else {
        anyhow::bail!("single committee required");
    };
    let export = fs::canonicalize(request.output.as_ref().context("missing proof directory")?)?;
    let destination = export.join("candidate");
    ensure!(!destination.exists(), "candidate directory already exists");
    let fields = fs::read(export.join("public_inputs"))?;
    let config = e3_zk_config::synchronized::Configs::for_profile(profile, committee)?;
    e3_zk_config::synchronized::public_signals::PublicSignals::decode(
        &config,
        CircuitName::DecryptionAggregator,
        &fields,
    )?;
    identity::check_tools(root, true, true)?;
    let (noir, bb) = identity::toolchain(root)?;
    let mut selection = request.clone();
    selection.groups =
        GroupSelection::Selected(vec![Group::Threshold, Group::RecursiveAggregation]);
    let roles = [
        (
            CircuitName::ThresholdShareDecryption,
            CircuitVariant::Recursive,
        ),
        (
            CircuitName::DecryptedSharesAggregation,
            CircuitVariant::Recursive,
        ),
        (CircuitName::DecryptionAggregator, CircuitVariant::Evm),
    ];
    selection.circuits = roles
        .iter()
        .map(|(role, _)| role.as_str().to_string())
        .collect();
    let source_hash = identity::source_hash(
        root,
        &selection,
        Some(profile.artifacts_namespace()),
        Some(committee.as_str()),
    )?;
    let circuits = artifacts::discover(root, &selection)?;
    let tmp = tempfile::tempdir_in(&export)?;
    let mut records = Vec::new();
    for (i, (role, variant)) in roles.into_iter().enumerate() {
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
        if i < 2 {
            ensure!(
                pin[..] == fields[i * 32..(i + 1) * 32],
                "qualified proof does not pin {role}"
            );
        } else {
            run(Command::new("bb")
                .args(["verify", "-t", target, "-k"])
                .arg(&vk)
                .arg("-p")
                .arg(export.join("proof"))
                .arg("-i")
                .arg(export.join("public_inputs")))?;
            run(Command::new("pnpm")
                .args(["exec", "tsx", "scripts/circuits/render-sync-honk.ts"])
                .arg(&dir)
                .env("E3_CUSTOM_BB", "bb")
                .current_dir(root))?;
            record["soliditySha256"] =
                json!(identity::checksum(&dir.join("SynchronizedHonk.sol"))?);
        }
        records.push(record);
    }
    write_json(
        &tmp.path().join("manifest.json"),
        &json!({"formatVersion":1,"scope":"decryption-only","admissionEnabled":false,
        "profile":profile.name(),"committee":committee.as_str(),"cryptoConfigId":profile.crypto_config_id(committee)?.to_string(),
        "sourceHash":source_hash,"nargo":noir,"bb":bb,"circuits":records}),
    )?;
    fs::rename(tmp.path(), &destination)?;
    println!("Verified candidate: {}", destination.display());
    Ok(())
}
