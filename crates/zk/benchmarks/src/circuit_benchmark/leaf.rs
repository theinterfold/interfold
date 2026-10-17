// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    artifacts,
    inputs::{self, Material, Ude},
    records::{Record, SharedPreparation},
    run,
    selection::Case,
    Options,
};
use anyhow::{bail, Result};
use e3_zk_prover::{WitnessGenerator, ZkProver};
use std::{fs, path::Path, process::Command, time::Instant};

#[allow(clippy::too_many_arguments)]
pub(crate) fn benchmark(
    root: &Path,
    output: &Path,
    work: &Path,
    options: &Options,
    prover: &ZkProver,
    pair: &str,
    noir: &str,
    material: &Material,
    case: Case,
    ude: &mut Option<Ude>,
    shared: &mut Vec<SharedPreparation>,
    record: &mut Record,
) -> Result<()> {
    let variant = super::selection::variant(&options.variant)?;
    if case == Case::Config && options.bench_compile {
        record.compilation.metric = "config_compile_and_provenance_wall".into();
        let start = Instant::now();
        let result = artifacts::compile_config(root, pair, noir);
        record.compilation.finish(start.elapsed(), &result);
        result?;
    }
    let (compiled, path, vk, identity) = artifacts::load(
        root,
        prover,
        pair,
        case,
        variant,
        noir,
        !options.witness_only && !options.bench_vk,
    )?;
    record.circuit_size_bytes = Some(fs::metadata(&path)?.len());
    record.vk_size_bytes = identity
        .vk_sha256
        .is_some()
        .then(|| fs::metadata(&vk).map(|data| data.len()))
        .transpose()?;
    record.artifact = Some(identity);
    let inputs = inputs::prepare(material, case, &compiled, ude, shared, record)?;
    if options.export_toml {
        fs::write(
            output.join(format!("{}.toml", case.path().replace('/', "_"))),
            noirc_abi::input_parser::Format::Toml.serialize(&inputs, &compiled.abi)?,
        )?;
    }
    let start = Instant::now();
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, inputs)
        .map_err(anyhow::Error::from);
    record.execution.finish(start.elapsed(), &witness);
    let witness = witness?;
    record.witness_size_bytes = Some(witness.len() as u64);
    if !options.skip_gates && !options.witness_only {
        let result = run(Command::new(prover.bb_binary())
            .args(["gates", "-b"])
            .arg(&path)
            .args(["-t", variant.verifier_target()]))
        .and_then(|text| artifacts::gate_counts(&text));
        match result {
            Ok((gates, opcodes)) => {
                record.gates.total_gates = Some(gates);
                record.gates.acir_opcodes = opcodes;
            }
            Err(error) => {
                record.gates.error = Some(format!("{error:#}"));
                return Err(error);
            }
        }
    }
    if options.witness_only {
        return Ok(());
    }
    let job = tempfile::Builder::new()
        .prefix("bb-leaf-")
        .tempdir_in(work)?;
    let mut selected_vk = vk.clone();
    if options.bench_vk {
        let start = Instant::now();
        let result = run(Command::new(prover.bb_binary())
            .args(["write_vk", "-b"])
            .arg(&path)
            .arg("-o")
            .arg(job.path())
            .args(["-t", variant.verifier_target()]));
        record.vk_generation.finish(start.elapsed(), &result);
        result?;
        selected_vk = job.path().join("vk");
        if case == Case::Config {
            record.artifact.as_mut().unwrap().source_stamp =
                artifacts::bind_config_vk(root, &path, variant, &selected_vk, &vk)?;
        }
        record.vk_size_bytes = Some(fs::metadata(&selected_vk)?.len());
        record.artifact.as_mut().unwrap().vk_sha256 = Some(artifacts::digest(&selected_vk)?);
    }
    if let Case::Named(name) = case {
        // The production adapter reads its immutable VK. Measured regeneration is a comparison only.
        if options.bench_vk
            && artifacts::digest(&selected_vk)?
                != artifacts::digest(
                    &prover
                        .circuits_dir(variant, pair)
                        .join(name.dir_path())
                        .join(format!("{}.vk", name.as_str())),
                )?
        {
            bail!("Measured VK differs from the selected production artifact");
        }
        let start = Instant::now();
        let proof = prover
            .generate_proof_with_variant(name, &witness, "benchmark", variant, pair)
            .map_err(anyhow::Error::from);
        record.proof_generation.finish(start.elapsed(), &proof);
        let proof = proof?;
        record.proof_bytes(&proof.data, &proof.public_signals);
        let start = Instant::now();
        let result = prover
            .verify_proof_with_variant(&proof, "benchmark", 1, variant, pair)
            .map_err(anyhow::Error::from)
            .and_then(|valid| {
                if valid {
                    Ok(())
                } else {
                    bail!("Production verifier rejected the proof")
                }
            });
        record.verification.finish(start.elapsed(), &result);
        result?;
    } else {
        // These development circuits have no protocol CircuitName. Use the same verifier-target flags.
        record.proof_generation.metric = "external_bb_prove_wall".into();
        record.verification.metric = "external_bb_verify_wall".into();
        let witness_path = job.path().join("witness.gz");
        fs::write(&witness_path, witness)?;
        let out = job.path().join("out");
        let start = Instant::now();
        let result = run(Command::new(prover.bb_binary())
            .args(["prove", "-b"])
            .arg(&path)
            .arg("-w")
            .arg(witness_path)
            .arg("-k")
            .arg(&selected_vk)
            .arg("-o")
            .arg(&out)
            .args(["-t", variant.verifier_target()]));
        record.proof_generation.finish(start.elapsed(), &result);
        result?;
        let proof = fs::read(out.join("proof"))?;
        let public = fs::read(out.join("public_inputs"))?;
        record.proof_bytes(&proof, &public);
        let start = Instant::now();
        let result = run(Command::new(prover.bb_binary())
            .args(["verify", "--scheme", "ultra_honk", "-k"])
            .arg(&selected_vk)
            .arg("-p")
            .arg(out.join("proof"))
            .arg("-i")
            .arg(out.join("public_inputs"))
            .args(["-t", variant.verifier_target()]));
        record.verification.finish(start.elapsed(), &result);
        result?;
    }
    Ok(())
}
