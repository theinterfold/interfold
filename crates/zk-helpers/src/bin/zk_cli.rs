// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! ZK CLI — command-line tool for zero-knowledge circuit artifact generation.
//!
//! This binary lists available circuits and generates Prover.toml and configs.nr
//! for use with the Noir prover. Use `--list_circuits` to see circuits and
//! `--circuit <name> --preset insecure|secure|2|80 [--committee minimum|micro|small]` to generate artifacts.
//!
//! **Share-computation (C2) configs.nr:** set `INTERFOLD_CIRCUITS_ROOT` to the repo `circuits`
//! directory (or run from the Interfold repo so it is auto-discovered). After `pnpm build:circuits`,
//! `circuits/bin/dkg/target/` contains `sk_share_computation.vk_recursive_hash` and
//! `e_sm_share_computation.vk_recursive_hash` for the inner recursive circuits; the aggregation
//! wrapper emits `share_computation.vk_recursive_hash` under
//! `circuits/bin/recursive_aggregation/wrapper/dkg/share_computation/target/` (from
//! `scripts/build-circuits.ts`). If `INTERFOLD_CIRCUITS_ROOT` is set and those files are missing,
//! codegen fails; if unset and artifacts are absent, the C2 literals are omitted from the generated
//! fragment.

use anyhow::{anyhow, Context, Result};
use clap::{arg, command, Parser};
use e3_fhe_params::{BfvPreset, ParameterType};
use e3_zk_helpers::ciphernodes_committee::CiphernodesCommitteeSize;
use e3_zk_helpers::circuits::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::circuits::dkg::share_computation::circuit::{
    ShareComputationCircuit, ShareComputationCircuitData,
};
use e3_zk_helpers::codegen::{write_artifacts, write_toml, CircuitCodegen};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_decryption::{
    ShareDecryptionCircuit as DkgShareDecryptionCircuit,
    ShareDecryptionCircuitData as DkgShareDecryptionCircuitData,
};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::registry::{Circuit, CircuitRegistry};
use e3_zk_helpers::threshold::decrypted_shares_aggregation::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuit;
use e3_zk_helpers::threshold::pk_aggregation::PkAggregationCircuitData;
use e3_zk_helpers::threshold::pk_generation::{PkGenerationCircuit, PkGenerationCircuitData};
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit as ThresholdShareDecryptionCircuit,
    ShareDecryptionCircuitData as ThresholdShareDecryptionCircuitData,
};
use e3_zk_helpers::threshold::user_data_encryption::{
    UserDataEncryptionCircuit, UserDataEncryptionCircuitData,
};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// DKG input type for circuits that derive witnesses from secret-key or smudging-noise samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DkgInputTypeArg {
    SecretKey,
    SmudgingNoise,
}

fn parse_committee(s: &str) -> Result<CiphernodesCommitteeSize> {
    use std::str::FromStr;
    CiphernodesCommitteeSize::from_str(s.trim())
}

fn parse_input_type(s: &str) -> Result<DkgInputTypeArg> {
    match s.trim().to_lowercase().as_str() {
        "secret-key" => Ok(DkgInputTypeArg::SecretKey),
        "smudging-noise" => Ok(DkgInputTypeArg::SmudgingNoise),
        _ => Err(anyhow!(
            "unknown input-type: {s}. Use \"secret-key\" or \"smudging-noise\""
        )),
    }
}

/// Clear the terminal screen (ANSI escape codes; works on Unix, macOS, and most Windows terminals).
fn clear_terminal() {
    print!("\x1b[2J\x1b[1H");
    let _ = std::io::stdout().flush();
}

/// Print a summary of what will be generated (circuit, preset, inputs, output, artifacts).
#[allow(clippy::too_many_arguments)]
fn print_generation_info(
    circuit: &str,
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    has_inputs: bool,
    dkg_input_type: DkgInputType,
    output: &std::path::Path,
    write_prover_toml: bool,
    no_configs: bool,
) {
    let meta = preset.metadata();
    let committee = committee_size.values();
    println!("  Circuit:    {}", circuit);
    println!(
        "  Preset:     {} (degree {}, {} moduli)",
        meta.security.as_config_str(),
        meta.degree,
        meta.num_moduli
    );
    println!(
        "  Committee:  {:?} (n={}, t={}, h={})",
        committee_size, committee.n, committee.threshold, committee.h
    );
    if has_inputs {
        println!(
            "  Inputs:  {}",
            match dkg_input_type {
                DkgInputType::SecretKey => "secret-key",
                DkgInputType::SmudgingNoise => "smudging-noise",
            }
        );
    }
    println!("  Output:   {}", output.display());
    println!("  Artifacts:");
    if no_configs {
        println!("    • Prover.toml only (--toml --no-configs)");
    } else if write_prover_toml {
        println!("    • configs.nr");
        println!("    • Prover.toml");
    } else {
        println!("    • configs.nr only (pass --toml to also generate Prover.toml)");
    }
    println!();
}

/// Run a closure while showing a spinner. Returns the closure's result.
fn run_with_spinner<F, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = Arc::clone(&done);
    let spinner = thread::spawn(move || {
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut i = 0usize;
        while !done_clone.load(Ordering::Relaxed) {
            print!("\r  {} Generating artifacts... ", frames[i % frames.len()]);
            i = i.wrapping_add(1);
            std::io::stdout().flush().ok();
            thread::sleep(Duration::from_millis(80));
        }
    });

    let result = f();
    done.store(true, Ordering::Relaxed);
    spinner.join().ok();
    result
}

/// Print the final success message.
fn print_success(output: &std::path::Path) {
    println!("\r  ✓ Artifacts written to {}", output.display());
}

/// Minimal ZK CLI for generating circuit artifacts.
#[derive(Debug, Parser)]
#[command(name = "zk-cli")]
struct Cli {
    /// List all available circuits and exit.
    #[arg(long)]
    list_circuits: bool,
    /// Circuit name to generate artifacts for (e.g. `pk`, `share-computation`).
    #[arg(long, required_unless_present = "list_circuits")]
    circuit: Option<String>,
    /// Preset: "insecure"|"secure" or λ (2|80). Drives both threshold and DKG params.
    #[arg(long, required_unless_present = "list_circuits")]
    preset: Option<String>,
    /// Select the witness family when sample generation depends on it.
    #[arg(long)]
    inputs: Option<String>,
    /// Committee size: minimum, micro, or small (must match circuits lib default).
    #[arg(long, default_value = "minimum")]
    committee: String,
    /// Output directory for generated artifacts.
    #[arg(long, default_value = "output")]
    output: PathBuf,
    /// Also write Prover.toml (default: configs.nr only).
    #[arg(long, default_value = "false")]
    toml: bool,
    /// When used with --toml: do not write configs.nr (e.g. for benchmarks where circuits use lib configs).
    #[arg(long, default_value = "false")]
    no_configs: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Register all circuits in the registry (metadata only).
    let mut registry = CircuitRegistry::new();
    registry.register(Arc::new(PkCircuit));
    registry.register(Arc::new(ShareComputationCircuit));
    registry.register(Arc::new(UserDataEncryptionCircuit));
    registry.register(Arc::new(PkGenerationCircuit));
    registry.register(Arc::new(ShareEncryptionCircuit));
    registry.register(Arc::new(DkgShareDecryptionCircuit));
    registry.register(Arc::new(PkAggregationCircuit));
    registry.register(Arc::new(ThresholdShareDecryptionCircuit));
    registry.register(Arc::new(DecryptedSharesAggregationCircuit));

    // Handle list circuits flag.
    if args.list_circuits {
        let circuits = registry.list_circuits();
        println!("Available circuits:");
        for circuit_name in circuits {
            if let Ok(circuit_meta) = registry.get(&circuit_name) {
                println!(
                    "  {} - params_type: {:?}",
                    circuit_name,
                    circuit_meta.supported_parameter(),
                );
            }
        }
        return Ok(());
    }

    // Unwrap required arguments (clap ensures they're present when list_circuits is false).
    let circuit = args.circuit.unwrap();
    let preset = BfvPreset::from_security_config_name(&args.preset.unwrap())?;

    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("failed to create output dir {}", args.output.display()))?;

    // Validate circuit exists in registry.
    let circuit_meta = registry.get(&circuit).map_err(|_| {
        let available = registry.list_circuits().join(", ");
        anyhow!("unknown circuit: {}. Available: {}", circuit, available)
    })?;

    // Validate preset matches circuit's supported parameter type (THRESHOLD or DKG).
    let circuit_param_type = circuit_meta.supported_parameter();
    let preset_ok = match circuit_param_type {
        ParameterType::THRESHOLD => preset.metadata().parameter_type == ParameterType::THRESHOLD,
        ParameterType::DKG => preset
            .dkg_counterpart()
            .is_some_and(|dkg| dkg.metadata().parameter_type == ParameterType::DKG),
    };
    if !preset_ok {
        return Err(anyhow!(
            "preset does not match circuit {} which requires {:?} (use insecure or secure)",
            circuit,
            circuit_param_type
        ));
    }

    let write_prover_toml = args.toml;
    let no_configs = args.no_configs && args.toml;
    let circuit_name = circuit_meta.name();

    // Some circuits reuse one helper entrypoint for multiple witness families, so `--inputs`
    // selects whether we derive secret-key or smudging-noise sample data.
    let requires_inputs_arg = circuit_name == ShareComputationCircuit::NAME
        || circuit_meta.name() == ShareEncryptionCircuit::NAME
        || circuit_meta.name() == DkgShareDecryptionCircuit::NAME;

    let show_input_type = requires_inputs_arg || circuit_name == ShareComputationCircuit::NAME;

    let dkg_input_type = if circuit_name == ShareComputationCircuit::NAME || requires_inputs_arg {
        let inputs_str = if !args.toml {
            args.inputs.as_deref().unwrap_or("secret-key")
        } else {
            args.inputs.as_deref().ok_or_else(|| {
                anyhow!(
                    "circuit {} requires --inputs (secret-key or smudging-noise) when writing Prover.toml",
                    circuit
                )
            })?
        };
        let arg = parse_input_type(inputs_str)?;
        match arg {
            DkgInputTypeArg::SecretKey => DkgInputType::SecretKey,
            DkgInputTypeArg::SmudgingNoise => DkgInputType::SmudgingNoise,
        }
    } else {
        DkgInputType::SecretKey
    };

    let committee_size = parse_committee(&args.committee)?;

    clear_terminal();
    print_generation_info(
        &circuit,
        preset,
        committee_size,
        show_input_type,
        dkg_input_type,
        &args.output,
        write_prover_toml,
        no_configs,
    );

    run_with_spinner(|| {
        let committee = committee_size.values();
        let artifacts = match circuit_name {
            name if name == <PkCircuit as Circuit>::NAME => {
                let sample = PkCircuitData::generate_sample(preset)?;

                let circuit = PkCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <ShareComputationCircuit as Circuit>::NAME => {
                let sample = ShareComputationCircuitData::generate_sample(
                    preset,
                    committee,
                    dkg_input_type,
                )?;

                let circuit = ShareComputationCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <ShareEncryptionCircuit as Circuit>::NAME => {
                let sd = preset.search_defaults().unwrap();
                let sample = ShareEncryptionCircuitData::generate_sample(
                    preset,
                    committee,
                    dkg_input_type,
                    sd.z,
                )?;

                let circuit = ShareEncryptionCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <UserDataEncryptionCircuit as Circuit>::NAME => {
                let sample = UserDataEncryptionCircuitData::generate_sample(preset)?;

                let circuit = UserDataEncryptionCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <PkGenerationCircuit as Circuit>::NAME => {
                let sample = PkGenerationCircuitData::generate_sample(preset, committee)?;

                let circuit = PkGenerationCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <DkgShareDecryptionCircuit as Circuit>::NAME => {
                let sample = DkgShareDecryptionCircuitData::generate_sample(
                    preset,
                    committee,
                    dkg_input_type,
                )?;

                let circuit = DkgShareDecryptionCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <PkAggregationCircuit as Circuit>::NAME => {
                let sample = PkAggregationCircuitData::generate_sample(preset, committee)?;

                let circuit = PkAggregationCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <ThresholdShareDecryptionCircuit as Circuit>::NAME => {
                let sample =
                    ThresholdShareDecryptionCircuitData::generate_sample(preset, committee)?;

                let circuit = ThresholdShareDecryptionCircuit;
                circuit.codegen(preset, &sample)?
            }
            name if name == <DecryptedSharesAggregationCircuit as Circuit>::NAME => {
                let sample =
                    DecryptedSharesAggregationCircuitData::generate_sample(preset, committee)?;

                let circuit = DecryptedSharesAggregationCircuit;
                circuit.codegen(preset, &sample)?
            }
            name => return Err(anyhow!("circuit {} not yet implemented", name)),
        };

        if no_configs {
            write_toml(&artifacts.toml, Some(args.output.as_path()))?;
        } else {
            let toml = if write_prover_toml {
                Some(&artifacts.toml)
            } else {
                None
            };
            write_artifacts(toml, &artifacts.configs, Some(args.output.as_path()))?;
        }
        Ok(())
    })?;

    print_success(&args.output);
    Ok(())
}
