// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample generation and static dispatch for the supported circuits.

use anyhow::{anyhow, Context, Result};
use clap::Args as ClapArgs;
use e3_committee::{CiphernodesCommittee, CiphernodesCommitteeSize};
use e3_fhe_params::{BfvPreset, ParameterType};
use e3_zk_helpers::codegen::{write_artifacts, write_toml, Artifacts, CircuitCodegen};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::pk::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::{ShareComputationCircuit, ShareComputationCircuitData};
use e3_zk_helpers::dkg::share_decryption::{
    ShareDecryptionCircuit as DkgShareDecryptionCircuit,
    ShareDecryptionCircuitData as DkgShareDecryptionCircuitData,
};
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::decrypted_shares_aggregation::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::threshold::pk_aggregation::{PkAggregationCircuit, PkAggregationCircuitData};
use e3_zk_helpers::threshold::pk_generation::{PkGenerationCircuit, PkGenerationCircuitData};
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit as ThresholdShareDecryptionCircuit,
    ShareDecryptionCircuitData as ThresholdShareDecryptionCircuitData,
};
use e3_zk_helpers::threshold::user_data_encryption::{
    UserDataEncryptionCircuit, UserDataEncryptionCircuitData,
};
use e3_zk_helpers::{Circuit, CircuitsErrors};
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(super) struct Args {
    /// Circuit name. Use `list` to see the supported names.
    #[arg(long)]
    circuit: String,
    /// Preset: insecure, secure, or security level 2 or 80.
    #[arg(long)]
    preset: String,
    /// Witness family: secret-key or smudging-noise.
    #[arg(long)]
    inputs: Option<String>,
    /// Committee size: minimum, micro, or small.
    #[arg(long, default_value = "minimum")]
    committee: String,
    /// Directory for generated artifacts.
    #[arg(long, default_value = "output")]
    output: PathBuf,
    /// Also write Prover.toml.
    #[arg(long)]
    toml: bool,
    /// With --toml, write Prover.toml without configs.nr.
    #[arg(long)]
    no_configs: bool,
}

type Generate =
    fn(BfvPreset, CiphernodesCommittee, DkgInputType) -> Result<Artifacts, CircuitsErrors>;

struct Entry {
    name: &'static str,
    parameter: ParameterType,
    needs_inputs: bool,
    generate: Generate,
}

impl Entry {
    const fn new<C: Circuit>(needs_inputs: bool, generate: Generate) -> Self {
        Self {
            name: C::NAME,
            parameter: C::SUPPORTED_PARAMETER,
            needs_inputs,
            generate,
        }
    }
}

static CIRCUITS: &[Entry] = &[
    Entry::new::<PkCircuit>(false, |preset, _, _| {
        let sample = PkCircuitData::generate_sample(preset)?;
        PkCircuit.codegen(preset, &sample)
    }),
    Entry::new::<ShareComputationCircuit>(true, |preset, committee, input_type| {
        let sample = ShareComputationCircuitData::generate_sample(preset, committee, input_type)?;
        ShareComputationCircuit.codegen(preset, &sample)
    }),
    Entry::new::<UserDataEncryptionCircuit>(false, |preset, _, _| {
        let sample = UserDataEncryptionCircuitData::generate_sample(preset)?;
        UserDataEncryptionCircuit.codegen(preset, &sample)
    }),
    Entry::new::<PkGenerationCircuit>(false, |preset, committee, _| {
        let sample = PkGenerationCircuitData::generate_sample(preset, committee)?;
        PkGenerationCircuit.codegen(preset, &sample)
    }),
    Entry::new::<ShareEncryptionCircuit>(true, |preset, committee, input_type| {
        let sd = preset.search_defaults().unwrap();
        let sample =
            ShareEncryptionCircuitData::generate_sample(preset, committee, input_type, sd.z)?;
        ShareEncryptionCircuit.codegen(preset, &sample)
    }),
    Entry::new::<DkgShareDecryptionCircuit>(true, |preset, committee, input_type| {
        let sample = DkgShareDecryptionCircuitData::generate_sample(preset, committee, input_type)?;
        DkgShareDecryptionCircuit.codegen(preset, &sample)
    }),
    Entry::new::<PkAggregationCircuit>(false, |preset, committee, _| {
        let sample = PkAggregationCircuitData::generate_sample(preset, committee)?;
        PkAggregationCircuit.codegen(preset, &sample)
    }),
    Entry::new::<ThresholdShareDecryptionCircuit>(false, |preset, committee, _| {
        let sample = ThresholdShareDecryptionCircuitData::generate_sample(preset, committee)?;
        ThresholdShareDecryptionCircuit.codegen(preset, &sample)
    }),
    Entry::new::<DecryptedSharesAggregationCircuit>(false, |preset, committee, _| {
        let sample = DecryptedSharesAggregationCircuitData::generate_sample(preset, committee)?;
        DecryptedSharesAggregationCircuit.codegen(preset, &sample)
    }),
];

pub(super) fn list() {
    let mut entries: Vec<_> = CIRCUITS.iter().collect();
    entries.sort_unstable_by_key(|entry| entry.name);
    println!("Available circuits:");
    for entry in entries {
        println!("  {} - params_type: {:?}", entry.name, entry.parameter);
    }
}

fn parse_input_type(s: &str) -> Result<DkgInputType> {
    match s.trim().to_lowercase().as_str() {
        "secret-key" => Ok(DkgInputType::SecretKey),
        "smudging-noise" => Ok(DkgInputType::SmudgingNoise),
        _ => Err(anyhow!(
            "unknown input-type: {s}. Use \"secret-key\" or \"smudging-noise\""
        )),
    }
}

pub(super) fn run(args: Args) -> Result<()> {
    let preset = BfvPreset::from_security_config_name(&args.preset)?;
    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("failed to create output dir {}", args.output.display()))?;
    let entry = CIRCUITS
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(&args.circuit))
        .ok_or_else(|| {
            let mut available: Vec<_> = CIRCUITS.iter().map(|entry| entry.name).collect();
            available.sort_unstable();
            anyhow!(
                "unknown circuit: {}. Available: {}",
                args.circuit,
                available.join(", ")
            )
        })?;

    let preset_ok = match entry.parameter {
        ParameterType::THRESHOLD => preset.metadata().parameter_type == ParameterType::THRESHOLD,
        ParameterType::DKG => preset
            .dkg_counterpart()
            .is_some_and(|dkg| dkg.metadata().parameter_type == ParameterType::DKG),
    };
    if !preset_ok {
        return Err(anyhow!(
            "preset does not match circuit {} which requires {:?} (use insecure or secure)",
            args.circuit,
            entry.parameter
        ));
    }

    let input_type = if entry.needs_inputs {
        let inputs = if args.toml {
            args.inputs.as_deref().ok_or_else(|| {
                anyhow!(
                    "circuit {} requires --inputs (secret-key or smudging-noise) when writing Prover.toml",
                    args.circuit
                )
            })?
        } else {
            args.inputs.as_deref().unwrap_or("secret-key")
        };
        parse_input_type(inputs)?
    } else {
        DkgInputType::SecretKey
    };
    let committee_size: CiphernodesCommitteeSize = args.committee.trim().parse()?;
    let committee = committee_size.values();
    let meta = preset.metadata();
    println!("  Circuit:    {}", args.circuit);
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
    println!("  Output:   {}", args.output.display());

    // Configs and witnesses use the same sampled data, even when only one file is written.
    let artifacts = (entry.generate)(preset, committee, input_type)?;
    if args.no_configs && args.toml {
        write_toml(&artifacts.toml, Some(&args.output))?;
    } else {
        let toml = args.toml.then_some(&artifacts.toml);
        write_artifacts(toml, &artifacts.configs, Some(&args.output))?;
    }
    println!("  ✓ Artifacts written to {}", args.output.display());
    Ok(())
}
