// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The benchmark entry: one full-proof run of the scenario runner, reported as the JSON files the
//! circuit benchmark tool (`crates/zk/benchmarks`) reads. Nothing here decides whether the run was
//! correct; [`run`] already asserted that before returning.
//!
//! Environment (set by that tool): `BENCHMARK_MODE` (`insecure`, the default, or `secure`),
//! `BENCHMARK_MULTITHREAD_JOBS` (Rayon jobs at once, default 1), `BENCHMARK_SUMMARY_OUTPUT` and
//! `BENCHMARK_FOLDED_OUTPUT` (files to write, each optional).

use super::nodes::DKG_FOLD_ATTESTATION_VERIFIER;
use super::runner::{run, Run, Scenario};
use alloy::primitives::hex;
use anyhow::Result;
use e3_events::{hlc::HlcTimestamp, prelude::*, EventSource, InterfoldEvent, InterfoldEventData};
use std::fs;
use std::time::Duration;

pub async fn run_from_env() -> Result<()> {
    let mode = std::env::var("BENCHMARK_MODE").unwrap_or_else(|_| "insecure".to_string());
    let jobs = std::env::var("BENCHMARK_MULTITHREAD_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(1);
    let run = run(&Scenario::benchmark(
        super::runner::Preset::from_mode(&mode),
        jobs,
    ))
    .await?;

    let report = Report::new(&run);
    println!("{}", report.serialize());
    if let Ok(path) = std::env::var("BENCHMARK_FOLDED_OUTPUT") {
        fs::write(&path, folded_artifacts_json(&run, ""))?;
        println!("Wrote folded benchmark proofs to {path}");
    }
    if let Ok(path) = std::env::var("BENCHMARK_SUMMARY_OUTPUT") {
        fs::write(&path, summary_json(&run, &mode, &report))?;
        println!("Wrote benchmark summary to {path}");
    }
    Ok(())
}

/// Labelled wall-clock phases, in the order the report lists them.
struct Report(Vec<(&'static str, Duration)>);

impl Report {
    fn new(run: &Run) -> Self {
        let t = &run.timings;
        let mut phases = vec![
            ("Starting trbfv actor test", Duration::ZERO),
            ("Setup completed", t.setup),
            ("Committee Setup Completed", t.committee_setup),
            ("Committee Finalization Complete", t.committee_finalization),
        ];

        // Peers forward the published key, so time the phase to the local publication only.
        let p2_events = run.pubkey_role_events.iter().filter(|event| {
            !matches!(event.get_data(), InterfoldEventData::PublicKeyAggregated(_))
                || event.source() == EventSource::Local
        });
        if let Some(secs) = wall_seconds_between(
            p2_events,
            |d| matches!(d, InterfoldEventData::PkAggregationProofPending(data) if data.e3_id == run.e3_id),
            |d| matches!(d, InterfoldEventData::PublicKeyAggregated(data) if data.e3_id == run.e3_id),
        ) {
            phases.push((
                "Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall)",
                Duration::from_secs_f64(secs),
            ));
        }
        phases.extend([
            ("ThresholdShares -> PublicKeyAggregated", t.shares_to_pubkey),
            ("E3Request -> PublicKeyAggregated", t.request_to_pubkey),
            ("Application CT Gen", t.ciphertext_generation),
            ("Running FHE Application", t.fhe_application),
        ]);

        // The plaintext flow starts at this party's first view of the ciphertext.
        let plaintext_start = run
            .plaintext_aggregator_events
            .iter()
            .position(|event| {
                matches!(
                    event.get_data(),
                    InterfoldEventData::CiphertextOutputPublished(data) if data.e3_id == run.e3_id
                )
            })
            .unwrap_or(0);
        let p4_events = run.plaintext_aggregator_events[plaintext_start..].iter();
        if let Some(secs) = wall_seconds_between(
            p4_events,
            |d| matches!(d, InterfoldEventData::AggregationProofPending(data) if data.e3_id == run.e3_id),
            |d| matches!(d, InterfoldEventData::PlaintextAggregated(data) if data.e3_id == run.e3_id),
        ) {
            phases.push((
                "Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)",
                Duration::from_secs_f64(secs),
            ));
        }
        phases.extend([
            (
                "Ciphertext published -> PlaintextAggregated",
                t.ciphertext_to_plaintext,
            ),
            ("Entire Test", t.whole),
        ]);

        Self(phases)
    }

    fn serialize(&self) -> String {
        let width = self.0.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        self.0
            .iter()
            .map(|(label, duration)| format!("{label:width$}: {:.3}s", duration.as_secs_f64()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Wall seconds between the earliest `start_when` and the latest `end_when` event (HLC physical
/// time). Selecting by timestamp keeps the result independent of event order when the events join
/// several nodes' histories.
fn wall_seconds_between<'a>(
    events: impl Iterator<Item = &'a InterfoldEvent> + Clone,
    start_when: impl Fn(&InterfoldEventData) -> bool,
    end_when: impl Fn(&InterfoldEventData) -> bool,
) -> Option<f64> {
    let wall_time = |event: &InterfoldEvent| HlcTimestamp::wall_time(event.ts());
    let start_us = events
        .clone()
        .filter(|e| start_when(e.get_data()))
        .map(wall_time)
        .min()?;
    let end_us = events
        .filter(|e| end_when(e.get_data()))
        .map(wall_time)
        .max()?;
    (end_us >= start_us).then(|| (end_us - start_us) as f64 / 1_000_000.0)
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The two aggregator proofs the contract benchmarks verify, as a JSON object body.
/// `indent` is prepended to every line, so the same text nests under a key.
fn folded_artifacts_json(run: &Run, indent: &str) -> String {
    let dkg = &run.dkg_aggregator_proof;
    let dec = &run.decryption_aggregator_proofs[0];
    format!(
        concat!(
            "{indent}{{\n",
            "{indent}  \"dkg_aggregator\": {{\n",
            "{indent}    \"proof_hex\": \"{}\",\n",
            "{indent}    \"public_inputs_hex\": \"{}\"\n",
            "{indent}  }},\n",
            "{indent}  \"decryption_aggregator\": {{\n",
            "{indent}    \"proof_hex\": \"{}\",\n",
            "{indent}    \"public_inputs_hex\": \"{}\"\n",
            "{indent}  }}\n",
            "{indent}}}\n"
        ),
        hex::encode_prefixed(&*dkg.data),
        hex::encode_prefixed(&*dkg.public_signals),
        hex::encode_prefixed(&*dec.data),
        hex::encode_prefixed(&*dec.public_signals),
        indent = indent,
    )
}

fn summary_json(run: &Run, mode: &str, report: &Report) -> String {
    let mt = &run.multithread;
    let config = &run.config;
    let operation_timings_json = mt
        .operation_timings_sec()
        .iter()
        .map(|op| {
            format!(
                "    {{\"name\": \"{}\", \"avg_seconds\": {:.9}, \"runs\": {}, \"total_seconds\": {:.9}}}",
                json_escape(&op.name),
                op.avg_seconds,
                op.runs,
                op.total_seconds
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let phase_timings_json = report
        .0
        .iter()
        .map(|(label, duration)| {
            format!(
                "    {{\"label\": \"{}\", \"seconds\": {:.9}, \"metric\": \"wall_clock\"}}",
                json_escape(label),
                duration.as_secs_f64(),
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let folded_section = format!(
        "  \"folded_artifacts\": {}\n",
        folded_artifacts_json(run, "  ").trim_start().trim_end()
    );

    let dkg_fold_verifier_json = if config.proof_aggregation_enabled {
        format!("  \"dkg_fold_attestation_verifier\": \"{DKG_FOLD_ATTESTATION_VERIFIER}\",\n")
    } else {
        String::new()
    };

    let benchmark_config_json = format!(
        concat!(
            "  \"benchmark_config\": {{\n",
            "    \"mode\": \"{}\",\n",
            "    \"bfv_preset_subdir\": \"{}\",\n",
            "    \"bfv_preset\": \"{:?}\",\n",
            "    \"lambda\": {},\n",
            "    \"proof_aggregation_enabled\": {},\n",
            "    \"multithread_concurrent_jobs\": {},\n",
            "    \"committee_h\": {},\n",
            "    \"committee_n\": {},\n",
            "    \"committee_t\": {},\n",
            "    \"nodes_spawned\": {},\n",
            "    \"network_model\": \"in_process_bus\",\n",
            "    \"testmode_harness\": true\n",
            "  }},\n"
        ),
        json_escape(mode),
        json_escape(config.preset.subdir()),
        config.preset.bfv_preset(),
        config.lambda,
        config.proof_aggregation_enabled,
        config.concurrent_jobs,
        config.committee_h,
        config.committee_n,
        config.committee_t,
        config.nodes_spawned,
    );

    format!(
        concat!(
            "{{\n",
            "  \"integration_test\": \"benchmark_trbfv_actor\",\n",
            "{benchmark_config_json}",
            "  \"proof_aggregation_enabled\": {},\n",
            "{dkg_fold_verifier_json}",
            "  \"multithread\": {{\n",
            "    \"rayon_threads\": {},\n",
            "    \"max_simultaneous_rayon_tasks\": {},\n",
            "    \"cores_available\": {}\n",
            "  }},\n",
            "  \"operation_timings\": [\n",
            "{}\n",
            "  ],\n",
            "  \"operation_timings_total_seconds\": {:.9},\n",
            "  \"operation_timings_metric\": \"tracked_job_wall\",\n",
            "  \"phase_timings\": [\n",
            "{}\n",
            "  ],\n",
            "{}",
            "}}\n"
        ),
        config.proof_aggregation_enabled,
        mt.rayon_threads(),
        mt.max_simultaneous_rayon_tasks(),
        mt.cores_available(),
        operation_timings_json,
        mt.tracked_total_seconds(),
        phase_timings_json,
        folded_section,
        benchmark_config_json = benchmark_config_json,
        dkg_fold_verifier_json = dkg_fold_verifier_json,
    )
}
