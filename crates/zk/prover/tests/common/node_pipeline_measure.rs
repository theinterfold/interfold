// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Support for the per-node trBFV DKG pipeline measurement (`node_pipeline_trbfv_measure.rs`).
//!
//! Output lines:
//! - `MEASURE <label> start <unix_ms>` / `MEASURE <label> done <s>s`: one top-level prover call,
//!   witness generation included.
//! - `BB <circuit>#<k> start <unix_ms>` / `BB <circuit>#<k> done <s>s job=<job>`: one `bb prove`
//!   run, read from the prover's tracing events. These lines also cover the proofs that run inside
//!   production functions (C3 fold chains, node folds, the C6 fold chain), so they do not add to
//!   the `MEASURE` lines.
//! - `STEP <label>/<step> <s>s`: sub-step wall times that a production function reports.
//! - `PHASE <name> start <unix_ms>` / `PHASE <name> <s>s`, then `TOTAL <who> <s>s`.
//! - `NOTE <text>`: a deviation from the production pipeline.
//!
//! The measurements prove sequentially. Only the production function that runs work in parallel
//! does so here: `prove_node_dkg_fold` runs C2ab || C3a chain || C3b chain with `rayon::join`.
//! Set `RAYON_NUM_THREADS=1` to serialize it too. Production also runs independent proof requests
//! (for example the C3 proofs) concurrently on its task pool, up to its configured limit.
//!
//! Staging: the shared `setup_compiled_circuit*` helpers in `common/helpers.rs` always stage under
//! `insecure-64/<committee>`. [`stage`] stages the active `circuits/bin` artifacts under the
//! directory that `ZkProver::resolve_artifacts_dir` gives for the measured preset and committee.

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::common::active_bin_committee;
use crate::node_fold_witness;
use e3_committee::{CiphernodesCommittee, CiphernodesCommitteeSize};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_zk_config::DkgInputType;
use e3_zk_prover::{
    generate_sequential_c6_fold, prove_node_dkg_fold, DecryptedSharesAggregationCircuit,
    FoldProveStepTiming, NodeDkgFoldInput, Provable, ShareEncryptionCircuit,
    ThresholdShareDecryptionCircuit, ZkBackend, ZkProver,
};
use e3_zk_witness::dkg::share_computation::Inputs as ShareComputationInputs;
use e3_zk_witness::dkg::share_decryption::ShareDecryptionCircuitData;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use tokio::fs;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The measured node. Its C4 has every other honest party as a sender.
pub const PARTY_ID: usize = 0;

pub fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| value == "1")
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn note(text: &str) {
    println!("NOTE {text}");
}

/// Returns the committee to measure when `MEASURE_RUN=1` and the active circuit artifacts match
/// `preset` and `MEASURE_COMMITTEE` (default `small`). Prints why it skips otherwise.
pub fn gate(
    preset: BfvPreset,
    extra_env: Option<&str>,
) -> Option<(CiphernodesCommitteeSize, String)> {
    if !env_flag("MEASURE_RUN") {
        println!("skipping: set MEASURE_RUN=1 to run this measurement");
        return None;
    }
    if let Some(name) = extra_env {
        if !env_flag(name) {
            println!("skipping: set {name}=1 to run this measurement");
            return None;
        }
    }
    let committee_name = std::env::var("MEASURE_COMMITTEE")
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|_| "small".to_string());
    let committee = CiphernodesCommitteeSize::from_str(&committee_name)
        .unwrap_or_else(|e| panic!("MEASURE_COMMITTEE: {e}"));
    let expected_preset = preset
        .artifacts_dir_for_committee(committee.as_str())
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    if active_bin_preset().as_deref() != Some(expected_preset.as_str())
        || active_bin_committee().as_deref() != Some(committee.as_str())
    {
        println!(
            "SKIP active circuit artifacts are {:?}/{:?}; this measurement needs {expected_preset}/{} (pnpm build:circuits --preset {expected_preset} --committee {})",
            active_bin_preset(),
            active_bin_committee(),
            committee.as_str(),
            committee.as_str()
        );
        return None;
    }
    let values = committee.values();
    println!(
        "measure: preset={expected_preset} committee={} n={} h={} t={} party={PARTY_ID}",
        committee.as_str(),
        values.n,
        values.h,
        values.threshold
    );
    Some((committee, committee.as_str().to_owned()))
}

/// The production prover. `MEASURE_SLOW_LOW_MEMORY=1` selects the low-memory `bb` mode that
/// production uses when it retries a failed proof.
pub fn prover(backend: &ZkBackend) -> ZkProver {
    let prover = ZkProver::new(backend);
    if env_flag("MEASURE_SLOW_LOW_MEMORY") {
        note("bb runs with --slow_low_memory (production uses it only on retries)");
        prover.with_slow_low_memory()
    } else {
        prover
    }
}

/// Root of the compiled circuit artifacts: `{workspace}/circuits/bin/`.
fn circuits_build_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("circuits")
        .join("bin")
}

/// The `preset` field of `circuits/bin/.active-preset.json` (for example `"secure-8192"`).
pub fn active_bin_preset() -> Option<String> {
    let raw = std::fs::read_to_string(circuits_build_root().join(".active-preset.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("preset")?.as_str().map(str::to_owned)
}

/// Stages the active compiled circuits from `circuits/bin` into the temporary backend, under
/// `artifacts_dir` (`ZkProver::resolve_artifacts_dir(preset, committee)`, the directory the
/// production handlers prove from). The file layout is the one `common/helpers.rs` stages.
pub async fn stage(
    backend: &ZkBackend,
    artifacts_dir: &str,
    leaves: &[CircuitName],
    folds: &[CircuitName],
) {
    let (preset, committee) = artifacts_dir
        .split_once('/')
        .expect("artifacts dir is <preset>/<committee>");
    assert_eq!(
        active_bin_preset().as_deref(),
        Some(preset),
        "the active circuit artifacts are not built for {preset}"
    );
    assert_eq!(
        active_bin_committee().as_deref(),
        Some(committee),
        "the active circuit artifacts are not built for committee {committee}"
    );
    let preset_dir = backend.circuits_dir.join(artifacts_dir);
    for circuit in leaves {
        stage_leaf(&preset_dir, *circuit).await;
    }
    for circuit in folds {
        stage_fold(&preset_dir, *circuit).await;
    }
}

async fn copy(from: &Path, to: &Path) {
    fs::copy(from, to)
        .await
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", from.display(), to.display()));
}

async fn copy_if_exists(from: &Path, to: &Path) {
    if from.exists() {
        copy(from, to).await;
    }
}

/// Copies `json` and a VK (+ optional hash) into `<preset_dir>/<variant>/<group>/<name>/`.
async fn stage_variant(
    preset_dir: &Path,
    variant: &str,
    circuit: CircuitName,
    json: &Path,
    vk: &Path,
    vk_hash: &Path,
) -> PathBuf {
    let name = circuit.as_str();
    let dir = preset_dir.join(variant).join(circuit.dir_path());
    fs::create_dir_all(&dir).await.unwrap();
    copy(json, &dir.join(format!("{name}.json"))).await;
    copy(vk, &dir.join(format!("{name}.vk"))).await;
    copy_if_exists(vk_hash, &dir.join(format!("{name}.vk_hash"))).await;
    dir
}

/// A leaf circuit: `evm` gets the EVM VK, `default` the noir-recursive-no-zk VK, `recursive` the
/// noir-recursive VK (each falling back as `setup_compiled_circuit_for_committee` does).
async fn stage_leaf(preset_dir: &Path, circuit: CircuitName) {
    let name = circuit.as_str();
    let target = circuits_build_root().join(circuit.group()).join("target");
    let file = |ext: &str| target.join(format!("{name}.{ext}"));
    let json = file("json");
    let (vk, vk_hash) = (file("vk"), file("vk_hash"));
    let (vk_recursive, vk_recursive_hash) = (file("vk_recursive"), file("vk_recursive_hash"));
    let (vk_noir, vk_noir_hash) = (file("vk_noir"), file("vk_noir_hash"));
    assert!(
        json.exists() && vk.exists(),
        "compiled circuit {name} not found under {} (run `pnpm build:circuits`)",
        target.display()
    );

    stage_variant(preset_dir, "evm", circuit, &json, &vk, &vk_hash).await;
    let (default_vk, default_hash) = if vk_recursive.exists() {
        (&vk_recursive, &vk_recursive_hash)
    } else {
        (&vk, &vk_hash)
    };
    stage_variant(
        preset_dir,
        "default",
        circuit,
        &json,
        default_vk,
        default_hash,
    )
    .await;
    let (recursive_vk, recursive_hash) = if vk_noir.exists() {
        (&vk_noir, &vk_noir_hash)
    } else {
        (default_vk, default_hash)
    };
    stage_variant(
        preset_dir,
        "recursive",
        circuit,
        &json,
        recursive_vk,
        recursive_hash,
    )
    .await;
}

/// A `recursive_aggregation` fold circuit: `default` gets the noir-recursive-no-zk VK (and the
/// VK-tree anchor for `nodes_fold` / `c6_fold`), `evm` the EVM VK when the build emits one (as
/// `setup_recursive_aggregation_fold_circuit` does).
async fn stage_fold(preset_dir: &Path, circuit: CircuitName) {
    let name = circuit.as_str();
    let target = circuits_build_root()
        .join(circuit.group())
        .join(name)
        .join("target");
    let file = |ext: &str| target.join(format!("{name}.{ext}"));
    let json = file("json");
    let vk_recursive = file("vk_recursive");
    assert!(
        json.exists() && vk_recursive.exists(),
        "compiled fold circuit {name} not found under {} (run `pnpm build:circuits`)",
        target.display()
    );

    let default_dir = stage_variant(
        preset_dir,
        "default",
        circuit,
        &json,
        &vk_recursive,
        &file("vk_recursive_hash"),
    )
    .await;
    if matches!(circuit, CircuitName::NodesFold | CircuitName::C6Fold) {
        copy(
            &file("vk_tree_hash"),
            &default_dir.join(format!("{name}.vk_tree_hash")),
        )
        .await;
    }
    if file("vk").exists() {
        stage_variant(
            preset_dir,
            "evm",
            circuit,
            &json,
            &file("vk"),
            &file("vk_hash"),
        )
        .await;
    }
}

/// Times one top-level prover call. A failure ends the measurement, because later proofs need
/// this one.
pub fn measure<T, E: Display>(label: &str, f: impl FnOnce() -> Result<T, E>) -> T {
    println!("MEASURE {label} start {}", now_ms());
    let started = Instant::now();
    match f() {
        Ok(value) => {
            println!(
                "MEASURE {label} done {:.1}s",
                started.elapsed().as_secs_f64()
            );
            value
        }
        Err(e) => {
            println!("FAIL {label}: {e}");
            panic!("{label} failed: {e}");
        }
    }
}

/// Times native witness preparation that is not part of the proving total.
pub fn prep<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let value = f();
    println!("PREP {label} {:.1}s", started.elapsed().as_secs_f64());
    value
}

pub fn print_steps(label: &str, steps: &[FoldProveStepTiming]) {
    for step in steps {
        println!("STEP {label}/{} {:.1}s", step.step, step.seconds);
    }
}

/// Wall-clock totals per phase.
pub struct Phases {
    who: &'static str,
    rows: Vec<(String, f64)>,
}

impl Phases {
    pub fn new(who: &'static str) -> Self {
        Self {
            who,
            rows: Vec::new(),
        }
    }

    pub fn run<T>(&mut self, name: &str, f: impl FnOnce() -> T) -> T {
        println!("PHASE {name} start {}", now_ms());
        let started = Instant::now();
        let value = f();
        let seconds = started.elapsed().as_secs_f64();
        println!("PHASE {name} {seconds:.1}s");
        self.rows.push((name.to_owned(), seconds));
        value
    }

    pub fn finish(&self) {
        let total: f64 = self.rows.iter().map(|(_, s)| s).sum();
        println!("TOTAL {} {total:.1}s", self.who);
    }
}

// --- bb run timing from the prover's tracing events -------------------------------------------

const PROVER_TARGET: &str = "e3_zk_prover::prover";
const START_PREFIX: &str = "generating proof for circuit ";
const DONE_PREFIX: &str = "generated proof (";

#[derive(Default)]
struct BbTrace {
    open: Mutex<HashMap<ThreadId, (String, Instant)>>,
    counts: Mutex<HashMap<String, usize>>,
}

#[derive(Default)]
struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for BbTrace {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && metadata.target() == PROVER_TARGET
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = Message::default();
        event.record(&mut message);
        let thread = std::thread::current().id();
        if let Some(rest) = message.0.strip_prefix(START_PREFIX) {
            let circuit = rest.split_whitespace().next().unwrap_or("?").to_owned();
            let index = {
                let mut counts = self.counts.lock().unwrap();
                let count = counts.entry(circuit.clone()).or_insert(0);
                *count += 1;
                *count - 1
            };
            let label = format!("{circuit}#{index}");
            println!("BB {label} start {}", now_ms());
            self.open
                .lock()
                .unwrap()
                .insert(thread, (label, Instant::now()));
        } else if let Some(rest) = message.0.strip_prefix(DONE_PREFIX) {
            let job = rest.rsplit(" / ").next().unwrap_or("?");
            match self.open.lock().unwrap().remove(&thread) {
                Some((label, started)) => println!(
                    "BB {label} done {:.1}s job={job}",
                    started.elapsed().as_secs_f64()
                ),
                None => println!("BB ? done ? job={job} (no start event on this thread)"),
            }
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Prints a `BB` line pair for every `bb prove` run. `MEASURE_BB_TRACE=0` turns it off.
pub fn install_bb_trace() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if std::env::var("MEASURE_BB_TRACE").is_ok_and(|v| v == "0") {
        return;
    }
    INSTALLED.get_or_init(|| {
        if tracing::subscriber::set_global_default(BbTrace::default()).is_err() {
            note("a global tracing subscriber exists; BB lines are not printed");
        }
    });
}

// --- DKG node pieces -----------------------------------------------------------------------------

/// The C3 proofs one dealer makes for one secret: one per (recipient, modulus) slot except its
/// own recipient's, in ascending slot order (as `generate_shares.rs` orders the requests). Every
/// recipient uses `dkg_pk`; the circuit cost does not depend on the key.
#[allow(clippy::too_many_arguments)]
pub fn prove_c3_set(
    prover: &ZkProver,
    preset: BfvPreset,
    committee: &CiphernodesCommittee,
    share_inputs: &ShareComputationInputs,
    dkg_pk: &PublicKey,
    input_type: DkgInputType,
    tag: &str,
    artifacts_dir: &str,
) -> (Vec<Proof>, Vec<u32>) {
    let config =
        e3_zk_config::dkg::share_encryption::Configs::for_preset(preset).expect("C3 configuration");
    let slots_per_party = preset.metadata().num_moduli;
    let total_slots = committee.n * slots_per_party;
    let mut proofs = Vec::with_capacity(total_slots - slots_per_party);
    let mut slots = Vec::with_capacity(total_slots - slots_per_party);
    for slot in 0..total_slots {
        if slot / slots_per_party == PARTY_ID {
            continue;
        }
        let data = node_fold_witness::share_encryption_for_slot(
            preset,
            dkg_pk,
            share_inputs,
            slot,
            input_type,
        )
        .expect("C3 witness data");
        proofs.push(measure(&format!("{tag}[{slot}]"), || {
            ShareEncryptionCircuit.prove(
                prover,
                &config,
                &data,
                &format!("measure-{tag}-{slot}"),
                artifacts_dir,
            )
        }));
        slots.push(slot as u32);
    }
    (proofs, slots)
}

/// C4 input rows in honest-party order; `None` marks the recipient's own slot.
pub type HonestCiphertexts = Vec<Option<Vec<Ciphertext>>>;

/// The external ciphertexts `PARTY_ID` decrypts in C4: for each other honest sender, its `L`
/// share rows for `PARTY_ID`, encrypted under `dkg_pk`. The senders' shares come from native
/// samples; C4 only decrypts them and commits the plaintexts.
pub fn external_c4_ciphertexts(
    preset: BfvPreset,
    committee: &CiphernodesCommittee,
    dkg_pk: &PublicKey,
) -> (HonestCiphertexts, HonestCiphertexts) {
    let (threshold_params, _) = build_pair_for_preset(preset).expect("threshold parameters");
    let moduli = threshold_params.moduli().to_vec();
    let mut rng = rand::rng();
    let mut encrypt_rows = |secret_sss: &[ndarray::Array2<BigInt>]| -> Vec<Ciphertext> {
        moduli
            .iter()
            .enumerate()
            .map(|(mod_idx, modulus)| {
                let row: Vec<u64> = secret_sss[mod_idx]
                    .row(PARTY_ID)
                    .iter()
                    .map(|value| {
                        let mut value = value % BigInt::from(*modulus);
                        if value.is_negative() {
                            value += BigInt::from(*modulus);
                        }
                        value.to_u64().expect("share coefficient fits u64")
                    })
                    .collect();
                let plaintext = Plaintext::try_encode(&row, Encoding::poly(), &dkg_pk.params)
                    .expect("share plaintext");
                dkg_pk
                    .try_encrypt(&plaintext, &mut rng)
                    .expect("share ciphertext")
            })
            .collect()
    };

    let mut sk_rows = Vec::with_capacity(committee.h);
    let mut esm_rows = Vec::with_capacity(committee.h);
    for sender in 0..committee.h {
        if sender == PARTY_ID {
            sk_rows.push(None);
            esm_rows.push(None);
            continue;
        }
        let (key_data, esi, secret_key) =
            node_fold_witness::pk_generation_sample_with_esi(preset, committee.clone())
                .expect("sender key sample");
        let share_sk = node_fold_witness::share_computation_sk_from_pk(
            preset,
            committee.clone(),
            &key_data,
            &secret_key,
        )
        .expect("sender sk shares");
        let share_esm = node_fold_witness::share_computation_esm_from_esi(
            preset,
            committee.clone(),
            &key_data,
            &esi,
        )
        .expect("sender e_sm shares");
        sk_rows.push(Some(encrypt_rows(&share_sk.secret_sss)));
        esm_rows.push(Some(encrypt_rows(&share_esm.secret_sss)));
    }
    (sk_rows, esm_rows)
}

/// C4 witness for `PARTY_ID` as recipient: the own slot uses the own plaintext share (as
/// `handle_dkg_share_decryption_proof` does), every other honest sender a ciphertext row.
pub fn c4_data(
    preset: BfvPreset,
    dkg_sk: &SecretKey,
    own_inputs: &ShareComputationInputs,
    honest_ciphertexts: HonestCiphertexts,
) -> ShareDecryptionCircuitData {
    let (threshold_params, _) = build_pair_for_preset(preset).expect("threshold parameters");
    let own_plaintext_share = threshold_params
        .moduli()
        .iter()
        .enumerate()
        .map(|(mod_idx, modulus)| {
            own_inputs
                .y
                .iter()
                .map(|coefficient| {
                    let mut value =
                        coefficient[mod_idx][PARTY_ID + 1].clone() % BigInt::from(*modulus);
                    if value.is_negative() {
                        value += BigInt::from(*modulus);
                    }
                    value.to_u64().expect("share coefficient fits u64")
                })
                .collect()
        })
        .collect();
    ShareDecryptionCircuitData {
        secret_key: dkg_sk.clone(),
        honest_ciphertexts,
        own_plaintext_share,
    }
}

/// The production node fold: C2ab || C3a chain || C3b chain, then C3ab, C4ab, and the node fold.
pub fn prove_node_fold(prover: &ZkProver, input: &NodeDkgFoldInput, artifacts_dir: &str) -> Proof {
    note(
        "node_dkg_fold runs c2ab || c3a chain || c3b chain concurrently (rayon::join, as in production); \
         its per-proof times are the BB lines (c3_fold_kernel*, c3_fold*, c2ab*, c3ab*, c4ab_fold, node_fold*)",
    );
    let result = measure("node_dkg_fold", || {
        prove_node_dkg_fold(prover, input, "measure-node-fold", artifacts_dir)
    });
    print_steps("node_dkg_fold", &result.step_timings);
    result.proof
}

/// Threshold decryption pieces. The node proves C6 for one ciphertext. With
/// `MEASURE_AGGREGATOR=1` the aggregator side also runs: `T` more C6 proofs as fold inputs, the
/// C6 fold chain over `T + 1` slots, and C7.
pub fn run_decryption(
    prover: &ZkProver,
    preset: BfvPreset,
    committee: &CiphernodesCommittee,
    artifacts_dir: &str,
) {
    let mut phases = Phases::new("decryption");
    let c6_config = e3_zk_config::threshold::share_decryption::Configs::for_preset(preset)
        .expect("C6 configuration");
    let c6_sample = || {
        e3_zk_samples::threshold::share_decryption::generate(
            &c6_config.params,
            preset,
            committee.clone(),
        )
        .expect("C6 sample")
    };
    let c6_data = prep("c6 sample", c6_sample);
    let c6 = phases.run("c6", || {
        measure("c6", || {
            ThresholdShareDecryptionCircuit.prove(
                prover,
                &c6_config,
                &c6_data,
                "measure-c6",
                artifacts_dir,
            )
        })
    });
    drop(c6_data);
    phases.finish();

    if !env_flag("MEASURE_AGGREGATOR") {
        println!("skipping aggregator decryption: set MEASURE_AGGREGATOR=1");
        return;
    }
    let mut aggregator = Phases::new("aggregator_decryption");
    let slots = committee.threshold + 1;
    let mut inner = vec![c6];
    // The other T shares come from other nodes; they are fold inputs, not aggregator work.
    for index in 1..slots {
        let data = prep(&format!("c6_input[{index}] sample"), c6_sample);
        inner.push(measure(&format!("c6_input[{index}]"), || {
            ThresholdShareDecryptionCircuit.prove(
                prover,
                &c6_config,
                &data,
                &format!("measure-c6-input-{index}"),
                artifacts_dir,
            )
        }));
    }
    let slot_indices: Vec<u32> = (0..slots as u32).collect();
    aggregator.run("c6_fold", || {
        measure("c6_fold_chain", || {
            generate_sequential_c6_fold(
                prover,
                &inner,
                &slot_indices,
                slots,
                "measure-c6-fold",
                artifacts_dir,
            )
        })
    });
    let c7_config = e3_zk_config::threshold::decrypted_shares_aggregation::Configs::for_preset(
        preset,
        CiphernodesCommitteeSize::from_threshold(committee.threshold, committee.n)
            .expect("canonical committee"),
    )
    .expect("C7 configuration");
    let c7_data = prep("c7 sample", || {
        e3_zk_samples::threshold::decrypted_shares_aggregation::generate(&c7_config, preset)
            .expect("C7 sample")
    });
    aggregator.run("c7", || {
        measure("c7", || {
            DecryptedSharesAggregationCircuit.prove(
                prover,
                &c7_config,
                &c7_data,
                "measure-c7",
                artifacts_dir,
            )
        })
    });
    note(
        "decryption_aggregator is not proved: the C6 and C7 samples are independent, so its \
         C6-to-C7 d-commitment and common-ciphertext checks fail. Production \
         (prove_decryption_aggregation_jobs) re-folds C6 and then proves one EVM decryption_aggregator per ciphertext",
    );
    aggregator.finish();
}
