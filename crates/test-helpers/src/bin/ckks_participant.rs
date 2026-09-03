// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS PARTICIPANT CLI — the client-side verifiable-encryption tool a
//! survey participant (or auction bidder) runs on their OWN machine.
//!
//! Encrypts one value under the committee's joint CKKS public key with
//! witnessed randomness, proves BOTH Greco legs
//! (`user_data_encryption_ckks_ct0` / `_ct1`) with nargo + bb, and emits
//! a self-contained `submission.json` the on-chain
//! `CkksE3Program.publishInput` gate verifies. The value never leaves
//! this process in clear.
//!
//! Usage:
//!   ckks_participant --param-set 3 --pubkey pubkey.bin \
//!       --value 52000 --cap 100000 --replicate-slots \
//!       --out-dir /tmp/participant0
//!
//! ONE `Inputs::compute` call feeds both the persisted ciphertext bytes
//! and the Prover.toml — encryption randomness is fresh per compute, so
//! a second compute would attest to a DIFFERENT ciphertext.
//!
//! CONCURRENCY: multiple participants may run at once. Each invocation
//! writes a uniquely-named `Prover_<nonce>.toml` and witness
//! `<pkg>_<nonce>.gz` (nargo `-p` / `[WITNESS_NAME]`), so nothing shared
//! is clobbered; an exclusive file lock (`std::fs::File::lock`) on
//! `<package dir>/.participant.lock` additionally serializes the nargo
//! compile+execute step per package (the compiled `target/<pkg>.json` is
//! a shared artifact). bb proving — the long pole — runs fully parallel
//! into a per-invocation output directory.

use clap::Parser;
use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::threshold::user_data_encryption_ckks::{
    ckks_preset_for_param_set, generate_toml, Inputs, UserDataEncryptionCkksCircuitData,
};
use fhe::ckks::CkksPublicKey;
use fhe_traits::DeserializeParametrized;
use serde_json::json;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// On-chain ParamSet (0 = dev insecure-512, 2 = auction ladder,
    /// 3 = statistics). Selects params, input bound, circuit packages
    /// and VKs.
    #[arg(long)]
    param_set: u8,

    /// Path to the committee's aggregated CKKS public key.
    #[arg(long)]
    pubkey: String,

    /// The participant's private value (e.g. a salary or a bid).
    #[arg(long)]
    value: f64,

    /// Public normalization cap: the circuit input is `value / cap`,
    /// which must stay within the param set's input bound.
    #[arg(long)]
    cap: f64,

    /// Replicate the value across all N/2 slots (required by the
    /// slot-batched auction bracket AND the packed statistics policy,
    /// whose one-hot masks read specific slots).
    #[arg(long, default_value_t = false)]
    replicate_slots: bool,

    /// Output directory for `ciphertext.bin` + `submission.json`.
    #[arg(long)]
    out_dir: String,

    /// The `circuits/bin/threshold` directory of an interfold checkout
    /// (compiled circuit artifacts + VKs must exist there).
    #[arg(long, default_value = "circuits/bin/threshold")]
    circuits_dir: String,
}

/// Package name + VK directory for one proof leg of a param set.
fn leg_names(param_set: u8, leg: usize) -> (String, String) {
    let suffix = match param_set {
        0 => String::new(),
        n => format!("_ps{n}"),
    };
    (
        format!("user_data_encryption_ckks_ct{leg}{suffix}"),
        format!("vk-ct{leg}{}", suffix),
    )
}

fn tool(env_key: &str, default_home_rel: &str) -> PathBuf {
    if let Ok(v) = std::env::var(env_key) {
        return PathBuf::from(v);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    Path::new(&home).join(default_home_rel)
}

fn run(
    cmd: &Path,
    args: &[&str],
    cwd: &Path,
    what: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let out = Command::new(cmd).args(args).current_dir(cwd).output()?;
    if !out.status.success() {
        return Err(format!(
            "{what} failed ({}):\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

/// Split a bb `public_inputs` file into 0x-prefixed 32-byte hex words.
fn read_words(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let buf = fs::read(path)?;
    if buf.len() % 32 != 0 {
        return Err(format!(
            "{}: length {} not a multiple of 32",
            path.display(),
            buf.len()
        )
        .into());
    }
    Ok(buf
        .chunks(32)
        .map(|w| format!("0x{}", hex::encode(w)))
        .collect())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let total = Instant::now();

    if !(args.cap.is_finite() && args.cap > 0.0) {
        return Err("--cap must be a positive finite number".into());
    }
    if !args.value.is_finite() {
        return Err("--value must be finite".into());
    }

    let preset = ckks_preset_for_param_set(args.param_set)?;
    let normalized = args.value / args.cap;
    if normalized.abs() > preset.input_bound {
        return Err(format!(
            "normalized value {normalized} exceeds the param-set input bound {} \
             (value {} over cap {})",
            preset.input_bound, args.value, args.cap
        )
        .into());
    }

    let pk_bytes = fs::read(&args.pubkey)?;
    let pk = CkksPublicKey::from_bytes(&pk_bytes, &preset.params)?;

    let slots = preset.params.degree() / 2;
    let values = if args.replicate_slots {
        vec![normalized; slots]
    } else {
        vec![normalized]
    };

    let out_dir = PathBuf::from(&args.out_dir);
    fs::create_dir_all(&out_dir)?;
    let circuits_dir = PathBuf::from(&args.circuits_dir);
    if !circuits_dir.join("target").exists() {
        return Err(format!(
            "{}/target not found — run from the interfold root or pass --circuits-dir",
            circuits_dir.display()
        )
        .into());
    }

    // ONE compute: the SAME struct feeds the persisted ciphertext and the
    // Prover.toml (fresh randomness per compute — see module docs).
    let t = Instant::now();
    let data = UserDataEncryptionCkksCircuitData {
        public_key: pk,
        values,
    };
    let inputs = Inputs::compute(preset, &data)?;
    let ciphertext = inputs.ciphertext.clone();
    let toml = generate_toml(inputs)?;
    eprintln!("witness computed in {:.2?}", t.elapsed());

    fs::write(out_dir.join("ciphertext.bin"), &ciphertext)?;

    // Per-invocation unique names for everything under the shared
    // circuits workspace.
    let nonce = format!("{}_{}", std::process::id(), rand::random::<u32>());
    let nargo = tool("NARGO_BIN", ".nargo/bin/nargo");
    let bb = tool("BB_BIN", ".bb/bb");

    let mut legs = Vec::new();
    for leg in 0..2usize {
        let (pkg, vk_dir) = leg_names(args.param_set, leg);
        let pkg_dir = circuits_dir.join(&pkg);
        if !pkg_dir.exists() {
            return Err(format!("circuit package dir missing: {}", pkg_dir.display()).into());
        }
        let prover_name = format!("Prover_{nonce}");
        let prover_path = pkg_dir.join(format!("{prover_name}.toml"));
        // The codegen toml carries both legs' keys; nargo ignores keys a
        // circuit does not declare, so one toml serves both packages.
        fs::write(&prover_path, &toml)?;

        let witness_name = format!("{pkg}_{nonce}");
        let t = Instant::now();
        {
            // Serialize nargo per package: compile writes the shared
            // target/<pkg>.json.
            let lockfile = File::create(pkg_dir.join(".participant.lock"))?;
            lockfile.lock()?;
            run(
                &nargo,
                &[
                    "execute",
                    "--package",
                    &pkg,
                    "-p",
                    &prover_name,
                    &witness_name,
                ],
                &circuits_dir,
                &format!("nargo execute ({pkg})"),
            )?;
            // Lock releases on drop.
        }
        let nargo_time = t.elapsed();

        let proof_dir = out_dir.join(format!("proof_ct{leg}"));
        fs::create_dir_all(&proof_dir)?;
        let t = Instant::now();
        run(
            &bb,
            &[
                "prove",
                "-b",
                &format!("target/{pkg}.json"),
                "-w",
                &format!("target/{witness_name}.gz"),
                "-k",
                &format!("target/{vk_dir}/vk"),
                "-o",
                proof_dir.to_str().ok_or("out-dir not valid UTF-8")?,
                "-t",
                "evm",
            ],
            &circuits_dir,
            &format!("bb prove ({pkg})"),
        )?;
        let bb_time = t.elapsed();
        eprintln!("{pkg}: nargo execute {nargo_time:.2?}, bb prove {bb_time:.2?}");

        // Clean the per-invocation scratch files from the shared tree.
        let _ = fs::remove_file(&prover_path);
        let _ = fs::remove_file(circuits_dir.join(format!("target/{witness_name}.gz")));

        let proof_hex = format!("0x{}", hex::encode(fs::read(proof_dir.join("proof"))?));
        let public_inputs = read_words(&proof_dir.join("public_inputs"))?;
        legs.push((proof_hex, public_inputs));
    }

    // Leg binding: ct0 outputs (pk0_c, ct0_c, m_c, u_c), ct1 outputs
    // (pk1_c, ct1_c, u_c) — the shared u commitment is the randomness
    // binding the on-chain gate checks.
    let (ct0_proof, ct0_inputs) = &legs[0];
    let (ct1_proof, ct1_inputs) = &legs[1];
    if ct0_inputs.len() != 4 || ct1_inputs.len() != 3 {
        return Err(format!(
            "unexpected public-input counts: ct0 {} (want 4), ct1 {} (want 3)",
            ct0_inputs.len(),
            ct1_inputs.len()
        )
        .into());
    }
    if ct0_inputs[3] != ct1_inputs[2] {
        return Err(format!(
            "u_commitment mismatch across legs: ct0 {} vs ct1 {}",
            ct0_inputs[3], ct1_inputs[2]
        )
        .into());
    }

    let submission = json!({
        "paramSet": args.param_set,
        "ciphertextHex": format!("0x{}", hex::encode(&ciphertext)),
        "ct0": { "proofHex": ct0_proof, "publicInputs": ct0_inputs },
        "ct1": { "proofHex": ct1_proof, "publicInputs": ct1_inputs },
    });
    let submission_path = out_dir.join("submission.json");
    fs::write(&submission_path, serde_json::to_string_pretty(&submission)?)?;

    println!("u_commitment: {}", ct0_inputs[3]);
    println!("submission: {}", submission_path.display());
    eprintln!("total {:.2?}", total.elapsed());
    Ok(())
}
