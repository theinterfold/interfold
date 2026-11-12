// SPDX-License-Identifier: LGPL-3.0-only

#[path = "../examples/sync_prf_vectors.rs"]
mod vectors;

#[test]
fn frozen_noir_prf_vectors_match_the_released_fhe_implementation() {
    vectors::check().unwrap();
}

#[test]
#[ignore = "requires pinned nargo and bb; proves the private-input PRF primitive, not C6/C7"]
fn private_prf_inputs_prove_and_reject_changed_keys_and_public_outputs() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use std::{fs, path::Path, process::Command};

    fn run(command: &mut Command) -> anyhow::Result<()> {
        let output = command
            .output()
            .with_context(|| format!("Run {command:?}"))?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.status.success() && !diagnostic.contains("bug:"),
            "{command:?}: {diagnostic}"
        );
        Ok(())
    }

    for (fixture, secure_width) in [
        (include_str!("fixtures/prf_conformance.nr"), false),
        (include_str!("fixtures/prf_wide_conformance.nr"), true),
    ] {
        let job = tempfile::tempdir()?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()?;
        fs::create_dir(job.path().join("src"))?;
        let manifest = format!(
            "[package]\nname=\"sync_prf\"\ntype=\"bin\"\nauthors=[]\n[dependencies]\nlib={{path={:?}}}\n",
            root.join("circuits/lib")
        );
        fs::write(job.path().join("Nargo.toml"), manifest)?;
        fs::write(job.path().join("src/main.nr"), fixture)?;
        let mut input = vectors::private_inputs(secure_width)?;
        fs::write(job.path().join("Prover.toml"), toml::to_string(&input)?)?;
        run(Command::new("nargo").arg("execute").current_dir(job.path()))?;

        let bb = std::env::var_os("E3_CUSTOM_BB").unwrap_or_else(|| "bb".into());
        let artifact = job.path().join("target/sync_prf.json");
        let output = job.path().join("proof");
        run(Command::new(&bb)
            .args(["prove", "--write_vk", "-t", "noir-recursive", "-b"])
            .arg(&artifact)
            .arg("-w")
            .arg(job.path().join("target/sync_prf.gz"))
            .arg("-o")
            .arg(&output))?;
        run(Command::new(&bb)
            .args([
                "verify",
                "--scheme",
                "ultra_honk",
                "-t",
                "noir-recursive",
                "-k",
            ])
            .arg(output.join("vk"))
            .arg("-p")
            .arg(output.join("proof"))
            .arg("-i")
            .arg(output.join("public_inputs")))?;

        let mut altered = fs::read(output.join("public_inputs"))?;
        *altered.last_mut().context("No public fields")? ^= 1;
        fs::write(output.join("tampered_inputs"), altered)?;
        let rejected = Command::new(&bb)
            .args([
                "verify",
                "--scheme",
                "ultra_honk",
                "-t",
                "noir-recursive",
                "-k",
            ])
            .arg(output.join("vk"))
            .arg("-p")
            .arg(output.join("proof"))
            .arg("-i")
            .arg(output.join("tampered_inputs"))
            .output()?;
        ensure!(
            !rejected.status.success(),
            "Tampered public mask was accepted"
        );

        // Owner 3's selected peer 1 is slot zero. The expected native mask remains unchanged.
        input["outgoing"][0][0] = serde_json::json!(input["outgoing"][0][0].as_u64().unwrap() ^ 1);
        fs::write(job.path().join("Prover.toml"), toml::to_string(&input)?)?;
        let rejected = Command::new("nargo")
            .arg("execute")
            .current_dir(job.path())
            .output()?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&rejected.stdout),
            String::from_utf8_lossy(&rejected.stderr)
        );
        ensure!(
            !rejected.status.success()
                && diagnostic.contains("constraint")
                && !diagnostic.contains("bug:"),
            "Changed PRF key did not fail a completed constraint check: {diagnostic}"
        );
    }
    Ok(())
}
