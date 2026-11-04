// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Explicit boundaries of the existing proving pipeline. Every saved proof is natively verified
//! again on admission; checkpoint metadata never substitutes for cryptographic verification.

use std::{fs, path::Path};

use eyre::{ensure, Result};
use openvm_circuit::arch::ContinuationVmProof;
use openvm_continuations::{CommitBytes, RootSC};
use openvm_sdk::{
    fs::read_halo2_pk_from_file,
    halo2_params::CacheHalo2ParamsReader,
    keygen::AppVerifyingKey,
    prover::{verify_app_proof_with_expected_exe_commit, Halo2Prover, InternalLayerMetadata},
    types::VersionedVmStarkProof,
    DefaultStarkEngine, Sdk, F, OPENVM_VERSION, SC,
};
use openvm_stark_backend::{
    codec::{Decode, Encode},
    p3_field::PrimeField32,
    proof::Proof,
    StarkEngine,
};
use sha2::{Digest, Sha256};

use crate::{
    checkpoint::{self, Checkpoint, Stage},
    read_items, sdk, seal, verify, Config,
};

pub(crate) fn run(
    action: &str,
    config: &Config,
    input: &Path,
    journal: &[u8],
    output: &Path,
) -> Result<()> {
    match action {
        "prove-app" => prove_app(config, input, journal, output),
        "aggregate-stark" => aggregate(config, input, journal, output),
        "prove-root" => prove_root(config, input, journal, output),
        "compress-root" => compress(config, input, journal, output),
        _ => eyre::bail!("Unknown proving stage"),
    }
}

fn require_journal(values: &[F], journal: &[u8]) -> Result<()> {
    ensure!(
        values.len() == 32
            && values
                .iter()
                .zip(Sha256::digest(journal))
                .all(|(value, byte)| value.as_canonical_u32() == u32::from(byte)),
        "Authenticated proof values do not equal SHA256(journal)"
    );
    Ok(())
}

fn verify_app(
    key: &AppVerifyingKey,
    proof: &ContinuationVmProof<SC>,
    expected_exe: CommitBytes,
    journal: &[u8],
) -> Result<()> {
    ensure!(
        key.num_user_pvs == 32,
        "Expected exactly 32 public byte values"
    );
    verify_app_proof_with_expected_exe_commit::<DefaultStarkEngine>(
        key,
        proof,
        Some(expected_exe.into()),
    )?;
    require_journal(&proof.user_public_values.public_values, journal)
}

fn verify_root(sdk: &Sdk, proof: &Proof<RootSC>, config: &Config, journal: &[u8]) -> Result<()> {
    let root = sdk.root_prover();
    root.create_engine()
        .verify(root.0.get_vk().as_ref(), proof)?;
    require_root_values(&proof.public_values, config, journal)
}

fn require_root_values(values: &[Vec<F>], config: &Config, journal: &[u8]) -> Result<()> {
    // The pinned RootCircuit exposes executable/VM commitments at AIR0, user values at AIR1.
    ensure!(
        values.len() >= 2 && values[0].len() == 16,
        "Invalid root public value layout"
    );
    let exe: [F; 8] = config.app_commit.app_exe_commit.into();
    let vm: [F; 8] = config.app_commit.app_vm_commit.into();
    ensure!(
        values[0][..8] == exe && values[0][8..] == vm,
        "Authenticated root application identity differs"
    );
    require_journal(&values[1], journal)
}

fn prove_app(config: &Config, input: &Path, journal: &[u8], output: &Path) -> Result<()> {
    let checkpoint = Checkpoint::create(output, config, journal, Stage::Application)?;
    let input = read_items(fs::File::open(input)?)?;
    let (sdk, exe) = sdk(config)?;
    let mut prover = sdk.app_prover(exe)?;
    // The checked SDK has already derived the VM/executable identity. Keep only the app prover
    // while proving, so recursive state does not occupy memory throughout this stage.
    let key = sdk.app_pk().get_app_vk();
    drop(sdk);
    eprintln!("OpenVM: proving the application");
    let proof = prover.prove(input)?;
    drop(prover);
    verify_app(&key, &proof, config.app_commit.app_exe_commit, journal)?;
    let bytes = bitcode::serialize(&proof)?;
    drop(proof);
    checkpoint.save(config, &[("app.proof", bytes)])?;
    eprintln!("OpenVM: saved verified application checkpoint");
    Ok(())
}

fn aggregate(config: &Config, input: &Path, journal: &[u8], output: &Path) -> Result<()> {
    let mut checkpoint = Checkpoint::create(output, config, journal, Stage::Aggregate)?;
    let saved = Checkpoint::open(input, config, journal, Stage::Application)?;
    let proof = bitcode::deserialize(&saved.read("app.proof")?)?;
    let (sdk, exe) = sdk(config)?;
    verify_app(
        &sdk.app_pk().get_app_vk(),
        &proof,
        config.app_commit.app_exe_commit,
        journal,
    )?;
    eprintln!("OpenVM: aggregating the verified application proof");
    let (stark, metadata) = sdk.agg_prover().prove_vm(proof)?;
    Sdk::verify_proof(
        sdk.agg_vk().as_ref().clone(),
        sdk.prover(exe)?.generate_baseline(),
        &stark,
    )?;
    require_journal(&stark.user_pvs_proof.public_values, journal)?;
    drop(sdk);
    let versioned = VersionedVmStarkProof::new(stark)?;
    checkpoint.write("aggregate.json", |writer| {
        Ok(serde_json::to_writer(writer, &versioned)?)
    })?;
    drop(versioned);
    checkpoint.write("metadata.bin", |mut writer| {
        Ok(metadata.encode(&mut writer)?)
    })?;
    checkpoint.finish(config)?;
    eprintln!("OpenVM: saved verified aggregate checkpoint");
    Ok(())
}

fn prove_root(config: &Config, input: &Path, journal: &[u8], output: &Path) -> Result<()> {
    let mut checkpoint = Checkpoint::create(output, config, journal, Stage::Root)?;
    let saved = Checkpoint::open(input, config, journal, Stage::Aggregate)?;
    let versioned: VersionedVmStarkProof = serde_json::from_slice(&saved.read("aggregate.json")?)?;
    // The SDK's TryFrom discards this field, so check it before decoding the native proof.
    ensure!(
        versioned.version == format!("v{OPENVM_VERSION}"),
        "Unsupported aggregate proof version"
    );
    let stark = versioned.try_into()?;
    let mut metadata = InternalLayerMetadata::decode_from_bytes(&saved.read("metadata.bin")?)?;
    ensure!(
        matches!(
            metadata.proofs_type,
            openvm_continuations::circuit::inner::ProofsType::Vm
        ),
        "Expected VM-only aggregation metadata"
    );
    let (sdk, exe) = sdk(config)?;
    Sdk::verify_proof(
        sdk.agg_vk().as_ref().clone(),
        sdk.prover(exe.clone())?.generate_baseline(),
        &stark,
    )?;
    require_journal(&stark.user_pvs_proof.public_values, journal)?;
    eprintln!("OpenVM: proving the root of the verified aggregate");
    let root = sdk
        .evm_prover_without_halo2(exe)?
        .prove_root_from_vm_stark_proof(stark, &mut metadata)?;
    verify_root(&sdk, &root, config, journal)?;
    drop(sdk);
    checkpoint.write("root.bin", |mut writer| Ok(root.encode(&mut writer)?))?;
    checkpoint.finish(config)?;
    eprintln!("OpenVM: saved verified root checkpoint");
    Ok(())
}

fn compress(config: &Config, input: &Path, journal: &[u8], output: &Path) -> Result<()> {
    checkpoint::check_new_file(output)?;
    let saved = Checkpoint::open(input, config, journal, Stage::Root)?;
    let root = Proof::<RootSC>::decode_from_bytes(&saved.read("root.bin")?)?;
    // Reject unrelated work before constructing prover state. Native verification below is
    // still mandatory; unverified public values can reject a job, never authorize one.
    require_root_values(&root.public_values, config, journal)?;
    {
        let (sdk, _) = sdk(config)?;
        verify_root(&sdk, &root, config, journal)?;
    } // Release recursive prover state before allocating Halo2 keys, SRS and proving buffers.
    eprintln!("OpenVM: compressing the verified root into an EVM proof");
    let halo2 = Halo2Prover::new(
        &CacheHalo2ParamsReader::new(&config.halo2_params_dir),
        read_halo2_pk_from_file(&config.halo2_pk)?,
    );
    let proof = halo2.prove_for_evm(&root)?;
    drop(halo2);
    drop(root);
    verify(&proof, config, journal)?;
    // Recheck provenance after the expensive stage before publishing its verified result.
    saved.check_artifacts(config)?;
    checkpoint::publish_new(output, &seal(&proof))?;
    eprintln!("OpenVM: saved verified EVM seal");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_config;
    use openvm_stark_backend::p3_field::PrimeCharacteristicRing;

    fn journal_values(journal: &[u8]) -> Vec<F> {
        Sha256::digest(journal)
            .into_iter()
            .map(|byte| F::from_u32(u32::from(byte)))
            .collect()
    }

    #[test]
    fn journal_values_must_be_exact_bytes_not_just_their_low_eight_bits() {
        let journal = [7; 288];
        let mut values = journal_values(&journal);
        require_journal(&values, &journal).unwrap();
        values[0] += F::from_u32(256);
        assert!(require_journal(&values, &journal).is_err());
        assert!(require_journal(&journal_values(&journal), &[8; 288]).is_err());
        assert!(require_journal(&journal_values(&journal)[..31], &journal).is_err());
        values.push(F::ZERO);
        assert!(require_journal(&values, &journal).is_err());
    }

    #[test]
    fn root_values_bind_both_commitments_and_the_exact_journal() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let journal = [7; 288];
        // Other root AIRs have no public values, but still appear in the proof's layout.
        let mut values = vec![vec![F::ZERO; 16], journal_values(&journal), vec![]];
        require_root_values(&values, &config, &journal).unwrap();
        for index in [0, 8] {
            values[0][index] = F::ONE;
            assert!(require_root_values(&values, &config, &journal).is_err());
            values[0][index] = F::ZERO;
        }
        assert!(require_root_values(&values, &config, &[8; 288]).is_err());
        assert!(require_root_values(&values[..1], &config, &journal).is_err());
        values[0].pop();
        assert!(require_root_values(&values, &config, &journal).is_err());
    }

    #[test]
    fn matching_hashes_do_not_make_invalid_serialized_proofs_acceptable() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        for (stage, name, action) in [
            (Stage::Application, "app.proof", "aggregate-stark"),
            (Stage::Root, "root.bin", "compress-root"),
        ] {
            let input = temp.path().join(name);
            Checkpoint::create(&input, &config, &[7; 288], stage)
                .unwrap()
                .save(&config, &[(name, vec![1, 2, 3])])
                .unwrap();
            let output = temp.path().join(action);
            assert!(run(action, &config, &input, &[7; 288], &output).is_err());
            assert!(!output.join("manifest.json").exists());
            if action == "compress-root" {
                assert!(!output.exists());
            }
        }
    }

    #[test]
    fn malformed_guest_framing_cannot_publish_an_application_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let input = temp.path().join("input.bin");
        // Zero input items followed by an unframed byte. Keys intentionally cannot deserialize.
        fs::write(&input, [0, 0, 0, 0, 1]).unwrap();
        let output = temp.path().join("application");
        let error = run("prove-app", &config, &input, &[7; 288], &output).unwrap_err();
        assert!(error
            .to_string()
            .contains("Unexpected bytes after the last guest input item"));
        assert!(!output.join("manifest.json").exists());
    }

    #[test]
    fn aggregate_proof_version_is_checked_even_when_manifest_and_digest_match() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let input = temp.path().join("aggregate");
        let versioned = VersionedVmStarkProof {
            version: "v0.0".to_owned(),
            proof: vec![],
            user_pvs_proof: vec![],
            deferral_merkle_proofs: None,
        };
        let metadata = InternalLayerMetadata {
            internal_recursive_layer: 0,
            internal_node_idx: 0,
            proofs_type: openvm_continuations::circuit::inner::ProofsType::Vm,
        };
        Checkpoint::create(&input, &config, &[7; 288], Stage::Aggregate)
            .unwrap()
            .save(
                &config,
                &[
                    ("aggregate.json", serde_json::to_vec(&versioned).unwrap()),
                    ("metadata.bin", metadata.encode_to_vec().unwrap()),
                ],
            )
            .unwrap();
        let output = temp.path().join("root");
        let error = run("prove-root", &config, &input, &[7; 288], &output).unwrap_err();
        assert!(error
            .to_string()
            .contains("Unsupported aggregate proof version"));
        assert!(!output.join("manifest.json").exists());
    }

    #[test]
    fn existing_seal_outputs_are_rejected_before_keys_or_checkpoints_are_read() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let input = temp.path().join("missing-checkpoint");
        let output = temp.path().join("seal");
        fs::write(&output, b"existing").unwrap();
        let error = run("compress-root", &config, &input, &[7; 288], &output).unwrap_err();
        assert!(error.to_string().contains("output already exists"));
        assert_eq!(fs::read(output).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_seal_output_is_rejected_before_keys_or_checkpoints_are_read() {
        use std::os::unix::fs::PermissionsExt;
        // Root can write through these permission bits; exercise this case as an ordinary user.
        // SAFETY: geteuid has no arguments or caller-side preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let directory = temp.path().join("read-only");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        let output = directory.join("seal");
        let result = run(
            "compress-root",
            &config,
            &temp.path().join("missing-checkpoint"),
            &[7; 288],
            &output,
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot create an output file before proving"));
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_seal_output_symlinks_are_rejected_without_following_them() {
        let temp = tempfile::tempdir().unwrap();
        let config = test_config(temp.path());
        let output = temp.path().join("seal");
        std::os::unix::fs::symlink(temp.path().join("missing"), &output).unwrap();
        let error = run(
            "compress-root",
            &config,
            &temp.path().join("missing-checkpoint"),
            &[7; 288],
            &output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("output already exists"));
        assert!(!temp.path().join("missing").exists());
    }

    #[test]
    #[ignore = "requires independently generated aggregate/root fixtures; checks encoding without prover setup"]
    fn real_checkpoint_encodings_survive_streaming_without_prover_setup() -> Result<()> {
        let aggregate = std::path::PathBuf::from(std::env::var("OPENVM_AGGREGATE_FIXTURE")?);
        let root = std::path::PathBuf::from(std::env::var("OPENVM_ROOT_FIXTURE")?);
        let config = crate::config(&root.join("config.json"))?;
        let journal = fs::read(root.join("journal.bin"))?;
        ensure!(journal.len() == 288, "Expected nine journal words");
        ensure!(
            fs::read(aggregate.join("journal.bin"))? == journal,
            "Fixture journals differ"
        );
        let temp = tempfile::tempdir()?;

        let versioned: VersionedVmStarkProof = serde_json::from_slice(&crate::read_limited(
            &aggregate.join("aggregate.json"),
            256 * 1024 * 1024,
        )?)?;
        let metadata_bytes = crate::read_limited(&aggregate.join("metadata.bin"), 64)?;
        let metadata = InternalLayerMetadata::decode_from_bytes(&metadata_bytes)?;
        let directory = temp.path().join("aggregate");
        let mut checkpoint = Checkpoint::create(&directory, &config, &journal, Stage::Aggregate)?;
        checkpoint.write("aggregate.json", |writer| {
            Ok(serde_json::to_writer(writer, &versioned)?)
        })?;
        checkpoint.write("metadata.bin", |mut writer| {
            Ok(metadata.encode(&mut writer)?)
        })?;
        checkpoint.finish(&config)?;
        let saved = Checkpoint::open(&directory, &config, &journal, Stage::Aggregate)?;
        let decoded: VersionedVmStarkProof =
            serde_json::from_slice(&saved.read("aggregate.json")?)?;
        assert_eq!(decoded.version, versioned.version);
        assert_eq!(decoded.proof, versioned.proof);
        assert_eq!(decoded.user_pvs_proof, versioned.user_pvs_proof);
        assert_eq!(
            decoded.deferral_merkle_proofs,
            versioned.deferral_merkle_proofs
        );
        assert_eq!(saved.read("metadata.bin")?, metadata_bytes);

        let root_bytes = crate::read_limited(&root.join("root.bin"), 256 * 1024 * 1024)?;
        let proof = Proof::<RootSC>::decode_from_bytes(&root_bytes)?;
        let directory = temp.path().join("root");
        let mut checkpoint = Checkpoint::create(&directory, &config, &journal, Stage::Root)?;
        checkpoint.write("root.bin", |mut writer| Ok(proof.encode(&mut writer)?))?;
        checkpoint.finish(&config)?;
        let saved = Checkpoint::open(&directory, &config, &journal, Stage::Root)?;
        assert_eq!(saved.read("root.bin")?, root_bytes);

        let keys = temp.path().join("unreadable-keys");
        fs::create_dir(&keys)?;
        let mut invalid_setup = test_config(&keys);
        invalid_setup.app_commit = config.app_commit.clone();
        let mut wrong_journal = proof;
        wrong_journal.public_values[1][0] += F::ONE;
        let directory = temp.path().join("wrong-root-journal");
        let mut checkpoint = Checkpoint::create(&directory, &invalid_setup, &journal, Stage::Root)?;
        checkpoint.write("root.bin", |mut writer| {
            Ok(wrong_journal.encode(&mut writer)?)
        })?;
        checkpoint.finish(&invalid_setup)?;
        let output = temp.path().join("must-not-publish");
        let error = run(
            "compress-root",
            &invalid_setup,
            &directory,
            &journal,
            &output,
        )
        .unwrap_err();
        // Invalid key files make this assertion fail cheaply if SDK setup runs before the
        // journal preflight. A matching manifest/hash must not cause that expensive setup.
        assert!(error.to_string().contains("SHA256(journal)"));
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    #[ignore = "requires an independently generated application STARK; see README"]
    fn real_application_checkpoint_rejects_wrong_executable_journal_and_tampered_public_values(
    ) -> Result<()> {
        use openvm_sdk::{
            config::AggregationSystemParams, fs::read_object_from_file, keygen::AppProvingKey,
            CpuSdk,
        };
        use openvm_sdk_config::SdkVmConfig;
        let fixture = std::path::PathBuf::from(std::env::var("OPENVM_APP_FIXTURE")?);
        let key: AppProvingKey<SdkVmConfig> = read_object_from_file(fixture.join("app.pk"))?;
        let app_vk = key.get_app_vk();
        let exe: crate::VmExe<F> = read_object_from_file(fixture.join("guest.vmexe"))?;
        let sdk = CpuSdk::builder()
            .app_pk(key)
            .agg_params(AggregationSystemParams::default())
            .build()?;
        eprintln!("Fixture: deriving the expected executable commitment");
        let expected_exe = sdk.app_prover(exe)?.app_exe_commit().into();
        let proof: ContinuationVmProof<SC> = read_object_from_file(fixture.join("app.proof"))?;
        let journal = fs::read(fixture.join("journal.bin"))?;
        ensure!(journal.len() == 288, "Expected nine journal words");
        eprintln!("Fixture: verifying the valid application proof and its serialized roundtrip");
        verify_app(&app_vk, &proof, expected_exe, &journal)?;
        let encoded = bitcode::serialize(&proof)?;
        let mut decoded: ContinuationVmProof<SC> = bitcode::deserialize(&encoded)?;
        verify_app(&app_vk, &decoded, expected_exe, &journal)?;
        eprintln!("Fixture: rejecting the wrong executable, journal and altered public values");
        assert!(verify_app(&app_vk, &proof, CommitBytes::try_new([0; 32])?, &journal).is_err());
        let mut wrong_journal = journal.clone();
        wrong_journal[0] ^= 1;
        assert!(verify_app(&app_vk, &proof, expected_exe, &wrong_journal).is_err());
        decoded.user_public_values.public_values[0] += F::ONE;
        assert!(verify_app(&app_vk, &decoded, expected_exe, &journal).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires an independently generated aggregate STARK and matching configuration; see README"]
    fn real_aggregate_checkpoint_authenticates_its_public_values() -> Result<()> {
        let fixture = std::path::PathBuf::from(std::env::var("OPENVM_AGGREGATE_FIXTURE")?);
        let config = crate::config(&fixture.join("config.json"))?;
        let journal = fs::read(fixture.join("journal.bin"))?;
        ensure!(journal.len() == 288, "Expected nine journal words");
        let versioned: VersionedVmStarkProof = serde_json::from_slice(&crate::read_limited(
            &fixture.join("aggregate.json"),
            256 * 1024 * 1024,
        )?)?;
        ensure!(
            versioned.version == format!("v{OPENVM_VERSION}"),
            "Unsupported aggregate proof version"
        );
        let stark = versioned.try_into()?;
        let (sdk, exe) = sdk(&config)?;
        let baseline = sdk.prover(exe)?.generate_baseline();
        Sdk::verify_proof(sdk.agg_vk().as_ref().clone(), baseline.clone(), &stark)?;
        require_journal(&stark.user_pvs_proof.public_values, &journal)?;
        let mut wrong_journal = journal.clone();
        wrong_journal[0] ^= 1;
        assert!(require_journal(&stark.user_pvs_proof.public_values, &wrong_journal).is_err());
        let mut tampered = stark;
        tampered.user_pvs_proof.public_values[0] += F::ONE;
        assert!(Sdk::verify_proof(sdk.agg_vk().as_ref().clone(), baseline, &tampered).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires an independently generated root STARK and matching configuration; see README"]
    fn real_root_checkpoint_is_verified_before_compression() -> Result<()> {
        use openvm_sdk::{
            fs::read_object_from_file,
            keygen::{AggProvingKey, AppProvingKey},
        };
        use openvm_sdk_config::SdkVmConfig;

        let fixture = std::path::PathBuf::from(std::env::var("OPENVM_ROOT_FIXTURE")?);
        let config = crate::config(&fixture.join("config.json"))?;
        let journal = fs::read(fixture.join("journal.bin"))?;
        ensure!(journal.len() == 288, "Expected nine journal words");
        let root = Proof::<RootSC>::decode_from_bytes(&crate::read_limited(
            &fixture.join("root.bin"),
            256 * 1024 * 1024,
        )?)?;
        // The independently prepared fixture supplies the trusted identity and keys. Root
        // admission needs the derived root verifier, without allocating an application VM.
        let app_pk: AppProvingKey<SdkVmConfig> = read_object_from_file(&config.app_pk)?;
        let agg_pk: AggProvingKey = read_object_from_file(&config.aggregation_pk)?;
        let sdk = Sdk::builder().app_pk(app_pk).agg_pk(agg_pk).build()?;
        verify_root(&sdk, &root, &config, &journal)?;
        let mut wrong_journal = journal.clone();
        wrong_journal[0] ^= 1;
        assert!(verify_root(&sdk, &root, &config, &wrong_journal).is_err());
        let mut tampered = root;
        tampered.public_values[1][0] += F::ONE;
        assert!(verify_root(&sdk, &tampered, &config, &journal).is_err());
        Ok(())
    }
}
