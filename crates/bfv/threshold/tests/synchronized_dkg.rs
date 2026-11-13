// SPDX-License-Identifier: LGPL-3.0-only

//! Independent native encrypted transport -> production encoders -> isolated Noir leaves.
//! These tests do not supply the missing authenticated recursive joins or enable admission.

use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{create_deterministic_crp_from_default_seed, BfvProfile};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_trbfv::{
    shares::{BfvEncryptedShare, ShamirShare},
    synchronized::{pack_key, unpack_key, PrfKey},
};
use e3_zk_config::{synchronized::Configs, CircuitName};
use e3_zk_witness::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment, compute_dkg_pk_commitment,
    compute_share_encryption_commitment_from_message, compute_threshold_pk_commitment,
    dkg::{pk, share_encryption},
    synchronized::{commitments, pk_generation, share_computation, share_decryption, SetupBinding},
};
use fhe::{
    bfv::{Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::PublicKeyShare,
    trbfv::ShareManager,
};
use fhe_traits::FheEncoder;
use ndarray::Array2;
use num_bigint::{BigInt, Sign};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PROFILE: BfvProfile = BfvProfile::SyncDecInsecure64;
const BINDING: SetupBinding = [0x2456, u128::MAX - 7];
const DEALERS: [u32; 2] = [0, 2];

struct Leaf {
    role: CircuitName,
    inputs: Value,
    outputs: Vec<BigInt>,
    prove: bool,
}

struct Fixture {
    config: Configs,
    leaves: Vec<Leaf>,
    openings: Vec<share_decryption::Data>,
}

impl Fixture {
    fn native() -> Result<Self> {
        let config = Configs::for_profile(PROFILE, CiphernodesCommitteeSize::Minimum)?;
        let values = config.committee.values();
        let mut rng = ChaCha8Rng::seed_from_u64(245602);
        let mut manager = ShareManager::new(values.n, values.threshold, config.threshold.clone())?;
        let keys = (0..values.n)
            .map(|_| {
                (0..values.n)
                    .map(|_| PrfKey::random(PROFILE, &mut rng))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let outgoing: Vec<Vec<_>> = keys
            .iter()
            .map(|row| row.iter().map(|key| *key.as_bytes()).collect())
            .collect();
        let roots = outgoing
            .iter()
            .enumerate()
            .map(|(owner, row)| commitments::outgoing_root(&config, BINDING, owner as u32, row))
            .collect::<Result<Vec<_>, _>>()?;
        let recipient_secrets: Vec<_> = (0..values.n)
            .map(|_| SecretKey::random(&config.transport, &mut rng))
            .collect();
        let recipient_public: Vec<_> = recipient_secrets
            .iter()
            .map(|secret| PublicKey::new(secret, &mut rng))
            .collect();
        let mut leaves = Vec::new();
        let mut public_commitments = Vec::new();
        for (recipient, public) in recipient_public.iter().enumerate() {
            let inputs = pk::Inputs::compute(&config.pk, public)?;
            let expected =
                compute_dkg_pk_commitment(&inputs.pk0is, &inputs.pk1is, config.pk.pk_bit);
            public_commitments.push(expected.clone());
            leaves.push(Leaf {
                role: CircuitName::PkBfv,
                inputs: inputs.to_json(),
                outputs: vec![expected],
                prove: recipient == 2,
            });
        }
        let mut messages = vec![Vec::new(); values.n];
        let mut message_commitments = vec![Vec::new(); values.n];
        let mut received_keys = vec![Vec::new(); values.n];
        let mut residues = vec![Vec::new(); values.n];
        let crp = create_deterministic_crp_from_default_seed(&config.threshold);
        for dealer in 0..values.n {
            let secret = SecretKey::random(&config.threshold, &mut rng);
            let (public, intermediates) =
                PublicKeyShare::new_with_intermediates(&secret, crp.clone(), &mut rng)?;
            let generation = pk_generation::Inputs::compute(
                &config,
                BINDING,
                dealer as u32,
                &pk_generation::Data {
                    pk0_share: CrtPolynomial::from_fhe_polynomial(public.p0_share()),
                    eek: CrtPolynomial::from_fhe_polynomial(intermediates.error()),
                    sk: CrtPolynomial::from_fhe_polynomial(intermediates.secret_key()),
                },
            )?;
            let sharing_poly = manager.coeffs_to_poly_level0(secret.coeffs.as_ref())?;
            let shares = manager.generate_secret_shares_from_poly(sharing_poly, &mut rng)?;
            let mut secret_crt = CrtPolynomial::from_fhe_polynomial(intermediates.secret_key());
            secret_crt.center(config.threshold.moduli())?;
            let sharing = share_computation::Inputs::compute(
                &config,
                BINDING,
                dealer as u32,
                share_computation::Data {
                    secret: secret_crt,
                    secret_sss: shares.iter().map(|row| row.mapv(BigInt::from)).collect(),
                    outgoing_keys: outgoing[dealer].clone(),
                },
            )?;
            let sk_commitment = e3_zk_witness::compute_share_computation_sk_commitment(
                &generation.sk,
                config.pk_generation.bits.sk_bit,
            );
            ensure!(sharing.expected_secret_commitment() == &sk_commitment);
            leaves.push(Leaf {
                role: CircuitName::PkGeneration,
                inputs: generation.to_json(),
                outputs: vec![
                    sk_commitment,
                    compute_threshold_pk_commitment(
                        &generation.pk0is,
                        config.pk_generation.bits.pk_bit,
                    ),
                ],
                prove: DEALERS.contains(&(dealer as u32)),
            });
            let mut packed_commitments = Vec::new();
            for recipient in 0..values.n {
                let share = ShamirShare::new(Array2::from_shape_fn(
                    (config.threshold.moduli().len(), config.threshold.degree()),
                    |(limb, coefficient)| shares[limb][[recipient, coefficient]],
                ));
                let packed = pack_key(PROFILE, &share, &keys[dealer][recipient])?;
                let expected: Vec<_> = packed
                    .rows()
                    .into_iter()
                    .map(|row| {
                        let polynomial =
                            Polynomial::new(row.iter().rev().copied().map(BigInt::from).collect());
                        compute_share_encryption_commitment_from_message(
                            &polynomial,
                            config.share_encryption.bits.msg_bit,
                        )
                    })
                    .collect();
                packed_commitments.extend(expected.clone());
                if !DEALERS.contains(&(dealer as u32)) {
                    continue;
                }
                let (encrypted, witnesses) = BfvEncryptedShare::encrypt_extended(
                    &packed,
                    &recipient_public[recipient],
                    &config.transport,
                    &mut rng,
                )?;
                let decoded = encrypted.decrypt(
                    &recipient_secrets[recipient],
                    &config.transport,
                    config.threshold.degree(),
                )?;
                let (unpacked, incoming) = unpack_key(PROFILE, &decoded)?;
                ensure!(unpacked == share, "Native transport changed the SK share");
                ensure!(
                    incoming.as_bytes() == keys[dealer][recipient].as_bytes(),
                    "Native transport changed the directed key"
                );
                messages[recipient]
                    .push(decoded.rows().into_iter().map(|row| row.to_vec()).collect());
                message_commitments[recipient].push(expected.clone());
                received_keys[recipient].push(*incoming.as_bytes());
                residues[recipient].push(unpacked.view().to_owned());
                for (limb, witness) in witnesses.into_iter().enumerate() {
                    let inputs = share_encryption::Inputs::compute(
                        &config.share_encryption,
                        &share_encryption::ShareEncryptionCircuitData {
                            plaintext: Plaintext::try_encode(
                                &witness.share_row,
                                Encoding::poly(),
                                &config.transport,
                            )?,
                            ciphertext: witness.ciphertext,
                            public_key: recipient_public[recipient].clone(),
                            u_rns: witness.u_rns,
                            e0_rns: witness.e0_rns,
                            e1_rns: witness.e1_rns,
                        },
                    )?;
                    ensure!(inputs.pk_commitment == public_commitments[recipient]);
                    ensure!(inputs.msg_commitment == expected[limb]);
                    leaves.push(Leaf {
                        role: CircuitName::ShareEncryption,
                        inputs: inputs.to_json(),
                        outputs: vec![compute_ciphertext_commitment(
                            &inputs.ct0is,
                            &inputs.ct1is,
                            config.share_encryption.bits.ct_bit,
                        )],
                        prove: dealer == 0 && recipient == 2,
                    });
                }
            }
            packed_commitments.push(roots[dealer].clone());
            leaves.push(Leaf {
                role: CircuitName::SkShareComputation,
                inputs: sharing.to_json(),
                outputs: packed_commitments,
                prove: DEALERS.contains(&(dealer as u32)),
            });
        }
        let mut openings = Vec::new();
        for recipient in 0..values.n {
            let aggregate = manager.aggregate_collected_shares(&residues[recipient])?;
            let mut aggregate = CrtPolynomial::from_fhe_polynomial(&aggregate);
            aggregate.reverse();
            aggregate.center(config.threshold.moduli())?;
            let sk = compute_aggregated_shares_commitment(&aggregate, config.aggregate_bit);
            let bundle = commitments::key_bundle(
                &config,
                BINDING,
                recipient as u32,
                &DEALERS,
                &sk,
                &outgoing[recipient],
                &received_keys[recipient],
            )?;
            let data = share_decryption::Data {
                recipient_id: recipient as u32,
                dealer_ids: DEALERS.to_vec(),
                expected_outgoing_root: roots[recipient].clone(),
                expected_commitments: message_commitments[recipient].clone(),
                packed_shares: messages[recipient].clone(),
                outgoing_keys: outgoing[recipient].clone(),
                incoming_keys: received_keys[recipient].clone(),
            };
            let inputs = share_decryption::Inputs::compute(&config, BINDING, copy_opening(&data))?;
            leaves.push(Leaf {
                role: CircuitName::DkgShareDecryption,
                inputs: inputs.to_json(),
                outputs: vec![sk, bundle],
                prove: true,
            });
            openings.push(data);
        }
        Ok(Self {
            config,
            leaves,
            openings,
        })
    }
}

// Keep production private inputs non-Clone/non-serializable; only the test explicitly copies them.
fn copy_opening(data: &share_decryption::Data) -> share_decryption::Data {
    share_decryption::Data {
        recipient_id: data.recipient_id,
        dealer_ids: data.dealer_ids.clone(),
        expected_outgoing_root: data.expected_outgoing_root.clone(),
        expected_commitments: data.expected_commitments.clone(),
        packed_shares: data.packed_shares.clone(),
        outgoing_keys: data.outgoing_keys.clone(),
        incoming_keys: data.incoming_keys.clone(),
    }
}

#[test]
fn native_transport_and_typed_openings_bind_full_committee_slots() -> Result<()> {
    let fixture = Fixture::native()?;
    ensure!(!PROFILE.admission_enabled());
    ensure!(!fixture.config.share_encryption.scaled_quotient.available);
    let base = &fixture.openings[2];
    for alter in 0..10 {
        let mut data = copy_opening(base);
        match alter {
            0 => data.dealer_ids.reverse(),
            1 => data.dealer_ids[1] = data.dealer_ids[0],
            2 => data.dealer_ids[1] = 3,
            3 => data.incoming_keys[0][0] ^= 1,
            4 => data.outgoing_keys[0][0] ^= 1,
            5 => data.incoming_keys[0][8] = 1,
            6 => data.expected_commitments[0][0] += 1,
            7 => data.packed_shares[0][1][0] = fixture.config.threshold.moduli()[1],
            8 => data.packed_shares[0][0][0] = 2 * fixture.config.threshold.moduli()[0],
            9 => {
                data.packed_shares[0][0].pop();
            }
            _ => unreachable!(),
        }
        ensure!(
            share_decryption::Inputs::compute(&fixture.config, BINDING, data).is_err(),
            "Malformed C4 input {alter} was accepted"
        );
    }
    ensure!(share_decryption::Inputs::compute(
        &fixture.config,
        [BINDING[0] + 1, BINDING[1]],
        copy_opening(base),
    )
    .is_err());
    let key = &base.outgoing_keys[0];
    let directed = commitments::directed_key(&fixture.config, BINDING, 2, 0, key)?;
    ensure!(directed != commitments::directed_key(&fixture.config, BINDING, 0, 2, key)?);
    ensure!(directed != commitments::directed_key(&fixture.config, [1, 2], 2, 0, key)?);
    let original = &fixture.leaves.last().context("Missing C4")?.outputs;
    let mut outgoing = base.outgoing_keys.clone();
    // Dealer 2 is roster row 1, but its outgoing key is full-committee slot 2.
    outgoing.swap(1, 2);
    ensure!(commitments::key_bundle(
        &fixture.config,
        BINDING,
        2,
        &DEALERS,
        &original[0],
        &outgoing,
        &base.incoming_keys,
    )
    .is_err());
    Ok(())
}

struct CircuitJob {
    directory: tempfile::TempDir,
}

fn run(command: &mut Command) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("Start {command:?}"))?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    ensure!(
        output.status.success() && !diagnostic.contains("bug:"),
        "{command:?}: {diagnostic}"
    );
    Ok(output)
}

impl CircuitJob {
    fn new(root: &Path, role: CircuitName) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join("src"))?;
        fs::write(
            directory.path().join("Nargo.toml"),
            format!(
                "[package]\nname=\"sync_leaf\"\ntype=\"bin\"\nauthors=[]\n[dependencies]\nlib={{path={:?}}}\n",
                root.join("circuits/lib")
            ),
        )?;
        fs::copy(
            root.join("circuits/bin")
                .join(role.source_path(PROFILE).context("Missing sync source")?)
                .join("src/main.nr"),
            directory.path().join("src/main.nr"),
        )?;
        Ok(Self { directory })
    }

    fn write(&self, input: &Value) -> Result<()> {
        fs::write(
            self.directory.path().join("Prover.toml"),
            toml::to_string(input)?,
        )?;
        Ok(())
    }

    fn execute(&self, input: &Value) -> Result<()> {
        self.write(input)?;
        run(Command::new("nargo")
            .arg("execute")
            .current_dir(self.directory.path()))?;
        Ok(())
    }

    fn reject(&self, input: &Value, case: &str) -> Result<()> {
        self.write(input)?;
        let output = Command::new("nargo")
            .arg("execute")
            .current_dir(self.directory.path())
            .output()?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        ensure!(
            !output.status.success()
                && (diagnostic.contains("constraint") || diagnostic.contains("Assertion failed"))
                && !diagnostic.contains("bug:"),
            "{case} did not fail a completed constraint check: {diagnostic}"
        );
        Ok(())
    }

    fn prove(&self, bb: &Path, config: &Configs, leaf: &Leaf) -> Result<()> {
        let target = self.directory.path().join("target");
        let proof = self.directory.path().join("proof");
        run(Command::new(bb)
            .args(["prove", "--write_vk", "-t", "noir-recursive", "-b"])
            .arg(target.join("sync_leaf.json"))
            .arg("-w")
            .arg(target.join("sync_leaf.gz"))
            .arg("-o")
            .arg(&proof))?;
        let verify = |inputs: &Path| {
            let mut command = Command::new(bb);
            command
                .args([
                    "verify",
                    "--scheme",
                    "ultra_honk",
                    "-t",
                    "noir-recursive",
                    "-k",
                ])
                .arg(proof.join("vk"))
                .arg("-p")
                .arg(proof.join("proof"))
                .arg("-i")
                .arg(inputs);
            command
        };
        let public_inputs = proof.join("public_inputs");
        run(&mut verify(&public_inputs))?;
        let fields = fs::read(&public_inputs)?;
        let expected_count = config
            .public_inputs(leaf.role)
            .context("Missing input count")?
            + config
                .public_outputs(leaf.role)
                .context("Missing output count")?;
        ensure!(
            fields.len() == expected_count * 32,
            "Unexpected leaf public layout"
        );
        let outputs = &fields[fields.len() - leaf.outputs.len() * 32..];
        for (encoded, expected) in outputs.chunks_exact(32).zip(&leaf.outputs) {
            ensure!(
                &BigInt::from_bytes_be(Sign::Plus, encoded) == expected,
                "{} disagrees with native transport commitments",
                leaf.role,
            );
        }
        let tampered = proof.join("tampered_inputs");
        for field in 0..expected_count {
            let mut altered = fields.clone();
            altered[field * 32 + 31] ^= 1;
            fs::write(&tampered, altered)?;
            let rejected = verify(&tampered).output()?;
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&rejected.stdout),
                String::from_utf8_lossy(&rejected.stderr),
            );
            ensure!(
                !rejected.status.success() && diagnostic.contains("Proof verification failed"),
                "Altered leaf public field {field} did not reach a completed invalid verification: {diagnostic}"
            );
        }
        Ok(())
    }
}

fn check_tools(root: &Path) -> Result<PathBuf> {
    let bb = PathBuf::from(std::env::var_os("E3_CUSTOM_BB").unwrap_or_else(|| "bb".into()));
    let nargo = run(Command::new("nargo").arg("--version"))?;
    let expected = e3_zk_build::pinned_noir_version(&fs::read_to_string(
        root.join("crates/zk/prover/Cargo.toml"),
    )?)?;
    ensure!(e3_zk_build::reports_version(
        &String::from_utf8_lossy(&nargo.stdout),
        &expected
    ));
    let pin: Value =
        serde_json::from_slice(&fs::read(root.join("crates/zk/prover/versions.json"))?)?;
    let version = run(Command::new(&bb).arg("--version"))?;
    ensure!(e3_zk_build::reports_version(
        &String::from_utf8_lossy(&version.stdout),
        pin["required_bb_version"]
            .as_str()
            .context("Missing BB pin")?,
    ));
    Ok(bb)
}

#[test]
#[ignore = "requires pinned nargo/bb; proves only disabled sync DKG leaves, not recursive/runtime admission"]
fn private_native_dkg_leaves_prove_and_reject_substitutions() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let bb = check_tools(&root)?;
    let fixture = Fixture::native()?;
    let mut jobs = BTreeMap::new();
    for role in CircuitName::SYNCHRONIZED_DKG {
        jobs.insert(role.dir_path(), CircuitJob::new(&root, role)?);
    }
    for leaf in &fixture.leaves {
        let job = &jobs[&leaf.role.dir_path()];
        job.execute(&leaf.inputs)?;
        if leaf.prove {
            job.prove(&bb, &fixture.config, leaf)?;
        }
    }
    let first = |role| {
        fixture
            .leaves
            .iter()
            .find(|leaf| leaf.role == role)
            .unwrap()
    };
    let mut c0 = first(CircuitName::PkBfv).inputs.clone();
    c0["pk0is"][0]["coefficients"][0] = json!(fixture.config.transport.moduli()[0].div_ceil(2));
    jobs[&CircuitName::PkBfv.dir_path()].reject(&c0, "C0 noncanonical key coefficient")?;
    let mut c1 = first(CircuitName::PkGeneration).inputs.clone();
    let quotient = &c1["ris"][0]["coefficients"][0];
    let quotient = quotient
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| quotient.to_string());
    c1["ris"][0]["coefficients"][0] =
        json!((quotient.parse::<BigInt>()? + BigInt::from(1)).to_string());
    jobs[&CircuitName::PkGeneration.dir_path()].reject(&c1, "C1 changed reduced quotient")?;
    let sharing = first(CircuitName::SkShareComputation);
    for (case, pointer, value) in [
        ("C2 excessive degree", "/y/0/0/3", json!(0)),
        (
            "C2 nonternary secret",
            "/sk_secret/coefficients/0",
            json!(2),
        ),
        ("C2 high key bits", "/outgoing_keys/2/8", json!(1)),
        ("C2 outside dealer", "/dealer_id", json!(3)),
        (
            "C2 foreign SK anchor",
            "/expected_secret_commitment",
            json!("1"),
        ),
    ] {
        let mut input = sharing.inputs.clone();
        *input.pointer_mut(pointer).context("Missing C2 field")? = value;
        jobs[&sharing.role.dir_path()].reject(&input, case)?;
    }
    let encryption = first(CircuitName::ShareEncryption);
    for (case, field) in [
        ("C3 substituted C0 key", "expected_pk_commitment"),
        (
            "C3 substituted packed message",
            "expected_message_commitment",
        ),
    ] {
        let mut input = encryption.inputs.clone();
        input[field] = json!("1");
        jobs[&encryption.role.dir_path()].reject(&input, case)?;
    }
    let opening = fixture
        .leaves
        .iter()
        .rev()
        .find(|leaf| leaf.role == CircuitName::DkgShareDecryption)
        .unwrap();
    for (case, pointer, value) in [
        ("C4 different context", "/setup_binding/0", json!("1")),
        ("C4 different recipient", "/recipient_id", json!(1)),
        ("C4 outside dealer", "/dealer_ids/1", json!(3)),
        ("C4 reversed roster", "/dealer_ids", json!([2, 0])),
        ("C4 duplicate roster", "/dealer_ids", json!([0, 0])),
        ("C4 substituted root", "/expected_outgoing_root", json!("1")),
        (
            "C4 changed incoming bit",
            "/incoming_keys/0/0",
            json!(fixture.openings[2].incoming_keys[0][0] ^ 1),
        ),
        ("C4 high key bits", "/incoming_keys/0/8", json!(1)),
        (
            "C4 malformed non-key limb",
            "/packed_shares/0/1/coefficients/0",
            json!(fixture.config.threshold.moduli()[1]),
        ),
        (
            "C4 malformed key limb",
            "/packed_shares/0/0/coefficients/0",
            json!(2 * fixture.config.threshold.moduli()[0]),
        ),
        (
            "C4 substituted message",
            "/expected_commitments/0/0",
            json!("1"),
        ),
    ] {
        let mut input = opening.inputs.clone();
        *input.pointer_mut(pointer).context("Missing C4 field")? = value;
        jobs[&opening.role.dir_path()].reject(&input, case)?;
    }
    // A leaf has no external authentication for dealer IDs. A consistent substitution changes its
    // public root; the recursive parent must compare it rather than assuming local rejection.
    let base = &fixture.openings[2];
    ensure!(
        commitments::outgoing_root(&fixture.config, BINDING, 1, &base.outgoing_keys)?
            != base.expected_outgoing_root
    );
    // A sorted different H-roster also passes this leaf in isolation. Its proof inputs and bundle
    // differ; authenticating the chosen dealers is the missing parent's responsibility.
    let mut changed_roster = opening.inputs.clone();
    changed_roster["dealer_ids"] = json!([1, 2]);
    jobs[&opening.role.dir_path()].execute(&changed_roster)?;
    ensure!(
        commitments::key_bundle(
            &fixture.config,
            BINDING,
            2,
            &[1, 2],
            &opening.outputs[0],
            &base.outgoing_keys,
            &base.incoming_keys,
        )? != opening.outputs[1]
    );
    Ok(())
}
