// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_zk_witness::synchronized::plaintext_aggregation::{prepare, Contribution};
use e3_zk_witness::{
    commitments::ciphertext_component_commitment, compute_threshold_decryption_share_commitment,
    encoding::fhe_poly_to_crt_centered, synchronized::threshold_decryption::Opening,
};
use fhe::bfv::Ciphertext;
use fhe::trbfv::{
    DecryptionShare, PartyPrfKeyTransport, PartyPrfKeys, SmudgingBoundCalculatorConfig,
    SmudgingNoiseGenerator, SynchronizedDecryptor,
};
use fhe_traits::{FheDecoder, FheEncrypter};

const DOMAIN: [u128; 2] = [0x2050, u128::MAX - 1];

#[test]
#[ignore = "requires pinned nargo and bb; checks C4/C6 proofs and C7 against native plaintext"]
fn native_partials_match_c4_c6_and_c7_proofs() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let bb = check_tools(&root)?;
    let fixture = Fixture::native()?;
    let cfg = &fixture.config;
    let params = &cfg.threshold;
    let mut rng = ChaCha8Rng::seed_from_u64(2050);
    let pk = PublicKey::from_shares(
        DEALERS
            .map(|i| fixture.threshold_shares[i as usize].clone())
            .to_vec(),
    )?;
    let width = e3_zk_config::MAX_MSG_NON_ZERO_COEFFS;
    let mut expected = vec![0u64; width];
    expected[0] = 7;
    expected[width - 1] = params.plaintext() - 1;
    let pt = Plaintext::try_encode(&expected, Encoding::poly(), params)?;
    let ct = pk.try_encrypt(&pt, &mut rng)?;
    let (shares, public) = prove_partials(&root, &bb, &fixture, DEALERS, &ct)?;
    let values = cfg.committee.values();
    let decryptor = SynchronizedDecryptor::new(values.n, values.threshold, params.clone())?;
    let plaintext = decryptor.decrypt_from_shares(&shares, &ct)?;
    ensure!(plaintext == pt);
    let decoded = Vec::<u64>::try_decode(&plaintext, Encoding::poly())?;
    let parts: Vec<_> = shares.into_iter().map(|s| s.into_parts().0).collect();
    let contributions: Vec<_> = public
        .iter()
        .zip(&parts)
        .map(|(row, share)| Contribution {
            public_signals: row,
            share,
        })
        .collect();
    let inputs = prepare(
        cfg,
        BINDING,
        DOMAIN,
        &DEALERS,
        &ct,
        &contributions,
        &decoded[..width],
    )?;
    let role = CircuitName::DecryptedSharesAggregation;
    let job = CircuitJob::new(&root, role)?;
    let leaf = Leaf {
        role,
        inputs,
        outputs: vec![],
        prove: true,
        transport_slot: None,
    };
    job.execute(&leaf.inputs)?;
    job.prove(&bb, cfg, &leaf)?;
    // The next recursion layer will have to compare exactly these fields, in exactly this order.
    let bytes = fs::read(job.directory.path().join("proof/public_inputs"))?;
    let public_batch = public.concat();
    ensure!(bytes.starts_with(&public_batch));
    for (field, &coefficient) in bytes[public_batch.len()..].chunks_exact(32).zip(&expected) {
        ensure!(BigInt::from_bytes_be(Sign::Plus, field) == BigInt::from(coefficient));
    }
    use e3_zk_config::synchronized::public_signals::PublicSignals;
    PublicSignals::decode(cfg, role, &bytes)?;
    let mut duplicate = bytes.clone();
    duplicate[public[0].len()..public_batch.len()].copy_from_slice(&public[0]);
    ensure!(PublicSignals::decode(cfg, role, &duplicate).is_err());
    let mut noncanonical_message = bytes.clone();
    noncanonical_message[public_batch.len() + 24..public_batch.len() + 32]
        .copy_from_slice(&params.plaintext().to_be_bytes());
    ensure!(PublicSignals::decode(cfg, role, &noncanonical_message).is_err());

    ensure!(prepare(
        cfg,
        BINDING,
        DOMAIN,
        &DEALERS,
        &ct,
        &contributions[..1],
        &expected
    )
    .is_err());
    let other_ct = pk.try_encrypt(&pt, &mut rng)?;
    ensure!(prepare(
        cfg,
        BINDING,
        DOMAIN,
        &DEALERS,
        &other_ct,
        &contributions,
        &expected
    )
    .is_err());
    let mut reversed = contributions;
    reversed.reverse();
    ensure!(prepare(cfg, BINDING, DOMAIN, &DEALERS, &ct, &reversed, &expected).is_err());
    let original = &leaf.inputs;
    for (pointer, value) in [
        ("/rows/0", original["rows"][1].clone()),
        ("/rows/1/0", json!("0")),
        ("/rows/0/5", json!("0")),
        ("/rows/1/9", json!("0")),
        ("/shares/1", original["shares"][0].clone()),
        (
            "/c0/0/63",
            json!(original["c0"][0][63].as_u64().unwrap() ^ 1),
        ),
        (
            "/shares/1/0/63",
            json!(original["shares"][1][0][63].as_u64().unwrap() ^ 1),
        ),
        ("/shares/1/0/0", json!(params.moduli()[0])),
        ("/message/0", json!(0)),
        ("/message/1", json!(1)),
        ("/message/49", json!(0)),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        let diagnostic = job.reject(&bad, pointer)?;
        if pointer == "/shares/1/0/0" {
            ensure!(
                diagnostic.contains("Noncanonical C6 share coefficient"),
                "wrong range rejection: {diagnostic}"
            );
        }
    }
    // Same ciphertext and E3, same owner in slot 1, but an independently proven C6 from
    // a different H/S. Neither set is complete after this replacement.
    let other = [1, 2];
    let alt = Fixture::native_with_roster(BINDING, other)?;
    let (alt_shares, alt_public) = prove_partials(&root, &bb, &alt, other, &ct)?;
    let alt_share = alt_shares.into_iter().last().unwrap().into_parts().0;
    let mixed = [
        Contribution {
            public_signals: &public[0],
            share: &parts[0],
        },
        Contribution {
            public_signals: &alt_public[1],
            share: &alt_share,
        },
    ];
    ensure!(prepare(cfg, BINDING, DOMAIN, &DEALERS, &ct, &mixed, &expected).is_err());
    let mut bad = original.clone();
    let alt_row: Vec<_> = alt_public[1]
        .chunks_exact(32)
        .map(|f| BigInt::from_bytes_be(Sign::Plus, f).to_string())
        .collect();
    bad["rows"][1] = json!(alt_row);
    bad["shares"][1] = json!(alt_share
        .coefficients()
        .outer_iter()
        .map(|row| row.to_vec())
        .collect::<Vec<_>>());
    let error = job.reject(&bad, "two incomplete sets of verified C6 shares")?;
    ensure!(
        error.contains("Mixed C6 roster"),
        "mixed proof rows failed for another reason: {error}"
    );
    Ok(())
}

fn prove_partials(
    root: &Path,
    bb: &Path,
    fixture: &Fixture,
    roster: [u32; 2],
    ct: &Ciphertext,
) -> Result<(Vec<DecryptionShare>, Vec<Vec<u8>>)> {
    let cfg = &fixture.config;
    let params = &cfg.threshold;
    let values = cfg.committee.values();
    let mut rng = ChaCha8Rng::seed_from_u64(2050 + u64::from(roster[0]));
    let component = |i: usize| fhe_poly_to_crt_centered(&ct[i], params.moduli());
    let ct_hash = compute_ciphertext_commitment(&component(0)?, &component(1)?, cfg.aggregate_bit);
    let c0_hash = ciphertext_component_commitment(&component(0)?, cfg.aggregate_bit);
    let preset = PROFILE.threshold_preset();
    let noise = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        values.n,
        preset.search_defaults().unwrap().z as usize,
        preset.lambda()?,
    )?)?;
    ensure!(noise.smudging_bound() == &cfg.pk_generation.bounds.e_sm_bound);
    let decryptor = SynchronizedDecryptor::new(values.n, values.threshold, params.clone())?;
    let set = roster.map(|id| id as usize + 1);
    let job = CircuitJob::new(root, CircuitName::ThresholdShareDecryption)?;
    let c4_job = CircuitJob::new(root, CircuitName::DkgShareDecryption)?;
    let mut shares = Vec::new();
    let mut public = Vec::new();
    for &owner in &roster {
        let i = owner as usize;
        let c4 = fixture
            .leaves
            .iter()
            .find(|l| {
                l.role == CircuitName::DkgShareDecryption && l.inputs["recipient_id"] == owner
            })
            .context("missing C4")?;
        c4_job.execute(&c4.inputs)?;
        c4_job.prove(bb, cfg, c4)?;
        let data = &fixture.openings[i];
        let opening = Opening {
            setup: BINDING,
            domain: DOMAIN,
            roster: &roster,
            owner,
            expected_sk: &c4.outputs[0],
            expected_bundle: &c4.outputs[1],
            expected_ct: &ct_hash,
            outgoing: &data.outgoing_keys,
            incoming: &data.incoming_keys,
            sk: &fixture.aggregate_sk[i],
        };
        // fhe.rs indexes by full committee slot. Only designated keys are ever evaluated.
        let mut incoming = vec![[0; 32]; values.n];
        for (&peer, key) in roster.iter().zip(opening.incoming) {
            incoming[peer as usize] = *key;
        }
        let keys = PartyPrfKeys::from_transport(PartyPrfKeyTransport::new(
            i + 1,
            values.n,
            opening.outgoing.to_vec(),
            incoming,
        )?)?;
        let signed = fhe_math::rq::sample_uniform_coefficients_bigint(
            &noise.smudging_bound().clone().into(),
            params.degree(),
            &mut rng,
        );
        let native = decryptor.decryption_share(
            ct,
            &opening.sk.clone().into_ntt(),
            i + 1,
            &set,
            noise.wrap_signed_coefficients(&signed)?,
            &keys,
        )?;
        let (d, id, coords) = native.into_parts();
        let inputs = opening.prepare(cfg, ct, &signed, (&d, id, &coords))?;
        ensure!(opening
            .prepare(cfg, ct, &signed, (&d, id, &[1, 2]))
            .is_err());
        let mut switched = ct.clone();
        switched.switch_to_level(1)?;
        ensure!(opening
            .prepare(cfg, &switched, &signed, (&d, id, &coords))
            .is_err());
        let share_hash = compute_threshold_decryption_share_commitment(
            &CrtPolynomial::from_fhe_polynomial(&d),
            cfg.share_bit,
            params.degree(),
        );
        let leaf = Leaf {
            role: CircuitName::ThresholdShareDecryption,
            inputs,
            outputs: vec![share_hash, c0_hash.clone()],
            prove: true,
            transport_slot: None,
        };
        job.execute(&leaf.inputs)?;
        job.prove(bb, cfg, &leaf)?;
        let bytes = fs::read(job.directory.path().join("proof/public_inputs"))?;
        let signals = e3_zk_config::synchronized::public_signals::PublicSignals::decode(
            cfg, leaf.role, &bytes,
        )?;
        ensure!(
            signals.binding() == Some(BINDING)
                && signals.party_id() == Some(owner)
                && signals.dealers().as_deref() == Some(&roster[..])
        );
        for (signal, expected) in [
            (signals.sk_commitment(), opening.expected_sk),
            (signals.key_bundle(), opening.expected_bundle),
            (signals.ciphertext_commitment(), &ct_hash),
        ] {
            ensure!(
                &BigInt::from_bytes_be(Sign::Plus, &signal.context("missing C6 anchor")?)
                    == expected
            );
        }
        for (field, limb) in signals.fields()[3 + values.h..5 + values.h]
            .iter()
            .zip(opening.domain)
        {
            ensure!(BigInt::from_bytes_be(Sign::Plus, field) == BigInt::from(limb));
        }
        if i == 0 {
            for (pointer, value) in [
                ("/expected_sk", json!("0")),
                ("/expected_bundle", json!("0")),
                ("/setup/0", json!("0")),
                ("/roster/1", json!(1)),
                ("/owner", json!(1)),
                ("/expected_ct", json!("0")),
                ("/incoming/1/0", json!(opening.incoming[1][0] ^ 1)),
                ("/outgoing/2/0", json!(opening.outgoing[2][0] ^ 1)),
                (
                    "/shifted_noise/0",
                    json!(2 * u64::try_from(noise.smudging_bound())? + 1),
                ),
                // High coefficients are bound too, outside the contracted plaintext width.
                ("/d/1/63", json!(d.coefficients()[[1, 63]] ^ 1)),
            ] {
                let mut bad = leaf.inputs.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                let diagnostic = job.reject(&bad, pointer)?;
                let reason = match pointer {
                    "/expected_sk" => Some("Wrong synchronized SK opening"),
                    "/shifted_noise/0" => Some("Local noise outside signed bound"),
                    _ => None,
                };
                if let Some(reason) = reason {
                    ensure!(
                        diagnostic.contains(reason),
                        "{pointer} failed for another reason: {diagnostic}"
                    );
                }
            }
        }
        shares.push(DecryptionShare::from_parts(d, id, coords, ct)?);
        public.push(bytes);
    }
    Ok((shares, public))
}
