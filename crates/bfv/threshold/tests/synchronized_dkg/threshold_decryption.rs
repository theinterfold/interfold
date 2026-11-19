// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_zk_witness::{
    commitments::ciphertext_component_commitment, compute_threshold_decryption_share_commitment,
    encoding::fhe_poly_to_crt_centered, synchronized::threshold_decryption::Opening,
};
use fhe::trbfv::{
    DecryptionShare, PartyPrfKeyTransport, PartyPrfKeys, SmudgingBoundCalculatorConfig,
    SmudgingNoiseGenerator, SynchronizedDecryptor,
};
use fhe_traits::FheEncrypter;

#[test]
#[ignore = "requires pinned nargo and bb; proves both non-prefix C4 openings and synchronized C6 shares"]
fn native_partials_match_c4_and_c6_proofs() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let bb = check_tools(&root)?;
    let fixture = Fixture::native()?;
    let cfg = &fixture.config;
    let params = &cfg.threshold;
    let values = cfg.committee.values();
    let mut rng = ChaCha8Rng::seed_from_u64(2050);
    let pk = PublicKey::from_shares(
        DEALERS
            .map(|i| fixture.threshold_shares[i as usize].clone())
            .to_vec(),
    )?;
    let pt = Plaintext::try_encode(&[7u64, 0, 42], Encoding::poly(), params)?;
    let ct = pk.try_encrypt(&pt, &mut rng)?;
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
    let set = DEALERS.map(|id| id as usize + 1);
    let job = CircuitJob::new(&root, CircuitName::ThresholdShareDecryption)?;
    let c4_job = CircuitJob::new(&root, CircuitName::DkgShareDecryption)?;
    let mut shares = Vec::new();
    for &owner in &DEALERS {
        let i = owner as usize;
        let c4 = fixture
            .leaves
            .iter()
            .find(|l| {
                l.role == CircuitName::DkgShareDecryption && l.inputs["recipient_id"] == owner
            })
            .context("missing C4")?;
        c4_job.execute(&c4.inputs)?;
        c4_job.prove(&bb, cfg, c4)?;
        let data = &fixture.openings[i];
        let opening = Opening {
            setup: BINDING,
            domain: [0x2050, u128::MAX - 1],
            roster: &DEALERS,
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
        for (&peer, key) in DEALERS.iter().zip(opening.incoming) {
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
            &ct,
            &opening.sk.clone().into_ntt(),
            i + 1,
            &set,
            noise.wrap_signed_coefficients(&signed)?,
            &keys,
        )?;
        let (d, id, coords) = native.into_parts();
        let inputs = opening.prepare(cfg, &ct, &signed, (&d, id, &coords))?;
        ensure!(opening
            .prepare(cfg, &ct, &signed, (&d, id, &[1, 2]))
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
        job.prove(&bb, cfg, &leaf)?;
        let bytes = fs::read(job.directory.path().join("proof/public_inputs"))?;
        let signals = e3_zk_config::synchronized::public_signals::PublicSignals::decode(
            cfg, leaf.role, &bytes,
        )?;
        ensure!(
            signals.binding() == Some(BINDING)
                && signals.party_id() == Some(owner)
                && signals.dealers().as_deref() == Some(&DEALERS[..])
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
                job.reject(&bad, pointer)?;
            }
        }
        shares.push(DecryptionShare::from_parts(d, id, coords, &ct)?);
    }
    ensure!(decryptor.decrypt_from_shares(&shares, &ct)? == pt);
    Ok(())
}
