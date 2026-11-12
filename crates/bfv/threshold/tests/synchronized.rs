// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::Result;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{create_deterministic_crp_from_default_seed, BfvProfile};
use e3_trbfv::{
    shares::{BfvEncryptedShare, ShamirShare},
    synchronized::{
        assemble_party_keys, create_share, pack_key, reconstruct, select_designated_set, PrfKey,
    },
};
use fhe::{
    bfv::{Encoding, Plaintext, PublicKey, SecretKey},
    mbfv::{AggregateIter, PublicKeyShare},
    trbfv::{
        ShareManager, SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator, SynchronizedDecryptor,
    },
};
use fhe_math::rq::{Ntt, Poly};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use zeroize::{Zeroize, Zeroizing};

const PROFILE: BfvProfile = BfvProfile::SyncDecInsecure64;

#[test]
fn native_sync_dkg_transport_and_non_prefix_reconstruction() -> Result<()> {
    let mut rng = ChaCha8Rng::seed_from_u64(2456);
    let committee = CiphernodesCommitteeSize::Minimum;
    let values = committee.values();
    let (params, transport) = PROFILE.build_pair()?;
    let mut manager = ShareManager::new(values.n, values.threshold, params.clone())?;
    let decryptor = SynchronizedDecryptor::new(values.n, values.threshold, params.clone())?;
    let roster = [0, 2];
    let designated = select_designated_set(&roster, committee)?;
    assert_eq!(designated, [0, 2]);

    let keys: Vec<Vec<_>> = (0..values.n)
        .map(|_| {
            (0..values.n)
                .map(|_| PrfKey::random(PROFILE, &mut rng))
                .collect()
        })
        .collect::<Result<_>>()?;
    let recipient_secrets: Vec<_> = (0..values.n)
        .map(|_| SecretKey::random(&transport, &mut rng))
        .collect();
    let recipient_public: Vec<_> = recipient_secrets
        .iter()
        .map(|sk| PublicKey::new(sk, &mut rng))
        .collect();

    let crp = create_deterministic_crp_from_default_seed(&params);
    let mut public_shares = Vec::new();
    let mut collected: Vec<Vec<Array2<u64>>> = vec![Vec::new(); values.n];
    let mut received = vec![vec![PrfKey::from_bytes(PROFILE, [0; 32])?; values.n]; values.n];
    for dealer in roster {
        let secret = SecretKey::random(&params, &mut rng);
        public_shares.push(PublicKeyShare::new(&secret, crp.clone(), &mut rng)?);
        let poly = manager.coeffs_to_poly_level0(secret.coeffs.as_ref())?;
        let mut dealt = manager.generate_secret_shares_from_poly(poly, &mut rng)?;
        for recipient in 0..values.n {
            let share = ShamirShare::new(Array2::from_shape_fn(
                (params.moduli().len(), params.degree()),
                |(limb, coefficient)| dealt[limb][[recipient, coefficient]],
            ));
            let packed = pack_key(PROFILE, &share, &keys[dealer as usize][recipient])?;
            let (encrypted, _) = BfvEncryptedShare::encrypt_extended(
                &packed,
                &recipient_public[recipient],
                &transport,
                &mut rng,
            )?;
            let opened =
                encrypted.decrypt(&recipient_secrets[recipient], &transport, params.degree())?;
            let (unpacked, key) = e3_trbfv::synchronized::unpack_key(PROFILE, &opened)?;
            assert_eq!(share, unpacked);
            assert_eq!(key.as_bytes(), keys[dealer as usize][recipient].as_bytes());
            received[recipient][dealer as usize] = key;
            collected[recipient].push(unpacked.view().to_owned());
        }
        for row in &mut dealt {
            row.iter_mut().for_each(Zeroize::zeroize);
        }
    }
    let public: PublicKey = public_shares.into_iter().aggregate()?;
    let secrets: Vec<Zeroizing<Poly<Ntt>>> = collected
        .iter_mut()
        .map(|rows| {
            let poly = manager.aggregate_collected_shares(rows)?;
            for row in rows {
                row.iter_mut().for_each(Zeroize::zeroize);
            }
            Ok(Zeroizing::new(poly.into_ntt()))
        })
        .collect::<Result<_>>()?;
    let party_keys = (0..values.n)
        .map(|party| assemble_party_keys(PROFILE, party as u64, &keys[party], &received[party]))
        .collect::<Result<Vec<_>>>()?;
    let noise = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        values.n,
        1,
        PROFILE.threshold_preset().lambda()?,
    )?)?;
    let expected: Vec<u64> = (0..50)
        .map(|index| if index % 3 == 0 { 0 } else { 7 * index })
        .collect();
    let plaintext = Plaintext::try_encode(&expected, Encoding::poly(), &params)?;
    let ciphertext = public.try_encrypt(&plaintext, &mut rng)?;
    let mut shares = Vec::new();
    for &party in &designated {
        shares.push(create_share(
            &decryptor,
            party,
            &designated,
            &ciphertext,
            &secrets[party as usize],
            noise.generate(&mut rng)?,
            &party_keys[party as usize],
        )?);
    }
    shares.reverse();
    let decoded = reconstruct(&decryptor, &designated, &ciphertext, shares.clone())?;
    let decoded = Vec::<u64>::try_decode(&decoded, Encoding::poly())?;
    assert_eq!(&decoded[..expected.len()], expected);
    assert!(decoded[expected.len()..].iter().all(|&value| value == 0));

    assert!(reconstruct(&decryptor, &designated, &ciphertext, shares[..1].to_vec()).is_err());
    assert!(reconstruct(
        &decryptor,
        &designated,
        &ciphertext,
        vec![shares[0].clone(); 2]
    )
    .is_err());
    assert!(reconstruct(&decryptor, &[0, 1], &ciphertext, shares.clone()).is_err());
    let other = public.try_encrypt(&plaintext, &mut rng)?;
    assert!(reconstruct(&decryptor, &designated, &other, shares).is_err());
    let mut wrong_level = ciphertext.clone();
    wrong_level.switch_down()?;
    assert!(create_share(
        &decryptor,
        0,
        &designated,
        &wrong_level,
        &secrets[0],
        noise.generate(&mut rng)?,
        &party_keys[0]
    )
    .is_err());
    for invalid in [&[0, 0][..], &[2, 0], &[0, 3], &[0], &[0, 1, 2]] {
        assert!(create_share(
            &decryptor,
            0,
            invalid,
            &ciphertext,
            &secrets[0],
            noise.generate(&mut rng)?,
            &party_keys[0]
        )
        .is_err());
    }
    assert!(create_share(
        &decryptor,
        1,
        &designated,
        &ciphertext,
        &secrets[1],
        noise.generate(&mut rng)?,
        &party_keys[1]
    )
    .is_err());
    assert!(create_share(
        &decryptor,
        0,
        &designated,
        &ciphertext,
        &secrets[0],
        noise.generate(&mut rng)?,
        &party_keys[2]
    )
    .is_err());
    assert!(!PROFILE.admission_enabled());
    Ok(())
}

#[test]
fn key_packing_is_little_endian_limb_zero_only_and_canonical() -> Result<()> {
    let (threshold, _) = PROFILE.build_pair()?;
    let share = ShamirShare::new(Array2::from_shape_fn(
        (threshold.moduli().len(), threshold.degree()),
        |(limb, _)| threshold.moduli()[limb] - 1,
    ));
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&0x8000000000000081u64.to_le_bytes());
    let key = PrfKey::from_bytes(PROFILE, bytes)?;
    let packed = pack_key(PROFILE, &share, &key)?;
    for j in 0..64 {
        let expected_bit = u64::from(j == 0 || j == 7 || j == 63);
        assert_eq!(
            packed[[0, j]],
            share[[0, j]] + expected_bit * threshold.moduli()[0]
        );
    }
    assert_eq!(packed.row(1), share.row(1));
    assert_eq!(packed.row(2), share.row(2));
    let (unpacked, recovered) = e3_trbfv::synchronized::unpack_key(PROFILE, &packed)?;
    assert_eq!(unpacked, share);
    assert_eq!(recovered.as_bytes(), key.as_bytes());
    for (limb, coefficient, value) in [
        (0, 0, 2 * threshold.moduli()[0]),
        (1, 0, threshold.moduli()[1]),
        (2, 63, u64::MAX),
    ] {
        let mut altered = packed.view().to_owned();
        altered[[limb, coefficient]] = value;
        assert!(e3_trbfv::synchronized::unpack_key(PROFILE, &ShamirShare::new(altered)).is_err());
    }
    let mut altered = share.view().to_owned();
    altered[[0, 0]] = threshold.moduli()[0];
    assert!(pack_key(PROFILE, &ShamirShare::new(altered), &key).is_err());
    assert!(pack_key(PROFILE, &ShamirShare::new(Array2::zeros((1, 64))), &key).is_err());
    assert!(pack_key(BfvProfile::SsInsecure64, &share, &key).is_err());
    bytes[8] = 1;
    assert!(PrfKey::from_bytes(PROFILE, bytes).is_err());
    Ok(())
}

#[test]
fn directed_keys_validate_owner_shape_and_test_only_width() -> Result<()> {
    let mut rng = ChaCha8Rng::seed_from_u64(2459);
    let keys = (0..3)
        .map(|_| PrfKey::random(PROFILE, &mut rng))
        .collect::<Result<Vec<_>>>()?;
    for key in &keys {
        assert!(key.as_bytes()[8..].iter().all(|&byte| byte == 0));
    }
    let party = assemble_party_keys(PROFILE, 2, &keys, &keys)?;
    assert_eq!(party.party_id(), 3);
    assert_eq!(party.committee_size(), 3);
    assert!(assemble_party_keys(PROFILE, 3, &keys, &keys).is_err());
    assert!(assemble_party_keys(PROFILE, 0, &keys, &keys[..2]).is_err());
    assert!(assemble_party_keys(PROFILE, 0, &[], &[]).is_err());
    assert!(PrfKey::random(BfvProfile::SsInsecure64, &mut rng).is_err());
    let mut key = keys[0].clone();
    key.zeroize();
    assert_eq!(key.as_bytes(), &[0; 32]);
    Ok(())
}

#[test]
fn initial_selection_validates_the_complete_published_roster() -> Result<()> {
    let small = CiphernodesCommitteeSize::Small;
    let roster: Vec<_> = (0..19).filter(|id| id % 4 != 0).collect();
    assert_eq!(roster.len(), 14);
    assert_eq!(select_designated_set(&roster, small)?, roster[..10]);
    let mut duplicate_tail = roster.clone();
    duplicate_tail[13] = duplicate_tail[12];
    assert!(select_designated_set(&duplicate_tail, small).is_err());
    let mut outside_tail = roster.clone();
    outside_tail[13] = 19;
    assert!(select_designated_set(&outside_tail, small).is_err());
    assert!(select_designated_set(&roster[..13], small).is_err());
    assert!(select_designated_set(&[2, 0], CiphernodesCommitteeSize::Minimum).is_err());
    Ok(())
}
