// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::canonical_key::CanonicalDkgAnchors;
use alloy::primitives::Address;
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{PublicKeyAggregated, ThresholdShareDecryptionProofRequest};
use e3_fhe_params::{BfvParamSet, BfvProfile};
use e3_utils::{ArcBytes, OrderedSet};

fn fixture() -> (E3id, CanonicalPublicKey) {
    let id = E3id::new(
        "1606938044258990275541962092341162602522202993782792835301385",
        31337,
    );
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let committee: Vec<_> = (1..=3).map(Address::repeat_byte).collect();
    let context = SynchronizedDkgContext {
        registry: Address::repeat_byte(4),
        verifying_contract: Address::repeat_byte(5),
        crypto_config_id: profile.crypto_config_id(size).unwrap().0,
    };
    let interfold_address = Address::repeat_byte(6);
    let setup_binding = DkgSetupContext {
        interfold_address,
        committee_hash: hash_committee_addresses(&committee),
        crypto_config_id: context.crypto_config_id.into(),
    }
    .hash(id.chain_id(), id.clone().try_into().unwrap())
    .0;
    (
        id,
        CanonicalPublicKey {
            pk_commitment: [1; 32],
            honest_committee: vec![committee[0], committee[2]],
            committee,
            params_profile: profile,
            committee_size: size,
            interfold_address,
            dkg_anchors: CanonicalDkgAnchors::Synchronized(SynchronizedDkgAuthority {
                version: 1,
                context,
                setup_binding,
                dealer_batch: [2; 32],
                party_ids: vec![0, 2],
                threshold_pk_commits: vec![[3; 32], [4; 32]],
                sk_agg_commits: vec![[5; 32], [6; 32]],
                key_bundle_commits: vec![[7; 32], [8; 32]],
            }),
        },
    )
}

fn authority(key: &mut CanonicalPublicKey) -> &mut SynchronizedDkgAuthority {
    let CanonicalDkgAnchors::Synchronized(authority) = &mut key.dkg_anchors else {
        panic!()
    };
    authority
}

fn remember(keys: &CanonicalPublicKeys, id: &E3id, key: &CanonicalPublicKey) -> Result<()> {
    let CanonicalDkgAnchors::Synchronized(authority) = &key.dkg_anchors else {
        panic!()
    };
    keys.remember_synchronized_context(id.clone(), authority.context)
}

#[test]
fn frozen_context_and_authority_are_immutable_and_request_bound() -> Result<()> {
    let (id, mut key) = fixture();
    let keys = CanonicalPublicKeys::default();
    assert!(keys
        .insert_synchronized_dkg_authority(id.clone(), key.clone())
        .is_err());
    remember(&keys, &id, &key)?;
    remember(&keys, &id, &key)?;
    let mut changed = authority(&mut key).context;
    changed.verifying_contract = Address::repeat_byte(7);
    assert!(keys
        .remember_synchronized_context(id.clone(), changed)
        .is_err());
    keys.insert_synchronized_dkg_authority(id.clone(), key.clone())?;
    keys.insert_synchronized_dkg_authority(id.clone(), key.clone())?;
    let original = key.clone();
    authority(&mut key).dealer_batch = [9; 32];
    assert!(keys
        .insert_synchronized_dkg_authority(id.clone(), key)
        .is_err());
    assert_eq!(keys.get(&id), Some(original.clone()));
    for other in [E3id::new("9", id.chain_id()), E3id::new(id.e3_id(), 1)] {
        remember(&keys, &other, &original)?;
        assert!(keys
            .insert_synchronized_dkg_authority(other, original.clone())
            .is_err());
    }
    keys.remove(&id);
    assert!(keys.get(&id).is_none() && keys.synchronized_context(&id).is_none());
    Ok(())
}

#[test]
fn synchronized_rows_cannot_masquerade_as_ss_or_another_roster() -> Result<()> {
    let (id, key) = fixture();
    let mutations: &[fn(&mut CanonicalPublicKey)] = &[
        |key| key.params_profile = BfvProfile::SsInsecure64,
        |key| key.committee.swap(0, 1),
        |key| key.honest_committee[1] = key.committee[1],
        |key| authority(key).party_ids = vec![0, 0],
        |key| authority(key).party_ids = vec![0, 3],
        |key| {
            authority(key).key_bundle_commits.pop();
        },
        |key| authority(key).threshold_pk_commits[0] = [255; 32],
        |key| authority(key).version = 2,
        |key| key.interfold_address = Address::repeat_byte(9),
        |key| {
            key.dkg_anchors = CanonicalDkgAnchors::SecretShared {
                sk_agg_commits: vec![[5; 32], [6; 32]],
                esm_agg_commits: vec![[7; 32], [8; 32]],
            }
        },
    ];
    for mutate in mutations {
        let keys = CanonicalPublicKeys::default();
        remember(&keys, &id, &key)?;
        let mut changed = key.clone();
        mutate(&mut changed);
        assert!(keys
            .insert_synchronized_dkg_authority(id.clone(), changed)
            .is_err());
        assert!(keys.get(&id).is_none());
        keys.insert_synchronized_dkg_authority(id.clone(), key.clone())?;
    }
    assert!(CanonicalPublicKeys::default().insert(id, key).is_err());
    Ok(())
}

#[actix::test]
async fn dormant_key_bytes_never_admit_decryption_or_ss_publication() -> Result<()> {
    let (id, mut key) = fixture();
    let params = BfvParamSet::from(key.params_profile.threshold_preset());
    let bytes = ArcBytes::from_bytes(&e3_bfv_client::client::generate_public_key(
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )?);
    key.pk_commitment = e3_bfv_client::compute_pk_commitment(
        bytes.to_vec(),
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )?;
    let keys = CanonicalPublicKeys::default();
    remember(&keys, &id, &key)?;
    keys.insert_synchronized_dkg_authority(id.clone(), key.clone())?;
    assert!(keys
        .remember_dkg_key(&id, ArcBytes::from_bytes(&[1]))
        .is_err());
    keys.remember_dkg_key(&id, bytes.clone())?;
    assert_eq!(keys.public_key(&id), Some(bytes.clone()));
    assert!(key.validate_key(&bytes).is_err());
    assert!(keys.remember_key(&id, bytes.clone()).is_err());
    assert!(!key.accepts(&PublicKeyAggregated {
        e3_id: id.clone(),
        pubkey: bytes.clone(),
        nodes: OrderedSet::new(),
        pk_commitment: key.pk_commitment,
        committee_addresses: key.committee.clone(),
        honest_committee_addresses: key.honest_committee.clone(),
        dkg_aggregator_proof: None,
        dkg_attestation_bundle: None,
    }));
    keys.remember_ciphertexts(&id, &[ArcBytes::from_bytes(&[1])])?;
    assert!(keys.decryption_domains(&id).is_none());
    let cipher = e3_crypto::Cipher::from_password("dormant-key-test").await?;
    let mut request = ThresholdShareDecryptionProofRequest {
        ciphertext_bytes: vec![],
        aggregated_pk_bytes: bytes,
        sk_poly_sum: e3_crypto::SensitiveBytes::new(vec![], &cipher)?,
        es_poly_sum: vec![],
        d_share_bytes: vec![],
        decryption_domain: key.domain(key.interfold_address),
        params_profile: key.params_profile,
        committee_size: key.committee_size,
    };
    assert!(!keys.accepts_request(&id, &request));
    assert!(keys.repair_request(&id, &mut request).is_err());
    keys.remove(&id);
    assert!(keys.public_key(&id).is_none());
    Ok(())
}
