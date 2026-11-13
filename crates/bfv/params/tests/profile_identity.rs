// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "abi-encoding")]

use alloy_primitives::B256;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{
    bfv_profile_crypto_config_id, encode_bfv_params, BfvDecryptionProtocol, BfvProfile,
    BfvProfileError,
};

/// The lookup table must hold every supported pair, and each identity must resolve only under its
/// own registry slot and committee. Admission is the caller's decision, so the disabled
/// synchronized profile resolves too.
#[test]
fn every_supported_identity_resolves_to_its_own_profile_only() {
    let mut supported = 0;
    for profile in BfvProfile::ALL {
        for committee in CiphernodesCommitteeSize::ALL {
            if !profile.supports_committee(committee) {
                continue;
            }
            supported += 1;
            let id = profile.crypto_config_id(committee).unwrap();
            assert_eq!(
                BfvProfile::from_crypto_config_id(profile.param_set(), committee, id).unwrap(),
                profile
            );
            for other in CiphernodesCommitteeSize::ALL {
                if other != committee {
                    assert!(
                        BfvProfile::from_crypto_config_id(profile.param_set(), other, id).is_err()
                    );
                }
            }
            for other in BfvProfile::ALL {
                if other.param_set() != profile.param_set() {
                    assert!(
                        BfvProfile::from_crypto_config_id(other.param_set(), committee, id)
                            .is_err()
                    );
                }
            }
        }
    }
    assert_eq!(supported, 7);

    let unknown = B256::repeat_byte(0x12);
    let error = BfvProfile::from_crypto_config_id(0, CiphernodesCommitteeSize::Minimum, unknown)
        .unwrap_err();
    assert!(
        matches!(&error, BfvProfileError::UnsupportedConfiguration(id) if *id == unknown.to_string()),
        "{error}"
    );
}

#[test]
fn profile_ids_still_match_the_published_configuration_catalogue() {
    let catalogue: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../packages/interfold-contracts/crypto-config.json"
    ))
    .unwrap();
    for row in catalogue["bfv"]["profiles"].as_array().unwrap() {
        let profile: BfvProfile = row["profile"].as_str().unwrap().parse().unwrap();
        for config in row["configurations"].as_array().unwrap() {
            let committee = config["committee"].as_str().unwrap().parse().unwrap();
            assert_eq!(
                profile.crypto_config_id(committee).unwrap().to_string(),
                config["cryptoConfigId"].as_str().unwrap()
            );
            assert_eq!(
                profile.admission_enabled(),
                config["admissionEnabled"].as_bool().unwrap()
            );
        }
    }
}

#[test]
fn profile_identity_binds_protocol_dkg_committee_statement_and_original_bytes() {
    let (threshold, dkg) = BfvProfile::SsInsecure64.build_pair().unwrap();
    let (_, synchronized_dkg) = BfvProfile::SyncDecInsecure64.build_pair().unwrap();
    let threshold = encode_bfv_params(&threshold);
    let dkg = encode_bfv_params(&dkg);
    let synchronized_dkg = encode_bfv_params(&synchronized_dkg);
    let profile = BfvProfile::SsInsecure64;
    let committee = CiphernodesCommitteeSize::Minimum;
    let identity = bfv_profile_crypto_config_id(
        profile.protocol(),
        &threshold,
        &dkg,
        committee,
        profile.statement_version(),
    );
    assert_eq!(identity, profile.crypto_config_id(committee).unwrap());
    assert_ne!(
        identity,
        bfv_profile_crypto_config_id(
            BfvDecryptionProtocol::Synchronized,
            &threshold,
            &dkg,
            committee,
            profile.statement_version(),
        )
    );
    assert_ne!(
        identity,
        bfv_profile_crypto_config_id(
            profile.protocol(),
            &threshold,
            &synchronized_dkg,
            committee,
            profile.statement_version(),
        )
    );
    assert_ne!(
        identity,
        bfv_profile_crypto_config_id(
            profile.protocol(),
            &threshold,
            &dkg,
            CiphernodesCommitteeSize::Micro,
            profile.statement_version(),
        )
    );
    assert_ne!(
        identity,
        bfv_profile_crypto_config_id(
            profile.protocol(),
            &threshold,
            &dkg,
            committee,
            "another-statement"
        )
    );
    for (threshold, dkg) in [
        ([threshold.as_slice(), &[0; 32]].concat(), dkg.clone()),
        (threshold.clone(), [dkg.as_slice(), &[0; 32]].concat()),
    ] {
        assert_ne!(
            identity,
            bfv_profile_crypto_config_id(
                profile.protocol(),
                &threshold,
                &dkg,
                committee,
                profile.statement_version(),
            )
        );
    }
    assert!(BfvProfile::SyncDecInsecure64
        .crypto_config_id(CiphernodesCommitteeSize::Small)
        .is_err());
}
