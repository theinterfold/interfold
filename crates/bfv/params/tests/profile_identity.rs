// SPDX-License-Identifier: LGPL-3.0-only

#![cfg(feature = "abi-encoding")]

use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{
    bfv_profile_crypto_config_id, encode_bfv_params, BfvDecryptionProtocol, BfvProfile,
};

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
