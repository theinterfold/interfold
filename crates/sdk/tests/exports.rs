// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(feature = "bfv")]
#[test]
fn bfv_exports_are_available() {
    let _ = e3_sdk::bfv_client::encode_vec_u64_to_bytes as fn(&[u64]) -> Vec<u8>;
    let _ = e3_sdk::bfv_params::BfvPreset::InsecureThreshold64;
}

#[cfg(feature = "indexer")]
#[test]
fn indexer_exports_are_available() {
    fn accepts_store<T: e3_sdk::indexer::DataStore>() {}
    accepts_store::<e3_sdk::indexer::InMemoryStore>();
}

#[cfg(feature = "evm")]
#[test]
#[allow(deprecated)]
fn preferred_and_legacy_evm_exports_are_the_same_types() {
    use e3_sdk::{evm, evm_helpers};
    use std::any::TypeId;

    assert_eq!(
        TypeId::of::<evm::contracts::E3>(),
        TypeId::of::<evm_helpers::events::E3>()
    );
    assert_eq!(
        TypeId::of::<evm::contracts::CommitteeSize>(),
        TypeId::of::<evm_helpers::contracts::CommitteeSize>()
    );
}
