// SPDX-License-Identifier: LGPL-3.0-only

//! Persisted inputs needed to resume interrupted threshold-keyshare effects.

use std::collections::{BTreeMap, BTreeSet};

use e3_events::{
    CiphernodeSelected, DecryptionKeyShared, DecryptionShareProofsPending, DkgCoordination,
    EncryptionKeyCreated, EventContext, Sequenced, ShareDecryptionProofPending,
    ShareVerificationComplete, ThresholdShareCreated, ThresholdSharePending, TypedEvent,
};

pub const THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION: u32 = 5;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThresholdKeyshareRecoveryState {
    pub schema_version: u32,
    pub ciphernode_selected: Option<TypedEvent<CiphernodeSelected>>,
    pub encryption_keys: BTreeMap<u64, TypedEvent<EncryptionKeyCreated>>,
    pub threshold_shares: BTreeMap<u64, TypedEvent<ThresholdShareCreated>>,
    pub collected_threshold_share_ids: Option<BTreeSet<u64>>,
    pub decryption_key_shares: BTreeMap<u64, TypedEvent<DecryptionKeyShared>>,
    pub threshold_share_pending: Option<TypedEvent<ThresholdSharePending>>,
    pub decryption_share_proofs_pending: Option<TypedEvent<DecryptionShareProofsPending>>,
    pub share_decryption_proof_pending: Option<TypedEvent<ShareDecryptionProofPending>>,
    pub share_verification_complete: Option<TypedEvent<ShareVerificationComplete>>,
    pub verified_dealer_ids: Option<BTreeSet<u64>>,
    pub decryption_verification_complete: Option<TypedEvent<ShareVerificationComplete>>,
    pub dkg_ready: Option<DkgCoordination>,
    pub ready_by_party: BTreeMap<u64, DkgCoordination>,
    pub pending_rosters: BTreeMap<u64, DkgCoordination>,
    pub dkg_roster: Option<DkgCoordination>,
    pub active_aggregator_party_id: Option<u64>,
    pub is_aggregator: bool,
    pub keyshare_publish_authorized: bool,
    pub last_ec: Option<EventContext<Sequenced>>,
}

impl Default for ThresholdKeyshareRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
            ciphernode_selected: None,
            encryption_keys: BTreeMap::new(),
            threshold_shares: BTreeMap::new(),
            collected_threshold_share_ids: None,
            decryption_key_shares: BTreeMap::new(),
            threshold_share_pending: None,
            decryption_share_proofs_pending: None,
            share_decryption_proof_pending: None,
            share_verification_complete: None,
            verified_dealer_ids: None,
            decryption_verification_complete: None,
            dkg_ready: None,
            ready_by_party: BTreeMap::new(),
            pending_rosters: BTreeMap::new(),
            dkg_roster: None,
            active_aggregator_party_id: None,
            is_aggregator: false,
            keyshare_publish_authorized: false,
            last_ec: None,
        }
    }
}
