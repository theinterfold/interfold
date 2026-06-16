// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure DKG phase state machine for the threshold keyshare flow.
//!
//! This module owns the persisted [`ThresholdKeyshareState`], the per-phase
//! state data, the [`KeyshareState`] phase enum and all transition validation.
//! It contains NO actix, persistence, bus or timer dependencies — only plain
//! synchronous data and transition logic, which makes it directly unit-testable.

use anyhow::{anyhow, Result};
use e3_crypto::SensitiveBytes;
use e3_events::{CiphernodeSelected, E3id, EncryptionKey, PartyId, SignedProofPayload};
use e3_trbfv::{
    shares::{Encrypted, SharedSecret},
    TrBFVConfig,
};
use e3_utils::utility_types::ArcBytes;
use std::{
    collections::{BTreeSet, HashSet},
    mem,
    sync::Arc,
};

use crate::domain::timeout_policy::now_unix_secs;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CollectingEncryptionKeysData {
    pub(crate) sk_bfv: SensitiveBytes,
    pub(crate) pk_bfv: ArcBytes,
    pub(crate) ciphernode_selected: CiphernodeSelected,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProofRequestData {
    pub pk0_share_raw: ArcBytes,
    pub sk_raw: SensitiveBytes,
    pub eek_raw: SensitiveBytes,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeneratingThresholdShareData {
    pub(crate) pk_share: Option<ArcBytes>,
    pub(crate) sk_sss: Option<Encrypted<SharedSecret>>,
    pub(crate) esi_sss: Option<Vec<Encrypted<SharedSecret>>>,
    pub(crate) e_sm_raw: Option<SensitiveBytes>,
    pub(crate) sk_bfv: SensitiveBytes,
    pub(crate) pk_bfv: ArcBytes,
    pub(crate) collected_encryption_keys: Vec<Arc<EncryptionKey>>,
    pub(crate) ciphernode_selected: Option<CiphernodeSelected>,
    pub(crate) proof_request_data: Option<ProofRequestData>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AggregatingDecryptionKey {
    pub(crate) pk_share: ArcBytes,
    pub(crate) sk_bfv: SensitiveBytes,
    /// Bincode-serialised `Vec<Vec<u64>>` of shape `[L][N]` — own party's plaintext sk
    /// share row per modulus. Used by C4a in lieu of self-encryption.
    pub(crate) own_sk_share_raw: SensitiveBytes,
    /// One bincode-serialised `Vec<Vec<u64>>` per smudging-noise (esi). Used by C4b.
    pub(crate) own_esi_shares_raw: Vec<SensitiveBytes>,
    pub(crate) signed_pk_generation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    pub(crate) signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReadyForDecryption {
    pub(crate) pk_share: ArcBytes,
    pub(crate) sk_poly_sum: SensitiveBytes,
    pub(crate) es_poly_sum: Vec<SensitiveBytes>,
    pub(crate) signed_pk_generation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    pub(crate) signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Decrypting {
    pub(crate) pk_share: ArcBytes,
    pub(crate) sk_poly_sum: SensitiveBytes,
    pub(crate) es_poly_sum: Vec<SensitiveBytes>,
    /// Ciphertext bytes from CiphertextOutputPublished, needed for C6 proof generation.
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) signed_pk_generation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    pub(crate) signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeneratingDecryptionProof {
    pub(crate) pk_share: ArcBytes,
    pub(crate) decryption_share: Vec<ArcBytes>,
    pub(crate) signed_pk_generation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_e_sm_share_computation_proof: Option<SignedProofPayload>,
    pub(crate) signed_sk_share_encryption_proofs: Vec<SignedProofPayload>,
    pub(crate) signed_e_sm_share_encryption_proofs: Vec<SignedProofPayload>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum KeyshareState {
    // Before anything
    Init,
    // Collecting BFV encryption keys from all parties
    CollectingEncryptionKeys(CollectingEncryptionKeysData),
    // Generating TrBFV share material
    GeneratingThresholdShare(GeneratingThresholdShareData),
    // Collecting remaining TrBFV shares to aggregate decryption key
    AggregatingDecryptionKey(AggregatingDecryptionKey),
    // Awaiting decryption
    ReadyForDecryption(ReadyForDecryption),
    // Decrypting something
    Decrypting(Decrypting),
    // Generating C6 proof of correct decryption
    GeneratingDecryptionProof(GeneratingDecryptionProof),
    // Finished
    Completed,
}

impl KeyshareState {
    pub fn next(self: &KeyshareState, new_state: KeyshareState) -> Result<KeyshareState> {
        use KeyshareState as K;
        // The following can be used to check that we are transitioning to a valid state
        let valid = {
            // If we are in the same branch the new state is valid
            if mem::discriminant(self) == mem::discriminant(&new_state) {
                true
            } else {
                matches!(
                    (self, &new_state),
                    (K::Init, K::CollectingEncryptionKeys(_))
                        | (
                            K::CollectingEncryptionKeys(_),
                            K::GeneratingThresholdShare(_)
                        )
                        | (
                            K::GeneratingThresholdShare(_),
                            K::AggregatingDecryptionKey(_)
                        )
                        | (K::AggregatingDecryptionKey(_), K::ReadyForDecryption(_))
                        | (K::ReadyForDecryption(_), K::Decrypting(_))
                        | (K::Decrypting(_), K::GeneratingDecryptionProof(_))
                        | (K::GeneratingDecryptionProof(_), K::Completed)
                )
            }
        };

        if valid {
            Ok(new_state)
        } else {
            Err(anyhow!(
                "Bad state transition {:?} -> {:?}",
                self.variant_name(),
                new_state.variant_name()
            ))
        }
    }
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Init => "Init",
            Self::CollectingEncryptionKeys(_) => "CollectingEncryptionKeys",
            Self::GeneratingThresholdShare(_) => "GeneratingThresholdShare",
            Self::AggregatingDecryptionKey(_) => "AggregatingDecryptionKey",
            Self::ReadyForDecryption(_) => "ReadyForDecryption",
            Self::Decrypting(_) => "Decrypting",
            Self::GeneratingDecryptionProof(_) => "GeneratingDecryptionProof",
            Self::Completed => "Completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdKeyshareState {
    pub e3_id: E3id,
    pub address: String,
    pub party_id: PartyId,
    pub state: KeyshareState,
    pub threshold_m: u64,
    pub threshold_n: u64,
    pub params: ArcBytes,
    /// Aggregated public key bytes, captured from PublicKeyAggregated event for C6 proof.
    pub aggregated_pk: Option<ArcBytes>,
    pub expelled_parties: HashSet<u64>,
    /// Honest party IDs in deterministic ascending order (`BTreeSet` guarantees this).
    /// Downstream proof circuits index parties by position in this sorted set.
    pub honest_parties: Option<BTreeSet<u64>>,
    pub dkg_started_at_unix_secs: Option<u64>,
    pub proof_aggregation_enabled: bool,
    /// Set once `KeyshareCreated` has actually been published from an authorized
    /// path (after C4 honest-set verification, the no-C4-proofs path, or the
    /// sole-honest fast path). `ReadyForDecryption` is entered *before* that
    /// authorization, so resume-after-crash must only re-publish when this is set;
    /// otherwise it could emit a keyshare that never passed C4 filtering.
    pub keyshare_published: bool,
}

impl ThresholdKeyshareState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        e3_id: E3id,
        party_id: PartyId,
        state: KeyshareState,
        threshold_m: u64,
        threshold_n: u64,
        params: ArcBytes,
        address: String,
        proof_aggregation_enabled: bool,
    ) -> Self {
        Self {
            e3_id,
            address,
            party_id,
            state,
            threshold_m,
            threshold_n,
            params,
            aggregated_pk: None,
            expelled_parties: HashSet::new(),
            honest_parties: None,
            dkg_started_at_unix_secs: Some(now_unix_secs()),
            proof_aggregation_enabled,
            keyshare_published: false,
        }
    }

    /// Return a valid Self based on a new state struct.
    pub fn new_state(self, new_state: KeyshareState) -> Result<Self> {
        Ok(ThresholdKeyshareState {
            state: self.state.next(new_state)?,
            ..self
        })
    }

    pub fn get_trbfv_config(&self) -> TrBFVConfig {
        TrBFVConfig::new(self.params.clone(), self.threshold_n, self.threshold_m)
    }

    pub fn get_e3_id(&self) -> &E3id {
        &self.e3_id
    }

    pub fn get_party_id(&self) -> PartyId {
        self.party_id
    }

    pub fn get_threshold_m(&self) -> u64 {
        self.threshold_m
    }

    pub fn get_threshold_n(&self) -> u64 {
        self.threshold_n
    }

    pub fn get_params(&self) -> &ArcBytes {
        &self.params
    }

    pub fn get_address(&self) -> &str {
        &self.address
    }

    pub fn variant_name(&self) -> &str {
        self.state.variant_name()
    }
}

impl TryInto<CollectingEncryptionKeysData> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<CollectingEncryptionKeysData, Self::Error> {
        match self.state {
            KeyshareState::CollectingEncryptionKeys(s) => Ok(s),
            _ => Err(anyhow!("Invalid state: expected CollectingEncryptionKeys")),
        }
    }
}

impl TryInto<GeneratingThresholdShareData> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<GeneratingThresholdShareData, Self::Error> {
        match self.state {
            KeyshareState::GeneratingThresholdShare(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<AggregatingDecryptionKey> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<AggregatingDecryptionKey, Self::Error> {
        match self.state {
            KeyshareState::AggregatingDecryptionKey(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<ReadyForDecryption> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<ReadyForDecryption, Self::Error> {
        match self.state {
            KeyshareState::ReadyForDecryption(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<Decrypting> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<Decrypting, Self::Error> {
        match self.state {
            KeyshareState::Decrypting(s) => Ok(s),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

impl TryInto<GeneratingDecryptionProof> for ThresholdKeyshareState {
    type Error = anyhow::Error;
    fn try_into(self) -> std::result::Result<GeneratingDecryptionProof, Self::Error> {
        match self.state {
            KeyshareState::GeneratingDecryptionProof(s) => Ok(s),
            _ => Err(anyhow!("Invalid state: expected GeneratingDecryptionProof")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::E3id;

    fn arc(bytes: &[u8]) -> ArcBytes {
        ArcBytes::from_bytes(bytes)
    }

    fn base_state(state: KeyshareState) -> ThresholdKeyshareState {
        ThresholdKeyshareState::new(
            E3id::new("42", 1),
            0,
            state,
            1,
            3,
            arc(b"params"),
            "0xabc".to_string(),
            true,
        )
    }

    #[test]
    fn new_initialises_defaults_and_records_dkg_start() {
        let s = base_state(KeyshareState::Init);
        assert_eq!(s.variant_name(), "Init");
        assert!(s.aggregated_pk.is_none());
        assert!(s.expelled_parties.is_empty());
        assert!(s.honest_parties.is_none());
        assert!(s.dkg_started_at_unix_secs.is_some());
        assert!(s.proof_aggregation_enabled);
        assert_eq!(s.get_threshold_m(), 1);
        assert_eq!(s.get_threshold_n(), 3);
        assert_eq!(s.get_party_id(), 0);
        assert_eq!(s.get_address(), "0xabc");
    }

    #[test]
    fn same_branch_transition_is_always_valid() {
        // Re-entering the same phase variant must be accepted (idempotent mutations).
        let a = KeyshareState::AggregatingDecryptionKey(adk());
        let b = KeyshareState::AggregatingDecryptionKey(adk());
        assert!(a.next(b).is_ok());
    }

    #[test]
    fn full_happy_path_transitions_in_order() {
        let order = [
            KeyshareState::Init,
            KeyshareState::CollectingEncryptionKeys(cek()),
            KeyshareState::GeneratingThresholdShare(gts()),
            KeyshareState::AggregatingDecryptionKey(adk()),
            KeyshareState::ReadyForDecryption(rfd()),
            KeyshareState::Decrypting(decrypting()),
            KeyshareState::GeneratingDecryptionProof(gdp()),
            KeyshareState::Completed,
        ];
        for pair in order.windows(2) {
            assert!(
                pair[0].next(pair[1].clone()).is_ok(),
                "expected {} -> {} to be valid",
                pair[0].variant_name(),
                pair[1].variant_name()
            );
        }
    }

    #[test]
    fn skipping_a_phase_is_rejected() {
        let init = KeyshareState::Init;
        // Init must go to CollectingEncryptionKeys, not straight to aggregation.
        assert!(init
            .next(KeyshareState::AggregatingDecryptionKey(adk()))
            .is_err());
    }

    #[test]
    fn backwards_transition_is_rejected() {
        let completed = KeyshareState::Completed;
        assert!(completed.next(KeyshareState::Init).is_err());
    }

    #[test]
    fn new_state_preserves_metadata_and_advances_phase() {
        let s = base_state(KeyshareState::Init);
        let next = s
            .clone()
            .new_state(KeyshareState::CollectingEncryptionKeys(cek()))
            .expect("valid transition");
        assert_eq!(next.variant_name(), "CollectingEncryptionKeys");
        assert_eq!(next.e3_id, s.e3_id);
        assert_eq!(next.party_id, s.party_id);
        assert_eq!(next.threshold_m, s.threshold_m);
        assert_eq!(next.threshold_n, s.threshold_n);
    }

    #[test]
    fn new_state_rejects_illegal_transition() {
        let s = base_state(KeyshareState::Init);
        assert!(s.new_state(KeyshareState::Completed).is_err());
    }

    // ---- builders for phase data (minimal, transition logic ignores contents) ----

    fn sens() -> SensitiveBytes {
        SensitiveBytes::from_encrypted(&[])
    }

    fn cek() -> CollectingEncryptionKeysData {
        CollectingEncryptionKeysData {
            sk_bfv: sens(),
            pk_bfv: arc(b"pk"),
            ciphernode_selected: CiphernodeSelected::default(),
        }
    }

    fn gts() -> GeneratingThresholdShareData {
        GeneratingThresholdShareData {
            pk_share: None,
            sk_sss: None,
            esi_sss: None,
            e_sm_raw: None,
            sk_bfv: sens(),
            pk_bfv: arc(b"pk"),
            collected_encryption_keys: Vec::new(),
            ciphernode_selected: None,
            proof_request_data: None,
        }
    }

    fn adk() -> AggregatingDecryptionKey {
        AggregatingDecryptionKey {
            pk_share: arc(b"pk"),
            sk_bfv: sens(),
            own_sk_share_raw: sens(),
            own_esi_shares_raw: Vec::new(),
            signed_pk_generation_proof: None,
            signed_sk_share_computation_proof: None,
            signed_e_sm_share_computation_proof: None,
            signed_sk_share_encryption_proofs: Vec::new(),
            signed_e_sm_share_encryption_proofs: Vec::new(),
        }
    }

    fn rfd() -> ReadyForDecryption {
        ReadyForDecryption {
            pk_share: arc(b"pk"),
            sk_poly_sum: sens(),
            es_poly_sum: Vec::new(),
            signed_pk_generation_proof: None,
            signed_sk_share_computation_proof: None,
            signed_e_sm_share_computation_proof: None,
            signed_sk_share_encryption_proofs: Vec::new(),
            signed_e_sm_share_encryption_proofs: Vec::new(),
        }
    }

    fn decrypting() -> Decrypting {
        Decrypting {
            pk_share: arc(b"pk"),
            sk_poly_sum: sens(),
            es_poly_sum: Vec::new(),
            ciphertext_output: Vec::new(),
            signed_pk_generation_proof: None,
            signed_sk_share_computation_proof: None,
            signed_e_sm_share_computation_proof: None,
            signed_sk_share_encryption_proofs: Vec::new(),
            signed_e_sm_share_encryption_proofs: Vec::new(),
        }
    }

    fn gdp() -> GeneratingDecryptionProof {
        GeneratingDecryptionProof {
            pk_share: arc(b"pk"),
            decryption_share: Vec::new(),
            signed_pk_generation_proof: None,
            signed_sk_share_computation_proof: None,
            signed_e_sm_share_computation_proof: None,
            signed_sk_share_encryption_proofs: Vec::new(),
            signed_e_sm_share_encryption_proofs: Vec::new(),
        }
    }
}
