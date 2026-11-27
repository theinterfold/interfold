// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

const OPERATION_ID_DOMAIN: &[u8] = b"interfold/lbfv/operation-id/v1";
const PUBLIC_ARTIFACT_DOMAIN: &[u8] = b"interfold/lbfv/public-artifact/v1";

/// A restart-stable identity for one l-BFV compute operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LbfvOperationId(pub [u8; 32]);

/// The l-BFV generation or proof family included in an operation identity.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LbfvOperationKind {
    GenKeyShares = 0,
    PkGeneration = 1,
    RlkGeneration = 2,
    PkAggregation = 3,
    /// RLK aggregation of one row's `d0` component.
    RlkD0Aggregation = 4,
    /// RLK aggregation of one row's `d2` component.
    RlkD2Aggregation = 5,
}

impl LbfvOperationId {
    /// Derive an operation identity from its complete semantic domain.
    pub fn new(
        session_id: [u8; 32],
        actor_party_id: u32,
        kind: LbfvOperationKind,
        row_index: Option<u32>,
        accepted_party_set_hash: Option<[u8; 32]>,
        public_artifact_digest: Option<[u8; 32]>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(OPERATION_ID_DOMAIN);
        hasher.update(session_id);
        hasher.update(actor_party_id.to_be_bytes());
        hasher.update([kind as u8]);
        update_optional_u32(&mut hasher, row_index);
        update_optional_digest(&mut hasher, accepted_party_set_hash);
        update_optional_digest(&mut hasher, public_artifact_digest);
        Self(hasher.finalize().into())
    }
}

impl fmt::Display for LbfvOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn update_optional_u32(hasher: &mut Sha256, value: Option<u32>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

fn update_optional_digest(hasher: &mut Sha256, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0]),
    }
}

/// Hash public artifact bytes for an l-BFV operation.
pub fn digest_lbfv_public_artifacts<'a>(artifacts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_ARTIFACT_DOMAIN);
    for artifact in artifacts {
        hasher.update((artifact.len() as u64).to_be_bytes());
        hasher.update(artifact);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCEPTED: [u8; 32] = [4; 32];

    fn operation_id() -> LbfvOperationId {
        LbfvOperationId::new(
            [1; 32],
            2,
            LbfvOperationKind::RlkD0Aggregation,
            Some(3),
            Some(ACCEPTED),
            Some(digest_lbfv_public_artifacts([
                &b"share-a"[..],
                &b"share-b"[..],
            ])),
        )
    }

    /// The identity survives restarts, so the bytes are pinned: SHA-256 over the domain label,
    /// the session, the big-endian party and the kind, then each optional component with its
    /// presence flag.
    #[test]
    fn operation_id_bytes_are_pinned() {
        let artifact = digest_lbfv_public_artifacts([&b"share-a"[..], &b"share-b"[..]]);
        assert_eq!(
            artifact
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "63a31033f38aef5c8a7ed76dd079424ea0c82898030bf0f14d5534b6389a3272"
        );

        let id = operation_id();
        assert_eq!(
            id.to_string(),
            "93ac72f20510d8ea60ebd20ca82fd91bffe04e5d8428950d8d2951d2c65252a0"
        );
        assert_eq!(bincode::serialize(&id).unwrap(), id.0);
    }

    #[test]
    fn operation_id_separates_each_domain_component() {
        let base = operation_id();
        let accepted = ACCEPTED;
        let artifact = digest_lbfv_public_artifacts([&b"share-a"[..], &b"share-b"[..]]);
        let variants = [
            LbfvOperationId::new(
                [9; 32],
                2,
                LbfvOperationKind::RlkD0Aggregation,
                Some(3),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                1,
                LbfvOperationKind::RlkD0Aggregation,
                Some(3),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::PkAggregation,
                Some(3),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkD2Aggregation,
                Some(3),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkD0Aggregation,
                Some(4),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkD0Aggregation,
                Some(3),
                Some([5; 32]),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkD0Aggregation,
                Some(3),
                Some(accepted),
                Some(digest_lbfv_public_artifacts([&b"other"[..]])),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkD0Aggregation,
                None,
                Some(accepted),
                Some(artifact),
            ),
        ];

        assert!(variants.into_iter().all(|variant| variant != base));
        assert_eq!(base.to_string().len(), 64);
    }
}
