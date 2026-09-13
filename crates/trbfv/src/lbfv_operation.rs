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
    RlkAggregation = 4,
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
            LbfvOperationKind::RlkAggregation,
            Some(3),
            Some(ACCEPTED),
            Some(digest_lbfv_public_artifacts([
                &b"share-a"[..],
                &b"share-b"[..],
            ])),
        )
    }

    #[test]
    fn operation_id_is_deterministic_and_serializable() {
        let first = operation_id();
        let second = operation_id();

        assert_eq!(first, second);
        assert_eq!(bincode::serialize(&first).unwrap().len(), 32);
        assert_eq!(
            bincode::deserialize::<LbfvOperationId>(&first.0).unwrap(),
            first
        );
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
                LbfvOperationKind::RlkAggregation,
                Some(3),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                1,
                LbfvOperationKind::RlkAggregation,
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
                LbfvOperationKind::RlkAggregation,
                Some(4),
                Some(accepted),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkAggregation,
                Some(3),
                Some([5; 32]),
                Some(artifact),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkAggregation,
                Some(3),
                Some(accepted),
                Some(digest_lbfv_public_artifacts([&b"other"[..]])),
            ),
            LbfvOperationId::new(
                [1; 32],
                2,
                LbfvOperationKind::RlkAggregation,
                None,
                Some(accepted),
                Some(artifact),
            ),
        ];

        assert!(variants.into_iter().all(|variant| variant != base));
        assert_eq!(base.to_string().len(), 64);
    }
}
