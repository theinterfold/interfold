// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic C1-C4 dispatch planning and sequence assignment.

use super::*;

/// A single planned threshold (C1/C2/C3) proof request: which proof, its `seq`
/// index for streaming aggregation, and the [`ZkRequest`] to dispatch.
pub(crate) struct ThresholdDispatchItem {
    pub(crate) kind: ThresholdProofKind,
    pub(crate) seq: usize,
    pub(crate) request: ZkRequest,
}

/// Build the deterministic, ordered set of C1/C2/C3 proof requests for a
/// `ThresholdSharePending` event. Pure: assigns the canonical `seq` indices
/// (C1=1, C2a=2, C3a[i]=3+i). Smudging requests are ignored.
pub(crate) fn plan_threshold_dispatch(
    proof_request: PkGenerationProofRequest,
    sk_share_computation_request: ShareComputationProofRequest,
    sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
) -> Vec<ThresholdDispatchItem> {
    let mut items = Vec::with_capacity(2 + sk_share_encryption_requests.len());

    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::PkGeneration,
        seq: 1,
        request: ZkRequest::PkGeneration(proof_request),
    });
    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::SkShareComputation,
        seq: 2,
        request: ZkRequest::ShareComputation(sk_share_computation_request),
    });

    for (i, req) in sk_share_encryption_requests.into_iter().enumerate() {
        let kind = ThresholdProofKind::SkShareEncryption {
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
        };
        items.push(ThresholdDispatchItem {
            kind,
            seq: 3 + i,
            request: ZkRequest::ShareEncryption(req),
        });
    }

    items
}

/// A single planned C4 (DkgShareDecryption) proof request.
pub(crate) struct DecryptionDispatchItem {
    pub(crate) kind: DecryptionProofKind,
    pub(crate) seq: usize,
    pub(crate) request: ZkRequest,
}

/// Build the ordered set of C4 proof requests (SecretKey then SmudgingNoise[i]).
/// `c4_base_seq` is the streaming-aggregation `seq` of the C4a (SecretKey) proof;
/// each C4b proof follows at `c4_base_seq + 1 + esi_idx`.
pub(crate) fn plan_decryption_dispatch(
    sk_request: DkgShareDecryptionProofRequest,
    esm_requests: Vec<DkgShareDecryptionProofRequest>,
    c4_base_seq: usize,
) -> Vec<DecryptionDispatchItem> {
    let mut items = Vec::with_capacity(1 + esm_requests.len());
    items.push(DecryptionDispatchItem {
        kind: DecryptionProofKind::SecretKey,
        seq: c4_base_seq,
        request: ZkRequest::DkgShareDecryption(sk_request),
    });
    let _ = esm_requests;
    items
}
