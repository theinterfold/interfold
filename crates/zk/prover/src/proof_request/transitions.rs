// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic C1-C4 dispatch planning and sequence assignment.

use super::*;
use crate::utils::{proves_c1, C1_SEQ};

/// A single planned threshold (C1/C2/C3) proof request: which proof, its `seq`
/// index for streaming aggregation, and the [`ZkRequest`] to dispatch.
pub(crate) struct ThresholdDispatchItem {
    pub(crate) kind: ThresholdProofKind,
    pub(crate) seq: usize,
    pub(crate) request: ZkRequest,
}

/// Build the deterministic, ordered set of C1/C2/C3 proof requests for a
/// `ThresholdSharePending` event. Pure: assigns the canonical `seq` indices
/// (C1=1, C2a=2, C2b=3, C3a[i]=4+i, C3b[j]=4+sk_count+j) and wraps each request.
/// The l-BFV path proves no C1, so its plan starts at C2a and leaves `seq` 1 unused.
pub(crate) fn plan_threshold_dispatch(
    proof_request: PkGenerationProofRequest,
    sk_share_computation_request: ShareComputationProofRequest,
    e_sm_share_computation_request: Option<ShareComputationProofRequest>,
    sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    e_sm_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
) -> anyhow::Result<Vec<ThresholdDispatchItem>> {
    let has_smudging = proof_request.params_profile.protocol()
        == e3_fhe_params::BfvDecryptionProtocol::SecretShared;
    anyhow::ensure!(
        has_smudging == e_sm_share_computation_request.is_some()
            && (has_smudging || e_sm_share_encryption_requests.is_empty()),
        "threshold proof plan does not match the selected protocol"
    );
    let sk_enc_count = sk_share_encryption_requests.len();
    let c3_start = 3 + usize::from(has_smudging);
    let mut items =
        Vec::with_capacity(c3_start - 1 + sk_enc_count + e_sm_share_encryption_requests.len());

    if proves_c1(proof_request.params_profile) {
        items.push(ThresholdDispatchItem {
            kind: ThresholdProofKind::PkGeneration,
            seq: C1_SEQ,
            request: ZkRequest::PkGeneration(proof_request),
        });
    }
    items.push(ThresholdDispatchItem {
        kind: ThresholdProofKind::SkShareComputation,
        seq: 2,
        request: ZkRequest::ShareComputation(sk_share_computation_request),
    });
    if let Some(request) = e_sm_share_computation_request {
        items.push(ThresholdDispatchItem {
            kind: ThresholdProofKind::ESmShareComputation,
            seq: 3,
            request: ZkRequest::ShareComputation(request),
        });
    }

    for (i, req) in sk_share_encryption_requests.into_iter().enumerate() {
        let kind = ThresholdProofKind::SkShareEncryption {
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
        };
        items.push(ThresholdDispatchItem {
            kind,
            seq: c3_start + i,
            request: ZkRequest::ShareEncryption(req),
        });
    }

    for (j, req) in e_sm_share_encryption_requests.into_iter().enumerate() {
        let kind = ThresholdProofKind::ESmShareEncryption {
            esi_index: req.esi_index,
            recipient_party_id: req.recipient_party_id,
            row_index: req.row_index,
        };
        items.push(ThresholdDispatchItem {
            kind,
            seq: c3_start + sk_enc_count + j,
            request: ZkRequest::ShareEncryption(req),
        });
    }

    Ok(items)
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
///
/// Every C4 proof of this node decrypts its own share row, so `recipient_party_id` is this node's
/// party ID. An l-BFV E3 names it in the request, because its chunked circuit commits under the
/// recipient's row. A trBFV E3 keeps the request that earlier releases stored.
pub(crate) fn plan_decryption_dispatch(
    sk_request: DkgShareDecryptionProofRequest,
    esm_requests: Vec<DkgShareDecryptionProofRequest>,
    recipient_party_id: u64,
    c4_base_seq: usize,
) -> Vec<DecryptionDispatchItem> {
    let request_for = |request: DkgShareDecryptionProofRequest| {
        if e3_fhe_params::is_lbfv_path(request.params_profile.threshold_preset()) {
            ZkRequest::LbfvDkgShareDecryption(LbfvDkgShareDecryptionProofRequest {
                request,
                recipient_party_id,
            })
        } else {
            ZkRequest::DkgShareDecryption(request)
        }
    };
    let mut items = Vec::with_capacity(1 + esm_requests.len());
    items.push(DecryptionDispatchItem {
        kind: DecryptionProofKind::SecretKey,
        seq: c4_base_seq,
        request: request_for(sk_request),
    });
    for (esi_idx, esm_req) in esm_requests.into_iter().enumerate() {
        items.push(DecryptionDispatchItem {
            kind: DecryptionProofKind::SmudgingNoise { esi_idx },
            seq: c4_base_seq + 1 + esi_idx,
            request: request_for(esm_req),
        });
    }
    items
}
