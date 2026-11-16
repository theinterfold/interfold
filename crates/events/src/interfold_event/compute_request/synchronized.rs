// SPDX-License-Identifier: LGPL-3.0-only

//! Local synchronized join work, not peer authority or the SS folding graph.

use crate::{Proof, SynchronizedProofContext, SynchronizedSetupAnchors};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvProfile;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedDkgProofRequest {
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
    pub context: SynchronizedProofContext,
    pub job: SynchronizedDkgProofJob,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SynchronizedDkgProofJob {
    Dealer {
        c1: Proof,
        c2: Proof,
        c3: Vec<Proof>,
    },
    Recipient {
        c0: Proof,
        own_c2: Proof,
        c4: Proof,
        dealers: Vec<Proof>,
        /// Independently admitted C1/C4/batch expectations, never decoded from the candidate.
        expected: SynchronizedSetupAnchors,
    },
    Publication {
        recipients: Vec<Proof>,
        c5: Proof,
        /// Independent native PK and admitted setup rows in selected H order.
        expected: SynchronizedPublicationExpectation,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SynchronizedPublicationExpectation {
    pub dealers: Vec<u32>,
    pub threshold_keys: Vec<[u8; 32]>,
    pub dealer_batch: [u8; 32],
    pub sk_commitments: Vec<[u8; 32]>,
    pub key_bundles: Vec<[u8; 32]>,
    pub public_key: ArcBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SynchronizedDkgProofResponse {
    Dealer {
        proof: Proof,
    },
    Recipient {
        proof: Proof,
        setup: SynchronizedSetupAnchors,
    },
    Publication {
        proof: Proof,
    },
}
