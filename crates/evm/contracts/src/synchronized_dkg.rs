// SPDX-License-Identifier: LGPL-3.0-only

//! ABI facts for the separate synchronized publication path, not chain-authority admission.

alloy_sol_types::sol! {
    #[sol(rpc, abi)]
    #[derive(Debug, PartialEq, Eq)]
    interface ISynchronizedDkgPublication {
        struct Publication {
            bytes32 pkCommitment;
            bytes32 dealerBatch;
            uint256[] partyIds;
            bytes proof;
            bytes[] signatures;
        }

        struct Authority {
            uint8 version;
            address verifier;
            bytes32 cryptoConfigId;
            bytes32 setupBinding;
            bytes32 dealerBatch;
            bytes32 pkCommitment;
            uint256[] partyIds;
            bytes32[] thresholdPkCommits;
            bytes32[] skAggCommits;
            bytes32[] keyBundleCommits;
        }

        function publishSynchronizedCommittee(uint256 e3Id, Publication calldata publication) external;
        function getSynchronizedDkgAuthority(uint256 e3Id) external view returns (Authority memory authority);
        event SynchronizedDkgContextEstablished(
            uint256 indexed e3Id, address registry, address verifier, bytes32 cryptoConfigId
        );
        event SynchronizedDkgAuthorityPublished(uint256 indexed e3Id, Authority authority);
        error InvalidSynchronizedDkgPublication();
        error SynchronizedDkgPublicationRequired();
    }
}
