// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    ISynchronizedDkgPublication
} from "../interfaces/ISynchronizedDkgPublication.sol";

/// Standalone verifier gas uses stored public sample anchors, without timing a DKG transaction.
contract BenchmarkSynchronizedAuthority {
    mapping(uint256 => ISynchronizedDkgPublication.Authority)
        private authorities;
    mapping(uint256 => bytes32) public getCommitteeHash;

    constructor(
        uint256 id,
        bytes32 committeeHash,
        ISynchronizedDkgPublication.Authority memory authority
    ) {
        authorities[id] = authority;
        getCommitteeHash[id] = committeeHash;
    }

    function getSynchronizedDkgAuthority(
        uint256 id
    ) external view returns (ISynchronizedDkgPublication.Authority memory) {
        return authorities[id];
    }
}
