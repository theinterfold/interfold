// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    IBfvDecryptionVerifierRoute
} from "../verifiers/bfv/BfvDecryptionVerifierRouter.sol";
import { IBfvPkVerifierRoute } from "../verifiers/bfv/BfvPkVerifierRouter.sol";

contract MockBfvPkVerifierRoute is IBfvPkVerifierRoute {
    error UnexpectedContext();

    uint256 public immutable override h;
    bytes32 public immutable override expectedNodesFoldKeyHash;
    bytes32 public immutable override expectedC5KeyHash;
    bool private immutable result;
    bool private checkContext;
    uint256 private expectedE3Id;
    uint256 private expectedCommitteeRoot;
    bytes32 private expectedSortedNodesHash;
    bytes32 private expectedPkCommitment;
    bytes32 private expectedCommitteeHash;
    bytes32 private expectedProofHash;

    constructor(
        uint256 _h,
        bytes32 _expectedNodesFoldKeyHash,
        bytes32 _expectedC5KeyHash,
        bool _result
    ) {
        h = _h;
        expectedNodesFoldKeyHash = _expectedNodesFoldKeyHash;
        expectedC5KeyHash = _expectedC5KeyHash;
        result = _result;
    }

    function setExpectedContext(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external {
        expectedE3Id = e3Id;
        expectedCommitteeRoot = committeeRoot;
        expectedSortedNodesHash = keccak256(abi.encode(sortedNodes));
        expectedPkCommitment = pkCommitment;
        expectedCommitteeHash = committeeHash;
        expectedProofHash = keccak256(proof);
        checkContext = true;
    }

    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view override returns (bool success) {
        if (
            checkContext &&
            (e3Id != expectedE3Id ||
                committeeRoot != expectedCommitteeRoot ||
                keccak256(abi.encode(sortedNodes)) != expectedSortedNodesHash ||
                pkCommitment != expectedPkCommitment ||
                committeeHash != expectedCommitteeHash ||
                keccak256(proof) != expectedProofHash)
        ) revert UnexpectedContext();
        success = result;
    }
}

contract MockBfvDecryptionVerifierRoute is IBfvDecryptionVerifierRoute {
    error UnexpectedContext();

    uint256 public immutable override threshold;
    bytes32 public immutable override expectedC6FoldKeyHash;
    bytes32 public immutable override expectedC7KeyHash;
    bool private immutable result;
    bool private checkContext;
    uint256 private expectedE3Id;
    bytes32 private expectedDecryptionDomain;
    bytes32 private expectedPlaintextOutputHash;
    bytes32 private expectedCommitteeHash;
    bytes32 private expectedCiphertextCommitment;
    bytes32 private expectedProofHash;

    constructor(
        uint256 _threshold,
        bytes32 _expectedC6FoldKeyHash,
        bytes32 _expectedC7KeyHash,
        bool _result
    ) {
        threshold = _threshold;
        expectedC6FoldKeyHash = _expectedC6FoldKeyHash;
        expectedC7KeyHash = _expectedC7KeyHash;
        result = _result;
    }

    function setExpectedContext(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external {
        expectedE3Id = e3Id;
        expectedDecryptionDomain = decryptionDomain;
        expectedPlaintextOutputHash = plaintextOutputHash;
        expectedCommitteeHash = committeeHash;
        expectedCiphertextCommitment = ciphertextCommitment;
        expectedProofHash = keccak256(proof);
        checkContext = true;
    }

    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view override returns (bool success) {
        if (
            checkContext &&
            (e3Id != expectedE3Id ||
                decryptionDomain != expectedDecryptionDomain ||
                plaintextOutputHash != expectedPlaintextOutputHash ||
                committeeHash != expectedCommitteeHash ||
                ciphertextCommitment != expectedCiphertextCommitment ||
                keccak256(proof) != expectedProofHash)
        ) revert UnexpectedContext();
        success = result;
    }
}
