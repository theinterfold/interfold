// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3 } from "../../interfaces/IE3.sol";
import { ICiphernodeRegistry } from "../../interfaces/ICiphernodeRegistry.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { IInterfold } from "../../interfaces/IInterfold.sol";
import { IPkVerifier } from "../../interfaces/IPkVerifier.sol";
import { ActiveCryptoConfig } from "../../lib/ActiveCryptoConfig.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";

/// @notice Verifies the secure-16384 V2 DKG aggregator proof.
contract BfvPkVerifierV2 is IPkVerifier {
    error InvalidCircuitVerifier(address verifier);
    error InvalidRegistry(address registry);
    error InvalidVerificationKeyHash();

    uint256 public constant V2_PUBLIC_INPUTS_LEN = 64;
    uint256 public constant V2_H = 2;
    uint256 public constant V2_N = 3;
    uint256 public constant V2_PK_COMMITMENT_IDX = 29;

    uint256 private constant LEGACY_VK_BINDING_LEN = 16;
    uint256 private constant V2_VK_BINDING_LEN = 13;
    uint256 private constant V2_SESSION_HI_IDX = 31;
    uint256 private constant V2_SESSION_LO_IDX = 32;
    uint256 private constant V2_AGGREGATOR_ID_IDX = 33;
    uint256 private constant V2_ACCEPTED_SET_HI_IDX = 34;
    uint256 private constant V2_ACCEPTED_SET_LO_IDX = 35;
    uint256 private constant V2_PARTY_ID_START = 2;
    uint256 private constant V2_COMMITTEE_HASH_HI_IDX = 4;
    uint256 private constant V2_COMMITTEE_HASH_LO_IDX = 5;
    uint256 private constant V2_LEGACY_VK_BINDING_START = 6;
    uint256 private constant V2_SK_C2_CHUNK_IDX = 23;
    uint256 private constant V2_ESM_C2_CHUNK_IDX = 24;
    uint256 private constant V2_VK_BINDING_START = 51;

    uint256 private constant LBFV_PROOF_DOMAIN_VERSION = 1;
    uint256 public constant LBFV_PROTOCOL_VERSION = 4;
    uint256 private constant LBFV_CONSTANTS_VERSION = 1;
    bytes32 private constant LBFV_PROOF_DOMAIN_LABEL_HASH =
        keccak256("interfold.lbfv.proof-domain:v1");
    bytes32 private constant LBFV_ACCEPTED_SET_LABEL_HASH =
        keccak256("interfold.lbfv.accepted-party-set:v1");

    /// @notice Honest-party count compiled into the V2 minimum circuit.
    uint256 public immutable override h;

    /// @notice Public-input count accepted by the generated Honk verifier.
    uint256 public immutable expectedPublicInputsLen;

    /// @notice Registry used to resolve request-time root and Interfold context.
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    /// @notice Generated secure-16384 V2 Honk verifier.
    ICircuitVerifier public immutable circuitVerifier;

    bytes32 public immutable expectedNodesFoldKeyHash;
    bytes32 public immutable expectedC5KeyHash;
    bytes32 public immutable expectedSkC2ChunkKeyHash;
    bytes32 public immutable expectedESmC2ChunkKeyHash;
    bytes32[16] public expectedLegacyVkBinding;
    bytes32[13] public expectedV2VkBinding;

    constructor(
        address _circuitVerifier,
        address _ciphernodeRegistry,
        bytes32 _expectedNodesFoldKeyHash,
        bytes32 _expectedC5KeyHash,
        bytes32 _expectedSkC2ChunkKeyHash,
        bytes32 _expectedESmC2ChunkKeyHash,
        bytes32[16] memory _expectedLegacyVkBinding,
        bytes32[13] memory _expectedV2VkBinding
    ) {
        if (_circuitVerifier.code.length == 0) {
            revert InvalidCircuitVerifier(_circuitVerifier);
        }
        if (_ciphernodeRegistry.code.length == 0) {
            revert InvalidRegistry(_ciphernodeRegistry);
        }
        if (
            _expectedNodesFoldKeyHash == bytes32(0) ||
            _expectedC5KeyHash == bytes32(0) ||
            _expectedSkC2ChunkKeyHash == bytes32(0) ||
            _expectedESmC2ChunkKeyHash == bytes32(0)
        ) revert InvalidVerificationKeyHash();

        for (uint256 i = 0; i < LEGACY_VK_BINDING_LEN; ++i) {
            if (_expectedLegacyVkBinding[i] == bytes32(0)) {
                revert InvalidVerificationKeyHash();
            }
            expectedLegacyVkBinding[i] = _expectedLegacyVkBinding[i];
        }
        for (uint256 i = 0; i < V2_VK_BINDING_LEN; ++i) {
            if (_expectedV2VkBinding[i] == bytes32(0)) {
                revert InvalidVerificationKeyHash();
            }
            expectedV2VkBinding[i] = _expectedV2VkBinding[i];
        }

        h = V2_H;
        expectedPublicInputsLen = V2_PUBLIC_INPUTS_LEN;
        ciphernodeRegistry = ICiphernodeRegistry(_ciphernodeRegistry);
        circuitVerifier = ICircuitVerifier(_circuitVerifier);
        expectedNodesFoldKeyHash = _expectedNodesFoldKeyHash;
        expectedC5KeyHash = _expectedC5KeyHash;
        expectedSkC2ChunkKeyHash = _expectedSkC2ChunkKeyHash;
        expectedESmC2ChunkKeyHash = _expectedESmC2ChunkKeyHash;
    }

    /// @inheritdoc IPkVerifier
    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view override returns (bool) {
        (bytes memory rawProof, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );

        if (publicInputs.length != expectedPublicInputsLen) {
            revert InvalidPublicInputsLength();
        }
        if (sortedNodes.length != V2_N) {
            revert DomainBindingMismatch();
        }
        if (
            committeeHash != CommitteeHashLib.hash(sortedNodes) ||
            ciphernodeRegistry.rootAt(e3Id) != committeeRoot
        ) {
            revert DomainBindingMismatch();
        }

        _checkV2VkAnchors(publicInputs);
        _checkPartyIds(publicInputs);
        _checkCommitteeHash(publicInputs, committeeHash);
        _checkAcceptedPartySet(publicInputs);

        if (publicInputs[V2_PK_COMMITMENT_IDX] != pkCommitment) {
            revert PkCommitmentMismatch();
        }
        _checkSession(e3Id, committeeHash, publicInputs);

        if (!circuitVerifier.verify(rawProof, publicInputs)) {
            revert InvalidProof();
        }
        return true;
    }

    function _checkV2VkAnchors(bytes32[] memory publicInputs) private view {
        if (publicInputs[0] != expectedNodesFoldKeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[1] != expectedC5KeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[V2_SK_C2_CHUNK_IDX] != expectedSkC2ChunkKeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[V2_ESM_C2_CHUNK_IDX] != expectedESmC2ChunkKeyHash) {
            revert VkHashMismatch();
        }
        for (uint256 i = 0; i < LEGACY_VK_BINDING_LEN; ++i) {
            if (
                publicInputs[V2_LEGACY_VK_BINDING_START + i] !=
                expectedLegacyVkBinding[i]
            ) {
                revert VkHashMismatch();
            }
        }
        for (uint256 i = 0; i < V2_VK_BINDING_LEN; ++i) {
            if (
                publicInputs[V2_VK_BINDING_START + i] != expectedV2VkBinding[i]
            ) {
                revert VkHashMismatch();
            }
        }
    }

    function _checkPartyIds(bytes32[] memory publicInputs) private pure {
        uint256 first = uint256(publicInputs[V2_PARTY_ID_START]);
        uint256 second = uint256(publicInputs[V2_PARTY_ID_START + 1]);
        if (first >= V2_N || second >= V2_N || first >= second) {
            revert DomainBindingMismatch();
        }
        if (uint256(publicInputs[V2_AGGREGATOR_ID_IDX]) >= V2_N) {
            revert DomainBindingMismatch();
        }
    }

    function _checkCommitteeHash(
        bytes32[] memory publicInputs,
        bytes32 committeeHash
    ) private pure {
        if (
            publicInputs[V2_COMMITTEE_HASH_HI_IDX] !=
            CommitteeHashLib.hi(committeeHash) ||
            publicInputs[V2_COMMITTEE_HASH_LO_IDX] !=
            CommitteeHashLib.lo(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }
    }

    function _checkAcceptedPartySet(
        bytes32[] memory publicInputs
    ) private pure {
        bytes32 acceptedSetHash = keccak256(
            abi.encodePacked(
                LBFV_ACCEPTED_SET_LABEL_HASH,
                uint32(V2_H),
                uint32(uint256(publicInputs[V2_PARTY_ID_START])),
                uint32(uint256(publicInputs[V2_PARTY_ID_START + 1]))
            )
        );
        if (
            publicInputs[V2_ACCEPTED_SET_HI_IDX] !=
            CommitteeHashLib.hi(acceptedSetHash) ||
            publicInputs[V2_ACCEPTED_SET_LO_IDX] !=
            CommitteeHashLib.lo(acceptedSetHash)
        ) {
            revert DomainBindingMismatch();
        }
    }

    function _checkSession(
        uint256 e3Id,
        bytes32 committeeHash,
        bytes32[] memory publicInputs
    ) private view {
        IInterfold interfold = ciphernodeRegistry.interfold();
        E3 memory e3 = interfold.getE3(e3Id);
        if (e3.paramSet != ActiveCryptoConfig.SECURE_16384_PARAM_SET) {
            revert DomainBindingMismatch();
        }

        bytes32 sessionId = keccak256(
            abi.encode(
                LBFV_PROOF_DOMAIN_LABEL_HASH,
                LBFV_PROOF_DOMAIN_VERSION,
                LBFV_PROTOCOL_VERSION,
                block.chainid,
                address(interfold),
                e3Id,
                ActiveCryptoConfig.configIdForParamSet(e3.paramSet),
                committeeHash,
                LBFV_CONSTANTS_VERSION,
                uint256(0),
                uint256(0)
            )
        );
        if (
            publicInputs[V2_SESSION_HI_IDX] != CommitteeHashLib.hi(sessionId) ||
            publicInputs[V2_SESSION_LO_IDX] != CommitteeHashLib.lo(sessionId)
        ) {
            revert DomainBindingMismatch();
        }
    }
}
