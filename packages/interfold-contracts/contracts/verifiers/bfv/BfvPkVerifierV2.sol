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

/// @notice Verifies a V2 l-BFV DKG aggregator proof.
contract BfvPkVerifierV2 is IPkVerifier {
    error InvalidCircuitVerifier(address verifier);
    error InvalidRegistry(address registry);
    error InvalidParamSet(uint8 paramSet);
    error InvalidVerificationKeyHash();

    uint256 private constant V2_PUBLIC_INPUTS_FIXED_LEN = 43;

    uint256 private constant LEGACY_VK_BINDING_LEN = 16;
    uint256 private constant V2_VK_BINDING_LEN = 13;
    uint256 private constant V2_PARTY_ID_START = 2;

    uint256 private constant LBFV_PROOF_DOMAIN_VERSION = 1;
    uint256 public constant LBFV_PROTOCOL_VERSION = 4;
    uint256 private constant LBFV_CONSTANTS_VERSION = 1;
    bytes32 private constant LBFV_PROOF_DOMAIN_LABEL_HASH =
        keccak256("interfold.lbfv.proof-domain:v1");
    bytes32 private constant LBFV_ACCEPTED_SET_LABEL_HASH =
        keccak256("interfold.lbfv.accepted-party-set:v1");

    /// @notice Honest-party count compiled into the V2 circuit.
    uint256 public immutable override h;

    /// @notice Total committee count compiled into the V2 circuit.
    uint256 public immutable committeeN;

    /// @notice Parameter-set identifier accepted by this route.
    uint8 public immutable expectedParamSet;

    /// @notice Number of l-BFV rows compiled into this route.
    uint256 public immutable lbfvRows;

    /// @notice Public-input count accepted by the generated Honk verifier.
    uint256 public immutable expectedPublicInputsLen;

    /// @notice Registry used to resolve request-time root and Interfold context.
    ICiphernodeRegistry public immutable ciphernodeRegistry;

    /// @notice Generated V2 Honk verifier.
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
        uint8 _paramSet,
        uint256 _committeeH,
        uint256 _committeeN,
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
        if (_paramSet > ActiveCryptoConfig.SECURE_16384_PARAM_SET) {
            revert InvalidParamSet(_paramSet);
        }
        if (_committeeH == 0 || _committeeN == 0 || _committeeH > _committeeN) {
            revert InvalidParamSet(_paramSet);
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

        h = _committeeH;
        committeeN = _committeeN;
        expectedParamSet = _paramSet;
        lbfvRows =
            _paramSet == ActiveCryptoConfig.SECURE_16384_PARAM_SET ? 5 : 3;
        expectedPublicInputsLen =
            V2_PUBLIC_INPUTS_FIXED_LEN + (3 * h) + (3 * lbfvRows);
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
        if (sortedNodes.length != committeeN) {
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

        if (publicInputs[23 + (3 * h)] != pkCommitment) {
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
        if (publicInputs[21 + h] != expectedSkC2ChunkKeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[22 + h] != expectedESmC2ChunkKeyHash) {
            revert VkHashMismatch();
        }
        for (uint256 i = 0; i < LEGACY_VK_BINDING_LEN; ++i) {
            if (
                publicInputs[4 + h + i] !=
                    expectedLegacyVkBinding[i]
            ) {
                revert VkHashMismatch();
            }
        }
        uint256 v2VkBindingStart = 30 + (3 * h) + (3 * lbfvRows);
        for (uint256 i = 0; i < V2_VK_BINDING_LEN; ++i) {
            if (
                publicInputs[v2VkBindingStart + i] != expectedV2VkBinding[i]
            ) {
                revert VkHashMismatch();
            }
        }
    }

    function _checkPartyIds(bytes32[] memory publicInputs) private view {
        uint256 previous;
        for (uint256 i = 0; i < h; ++i) {
            uint256 partyId = uint256(publicInputs[V2_PARTY_ID_START + i]);
            if (partyId >= committeeN || (i > 0 && partyId <= previous)) {
                revert DomainBindingMismatch();
            }
            previous = partyId;
        }
        if (uint256(publicInputs[27 + (3 * h)]) >= committeeN) {
            revert DomainBindingMismatch();
        }
    }

    function _checkCommitteeHash(
        bytes32[] memory publicInputs,
        bytes32 committeeHash
    ) private view {
        if (
            publicInputs[2 + h] !=
                CommitteeHashLib.hi(committeeHash) ||
            publicInputs[3 + h] !=
                CommitteeHashLib.lo(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }
    }

    function _checkAcceptedPartySet(
        bytes32[] memory publicInputs
    ) private view {
        bytes memory acceptedSetPreimage = abi.encodePacked(
            LBFV_ACCEPTED_SET_LABEL_HASH,
            uint32(h)
        );
        for (uint256 i = 0; i < h; ++i) {
            acceptedSetPreimage = bytes.concat(
                acceptedSetPreimage,
                abi.encodePacked(
                    uint32(uint256(publicInputs[V2_PARTY_ID_START + i]))
                )
            );
        }
        bytes32 acceptedSetHash = keccak256(
            acceptedSetPreimage
        );
        uint256 acceptedSetHiIdx = 28 + (3 * h);
        uint256 acceptedSetLoIdx = 29 + (3 * h);
        if (
            publicInputs[acceptedSetHiIdx] !=
                CommitteeHashLib.hi(acceptedSetHash) ||
            publicInputs[acceptedSetLoIdx] !=
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
        if (e3.paramSet != expectedParamSet) {
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
                ActiveCryptoConfig.configIdForParamSet(expectedParamSet),
                committeeHash,
                LBFV_CONSTANTS_VERSION,
                uint256(0),
                uint256(0)
            )
        );
        uint256 sessionHiIdx = 25 + (3 * h);
        uint256 sessionLoIdx = 26 + (3 * h);
        if (
            publicInputs[sessionHiIdx] != CommitteeHashLib.hi(sessionId) ||
            publicInputs[sessionLoIdx] != CommitteeHashLib.lo(sessionId)
        ) {
            revert DomainBindingMismatch();
        }
    }
}
