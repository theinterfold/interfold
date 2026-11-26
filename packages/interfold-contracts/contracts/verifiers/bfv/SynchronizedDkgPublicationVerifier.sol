// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";
import { BfvProtocol } from "../../lib/BfvProtocol.sol";

/**
 * @notice Synchronized setup verifier, deliberately not an IPkVerifier/SS route.
 * @dev The registry supplies request-frozen facts and checks selected-recipient publication consent.
 * This stateless boundary neither authenticates those facts nor publishes/stores a committee.
 * SK and key-bundle anchors are distinct; no ESM field or attestation is reinterpreted.
 */
contract SynchronizedDkgPublicationVerifier {
    error InvalidConfiguration();
    error InvalidPublication();

    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ICircuitVerifier public immutable CIRCUIT_VERIFIER;
    address public immutable INTERFOLD;
    bytes32 public immutable CRYPTO_CONFIG_ID;
    bytes32 public immutable SETUP_TREE_HASH;
    bytes32 public immutable C5_KEY_HASH;
    uint256 public immutable N;
    uint256 public immutable H;

    constructor(
        address verifier,
        address deployment,
        bytes32 configId,
        bytes32 treeHash,
        bytes32 c5Hash,
        uint256 committeeN,
        uint256 committeeH
    ) {
        if (
            verifier.code.length == 0 ||
            deployment == address(0) ||
            !BfvProtocol.isSynchronizedMinimum(configId) ||
            treeHash == bytes32(0) ||
            c5Hash == bytes32(0) ||
            committeeH != BfvProtocol.MINIMUM_H ||
            committeeN != BfvProtocol.MINIMUM_N
        ) revert InvalidConfiguration();
        CIRCUIT_VERIFIER = ICircuitVerifier(verifier);
        INTERFOLD = deployment;
        CRYPTO_CONFIG_ID = configId;
        SETUP_TREE_HASH = treeHash;
        C5_KEY_HASH = c5Hash;
        N = committeeN;
        H = committeeH;
    }

    /// @notice Verify an isolated setup candidate against independently admitted expectations.
    /// @dev Public fields: tree, C5 VK, binding[2], dealers[H]; return batch, PKs[H],
    /// SKs[H], bundles[H], aggregate PK. Total 6+4H. No legacy SS layout is accepted.
    function verify(
        uint256 e3Id,
        address[] calldata committee,
        uint256[] calldata dealers,
        bytes32 pkCommitment,
        bytes32 dealerBatch,
        bytes calldata proof
    )
        external
        view
        returns (
            bytes32[] memory sk,
            bytes32[] memory bundles,
            bytes32[] memory thresholdKeys
        )
    {
        (bytes memory raw, bytes32[] memory inputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );
        if (
            inputs.length != 6 + 4 * H ||
            committee.length != N ||
            dealers.length != H
        ) revert InvalidPublication();
        for (uint256 i = 0; i < inputs.length; ++i) {
            if (uint256(inputs[i]) >= SCALAR_MODULUS)
                revert InvalidPublication();
        }
        bytes32 binding = _setupBinding(e3Id, committee);
        if (
            inputs[0] != SETUP_TREE_HASH ||
            inputs[1] != C5_KEY_HASH ||
            inputs[2] != CommitteeHashLib.hi(binding) ||
            inputs[3] != CommitteeHashLib.lo(binding) ||
            inputs[4 + H] != dealerBatch ||
            inputs[5 + 4 * H] != pkCommitment
        ) revert InvalidPublication();
        sk = new bytes32[](H);
        bundles = new bytes32[](H);
        thresholdKeys = new bytes32[](H);
        for (uint256 i = 0; i < H; ++i) {
            if (
                dealers[i] >= N ||
                (i > 0 && dealers[i - 1] >= dealers[i]) ||
                uint256(inputs[4 + i]) != dealers[i]
            ) revert InvalidPublication();
            sk[i] = inputs[5 + 2 * H + i];
            bundles[i] = inputs[5 + 3 * H + i];
            thresholdKeys[i] = inputs[5 + H + i];
        }
        if (!CIRCUIT_VERIFIER.verify(raw, inputs)) revert InvalidPublication();
    }

    /// @notice Request context signed by each selected recipient before registry publication.
    function setupBinding(
        uint256 e3Id,
        address[] calldata committee
    ) external view returns (bytes32) {
        if (committee.length != N) revert InvalidPublication();
        return _setupBinding(e3Id, committee);
    }

    /// @notice Honest-party metadata for request-time verifier configuration checks.
    function h() external view returns (uint256) {
        return H;
    }

    function _setupBinding(
        uint256 e3Id,
        address[] calldata committee
    ) private view returns (bytes32) {
        for (uint256 i = 0; i < N; ++i) {
            if (
                committee[i] == address(0) ||
                (i > 0 && committee[i - 1] >= committee[i])
            ) revert InvalidPublication();
        }
        return
            keccak256(
                abi.encode(
                    keccak256("interfold:sync-dkg-setup:v1"),
                    block.chainid,
                    INTERFOLD,
                    e3Id,
                    CommitteeHashLib.hash(committee),
                    CRYPTO_CONFIG_ID
                )
            );
    }
}
