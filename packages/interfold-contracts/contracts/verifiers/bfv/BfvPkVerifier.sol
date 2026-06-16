// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../../interfaces/IPkVerifier.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";

/**
 * @title BfvPkVerifier
 * @notice Verifies the DkgAggregator (EVM) proof produced by the recursive
 *         aggregation pipeline (node folds + C5/pk_aggregation verified
 *         internally) and binds it to the full on-chain call context.
 * @dev Used when the Interfold is configured with encryptionSchemeId
 *      keccak256("fhe.rs:BFV"). Constructor `h` must match the compiled
 *      DkgAggregator honest-set size (`lib::configs::default::H`).
 *
 *      Expected `publicInputs` layout for DkgAggregator EVM outputs:
 *        [0]                = expectedNodesFoldKeyHash  (VK anchor)
 *        [1]                = expectedC5KeyHash         (VK anchor)
 *        [2 .. 2+H)         = party_ids                 (H slots)
 *        [2+H]              = committee_hash_hi
 *        [3+H]              = committee_hash_lo
 *        [4+H .. 4+3H)      = expected_pk               (2*H slots)
 *        [4+3H]             = pk_commitment
 *        Total: expectedPublicInputsLen = 3*H + 6.
 *
 *      The two VK-hash slots are checked against contract immutables set at
 *      construction; this anchors the recursive aggregation trust and
 *      prevents a malicious aggregator from substituting a forged sub-VK.
 *
 *      NOTE — domain binding relaxation: wrapper-level chainId/deployment/e3Id
 *      binding requires a dedicated circuit public input. The current circuits
 *      do not expose such a slot. Full cryptographic enforcement tracked as
 *      future work. The caller-supplied `e3Id`, `committeeRoot`, and
 *      `sortedNodes` are preserved in the interface for forward compatibility.
 */
contract BfvPkVerifier is IPkVerifier {
    /// @dev `dkg_aggregator` return field count.
    uint256 internal constant DKG_RETURN_TAIL_LEN = 2;

    /// @notice Honest-set size `H` (`party_ids` length); must match the compiled DkgAggregator circuit.
    uint256 public immutable h;

    /// @dev `publicInputs` index for `committee_hash_hi` (after VK anchors and `party_ids`).
    uint256 internal immutable committeeHashHiIdx;

    /// @dev `publicInputs` index for `committee_hash_lo`.
    uint256 internal immutable committeeHashLoIdx;

    /// @dev Total expected length of EVM public inputs for `dkg_aggregator`.
    uint256 internal immutable expectedPublicInputsLen;

    /// @dev Index of `pkCommitment` (last return field).
    uint256 internal immutable pkCommitmentIdx;

    /// @notice Underlying Honk verifier for the DkgAggregator circuit.
    ICircuitVerifier public immutable circuitVerifier;

    /// @notice keccak256 commitment to the node-fold recursive VK; expected at
    ///         `publicInputs[0]`. Provenance: `bb verify_key -b
    ///         circuits/bin/recursive_aggregation/node_fold/target/...` --
    ///         pinned at deployment time, must match the circuit version the
    ///         aggregator was built against.
    bytes32 public immutable expectedNodesFoldKeyHash;

    /// @notice keccak256 commitment to the C5 (pk_aggregation) recursive VK;
    ///         expected at `publicInputs[1]`. Same provenance as above.
    bytes32 public immutable expectedC5KeyHash;

    constructor(
        address _circuitVerifier,
        bytes32 _expectedNodesFoldKeyHash,
        bytes32 _expectedC5KeyHash,
        uint256 _h
    ) {
        require(_h > 0, "BfvPkVerifier: h=0");
        h = _h;
        committeeHashHiIdx = 2 + _h;
        committeeHashLoIdx = 3 + _h;
        expectedPublicInputsLen = (3 * _h) + 6;
        pkCommitmentIdx = expectedPublicInputsLen - 1;

        circuitVerifier = ICircuitVerifier(_circuitVerifier);
        expectedNodesFoldKeyHash = _expectedNodesFoldKeyHash;
        expectedC5KeyHash = _expectedC5KeyHash;
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

        // Anchor recursive-aggregation trust to immutable VK hashes.
        if (publicInputs[0] != expectedNodesFoldKeyHash) {
            revert VkHashMismatch();
        }
        if (publicInputs[1] != expectedC5KeyHash) {
            revert VkHashMismatch();
        }

        // Bind to the on-chain committee hash (hi/lo split per Noir field convention).
        if (
            publicInputs[committeeHashHiIdx] !=
            CommitteeHashLib.hi(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }
        if (
            publicInputs[committeeHashLoIdx] !=
            CommitteeHashLib.lo(committeeHash)
        ) {
            revert DomainBindingMismatch();
        }

        // Aggregated PK commitment is the last slot.
        if (publicInputs[pkCommitmentIdx] != pkCommitment) {
            revert PkCommitmentMismatch();
        }

        // Suppress unused-variable warnings for forward-compatibility params.
        // These will be used for circuit-level domain binding in a future circuit update.
        e3Id;
        committeeRoot;
        sortedNodes;

        // Bubble up as a revert instead of a silent `false`.
        if (!circuitVerifier.verify(rawProof, publicInputs)) {
            revert InvalidProof();
        }
        return true;
    }
}
