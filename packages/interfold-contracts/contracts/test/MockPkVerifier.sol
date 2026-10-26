// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../interfaces/IPkVerifier.sol";

contract MockPkVerifier is IPkVerifier {
    uint256 public constant override h = 2;

    /// @dev l-BFV `DkgAggregatorV2` statements carry `39 + 3h + 3 * rows` inputs with at
    ///      least one row; the key-envelope commitment sits at `21 + 3h`, followed by the
    ///      session domain, the aggregate commitments and the verification-key bindings.
    ///      Anything shorter is a legacy `DkgAggregator` statement, whose commitment is last.
    uint256 private constant V2_MIN_PUBLIC_INPUTS_LEN = 39 + (3 * h) + 3;
    uint256 private constant V2_COMMITMENT_INDEX = 21 + (3 * h);

    bytes4 private constant _RETURN_FALSE_MAGIC = 0xfafafafa;

    /// @dev Permissive test mock: only enforces the pk-commitment slot the
    ///      real wrappers enforce (the last slot for the legacy layout, the
    ///      key-envelope slot for the l-BFV V2 layout), so existing fixtures
    ///      (`[pkCommitment]`) and test-only l-BFV placeholder proofs keep
    ///      working. Intentionally ignores VK-hash slots and domain
    ///      binding — those are exercised by `BfvPkVerifier.spec.ts` and
    ///      `BfvPkVerifierV2.spec.ts` against the real wrappers.
    function verify(
        uint256,
        uint256,
        address[] calldata,
        bytes32 pkCommitment,
        bytes32,
        bytes calldata proof
    ) external pure returns (bool) {
        (bytes memory rawProof, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );
        if (publicInputs.length == 0) revert InvalidPublicInputsLength();
        uint256 commitmentIndex = publicInputs.length >=
            V2_MIN_PUBLIC_INPUTS_LEN
            ? V2_COMMITMENT_INDEX
            : publicInputs.length - 1;
        if (publicInputs[commitmentIndex] != pkCommitment) {
            revert PkCommitmentMismatch();
        }
        if (
            keccak256(rawProof) ==
            keccak256(abi.encodePacked(_RETURN_FALSE_MAGIC))
        ) return false;
        return true;
    }
}
