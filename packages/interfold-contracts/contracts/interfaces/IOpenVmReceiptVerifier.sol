// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Verifies an OpenVM receipt against a configured application and journal digest.
interface IOpenVmReceiptVerifier {
    /// @notice The receipt identity that `verify` accepts.
    function imageId() external view returns (bytes32);

    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}
