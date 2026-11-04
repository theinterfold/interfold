// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice The ABI of ZKPassport's root verifier, which has the same address on every network.
/// @dev The tuple layouts must match ZKPassport's `ProofVerificationParams` exactly; the names follow
///      ZKPassport's documentation.
interface IZKPassportVerifier {
    struct ProofVerificationParams {
        bytes32 version;
        ProofVerificationData proofVerificationData;
        bytes committedInputs;
        ServiceConfig serviceConfig;
    }

    struct ProofVerificationData {
        bytes32 vkeyHash;
        bytes proof;
        bytes32[] publicInputs;
    }

    struct ServiceConfig {
        uint256 validityPeriodInSeconds;
        string domain;
        string scope;
        bool devMode;
    }

    struct BoundData {
        address senderAddress;
        uint256 chainId;
        string customData;
    }

    enum FaceMatchMode {
        NONE,
        REGULAR,
        STRICT
    }

    enum OS {
        ANY,
        IOS,
        ANDROID
    }

    /// @notice Verifies a proof with the sub-verifier of `params.version`.
    /// @return verified Whether the proof is valid.
    /// @return uniqueIdentifier The document's identifier for the proof's domain and scope.
    /// @return helper The helper that reads the proof's committed inputs.
    function verify(
        ProofVerificationParams calldata params
    )
        external
        returns (
            bool verified,
            bytes32 uniqueIdentifier,
            IZKPassportHelper helper
        );
}

/// @notice The ZKPassport helper functions that read a verified proof's committed inputs.
interface IZKPassportHelper {
    function getBoundData(
        bytes calldata committedInputs
    ) external view returns (IZKPassportVerifier.BoundData memory);

    /// @notice Whether the proof shows an expiry date at or after `minDate`. `minDate` must equal the
    ///         lower bound that the proof committed to.
    function isExpiryDateAfterOrEqual(
        uint256 minDate,
        bytes calldata committedInputs
    ) external view returns (bool);

    function isFaceMatchVerified(
        IZKPassportVerifier.FaceMatchMode faceMatchMode,
        IZKPassportVerifier.OS os,
        bytes calldata committedInputs
    ) external view returns (bool);
}
