// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import {
    IZKPassportHelper,
    IZKPassportVerifier
} from "../interfaces/IZKPassportVerifier.sol";

/// @notice Returns a configured result and keeps the last service configuration it received.
contract MockZKPassportRootVerifier is IZKPassportVerifier {
    IZKPassportHelper private immutable helper;
    bool private verified = true;
    bytes32 private uniqueIdentifier;

    uint256 public lastValidityPeriod;
    string public lastDomain;
    string public lastScope;
    bool public lastDevMode;

    constructor(IZKPassportHelper _helper, bytes32 _uniqueIdentifier) {
        helper = _helper;
        uniqueIdentifier = _uniqueIdentifier;
    }

    function setResult(bool _verified, bytes32 _uniqueIdentifier) external {
        verified = _verified;
        uniqueIdentifier = _uniqueIdentifier;
    }

    function verify(
        ProofVerificationParams calldata params
    ) external override returns (bool, bytes32, IZKPassportHelper) {
        lastValidityPeriod = params.serviceConfig.validityPeriodInSeconds;
        lastDomain = params.serviceConfig.domain;
        lastScope = params.serviceConfig.scope;
        lastDevMode = params.serviceConfig.devMode;
        return (verified, uniqueIdentifier, helper);
    }
}

/// @notice Returns configured committed-input answers.
contract MockZKPassportHelper is IZKPassportHelper {
    address private senderAddress;
    uint256 private chainId;
    uint256 private expiryLowerBound;
    bool private faceMatchVerified = true;

    function setBinding(address _senderAddress, uint256 _chainId) external {
        senderAddress = _senderAddress;
        chainId = _chainId;
    }

    function setExpiryLowerBound(uint256 _expiryLowerBound) external {
        expiryLowerBound = _expiryLowerBound;
    }

    function setFaceMatchVerified(bool _faceMatchVerified) external {
        faceMatchVerified = _faceMatchVerified;
    }

    function getBoundData(
        bytes calldata
    ) external view override returns (IZKPassportVerifier.BoundData memory) {
        return IZKPassportVerifier.BoundData(senderAddress, chainId, "");
    }

    function isExpiryDateAfterOrEqual(
        uint256 minDate,
        bytes calldata
    ) external view override returns (bool) {
        return minDate == expiryLowerBound;
    }

    function isFaceMatchVerified(
        IZKPassportVerifier.FaceMatchMode,
        IZKPassportVerifier.OS,
        bytes calldata
    ) external view override returns (bool) {
        return faceMatchVerified;
    }
}
