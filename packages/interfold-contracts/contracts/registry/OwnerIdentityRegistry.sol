// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {
    Checkpoints
} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IIdentityVerifier } from "../interfaces/IIdentityVerifier.sol";
import { IOwnerIdentityRegistry } from "../interfaces/IOwnerIdentityRegistry.sol";

/// @notice Reserves uniqueness identifiers and checkpoints each owner's credential expiry.
contract OwnerIdentityRegistry is IOwnerIdentityRegistry, Ownable2Step {
    using Checkpoints for Checkpoints.Trace208;

    struct Identity {
        bytes32 identityId;
        uint48 expiresAt;
    }

    address public override verifier;
    mapping(bytes32 identityId => address owner) public override ownerOfIdentity;
    mapping(bytes32 identityId => bool revoked) private _revoked;
    mapping(address owner => Identity identity) private _identities;
    mapping(address owner => Checkpoints.Trace208 history) private _history;

    constructor(
        address initialOwner,
        address initialVerifier
    ) Ownable(initialOwner) {
        _setVerifier(initialVerifier);
    }

    function register(
        bytes calldata evidence
    ) external returns (bytes32 identityId, uint48 expiresAt) {
        if (verifier == address(0)) revert VerifierNotSet();
        (identityId, expiresAt) = IIdentityVerifier(verifier).verify(
            msg.sender,
            evidence
        );
        if (block.timestamp > expiresAt)
            revert IdentityExpired(identityId, expiresAt);
        if (_revoked[identityId]) revert IdentityIsRevoked(identityId);
        address reservedOwner = ownerOfIdentity[identityId];
        if (reservedOwner != address(0) && reservedOwner != msg.sender)
            revert IdentityInUse(identityId, reservedOwner);

        // Keep every reservation so a replaced credential cannot verify another owner.
        ownerOfIdentity[identityId] = msg.sender;
        _identities[msg.sender] = Identity(identityId, expiresAt);
        _history[msg.sender].push(SafeCast.toUint48(block.timestamp), expiresAt);
        emit IdentityRegistered(msg.sender, identityId, expiresAt);
    }

    function revoke(bytes32 identityId) external onlyOwner {
        address identityOwner = ownerOfIdentity[identityId];
        if (identityOwner == address(0)) revert UnknownIdentity(identityId);
        _revoked[identityId] = true;
        if (_identities[identityOwner].identityId == identityId) {
            delete _identities[identityOwner];
            _history[identityOwner].push(SafeCast.toUint48(block.timestamp), 0);
        }
        emit IdentityRevoked(identityOwner, identityId);
    }

    function setVerifier(address newVerifier) external onlyOwner {
        _setVerifier(newVerifier);
    }

    function isVerifiedAt(
        address identityOwner,
        uint256 timepoint
    ) external view returns (bool) {
        uint208 expiresAt = _history[identityOwner].upperLookupRecent(
            SafeCast.toUint48(timepoint)
        );
        return expiresAt != 0 && timepoint <= expiresAt;
    }

    function identityOf(
        address identityOwner
    ) external view returns (bytes32 identityId, uint48 expiresAt) {
        Identity storage identity = _identities[identityOwner];
        return (identity.identityId, identity.expiresAt);
    }

    function _setVerifier(address newVerifier) private {
        verifier = newVerifier;
        emit VerifierUpdated(newVerifier);
    }
}
