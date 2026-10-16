// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Binds each bond owner to one uniqueness identifier, with a timestamp history.
/// @dev An identifier stays reserved for the first owner that registered it, also after a renewal
///      or a revocation, so that one document or person can never verify a second owner.
interface IOwnerIdentityRegistry {
    event IdentityRegistered(
        address indexed owner,
        bytes32 indexed identityId,
        uint48 expiresAt
    );
    event IdentityRevoked(address indexed owner, bytes32 indexed identityId);
    event VerifierUpdated(address indexed verifier);

    error VerifierNotSet();
    error IdentityInUse(bytes32 identityId, address owner);
    error IdentityIsRevoked(bytes32 identityId);
    error IdentityExpired(bytes32 identityId, uint48 expiresAt);
    error UnknownIdentity(bytes32 identityId);

    /// @notice Registers or renews the caller's credential through the configured verifier.
    /// @dev The caller is the bond owner. A Safe owner calls this from the Safe.
    function register(
        bytes calldata evidence
    ) external returns (bytes32 identityId, uint48 expiresAt);

    /// @notice Governance revokes an identifier, for example after shown abuse. The identifier
    ///         cannot register again.
    function revoke(bytes32 identityId) external;

    /// @notice Governance sets the verifier for future registrations. Existing identities keep
    ///         their expiry.
    function setVerifier(address verifier) external;

    /// @notice Whether `owner` held a valid identity at `timepoint`, read from the checkpoint
    ///         history, so that a past request boundary keeps its answer.
    function isVerifiedAt(
        address owner,
        uint256 timepoint
    ) external view returns (bool);

    /// @notice The owner's current identifier and expiry; zero values when it has none.
    function identityOf(
        address owner
    ) external view returns (bytes32 identityId, uint48 expiresAt);

    /// @notice The owner that holds `identityId`; the zero address when it is unused.
    function ownerOfIdentity(bytes32 identityId) external view returns (address);

    function verifier() external view returns (address);
}
