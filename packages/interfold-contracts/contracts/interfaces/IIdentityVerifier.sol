// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @notice Checks one uniqueness credential for a bond owner.
/// @dev `OwnerIdentityRegistry` calls this once per registration. An implementation must bind the
///      credential to `owner`, so that a credential for one address cannot register another.
///      It may keep state, for example to reject a replayed attestation.
interface IIdentityVerifier {
    /// @notice Verifies `evidence` for `owner`.
    /// @param owner The bond owner that registers the credential.
    /// @param evidence The credential, in the format of the implementation.
    /// @return identityId The uniqueness identifier. The same person or document yields the same
    ///         identifier, so that it cannot register a second owner.
    /// @return expiresAt The last timestamp at which the credential is valid.
    function verify(
        address owner,
        bytes calldata evidence
    ) external returns (bytes32 identityId, uint48 expiresAt);
}
