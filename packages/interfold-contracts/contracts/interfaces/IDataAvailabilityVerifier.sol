// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

/// @notice Verifies that content-addressed bytes were published to an external DA layer.
interface IDataAvailabilityVerifier {
    /// @notice Stable coordinates needed to retrieve an object after verification.
    /// @dev ZEN2-08: these coordinates have no provider identifier, and callers persist only
    ///      `contentHash`. They are therefore interpretable only under the single verifier that
    ///      produced them, which is why a round's verifier must not change while it runs. Adding a
    ///      provider identifier here is the prerequisite for any multi-provider round.
    struct DataReference {
        bytes32 contentHash;
        uint32 blockNumber;
        uint128 leafIndex;
    }

    /// @notice Verifies one receipt and returns its normalized retrieval coordinates.
    /// @param expectedContentHash Keccak-256 of the exact raw object bytes.
    /// @param proof Provider-specific proof bytes.
    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    ) external view returns (DataReference memory receipt);
}

/// @notice E3-program extension used when an aggregate ciphertext is stored outside Ethereum.
interface IE3ProgramDataAvailability {
    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    )
        external
        view
        returns (IDataAvailabilityVerifier.DataReference memory receipt);
}
