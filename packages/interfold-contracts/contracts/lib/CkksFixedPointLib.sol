// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/**
 * @title CkksFixedPointLib
 * @notice Decodes the canonical CKKS fixed-point plaintext output published
 *         by `publishPlaintextOutput` for CKKS E3s.
 * @dev Mirror of `e3_trckks::program::encode_fixed_point_output` (Rust):
 *      big-endian `int128` words, one per value, at a declared decimal
 *      scale. The encoding truncates below the scale so any honest t+1
 *      committee subset publishes byte-identical output (smudging noise is
 *      subset-dependent below the precision floor; see the Rust module
 *      docs). A cross-language fixture test pins both sides
 *      (`solidity_fixture_vector` in e3-trckks / CkksFixedPointLib.spec.ts).
 */
library CkksFixedPointLib {
    /// @notice Thrown when the payload length is not a multiple of 16.
    error RaggedFixedPointPayload(uint256 length);

    /// @notice Number of values encoded in `data`.
    function count(bytes calldata data) internal pure returns (uint256) {
        if (data.length % 16 != 0) revert RaggedFixedPointPayload(data.length);
        return data.length / 16;
    }

    /// @notice Decode the scaled integer at `index` (no division applied —
    ///         the caller decides what to do with the `10**decimals` scale,
    ///         since solidity has no floats).
    function valueAt(
        bytes calldata data,
        uint256 index
    ) internal pure returns (int128) {
        if (data.length % 16 != 0) revert RaggedFixedPointPayload(data.length);
        uint256 offset = index * 16;
        // Read 16 bytes big-endian into the low bits, then sign-extend.
        uint128 raw = uint128(bytes16(data[offset:offset + 16]));
        return int128(raw);
    }

    /// @notice Convenience: decode every scaled integer.
    function decodeAll(
        bytes calldata data
    ) internal pure returns (int128[] memory values) {
        uint256 n = count(data);
        values = new int128[](n);
        for (uint256 i = 0; i < n; i++) {
            values[i] = valueAt(data, i);
        }
    }
}
