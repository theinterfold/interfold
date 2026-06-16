// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity 0.8.28;

/**
 * @title CommitteeHashLib
 * @notice Canonical `keccak256(abi.encodePacked(topNodes))` binding for aggregator proofs.
 * @dev Must match `e3_utils::committee_hash` (hi/lo split into two 128-bit limbs).
 */
library CommitteeHashLib {
    uint256 private constant _LO_MASK = (uint256(1) << 128) - 1;

    /// @notice `keccak256(concat(20-byte addresses))` for the ordered on-chain committee.
    /// @dev Must match `e3_utils::committee_hash::hash_committee_addresses`, which packs
    ///      each address as raw 20 bytes with no padding. NOTE: `abi.encodePacked(address[])`
    ///      pads each element to 32 bytes (left-padded), which does NOT match the off-chain
    ///      canonical encoding — so we build the 20*N byte buffer manually.
    function hash(address[] memory nodes) internal pure returns (bytes32) {
        uint256 n = nodes.length;
        bytes memory packed = new bytes(n * 20);
        for (uint256 i = 0; i < n; ++i) {
            bytes20 a = bytes20(nodes[i]);
            uint256 offset = i * 20;
            // Write 20-byte address in one word store; trailing 12 bytes are
            // zeroed and either overwritten by the next address or ignored by
            // `keccak256(packed)` because bytes length is exactly `20*n`.
            // solhint-disable-next-line no-inline-assembly
            assembly {
                mstore(add(add(packed, 0x20), offset), shl(96, a))
            }
        }
        return keccak256(packed);
    }

    /// @notice High 128 bits of a committee hash (Noir public input `committee_hash_hi`).
    function hi(bytes32 committeeHash) internal pure returns (bytes32) {
        return bytes32(uint256(committeeHash) >> 128);
    }

    /// @notice Low 128 bits of a committee hash (Noir public input `committee_hash_lo`).
    function lo(bytes32 committeeHash) internal pure returns (bytes32) {
        return bytes32(uint256(committeeHash) & _LO_MASK);
    }
}
