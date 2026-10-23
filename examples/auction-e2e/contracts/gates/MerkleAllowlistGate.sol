// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { IBidderGate } from "../interfaces/IBidderGate.sol";

/// @title Allowlist gate: only listed addresses may bid.
/// @notice `config` is `abi.encode(address[] members)`: 1 to 256 strictly increasing addresses. The
/// gate builds a Merkle tree over them on chain and stores the root. The tree has the leaf
/// `keccak256(abi.encodePacked(member))`, sorted-pair `keccak256` for the inner nodes, and an odd
/// node is promoted to the next level unchanged. A bidder's `proof` is `abi.encode(bytes32[] path)`,
/// checked with OpenZeppelin `MerkleProof.verify`. `shared/allowlist.ts` builds the same root and path.
contract MerkleAllowlistGate is IBidderGate {
  uint256 public constant MAX_MEMBERS = 256;

  /// @notice The root of the allowlist of an auction, by program and E3.
  mapping(address program => mapping(uint256 e3Id => bytes32 root)) public roots;

  error EmptyAllowlist();
  error AllowlistTooLarge(uint256 count);
  error MembersNotIncreasing();
  error AlreadyConfigured();

  /// @notice The allowlist of an auction was set. Clients read the members from here to build proofs.
  event AllowlistSet(address indexed program, uint256 indexed e3Id, bytes32 root, address[] members);

  /// @inheritdoc IBidderGate
  function configure(uint256 e3Id, bytes calldata config) external override {
    if (roots[msg.sender][e3Id] != bytes32(0)) revert AlreadyConfigured();
    address[] memory members = abi.decode(config, (address[]));
    uint256 count = members.length;
    if (count == 0) revert EmptyAllowlist();
    if (count > MAX_MEMBERS) revert AllowlistTooLarge(count);

    bytes32[] memory level = new bytes32[](count);
    for (uint256 i = 0; i < count; i++) {
      if (i > 0 && members[i] <= members[i - 1]) revert MembersNotIncreasing();
      level[i] = keccak256(abi.encodePacked(members[i]));
    }
    // Reduce the level in place: pair up the nodes, promote an odd last node.
    while (count > 1) {
      uint256 next = 0;
      for (uint256 i = 0; i + 1 < count; i += 2) {
        level[next++] = _hashPair(level[i], level[i + 1]);
      }
      if (count % 2 == 1) level[next++] = level[count - 1];
      count = next;
    }
    bytes32 root = level[0];
    roots[msg.sender][e3Id] = root;
    emit AllowlistSet(msg.sender, e3Id, root, members);
  }

  /// @inheritdoc IBidderGate
  function isEligible(uint256 e3Id, address bidder, bytes calldata proof) external view override returns (bool) {
    bytes32 root = roots[msg.sender][e3Id];
    if (root == bytes32(0)) return false;
    bytes32[] memory path = abi.decode(proof, (bytes32[]));
    return MerkleProof.verify(path, root, keccak256(abi.encodePacked(bidder)));
  }

  /// @dev Sorted-pair hash, the one `MerkleProof` uses.
  function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
    return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
  }
}
