// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";

/// @title The zk-kit incremental Poseidon tree behind an external library.
/// @notice `InternalLazyIMT` inlines about 3.5 kB of Poseidon tree code into each contract that uses it.
/// `TokenLaunchProgram` is near the size limit of a contract, so it calls these functions instead (the library links
/// `PoseidonT3`). The node hash is circomlib's `Poseidon(2)`; an empty leaf is 0.
library IncrementalTree {
  using InternalLazyIMT for LazyIMTData;

  function init(LazyIMTData storage tree, uint8 depth) public {
    tree._init(depth);
  }

  function insert(LazyIMTData storage tree, uint256 leaf) public {
    tree._insert(leaf);
  }

  /// @notice Replaces the leaf `index`, which must exist.
  function update(LazyIMTData storage tree, uint256 leaf, uint40 index) public {
    tree._update(leaf, index);
  }

  /// @notice The root with the smallest depth that holds the leaves (the input trees).
  function root(LazyIMTData storage tree) public view returns (uint256) {
    return tree._root();
  }

  /// @notice The root of a tree of the fixed height `depth` (the claim tree).
  function rootAt(LazyIMTData storage tree, uint8 depth) public view returns (uint256) {
    return tree._root(depth);
  }

  function leafAt(LazyIMTData storage tree, uint40 index) public view returns (uint256) {
    return tree.elements[InternalLazyIMT._indexForElement(0, index)];
  }
}
