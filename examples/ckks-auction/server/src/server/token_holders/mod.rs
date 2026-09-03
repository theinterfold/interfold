// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Balance snapshot → Poseidon Merkle tree (CRISP's `token_holders/`): the round opener attests
//! every bidder's balance by publishing ONE root on-chain; each bidder proves in-circuit that
//! `(their address, their balance)` is a leaf and that `bid ≤ balance`.
//!
//! The tree is `e3_zk_helpers::threshold::ckks_app_validity::BalanceTree` — the very
//! implementation the circuit's witness builder and the on-chain fixtures were produced with
//! (light-poseidon 0.2 circom params, zero-LEAF padding, depth `max(1, ceil(log2 n))`). The
//! client's `poseidon-lite` tree is checked against the same fixture root.

pub mod merkle_tree;

pub use merkle_tree::{
    build_tree, compute_token_holder_hashes, get_mock_token_holders, BalanceSnapshotTree,
};
