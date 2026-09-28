// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! # CRISP Library
//!
//! Library modules for CRISP (Coercion-Resistant Impartial Selection Protocol) circuits.
//! This library provides utilities for ciphertext operations, commitments, ECDSA signature
//! verification, Merkle tree operations, and vote validation.

pub mod constants;
pub mod ciphertext_addition;
pub mod ecdsa;
pub mod merkle_tree;
pub mod utils;
pub mod safe_auth;
