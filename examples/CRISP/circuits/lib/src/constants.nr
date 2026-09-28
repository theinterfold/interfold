// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Maximum number of options for a vote.
/// We need this value because we need a compile-time bound value
/// for looping.
pub global MAX_OPTIONS: u32 = 10;

// This constant defines the size of the coefficient region allocated for encoding vote amounts
/// in binary format within each half of the polynomial. Votes are encoded as binary numbers.
pub global MAX_VOTE_BITS: u32 = 50;

/// Largest owner list of a Safe that can cast a ballot.
/// The contract commits to the owner list padded to this length, so the circuit hashes a fixed
/// number of bytes. Must stay aligned with `MAX_SAFE_OWNERS` in `CRISPProgram.sol`.
pub global MAX_SAFE_OWNERS: u32 = 10;

/// Largest Safe threshold that can cast a ballot.
/// Every ballot proof has this many signature slots, and each slot costs one secp256k1 check and
/// one Keccak hash. Must stay aligned with `MAX_SAFE_SIGNERS` in `CRISPProgram.sol`.
pub global MAX_SAFE_SIGNERS: u32 = 3;
