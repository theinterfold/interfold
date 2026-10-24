// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The part of the package that has no proving backend: the slot layout and the output decoder, the
 * clearing, and the encoders of the sale parameters and of a bid. `BidProver` and `ClaimProver` are in
 * `@interfold/sealed-cca/prover`, which loads `@aztec-foundation/bb.js` and the circuits.
 */
export * from './layout'
export * from './clearing'
