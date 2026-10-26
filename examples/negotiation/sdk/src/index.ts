// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The part of the package that has no proving backend: the slot layout and the output decoder, the price grid,
 * the uniformity analysis and the encoders of the negotiation parameters and of an offer. `OfferProver` is in
 * `@interfold/negotiation/prover`, which loads `@aztec-foundation/bb.js` and the circuits.
 */
export * from './layout'
export * from './uniformity'
export * from './negotiation'
