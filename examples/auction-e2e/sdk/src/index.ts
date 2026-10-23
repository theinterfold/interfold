// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The part of the package that has no proving backend: the slot encoding and the result decoders,
 * the bid selection and the allowlist tree. `BidProver` is in `@interfold/auction/prover`, which
 * loads `@aztec-foundation/bb.js` and the bid circuits.
 */
export * from './layout'
export * from './selection'
export * from './allowlist'
