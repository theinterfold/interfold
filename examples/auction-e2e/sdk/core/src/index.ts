// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The part of the auction SDK that every design shares and that has no proving backend: the slot
 * encoding, the on-chain encoding, the bid selection, the allowlist tree and the reader of the
 * published result. The proving engine is in `@interfold/auction-core/prover`. The design packages
 * (`@interfold/auction-first-price`, `@interfold/auction-provider-second-price` and
 * `@interfold/auction-qnr-second-price`) build on this package.
 *
 * @packageDocumentation
 */
export * from './layout'
export * from './params'
export * from './selection'
export * from './result'
export * from './allowlist'
export * from './hex'
