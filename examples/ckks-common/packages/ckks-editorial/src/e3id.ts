// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * Human-readable E3 ids.
 *
 * `Interfold.request()` assigns `e3Id = (uint160(address(this)) << 96) | counter`
 * (see `Interfold.sol` — `nexte3Id` is seeded with the contract address and the
 * low 96 bits count from zero), so the on-chain id is a ~77-digit decimal that
 * is useless to read. The low 96 bits are the sequential round number, which is
 * what people mean by "round 1".
 *
 * The full id stays the routing/API key everywhere; only the DISPLAY changes.
 */

const LOW_96 = (1n << 96n) - 1n

/** Sequential round number encoded in the low 96 bits of an E3 id. */
export function e3Seq(e3Id: string | bigint | number): bigint {
  const id = typeof e3Id === 'bigint' ? e3Id : BigInt(String(e3Id))
  return id & LOW_96
}

/** `1`, `2`, … (1-based so the first round reads as round 1, not 0). */
export function e3Short(e3Id: string | bigint | number): string {
  return (e3Seq(e3Id) + 1n).toString()
}

/** `01`, `02`, … for the editorial section gutter. */
export function e3Num(e3Id: string | bigint | number): string {
  return e3Short(e3Id).padStart(2, '0')
}

/** The upper 160 bits as the Interfold contract address (for tooltips). */
export function e3Contract(e3Id: string | bigint | number): string {
  const id = typeof e3Id === 'bigint' ? e3Id : BigInt(String(e3Id))
  return '0x' + (id >> 96n).toString(16).padStart(40, '0')
}

/** `…a1b2c3` — tail of the full id for tooltips / titles. */
export function e3Tail(e3Id: string | bigint | number, n = 6): string {
  const s = String(e3Id)
  return s.length > n ? '…' + s.slice(-n) : s
}
