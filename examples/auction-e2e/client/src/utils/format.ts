// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * An E3 id is a 77-digit number: shown whole it breaks any layout. This keeps the first `head` and
 * the last `tail` digits (`6846…71744`). Use it for display only; URLs, storage keys and contract
 * arguments keep the full id.
 */
export function shortId(id: bigint | string, head = 4, tail = 5): string {
  const digits = id.toString()
  return digits.length <= head + tail + 1 ? digits : `${digits.slice(0, head)}…${digits.slice(-tail)}`
}

/** Whether `a` and `b` are the same address, ignoring case. `b` may be missing. */
export const sameAddress = (a: string, b: string | undefined): boolean => b !== undefined && a.toLowerCase() === b.toLowerCase()
