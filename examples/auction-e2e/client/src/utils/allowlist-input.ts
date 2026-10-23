// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { isAddress, type Address } from 'viem'
import { MAX_ALLOWLIST_MEMBERS, sortedAllowlist } from '@interfold/auction'

/**
 * The addresses in a pasted list: separated by spaces, commas, semicolons or new lines. `members` is
 * sorted and has no duplicates, which is the form the gate wants; it is empty when there are none or
 * more than the gate takes. `count` is the number of unique addresses. `invalid` holds the entries that are no address.
 */
export function parseAllowlist(text: string): { members: Address[]; count: number; invalid: string[] } {
  const entries = text.split(/[\s,;]+/).filter((entry) => entry !== '')
  const valid = entries.filter((entry): entry is Address => isAddress(entry))
  const count = new Set(valid.map((entry) => entry.toLowerCase())).size
  const members = count === 0 || count > MAX_ALLOWLIST_MEMBERS ? [] : sortedAllowlist(valid)
  return { members, count, invalid: entries.filter((entry) => !isAddress(entry)) }
}
