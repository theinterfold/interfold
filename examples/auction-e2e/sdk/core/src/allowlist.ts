// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The allowlist tree of `contracts/gates/MerkleAllowlistGate.sol`.
 *
 * The leaf of a member is `keccak256(address)` over the 20 address bytes. An inner node is the
 * `keccak256` of its two children, the smaller one first. A level with an odd number of nodes
 * promotes its last node unchanged. The members are strictly increasing addresses, 1 to 256 of them.
 * The contract builds the root on chain from the same list; `test/MerkleAllowlistGate.test.ts` and the Solidity
 * gate check one shared test vector.
 */
import { type Address, type Hex, encodeAbiParameters, getAddress, isAddress, keccak256, parseAbiParameters } from 'viem'

/** `MerkleAllowlistGate.MAX_MEMBERS`. */
export const MAX_ALLOWLIST_MEMBERS = 256

const compareHex = (a: Hex, b: Hex): number => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0)

/**
 * The members in the order the contract requires: checksummed, deduplicated, ascending by address.
 * Throws on an invalid address, an empty list or more than `MAX_ALLOWLIST_MEMBERS` addresses.
 */
export function sortedAllowlist(members: readonly string[]): Address[] {
  const unique = new Map<string, Address>()
  for (const member of members) {
    if (!isAddress(member, { strict: false })) throw new Error(`Not an address: ${member}`)
    unique.set(member.toLowerCase(), getAddress(member))
  }
  const sorted = [...unique.values()].sort(compareHex)
  if (sorted.length === 0) throw new Error('An allowlist needs at least one address')
  if (sorted.length > MAX_ALLOWLIST_MEMBERS) {
    throw new Error(`An allowlist has at most ${MAX_ALLOWLIST_MEMBERS} addresses, got ${sorted.length}`)
  }
  return sorted
}

/** The gate config of `AuctionProgram` customParams: `abi.encode(address[] members)`, sorted and deduplicated. */
export function encodeAllowlistConfig(members: readonly string[]): Hex {
  return encodeAbiParameters(parseAbiParameters('address[]'), [sortedAllowlist(members)])
}

/** The tree levels, from the leaves up to the root. */
function levelsOf(members: readonly string[]): { leaves: Address[]; levels: Hex[][] } {
  const leaves = sortedAllowlist(members)
  const levels: Hex[][] = [leaves.map((member) => keccak256(member.toLowerCase() as Hex))]
  while (levels[levels.length - 1].length > 1) {
    const level = levels[levels.length - 1]
    const next: Hex[] = []
    for (let i = 0; i + 1 < level.length; i += 2) {
      const [low, high] = compareHex(level[i], level[i + 1]) <= 0 ? [level[i], level[i + 1]] : [level[i + 1], level[i]]
      next.push(keccak256(`${low}${high.slice(2)}`))
    }
    if (level.length % 2 === 1) next.push(level[level.length - 1])
    levels.push(next)
  }
  return { leaves, levels }
}

/** The root that `MerkleAllowlistGate.configure` stores for `members`. */
export function allowlistRoot(members: readonly string[]): Hex {
  const { levels } = levelsOf(members)
  return levels[levels.length - 1][0]
}

/**
 * The gate proof of `bidder`: `abi.encode(bytes32[] path)`, the sibling hashes from the leaf up to
 * the root, with no entry at a level where the node is promoted. Throws when `bidder` is not a member.
 */
export function allowlistProof(members: readonly string[], bidder: string): Hex {
  const { leaves, levels } = levelsOf(members)
  let index = leaves.findIndex((member) => member.toLowerCase() === bidder.toLowerCase())
  if (index < 0) throw new Error(`${bidder} is not on the allowlist`)
  const path: Hex[] = []
  for (const level of levels.slice(0, -1)) {
    const sibling = index ^ 1
    if (sibling < level.length) path.push(level[sibling])
    index >>= 1
  }
  return encodeAbiParameters(parseAbiParameters('bytes32[]'), [path])
}
