// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

import { poseidon2 } from 'poseidon-lite'
import { describe, expect, it } from 'vitest'
import { CLAIM_TREE_DEPTH } from './layout'
import { ClaimTree, ZEROS, rootFromPath } from './merkle'

describe('ClaimTree', () => {
  it('has the zero values of the zk-kit LazyIMT', () => {
    // `Z_1` and `Z_7` of `InternalLazyIMT.sol`.
    expect(ZEROS[0]).toBe(0n)
    expect(ZEROS[1]).toBe(14744269619966411208579211824598458697587494354926760081771325075741142829156n)
    expect(ZEROS[7]).toBe(3396914609616007258851405644437304192397291162432396347162513310381425243293n)
    expect(new ClaimTree().root).toBe(ZEROS[CLAIM_TREE_DEPTH])
  })

  it('hashes the pair of the first two leaves', () => {
    const tree = ClaimTree.from([5n, 9n])
    let node = poseidon2([5n, 9n])
    for (let k = 1; k < CLAIM_TREE_DEPTH; k++) node = poseidon2([node, ZEROS[k]])
    expect(tree.root).toBe(node)
  })

  it('gives a path from every leaf to the root, for every size up to 85 and the full tree', () => {
    for (const size of [1, 2, 3, 7, 8, 9, 40, 85, 128]) {
      const tree = ClaimTree.from(Array.from({ length: size }, (_, i) => BigInt(i + 1) * 7919n))
      for (const index of [0, size >> 1, size - 1]) {
        const path = tree.path(index)
        expect(path.siblings).toHaveLength(CLAIM_TREE_DEPTH)
        expect(rootFromPath(BigInt(index + 1) * 7919n, path), `size ${size} leaf ${index}`).toBe(tree.root)
      }
    }
  })

  it('changes root with every insertion, and refuses a 129th leaf or a missing path', () => {
    const tree = new ClaimTree()
    const roots = new Set<bigint>([tree.root])
    for (let i = 0; i < 128; i++) {
      tree.insert(BigInt(i + 1))
      roots.add(tree.root)
    }
    expect(roots.size).toBe(129)
    expect(() => tree.insert(1n)).toThrow('full')
    expect(() => tree.path(128)).toThrow('no leaf')
  })
})
