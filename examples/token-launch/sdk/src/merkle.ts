// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/**
 * The claim tree: the depth-7 Poseidon tree that `TokenLaunchProgram` builds with zk-kit's `InternalLazyIMT` over
 * the bid commitments (leaf `i` is bid `i`). The node hash is circomlib's `Poseidon(2)`, which is what the claim
 * circuit's `poseidon::bn254::hash_2` computes. An empty subtree at level `k` is `ZEROS[k]`:
 * `ZEROS[0] = 0`, `ZEROS[k + 1] = hash(ZEROS[k], ZEROS[k])`. Bit `k` of a leaf index is 1 when the node is the
 * right child at level `k`.
 */
import { poseidon2 } from 'poseidon-lite'
import { CLAIM_TREE_DEPTH } from './layout'

const hash = (left: bigint, right: bigint): bigint => poseidon2([left, right])

/** `ZEROS[k]`: the root of an empty subtree of height `k`, for `k = 0..CLAIM_TREE_DEPTH`. */
export const ZEROS: readonly bigint[] = (() => {
  const zeros = [0n]
  for (let k = 0; k < CLAIM_TREE_DEPTH; k++) zeros.push(hash(zeros[k], zeros[k]))
  return zeros
})()

/** The authentication path of a leaf. */
export interface ClaimPath {
  /** The leaf index. */
  index: number
  /** The sibling at each level, from the leaf up. Length `CLAIM_TREE_DEPTH`. */
  siblings: bigint[]
}

export class ClaimTree {
  private readonly leaves: bigint[] = []

  /** A tree with these leaves, in order. */
  static from(leaves: Iterable<bigint>): ClaimTree {
    const tree = new ClaimTree()
    for (const leaf of leaves) tree.insert(leaf)
    return tree
  }

  get size(): number {
    return this.leaves.length
  }

  /** Appends a leaf; returns its index. */
  insert(leaf: bigint): number {
    if (this.leaves.length >= 2 ** CLAIM_TREE_DEPTH) throw new Error('the claim tree is full')
    this.leaves.push(leaf)
    return this.leaves.length - 1
  }

  /** The nodes of each level, from the leaves up; each level is padded on the right with its empty subtree. */
  private levels(): bigint[][] {
    const levels: bigint[][] = [this.leaves]
    for (let k = 0; k < CLAIM_TREE_DEPTH; k++) {
      const below = levels[k]
      const above: bigint[] = []
      for (let i = 0; i < below.length; i += 2) above.push(hash(below[i], i + 1 < below.length ? below[i + 1] : ZEROS[k]))
      levels.push(above)
    }
    return levels
  }

  /** The root: the same value as `claimRoot` of the contract after the same insertions. */
  get root(): bigint {
    return this.levels()[CLAIM_TREE_DEPTH][0] ?? ZEROS[CLAIM_TREE_DEPTH]
  }

  /** The authentication path of leaf `index`. */
  path(index: number): ClaimPath {
    if (!Number.isInteger(index) || index < 0 || index >= this.leaves.length) throw new Error(`no leaf ${index}`)
    const levels = this.levels()
    const siblings: bigint[] = []
    let i = index
    for (let k = 0; k < CLAIM_TREE_DEPTH; k++) {
      siblings.push(levels[k][i ^ 1] ?? ZEROS[k])
      i >>= 1
    }
    return { index, siblings }
  }
}

/** The root that `leaf` at `path.index` and the siblings of `path` lead to. */
export function rootFromPath(leaf: bigint, path: ClaimPath): bigint {
  let node = leaf
  for (let k = 0; k < CLAIM_TREE_DEPTH; k++) {
    node = (path.index >> k) & 1 ? hash(path.siblings[k], node) : hash(node, path.siblings[k])
  }
  return node
}
