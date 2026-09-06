// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Issuer feature tree — the SAME circom-compatible Poseidon the circuit uses (`poseidon::bn254::hash_9`
// for the leaf, `hash_2` for the nodes; zk-kit `binary_merkle_root`). poseidon-lite matches the
// server's light-poseidon 0.2. Layout mirrors `e3_zk_helpers::threshold::ckks_credit_validity::FeatureTree`:
// leaves are `poseidon9([address, x_0, .., x_7])`, padded with ZERO leaves to `2^depth`, depth =
// max(1, ceil(log2 n)). The server is authoritative; the client recomputes only to sanity-check the
// served path before proving.

import { poseidon2, poseidon9 } from 'poseidon-lite'
import type { Address, Hex } from 'viem'
import { getAddress } from 'viem'

import { FEATURES, MERKLE_MAX_DEPTH } from './types'
import type { ApplicantEntry, FeatureProof } from './types'

export const featureLeaf = (address: Address, features: number[]): bigint => {
  if (features.length !== FEATURES) throw new Error(`expected ${FEATURES} features`)
  return poseidon9([BigInt(address), ...features.map((x) => BigInt(x))])
}

export const toRootHex = (root: bigint): Hex => `0x${root.toString(16).padStart(64, '0')}`

export class FeatureTree {
  readonly depth: number
  private readonly levels: bigint[][]
  private readonly entries: ApplicantEntry[]

  constructor(entries: ApplicantEntry[]) {
    if (entries.length === 0) throw new Error('feature tree needs a leaf')
    this.entries = entries.map((e) => ({ address: getAddress(e.address), features: e.features }))
    this.depth = Math.max(1, Math.ceil(Math.log2(entries.length)))
    if (this.depth > MERKLE_MAX_DEPTH) throw new Error(`tree depth ${this.depth} exceeds circuit max ${MERKLE_MAX_DEPTH}`)
    const leaves: bigint[] = this.entries.map((e) => featureLeaf(e.address, e.features))
    while (leaves.length < 1 << this.depth) leaves.push(0n)
    this.levels = [leaves]
    for (let l = 0; l < this.depth; l++) {
      const prev = this.levels[l]
      const next: bigint[] = []
      for (let i = 0; i < prev.length; i += 2) next.push(poseidon2([prev[i], prev[i + 1]]))
      this.levels.push(next)
    }
  }

  root(): bigint {
    return this.levels[this.depth][0]
  }

  rootHex(): Hex {
    return toRootHex(this.root())
  }
}

/** Recomputes the root a served path opens to (client-side sanity check before proving). */
export const rootFromProof = (proof: FeatureProof): Hex => {
  let node = featureLeaf(proof.address, proof.features)
  for (let i = 0; i < proof.depth; i++) {
    const sibling = BigInt(proof.siblings[i])
    node = proof.indices[i] ? poseidon2([sibling, node]) : poseidon2([node, sibling])
  }
  return toRootHex(node)
}
