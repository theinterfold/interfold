// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Balance Merkle tree — the CRISP token-holder model, computed with the SAME circom-compatible
// Poseidon the circuit uses (`poseidon::bn254::hash_2`, zk-kit `binary_merkle_root`). poseidon-lite
// is what CRISP's sdk uses for its LeanIMT; it matches the server's light-poseidon 0.2 (checked
// against the `ckks_auction_ps2` fixture root in tests/balanceTree.test.ts).
//
// Layout mirrors `e3_zk_helpers::threshold::ckks_app_validity::BalanceTree`: leaves are
// `poseidon([address, balance])`, padded with ZERO leaves (not zero siblings) to `2^depth`, depth
// = max(1, ceil(log2(n))). The server is authoritative; the client recomputes only to display and
// to sanity check the served path before spending ~40 s on proofs.

import { poseidon2 } from 'poseidon-lite'
import type { Address, Hex } from 'viem'
import { getAddress } from 'viem'

import { MERKLE_MAX_DEPTH } from './types'
import type { BalanceEntry, BalanceProof } from './types'

export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

export const balanceLeaf = (address: Address, balance: bigint): bigint =>
  poseidon2([BigInt(address), balance])

export const toRootHex = (root: bigint): Hex => `0x${root.toString(16).padStart(64, '0')}`

export class BalanceTree {
  readonly depth: number
  private readonly levels: bigint[][]
  private readonly entries: BalanceEntry[]

  constructor(entries: BalanceEntry[]) {
    if (entries.length === 0) throw new Error('balance tree needs a leaf')
    this.entries = entries.map((e) => ({ address: getAddress(e.address), balance: e.balance }))
    this.depth = Math.max(1, Math.ceil(Math.log2(entries.length)))
    if (this.depth > MERKLE_MAX_DEPTH) throw new Error(`balance tree depth ${this.depth} exceeds circuit max ${MERKLE_MAX_DEPTH}`)
    const leaves: bigint[] = this.entries.map((e) => balanceLeaf(e.address, BigInt(e.balance)))
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

  indexOf(address: Address): number {
    const a = getAddress(address)
    return this.entries.findIndex((e) => e.address === a)
  }

  proof(address: Address): BalanceProof {
    const index = this.indexOf(address)
    if (index < 0) throw new Error(`${address} is not in the balance snapshot`)
    const indices: boolean[] = []
    const siblings: string[] = []
    let pos = index
    for (let l = 0; l < this.depth; l++) {
      const isRight = pos % 2 === 1
      indices.push(isRight)
      siblings.push(this.levels[l][isRight ? pos - 1 : pos + 1].toString())
      pos = Math.floor(pos / 2)
    }
    return {
      address: this.entries[index].address,
      balance: this.entries[index].balance,
      merkleRoot: this.rootHex(),
      depth: this.depth,
      indices,
      siblings,
    }
  }
}

/** Recomputes the root a served path opens to (client-side sanity check before proving). */
export const rootFromProof = (proof: BalanceProof): Hex => {
  let node = balanceLeaf(proof.address, BigInt(proof.balance))
  for (let i = 0; i < proof.depth; i++) {
    const sibling = BigInt(proof.siblings[i])
    node = proof.indices[i] ? poseidon2([sibling, node]) : poseidon2([node, sibling])
  }
  return toRootHex(node)
}
